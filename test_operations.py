import json
import tempfile
import threading
import unittest
from datetime import date, timedelta
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from app import Handler
from operations import Store, today
from scoring import score, rank, parse_csv

D = date(2026, 11, 26)


def finding(**kw):
    return dict(cve='CVE-2025-90001', asset='claims', cvss=8, epss=.5, kev=False,
                criticality=4, impact=5, exposure='restricted') | kw


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name)/'inventory.sqlite')
        self.store.ingest([finding()], D)

    def row(self):
        return self.store.inventory(D)[0]

    def change(self, **patch):
        r = self.row()
        return self.store.change(r['id'],r['revision'],patch,D)

    def test_persistence(self):
        self.assertEqual(Store(self.store.path).inventory(D),self.store.inventory(D))

    def test_merge_preserves_owner_and_first_seen(self):
        self.change(owner='Alice',team='Security')
        self.assertEqual(self.store.ingest([finding(asset='CLAIMS',cvss=10)],D+timedelta(days=2)),{'added':0,'updated':1})
        r=self.row(); self.assertEqual((r['owner'],r['team'],r['first_seen']),('Alice','Security',D.isoformat()))

    def test_distinct_assets(self):
        self.store.ingest([finding(asset='other')],D)
        self.assertEqual(len(self.store.inventory(D)),2)

    def test_invalid_batch_atomic(self):
        with self.assertRaises(ValueError): self.store.ingest([finding(asset='valid'),finding(cvss=11)],D)
        self.assertEqual(len(self.store.inventory(D)),1)

    def test_owner_team_note(self):
        self.assertEqual(self.change(owner='A',team='B',note='C')['note'],'C')
        self.assertEqual(self.row()['team'],'B')

    def test_transition_and_reopen(self):
        self.change(status='in_progress'); self.change(status='resolved',evidence='Patch verified')
        self.assertFalse(self.row()['active']); self.change(status='open'); self.assertTrue(self.row()['active'])

    def test_mitigation_requires_evidence(self):
        with self.assertRaises(ValueError): self.change(status='mitigated')
        self.assertEqual(self.change(status='mitigated',evidence='Firewall rule')['status'],'mitigated')

    def test_resolution_requires_evidence(self):
        with self.assertRaises(ValueError): self.change(status='resolved')

    def test_invalid_transition(self):
        self.change(status='resolved',evidence='Patch')
        with self.assertRaises(ValueError): self.change(status='in_progress')

    def test_acceptance_requirements(self):
        for patch in ({'status':'accepted'},{'status':'accepted','note':'reason','owner':'A','exception_until':D.isoformat()}):
            with self.assertRaises(ValueError): self.change(**patch)

    def test_expiry(self):
        expiry=D+timedelta(days=2)
        self.change(status='accepted',owner='A',note='Approved',exception_until=expiry.isoformat())
        self.assertFalse(self.row()['active']); self.assertTrue(self.store.inventory(expiry)[0]['exception_expired'])
        self.assertTrue(self.store.inventory(expiry)[0]['active'])

    def test_overdue(self):
        self.assertEqual(self.row()['due'],'2026-12-03')
        self.assertTrue(self.store.inventory(D+timedelta(days=8))[0]['overdue'])

    def test_revision_conflict(self):
        r=self.row(); self.change(owner='A')
        with self.assertRaises(RuntimeError): self.store.change(r['id'],r['revision'],{'owner':'B'},D)

    def test_audit(self):
        self.change(owner='A'); events=self.store.audit()
        self.assertEqual([e['action'] for e in events],['change','import'])
        self.assertEqual(events[0]['detail']['after']['owner'],'A')

    def test_epss_and_freshness(self):
        self.store.enrich('epss','#metadata\ncve,epss\nCVE-2025-90001,0.95',D.isoformat(),D)
        self.assertEqual(self.row()['epss'],.95); self.assertTrue(self.row()['stale_intelligence'])
        self.store.enrich('kev',json.dumps({'vulnerabilities':[{'cveID':'CVE-2025-90001'}]}),D.isoformat(),D)
        self.assertFalse(self.row()['stale_intelligence']); self.assertEqual(self.row()['priority'],'P1')
        self.assertTrue(self.store.inventory(D+timedelta(days=8))[0]['stale_intelligence'])

    def test_older_intelligence(self):
        self.store.enrich('epss','cve,epss\nCVE-2025-90001,.9',D.isoformat(),D)
        result=self.store.enrich('epss','cve,epss\nCVE-2025-90001,.1',(D-timedelta(days=1)).isoformat(),D)
        self.assertEqual(result['skipped_older'],1); self.assertEqual(self.row()['epss'],.9)

    def test_invalid_intelligence(self):
        for kind,payload,stamp in [('epss','cve,epss\nCVE-2025-90001,2',D.isoformat()),('kev','{}',D.isoformat()),('epss','cve,epss',(D+timedelta(days=1)).isoformat())]:
            with self.assertRaises(ValueError): self.store.enrich(kind,payload,stamp,D)

    def test_report(self):
        r=self.store.report(D); self.assertEqual((r['total'],r['active'],r['unassigned'],r['stale_intelligence']),(1,1,1,1))
        self.assertEqual(r['assets'][0]['asset'],'claims'); self.assertEqual(r['by_priority']['P2'],1)

    def test_invalid_patch(self):
        for patch in ({'risk':0},{'owner':1},{'status':[]},{'owner':'x'*201}):
            with self.assertRaises(ValueError): self.change(**patch)

    def test_kev_not_listed(self):
        self.store.enrich('kev',json.dumps({'vulnerabilities':[{'cveID':'CVE-2025-99999'}]}),D.isoformat(),D)
        self.assertIs(self.row()['kev'],False)


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.server.store=Store(Path(self.tmp.name)/'db.sqlite')
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True); self.thread.start()
        self.addCleanup(self.server.server_close); self.addCleanup(self.thread.join); self.addCleanup(self.server.shutdown)

    def call(self,path,data=None,headers=None,method=None):
        c=HTTPConnection('127.0.0.1',self.server.server_port,timeout=3)
        try:
            c.request(method or ('GET' if data is None else 'POST'),path,None if data is None else json.dumps(data),{'Host':'localhost:8000','Content-Type':'application/json'} | (headers or {}))
            r=c.getresponse(); body=r.read(); return r.status,body,r.headers
        finally: c.close()

    def test_endpoints(self):
        self.assertEqual(self.call('/health')[0],200)
        self.assertEqual(self.call('/operations')[0],200)
        self.assertEqual(self.call('/api/rank',{'findings':[finding()]})[0],200)
        self.assertEqual(self.call('/api/ops/import',{'findings':[finding()]})[0],200)
        r=json.loads(self.call('/api/ops/inventory')[1])[0]
        patch={'id':r['id'],'revision':r['revision'],'patch':{'owner':'A'}}
        self.assertEqual(self.call('/api/ops/change',patch)[0],200)
        self.assertEqual(self.call('/api/ops/change',patch)[0],409)
        self.assertEqual(self.call('/api/ops/intelligence',{'kind':'epss','payload':'cve,epss\nCVE-2025-90001,.99','as_of':today().isoformat()})[0],200)
        self.assertEqual(json.loads(self.call('/api/ops/report')[1])['unassigned'],0)
        self.assertEqual(len(json.loads(self.call('/api/ops/audit')[1])),3)

    def test_security(self):
        self.assertEqual(self.call('/api/ops/inventory',headers={'Host':'evil.test'})[0],403)
        self.assertEqual(self.call('/api/ops/import',{'findings':[]},headers={'Origin':'https://evil.test'})[0],403)
        self.assertEqual(self.call('/api/ops/import',{'findings':[]},headers={'Content-Type':'text/plain'})[0],415)
        self.assertEqual(self.call('/api/ops/import')[0],405)
        self.assertEqual(self.call('/api/ops/import',{'wrong':[]})[0],400)
        self.assertEqual(self.call('/api/ops/change',{'id':'missing','revision':1,'patch':{'owner':'A'}})[0],404)
        self.assertEqual(self.call('/api/ops/inventory')[2]['X-Content-Type-Options'],'nosniff')


if __name__=='__main__': unittest.main()
