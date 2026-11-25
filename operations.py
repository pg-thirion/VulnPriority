"""Persistent local vulnerability operations and intelligence ingestion."""
import csv
import io
import json
import sqlite3
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from scoring import FIELDS, rank, validate

STATES = ('open', 'in_progress', 'mitigated', 'resolved', 'accepted')
TRANSITIONS = {
    'open': {'in_progress', 'mitigated', 'resolved', 'accepted'},
    'in_progress': {'open', 'mitigated', 'resolved', 'accepted'},
    'mitigated': {'open', 'in_progress', 'resolved', 'accepted'},
    'resolved': {'open'}, 'accepted': {'open', 'in_progress'},
}


def today():
    return datetime.now(timezone.utc).date()


def clean(value, limit=200):
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 and c != '\n' for c in value):
        raise ValueError('Invalid text field')
    return value.strip()


def day(value):
    if not isinstance(value, str):
        raise ValueError('Expected ISO date')
    d = date.fromisoformat(value)
    if d.isoformat() != value:
        raise ValueError('Expected YYYY-MM-DD')
    return d


def fresh(value, now, max_age=7):
    return bool(value and 0 <= (now - day(value)).days <= max_age)


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.touch(mode=0o600, exist_ok=True)
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY, identity TEXT UNIQUE NOT NULL, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, at TEXT NOT NULL, action TEXT NOT NULL, finding TEXT NOT NULL, detail TEXT NOT NULL);
            ''')

    def connect(self):
        return sqlite3.connect(self.path, timeout=10)

    @staticmethod
    def event(db, action, ident, detail):
        db.execute('INSERT INTO audit(at,action,finding,detail) VALUES(?,?,?,?)',
                   (datetime.now(timezone.utc).isoformat(), action, ident, json.dumps(detail, ensure_ascii=False)))

    @staticmethod
    def put(db, row):
        db.execute('INSERT INTO findings VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body',
                   (row['id'], row['cve']+'|'+row['asset'].casefold(), json.dumps(row, allow_nan=False)))

    @staticmethod
    def rows(db):
        return [json.loads(r[0]) for r in db.execute('SELECT body FROM findings')]

    def ingest(self, rows, now=None):
        now = now or today()
        checked = rank(rows)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            existing = {(r['cve'], r['asset'].casefold()): r for r in self.rows(db)}
            if len(existing.keys() | {(r['cve'], r['asset'].casefold()) for r in checked}) > 5000:
                raise ValueError('Inventory limit is 5000 findings')
            added = updated = 0
            for f in checked:
                k = (f['cve'], f['asset'].casefold())
                old = existing.get(k)
                if old:
                    row = {**old, **f, 'revision': old['revision']+1,
                           'epss_date': None, 'kev_date': None}
                    updated += 1
                else:
                    row = {**f, 'id': uuid.uuid4().hex, 'revision': 1, 'status': 'open',
                           'owner': '', 'team': '', 'note': '', 'evidence': '', 'exception_until': None,
                           'first_seen': now.isoformat(), 'epss_date': None, 'kev_date': None}
                    added += 1
                row['due'] = (day(row['first_seen']) + timedelta(days=f['sla_days'])).isoformat()
                self.put(db, row)
                self.event(db, 'import', row['id'], {'revision': row['revision']})
        return {'added': added, 'updated': updated}

    def change(self, ident, revision, patch, now=None):
        now = now or today()
        if type(revision) is not int or not isinstance(patch, dict) or not patch or not set(patch) <= {'status','owner','team','note','evidence','exception_until'}:
            raise ValueError('Invalid change')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            found = db.execute('SELECT body FROM findings WHERE id=?', (ident,)).fetchone()
            if not found:
                raise LookupError('Finding not found')
            r = json.loads(found[0])
            if revision != r['revision']:
                raise RuntimeError('Revision conflict: reload finding')
            before = {k: r[k] for k in patch}
            for k, v in patch.items():
                if k not in ('status','exception_until'):
                    r[k] = clean(v, 2000 if k in ('note','evidence') else 200)
            status = patch.get('status', r['status'])
            if not isinstance(status, str) or (status != r['status'] and status not in TRANSITIONS[r['status']]):
                raise ValueError('Invalid status transition')
            if status in ('resolved','mitigated') and not r['evidence']:
                raise ValueError('Remediation evidence required')
            expiry = patch.get('exception_until', r['exception_until'])
            if status == 'accepted':
                if not r['note'] or not r['owner'] or not expiry or day(expiry) <= now:
                    raise ValueError('Acceptance requires owner, reason and future expiry')
            else:
                expiry = None
            r.update(status=status, exception_until=expiry, revision=revision+1)
            self.put(db,r)
            self.event(db,'change',ident,{'before':before,'after':{k:r[k] for k in patch},'revision':r['revision']})
            return r

    def enrich(self, kind, payload, as_of, now=None):
        now = now or today()
        if not fresh(as_of, now, 30):
            raise ValueError('Intelligence must be dated within the last 30 days')
        if not isinstance(payload, str) or len(payload) > 12_000_000:
            raise ValueError('Invalid intelligence payload')
        if kind == 'epss':
            reader = csv.DictReader(io.StringIO('\n'.join(line for line in payload.splitlines() if not line.startswith('#'))))
            if not reader.fieldnames or not {'cve','epss'} <= set(reader.fieldnames):
                raise ValueError('EPSS CSV requires cve and epss')
            values = {}
            for row in reader:
                if not row.get('cve') or row.get('epss') is None:
                    raise ValueError('Malformed EPSS row')
                from scoring import number
                values[row['cve'].upper()] = number(row['epss'],0,1,'EPSS')
        elif kind == 'kev':
            doc = json.loads(payload)
            if not isinstance(doc, dict) or not isinstance(doc.get('vulnerabilities'), list) or not doc['vulnerabilities']:
                raise ValueError('Expected nonempty CISA KEV catalogue')
            values = {}
            for row in doc['vulnerabilities']:
                if not isinstance(row,dict) or not isinstance(row.get('cveID'),str):
                    raise ValueError('Malformed KEV entry')
                values[row['cveID'].upper()] = True
        else:
            raise ValueError('Unknown intelligence kind')
        changed = skipped = 0
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            for r in self.rows(db):
                if r.get(kind+'_date') and day(r[kind+'_date']) > day(as_of):
                    skipped += 1
                    continue
                if kind == 'epss' and r['cve'] not in values:
                    continue
                r[kind] = values.get(r['cve'], False)
                r[kind+'_date'] = as_of
                r.update(rank([{k:r[k] for k in FIELDS}])[0])
                r['due'] = (day(r['first_seen']) + timedelta(days=r['sla_days'])).isoformat()
                r['revision'] += 1
                self.put(db,r)
                self.event(db,'intelligence',r['id'],{'kind':kind,'as_of':as_of,'value':r[kind]})
                changed += 1
        return {'updated':changed,'skipped_older':skipped}

    def inventory(self, now=None):
        now = now or today()
        with self.connect() as db:
            rows = self.rows(db)
        for r in rows:
            r['exception_expired'] = r['status']=='accepted' and day(r['exception_until']) <= now
            r['active'] = r['status'] not in ('resolved','accepted') or r['exception_expired']
            r['overdue'] = r['active'] and day(r['due']) < now
            r['stale_intelligence'] = not (fresh(r['epss_date'],now) and fresh(r['kev_date'],now))
        return sorted(rows,key=lambda r:(not r['active'],-r['risk'],r['cve'],r['asset']))

    def report(self, now=None):
        rows = self.inventory(now)
        active = [r for r in rows if r['active']]
        assets = {}
        for r in active:
            a = assets.setdefault(r['asset'].casefold(),{'asset':r['asset'],'count':0,'max_risk':0,'p1':0})
            a['count'] += 1
            a['max_risk'] = max(a['max_risk'],r['risk'])
            a['p1'] += r['priority']=='P1'
        return {'total':len(rows),'active':len(active),'overdue':sum(r['overdue'] for r in rows),
                'expired_exceptions':sum(r['exception_expired'] for r in rows),
                'stale_intelligence':sum(r['stale_intelligence'] for r in active),
                'unassigned':sum(not r['owner'] for r in active),
                'by_priority':{p:sum(r['priority']==p for r in active) for p in ('P1','P2','P3','P4')},
                'by_status':{s:sum(r['status']==s for r in rows) for s in STATES},
                'assets':sorted(assets.values(),key=lambda a:(-a['max_risk'],-a['count'],a['asset']))}

    def audit(self, limit=200):
        with self.connect() as db:
            return [{'sequence':s,'at':a,'action':k,'finding':f,'detail':json.loads(d)} for s,a,k,f,d in db.execute('SELECT * FROM audit ORDER BY seq DESC LIMIT ?', (limit,))]
