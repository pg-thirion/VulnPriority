import unittest
from scoring import score, rank, parse_csv

def finding(**kwargs):
    return dict(cve="CVE-2025-90001", asset="claims-api", cvss=8.0, epss=.5,
                kev=False, criticality=4, impact=5, exposure="restricted") | kwargs

class RiskTests(unittest.TestCase):
    def test_weighted_score(self):
        result = score(finding())
        self.assertEqual(result["risk"], 73)
        self.assertEqual(result["priority"], "P2")
        self.assertEqual(result["sla_days"], 7)
        self.assertEqual(sum(result["components"].values()), 73)
    def test_kev_floor(self):
        self.assertEqual(score(finding(kev=True, epss=0, exposure="internet"))["risk"], 95)
        self.assertEqual(score(finding(kev=True, epss=0, exposure="internal"))["risk"], 85)
    def test_maximum(self):
        self.assertEqual(score(finding(cvss=10, epss=1, criticality=5, impact=5, exposure="internet"))["risk"], 100)
    def test_missing_intelligence(self):
        result = score(finding(epss=None, kev=None))
        self.assertEqual(len(result["warnings"]), 2)
        self.assertIsNone(result["epss"])
        self.assertEqual(result["components"]["Exploit likelihood"], 15)
    def test_monotonic(self):
        self.assertGreater(score(finding(epss=.9))["risk"], score(finding(epss=.1))["risk"])
        self.assertGreater(score(finding(criticality=5))["risk"], score(finding(criticality=1))["risk"])
        self.assertGreater(score(finding(impact=5))["risk"], score(finding(impact=1))["risk"])
    def test_ranking(self):
        result = rank([finding(asset="low", cvss=1, epss=0), finding(asset="high", kev=True)])
        self.assertEqual(result[0]["asset"], "high")
    def test_distinct_assets(self):
        self.assertEqual(len(rank([finding(), finding(asset="other")])), 2)
    def test_duplicates(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            rank([finding(), finding(asset="CLAIMS-API")])
    def test_invalid_values(self):
        for bad in [dict(cvss=11), dict(epss=-.1), dict(epss="nan"), dict(criticality=3.5),
                    dict(impact=0), dict(kev="maybe"), dict(exposure="unknown"), dict(cve="wrong"),
                    dict(asset=""), dict(cvss=True)]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                score(finding(**bad))
    def test_csv(self):
        header = "cve,asset,cvss,epss,kev,criticality,impact,exposure\n"
        rows = parse_csv(header + 'CVE-2025-90001,"asset, one",8,,true,4,5,internet\n')
        self.assertEqual(rank(rows)[0]["risk"], 95)
        self.assertEqual(rows[0]["asset"], "asset, one")
    def test_csv_rejects_bad_shape(self):
        with self.assertRaises(ValueError):
            parse_csv("cve,asset\nCVE-2025-90001,x")
        with self.assertRaises(ValueError):
            parse_csv("cve,asset,cvss,epss,kev,criticality,impact,exposure\nCVE-2025-90001,x,8")
    def test_empty(self):
        self.assertEqual(rank([]), [])

if __name__ == "__main__":
    unittest.main()
