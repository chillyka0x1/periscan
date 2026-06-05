"""Unit-Tests für Periscan — reine Logik, kein Netzwerk. Lauf: python -m unittest discover -s tests"""
import unittest

import periscan as ps


class TestRisk(unittest.TestCase):
    def test_is_private(self):
        self.assertTrue(ps._is_private("10.10.1.1"))
        self.assertTrue(ps._is_private("192.168.0.5"))
        self.assertFalse(ps._is_private("1.1.1.1"))

    def test_worst_risk(self):
        self.assertEqual(ps._worst_risk("LOW", "CRITICAL", "MEDIUM"), "CRITICAL")
        self.assertEqual(ps._worst_risk("INFO", "LOW"), "LOW")

    def test_adjust_risk_blocked(self):
        self.assertEqual(ps.adjust_risk({"status": 403}, "CRITICAL"), "OK")
        self.assertEqual(ps.adjust_risk({"status": 401}, "HIGH"), "OK")

    def test_adjust_risk_origin_error(self):
        self.assertEqual(ps.adjust_risk({"status": 525}, "MEDIUM"), "LOW")

    def test_adjust_risk_tls_bump(self):
        r = {"status": 200, "scheme": "https", "tls": {"valid": False}}
        self.assertEqual(ps.adjust_risk(r, "INFO"), "MEDIUM")


class TestAccess(unittest.TestCase):
    def test_blocked(self):
        self.assertEqual(ps.detect_access({"status": 403}), "geschützt")

    def test_login(self):
        self.assertEqual(ps.detect_access({"status": 200, "body": '<input type="password">'}), "Login")

    def test_spa_no_false_open(self):
        # SPA ohne Passwortfeld -> KEINE Behauptung (kein Fehlalarm "offen")
        self.assertEqual(ps.detect_access({"status": 200, "body": "<div id=app></div>"}), "")


class TestIdentify(unittest.TestCase):
    def _res(self, **k):
        base = {"title": "", "server": "", "headers_str": "", "body": "", "status": 200}
        base.update(k)
        return base

    def test_proxmox_critical(self):
        app, risk, fp = ps.identify(self._res(title="Proxmox Virtual Environment"))
        self.assertEqual(app, "Proxmox VE")
        self.assertEqual(risk, "CRITICAL")
        self.assertIsNotNone(fp)

    def test_cloudflare_origin_error(self):
        app, risk, fp = ps.identify(self._res(status=525))
        self.assertTrue(app.startswith("kein Dienst"))
        self.assertIsNone(fp)

    def test_unknown(self):
        app, risk, fp = ps.identify(self._res(title="irgendeine seite", body="nichts"))
        self.assertEqual(app, "Unbekannter Dienst")


class TestMonitoringDiff(unittest.TestCase):
    def test_diff(self):
        prev = {"host:a": {"label": "a", "risk": "LOW"}}
        curr = {"host:a": {"label": "a", "risk": "HIGH"},
                "port:1.2.3.4:8006": {"label": "px", "risk": "CRITICAL"}}
        added, removed, changed = ps.diff_exposures(prev, curr)
        self.assertEqual([a["key"] for a in added], ["port:1.2.3.4:8006"])
        self.assertEqual(changed[0]["was"], "LOW")
        self.assertEqual(changed[0]["risk"], "HIGH")
        self.assertEqual(removed, [])

    def test_exposures_excludes_noise(self):
        data = {
            "results": [
                {"scheme": "https", "host": "x", "app": "n8n", "risk": "HIGH", "findings": []},
                {"scheme": "https", "host": "y", "app": "Unbekannter Dienst", "risk": "LOW"},
                {"scheme": "https", "host": "z", "app": "Pi-hole", "risk": "OK"},
            ],
            "ports": [{"ip": "1.2.3.4", "port": 8006, "service": "Proxmox VE", "risk": "CRITICAL"}],
        }
        ex = ps.exposures(data)
        self.assertIn("host:x", ex)            # echte Exposition
        self.assertNotIn("host:y", ex)         # "Unbekannter Dienst" = Rauschen
        self.assertNotIn("host:z", ex)         # OK/geschützt zählt nicht als Exposition
        self.assertIn("port:1.2.3.4:8006", ex)


if __name__ == "__main__":
    unittest.main()
