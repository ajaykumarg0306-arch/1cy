"""Run: python3 test_truthguard.py  (starts its own server on a temp DB)"""
import os, sys, json, time, tempfile, subprocess, unittest, urllib.request, urllib.error, http.cookiejar
PORT = "8765"; BASE = f"http://127.0.0.1:{PORT}"

class C:  # one browser session
    def __init__(s): s.jar = http.cookiejar.CookieJar(); s.o = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(s.jar))
    def call(s, m, u, b=None, ctype="application/json"):
        r = urllib.request.Request(BASE + u, method=m, data=json.dumps(b).encode() if b is not None else None, headers={"Content-Type": ctype})
        try:
            with s.o.open(r) as x: return x.status, json.loads(x.read() or b"{}")
        except urllib.error.HTTPError as e: return e.code, json.loads(e.read() or b"{}")

RES = lambda cls="NOT_SURE", cat="Unknown / Insufficient Evidence": {"cls": cls, "cat": cat, "trust": 40, "risk": 60, "warn": [], "urls": [], "why": "x"}
def reg(c, n, pw="Passw0rdOK"): return c.call("POST", "/api/register", {"name": n, "email": f"{n}@ex.com", "password": pw, "terms": True})

class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(); env = dict(os.environ, TG_DB=cls.d + "/t.db", TG_PORT=PORT)
        cls.p = subprocess.Popen([sys.executable, "server.py"], env=env); time.sleep(1)
    @classmethod
    def tearDownClass(cls): cls.p.terminate()

    def test_1_auth(self):
        c = C()
        self.assertEqual(c.call("GET", "/api/dashboard")[0], 401)                 # unauthorized
        self.assertEqual(reg(c, "alice")[0], 201)                                  # register + auto-login
        self.assertEqual(C().call("POST", "/api/register", {"name": "a", "email": "alice@ex.com", "password": "Passw0rdOK", "terms": True})[0], 409)  # duplicate
        self.assertEqual(C().call("POST", "/api/register", {"name": "b", "email": "b@ex.com", "password": "short", "terms": True})[0], 400)
        c2 = C(); self.assertEqual(c2.call("POST", "/api/login", {"email": "alice@ex.com", "password": "wrong"})[0], 401)
        self.assertEqual(c2.call("POST", "/api/login", {"email": "alice@ex.com", "password": "Passw0rdOK"})[0], 200)
        self.assertEqual(c2.call("GET", "/api/me")[0], 200)
        self.assertEqual(c2.call("POST", "/api/logout", {})[0], 200)               # logout invalidates
        self.assertEqual(c2.call("GET", "/api/me")[0], 401)
        self.assertEqual(c.call("POST", "/api/login", {"email": "x"}, ctype="text/plain")[0], 415)  # CSRF guard: JSON only
        import sqlite3; db = sqlite3.connect(self.d + "/t.db")
        self.assertNotIn("Passw0rdOK", db.execute("select pw from users").fetchone()[0])  # hashed

    def test_2_expired_session(self):
        import sqlite3; c = C(); reg(c, "exp"); db = sqlite3.connect(self.d + "/t.db"); db.execute("update sessions set exp=1"); db.commit()
        self.assertEqual(c.call("GET", "/api/me")[0], 401)

    def test_3_isolation_and_stats(self):
        a, b = C(), C(); reg(a, "u1"); reg(b, "u2")
        d = b.call("GET", "/api/dashboard")[1]; self.assertEqual((d["total"], d["scam"], d["reports"]), (0, 0, 0))   # new user = zeros
        _, r = a.call("POST", "/api/analyses", {"kind": "Text", "text": "hi 123456", "result": RES("LIKELY_SCAM", "Phishing links")})
        a.call("POST", "/api/analyses", {"kind": "Text", "text": "y", "result": RES()})
        d = a.call("GET", "/api/dashboard")[1]; self.assertEqual((d["total"], d["scam"], d["notsure"]), (2, 1, 1))
        self.assertEqual(b.call("GET", f"/api/analyses/{r['id']}")[0], 404)         # no cross-user access
        self.assertEqual(a.call("GET", f"/api/analyses/{r['id']}")[1]["text"], "hi ••••••")
        self.assertEqual(b.call("GET", "/api/dashboard")[1]["total"], 0)
        self.assertEqual(a.call("POST", "/api/analyses", {"result": {"cls": "BOGUS", "trust": 5}})[0], 400)

    def test_4_community_threshold(self):
        us = [C() for _ in range(6)]
        for i, u in enumerate(us): reg(u, f"r{i}")
        for i, u in enumerate(us):
            self.assertEqual(u.call("POST", "/api/reports", {"sender": "9876543210", "cat": "x"})[0], 201)
            if i == 0: self.assertEqual(u.call("POST", "/api/reports", {"sender": "9876543210", "cat": "x"})[0], 409)  # duplicate blocked
            n = u.call("GET", "/api/community?sender=9876543210")[1]
            self.assertEqual((n["count"], n["alert"]), (i + 1, i + 1 >= 6))
        us[0].call("DELETE", "/api/reports?sender=9876543210")                        # withdrawn no longer counts
        self.assertFalse(us[1].call("GET", "/api/community?sender=9876543210")[1]["alert"])

    def test_5_password_and_delete(self):
        c = C(); reg(c, "pw"); self.assertEqual(c.call("POST", "/api/password", {"current": "bad", "new": "NewPassw0rd"})[0], 403)
        self.assertEqual(c.call("POST", "/api/password", {"current": "Passw0rdOK", "new": "NewPassw0rd"})[0], 200)
        self.assertEqual(c.call("DELETE", "/api/me", {"password": "NewPassw0rd"})[0], 200)
        self.assertEqual(C().call("POST", "/api/login", {"email": "pw@ex.com", "password": "NewPassw0rd"})[0], 401)

if __name__ == "__main__": unittest.main(verbosity=1)
