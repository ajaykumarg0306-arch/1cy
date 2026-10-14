#!/usr/bin/env python3
"""TruthGuard AI server. Python 3.9+ standard library only: static app + JSON API + SQLite."""
import os, re, json, time, hashlib, secrets, sqlite3, threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from http.cookies import SimpleCookie

ROOT = os.path.dirname(os.path.abspath(__file__))
DBP = os.environ.get("TG_DB", os.path.join(ROOT, "truthguard.db"))
SECURE = os.environ.get("TG_SECURE") == "1"          # set to 1 when served over HTTPS
HOST = os.environ.get("TG_HOST", "127.0.0.1")
PORT = int(os.environ.get("TG_PORT", "8000"))
SHORT, LONG, ALERT_AT = 12 * 3600, 30 * 86400, 6
INELIGIBLE = ("Rejected", "Abusive", "Withdrawn")

# Append-only migrations; PRAGMA user_version tracks how many have run. Never edit old entries.
MIGRATIONS = ["""
CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, pw TEXT NOT NULL,
  save_text INTEGER NOT NULL DEFAULT 1, created INTEGER NOT NULL);
CREATE TABLE sessions(h TEXT PRIMARY KEY, uid INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, exp INTEGER NOT NULL);
CREATE TABLE analyses(id INTEGER PRIMARY KEY, uid INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, at INTEGER NOT NULL,
  kind TEXT NOT NULL, cls TEXT NOT NULL, cat TEXT NOT NULL, trust INTEGER NOT NULL, text TEXT NOT NULL, result TEXT NOT NULL);
CREATE INDEX ia ON analyses(uid, at);
CREATE TABLE reports(id INTEGER PRIMARY KEY, uid INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, sender TEXT NOT NULL,
  cat TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Pending', at INTEGER NOT NULL, UNIQUE(sender, uid));
"""]

def migrate():
    c = sqlite3.connect(DBP)
    for i in range(c.execute("PRAGMA user_version").fetchone()[0], len(MIGRATIONS)):
        c.executescript(MIGRATIONS[i]); c.execute(f"PRAGMA user_version={i + 1}")
    c.commit(); c.close()

def conn():
    c = sqlite3.connect(DBP); c.row_factory = sqlite3.Row; c.execute("PRAGMA foreign_keys=ON"); return c

def hpw(p, salt=None):
    salt = salt or secrets.token_bytes(16)
    return salt.hex() + "$" + hashlib.scrypt(p.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32).hex()

def vpw(p, stored):
    salt, h = stored.split("$")
    return secrets.compare_digest(hpw(p, bytes.fromhex(salt)).split("$")[1], h)

DUMMY = hpw("dummy-password-for-timing")
EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,200}\.[^@\s]{2,}$")
FAILS, LOCK = {}, threading.Lock()

def pwerr(p):
    ok = 8 <= len(p) <= 128 and re.search("[A-Za-z]", p) and re.search(r"\d", p)
    return None if ok else "Password must be 8 to 128 characters and include a letter and a number."

def pub(u):
    return {"id": u["id"], "name": u["name"], "email": u["email"], "save_text": bool(u["save_text"])}

def eligible(c, sender):
    q = "SELECT COUNT(DISTINCT uid) FROM reports WHERE sender=? AND status NOT IN (?,?,?)"
    return c.execute(q, (sender, *INELIGIBLE)).fetchone()[0]

def ckie(tok, age=None):
    s = f"tg_session={tok}; HttpOnly; SameSite=Strict; Path=/"
    if age is not None: s += f"; Max-Age={age}"
    return s + ("; Secure" if SECURE else "")

class E(Exception):
    def __init__(s, code, msg): s.code, s.msg = code, msg

class H(BaseHTTPRequestHandler):
    def log_message(s, *a): pass

    def out(s, code, body, ctype="application/json", cookie=None):
        b = body if isinstance(body, bytes) else json.dumps(body).encode()
        s.send_response(code)
        for k, v in (("Content-Type", ctype), ("Content-Length", str(len(b))), ("Cache-Control", "no-store"),
                     ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"), ("Referrer-Policy", "same-origin")):
            s.send_header(k, v)
        if cookie: s.send_header("Set-Cookie", cookie)
        s.end_headers(); s.wfile.write(b)

    def do_GET(s): s.run("GET")
    def do_POST(s): s.run("POST")
    def do_PATCH(s): s.run("PATCH")
    def do_DELETE(s): s.run("DELETE")

    def run(s, m):
        u = urlparse(s.path); p = u.path; qs = {k: v[0] for k, v in parse_qs(u.query).items()}
        if not p.startswith("/api/"):                      # SPA: every page path serves the app
            if m != "GET": return s.out(405, {"error": "Method not allowed"})
            return s.out(200, open(os.path.join(ROOT, "index.html"), "rb").read(), "text/html; charset=utf-8")
        try:
            body = {}
            if m != "GET":
                # JSON-only + no CORS headers + SameSite=Strict cookie = CSRF protection (cross-site forms/fetches can't match)
                if not s.headers.get("Content-Type", "").startswith("application/json"): raise E(415, "JSON required")
                n = int(s.headers.get("Content-Length") or 0)
                if n > 65536: raise E(413, "Request too large")
                body = json.loads(s.rfile.read(n) or b"{}")
                if not isinstance(body, dict): raise E(400, "Bad request")
            c = conn()
            try:
                r = s.route(c, m, p[5:], qs, body); c.commit()
            finally:
                c.close()
            code, data, *ck = r
            s.out(code, data, cookie=ck[0] if ck else None)
        except E as e: s.out(e.code, {"error": e.msg})
        except ValueError: s.out(400, {"error": "Bad request"})
        except Exception: s.out(500, {"error": "Server error"})

    def sid(s):
        m = SimpleCookie(s.headers.get("Cookie", "")).get("tg_session")
        return hashlib.sha256(m.value.encode()).hexdigest() if m else None

    def auth(s, c):
        h = s.sid()
        if h:
            r = c.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.uid WHERE s.h=? AND s.exp>?", (h, int(time.time()))).fetchone()
            if r: return r
        raise E(401, "Please log in.")

    def start(s, c, uid, age):
        tok = secrets.token_urlsafe(32); now = int(time.time())
        c.execute("DELETE FROM sessions WHERE exp<?", (now,))
        c.execute("INSERT INTO sessions VALUES(?,?,?)", (hashlib.sha256(tok.encode()).hexdigest(), uid, now + (age or SHORT)))
        return ckie(tok, age)

    def route(s, c, m, r, qs, b):
        now = int(time.time())
        if (m, r) == ("POST", "register"):
            name, em, pw = str(b.get("name", "")).strip(), str(b.get("email", "")).strip().lower(), str(b.get("password", ""))
            if not 1 <= len(name) <= 80: raise E(400, "Enter your full name.")
            if not EMAIL.match(em): raise E(400, "Enter a valid email address.")
            if pwerr(pw): raise E(400, pwerr(pw))
            if not b.get("terms"): raise E(400, "Accept the Terms and Privacy Policy to continue.")
            if c.execute("SELECT 1 FROM users WHERE email=?", (em,)).fetchone(): raise E(409, "An account with this email already exists.")
            uid = c.execute("INSERT INTO users(email,name,pw,created) VALUES(?,?,?,?)", (em, name, hpw(pw), now)).lastrowid
            return 201, {"user": pub(c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone())}, s.start(c, uid, None)
        if (m, r) == ("POST", "login"):
            em, pw = str(b.get("email", "")).strip().lower(), str(b.get("password", ""))
            key = (s.client_address[0], em)
            with LOCK:
                n, t = FAILS.get(key, (0, now))
                if n >= 5 and now - t < 900: raise E(429, "Too many attempts. Try again in 15 minutes.")
            u = c.execute("SELECT * FROM users WHERE email=?", (em,)).fetchone()
            ok = vpw(pw, u["pw"] if u else DUMMY) and u is not None   # always hash: constant-ish timing
            if not ok:
                with LOCK: n, t = FAILS.get(key, (0, now)); FAILS[key] = (n + 1, t if n else now)
                raise E(401, "Invalid email or password.")
            with LOCK: FAILS.pop(key, None)
            return 200, {"user": pub(u)}, s.start(c, u["id"], LONG if b.get("remember") else None)
        if (m, r) == ("POST", "logout"):
            h = s.sid()
            if h: c.execute("DELETE FROM sessions WHERE h=?", (h,))
            return 200, {"ok": True}, ckie("", 0)
        u = s.auth(c); uid = u["id"]
        if (m, r) == ("GET", "me"): return 200, {"user": pub(u)}
        if (m, r) == ("PATCH", "me"):
            if "name" in b:
                nm = str(b["name"]).strip()
                if not 1 <= len(nm) <= 80: raise E(400, "Enter a name up to 80 characters.")
                c.execute("UPDATE users SET name=? WHERE id=?", (nm, uid))
            if "save_text" in b: c.execute("UPDATE users SET save_text=? WHERE id=?", (1 if b["save_text"] else 0, uid))
            return 200, {"user": pub(c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone())}
        if (m, r) == ("POST", "password"):
            if not vpw(str(b.get("current", "")), u["pw"]): raise E(403, "Current password is incorrect.")
            if pwerr(str(b.get("new", ""))): raise E(400, pwerr(str(b.get("new", ""))))
            c.execute("UPDATE users SET pw=? WHERE id=?", (hpw(str(b["new"])), uid))
            c.execute("DELETE FROM sessions WHERE uid=? AND h<>?", (uid, s.sid()))   # sign out other devices
            return 200, {"ok": True}
        if (m, r) == ("DELETE", "me"):
            if not vpw(str(b.get("password", "")), u["pw"]): raise E(403, "Password is incorrect.")
            c.execute("DELETE FROM users WHERE id=?", (uid,))
            return 200, {"ok": True}, ckie("", 0)
        if (m, r) == ("POST", "analyses"):
            res = b.get("result")
            if not isinstance(res, dict) or res.get("cls") not in ("LIKELY_SCAM", "LIKELY_GENUINE", "NOT_SURE"): raise E(400, "Invalid result.")
            trust = int(res.get("trust"))
            if not 0 <= trust <= 100 or len(json.dumps(res)) > 20000: raise E(400, "Invalid result.")
            text = re.sub(r"\d{4,}", lambda x: "•" * len(x.group()), str(b.get("text", ""))[:2000]) if u["save_text"] else ""
            i = c.execute("INSERT INTO analyses(uid,at,kind,cls,cat,trust,text,result) VALUES(?,?,?,?,?,?,?,?)",
                          (uid, now, "Screenshot" if b.get("kind") == "Screenshot" else "Text", res["cls"], str(res.get("cat", ""))[:60],
                           trust, text, json.dumps(res))).lastrowid
            return 201, {"id": i}
        if (m, r) == ("GET", "analyses"):
            size = max(1, min(50, int(qs.get("size", 8)))); pg = max(1, int(qs.get("page", 1)))
            tot = c.execute("SELECT COUNT(*) FROM analyses WHERE uid=?", (uid,)).fetchone()[0]
            rows = c.execute("SELECT id,at,kind,cls,cat,trust FROM analyses WHERE uid=? ORDER BY at DESC,id DESC LIMIT ? OFFSET ?",
                             (uid, size, (pg - 1) * size)).fetchall()
            return 200, {"rows": [dict(x) for x in rows], "total": tot, "pages": max(1, -(-tot // size))}
        if (m, r) == ("DELETE", "analyses"):
            c.execute("DELETE FROM analyses WHERE uid=?", (uid,)); return 200, {"ok": True}
        mm = re.fullmatch(r"analyses/(\d+)", r)
        if m == "GET" and mm:
            x = c.execute("SELECT * FROM analyses WHERE id=? AND uid=?", (mm.group(1), uid)).fetchone()   # owner-only
            if not x: raise E(404, "Analysis not found.")
            return 200, {"id": x["id"], "at": x["at"], "kind": x["kind"], "text": x["text"], "result": json.loads(x["result"])}
        if (m, r) == ("GET", "dashboard"):
            cnt = {x["cls"]: x["n"] for x in c.execute("SELECT cls,COUNT(*) n FROM analyses WHERE uid=? GROUP BY cls", (uid,))}
            cats = [dict(x) for x in c.execute("SELECT cat,COUNT(*) n FROM analyses WHERE uid=? AND cls='LIKELY_SCAM' GROUP BY cat ORDER BY n DESC LIMIT 8", (uid,))]
            since = now - 14 * 86400; per = {}
            for x in c.execute("SELECT at FROM analyses WHERE uid=? AND at>=?", (uid, since)):
                d = time.strftime("%Y-%m-%d", time.gmtime(x["at"])); per[d] = per.get(d, 0) + 1
            act = [{"d": (d := time.strftime("%Y-%m-%d", time.gmtime(now - k * 86400))), "n": per.get(d, 0)} for k in range(13, -1, -1)]
            recent = [dict(x) for x in c.execute("SELECT id,at,kind,cls,cat,trust FROM analyses WHERE uid=? ORDER BY at DESC,id DESC LIMIT 5", (uid,))]
            rep = c.execute("SELECT COUNT(*) FROM reports WHERE uid=? AND status<>'Withdrawn'", (uid,)).fetchone()[0]
            comm = []
            for x in c.execute("SELECT sender,cat,status FROM reports WHERE uid=? AND status<>'Withdrawn' ORDER BY at DESC LIMIT 5", (uid,)):
                n = eligible(c, x["sender"])   # masked: only senders this user reported, last 4 digits only
                comm.append({"sender": "••••••" + x["sender"][-4:], "count": n, "cat": x["cat"], "status": x["status"], "alert": n >= ALERT_AT})
            return 200, {"total": sum(cnt.values()), "scam": cnt.get("LIKELY_SCAM", 0), "genuine": cnt.get("LIKELY_GENUINE", 0),
                         "notsure": cnt.get("NOT_SURE", 0), "reports": rep, "cats": cats, "activity": act, "recent": recent, "community": comm}
        if (m, r) == ("GET", "community"):
            sd = qs.get("sender", "")
            if not re.fullmatch(r"\d{10}", sd): raise E(400, "Enter a 10-digit phone number.")
            n = eligible(c, sd)
            mine = c.execute("SELECT 1 FROM reports WHERE sender=? AND uid=? AND status<>'Withdrawn'", (sd, uid)).fetchone()
            return 200, {"count": n, "alert": n >= ALERT_AT, "mine": bool(mine)}
        if (m, r) == ("POST", "reports"):
            sd, cat = str(b.get("sender", "")), str(b.get("cat", ""))[:60]
            if not re.fullmatch(r"\d{10}", sd) or not cat: raise E(400, "Enter a 10-digit phone number and a category.")
            x = c.execute("SELECT id,status FROM reports WHERE sender=? AND uid=?", (sd, uid)).fetchone()
            if x and x["status"] != "Withdrawn": raise E(409, "You already reported this sender.")
            if x: c.execute("UPDATE reports SET status='Pending',cat=?,at=? WHERE id=?", (cat, now, x["id"]))
            else: c.execute("INSERT INTO reports(uid,sender,cat,at) VALUES(?,?,?,?)", (uid, sd, cat, now))
            return 201, {"ok": True}
        if (m, r) == ("GET", "reports"):
            return 200, {"rows": [dict(x) for x in c.execute("SELECT id,sender,cat,status,at FROM reports WHERE uid=? AND status<>'Withdrawn' ORDER BY at DESC", (uid,))]}
        if (m, r) == ("DELETE", "reports"):
            if qs.get("id", "").isdigit(): c.execute("UPDATE reports SET status='Withdrawn' WHERE id=? AND uid=?", (qs["id"], uid))
            else: c.execute("UPDATE reports SET status='Withdrawn' WHERE sender=? AND uid=?", (qs.get("sender", ""), uid))
            return 200, {"ok": True}
        raise E(404, "Not found")

if __name__ == "__main__":
    migrate()
    print(f"TruthGuard AI on http://{HOST}:{PORT}  (db: {DBP})")
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()
