"""Users, roles, sessions and API tokens.

Roles (what a person may do):
  viewer   read everything
  analyst  viewer + triage alerts, work cases, classify events, import data
  admin    analyst + users, tokens of others, settings, detections tuning, deleting data
API tokens belong to a user and carry their own permission (view, modify, full). The effective level is the
lower of the two, so a token can never do more than its owner.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time

from . import db

ROLES = {"viewer": 1, "analyst": 2, "admin": 3}
ROLE_TEXT = {"viewer": "Read everything", "analyst": "Triage alerts, work cases, classify events, import data",
             "admin": "Everything, including users, settings and deleting data"}
TOKEN_PERMS = {"view": 1, "modify": 2, "full": 3}
LEVEL_NAME = {1: "viewer", 2: "analyst", 3: "admin"}
COOKIE = "siem_session"
USERNAME_RX = re.compile(r"^[A-Za-z0-9._@-]{2,40}$")
MAX_SESSION_DAYS = 30
LOCK_AFTER, LOCK_MINUTES = 5, 5

POLICY_DEFAULT = {"session_hours": 8, "tokens_enabled": True, "token_default_days": 90,
                  "token_max_days": 365, "min_password_length": 10}

_cur = threading.local()


class AuthError(Exception):
    def __init__(self, code, msg):
        self.code, self.msg = code, msg


def set_current(user):
    _cur.user = user


def current_name():
    u = getattr(_cur, "user", None)
    return (u["display_name"] or u["username"]) if u else db.get_settings().get("analyst", "analyst")


def _now():
    return db.now_ms()


# ------------------------------------------------------------------ passwords
def hash_pw(pw):
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${h.hex()}"


def verify_pw(pw, stored):
    try:
        _, n, r, p, salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(calc.hex(), h)
    except (ValueError, TypeError):
        return False


_DUMMY = None


def _check_password_rules(pw, username=""):
    pol = get_policy()
    if not isinstance(pw, str) or len(pw) < pol["min_password_length"]:
        raise ValueError(f"The password needs at least {pol['min_password_length']} characters")
    if len(pw) > 200:
        raise ValueError("The password is too long")
    if username and pw.lower() == username.lower():
        raise ValueError("The password must differ from the username")


# ------------------------------------------------------------------ policy and backend connection
def _get_private(key, default):
    r = db.conn().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    if r:
        try:
            v = json.loads(r["value"])
            if isinstance(v, dict):
                return {**default, **v}
        except ValueError:
            pass
    return dict(default)


def _put_private(key, value):
    db.conn().execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?,?)", (key, json.dumps(value)))
    db.conn().commit()


def get_policy():
    return _get_private("_auth_policy", POLICY_DEFAULT)


def put_policy(new):
    cur = get_policy()

    def num(k, lo, hi):
        if k in new:
            try:
                v = int(new[k])
            except (TypeError, ValueError):
                raise ValueError(f"{k} must be a whole number")
            if not lo <= v <= hi:
                raise ValueError(f"{k} must be between {lo} and {hi}")
            cur[k] = v
    num("session_hours", 1, 168)
    num("token_default_days", 1, 3650)
    num("token_max_days", 0, 3650)  # 0 = no upper limit
    num("min_password_length", 8, 128)
    if "tokens_enabled" in new:
        cur["tokens_enabled"] = bool(new["tokens_enabled"])
    if cur["token_max_days"] and cur["token_default_days"] > cur["token_max_days"]:
        cur["token_default_days"] = cur["token_max_days"]
    _put_private("_auth_policy", cur)
    return cur


def check_backend_url(value):
    u = str(value or "").strip().rstrip("/")
    if u and not re.match(r"^(https://[^/\s]+|http://(127\.0\.0\.1|localhost)(:\d+)?)(/\S*)?$", u):
        raise ValueError("The backend URL must start with https:// (http:// is only accepted for localhost)")
    return u


def get_backend():
    b = _get_private("_backend", {"base_url": "", "token": ""})
    return {"base_url": b["base_url"], "token_set": bool(b["token"]), "token_preview": b["token"][-4:] if len(b["token"]) > 12 else ""}


def backend_secret():
    """For the future sync job only; never sent to the browser."""
    return _get_private("_backend", {"base_url": "", "token": ""})


def put_backend(new):
    cur = _get_private("_backend", {"base_url": "", "token": ""})
    if "base_url" in new:
        cur["base_url"] = check_backend_url(new["base_url"])
    if new.get("clear_token"):
        cur["token"] = ""
    elif str(new.get("token", "")).strip():
        t = str(new["token"]).strip()
        if len(t) < 8 or len(t) > 500 or re.search(r"\s", t):
            raise ValueError("That does not look like a token")
        cur["token"] = t
    _put_private("_backend", cur)
    return get_backend()


# ------------------------------------------------------------------ audit
# Append-only. Every row carries a hash over its own content and the previous row's hash, so an edited or
# removed row breaks the chain and verify_audit() reports where. This catches mistakes and casual edits; someone
# with write access to the database file could recompute the chain, so it is evidence, not a vault.
def current_actor():
    u = getattr(_cur, "user", None)
    return u["username"] if u else "system"


def _via():
    u = getattr(_cur, "user", None)
    if not u:
        return ""
    return f"token #{u['token_id']}" if u["via"] == "token" else "session"


def _digest(prev, ts, actor, via, action, target, detail):
    return hashlib.sha256((prev + "|" + json.dumps([ts, actor, via, action, target, detail], ensure_ascii=False)).encode()).hexdigest()


def log(actor, action, detail="", target="", via=None):
    """Record one action. Joins the caller's open transaction if there is one (so the entry commits or rolls back
    with the change it describes), otherwise commits on its own."""
    c = db.conn()
    own = not c.in_transaction
    if own:
        c.execute("BEGIN IMMEDIATE")
    try:
        prev = c.execute("SELECT hash FROM audit WHERE hash IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
        prev = prev[0] if prev else ""
        ts, actor, action = _now(), str(actor)[:60], str(action)[:40]
        target, detail = str(target)[:80], str(detail)[:400]
        via = _via() if via is None else via
        c.execute("INSERT INTO audit(ts, actor, via, action, target, detail, hash) VALUES(?,?,?,?,?,?,?)",
                  (ts, actor, via, action, target, detail, _digest(prev, ts, actor, via, action, target, detail)))
        if own:
            c.commit()
    except Exception:
        if own:
            c.rollback()
        raise


def _audit_where(p):
    where, args = [], []
    one = lambda k: (p.get(k) or [""])[0].strip()
    if one("q"):
        like = "%" + one("q").replace("%", "").replace("_", "") + "%"
        where.append("(actor LIKE ? OR action LIKE ? OR target LIKE ? OR detail LIKE ?)")
        args += [like] * 4
    if one("actor"):
        where.append("actor=?"); args.append(one("actor"))
    if one("action"):
        a = one("action")
        if a.endswith("."):
            where.append("action LIKE ?"); args.append(a + "%")
        else:
            where.append("action=?"); args.append(a)
    import datetime
    for k, op, add in (("from", ">=", 0), ("to", "<", 86400000)):
        if one(k):
            try:
                d = datetime.datetime.strptime(one(k), "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
            except ValueError:
                raise ValueError(f"'{k}' must be a date like 2026-10-14")
            where.append(f"ts {op} ?"); args.append(int(d.timestamp() * 1000) + add)
    return (" WHERE " + " AND ".join(where)) if where else "", args


def audit_list(p):
    c = db.conn()
    w, args = _audit_where(p)
    page = max(1, int((p.get("page") or ["1"])[0] or 1))
    size = min(500, max(10, int((p.get("size") or ["100"])[0] or 100)))
    total = c.execute("SELECT COUNT(*) FROM audit" + w, args).fetchone()[0]
    rows = [dict(r) for r in c.execute(f"SELECT id, ts, actor, via, action, target, detail FROM audit{w} ORDER BY id DESC LIMIT ? OFFSET ?", (*args, size, (page - 1) * size))]
    return {"total": total, "page": page, "size": size, "rows": rows,
            "actors": [r[0] for r in c.execute("SELECT DISTINCT actor FROM audit ORDER BY actor COLLATE NOCASE")],
            "actions": [r[0] for r in c.execute("SELECT DISTINCT action FROM audit ORDER BY action")]}


def audit_iter(p):
    w, args = _audit_where(p)
    return db.conn().execute(f"SELECT id, ts, actor, via, action, target, detail FROM audit{w} ORDER BY id DESC", args)


def verify_audit():
    c = db.conn()
    prev, checked, legacy = "", 0, 0
    for r in c.execute("SELECT * FROM audit ORDER BY id"):
        if r["hash"] is None:
            legacy += 1
            continue
        if _digest(prev, r["ts"], r["actor"], r["via"] or "", r["action"], r["target"] or "", r["detail"] or "") != r["hash"]:
            return {"ok": False, "checked": checked, "legacy": legacy, "broken_at": r["id"], "head": prev}
        prev = r["hash"]
        checked += 1
    return {"ok": True, "checked": checked, "legacy": legacy, "broken_at": None, "head": prev}


# ------------------------------------------------------------------ users
def _public(r):
    return {"id": r["id"], "username": r["username"], "display_name": r["display_name"] or "", "role": r["role"],
            "active": bool(r["active"]), "created_at": r["created_at"], "last_login": r["last_login"]}


def user_count():
    return db.conn().execute("SELECT COUNT(*) FROM users").fetchone()[0]


def _admins_left(excluding=None):
    q = "SELECT COUNT(*) FROM users WHERE role='admin' AND active=1"
    a = ()
    if excluding:
        q += " AND id<>?"
        a = (excluding,)
    return db.conn().execute(q, a).fetchone()[0]


def _clean_user_fields(body, creating):
    out = {}
    if creating or "username" in body:
        u = str(body.get("username", "")).strip()
        if not USERNAME_RX.match(u):
            raise ValueError("The username needs 2 to 40 characters: letters, digits and . _ @ -")
        out["username"] = u
    if "display_name" in body or creating:
        out["display_name"] = str(body.get("display_name", "")).strip()[:60]
    if "role" in body or creating:
        if body.get("role") not in ROLES:
            raise ValueError("The role must be viewer, analyst or admin")
        out["role"] = body["role"]
    return out


def create_user(body, actor="system"):
    f = _clean_user_fields(body, True)
    _check_password_rules(body.get("password"), f["username"])
    c = db.conn()
    if c.execute("SELECT 1 FROM users WHERE username=?", (f["username"],)).fetchone():
        raise ValueError("That username is already taken")
    cur = c.execute("INSERT INTO users(username, display_name, role, pw_hash, active, created_at) VALUES(?,?,?,?,1,?)",
                    (f["username"], f["display_name"], f["role"], hash_pw(body["password"]), _now()))
    c.commit()
    log(actor, "user.create", f"{f['username']} as {f['role']}", target=f"user:{cur.lastrowid}")
    return _public(c.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone())


def _get(uid):
    r = db.conn().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not r:
        raise AuthError(404, "user not found")
    return r


def update_user(uid, body, actor):
    c = db.conn()
    cur = _get(uid)
    f = _clean_user_fields(body, False)
    if "username" in f and f["username"].lower() != cur["username"].lower() \
            and c.execute("SELECT 1 FROM users WHERE username=? AND id<>?", (f["username"], uid)).fetchone():
        raise ValueError("That username is already taken")
    new_role = f.get("role", cur["role"])
    new_active = bool(body["active"]) if "active" in body else bool(cur["active"])
    if cur["role"] == "admin" and cur["active"] and (new_role != "admin" or not new_active) and _admins_left(uid) == 0:
        raise ValueError("This is the last active administrator. Make someone else an administrator first.")
    sets, args = [], []
    for k, v in f.items():
        sets.append(f"{k}=?"); args.append(v)
    sets.append("active=?"); args.append(1 if new_active else 0)
    revoke = not new_active or new_role != cur["role"]
    if body.get("password"):
        _check_password_rules(body["password"], f.get("username", cur["username"]))
        sets.append("pw_hash=?"); args.append(hash_pw(body["password"]))
        sets.append("failed=0"); sets.append("locked_until=0")
        revoke = True
    if body.get("unlock"):
        sets.append("failed=0"); sets.append("locked_until=0")
    c.execute(f"UPDATE users SET {', '.join(sets)} WHERE id=?", (*args, uid))
    if revoke:
        c.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
    c.commit()
    changes = [k for k in ("username", "display_name", "role") if k in f and f[k] != cur[k]]
    if new_active != bool(cur["active"]):
        changes.append("active" if new_active else "deactivated")
    if body.get("password"):
        changes.append("password reset")
    log(actor, "user.update", f"{cur['username']}: {', '.join(changes) or 'no change'}", target=f"user:{uid}")
    return _public(_get(uid))


def delete_user(uid, actor_user):
    c = db.conn()
    cur = _get(uid)
    if uid == actor_user["id"]:
        raise ValueError("You cannot delete your own account")
    if cur["role"] == "admin" and cur["active"] and _admins_left(uid) == 0:
        raise ValueError("This is the last active administrator")
    c.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
    c.execute("DELETE FROM api_tokens WHERE user_id=?", (uid,))
    c.execute("DELETE FROM users WHERE id=?", (uid,))
    c.commit()
    log(actor_user["username"], "user.delete", cur["username"], target=f"user:{uid}")
    return {"ok": True}


def list_users():
    now = _now()
    out = []
    for r in db.conn().execute("SELECT * FROM users ORDER BY username COLLATE NOCASE"):
        u = _public(r)
        u["locked"] = (r["locked_until"] or 0) > now
        u["tokens"] = db.conn().execute("SELECT COUNT(*) FROM api_tokens WHERE user_id=? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>?)", (r["id"], now)).fetchone()[0]
        out.append(u)
    return out


def user_names():
    return [r["username"] for r in db.conn().execute("SELECT username FROM users WHERE active=1 ORDER BY username COLLATE NOCASE")]


def change_password(user, body, keep_session=None):
    r = _get(user["id"])
    if not verify_pw(str(body.get("old_password", "")), r["pw_hash"]):
        raise ValueError("The current password is wrong")
    _check_password_rules(body.get("new_password"), r["username"])
    c = db.conn()
    c.execute("UPDATE users SET pw_hash=? WHERE id=?", (hash_pw(body["new_password"]), user["id"]))
    c.execute("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (user["id"], keep_session or ""))
    c.commit()
    log(r["username"], "password.change", "", target=f"user:{r['id']}")
    return {"ok": True}


# ------------------------------------------------------------------ login and sessions
def _sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def setup_first_admin(body):
    if user_count():
        raise AuthError(403, "Setup is already done")
    body = dict(body, role="admin")
    u = create_user(body, actor="setup")
    log("setup", "setup.admin", f"first administrator {u['username']}", target=f"user:{u['id']}")
    return u


def login(username, password):
    global _DUMMY
    c = db.conn()
    r = c.execute("SELECT * FROM users WHERE username=?", (str(username).strip(),)).fetchone()
    now = _now()
    if r and (r["locked_until"] or 0) > now:
        mins = int(((r["locked_until"] - now) / 60000) + 1)
        raise AuthError(429, f"Too many failed attempts. Try again in {mins} minute{'s' if mins > 1 else ''}.")
    if not r:  # spend the same time as a real check so the response does not reveal which usernames exist
        _DUMMY = _DUMMY or hash_pw("dummy-password")
        verify_pw(str(password), _DUMMY)
    ok = bool(r) and r["active"] and verify_pw(str(password), r["pw_hash"])
    if not ok:
        if not r:
            log(str(username).strip()[:60] or "(empty)", "login.failed", "unknown user", via="")
        if r:
            failed = (r["failed"] or 0) + 1
            lock = now + LOCK_MINUTES * 60000 if failed >= LOCK_AFTER else 0
            c.execute("UPDATE users SET failed=?, locked_until=? WHERE id=?", (0 if lock else failed, lock, r["id"]))
            c.commit()
            log(r["username"], "login.failed", "account locked for 5 minutes" if lock else ("account inactive" if not r["active"] else "wrong password"), via="")
        raise AuthError(401, "Wrong username or password")
    c.execute("UPDATE users SET failed=0, locked_until=0, last_login=? WHERE id=?", (now, r["id"]))
    c.execute("DELETE FROM sessions WHERE expires_at<?", (now,))
    raw = secrets.token_urlsafe(32)
    hours = get_policy()["session_hours"]
    c.execute("INSERT INTO sessions(token_hash, user_id, created_at, last_seen, expires_at) VALUES(?,?,?,?,?)",
              (_sha(raw), r["id"], now, now, now + hours * 3600000))
    c.commit()
    log(r["username"], "login", "", via="")
    return raw, hours * 3600


def logout(raw):
    if raw:
        db.conn().execute("DELETE FROM sessions WHERE token_hash=?", (_sha(raw),))
        db.conn().commit()


def _user_dict(r, level, via, **kw):
    return {"id": r["id"], "username": r["username"], "display_name": r["display_name"] or "", "role": r["role"],
            "level": level, "via": via, **kw}


def identify(headers):
    """Return the caller (dict) or None. Bearer token wins over cookie."""
    c = db.conn()
    now = _now()
    authz = headers.get("Authorization") or ""
    if authz.lower().startswith("bearer "):
        raw = authz[7:].strip()
        t = c.execute("SELECT * FROM api_tokens WHERE token_hash=?", (_sha(raw),)).fetchone()
        if not t or t["revoked_at"] or (t["expires_at"] and t["expires_at"] < now) or not get_policy()["tokens_enabled"]:
            return None
        u = c.execute("SELECT * FROM users WHERE id=?", (t["user_id"],)).fetchone()
        if not u or not u["active"]:
            return None
        if now - (t["last_used"] or 0) > 60000:
            c.execute("UPDATE api_tokens SET last_used=? WHERE id=?", (now, t["id"]))
            c.commit()
        return _user_dict(u, min(ROLES[u["role"]], TOKEN_PERMS.get(t["perm"], 1)), "token", token_id=t["id"])
    m = re.search(r"(?:^|;\s*)" + COOKIE + r"=([^;]+)", headers.get("Cookie") or "")
    if not m:
        return None
    h = _sha(m.group(1))
    s = c.execute("SELECT * FROM sessions WHERE token_hash=?", (h,)).fetchone()
    if not s or s["expires_at"] < now or now - s["created_at"] > MAX_SESSION_DAYS * 86400000:
        if s:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (h,)); c.commit()
        return None
    u = c.execute("SELECT * FROM users WHERE id=?", (s["user_id"],)).fetchone()
    if not u or not u["active"]:
        return None
    if now - s["last_seen"] > 60000:
        c.execute("UPDATE sessions SET last_seen=?, expires_at=? WHERE token_hash=?", (now, now + get_policy()["session_hours"] * 3600000, h))
        c.commit()
    return _user_dict(u, ROLES[u["role"]], "session", session=h)


def me(u):
    return {"id": u["id"], "username": u["username"], "display_name": u["display_name"], "role": u["role"], "level": u["level"], "via": u["via"]}


# ------------------------------------------------------------------ API tokens
def _token_row(r, owner=None):
    now = _now()
    state = "revoked" if r["revoked_at"] else ("expired" if r["expires_at"] and r["expires_at"] < now else "active")
    d = {"id": r["id"], "name": r["name"], "preview": r["preview"], "perm": r["perm"], "created_at": r["created_at"],
         "expires_at": r["expires_at"], "last_used": r["last_used"], "state": state}
    if owner is not None:
        d["owner"] = owner
    return d


def create_token(user, body):
    pol = get_policy()
    if not pol["tokens_enabled"]:
        raise ValueError("API tokens are switched off by the administrator")
    name = str(body.get("name", "")).strip()[:60]
    if not name:
        raise ValueError("Give the token a name so you know what it is used for")
    perm = body.get("perm", "view")
    if perm not in TOKEN_PERMS:
        raise ValueError("The permission must be view, modify or full")
    if TOKEN_PERMS[perm] > ROLES[user["role"]]:
        raise ValueError(f"A {user['role']} cannot create a token with the {perm!r} permission")
    days = body.get("expires_days", pol["token_default_days"])
    try:
        days = int(days)
    except (TypeError, ValueError):
        raise ValueError("The lifetime must be a whole number of days")
    mx = pol["token_max_days"]
    if days == 0 and mx:
        raise ValueError(f"Tokens must expire. The longest allowed lifetime is {mx} days")
    if days < 0 or (mx and days > mx):
        raise ValueError(f"The lifetime must be between 1 and {mx or 3650} days")
    now = _now()
    raw = "ids_" + secrets.token_urlsafe(32)
    c = db.conn()
    cur = c.execute("INSERT INTO api_tokens(user_id, name, token_hash, preview, perm, created_at, expires_at) VALUES(?,?,?,?,?,?,?)",
                    (user["id"], name, _sha(raw), raw[-4:], perm, now, now + days * 86400000 if days else None))
    c.commit()
    log(user["username"], "token.create", f"{name} ({perm}, {days or 'no'} days)", target=f"token:{cur.lastrowid}")
    return {**_token_row(c.execute("SELECT * FROM api_tokens WHERE id=?", (cur.lastrowid,)).fetchone()), "token": raw}


def list_tokens(user, all_users=False):
    c = db.conn()
    if all_users:
        rows = c.execute("SELECT t.*, u.username AS owner FROM api_tokens t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC").fetchall()
        return [_token_row(r, r["owner"]) for r in rows]
    return [_token_row(r) for r in c.execute("SELECT * FROM api_tokens WHERE user_id=? ORDER BY id DESC", (user["id"],))]


def revoke_token(user, tid):
    c = db.conn()
    t = c.execute("SELECT t.*, u.username AS owner FROM api_tokens t JOIN users u ON u.id=t.user_id WHERE t.id=?", (tid,)).fetchone()
    if not t or (t["user_id"] != user["id"] and user["role"] != "admin"):
        raise AuthError(404, "token not found")
    c.execute("UPDATE api_tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (_now(), tid))
    c.commit()
    log(user["username"], "token.revoke", f"{t['name']} of {t['owner']}", target=f"token:{tid}")
    return {"ok": True}
