"""Second factor for sign-in: authenticator-app codes (TOTP, RFC 6238), passkeys (WebAuthn) and recovery codes.

* TOTP: SHA-1, 6 digits, 30 seconds, one step of clock drift either way, a code can be used once.
* Passkeys: sign in on their own (they are discoverable and require user verification, so they count as both
  factors) or answer the second step after the password. Only usable at http://localhost:PORT because a
  WebAuthn relying-party id must be a domain name, not an IP address.
* Recovery codes: ten single-use codes, stored as hashes, shown once.
Failed codes count towards the same lock-out as wrong passwords.
"""
import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
import threading
import time
from urllib.parse import quote

from . import auth, db, qr, webauthn as wa

ISSUER = "Fleet IDS SIEM"
RP_ID = "localhost"
LOGIN_TTL_MS = 5 * 60000
CHALLENGE_TTL_MS = 2 * 60000
MAX_TRIES = 5
RECOVERY_COUNT = 10

_lock = threading.Lock()
_PENDING = {}    # sha256(mfa_token) -> {uid, exp, tries}
_CHAL = {}       # challenge -> {kind, uid, exp, pending}


def _now():
    return int(time.time() * 1000)


def _sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def _purge(store):
    now = _now()
    for k in [k for k, v in store.items() if v["exp"] < now]:
        del store[k]
    while len(store) > 500:
        store.pop(next(iter(store)))


# ---------------------------------------------------------------- state
def _rows(uid, kind=None, confirmed=1):
    q = "SELECT * FROM mfa_creds WHERE user_id=? AND confirmed=?"
    a = [uid, confirmed]
    if kind:
        q += " AND kind=?"; a.append(kind)
    return db.conn().execute(q + " ORDER BY id", a).fetchall()


def has_mfa(uid):
    return db.conn().execute("SELECT 1 FROM mfa_creds WHERE user_id=? AND confirmed=1 LIMIT 1", (uid,)).fetchone() is not None


def recovery_left(uid):
    return db.conn().execute("SELECT COUNT(*) FROM mfa_recovery WHERE user_id=? AND used_at IS NULL", (uid,)).fetchone()[0]


def methods(uid):
    m = []
    if _rows(uid, "totp"):
        m.append("totp")
    if _rows(uid, "passkey"):
        m.append("passkey")
    if m and recovery_left(uid):
        m.append("recovery")
    return m


def status(user, host=""):
    uid = user["id"]
    pk = [{"id": r["id"], "name": r["name"], "created_at": r["created_at"], "last_used": r["last_used"]} for r in _rows(uid, "passkey")]
    t = _rows(uid, "totp")
    ok, why = passkey_available(host)
    return {"enabled": has_mfa(uid), "totp": bool(t), "totp_since": t[0]["created_at"] if t else None, "passkeys": pk,
            "recovery_left": recovery_left(uid), "required": bool(auth.get_policy().get("mfa_required")),
            "passkey_ok": ok, "passkey_hint": why}


def reauth(user, password):
    """Sensitive changes ask for the password again, so a stolen session cannot weaken the account quietly."""
    r = auth._get(user["id"])
    auth.check_locked(r)
    if not auth.verify_pw(str(password or ""), r["pw_hash"]):
        auth.register_failure(r, "wrong password (re-check for a security change)")
        raise ValueError("The password is wrong")
    return r


# ---------------------------------------------------------------- recovery codes
def _norm_code(c):
    return re.sub(r"[^a-z0-9]", "", str(c).lower())


def new_recovery_codes(uid):
    c = db.conn()
    c.execute("DELETE FROM mfa_recovery WHERE user_id=?", (uid,))
    codes = []
    for _ in range(RECOVERY_COUNT):
        raw = secrets.token_hex(5)
        codes.append(raw[:5] + "-" + raw[5:])
        c.execute("INSERT INTO mfa_recovery(user_id, code_hash) VALUES(?,?)", (uid, _sha(_norm_code(raw))))
    c.commit()
    return codes


def _use_recovery(uid, code):
    h = _sha(_norm_code(code))
    r = db.conn().execute("SELECT id FROM mfa_recovery WHERE user_id=? AND code_hash=? AND used_at IS NULL", (uid, h)).fetchone()
    if not r:
        return False
    db.conn().execute("UPDATE mfa_recovery SET used_at=? WHERE id=?", (_now(), r["id"]))
    db.conn().commit()
    return True


def regenerate_recovery(user, password):
    r = reauth(user, password)
    if not has_mfa(user["id"]):
        raise ValueError("Set up an authenticator app or a passkey first")
    codes = new_recovery_codes(user["id"])
    auth.log(r["username"], "mfa.recovery", "new recovery codes created, the old ones no longer work", target=f"user:{r['id']}")
    return {"recovery_codes": codes}


# ---------------------------------------------------------------- TOTP
def _hotp(secret, counter):
    d = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = d[-1] & 15
    return "%06d" % ((struct.unpack(">I", d[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def _secret_bytes(b32):
    return base64.b32decode(b32 + "=" * (-len(b32) % 8))


def totp_begin(user, password):
    r = reauth(user, password)
    if _rows(user["id"], "totp"):
        raise ValueError("An authenticator app is already set up. Remove it first to set up another.")
    c = db.conn()
    c.execute("DELETE FROM mfa_creds WHERE user_id=? AND kind='totp' AND confirmed=0", (user["id"],))
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
    c.execute("INSERT INTO mfa_creds(user_id, kind, name, data, created_at, confirmed) VALUES(?,?,?,?,?,0)",
              (user["id"], "totp", "Authenticator app", json.dumps({"secret": secret, "last": 0}), _now()))
    c.commit()
    uri = f"otpauth://totp/{quote(ISSUER)}:{quote(r['username'])}?secret={secret}&issuer={quote(ISSUER)}"
    return {"secret": " ".join(secret[i:i + 4] for i in range(0, len(secret), 4)), "uri": uri, "qr": qr.encode(uri)}


def _check_totp_row(row, code):
    d = json.loads(row["data"])
    code = re.sub(r"\s", "", str(code))
    if not re.fullmatch(r"\d{6}", code):
        return False
    t = int(time.time()) // 30
    sec = _secret_bytes(d["secret"])
    for off in (0, -1, 1):
        n = t + off
        if n > d.get("last", 0) and hmac.compare_digest(_hotp(sec, n), code):
            d["last"] = n
            db.conn().execute("UPDATE mfa_creds SET data=?, last_used=? WHERE id=?", (json.dumps(d), _now(), row["id"]))
            db.conn().commit()
            return True
    return False


def totp_confirm(user, code):
    row = _rows(user["id"], "totp", confirmed=0)
    if not row:
        raise ValueError("Start the setup again")
    r = auth._get(user["id"])
    auth.check_locked(r)
    if not _check_totp_row(row[0], code):
        auth.register_failure(r, "wrong code while setting up the authenticator app")
        raise ValueError("That code is not right. Check the clock on your phone and try the next code.")
    first = not has_mfa(user["id"])
    db.conn().execute("UPDATE mfa_creds SET confirmed=1 WHERE id=?", (row[0]["id"],))
    db.conn().commit()
    auth.log(r["username"], "mfa.totp.add", "authenticator app set up", target=f"user:{r['id']}")
    return {"recovery_codes": new_recovery_codes(user["id"]) if first else None}


def _guard_last_factor(uid):
    if auth.get_policy().get("mfa_required") and len(_rows(uid)) <= 1:
        raise ValueError("Your administrator requires two-step sign-in. Add another method before removing this one.")


def totp_remove(user, password):
    r = reauth(user, password)
    if not _rows(user["id"], "totp"):
        raise ValueError("No authenticator app is set up")
    _guard_last_factor(user["id"])
    db.conn().execute("DELETE FROM mfa_creds WHERE user_id=? AND kind='totp'", (user["id"],))
    _cleanup(user["id"])
    auth.log(r["username"], "mfa.totp.remove", "authenticator app removed", target=f"user:{r['id']}")
    return {"ok": True}


def _cleanup(uid):
    c = db.conn()
    if not c.execute("SELECT 1 FROM mfa_creds WHERE user_id=? AND confirmed=1", (uid,)).fetchone():
        c.execute("DELETE FROM mfa_recovery WHERE user_id=?", (uid,))
    c.commit()


# ---------------------------------------------------------------- second step of a sign-in
def begin_login(uid):
    token = secrets.token_urlsafe(24)
    with _lock:
        _purge(_PENDING)
        _PENDING[_sha(token)] = {"uid": uid, "exp": _now() + LOGIN_TTL_MS, "tries": 0}
    return {"mfa_required": True, "mfa_token": token, "methods": methods(uid)}


def _pending(token):
    p = _PENDING.get(_sha(str(token or "")))
    if not p or p["exp"] < _now():
        raise auth.AuthError(401, "The sign-in took too long. Start again.")
    return p


def complete_code(token, code):
    """Second step with an authenticator code or a recovery code. Returns (cookie value, seconds)."""
    with _lock:
        p = _pending(token)
        r = auth._get(p["uid"])
        auth.check_locked(r)
        code = str(code or "").strip()
        digits = re.sub(r"\s", "", code)
        how = None
        if re.fullmatch(r"\d{6}", digits):
            for row in _rows(r["id"], "totp"):
                if _check_totp_row(row, digits):
                    how = "password and authenticator code"
        elif _use_recovery(r["id"], code):
            how = "password and recovery code"
            left = recovery_left(r["id"])
        if how:
            del _PENDING[_sha(token)]
            if how.endswith("recovery code"):
                auth.log(r["username"], "mfa.recovery.used", f"{left} recovery code(s) left", target=f"user:{r['id']}", via="")
            return auth.start_session(r, how)
        p["tries"] += 1
        auth.register_failure(r, "wrong authentication code")
        if p["tries"] >= MAX_TRIES:
            del _PENDING[_sha(token)]
        raise auth.AuthError(401, "That code is not right")


# ---------------------------------------------------------------- passkeys
def passkey_available(host):
    h = (host or "").rsplit(":", 1)[0] if not (host or "").startswith("[") else "[::1]"
    if h == RP_ID:
        return True, ""
    return False, "Passkeys need the address http://localhost:PORT (you opened the tool with an IP address). Open it as localhost."


def _origin(host):
    ok, why = passkey_available(host)
    if not ok:
        raise ValueError(why)
    return f"http://{host}"


def _new_challenge(kind, uid=None, pending=None):
    ch = wa.b64u(secrets.token_bytes(32))
    with _lock:
        _purge(_CHAL)
        _CHAL[ch] = {"kind": kind, "uid": uid, "pending": pending, "exp": _now() + CHALLENGE_TTL_MS}
    return ch


def _take_challenge(ch, kind):
    with _lock:
        v = _CHAL.pop(ch, None)
    if not v or v["exp"] < _now() or v["kind"] != kind:
        raise wa.WebAuthnError("challenge expired or unknown")
    return v


def _handle(uid):
    return wa.b64u(hashlib.sha256(f"fleet-ids-user-{uid}".encode()).digest())


def passkey_register_options(user, password, host):
    r = reauth(user, password)
    _origin(host)
    ch = _new_challenge("create", user["id"])
    return {"publicKey": {
        "rp": {"name": ISSUER, "id": RP_ID},
        "user": {"id": _handle(r["id"]), "name": r["username"], "displayName": r["display_name"] or r["username"]},
        "challenge": ch, "timeout": 120000, "attestation": "none",
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}],
        "authenticatorSelection": {"residentKey": "required", "requireResidentKey": True, "userVerification": "required"},
        "excludeCredentials": [{"type": "public-key", "id": x["cred_id"]} for x in _rows(r["id"], "passkey")],
    }}


def passkey_register(user, body, host):
    origin = _origin(host)
    cred = body.get("credential") or {}
    resp = cred.get("response") or {}
    r = auth._get(user["id"])
    try:
        cd_raw = wa.b64u_decode(resp["clientDataJSON"])
        ch = json.loads(cd_raw.decode()).get("challenge")
        c = _take_challenge(ch, "create")
        if c["uid"] != user["id"]:
            raise wa.WebAuthnError("challenge belongs to someone else")
        wa.check_client_data(cd_raw, "webauthn.create", ch, origin)
        att, _ = wa.cbor_decode(wa.b64u_decode(resp["attestationObject"]))
        ad = wa.parse_auth_data(att["authData"], need_cred=True)
        wa.check_rp(ad, RP_ID, require_uv=True)
        pub = wa.cose_to_key(ad["key"])
        cid = wa.b64u(ad["cred_id"])
        if cred.get("id") and cred["id"] != cid:
            raise wa.WebAuthnError("credential id mismatch")
    except (wa.WebAuthnError, KeyError, TypeError, ValueError) as e:
        auth.log(r["username"], "mfa.passkey.failed", f"registration refused: {str(e)[:120]}", target=f"user:{r['id']}")
        raise ValueError(f"The passkey could not be added: {e}")
    c = db.conn()
    if c.execute("SELECT 1 FROM mfa_creds WHERE cred_id=?", (cid,)).fetchone():
        raise ValueError("This passkey is already registered")
    name = (str(body.get("name") or "").strip() or "Passkey")[:40]
    first = not has_mfa(user["id"])
    c.execute("INSERT INTO mfa_creds(user_id, kind, name, cred_id, data, created_at, confirmed) VALUES(?,?,?,?,?,?,1)",
              (user["id"], "passkey", name, cid, json.dumps({"pub": pub, "count": ad["count"]}), _now()))
    c.commit()
    auth.log(r["username"], "mfa.passkey.add", f"passkey “{name}” added", target=f"user:{r['id']}")
    return {"recovery_codes": new_recovery_codes(user["id"]) if first else None}


def passkey_remove(user, cred_row_id, password):
    r = reauth(user, password)
    row = db.conn().execute("SELECT * FROM mfa_creds WHERE id=? AND user_id=? AND kind='passkey'", (cred_row_id, user["id"])).fetchone()
    if not row:
        raise ValueError("Passkey not found")
    _guard_last_factor(user["id"])
    db.conn().execute("DELETE FROM mfa_creds WHERE id=?", (row["id"],))
    _cleanup(user["id"])
    auth.log(r["username"], "mfa.passkey.remove", f"passkey “{row['name']}” removed", target=f"user:{r['id']}")
    return {"ok": True}


def passkey_login_options(mfa_token, host):
    _origin(host)
    uid = None
    if mfa_token:
        uid = _pending(mfa_token)["uid"]
    ch = _new_challenge("get", uid)
    allow = [{"type": "public-key", "id": x["cred_id"]} for x in _rows(uid, "passkey")] if uid else []
    return {"publicKey": {"challenge": ch, "rpId": RP_ID, "timeout": 120000, "userVerification": "required", "allowCredentials": allow}}


def passkey_login(body, host):
    """Verify a passkey assertion and start a session. Every failure gives the same message; the audit log has the reason."""
    origin = _origin(host)
    cred = body.get("credential") or {}
    resp = cred.get("response") or {}
    who = "(passkey)"
    try:
        cd_raw = wa.b64u_decode(resp["clientDataJSON"])
        ch = json.loads(cd_raw.decode()).get("challenge")
        c = _take_challenge(ch, "get")
        wa.check_client_data(cd_raw, "webauthn.get", ch, origin)
        row = db.conn().execute("SELECT * FROM mfa_creds WHERE cred_id=? AND kind='passkey' AND confirmed=1", (str(cred.get("id")),)).fetchone()
        if not row:
            raise wa.WebAuthnError("unknown passkey")
        if c["uid"] and c["uid"] != row["user_id"]:
            raise wa.WebAuthnError("passkey belongs to another account")
        u = db.conn().execute("SELECT * FROM users WHERE id=?", (row["user_id"],)).fetchone()
        if not u or not u["active"]:
            raise wa.WebAuthnError("account inactive")
        who = u["username"]
        auth.check_locked(u)
        ad_raw = wa.b64u_decode(resp["authenticatorData"])
        ad = wa.parse_auth_data(ad_raw)
        wa.check_rp(ad, RP_ID, require_uv=True)
        d = json.loads(row["data"])
        if not wa.verify_signature(d["pub"], ad_raw, cd_raw, wa.b64u_decode(resp["signature"])):
            raise wa.WebAuthnError("signature invalid")
        if (ad["count"] or d.get("count")) and ad["count"] <= d.get("count", 0):
            raise wa.WebAuthnError("signature counter did not increase, the passkey may be cloned")
    except auth.AuthError:
        raise
    except (wa.WebAuthnError, KeyError, TypeError, ValueError) as e:
        auth.log(who, "login.failed", f"passkey refused: {str(e)[:120]}", via="")
        raise auth.AuthError(401, "The passkey was not accepted")
    d["count"] = ad["count"]
    db.conn().execute("UPDATE mfa_creds SET data=?, last_used=? WHERE id=?", (json.dumps(d), _now(), row["id"]))
    db.conn().commit()
    with _lock:
        if c.get("uid") and body.get("mfa_token"):
            _PENDING.pop(_sha(str(body["mfa_token"])), None)
    return auth.start_session(u, f"passkey “{row['name']}”")


# ---------------------------------------------------------------- administration
def admin_reset(uid, actor):
    c = db.conn()
    u = auth._get(uid)
    n = c.execute("DELETE FROM mfa_creds WHERE user_id=?", (uid,)).rowcount
    c.execute("DELETE FROM mfa_recovery WHERE user_id=?", (uid,))
    c.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
    c.commit()
    with _lock:
        for k in [k for k, v in _PENDING.items() if v["uid"] == uid]:
            del _PENDING[k]
    auth.log(actor, "mfa.reset", f"{u['username']}: {n} method(s) removed, signed out everywhere", target=f"user:{uid}")
    return {"ok": True, "removed": n}
