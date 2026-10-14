"""Minimal WebAuthn relying-party code with the standard library only.

Supports what browsers, platform authenticators and security keys use with attestation "none":
ES256 (ECDSA P-256 / SHA-256) and RS256 (RSASSA-PKCS1-v1_5 / SHA-256, as some Windows Hello setups still use).
It parses CBOR (definite lengths only) and the authenticator data, checks the client data, the relying-party
hash, the user-presence and user-verification flags and the signature. Attestation statements are not
evaluated (there is no trust anchor for a local tool); the registered key is trusted on first use.
"""
import base64
import hashlib
import json
import struct

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


class WebAuthnError(ValueError):
    pass


def b64u_decode(s):
    s = str(s)
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ---------------------------------------------------------------- CBOR
def cbor_decode(data):
    val, pos = _cbor(data, 0, 0)
    return val, pos


def _cbor(d, i, depth):
    if depth > 8 or i >= len(d):
        raise WebAuthnError("bad CBOR")
    ib = d[i]; i += 1
    major, info = ib >> 5, ib & 31
    if info < 24:
        n = info
    elif info in (24, 25, 26, 27):
        size = {24: 1, 25: 2, 26: 4, 27: 8}[info]
        if i + size > len(d):
            raise WebAuthnError("bad CBOR")
        n = int.from_bytes(d[i:i + size], "big"); i += size
    else:
        raise WebAuthnError("unsupported CBOR")
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major in (2, 3):
        if i + n > len(d):
            raise WebAuthnError("bad CBOR")
        raw = d[i:i + n]
        return (bytes(raw) if major == 2 else raw.decode("utf-8")), i + n
    if major == 4:
        if n > 64:
            raise WebAuthnError("bad CBOR")
        out = []
        for _ in range(n):
            v, i = _cbor(d, i, depth + 1); out.append(v)
        return out, i
    if major == 5:
        if n > 64:
            raise WebAuthnError("bad CBOR")
        out = {}
        for _ in range(n):
            k, i = _cbor(d, i, depth + 1)
            v, i = _cbor(d, i, depth + 1)
            out[k] = v
        return out, i
    if major == 7 and info in (20, 21, 22):
        return {20: False, 21: True, 22: None}[info], i
    raise WebAuthnError("unsupported CBOR")


# ---------------------------------------------------------------- ECDSA P-256
def _inv(x, m):
    return pow(x, -1, m)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 + A) * _inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def _mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
        k >>= 1
    return r


def on_curve(x, y):
    return 0 < x < P and 0 < y < P and (y * y - (x * x * x + A * x + B)) % P == 0


def _der_sig(sig):
    try:
        if sig[0] != 0x30:
            raise ValueError
        i = 2 if sig[1] < 0x80 else 3
        if sig[i] != 0x02:
            raise ValueError
        lr = sig[i + 1]; r = int.from_bytes(sig[i + 2:i + 2 + lr], "big"); i += 2 + lr
        if sig[i] != 0x02:
            raise ValueError
        ls = sig[i + 1]; s = int.from_bytes(sig[i + 2:i + 2 + ls], "big")
        if i + 2 + ls != len(sig):
            raise ValueError
        return r, s
    except (IndexError, ValueError):
        raise WebAuthnError("bad signature encoding")


def verify_es256(x, y, message, sig_der):
    if not on_curve(x, y):
        return False
    r, s = _der_sig(sig_der)
    if not (0 < r < N and 0 < s < N):
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = _inv(s, N)
    pt = _add(_mul(e * w % N, (GX, GY)), _mul(r * w % N, (x, y)))
    return pt is not None and pt[0] % N == r


# ---------------------------------------------------------------- RSA PKCS#1 v1.5 / SHA-256
_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def verify_rs256(n, e, message, sig):
    if n.bit_length() < 2048 or e < 3 or e % 2 == 0:
        return False
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    t = _SHA256_PREFIX + hashlib.sha256(message).digest()
    expect = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return hmac_eq(em, expect)


def hmac_eq(a, b):
    import hmac
    return hmac.compare_digest(a, b)


# ---------------------------------------------------------------- parsing
def parse_auth_data(ad, need_cred=False):
    if len(ad) < 37:
        raise WebAuthnError("authenticator data too short")
    out = {"rp_hash": ad[:32], "flags": ad[32], "count": struct.unpack(">I", ad[33:37])[0]}
    out["up"] = bool(ad[32] & 1); out["uv"] = bool(ad[32] & 4); out["at"] = bool(ad[32] & 64)
    if need_cred:
        if not out["at"] or len(ad) < 55:
            raise WebAuthnError("no credential data")
        n = struct.unpack(">H", ad[53:55])[0]
        if n == 0 or n > 1023 or len(ad) < 55 + n:
            raise WebAuthnError("bad credential id")
        out["cred_id"] = ad[55:55 + n]
        key, _end = cbor_decode(ad[55 + n:])
        out["key"] = key
    return out


def cose_to_key(key):
    """COSE_Key -> {'alg': -7, 'x': int, 'y': int} or {'alg': -257, 'n': int, 'e': int}. Raises on anything else."""
    if not isinstance(key, dict):
        raise WebAuthnError("bad public key")
    kty, alg = key.get(1), key.get(3)
    if kty == 2 and alg == -7 and key.get(-1) == 1:
        x, y = key.get(-2), key.get(-3)
        if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == 32 and len(y) == 32):
            raise WebAuthnError("bad EC key")
        xi, yi = int.from_bytes(x, "big"), int.from_bytes(y, "big")
        if not on_curve(xi, yi):
            raise WebAuthnError("EC key is not on the curve")
        return {"alg": -7, "x": xi, "y": yi}
    if kty == 3 and alg == -257:
        n, e = key.get(-1), key.get(-2)
        if not (isinstance(n, bytes) and isinstance(e, bytes)):
            raise WebAuthnError("bad RSA key")
        ni, ei = int.from_bytes(n, "big"), int.from_bytes(e, "big")
        if ni.bit_length() < 2048:
            raise WebAuthnError("RSA key is too short")
        return {"alg": -257, "n": ni, "e": ei}
    raise WebAuthnError("unsupported key type")


def check_client_data(raw, kind, challenge, origin):
    try:
        cd = json.loads(raw.decode("utf-8"))
    except ValueError:
        raise WebAuthnError("bad client data")
    if cd.get("type") != kind:
        raise WebAuthnError("wrong ceremony type")
    if cd.get("challenge") != challenge:
        raise WebAuthnError("challenge mismatch")
    if cd.get("origin") != origin:
        raise WebAuthnError(f"origin mismatch (expected {origin})")
    if cd.get("crossOrigin"):
        raise WebAuthnError("cross-origin request refused")
    return cd


def check_rp(auth_data, rp_id, require_uv=True):
    if not hmac_eq(auth_data["rp_hash"], hashlib.sha256(rp_id.encode()).digest()):
        raise WebAuthnError("relying party mismatch")
    if not auth_data["up"]:
        raise WebAuthnError("user presence missing")
    if require_uv and not auth_data["uv"]:
        raise WebAuthnError("user verification missing")


def verify_signature(pub, auth_data_raw, client_data_raw, sig):
    msg = auth_data_raw + hashlib.sha256(client_data_raw).digest()
    if pub["alg"] == -7:
        return verify_es256(pub["x"], pub["y"], msg, sig)
    if pub["alg"] == -257:
        return verify_rs256(pub["n"], pub["e"], msg, sig)
    return False
