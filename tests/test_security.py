"""Password hashing, sign-in, lockout, audit hash chain, TOTP."""
import unittest

from base import DbCase
from ids_siem import auth, db, mfa


class TestPasswords(unittest.TestCase):
    def test_hash_verify_roundtrip(self):
        h = auth.hash_pw("correct horse battery")
        self.assertTrue(h.startswith("scrypt$"))
        self.assertTrue(auth.verify_pw("correct horse battery", h))
        self.assertFalse(auth.verify_pw("wrong", h))

    def test_salt_is_random(self):
        self.assertNotEqual(auth.hash_pw("same password"), auth.hash_pw("same password"))

    def test_garbage_hash_does_not_verify(self):
        for s in ("", "x", "scrypt$a$b$c$d$e"):
            self.assertFalse(auth.verify_pw("p", s))

    def test_rehash_of_old_parameters(self):
        self.assertTrue(auth.needs_rehash("scrypt$16384$8$1$00$00"))
        self.assertFalse(auth.needs_rehash(auth.hash_pw("abcdefghij")))


class TestAccounts(DbCase):
    def admin(self):
        return auth.setup_first_admin({"username": "root", "password": "correct horse battery", "display_name": "R"})

    def test_setup_only_once(self):
        self.admin()
        with self.assertRaises(auth.AuthError):
            auth.setup_first_admin({"username": "x2", "password": "correct horse battery"})

    def test_password_rules(self):
        with self.assertRaises(ValueError):
            auth.create_user({"username": "bob", "password": "short", "role": "viewer"})
        with self.assertRaises(ValueError):
            auth.create_user({"username": "bobbobbobb", "password": "bobbobbobb", "role": "viewer"})

    def test_role_and_username_validation(self):
        with self.assertRaises(ValueError):
            auth.create_user({"username": "bob", "password": "correct horse battery", "role": "god"})
        with self.assertRaises(ValueError):
            auth.create_user({"username": "b o b", "password": "correct horse battery", "role": "viewer"})

    def test_login_success_returns_session(self):
        self.admin()
        raw, ttl = auth.login("root", "correct horse battery")
        self.assertTrue(len(raw) > 30 and ttl > 0)
        u = auth.identify({"Cookie": f"{auth.COOKIE}={raw}"})
        self.assertEqual(u["username"], "root")

    def test_session_stored_only_as_hash(self):
        self.admin()
        raw, _ = auth.login("root", "correct horse battery")
        stored = db.conn().execute("SELECT token_hash FROM sessions").fetchone()[0]
        self.assertNotEqual(stored, raw)

    def test_wrong_password_and_unknown_user_same_message(self):
        self.admin()
        msgs = []
        for u, p in (("root", "nope nope nope"), ("ghost", "nope nope nope")):
            with self.assertRaises(auth.AuthError) as cm:
                auth.login(u, p)
            msgs.append(str(cm.exception.args))
        self.assertEqual(msgs[0], msgs[1])

    def test_lockout_after_five_failures(self):
        self.admin()
        for _ in range(auth.LOCK_AFTER):
            with self.assertRaises(auth.AuthError):
                auth.login("root", "bad bad bad bad")
        with self.assertRaises(auth.AuthError) as cm:  # even the right password is refused while locked
            auth.login("root", "correct horse battery")
        self.assertIn("Too many", str(cm.exception.args))

    def test_unauthenticated_request_not_identified(self):
        self.admin()
        self.assertIsNone(auth.identify({}))
        self.assertIsNone(auth.identify({"Cookie": f"{auth.COOKIE}=forged"}))

    def test_last_admin_cannot_be_removed(self):
        u = self.admin()
        me = auth.identify({"Cookie": f"{auth.COOKIE}={auth.login('root', 'correct horse battery')[0]}"})
        with self.assertRaises(Exception):
            auth.update_user(u["id"], {"role": "viewer"}, "root")
        with self.assertRaises(Exception):
            auth.delete_user(u["id"], me)


class TestAuditChain(DbCase):
    def test_empty_chain_ok(self):
        self.assertTrue(auth.verify_audit()["ok"])

    def test_chain_verifies(self):
        for i in range(5):
            auth.log("tester", "t.action", f"entry {i}")
        r = auth.verify_audit()
        self.assertTrue(r["ok"])
        self.assertEqual(r["checked"], 5)

    def test_modified_entry_detected(self):
        for i in range(5):
            auth.log("tester", "t.action", f"entry {i}")
        target = db.conn().execute("SELECT id FROM audit ORDER BY id LIMIT 1 OFFSET 2").fetchone()[0]
        db.conn().execute("UPDATE audit SET detail='tampered' WHERE id=?", (target,))
        db.conn().commit()
        r = auth.verify_audit()
        self.assertFalse(r["ok"])
        self.assertEqual(r["broken_at"], target)

    def test_deleted_entry_detected(self):
        for i in range(5):
            auth.log("tester", "t.action", f"entry {i}")
        target = db.conn().execute("SELECT id FROM audit ORDER BY id LIMIT 1 OFFSET 2").fetchone()[0]
        db.conn().execute("DELETE FROM audit WHERE id=?", (target,))
        db.conn().commit()
        self.assertFalse(auth.verify_audit()["ok"])

    def test_login_events_are_logged(self):
        auth.setup_first_admin({"username": "root", "password": "correct horse battery"})
        with self.assertRaises(auth.AuthError):
            auth.login("root", "bad bad bad bad")
        auth.login("root", "correct horse battery")
        acts = [r[0] for r in db.conn().execute("SELECT action FROM audit")]
        for a in ("setup.admin", "login.failed", "login"):
            self.assertIn(a, acts)


class TestTotp(unittest.TestCase):
    SECRET = b"12345678901234567890"

    def test_rfc4226_vectors(self):
        expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
        self.assertEqual([mfa._hotp(self.SECRET, i) for i in range(10)], expected)

    def test_base32_secret_roundtrip(self):
        import base64
        b32 = base64.b32encode(self.SECRET).decode().rstrip("=")
        self.assertEqual(mfa._secret_bytes(b32), self.SECRET)


if __name__ == "__main__":
    unittest.main()
