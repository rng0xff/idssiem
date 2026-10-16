"""Shared fixture: every test gets its own empty SQLite database."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ids_siem import db  # noqa: E402

DAY = 86400000
T0 = 1_780_000_000_000  # 2026-05-28, inside the plausible timestamp range


def ev(vin="SC6GM1CA0TF000001", etype="can", eid=32795, ecu="ECU-A", ts=T0, name="x"):
    return {"event_type": etype, "event_id": eid, "vin": vin, "ecu_name": ecu, "ts": ts, "name": name}


class DbCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        db.DB_PATH = os.path.join(self._tmp.name, "t.db")
        db._local.c = None
        db.init()

    def tearDown(self):
        c = getattr(db._local, "c", None)
        if c is not None:
            c.close()
        db._local.c = None
        self._tmp.cleanup()

    def load(self, rows, name="t"):
        from ids_siem import ingest
        return ingest.import_rows(rows, name)

    def alerts(self, rule=None):
        from ids_siem import rules
        rules.run_all()
        q = "SELECT * FROM alerts" + (" WHERE rule=?" if rule else "")
        return db.conn().execute(q, (rule,) if rule else ()).fetchall()
