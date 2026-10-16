"""Import: normalisation, de-duplication, timestamp plausibility, catalog registration."""
import json
import unittest

from base import DbCase, ev, T0
from ids_siem import db, ingest, catalog


class TestIngest(DbCase):
    def test_reimport_is_noop(self):
        rows = [ev(ts=T0 + i) for i in range(5)]
        a = self.load(rows)
        b = self.load(rows)
        self.assertEqual((a["rows_new"], b["rows_new"], b["rows_duplicate"]), (5, 0, 5))
        self.assertEqual(db.conn().execute("SELECT COUNT(*) FROM events").fetchone()[0], 5)

    def test_identical_rows_in_one_file_are_kept(self):
        st = self.load([ev(ts=None), ev(ts=None), ev(ts=None)])
        self.assertEqual(st["rows_new"], 3)
        self.assertEqual(self.load([ev(ts=None)] * 3)["rows_new"], 0)

    def test_invalid_rows_counted(self):
        st = self.load([ev(vin=""), {"event_type": "", "vin": "X"}, ev()])
        self.assertEqual((st["rows_invalid"], st["rows_new"]), (2, 1))

    def test_vin_upper_and_event_type_lower(self):
        self.load([ev(vin="sc6gm1ca0tf000001", etype="CAN")])
        r = db.conn().execute("SELECT vin, event_type FROM events").fetchone()
        self.assertEqual((r["vin"], r["event_type"]), ("SC6GM1CA0TF000001", "can"))

    def test_timestamp_plausibility(self):
        far_future = db.now_ms() + 10 * 365 * 86400000
        self.load([ev(ts=T0), ev(ts=0, eid=1), ev(ts=far_future, eid=2), ev(ts=None, eid=3), ev(ts=1_600_000_000_000, eid=4)])
        ok = {r["event_id"]: r["ts_ok"] for r in db.conn().execute("SELECT event_id, ts_ok FROM events")}
        self.assertEqual(ok, {32795: 1, 1: 0, 2: 0, 3: 0, 4: 0})

    def test_parse_ts_formats(self):
        self.assertEqual(ingest._parse_ts("2026-05-28T10:00:00Z"), 1779962400000)
        self.assertEqual(ingest._parse_ts("2026-05-28T10:00:00+00:00"), 1779962400000)
        self.assertEqual(ingest._parse_ts("1779962400000"), 1779962400000)
        self.assertIsNone(ingest._parse_ts("not a date"))
        self.assertIsNone(ingest._parse_ts(""))
        self.assertIsNone(ingest._parse_ts(None))

    def test_known_event_gets_catalog_default(self):
        self.load([ev(eid=32795)])
        r = db.conn().execute("SELECT * FROM catalog WHERE cat_id='can:32795'").fetchone()
        self.assertEqual((r["severity"], r["auto"]), ("high", 0))

    def test_unknown_event_registered_as_unclassified(self):
        self.load([ev(etype="xyz", eid=7)])
        r = db.conn().execute("SELECT * FROM catalog WHERE cat_id='xyz:7'").fetchone()
        self.assertEqual((r["severity"], r["auto"]), ("low", 1))

    def test_event_without_id_gets_catalog_row(self):
        self.load([ev(etype="zzz", eid=None)])
        self.assertIsNotNone(db.conn().execute("SELECT 1 FROM catalog WHERE cat_id='zzz:None'").fetchone())

    def test_csv_header_aliases(self):
        data = b"type,time,VIN,ecu,event_id\ncan,2026-05-28T10:00:00Z,SC6GM1CA0TF000001,ECU-A,32795\n"
        rows = ingest.rows_for_file("x.csv", data)
        st = ingest.import_rows(rows, "x.csv")
        self.assertEqual(st["rows_new"], 1)

    def test_json_rows(self):
        data = json.dumps([ev()]).encode()
        st = ingest.import_rows(ingest.rows_for_file("x.json", data), "x.json")
        self.assertEqual(st["rows_new"], 1)

    def test_file_without_known_headers_rejected(self):
        with self.assertRaises(ingest.ImportError_):
            list(ingest.rows_for_file("x.csv", b"foo;bar\n1;2\n"))

    def test_backend_import_dedupes_by_id(self):
        def run(rows):
            imp = ingest.Importer("sync", "backend", by_id=True)
            imp.add(rows)
            return imp.finish()
        r = dict(ev(), backend_id="b-1")
        self.assertEqual(run([r])["rows_new"], 1)
        self.assertEqual(run([r])["rows_new"], 0)

    def test_catalog_short_name_derivation(self):
        self.assertEqual(catalog.derive_short_name("IdsMEventConfig_ECU_A_Foo", "ECU-A", "can", 1), "Foo")
        self.assertEqual(catalog.derive_short_name("", "", "can", 5), "CAN_5")


if __name__ == "__main__":
    unittest.main()
