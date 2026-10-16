"""Detection rules (README: Detections). Each test names the rule and the threshold it exercises."""
import json
import unittest

from base import DbCase, ev, T0, DAY
from ids_siem import db, rules

MIN = 60000
V = lambda i: f"SC6GM1CA0TF{i:06d}"  # noqa: E731
DAY0 = (T0 // DAY) * DAY


class TestRules(DbCase):
    def test_high_sev_alert_for_high_event(self):
        self.load([ev(eid=32795)])  # UDS_CRIT_NR_NRC = high
        a = self.alerts("high_sev")
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["severity"], "high")

    def test_no_high_sev_alert_for_medium_event(self):
        self.load([ev(eid=32780)])  # medium
        self.assertEqual(self.alerts("high_sev"), [])

    def test_burst_three_in_window_bumps_severity(self):
        self.load([ev(eid=32780, ts=T0 + i * 10 * MIN) for i in range(3)])  # 3 events in 20 min, medium
        a = self.alerts("burst")
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["severity"], "high")  # medium + 1
        self.assertEqual(a[0]["event_count"], 3)

    def test_burst_two_events_no_alert(self):
        self.load([ev(eid=32780, ts=T0 + i * MIN) for i in range(2)])
        self.assertEqual(self.alerts("burst"), [])

    def test_burst_outside_window_no_alert(self):
        self.load([ev(eid=32780, ts=T0 + i * 90 * MIN) for i in range(3)])  # 90 min apart > 60 min window
        self.assertEqual(self.alerts("burst"), [])

    def test_burst_ignores_info_events(self):
        self.load([ev(eid=32787, ts=T0 + i * MIN) for i in range(5)])  # BURST_START = info
        self.assertEqual(self.alerts("burst"), [])

    def test_burst_severity_capped_at_high(self):
        self.load([ev(eid=32795, ts=T0 + i * MIN) for i in range(3)])  # already high
        a = self.alerts("burst")
        self.assertEqual(a[0]["severity"], "high")

    def test_multi_ecu_three_ecus_one_day(self):
        self.load([ev(eid=32780, ecu=f"ECU-{k}", ts=T0 + i * MIN) for i, k in enumerate("ABC")])
        a = self.alerts("multi_ecu")
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["severity"], "medium")

    def test_multi_ecu_two_ecus_no_alert(self):
        self.load([ev(eid=32780, ecu=f"ECU-{k}", ts=T0 + k_i * MIN) for k_i, k in enumerate("AB")])
        self.assertEqual(self.alerts("multi_ecu"), [])

    def test_multi_ecu_high_when_high_event_involved(self):
        rows = [ev(eid=32780, ecu="ECU-A", ts=T0), ev(eid=32780, ecu="ECU-B", ts=T0 + MIN), ev(eid=32795, ecu="ECU-C", ts=T0 + 2 * MIN)]
        self.load(rows)
        self.assertEqual(self.alerts("multi_ecu")[0]["severity"], "high")

    def test_vehicle_outlier(self):
        rows = [ev(vin=V(i), eid=32772, ts=T0 + i) for i in range(1, 30)]
        rows += [ev(vin=V(99), eid=32772, ts=T0 + 1000 + i) for i in range(50)]
        self.load(rows)
        a = self.alerts("vehicle_outlier")
        self.assertEqual([x["vin"] for x in a], [V(99)])

    def test_vehicle_outlier_needs_five_vehicles(self):
        self.load([ev(vin=V(i), eid=32772, ts=T0 + i * 5) for i in range(1, 4) for _ in range(1)]
                  + [ev(vin=V(9), eid=32772, ts=T0 + 100 + i) for i in range(50)])
        self.assertEqual(self.alerts("vehicle_outlier"), [])

    def test_fleet_spike(self):
        rows = []
        for d in range(20):
            n = 100 if d == 10 else 2
            rows += [ev(vin=V(1 + i % 3), eid=32772, ts=DAY0 + d * DAY + 3600000 + i) for i in range(n)]
        self.load(rows)
        a = self.alerts("fleet_spike")
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["event_count"], 100)

    def test_fleet_spike_needs_seven_days(self):
        rows = []
        for d in range(5):
            rows += [ev(eid=32772, ts=DAY0 + d * DAY + i) for i in range(100 if d == 2 else 2)]
        self.load(rows)
        self.assertEqual(self.alerts("fleet_spike"), [])

    def test_new_event_type_alert(self):
        self.load([ev(etype="foo", eid=1, name="Foo_Event")])
        a = self.alerts("new_event_type")
        self.assertEqual(len(a), 1)
        self.assertEqual(a[0]["severity"], "low")

    def test_new_event_type_resolved_once_classified(self):
        self.load([ev(etype="foo", eid=1)])
        self.alerts()
        db.conn().execute("UPDATE catalog SET auto=0 WHERE cat_id='foo:1'")
        db.conn().commit()
        rules.run_all()
        st = db.conn().execute("SELECT status FROM alerts WHERE rule='new_event_type'").fetchone()[0]
        self.assertEqual(st, "resolved")

    def test_run_all_is_idempotent(self):
        self.load([ev(eid=32795)])
        first = rules.run_all()
        second = rules.run_all()
        self.assertEqual(first["created"], 1)
        self.assertEqual(second["created"], 0)
        self.assertEqual(db.conn().execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 1)

    def test_disabled_rule_does_not_run(self):
        self.load([ev(eid=32795)])
        db.conn().execute("INSERT INTO settings(key,value) VALUES('rules', ?)", (json.dumps({"high_sev": {"enabled": False}}),))
        db.conn().commit()
        stats = rules.run_all()
        self.assertIsNone(stats["per_rule"]["high_sev"])
        self.assertEqual(db.conn().execute("SELECT COUNT(*) FROM alerts WHERE rule='high_sev'").fetchone()[0], 0)

    def test_events_without_valid_timestamp_do_not_feed_time_rules(self):
        self.load([ev(eid=32780, ts=None) for _ in range(5)])  # no timestamp: burst needs ts_ok
        self.assertEqual(self.alerts("burst"), [])


class TestSuppressionAndLifecycle(DbCase):
    def test_suppression_marks_alert_suppressed(self):
        self.load([ev(eid=32795)])
        rules.create_suppression({"rule": "high_sev", "reason": "known test vehicle", "days": 30})
        a = self.alerts("high_sev")
        self.assertEqual(a[0]["status"], "suppressed")

    def test_suppression_needs_scope_and_reason(self):
        with self.assertRaises(ValueError):
            rules.create_suppression({"reason": "everything"})
        with self.assertRaises(ValueError):
            rules.create_suppression({"rule": "burst", "reason": "x"})

    def test_duplicate_suppression_rejected(self):
        rules.create_suppression({"rule": "burst", "reason": "first reason"})
        with self.assertRaises(ValueError):
            rules.create_suppression({"rule": "burst", "reason": "second reason"})

    def test_resolved_alert_reopens_on_new_events(self):
        self.load([ev(eid=32795, ts=T0)])
        rules.run_all()
        aid = db.conn().execute("SELECT id FROM alerts").fetchone()[0]
        db.conn().execute("UPDATE alerts SET status='resolved' WHERE id=?", (aid,))
        db.conn().commit()
        self.load([ev(eid=32795, ts=T0 + 5000)], "more")
        st = rules.run_all()
        self.assertEqual(st["reopened"], 1)
        self.assertEqual(db.conn().execute("SELECT status FROM alerts WHERE id=?", (aid,)).fetchone()[0], "new")


if __name__ == "__main__":
    unittest.main()
