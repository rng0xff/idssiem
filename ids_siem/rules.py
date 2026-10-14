"""Detection rules. Each rule scans the event store and yields alerts.

Alerts are upserted by a deterministic key, so re-running the rules never loses analyst triage
(status, assignee, comments). A resolved alert is re-opened if new events show up for it.
"""
import datetime
import json
import statistics
from collections import defaultdict

from . import db
from .catalog import SEVERITIES, SEV_NUM

RULE_INFO = {
    "high_sev": ("High-severity event", "Any event type classified at or above the chosen severity, grouped per vehicle, ECU and event type."),
    "burst": ("Event burst", "N or more events of the same type on one vehicle within a sliding time window. Raises the catalog severity by one level (max high). Info events are ignored."),
    "multi_ecu": ("Multiple ECUs affected", "One vehicle reports non-info events from at least N different ECUs on the same UTC day."),
    "vehicle_outlier": ("Vehicle outlier", "A vehicle's number of non-info events is more than K standard deviations above the fleet average."),
    "fleet_spike": ("Fleet-wide spike", "A UTC day with a non-info event count more than K standard deviations above the daily average. Spike days at most one quiet day apart are merged into one alert."),
    "new_event_type": ("Unclassified event type", "An event type that is not in the built-in catalog. Classify it on the Catalog page."),
}


def _bump(sev, n=1, cap="high"):
    return SEVERITIES[min(SEV_NUM[sev] + n, SEV_NUM[cap])]


def _day(ms):
    return datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc).strftime("%Y-%m-%d")


def _day_range(day):
    d = datetime.datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
    lo = int(d.timestamp() * 1000)
    return lo, lo + 86400000 - 1


def _alert(key, rule, title, severity, vin=None, ecu=None, cat=None, first_ts=None, last_ts=None, count=0, details=None, flt=None):
    return dict(key=key, rule=rule, title=title, severity=severity, vin=vin, ecu=ecu or "", cat=cat,
                first_ts=first_ts, last_ts=last_ts, count=count, details=details or {}, filter=flt or {})


# ------------------------------------------------------------------ rules
def rule_high_sev(c, cfg):
    minsev = SEV_NUM.get(cfg.get("min_severity", "high"), 3)
    q = ("SELECT e.vin, e.ecu_name, e.cat_id, c.short_name, c.severity, c.category, COUNT(*) n, "
         "MIN(CASE WHEN e.ts_ok=1 THEN e.ts END) f, MAX(CASE WHEN e.ts_ok=1 THEN e.ts END) l, SUM(e.ts_ok=0) nots "
         "FROM events e JOIN catalog c ON c.cat_id=e.cat_id WHERE c.sev_num>=? GROUP BY e.vin, e.ecu_name, e.cat_id")
    for r in c.execute(q, (minsev,)):
        flt = {"vin": r["vin"], "cat": r["cat_id"]}
        if r["ecu_name"]:
            flt["ecu"] = r["ecu_name"]
        yield _alert(f"high_sev|{r['vin']}|{r['ecu_name']}|{r['cat_id']}", "high_sev",
                     f"{r['short_name']}" + (f" on {r['ecu_name']}" if r["ecu_name"] else ""), r["severity"], r["vin"], r["ecu_name"],
                     r["cat_id"], r["f"], r["l"], r["n"],
                     {"category": r["category"], "events_without_valid_timestamp": r["nots"]}, flt)


def rule_burst(c, cfg):
    n_min, win = int(cfg.get("threshold", 3)), int(cfg.get("window_min", 60)) * 60000
    q = ("SELECT e.vin, e.cat_id, c.short_name, c.severity, e.ts FROM events e JOIN catalog c ON c.cat_id=e.cat_id "
         "WHERE e.ts_ok=1 AND c.sev_num>=1 ORDER BY e.vin, e.cat_id, e.ts")
    groups = defaultdict(list)
    meta = {}
    for r in c.execute(q):
        k = (r["vin"], r["cat_id"])
        groups[k].append(r["ts"])
        meta[k] = (r["short_name"], r["severity"])
    for (vin, cid), tss in groups.items():
        if len(tss) < n_min:
            continue
        # sliding window; merge overlapping windows into one cluster
        clusters, i = [], 0
        for j in range(len(tss)):
            while tss[j] - tss[i] > win:
                i += 1
            if j - i + 1 >= n_min:
                if clusters and i <= clusters[-1][1]:
                    clusters[-1][1] = j
                else:
                    clusters.append([i, j])
        short, sev = meta[(vin, cid)]
        for a, b in clusters:
            cnt = b - a + 1
            yield _alert(f"burst|{vin}|{cid}|{tss[a]}", "burst", f"{cnt}× {short} within {max(1, round((tss[b]-tss[a])/60000))} min",
                         _bump(sev), vin, None, cid, tss[a], tss[b], cnt,
                         {"window_min": win // 60000, "threshold": n_min},
                         {"vin": vin, "cat": cid, "from": str(tss[a] - 1), "to": str(tss[b] + 1)})


def rule_multi_ecu(c, cfg):
    n_min = int(cfg.get("min_ecus", 3))
    q = ("SELECT e.vin, e.ts, e.ecu_name, c.sev_num FROM events e JOIN catalog c ON c.cat_id=e.cat_id "
         "WHERE e.ts_ok=1 AND c.sev_num>=1 AND e.ecu_name<>''")
    days = defaultdict(lambda: {"ecus": defaultdict(int), "max": 0, "f": None, "l": None, "n": 0})
    for r in c.execute(q):
        d = days[(r["vin"], _day(r["ts"]))]
        d["ecus"][r["ecu_name"]] += 1
        d["max"] = max(d["max"], r["sev_num"])
        d["n"] += 1
        d["f"] = r["ts"] if d["f"] is None else min(d["f"], r["ts"])
        d["l"] = r["ts"] if d["l"] is None else max(d["l"], r["ts"])
    for (vin, day), d in days.items():
        if len(d["ecus"]) >= n_min:
            lo, hi = _day_range(day)
            sev = "high" if d["max"] >= 3 else "medium"
            yield _alert(f"multi_ecu|{vin}|{day}", "multi_ecu", f"{len(d['ecus'])} ECUs affected on {day}", sev, vin, None, None,
                         d["f"], d["l"], d["n"], {"ecus": dict(d["ecus"]), "day": day},
                         {"vin": vin, "from": str(lo), "to": str(hi)})


def rule_vehicle_outlier(c, cfg):
    k, min_ev = float(cfg.get("sigma", 3)), int(cfg.get("min_events", 10))
    rows = c.execute("SELECT e.vin, COUNT(*) n, MIN(CASE WHEN e.ts_ok=1 THEN e.ts END) f, MAX(CASE WHEN e.ts_ok=1 THEN e.ts END) l "
                     "FROM events e JOIN catalog c ON c.cat_id=e.cat_id WHERE c.sev_num>=1 GROUP BY e.vin").fetchall()
    if len(rows) < 5:
        return
    vals = [r["n"] for r in rows]
    mean, sd = statistics.mean(vals), statistics.pstdev(vals)
    limit = mean + k * sd
    for r in rows:
        if r["n"] > limit and r["n"] >= min_ev:
            z = (r["n"] - mean) / sd if sd else 0
            yield _alert(f"vehicle_outlier|{r['vin']}", "vehicle_outlier", f"{r['n']} events, {z:.1f}σ above fleet average",
                         "medium", r["vin"], None, None, r["f"], r["l"], r["n"],
                         {"fleet_mean": round(mean, 2), "fleet_sd": round(sd, 2), "z": round(z, 2)}, {"vin": r["vin"]})


def rule_fleet_spike(c, cfg):
    k, min_ev = float(cfg.get("sigma", 3)), int(cfg.get("min_events", 30))
    q = ("SELECT (e.ts/86400000) AS d, COUNT(*) n, COUNT(DISTINCT e.vin) vins, MIN(e.ts) f, MAX(e.ts) l "
         "FROM events e JOIN catalog c ON c.cat_id=e.cat_id WHERE e.ts_ok=1 AND c.sev_num>=1 GROUP BY d")
    rows = c.execute(q).fetchall()
    if len(rows) < 7:
        return
    vals = [r["n"] for r in rows]
    mean, sd = statistics.mean(vals), statistics.pstdev(vals)
    spikes = [r for r in rows if r["n"] > mean + k * sd and r["n"] >= min_ev]
    # Merge spike days that are at most one quiet day apart into one alert (a sustained surge is one finding)
    runs = []
    for r in spikes:
        if runs and r["d"] - runs[-1][-1]["d"] <= 2:
            runs[-1].append(r)
        else:
            runs.append([r])
    for run in runs:
        d0, d1 = run[0]["d"] * 86400000, run[-1]["d"] * 86400000 + 86399999
        total = sum(r["n"] for r in run)
        peak = max(run, key=lambda r: r["n"])
        vins = c.execute("SELECT COUNT(DISTINCT e.vin) FROM events e JOIN catalog c ON c.cat_id=e.cat_id "
                         "WHERE e.ts_ok=1 AND c.sev_num>=1 AND e.ts BETWEEN ? AND ?", (d0, d1)).fetchone()[0]
        first_day, last_day = _day(d0), _day(d1)
        span = first_day if first_day == last_day else f"{first_day} to {last_day}"
        z = (peak["n"] - mean) / sd if sd else 0
        yield _alert(f"fleet_spike|{first_day}", "fleet_spike",
                     f"{total} events from {vins} vehicles, {span}", "medium", None, None, None,
                     min(r["f"] for r in run), max(r["l"] for r in run), total,
                     {"spike_days": len(run), "peak_day": _day(peak["d"] * 86400000), "peak_events": peak["n"], "peak_z": round(z, 2),
                      "daily_mean": round(mean, 2), "daily_sd": round(sd, 2), "vehicles": vins},
                     {"from": str(d0), "to": str(d1)})


def rule_new_event_type(c, cfg):
    for r in c.execute("SELECT c.cat_id, c.short_name, c.event_type, c.event_id, COUNT(e.id) n, "
                       "MIN(CASE WHEN e.ts_ok=1 THEN e.ts END) f, MAX(CASE WHEN e.ts_ok=1 THEN e.ts END) l "
                       "FROM catalog c LEFT JOIN events e ON e.cat_id=c.cat_id WHERE c.auto=1 GROUP BY c.cat_id"):
        yield _alert(f"new_event_type|{r['cat_id']}", "new_event_type", f"Unclassified event type {r['short_name']} ({r['cat_id']})", "low",
                     None, None, r["cat_id"], r["f"], r["l"], r["n"], {"event_type": r["event_type"], "event_id": r["event_id"]},
                     {"cat": r["cat_id"]})


RULES = {"high_sev": rule_high_sev, "burst": rule_burst, "multi_ecu": rule_multi_ecu,
         "vehicle_outlier": rule_vehicle_outlier, "fleet_spike": rule_fleet_spike, "new_event_type": rule_new_event_type}


# ------------------------------------------------------------------ runner
def run_all():
    c = db.conn()
    cfg = db.get_settings()["rules"]
    now = db.now_ms()
    stats = {"created": 0, "updated": 0, "reopened": 0, "per_rule": {}}
    c.execute("BEGIN")
    try:
        for name, fn in RULES.items():
            if not cfg.get(name, {}).get("enabled", True):
                stats["per_rule"][name] = None
                continue
            n = 0
            for a in fn(c, cfg.get(name, {})):
                n += 1
                row = c.execute("SELECT id, status, event_count FROM alerts WHERE alert_key=?", (a["key"],)).fetchone()
                details, flt = json.dumps(a["details"]), json.dumps(a["filter"])
                if row is None:
                    c.execute("INSERT INTO alerts(alert_key, rule, title, severity, sev_num, vin, ecu_name, cat_id, first_ts, last_ts, event_count, "
                              "status, details, filter, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'new',?,?,?,?)",
                              (a["key"], a["rule"], a["title"], a["severity"], SEV_NUM[a["severity"]], a["vin"], a["ecu"], a["cat"],
                               a["first_ts"], a["last_ts"], a["count"], details, flt, now, now))
                    stats["created"] += 1
                else:
                    status = row["status"]
                    if status in ("resolved", "false_positive") and a["count"] > row["event_count"]:
                        status = "new"
                        c.execute("INSERT INTO alert_comments(alert_id, author, body, created_at) VALUES(?,?,?,?)",
                                  (row["id"], "system", f"Re-opened: {a['count'] - row['event_count']} new matching event(s).", now))
                        stats["reopened"] += 1
                        cr = c.execute("SELECT case_id FROM case_alerts WHERE alert_id=?", (row["id"],)).fetchone()
                        if cr:
                            c.execute("INSERT INTO case_log(case_id, author, kind, body, created_at) VALUES(?,?,?,?,?)",
                                      (cr["case_id"], "system", "system",
                                       f"Alert #{row['id']} was re-opened: {a['count'] - row['event_count']} new matching event(s). Check whether this case needs more work.", now))
                    changed = c.execute("SELECT 1 FROM alerts WHERE id=? AND (event_count<>? OR severity<>? OR title<>?)",
                                        (row["id"], a["count"], a["severity"], a["title"])).fetchone()
                    c.execute("UPDATE alerts SET title=?, severity=?, sev_num=?, first_ts=?, last_ts=?, event_count=?, details=?, filter=?, status=?, "
                              "updated_at=CASE WHEN ? THEN ? ELSE updated_at END WHERE id=?",
                              (a["title"], a["severity"], SEV_NUM[a["severity"]], a["first_ts"], a["last_ts"], a["count"], details, flt, status,
                               1 if changed else 0, now, row["id"]))
                    if changed:
                        stats["updated"] += 1
            stats["per_rule"][name] = n
        # A new_event_type alert whose catalog entry has since been classified is no longer relevant
        c.execute("UPDATE alerts SET status='resolved', updated_at=? WHERE rule='new_event_type' AND status IN ('new','in_progress') "
                  "AND cat_id IN (SELECT cat_id FROM catalog WHERE auto=0)", (now,))
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
    return stats


# ------------------------------------------------------------------ alert access
STATUSES = ["new", "in_progress", "resolved", "false_positive"]


def _alert_row(r):
    d = dict(r)
    d["details"] = json.loads(d["details"] or "{}")
    d["filter"] = json.loads(d["filter"] or "{}")
    d["rule_title"] = RULE_INFO.get(d["rule"], (d["rule"], ""))[0]
    return d


def list_alerts(p):
    c = db.conn()
    w, a = ["1=1"], []
    for key, col in (("status", "alerts.status"), ("severity", "alerts.severity"), ("rule", "alerts.rule")):
        vals = [x for v in p.get(key, []) for x in v.split(",") if x]
        if vals:
            w.append(f"{col} IN ({','.join('?' * len(vals))})")
            a += vals
    if p.get("vin"):
        w.append("alerts.vin = ?")
        a.append(p["vin"][0].upper())
    if p.get("q") and p["q"][0].strip():
        w.append("(alerts.title LIKE ? OR alerts.vin LIKE ?)")
        a += [f"%{p['q'][0].strip()}%"] * 2
    cs = (p.get("case") or [""])[0]
    if cs == "none":
        w.append("NOT EXISTS (SELECT 1 FROM case_alerts x WHERE x.alert_id = alerts.id)")
    elif cs == "any":
        w.append("EXISTS (SELECT 1 FROM case_alerts x WHERE x.alert_id = alerts.id)")
    elif cs.isdigit():
        w.append("EXISTS (SELECT 1 FROM case_alerts x WHERE x.alert_id = alerts.id AND x.case_id = ?)")
        a.append(int(cs))
    sort = {"severity": "alerts.sev_num", "events": "alerts.event_count", "last": "alerts.last_ts", "updated": "alerts.updated_at",
            "status": "alerts.status"}.get((p.get("sort") or ["severity"])[0], "alerts.sev_num")
    d = "ASC" if (p.get("dir") or ["desc"])[0] == "asc" else "DESC"
    page = max(1, int((p.get("page") or ["1"])[0]))
    size = min(200, max(1, int((p.get("size") or ["50"])[0])))
    where = " AND ".join(w)
    total = c.execute(f"SELECT COUNT(*) FROM alerts WHERE {where}", a).fetchone()[0]
    rows = c.execute(
        f"SELECT alerts.*, ca.case_id AS case_id, cs.status AS case_status FROM alerts "
        f"LEFT JOIN case_alerts ca ON ca.alert_id = alerts.id LEFT JOIN cases cs ON cs.id = ca.case_id "
        f"WHERE {where} ORDER BY {sort} {d}, alerts.updated_at DESC LIMIT ? OFFSET ?", a + [size, (page - 1) * size]).fetchall()
    counts = {r["status"]: r["n"] for r in c.execute("SELECT status, COUNT(*) n FROM alerts GROUP BY status")}
    return {"total": total, "page": page, "size": size, "alerts": [_alert_row(r) for r in rows], "status_counts": counts}


def get_alert(aid):
    c = db.conn()
    r = c.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
    if not r:
        return None
    d = _alert_row(r)
    cs = c.execute("SELECT cs.id, cs.title, cs.status FROM case_alerts ca JOIN cases cs ON cs.id=ca.case_id WHERE ca.alert_id=?", (aid,)).fetchone()
    d["case"] = dict(cs) if cs else None
    d["comments"] = [dict(x) for x in c.execute("SELECT * FROM alert_comments WHERE alert_id=? ORDER BY created_at", (aid,))]
    d["rule_description"] = RULE_INFO.get(d["rule"], ("", ""))[1]
    return d


def update_alert(aid, body):
    c = db.conn()
    r = c.execute("SELECT status, assignee FROM alerts WHERE id=?", (aid,)).fetchone()
    if not r:
        return None
    now = db.now_ms()
    who = db.get_settings().get("analyst", "analyst")
    if "status" in body and body["status"] != r["status"]:
        if body["status"] not in STATUSES:
            raise ValueError("invalid status")
        c.execute("UPDATE alerts SET status=?, updated_at=? WHERE id=?", (body["status"], now, aid))
        c.execute("INSERT INTO alert_comments(alert_id, author, body, created_at) VALUES(?,?,?,?)",
                  (aid, "system", f"{who} changed status: {r['status']} → {body['status']}", now))
    if "assignee" in body and body["assignee"] != r["assignee"]:
        c.execute("UPDATE alerts SET assignee=?, updated_at=? WHERE id=?", (str(body["assignee"])[:60], now, aid))
    if body.get("comment"):
        c.execute("INSERT INTO alert_comments(alert_id, author, body, created_at) VALUES(?,?,?,?)", (aid, who, str(body["comment"])[:5000], now))
        c.execute("UPDATE alerts SET updated_at=? WHERE id=?", (now, aid))
    c.commit()
    return get_alert(aid)


def bulk_update(ids, status):
    if status not in STATUSES:
        raise ValueError("invalid status")
    for i in ids:
        update_alert(int(i), {"status": status})
    return len(ids)
