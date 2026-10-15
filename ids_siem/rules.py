"""Detection rules. Each rule scans the event store and yields alerts.

Alerts are upserted by a deterministic key, so re-running the rules never loses analyst triage
(status, assignee, comments). A resolved alert is re-opened if new events show up for it.

Suppression rules silence known-benign patterns: a matching alert gets the status 'suppressed' (it stays
visible on its own tab and is counted), and returns to 'new' when the rule is disabled, deleted or expired.
Alerts that someone already works on (in progress, in a case) are never suppressed.
"""
import datetime
import json
import statistics
from collections import defaultdict

from . import auth, db
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


# ------------------------------------------------------------------ suppression
def _active_suppressions(c, now):
    return [dict(r) for r in c.execute(
        "SELECT * FROM suppressions WHERE enabled=1 AND (expires_at IS NULL OR expires_at > ?) ORDER BY id", (now,))]


def _first_match(sups, rule, vin, ecu, cat):
    for s in sups:
        if s["rule"] and s["rule"] != rule:
            continue
        if s["vin"] and s["vin"] != (vin or ""):
            continue
        if s["ecu_name"] and s["ecu_name"] != (ecu or ""):
            continue
        if s["cat_id"] and s["cat_id"] != (cat or ""):
            continue
        return s
    return None


def _sweep(c, sups, now):
    """Alerts still marked suppressed although no active rule matches them any more go back to 'new'."""
    n = 0
    for r in c.execute("SELECT id, rule, vin, ecu_name, cat_id FROM alerts WHERE status='suppressed'").fetchall():
        if not _first_match(sups, r["rule"], r["vin"], r["ecu_name"], r["cat_id"]):
            c.execute("UPDATE alerts SET status='new', updated_at=? WHERE id=?", (now, r["id"]))
            c.execute("INSERT INTO alert_comments(alert_id, author, body, created_at) VALUES(?,?,?,?)",
                      (r["id"], "system", "No suppression rule applies any more. Back to new.", now))
            n += 1
    return n


def sweep_expired():
    """Cheap check used when alerts are listed, so an expired rule stops hiding alerts without a detection run."""
    c = db.conn()
    if not c.execute("SELECT 1 FROM alerts WHERE status='suppressed' LIMIT 1").fetchone():
        return 0
    now = db.now_ms()
    c.execute("BEGIN")
    try:
        n = _sweep(c, _active_suppressions(c, now), now)
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
    return n


SUPPRESSION_FIELDS = ("rule", "vin", "ecu_name", "cat_id")


def _sup_row(r, suppressed_alerts, now):
    d = dict(r)
    d["expired"] = bool(d["expires_at"]) and d["expires_at"] <= now
    d["active"] = bool(d["enabled"]) and not d["expired"]
    d["rule_title"] = RULE_INFO.get(d["rule"], (d["rule"], ""))[0] if d["rule"] else ""
    d["alerts_now"] = sum(1 for a in suppressed_alerts if _first_match([d], a["rule"], a["vin"], a["ecu_name"], a["cat_id"]))
    return d


def list_suppressions():
    c = db.conn()
    now = db.now_ms()
    sa = c.execute("SELECT rule, vin, ecu_name, cat_id FROM alerts WHERE status='suppressed'").fetchall()
    cat = {r["cat_id"]: r["short_name"] for r in c.execute("SELECT cat_id, short_name FROM catalog")}
    out = []
    for r in c.execute("SELECT * FROM suppressions ORDER BY id DESC"):
        d = _sup_row(r, sa, now)
        d["event_name"] = cat.get(d["cat_id"], "") if d["cat_id"] else ""
        out.append(d)
    return out


def create_suppression(body):
    vals = {k: str(body.get(k) or "").strip()[:200] for k in SUPPRESSION_FIELDS}
    if vals["vin"]:
        vals["vin"] = vals["vin"].upper()
    if vals["rule"] and vals["rule"] not in RULE_INFO:
        raise ValueError("unknown detection")
    if not any(vals.values()):
        raise ValueError("Choose at least one of detection, vehicle, ECU or event type. A rule for everything would hide every alert.")
    reason = str(body.get("reason") or "").strip()
    if len(reason) < 5:
        raise ValueError("Give a reason (at least 5 characters). It is shown on every suppressed alert and kept in the audit log.")
    days = body.get("days", 90)
    try:
        days = int(days)
    except (TypeError, ValueError):
        raise ValueError("days must be a number")
    if days < 0 or days > 3650:
        raise ValueError("days must be between 0 (no expiry) and 3650")
    now = db.now_ms()
    who = auth.current_name()
    c = db.conn()
    dup = c.execute("SELECT id FROM suppressions WHERE rule=? AND vin=? AND ecu_name=? AND cat_id=? AND enabled=1 AND (expires_at IS NULL OR expires_at>?)",
                    (vals["rule"], vals["vin"], vals["ecu_name"], vals["cat_id"], now)).fetchone()
    if dup:
        raise ValueError(f"An identical active rule already exists (#{dup['id']}).")
    cur = c.execute("INSERT INTO suppressions(rule, vin, ecu_name, cat_id, reason, created_by, created_at, expires_at, enabled) VALUES(?,?,?,?,?,?,?,?,1)",
                    (vals["rule"], vals["vin"], vals["ecu_name"], vals["cat_id"], reason[:500], who, now, now + days * 86400000 if days else None))
    c.commit()
    sid = cur.lastrowid
    scope = ", ".join(f"{k}={v}" for k, v in vals.items() if v)
    auth.log(auth.current_actor(), "suppression.create", f"{scope}; {'expires in %d days' % days if days else 'no expiry'}; reason: {reason[:200]}", target=f"suppression:{sid}")
    return sid


def update_suppression(sid, body):
    c = db.conn()
    r = c.execute("SELECT * FROM suppressions WHERE id=?", (sid,)).fetchone()
    if not r:
        return False
    if "enabled" in body:
        en = 1 if body["enabled"] else 0
        c.execute("UPDATE suppressions SET enabled=? WHERE id=?", (en, sid))
        auth.log(auth.current_actor(), "suppression.enable" if en else "suppression.disable", "", target=f"suppression:{sid}")
    c.commit()
    return True


def delete_suppression(sid):
    c = db.conn()
    r = c.execute("SELECT * FROM suppressions WHERE id=?", (sid,)).fetchone()
    if not r:
        return False
    c.execute("DELETE FROM suppressions WHERE id=?", (sid,))
    c.commit()
    auth.log(auth.current_actor(), "suppression.delete", f"reason was: {r['reason'][:200]}", target=f"suppression:{sid}")
    return True


# ------------------------------------------------------------------ runner
def run_all():
    c = db.conn()
    cfg = db.get_settings()["rules"]
    now = db.now_ms()
    stats = {"created": 0, "updated": 0, "reopened": 0, "suppressed": 0, "unsuppressed": 0, "per_rule": {}}
    sups = _active_suppressions(c, now)
    c.execute("BEGIN")
    try:
        for name, fn in RULES.items():
            if not cfg.get(name, {}).get("enabled", True):
                stats["per_rule"][name] = None
                continue
            n = 0
            for a in fn(c, cfg.get(name, {})):
                n += 1
                row = c.execute("SELECT id, status, event_count, filter FROM alerts WHERE alert_key=?", (a["key"],)).fetchone()
                details, flt = json.dumps(a["details"]), json.dumps(a["filter"])
                hit = _first_match(sups, a["rule"], a["vin"], a["ecu"], a["cat"])
                if row is None:
                    c.execute("INSERT INTO alerts(alert_key, rule, title, severity, sev_num, vin, ecu_name, cat_id, first_ts, last_ts, event_count, "
                              "status, details, filter, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                              (a["key"], a["rule"], a["title"], a["severity"], SEV_NUM[a["severity"]], a["vin"], a["ecu"], a["cat"],
                               a["first_ts"], a["last_ts"], a["count"], "suppressed" if hit else "new", details, flt, now, now))
                    db.cover_alert(c, c.execute("SELECT last_insert_rowid()").fetchone()[0], flt)
                    stats["created"] += 1
                    if hit:
                        stats["suppressed"] += 1
                else:
                    status = row["status"]
                    if status == "new" and hit:
                        status = "suppressed"
                        stats["suppressed"] += 1
                        c.execute("INSERT INTO alert_comments(alert_id, author, body, created_at) VALUES(?,?,?,?)",
                                  (row["id"], "system", f"Suppressed by rule #{hit['id']}: {hit['reason']}", now))
                    elif status == "suppressed" and not hit:
                        status = "new"
                        stats["unsuppressed"] += 1
                        c.execute("INSERT INTO alert_comments(alert_id, author, body, created_at) VALUES(?,?,?,?)",
                                  (row["id"], "system", "No suppression rule applies any more. Back to new.", now))
                    if status in ("resolved", "false_positive") and a["count"] > row["event_count"]:
                        status = "new"
                        c.execute("INSERT INTO alert_comments(alert_id, author, body, created_at) VALUES(?,?,?,?)",
                                  (row["id"], "system", f"Re-opened: {a['count'] - row['event_count']} new matching event(s).", now))
                        stats["reopened"] += 1
                        auth.log("system", "alert.reopen", f"{a['count'] - row['event_count']} new matching event(s)", target=f"alert:{row['id']}", via="detection")
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
                    if changed or row["filter"] != flt:
                        db.cover_alert(c, row["id"], flt)
                    if changed:
                        stats["updated"] += 1
            stats["per_rule"][name] = n
        # A new_event_type alert whose catalog entry has since been classified is no longer relevant
        c.execute("UPDATE alerts SET status='resolved', updated_at=? WHERE rule='new_event_type' AND status IN ('new','in_progress') "
                  "AND cat_id IN (SELECT cat_id FROM catalog WHERE auto=0)", (now,))
        stats["unsuppressed"] += _sweep(c, sups, now)
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
    return stats


# ------------------------------------------------------------------ alert access
STATUSES = ["new", "in_progress", "resolved", "false_positive"]


SUGGEST_DAYS = 30


def suggest_cases(c, a, limit=3):
    """Cases that already deal with the same thing: same vehicle and event type (or same detection when the alert has no
    event type), with the other alert's activity within 30 days of this one. Only a hint, nothing is linked."""
    if a["case_id"] if "case_id" in a.keys() else c.execute("SELECT 1 FROM case_alerts WHERE alert_id=?", (a["id"],)).fetchone():
        return []
    when = a["first_ts"] or a["created_at"]
    span = SUGGEST_DAYS * 86400000
    if a["cat_id"]:
        same, args = "b.cat_id = ?", [a["cat_id"]]
    else:
        same, args = "b.rule = ?", [a["rule"]]
    vin = "b.vin = ?" if a["vin"] else "b.vin IS NULL"
    if a["vin"]:
        args.append(a["vin"])
    rows = c.execute(
        f"SELECT cs.id, cs.title, cs.status, cs.resolution, b.id AS alert_id, b.status AS alert_status, "
        f"COALESCE(b.last_ts, b.created_at) AS seen FROM case_alerts ca JOIN alerts b ON b.id = ca.alert_id "
        f"JOIN cases cs ON cs.id = ca.case_id WHERE b.id <> ? AND {same} AND {vin} "
        f"AND ABS(COALESCE(b.last_ts, b.created_at) - ?) <= ? "
        f"ORDER BY (cs.status = 'closed'), seen DESC", [a["id"]] + args + [when, span]).fetchall()
    out, seen = [], set()
    for r in rows:
        if r["id"] in seen:
            continue
        seen.add(r["id"])
        out.append({"id": r["id"], "title": r["title"], "status": r["status"], "resolution": r["resolution"],
                    "alert_id": r["alert_id"], "alert_status": r["alert_status"],
                    "basis": "same vehicle and event type" if a["cat_id"] and a["vin"] else
                             ("same event type" if a["cat_id"] else "same vehicle and detection" if a["vin"] else "same detection")})
        if len(out) >= limit:
            break
    return out


def _alert_row(r):
    d = dict(r)
    d["details"] = json.loads(d["details"] or "{}")
    d["filter"] = json.loads(d["filter"] or "{}")
    d["rule_title"] = RULE_INFO.get(d["rule"], (d["rule"], ""))[0]
    return d


def list_alerts(p):
    sweep_expired()
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
    alerts = [_alert_row(r) for r in rows]
    for al in alerts:
        al["suggested_case"] = None
        if al["status"] in ("new", "in_progress") and not al["case_id"]:
            sg = [x for x in suggest_cases(c, al, 1) if x["status"] != "closed"]
            al["suggested_case"] = sg[0]["id"] if sg else None
    return {"total": total, "page": page, "size": size, "alerts": alerts, "status_counts": counts}


def get_alert(aid):
    c = db.conn()
    r = c.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
    if not r:
        return None
    d = _alert_row(r)
    cs = c.execute("SELECT cs.id, cs.title, cs.status FROM case_alerts ca JOIN cases cs ON cs.id=ca.case_id WHERE ca.alert_id=?", (aid,)).fetchone()
    d["case"] = dict(cs) if cs else None
    d["suggested_cases"] = [] if cs else suggest_cases(c, r)
    d["comments"] = [dict(x) for x in c.execute("SELECT * FROM alert_comments WHERE alert_id=? ORDER BY created_at", (aid,))]
    d["rule_description"] = RULE_INFO.get(d["rule"], ("", ""))[1]
    return d


def update_alert(aid, body):
    c = db.conn()
    r = c.execute("SELECT status, assignee FROM alerts WHERE id=?", (aid,)).fetchone()
    if not r:
        return None
    now = db.now_ms()
    who = auth.current_name()
    if "status" in body and body["status"] != r["status"]:
        if body["status"] not in STATUSES:
            raise ValueError("invalid status")
        c.execute("UPDATE alerts SET status=?, updated_at=? WHERE id=?", (body["status"], now, aid))
        c.execute("INSERT INTO alert_comments(alert_id, author, body, created_at) VALUES(?,?,?,?)",
                  (aid, "system", f"{who} changed status: {r['status']} → {body['status']}", now))
        auth.log(auth.current_actor(), "alert.status", f"{r['status']} → {body['status']}", target=f"alert:{aid}")
    if "assignee" in body and body["assignee"] != r["assignee"]:
        c.execute("UPDATE alerts SET assignee=?, updated_at=? WHERE id=?", (str(body["assignee"])[:60], now, aid))
        auth.log(auth.current_actor(), "alert.assign", f"'{r['assignee']}' → '{str(body['assignee'])[:60]}'", target=f"alert:{aid}")
    if body.get("comment"):
        c.execute("INSERT INTO alert_comments(alert_id, author, body, created_at) VALUES(?,?,?,?)", (aid, who, str(body["comment"])[:5000], now))
        auth.log(auth.current_actor(), "alert.comment", f"note added ({len(str(body['comment']))} characters)", target=f"alert:{aid}")
        c.execute("UPDATE alerts SET updated_at=? WHERE id=?", (now, aid))
    c.commit()
    return get_alert(aid)


def bulk_update(ids, status):
    if status not in STATUSES:
        raise ValueError("invalid status")
    for i in ids:
        update_alert(int(i), {"status": status})
    return len(ids)
