"""Search, facets, timelines and aggregates over the event store."""
import datetime
import json
import re

from . import db, sevconfig
from .catalog import SEVERITIES

BASE = "FROM events e JOIN catalog c ON c.cat_id = e.cat_id"

SORTABLE = {
    "ts": "e.ts_ok DESC, e.ts {d}, e.id {d}",
    "vin": "e.vin {d}, e.ts_ok DESC, e.ts DESC",
    "ecu": "e.ecu_name {d}, e.ts_ok DESC, e.ts DESC",
    "event": "c.short_name {d}, e.ts_ok DESC, e.ts DESC",
    "severity": "c.sev_num {d}, e.ts_ok DESC, e.ts DESC",
    "type": "e.event_type {d}, e.ts_ok DESC, e.ts DESC",
}

TOKEN_RE = re.compile(r'(-?)(?:([A-Za-z_]+):)?("(?:[^"]*)"|\S+)')


def _like(v):
    v = v.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{v}%"


def _unq(v):
    return v[1:-1] if len(v) >= 2 and v[0] == v[-1] == '"' else v


def _to_ms(v, end=False):
    """Accepts epoch ms or YYYY-MM-DD[THH:MM]."""
    if v in (None, ""):
        return None
    s = str(v).strip()
    if s.isdigit():
        return int(s)
    try:
        d = datetime.datetime.fromisoformat(s)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=datetime.timezone.utc)
    ms = int(d.timestamp() * 1000)
    if end and len(s) <= 10:
        ms += 86400000 - 1  # a bare date means the whole day
    elif end and len(s) <= 16:
        ms += 59999  # HH:MM means the whole minute
    return ms


def _covering(events):
    """Alerts (with their case) whose filter contains each event, added to the events as "alerts"."""
    by_id = {e["id"]: e for e in events}
    for e in events:
        e["alerts"] = []
    if not by_id:
        return events
    ids = list(by_id)
    for r in rows("SELECT ae.event_id, a.id, a.status, a.severity, a.title, ca.case_id FROM alert_events ae "
                  "JOIN alerts a ON a.id = ae.alert_id LEFT JOIN case_alerts ca ON ca.alert_id = a.id "
                  f"WHERE ae.event_id IN ({','.join('?' * len(ids))}) ORDER BY a.sev_num DESC, a.id", ids):
        by_id[r["event_id"]]["alerts"].append({k: r[k] for k in ("id", "status", "severity", "title", "case_id")})
    return events


def build_where(p):
    """p: dict of query params (values are lists). Returns (where_sql, args)."""
    def one(k):
        v = p.get(k)
        return v[0] if v else None

    def many(k):
        out = []
        for v in p.get(k, []):
            out += [x for x in v.split(",") if x != ""]
        return out

    w, a = ["1=1"], []
    for col, key in (("e.ecu_name", "ecu"), ("e.event_type", "type"), ("c.severity", "severity"),
                     ("c.category", "category"), ("e.vin_prefix", "vin_prefix"), ("e.cat_id", "cat")):
        vals = many(key)
        if vals:
            if key == "ecu":
                vals = ["" if v == "(none)" else v for v in vals]
            w.append(f"{col} IN ({','.join('?' * len(vals))})")
            a += vals
    if one("vin"):
        w.append("e.vin = ?")
        a.append(one("vin").upper())
    if one("import_id"):
        w.append("e.import_id = ?")
        a.append(int(one("import_id")))
    lo, hi = _to_ms(one("from")), _to_ms(one("to"), end=True)
    if lo is not None:
        w.append("e.ts_ok = 1 AND e.ts >= ?")
        a.append(lo)
    if hi is not None:
        w.append("e.ts_ok = 1 AND e.ts <= ?")
        a.append(hi)
    tsq = one("ts")
    if tsq == "valid":
        w.append("e.ts_ok = 1")
    elif tsq == "invalid":
        w.append("e.ts_ok = 0")

    # coverage: is the event inside the filter of an alert, and is that alert in a case
    al, cs = one("alert"), one("case")
    if al in ("any", "none"):
        w.append(("" if al == "any" else "NOT ") + "EXISTS (SELECT 1 FROM alert_events ae WHERE ae.event_id = e.id)")
    if cs in ("any", "none"):
        w.append(("" if cs == "any" else "NOT ") + "EXISTS (SELECT 1 FROM alert_events ae JOIN case_alerts ca ON ca.alert_id = ae.alert_id WHERE ae.event_id = e.id)")

    q = (one("q") or "").strip()
    for m in TOKEN_RE.finditer(q):
        neg, field, val = m.group(1) == "-", (m.group(2) or "").lower(), _unq(m.group(3))
        if not val:
            continue
        cond, args = None, []
        if field in ("vin",):
            cond, args = "e.vin LIKE ? ESCAPE '\\'", [_like(val.upper())]
        elif field == "ecu":
            cond, args = "e.ecu_name = ? COLLATE NOCASE", [val]
        elif field == "type":
            cond, args = "e.event_type = ? COLLATE NOCASE", [val]
        elif field == "name":
            cond, args = "(e.name LIKE ? ESCAPE '\\' OR c.short_name LIKE ? ESCAPE '\\')", [_like(val)] * 2
        elif field == "id":
            cond, args = "e.event_id = ?", [val]
        elif field in ("sev", "severity"):
            cond, args = "c.severity = ? COLLATE NOCASE", [val]
        elif field in ("cat", "category"):
            cond, args = "c.category LIKE ? ESCAPE '\\'", [_like(val)]
        elif field in ("desc", "description"):
            cond, args = "e.description LIKE ? ESCAPE '\\'", [_like(val)]
        elif field == "ts":
            cond = "e.ts_ok = ?"
            args = [0 if val.lower().startswith("inv") else 1]
        elif field == "":
            cond = "(e.vin LIKE ? ESCAPE '\\' OR e.name LIKE ? ESCAPE '\\' OR e.description LIKE ? ESCAPE '\\' OR c.short_name LIKE ? ESCAPE '\\')"
            args = [_like(val)] * 4
        else:  # unknown "field:" -> treat the whole token as free text
            cond = "(e.name LIKE ? ESCAPE '\\' OR e.description LIKE ? ESCAPE '\\')"
            args = [_like(f"{field}:{val}")] * 2
        w.append(("NOT " if neg else "") + cond)
        a += args
    return " AND ".join(w), a


def rows(sql, args=()):
    return [dict(r) for r in db.conn().execute(sql, args).fetchall()]


def one_val(sql, args=()):
    r = db.conn().execute(sql, args).fetchone()
    return r[0] if r else None


EVENT_COLS = ("e.id, e.ts, e.ts_ok, e.vin, e.event_type, e.ecu_name, e.ecu_id, e.event_id, e.cat_id, e.name, e.description, "
              "c.short_name, c.category, c.severity, c.sev_num, e.import_id")


def search_events(p):
    where, args = build_where(p)
    page = max(1, int((p.get("page") or ["1"])[0]))
    size = min(500, max(1, int((p.get("size") or ["50"])[0])))
    sort = (p.get("sort") or ["ts"])[0]
    d = "ASC" if (p.get("dir") or ["desc"])[0].lower() == "asc" else "DESC"
    order = SORTABLE.get(sort, SORTABLE["ts"]).format(d=d)
    total = one_val(f"SELECT COUNT(*) {BASE} WHERE {where}", args)
    data = rows(f"SELECT {EVENT_COLS} {BASE} WHERE {where} ORDER BY {order} LIMIT ? OFFSET ?", args + [size, (page - 1) * size])
    return {"total": total, "page": page, "size": size, "events": _covering(data)}


def iter_events_for_export(p):
    where, args = build_where(p)
    cur = db.conn().execute(f"SELECT {EVENT_COLS} {BASE} WHERE {where} ORDER BY e.ts_ok DESC, e.ts DESC", args)
    while True:
        chunk = cur.fetchmany(2000)
        if not chunk:
            return
        for r in chunk:
            yield dict(r)


def get_event(eid):
    r = rows(f"SELECT {EVENT_COLS} {BASE} WHERE e.id = ?", [eid])
    if not r:
        return None
    ev = r[0]
    note = db.conn().execute("SELECT note FROM event_notes WHERE event_id=?", (eid,)).fetchone()
    ev["note"] = note["note"] if note else ""
    x = db.conn().execute("SELECT extra FROM events WHERE id=?", (eid,)).fetchone()
    try:
        extra = json.loads(x["extra"]) if x and x["extra"] else {}
    except ValueError:
        extra = {}
    ev["alerts"] = _covering([ev])[0]["alerts"]
    ev["backend"] = extra
    ev["configured"] = sevconfig.describe(ev["ecu_id"], ev["event_id"], extra)
    # neighbours on the same vehicle (±1 h around this event, otherwise the 10 most recent)
    if ev["ts_ok"]:
        ev["related"] = rows(
            f"SELECT {EVENT_COLS} {BASE} WHERE e.vin=? AND e.id<>? AND e.ts_ok=1 AND e.ts BETWEEN ? AND ? ORDER BY e.ts LIMIT 25",
            [ev["vin"], eid, ev["ts"] - 3600000, ev["ts"] + 3600000])
        ev["related_label"] = "Same vehicle, within ±1 hour"
    else:
        ev["related"] = rows(f"SELECT {EVENT_COLS} {BASE} WHERE e.vin=? AND e.id<>? ORDER BY e.ts_ok DESC, e.ts DESC LIMIT 10", [ev["vin"], eid])
        ev["related_label"] = "Same vehicle, most recent"
    return ev


def facets(p):
    where, args = build_where(p)
    out = {}
    for key, col in (("severity", "c.severity"), ("ecu", "e.ecu_name"), ("type", "e.event_type"),
                     ("category", "c.category"), ("vin_prefix", "e.vin_prefix")):
        r = rows(f"SELECT {col} AS value, COUNT(*) AS n {BASE} WHERE {where} GROUP BY {col} ORDER BY n DESC", args)
        for x in r:
            if x["value"] in ("", None):
                x["value"] = "(none)"
        if key == "severity":
            r.sort(key=lambda x: -SEVERITIES.index(x["value"]) if x["value"] in SEVERITIES else 0)
        out[key] = r
    out["event"] = rows(
        f"SELECT e.cat_id AS value, c.short_name AS label, c.severity AS severity, COUNT(*) AS n {BASE} WHERE {where} "
        f"GROUP BY e.cat_id ORDER BY n DESC LIMIT 40", args)
    return out


BUCKETS = [("hour", 3600000), ("6 hours", 6 * 3600000), ("day", 86400000), ("week", 7 * 86400000), ("30 days", 30 * 86400000)]


def timeline(p):
    where, args = build_where(p)
    group = (p.get("group") or ["severity"])[0]
    gcol = {"severity": "c.severity", "ecu": "CASE WHEN e.ecu_name='' THEN '(none)' ELSE e.ecu_name END", "type": "e.event_type",
            "category": "c.category", "none": "'events'"}.get(group, "c.severity")
    vw = f"{where} AND e.ts_ok = 1"
    rng = db.conn().execute(f"SELECT MIN(e.ts) lo, MAX(e.ts) hi {BASE} WHERE {vw}", args).fetchone()
    if rng["lo"] is None:
        return {"bucket_ms": 0, "bucket_label": "", "series": [], "groups": [], "invalid": _invalid_count(where, args)}
    span = max(rng["hi"] - rng["lo"], 1)
    want = int((p.get("buckets") or ["90"])[0])
    label, size = next(((l, s) for l, s in BUCKETS if span / s <= want), BUCKETS[-1])
    data = rows(f"SELECT (e.ts / {size}) * {size} AS t, {gcol} AS g, COUNT(*) AS n {BASE} WHERE {vw} GROUP BY t, g ORDER BY t", args)
    groups = sorted({r["g"] for r in data}, key=lambda g: (SEVERITIES.index(g) if g in SEVERITIES else 99, g))
    series = {}
    for r in data:
        series.setdefault(r["t"], {})[r["g"]] = r["n"]
    return {"bucket_ms": size, "bucket_label": label, "lo": rng["lo"], "hi": rng["hi"],
            "series": [{"t": t, "counts": series[t]} for t in sorted(series)], "groups": groups,
            "invalid": _invalid_count(where, args)}


def _invalid_count(where, args):
    return one_val(f"SELECT COUNT(*) {BASE} WHERE {where} AND e.ts_ok = 0", args)


def top(p):
    where, args = build_where(p)
    by = (p.get("by") or ["vin"])[0]
    limit = min(50, int((p.get("limit") or ["10"])[0]))
    if by == "vin":
        sql = f"SELECT e.vin AS key, e.vin AS label, COUNT(*) AS n, MAX(c.sev_num) AS sev_num {BASE} WHERE {where} GROUP BY e.vin ORDER BY n DESC LIMIT ?"
    elif by == "ecu":
        sql = f"SELECT e.ecu_name AS key, CASE WHEN e.ecu_name='' THEN '(none)' ELSE e.ecu_name END AS label, COUNT(*) AS n, MAX(c.sev_num) AS sev_num {BASE} WHERE {where} GROUP BY e.ecu_name ORDER BY n DESC LIMIT ?"
    else:
        sql = f"SELECT e.cat_id AS key, c.short_name AS label, COUNT(*) AS n, MAX(c.sev_num) AS sev_num {BASE} WHERE {where} GROUP BY e.cat_id ORDER BY n DESC LIMIT ?"
    r = rows(sql, args + [limit])
    for x in r:
        x["severity"] = SEVERITIES[x["sev_num"]]
    return r


def summary(p):
    where, args = build_where(p)
    c = db.conn()
    r = c.execute(
        f"SELECT COUNT(*) total, COUNT(DISTINCT e.vin) vins, COUNT(DISTINCT NULLIF(e.ecu_name,'')) ecus, COUNT(DISTINCT e.cat_id) types, "
        f"SUM(e.ts_ok=0) no_ts, MIN(CASE WHEN e.ts_ok=1 THEN e.ts END) first_ts, MAX(CASE WHEN e.ts_ok=1 THEN e.ts END) last_ts, "
        f"SUM(c.sev_num>=3) high {BASE} WHERE {where}", args).fetchone()
    out = dict(r)
    for k in out:
        if out[k] is None:
            out[k] = 0 if k not in ("first_ts", "last_ts") else None
    al = rows("SELECT severity, COUNT(*) n FROM alerts WHERE status IN ('new','in_progress') GROUP BY severity")
    out["open_alerts"] = {x["severity"]: x["n"] for x in al}
    out["open_alerts_total"] = sum(x["n"] for x in al)
    out["new_alerts"] = one_val("SELECT COUNT(*) FROM alerts WHERE status='new'")
    out["unclassified_types"] = one_val("SELECT COUNT(*) FROM catalog WHERE auto=1")
    out["open_cases"] = one_val("SELECT COUNT(*) FROM cases WHERE status <> 'closed'")
    return out


from . import vin as vinmod

RISK_WEIGHT = {0: 0, 1: 1, 2: 3, 3: 10, 4: 25}


def _vin_attr_filter(p, where, args):
    """Restrict to VINs whose decoded attributes match, e.g. year=2024&engine=Diesel EU6d."""
    want = {d: (p.get(d) or [""])[0] for d in vinmod.DIMENSIONS if (p.get(d) or [""])[0]}
    if not want:
        return where, args
    ok = [r["vin"] for r in rows("SELECT DISTINCT vin FROM events WHERE vin IS NOT NULL AND vin <> ''")
          if all(vinmod.dim_value(vinmod.decode(r["vin"]), d) == val for d, val in want.items())]
    if not ok:
        return where + " AND 0", args
    return where + " AND e.vin IN (" + ",".join("?" * len(ok)) + ")", args + ok


def fleet_profile():
    """Vehicles, events and high or critical events grouped by each decoded VIN attribute."""
    per = rows(f"SELECT e.vin AS vin, COUNT(*) AS events, SUM(c.sev_num>=3) AS high {BASE} "
               f"WHERE e.vin IS NOT NULL AND e.vin <> '' GROUP BY e.vin")
    out = {d: {} for d in vinmod.DIMENSIONS}
    bad = []
    for r in per:
        info = vinmod.decode(r["vin"])
        if not info["valid"] or info["unknown"]:
            bad.append({"vin": r["vin"], "problem": info.get("problem") or "Unknown code: " + ", ".join(info["unknown"])})
        for d in vinmod.DIMENSIONS:
            g = out[d].setdefault(vinmod.dim_value(info, d), {"vehicles": 0, "events": 0, "high": 0})
            g["vehicles"] += 1
            g["events"] += r["events"] or 0
            g["high"] += r["high"] or 0
    dims = []
    for d, name in vinmod.DIMENSIONS.items():
        items = [{"value": k, **v} for k, v in out[d].items()]
        items.sort(key=lambda x: (-x["vehicles"], x["value"]))
        dims.append({"key": d, "name": name, "items": items})
    return {"vehicles": len(per), "dimensions": dims, "check_failed": sum(
        1 for r in per if (lambda i: i["valid"] and not i["check_ok"])(vinmod.decode(r["vin"]))), "undecodable": bad[:20]}


def vehicles(p):
    where, args = build_where(p)
    where, args = _vin_attr_filter(p, where, args)
    page = max(1, int((p.get("page") or ["1"])[0]))
    size = min(200, max(1, int((p.get("size") or ["50"])[0])))
    sort = (p.get("sort") or ["risk"])[0]
    d = "ASC" if (p.get("dir") or ["desc"])[0].lower() == "asc" else "DESC"
    col = {"vin": "vin", "events": "events", "last": "last_seen", "first": "first_seen", "risk": "risk", "high": "high",
           "ecus": "ecus", "sev": "max_sev"}.get(sort, "risk")
    risk = " + ".join(f"SUM(c.sev_num={k})*{v}" for k, v in RISK_WEIGHT.items() if v)
    inner = (f"SELECT e.vin AS vin, COUNT(*) AS events, SUM(c.sev_num>=3) AS high, MAX(c.sev_num) AS max_sev, "
             f"COUNT(DISTINCT NULLIF(e.ecu_name,'')) AS ecus, MIN(CASE WHEN e.ts_ok=1 THEN e.ts END) AS first_seen, "
             f"MAX(CASE WHEN e.ts_ok=1 THEN e.ts END) AS last_seen, ({risk}) AS risk {BASE} WHERE {where} GROUP BY e.vin")
    total = one_val(f"SELECT COUNT(*) FROM ({inner})", args)
    data = rows(f"SELECT * FROM ({inner}) ORDER BY {col} {d}, vin LIMIT ? OFFSET ?", args + [size, (page - 1) * size])
    open_by_vin = {r["vin"]: r["n"] for r in rows("SELECT vin, COUNT(*) n FROM alerts WHERE status IN ('new','in_progress') AND vin IS NOT NULL GROUP BY vin")}
    for v in data:
        v["max_severity"] = SEVERITIES[v["max_sev"] or 0]
        v["open_alerts"] = open_by_vin.get(v["vin"], 0)
        v["info"] = vinmod.decode(v["vin"])
    return {"total": total, "page": page, "size": size, "vehicles": data}


def vehicle(vin):
    vin = vin.upper()
    s = summary({"vin": [vin]})
    if not s["total"]:
        return None
    by_event = rows(
        f"SELECT e.cat_id, c.short_name, c.severity, e.ecu_name, COUNT(*) n, MIN(CASE WHEN e.ts_ok=1 THEN e.ts END) first_ts, "
        f"MAX(CASE WHEN e.ts_ok=1 THEN e.ts END) last_ts {BASE} WHERE e.vin=? GROUP BY e.cat_id, e.ecu_name ORDER BY c.sev_num DESC, n DESC", [vin])
    alerts = rows("SELECT id, rule, title, severity, status, event_count, last_ts FROM alerts WHERE vin=? ORDER BY sev_num DESC, updated_at DESC", [vin])
    return {"vin": vin, "info": vinmod.decode(vin), "summary": s, "by_event": by_event, "alerts": alerts}
