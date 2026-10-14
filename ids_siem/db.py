"""SQLite storage. One connection per thread, WAL mode."""
import json
import os
import sqlite3
import threading
import time

DB_PATH = os.environ.get("IDS_SIEM_DB", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "siem.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS imports(
  id INTEGER PRIMARY KEY,
  filename TEXT, source TEXT, imported_at INTEGER,
  rows_total INTEGER, rows_new INTEGER, rows_dup INTEGER, rows_invalid INTEGER
);
CREATE TABLE IF NOT EXISTS catalog(
  cat_id TEXT PRIMARY KEY,
  event_type TEXT, event_id INTEGER,
  short_name TEXT, category TEXT,
  severity TEXT, sev_num INTEGER,
  notes TEXT DEFAULT '',
  auto INTEGER DEFAULT 0,
  first_seen INTEGER
);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY,
  dedupe_key TEXT UNIQUE,
  import_id INTEGER,
  event_type TEXT, ts INTEGER, ts_ok INTEGER DEFAULT 0,
  vin TEXT, vin_prefix TEXT,
  ecu_name TEXT, ecu_id TEXT,
  event_id INTEGER, cat_id TEXT,
  name TEXT, description TEXT
);
CREATE INDEX IF NOT EXISTS ix_ev_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_ev_vin ON events(vin);
CREATE INDEX IF NOT EXISTS ix_ev_cat ON events(cat_id);
CREATE INDEX IF NOT EXISTS ix_ev_ecu ON events(ecu_name);
CREATE INDEX IF NOT EXISTS ix_ev_import ON events(import_id);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY,
  alert_key TEXT UNIQUE,
  rule TEXT, title TEXT,
  severity TEXT, sev_num INTEGER,
  vin TEXT, ecu_name TEXT, cat_id TEXT,
  first_ts INTEGER, last_ts INTEGER, event_count INTEGER,
  status TEXT DEFAULT 'new', assignee TEXT DEFAULT '',
  details TEXT, filter TEXT,
  created_at INTEGER, updated_at INTEGER
);
CREATE INDEX IF NOT EXISTS ix_al_status ON alerts(status);
CREATE TABLE IF NOT EXISTS alert_comments(
  id INTEGER PRIMARY KEY, alert_id INTEGER, author TEXT, body TEXT, created_at INTEGER
);
CREATE TABLE IF NOT EXISTS event_notes(
  event_id INTEGER PRIMARY KEY, note TEXT, updated_at INTEGER
);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
"""

DEFAULT_SETTINGS = {
    # Timestamps before this date (or in the far future) are treated as an unsynchronised ECU clock.
    "ts_min": "2022-01-01",
    "analyst": "analyst",
    "rules": {
        "high_sev": {"enabled": True, "min_severity": "high"},
        "burst": {"enabled": True, "threshold": 3, "window_min": 60},
        "multi_ecu": {"enabled": True, "min_ecus": 3},
        "vehicle_outlier": {"enabled": True, "sigma": 3.0, "min_events": 10},
        "fleet_spike": {"enabled": True, "sigma": 3.0, "min_events": 30},
        "new_event_type": {"enabled": True},
    },
}

_local = threading.local()


def conn():
    c = getattr(_local, "c", None)
    if c is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        c = sqlite3.connect(DB_PATH, timeout=30)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        _local.c = c
    return c


def init():
    c = conn()
    c.executescript(SCHEMA)
    c.commit()


def now_ms():
    return int(time.time() * 1000)


def get_settings():
    c = conn()
    out = json.loads(json.dumps(DEFAULT_SETTINGS))
    for r in c.execute("SELECT key, value FROM settings"):
        try:
            v = json.loads(r["value"])
        except ValueError:
            continue
        if r["key"] == "rules" and isinstance(v, dict):
            for rule, params in v.items():
                if rule in out["rules"] and isinstance(params, dict):
                    out["rules"][rule].update(params)
        else:
            out[r["key"]] = v
    return out


def put_settings(new):
    c = conn()
    cur = get_settings()
    if "ts_min" in new:
        cur["ts_min"] = str(new["ts_min"])
    if "analyst" in new:
        cur["analyst"] = str(new["analyst"])[:60] or "analyst"
    if isinstance(new.get("rules"), dict):
        for rule, params in new["rules"].items():
            if rule in cur["rules"] and isinstance(params, dict):
                for k, v in params.items():
                    if k in cur["rules"][rule]:
                        cur["rules"][rule][k] = v
    for k in ("ts_min", "analyst", "rules"):
        c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)", (k, json.dumps(cur[k])))
    c.commit()
    recompute_ts_ok()
    return cur


def ts_bounds():
    """(min_ms, max_ms) of plausible timestamps."""
    import datetime
    s = get_settings()
    try:
        d = datetime.datetime.strptime(s["ts_min"], "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        d = datetime.datetime(2022, 1, 1, tzinfo=datetime.timezone.utc)
    return int(d.timestamp() * 1000), now_ms() + 86400000


def recompute_ts_ok():
    lo, hi = ts_bounds()
    c = conn()
    c.execute("UPDATE events SET ts_ok = CASE WHEN ts IS NOT NULL AND ts BETWEEN ? AND ? THEN 1 ELSE 0 END", (lo, hi))
    c.commit()
