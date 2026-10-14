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
CREATE INDEX IF NOT EXISTS ix_al_vin ON alerts(vin);
CREATE TABLE IF NOT EXISTS suppressions(
  id INTEGER PRIMARY KEY,
  rule TEXT DEFAULT '', vin TEXT DEFAULT '', ecu_name TEXT DEFAULT '', cat_id TEXT DEFAULT '',
  reason TEXT NOT NULL,
  created_by TEXT, created_at INTEGER,
  expires_at INTEGER,
  enabled INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS alert_comments(
  id INTEGER PRIMARY KEY, alert_id INTEGER, author TEXT, body TEXT, created_at INTEGER
);
CREATE TABLE IF NOT EXISTS event_notes(
  event_id INTEGER PRIMARY KEY, note TEXT, updated_at INTEGER
);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS cases(
  id INTEGER PRIMARY KEY,
  title TEXT, summary TEXT DEFAULT '',
  severity TEXT, sev_num INTEGER,
  status TEXT DEFAULT 'open',
  owner TEXT DEFAULT '', due_date TEXT DEFAULT '',
  resolution TEXT DEFAULT '', findings TEXT DEFAULT '',
  created_by TEXT DEFAULT '',
  created_at INTEGER, updated_at INTEGER, closed_at INTEGER
);
CREATE INDEX IF NOT EXISTS ix_cases_status ON cases(status);
CREATE TABLE IF NOT EXISTS case_alerts(
  case_id INTEGER, alert_id INTEGER UNIQUE, linked_at INTEGER,
  PRIMARY KEY(case_id, alert_id)
);
CREATE TABLE IF NOT EXISTS case_tasks(
  id INTEGER PRIMARY KEY, case_id INTEGER, title TEXT,
  done INTEGER DEFAULT 0, done_at INTEGER, done_by TEXT DEFAULT '', position INTEGER
);
CREATE INDEX IF NOT EXISTS ix_ct_case ON case_tasks(case_id);
CREATE TABLE IF NOT EXISTS case_log(
  id INTEGER PRIMARY KEY, case_id INTEGER, author TEXT, kind TEXT, body TEXT, created_at INTEGER
);
CREATE INDEX IF NOT EXISTS ix_cl_case ON case_log(case_id);
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT DEFAULT '',
  role TEXT NOT NULL DEFAULT 'viewer',
  pw_hash TEXT NOT NULL,
  active INTEGER DEFAULT 1,
  failed INTEGER DEFAULT 0, locked_until INTEGER DEFAULT 0,
  created_at INTEGER, last_login INTEGER
);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY, user_id INTEGER,
  created_at INTEGER, last_seen INTEGER, expires_at INTEGER
);
CREATE INDEX IF NOT EXISTS ix_sess_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS mfa_creds(
  id INTEGER PRIMARY KEY, user_id INTEGER, kind TEXT, name TEXT, cred_id TEXT,
  data TEXT, created_at INTEGER, last_used INTEGER, confirmed INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_mfa_user ON mfa_creds(user_id);
CREATE INDEX IF NOT EXISTS ix_mfa_cred ON mfa_creds(cred_id);
CREATE TABLE IF NOT EXISTS mfa_recovery(
  id INTEGER PRIMARY KEY, user_id INTEGER, code_hash TEXT, used_at INTEGER
);
CREATE INDEX IF NOT EXISTS ix_mfar_user ON mfa_recovery(user_id);
CREATE TABLE IF NOT EXISTS api_tokens(
  id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT,
  token_hash TEXT UNIQUE, preview TEXT,
  perm TEXT, created_at INTEGER, expires_at INTEGER, last_used INTEGER, revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS ix_tok_user ON api_tokens(user_id);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY, ts INTEGER, actor TEXT, action TEXT, detail TEXT,
  via TEXT DEFAULT '', target TEXT DEFAULT '', hash TEXT
);
CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit(ts);
"""

DEFAULT_SETTINGS = {
    # Timestamps before this date (or in the far future) are treated as an unsynchronised ECU clock.
    "ts_min": "2022-01-01",
    "analyst": "analyst",
    # Checklist every new case starts with (editable on the Data page, one line per task)
    "case_tasks": [
        "Review the linked events and the vehicle history",
        "Check whether other vehicles show the same pattern",
        "Assess the impact on TARA threat scenarios and CSMS",
        "Decide on the response and whether reporting is needed",
        "Document the findings",
    ],
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
        try:  # the file holds password hashes and a backend token: owner only
            os.chmod(DB_PATH, 0o600)
        except OSError:
            pass
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        _local.c = c
    return c


def init():
    c = conn()
    c.executescript(SCHEMA)
    have = {r["name"] for r in c.execute("PRAGMA table_info(audit)")}
    for col, ddl in (("via", "TEXT DEFAULT ''"), ("target", "TEXT DEFAULT ''"), ("hash", "TEXT")):
        if col not in have:  # database created by an earlier version
            c.execute(f"ALTER TABLE audit ADD COLUMN {col} {ddl}")
    if "extra" not in {r["name"] for r in c.execute("PRAGMA table_info(events)")}:
        c.execute("ALTER TABLE events ADD COLUMN extra TEXT")  # backend details (context data, counters), JSON
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
        if r["key"].startswith("_"):
            continue  # private (auth policy, backend secret): never part of /api/settings
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
    if isinstance(new.get("case_tasks"), list):
        cur["case_tasks"] = [str(t).strip()[:200] for t in new["case_tasks"] if str(t).strip()][:20]
    if isinstance(new.get("rules"), dict):
        for rule, params in new["rules"].items():
            if rule in cur["rules"] and isinstance(params, dict):
                for k, v in params.items():
                    if k in cur["rules"][rule]:
                        cur["rules"][rule][k] = v
    for k in ("ts_min", "analyst", "rules", "case_tasks"):
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
