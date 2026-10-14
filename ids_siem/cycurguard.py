"""Pull events from the CycurGUARD backend (REST) into the local database.

How it pages: the backend returns at most ~10,000 results per search, so the sync walks forward through
`cg_ingest_timestamp` (when CycurGUARD received the data), oldest first. Each page starts at the newest timestamp of the
previous one, inclusive, so nothing at a boundary is lost; the overlap is harmless because every event is stored under
its backend id. A sync stops when a page brings no newer timestamp.
"""
import datetime
import json
import re
import ssl
import threading
import time
import urllib.error
import urllib.request

from . import auth, db, ingest, rules

PAGE = 5000                      # events per request (the backend's own cap is higher)
OVERLAP_MS = 10 * 60 * 1000      # incremental syncs start this far before the last one ended
SOURCE_FIELDS = ["id", "type", "report.event_type", "sev_metadata.timestamp", "cg_ingest_timestamp", "vin", "ecu_name", "ecu_id",
                 "sev_metadata.event_id", "sev_metadata.name", "sev_metadata.description"]
TIMEOUT = 180


class BackendError(Exception):
    def __init__(self, msg, code=502):
        super().__init__(msg)
        self.code = code


# ------------------------------------------------------------------ configuration and HTTP
def config():
    """Backend URL and token. Environment variables win over what the administrator saved (handy for the command line)."""
    import os
    saved = auth.backend_secret()
    url = (os.environ.get("CYCURGUARD_URL") or saved["base_url"] or "").rstrip("/")
    token = (os.environ.get("CYCURGUARD_TOKEN") or saved["token"] or "").strip()
    return {"base_url": url, "token": token}


def _check(cfg):
    if not cfg["base_url"] or not cfg["token"]:
        raise BackendError("The backend is not set up. An administrator can enter its address and API token on the Users page.", 400)


def _request(cfg, method, path, body=None, timeout=TIMEOUT):
    _check(cfg)
    headers = {"Accept": "application/json", "Authorization": "Bearer " + cfg["token"]}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(cfg["base_url"] + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        detail = e.read()[:300].decode("utf-8", "replace")
        if e.code in (401, 403):
            raise BackendError(f"The backend refused the token ({e.code}). It may have expired, or it may be a short-lived login token. "
                               "Create an API token in CycurGUARD with view permission for reports and save it on the Users page.")
        raise BackendError(f"The backend answered {e.code} for {method} {path}: {detail}")
    except urllib.error.URLError as e:
        raise BackendError(f"Cannot reach the backend: {e.reason}")
    except (TimeoutError, OSError) as e:
        raise BackendError(f"Cannot reach the backend: {e}")
    try:
        return json.loads(raw)
    except ValueError:
        raise BackendError(f"The backend did not answer with JSON for {method} {path}")


def _params(from_ms, to_ms, size=None, offset=None, fields=True):
    p = {}
    rng = {}
    if from_ms is not None:
        rng["range_from"] = from_ms
    if to_ms is not None:
        rng["range_to"] = to_ms
    if rng:
        p["filter_params"] = {"cg_ingest_timestamp": {"name": "cg_ingest_timestamp", "filter_ranges": [rng]}}
    if size is not None:
        p["max_results"] = size
        p["offset"] = offset or 0
        p["sort_params"] = [{"field": "cg_ingest_timestamp", "order": "asc"}]
        if fields:
            p["source_fields"] = SOURCE_FIELDS
    return p


def count(cfg, from_ms, to_ms):
    n = _request(cfg, "POST", "/v1/stats/count", _params(from_ms, to_ms))
    if not isinstance(n, int):
        raise BackendError(f"Unexpected answer from /v1/stats/count: {str(n)[:100]}")
    return n


def search(cfg, from_ms, to_ms, size, offset=0):
    try:
        res = _request(cfg, "POST", "/v1/search", _params(from_ms, to_ms, size, offset))
    except BackendError as e:
        if "answered 4" not in str(e) or "refused" in str(e):
            raise
        # some deployments may not accept source_fields: fall back to full records
        res = _request(cfg, "POST", "/v1/search", _params(from_ms, to_ms, size, offset, fields=False))
    if not isinstance(res, dict) or not isinstance(res.get("results"), list):
        raise BackendError("Unexpected answer from /v1/search (no 'results' list)")
    return res["results"]


def version(cfg):
    return _request(cfg, "GET", "/v1/version")


# ------------------------------------------------------------------ mapping
_ISO = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.(\d+))?(?:Z|[+-]00:?00)?$")


def iso_ms(s):
    """'2025-10-04T02:01:28.266277313Z' -> epoch milliseconds (nanosecond fractions are cut, not rounded)."""
    m = _ISO.match(str(s or "").strip())
    if not m:
        return None
    y, mo, d, h, mi, se = (int(x) for x in m.groups()[:6])
    frac = int((m.group(7) or "0")[:3].ljust(3, "0"))
    dt = datetime.datetime(y, mo, d, h, mi, se, tzinfo=datetime.timezone.utc)
    return int(dt.timestamp()) * 1000 + frac


def to_row(rec):
    """One backend record -> the importer's internal field names."""
    return {"backend_id": rec.get("id"),
            "event_type": rec.get("report.event_type") or rec.get("type"),
            "ts": rec.get("sev_metadata.timestamp"),
            "vin": rec.get("vin"), "ecu_name": rec.get("ecu_name"), "ecu_id": rec.get("ecu_id"),
            "event_id": rec.get("sev_metadata.event_id"), "name": rec.get("sev_metadata.name"),
            "description": rec.get("sev_metadata.description")}


# ------------------------------------------------------------------ the sync job
_lock = threading.Lock()
STATE = {"running": False, "cancel": False, "phase": "", "started_at": None, "finished_at": None, "mode": "",
         "total": None, "fetched": 0, "new": 0, "duplicate": 0, "matched": 0, "pages": 0, "error": None, "result": None,
         "from_ms": None, "up_to_ms": None}


def _private():
    return auth._get_private("_sync", {"cursor_ms": None, "last_run": None, "last_result": None})


def status():
    cfg = config()
    p = _private()
    return {"configured": bool(cfg["base_url"] and cfg["token"]), "base_url": cfg["base_url"], "state": dict(STATE),
            "cursor_ms": p["cursor_ms"], "last_run": p["last_run"], "last_result": p["last_result"], "schedule": schedule()}


def start_window(days):
    """First sync: how far back. Later syncs continue from where the last one ended."""
    p = _private()
    now = db.now_ms()
    if p["cursor_ms"]:
        return max(0, p["cursor_ms"] - OVERLAP_MS), "continue"
    if days:
        return now - int(days) * 86400000, f"first sync, last {int(days)} days"
    return None, "first sync, everything"


def preview(days=None):
    cfg = config()
    _check(cfg)
    v = version(cfg)
    from_ms, mode = start_window(days)
    total = count(cfg, from_ms, None)
    sample = [to_row(r) for r in search(cfg, from_ms, None, 3)]
    return {"version": v.get("version"), "mode": mode, "from_ms": from_ms, "total": total, "sample": sample}


USED_FIELDS = {"id", "report.event_type", "type", "sev_metadata.timestamp", "cg_ingest_timestamp", "vin", "ecu_name", "ecu_id",
               "sev_metadata.event_id", "sev_metadata.name", "sev_metadata.description"}


def _flatten(x, prefix="", out=None):
    out = {} if out is None else out
    if isinstance(x, dict) and x:
        for k, v in x.items():
            _flatten(v, f"{prefix}.{k}" if prefix else str(k), out)
    elif isinstance(x, list) and x and all(isinstance(i, (dict, list)) for i in x):
        for n, v in enumerate(x[:3]):
            _flatten(v, f"{prefix}[{n}]", out)
    else:
        out[prefix] = x
    return out


def fields_probe(n=200):
    """Fetch a batch of complete records (no field filter) and list every field the backend returns."""
    cfg = config()
    _check(cfg)
    from_ms, _mode = start_window(None)
    res = _request(cfg, "POST", "/v1/search", _params(from_ms, None, n, 0, fields=False))
    recs = res.get("results") if isinstance(res, dict) else None
    if not isinstance(recs, list):
        raise BackendError("Unexpected answer from /v1/search (no 'results' list)")
    seen = {}
    for r in recs:
        for k, v in _flatten(r).items():
            e = seen.setdefault(k, {"field": k, "present": 0, "types": set(), "examples": [], "distinct": set()})
            e["present"] += 1
            e["types"].add(type(v).__name__ if v is not None else "null")
            t = v if isinstance(v, str) else json.dumps(v, default=str)
            if len(e["distinct"]) < 50:
                e["distinct"].add(t)
            if t not in e["examples"] and len(e["examples"]) < 2:
                e["examples"].append(t[:160] + ("…" if len(t) > 160 else ""))
    out = [{"field": e["field"], "present": e["present"], "types": sorted(e["types"]), "examples": e["examples"],
            "distinct": len(e["distinct"]) if len(e["distinct"]) < 50 else "50+",
            "used": e["field"] in USED_FIELDS or e["field"].split("[")[0] in USED_FIELDS}
           for e in seen.values()]
    out.sort(key=lambda e: (e["used"], -e["present"], e["field"]))
    return {"records": len(recs), "fields": out}


def _begin():
    with _lock:
        if STATE["running"]:
            raise BackendError("A sync is already running", 409)
        STATE.update(running=True, cancel=False, phase="starting", started_at=db.now_ms(), finished_at=None, total=None, fetched=0,
                     new=0, duplicate=0, matched=0, pages=0, error=None, result=None, mode="", from_ms=None, up_to_ms=None)


def _save_cursor(newest, final=None):
    """Everything older than `newest` is stored (pages come oldest first), so an interrupted sync resumes from here."""
    p = _private()
    p["cursor_ms"] = max(newest, p["cursor_ms"] or 0) or None
    if final:
        p.update(last_run=db.now_ms(), last_result=final)
    auth._put_private("_sync", p)


def run(days=None, actor="system", progress=None):
    """Blocking sync (the command line calls this directly). Returns the result dict."""
    _check(config())
    _begin()
    return _execute(days, actor, progress)


def _execute(days, actor, progress=None, quiet=False):
    cfg = config()
    imp = None
    try:
        from_ms, mode = start_window(days)
        up_to = db.now_ms()
        STATE.update(mode=mode, from_ms=from_ms, up_to_ms=up_to, phase="counting")
        if not quiet:
            auth.log(actor, "sync.start", f"{mode}; backend {cfg['base_url']}", via="sync")
        STATE["total"] = count(cfg, from_ms, up_to)
        imp = ingest.Importer("CycurGUARD sync", "cycurguard", by_id=True)
        cursor, newest = from_ms, from_ms or 0
        STATE["phase"] = "downloading"
        while True:
            if STATE["cancel"]:
                raise BackendError("Cancelled")
            recs = search(cfg, cursor, up_to, PAGE)
            STATE["pages"] += 1
            if not recs:
                break
            imp.add(to_row(r) for r in recs)
            stamps = [t for t in (iso_ms(r.get("cg_ingest_timestamp")) for r in recs) if t is not None]
            if not stamps:
                raise BackendError("The backend returned events without cg_ingest_timestamp, so the sync cannot page through them")
            top = max(stamps)
            progressed = cursor is None or top > cursor
            if progressed:
                newest = max(newest, top)
            # events of the newest timestamp may continue on the next page, so resume from just before it
            st = imp.checkpoint(after_commit=(lambda: _save_cursor(newest - 1)) if progressed else None)
            STATE.update(fetched=imp.total, new=st["rows_new"], duplicate=st["rows_duplicate"], matched=st["rows_matched_to_earlier_import"])
            if progress:
                progress(dict(STATE))
            if not progressed:
                if len(recs) >= PAGE:
                    raise BackendError(f"More than {PAGE} events share the ingest time {top}. The sync cannot page past that.")
                break
            cursor = top
        res = imp.finish()
        imp = None
        STATE["phase"] = "detecting"
        res["detections"] = rules.run_all()
        res["newest_ms"] = newest
        _save_cursor(newest, {k: res[k] for k in ("rows_total", "rows_new", "rows_duplicate", "rows_matched_to_earlier_import")})
        if not quiet or res["rows_new"]:  # a scheduled run that found nothing new stays out of the audit log
            auth.log(actor, "sync.finish", f"{res['rows_new']} new, {res['rows_duplicate']} already present, "
                     f"{res['rows_matched_to_earlier_import']} matched to earlier file imports", via="sync")
        STATE["result"] = res
        return res
    except Exception as e:
        if imp:
            try:
                imp.finish()  # keep what was already downloaded; the next sync continues from the saved position
            except Exception:  # noqa
                imp.abort()
        STATE["error"] = str(e)
        auth.log(actor, "sync.cancel" if str(e) == "Cancelled" else "sync.error", str(e)[:300], via="sync")
        raise
    finally:
        STATE.update(running=False, phase="", finished_at=db.now_ms())


def start_background(days, actor):
    _check(config())
    _begin()  # claims the slot now, so a second click is refused instead of racing

    def job():
        try:
            _execute(days, actor)
        except Exception:  # noqa  (already recorded in STATE and the audit log)
            pass
    threading.Thread(target=job, daemon=True, name="cycurguard-sync").start()
    return True


def cancel():
    STATE["cancel"] = True


def test_connection(base_url=None, token=None):
    """Check address and token without saving anything. Blank fields fall back to what is saved."""
    import time
    cfg = config()
    if base_url is not None and str(base_url).strip():
        cfg["base_url"] = auth.check_backend_url(base_url)
    if token is not None and str(token).strip():
        cfg["token"] = str(token).strip()
    if not cfg["base_url"]:
        raise BackendError("Enter the backend address first.", 400)
    if not cfg["token"]:
        raise BackendError("Enter an API token first.", 400)
    t0 = time.time()
    v = _request(cfg, "GET", "/v1/version", timeout=20)  # open endpoint: proves the address is right
    out = {"base_url": cfg["base_url"], "version": v.get("version") if isinstance(v, dict) else None}
    try:
        out["total"] = _request(cfg, "POST", "/v1/stats/count", {}, timeout=30)  # needs a valid token
    except BackendError as e:
        raise BackendError(f"The backend answered (version {out['version']}), but: {e}", e.code)
    out["ms"] = int((time.time() - t0) * 1000)
    return out


# ------------------------------------------------------------------ schedule
TICK = 20  # seconds between checks of the schedule
SCHEDULE_DEFAULT = {"enabled": False, "minutes": 60, "last_attempt": None}
MINUTES = (5, 15, 30, 60, 180, 360, 720, 1440)


def schedule():
    s = auth._get_private("_sync_schedule", SCHEDULE_DEFAULT)
    nxt = (s["last_attempt"] or db.now_ms()) + s["minutes"] * 60000 if s["enabled"] else None
    return {"enabled": bool(s["enabled"]), "minutes": s["minutes"], "last_attempt": s["last_attempt"], "next_run": nxt,
            "choices": list(MINUTES), "needs_first_sync": not _private()["cursor_ms"]}


def put_schedule(new, actor):
    cur = auth._get_private("_sync_schedule", SCHEDULE_DEFAULT)
    if "minutes" in new:
        try:
            m = int(new["minutes"])
        except (TypeError, ValueError):
            raise BackendError("minutes must be a whole number", 400)
        if m not in MINUTES:
            raise BackendError("Choose one of: " + ", ".join(str(x) for x in MINUTES) + " minutes", 400)
        cur["minutes"] = m
    if "enabled" in new:
        on = bool(new["enabled"])
        if on and not (config()["base_url"] and config()["token"]):
            raise BackendError("Set up the backend address and token first", 400)
        if on and not cur["enabled"]:
            cur["last_attempt"] = db.now_ms()  # the first automatic run is one interval from now
        cur["enabled"] = on
    auth._put_private("_sync_schedule", cur)
    auth.log(actor, "sync.schedule", f"automatic sync {'every ' + str(cur['minutes']) + ' minutes' if cur['enabled'] else 'off'}", via="session")
    return schedule()


def _scheduler():
    while True:
        time.sleep(TICK)
        try:
            s = auth._get_private("_sync_schedule", SCHEDULE_DEFAULT)
            if not s["enabled"] or STATE["running"]:
                continue
            if db.now_ms() < (s["last_attempt"] or 0) + s["minutes"] * 60000:
                continue
            cfg = config()
            s["last_attempt"] = db.now_ms()
            auth._put_private("_sync_schedule", s)
            if not (cfg["base_url"] and cfg["token"]) or not _private()["cursor_ms"]:
                continue  # needs a first sync done by a person: how far back to go is their decision
            try:
                _begin()
            except BackendError:
                continue
            try:
                _execute(None, "schedule", quiet=True)
            except Exception:  # noqa  (recorded in STATE and the audit log)
                pass
        except Exception:  # noqa  keep the scheduler alive
            pass


def start_scheduler():
    threading.Thread(target=_scheduler, daemon=True, name="sync-schedule").start()
