"""Tiny threaded HTTP server: static UI + JSON API. Standard library only.

Security notes (the data is vehicle telemetry, so the defaults are strict):
  * binds to 127.0.0.1 only
  * rejects requests whose Host header is not a loopback name (DNS-rebinding protection)
  * every state-changing request must carry the header  X-SIEM: 1  (a custom header forces a CORS
    preflight, which this server never answers, so other websites cannot trigger writes)
"""
import csv
import io
import json
import mimetypes
import os
import re
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import cases, catalog, db, ingest, query, rules

STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
MAX_BODY = 1024 * 1024 * 1024
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}

ROUTES = []


def route(method, pattern):
    rx = re.compile("^" + pattern + "$")

    def deco(fn):
        ROUTES.append((method, rx, fn))
        return fn
    return deco


class HttpError(Exception):
    def __init__(self, code, msg):
        self.code, self.msg = code, msg


# ------------------------------------------------------------------ API
@route("GET", "/api/summary")
def api_summary(h, p):
    return query.summary(p)


@route("GET", "/api/events")
def api_events(h, p):
    return query.search_events(p)


@route("GET", r"/api/events/(\d+)")
def api_event(h, p, eid):
    ev = query.get_event(int(eid))
    if not ev:
        raise HttpError(404, "event not found")
    return ev


@route("PUT", r"/api/events/(\d+)/note")
def api_event_note(h, p, eid):
    body = h.json_body()
    note = str(body.get("note", ""))[:5000]
    c = db.conn()
    if note.strip():
        c.execute("INSERT OR REPLACE INTO event_notes(event_id, note, updated_at) VALUES(?,?,?)", (int(eid), note, db.now_ms()))
    else:
        c.execute("DELETE FROM event_notes WHERE event_id=?", (int(eid),))
    c.commit()
    return {"ok": True}


@route("GET", "/api/facets")
def api_facets(h, p):
    return query.facets(p)


@route("GET", "/api/timeline")
def api_timeline(h, p):
    return query.timeline(p)


@route("GET", "/api/top")
def api_top(h, p):
    return query.top(p)


@route("GET", "/api/vehicles")
def api_vehicles(h, p):
    return query.vehicles(p)


@route("GET", r"/api/vehicles/([A-Za-z0-9]+)")
def api_vehicle(h, p, vin):
    v = query.vehicle(vin)
    if not v:
        raise HttpError(404, "vehicle not found")
    return v


@route("GET", "/api/alerts")
def api_alerts(h, p):
    return rules.list_alerts(p)


@route("GET", r"/api/alerts/(\d+)")
def api_alert(h, p, aid):
    a = rules.get_alert(int(aid))
    if not a:
        raise HttpError(404, "alert not found")
    return a


@route("PATCH", r"/api/alerts/(\d+)")
def api_alert_update(h, p, aid):
    try:
        a = rules.update_alert(int(aid), h.json_body())
    except ValueError as e:
        raise HttpError(400, str(e))
    if not a:
        raise HttpError(404, "alert not found")
    return a


@route("POST", "/api/alerts/bulk")
def api_alert_bulk(h, p):
    b = h.json_body()
    try:
        return {"updated": rules.bulk_update(b.get("ids", []), b.get("status"))}
    except ValueError as e:
        raise HttpError(400, str(e))


@route("POST", "/api/detections/run")
def api_run(h, p):
    return rules.run_all()


# ------------------------------------------------------------------ cases
def _case_call(fn, *args):
    try:
        return fn(*args)
    except cases.NotFound as e:
        raise HttpError(404, str(e))
    except ValueError as e:
        raise HttpError(400, str(e))


@route("GET", "/api/cases")
def api_cases(h, p):
    return cases.list_cases(p)


@route("POST", "/api/cases")
def api_case_create(h, p):
    return _case_call(cases.create_case, h.json_body())


@route("GET", "/api/cases/dashboard")
def api_cases_dashboard(h, p):
    return cases.dashboard()


@route("GET", "/api/cases/picker")
def api_cases_picker(h, p):
    return cases.open_cases_for_picker()


@route("GET", r"/api/cases/(\d+)")
def api_case(h, p, cid):
    return _case_call(cases.get_case, int(cid))


@route("PATCH", r"/api/cases/(\d+)")
def api_case_update(h, p, cid):
    return _case_call(cases.update_case, int(cid), h.json_body())


@route("DELETE", r"/api/cases/(\d+)")
def api_case_delete(h, p, cid):
    return _case_call(cases.delete_case, int(cid))


@route("POST", r"/api/cases/(\d+)/close")
def api_case_close(h, p, cid):
    return _case_call(cases.close_case, int(cid), h.json_body())


@route("POST", r"/api/cases/(\d+)/reopen")
def api_case_reopen(h, p, cid):
    return _case_call(cases.reopen_case, int(cid))


@route("POST", r"/api/cases/(\d+)/comments")
def api_case_comment(h, p, cid):
    return _case_call(cases.add_comment, int(cid), h.json_body())


@route("POST", r"/api/cases/(\d+)/tasks")
def api_case_task_add(h, p, cid):
    return _case_call(cases.add_task, int(cid), h.json_body())


@route("PATCH", r"/api/cases/(\d+)/tasks/(\d+)")
def api_case_task_update(h, p, cid, tid):
    return _case_call(cases.update_task, int(cid), int(tid), h.json_body())


@route("DELETE", r"/api/cases/(\d+)/tasks/(\d+)")
def api_case_task_delete(h, p, cid, tid):
    return _case_call(cases.delete_task, int(cid), int(tid))


@route("POST", r"/api/cases/(\d+)/alerts")
def api_case_link(h, p, cid):
    return _case_call(cases.link_alerts, int(cid), h.json_body())


@route("DELETE", r"/api/cases/(\d+)/alerts/(\d+)")
def api_case_unlink(h, p, cid, aid):
    return _case_call(cases.unlink_alert, int(cid), int(aid))


@route("GET", "/api/rules")
def api_rules(h, p):
    cfg = db.get_settings()["rules"]
    return [{"id": k, "title": v[0], "description": v[1], "params": cfg.get(k, {})} for k, v in rules.RULE_INFO.items()]


@route("GET", "/api/settings")
def api_settings(h, p):
    return db.get_settings()


@route("PUT", "/api/settings")
def api_settings_put(h, p):
    return db.put_settings(h.json_body())


@route("GET", "/api/catalog")
def api_catalog(h, p):
    return query.rows(
        "SELECT c.*, (SELECT COUNT(*) FROM events e WHERE e.cat_id=c.cat_id) AS events FROM catalog c ORDER BY c.sev_num DESC, c.event_type, c.event_id")


@route("PUT", "/api/catalog")
def api_catalog_put(h, p):
    items = h.json_body()
    if not isinstance(items, list):
        raise HttpError(400, "expected a list")
    c = db.conn()
    for it in items:
        sev = it.get("severity")
        if sev not in catalog.SEV_NUM:
            raise HttpError(400, f"invalid severity {sev!r}")
        c.execute("UPDATE catalog SET severity=?, sev_num=?, category=?, notes=?, auto=0 WHERE cat_id=?",
                  (sev, catalog.SEV_NUM[sev], str(it.get("category", ""))[:60], str(it.get("notes", ""))[:500], it["cat_id"]))
    c.commit()
    # Severity drives alerts: refresh detections so the queue reflects the new classification
    return {"updated": len(items), "detections": rules.run_all()}


@route("GET", "/api/imports")
def api_imports(h, p):
    return query.rows("SELECT i.*, (SELECT COUNT(*) FROM events e WHERE e.import_id=i.id) AS events_now FROM imports i ORDER BY id DESC")


@route("DELETE", r"/api/imports/(\d+)")
def api_import_delete(h, p, iid):
    c = db.conn()
    n = c.execute("DELETE FROM events WHERE import_id=?", (int(iid),)).rowcount
    c.execute("DELETE FROM imports WHERE id=?", (int(iid),))
    c.commit()
    return {"deleted_events": n}


@route("GET", "/api/quality")
def api_quality(h, p):
    c = db.conn()
    lo, hi = db.ts_bounds()
    one = lambda sql, a=(): c.execute(sql, a).fetchone()[0]
    total = one("SELECT COUNT(*) FROM events")
    q = {
        "total": total,
        "no_timestamp": one("SELECT COUNT(*) FROM events WHERE ts IS NULL"),
        "implausible_timestamp": one("SELECT COUNT(*) FROM events WHERE ts IS NOT NULL AND ts_ok=0"),
        "plausible_window": {"from": lo, "to": hi},
        "no_ecu": one("SELECT COUNT(*) FROM events WHERE ecu_name=''"),
        "vins_not_17_chars": one("SELECT COUNT(DISTINCT vin) FROM events WHERE LENGTH(vin)<>17"),
        "by_type_no_ts": query.rows("SELECT event_type, COUNT(*) n, SUM(ts_ok=0) bad FROM events GROUP BY event_type"),
        "worst_vehicles": query.rows(
            "SELECT vin, COUNT(*) n, SUM(ts_ok=0) bad FROM events GROUP BY vin HAVING bad>0 ORDER BY bad DESC LIMIT 10"),
    }
    return q


@route("POST", "/api/import")
def api_import(h, p):
    name = (p.get("filename") or ["upload"])[0]
    data = h.raw_body()
    try:
        stats = ingest.import_rows(ingest.rows_for_file(name, data), filename=name, source="file")
    except ingest.ImportError_ as e:
        raise HttpError(400, str(e))
    stats["detections"] = rules.run_all()
    return stats


@route("POST", "/api/ingest")
def api_ingest(h, p):
    """Programmatic ingest (future REST pull): POST a JSON list of events with the backend's column names."""
    try:
        rows = list(ingest.rows_from_json(h.raw_body()))
        stats = ingest.import_rows(rows, filename=(p.get("source") or ["api"])[0], source="api")
    except (ingest.ImportError_, ValueError) as e:
        raise HttpError(400, str(e))
    stats["detections"] = rules.run_all()
    return stats


@route("POST", "/api/reset")
def api_reset(h, p):
    if h.json_body().get("confirm") != "DELETE ALL EVENTS":
        raise HttpError(400, "confirmation text missing")
    c = db.conn()
    for t in ("events", "alerts", "alert_comments", "event_notes", "imports", "cases", "case_alerts", "case_tasks", "case_log"):
        c.execute(f"DELETE FROM {t}")
    c.commit()
    return {"ok": True}


EXPORT_COLS = ["report.event_type", "sev_metadata.timestamp", "timestamp_utc", "vin", "ecu_name", "ecu_id", "sev_metadata.event_id",
               "sev_metadata.name", "severity", "category", "sev_metadata.description"]


@route("GET", "/api/export.csv")
def api_export(h, p):
    import datetime
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(EXPORT_COLS)
    for r in query.iter_events_for_export(p):
        ts_utc = datetime.datetime.fromtimestamp(r["ts"] / 1000, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if r["ts_ok"] else ""
        w.writerow([r["event_type"], r["ts"] if r["ts"] is not None else "", ts_utc, r["vin"], r["ecu_name"], r["ecu_id"],
                    r["event_id"] if r["event_id"] is not None else "", r["name"], r["severity"], r["category"], r["description"]])
    return ("raw", "text/csv; charset=utf-8", buf.getvalue().encode("utf-8-sig"),
            {"Content-Disposition": 'attachment; filename="ids-events-export.csv"'})


# ------------------------------------------------------------------ HTTP plumbing
class Handler(BaseHTTPRequestHandler):
    server_version = "IDS-SIEM"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        if os.environ.get("IDS_SIEM_VERBOSE"):
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    # -- helpers
    def raw_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise HttpError(413, "upload too large")
        data = self.rfile.read(n) if n else b""
        if len(data) != n:  # connection dropped mid-upload: never import a truncated file
            raise HttpError(400, f"incomplete upload: received {len(data)} of {n} bytes")
        return data

    def json_body(self):
        raw = self.raw_body()
        try:
            return json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            raise HttpError(400, "invalid JSON body")

    def send(self, code, ctype, body, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, code, obj):
        self.send(code, "application/json; charset=utf-8", json.dumps(obj, default=str).encode())

    # -- dispatch
    def handle_any(self, method):
        try:
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0] if not (self.headers.get("Host") or "").startswith("[") else "[::1]"
            if host not in ALLOWED_HOSTS:
                raise HttpError(403, "forbidden host")
            if method != "GET" and self.headers.get("X-SIEM") != "1":
                raise HttpError(403, "missing X-SIEM header")
            u = urlparse(self.path)
            params = parse_qs(u.query)
            if u.path.startswith("/api/"):
                for m, rx, fn in ROUTES:
                    if m == method:
                        mt = rx.match(u.path)
                        if mt:
                            res = fn(self, params, *mt.groups())
                            if isinstance(res, tuple) and res and res[0] == "raw":
                                return self.send(200, res[1], res[2], res[3] if len(res) > 3 else None)
                            return self.send_json(200, res)
                raise HttpError(404, "no such endpoint")
            if method != "GET":
                raise HttpError(405, "method not allowed")
            return self.static(u.path)
        except HttpError as e:
            self.send_json(e.code, {"error": e.msg})
        except Exception as e:  # noqa
            traceback.print_exc()
            self.send_json(500, {"error": f"{type(e).__name__}: {e}"})

    def static(self, path):
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        full = os.path.realpath(os.path.join(STATIC, rel))
        if not full.startswith(os.path.realpath(STATIC) + os.sep) or not os.path.isfile(full):
            raise HttpError(404, "not found")
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"
        with open(full, "rb") as f:
            self.send(200, ctype, f.read())

    def do_GET(self): self.handle_any("GET")
    def do_POST(self): self.handle_any("POST")
    def do_PUT(self): self.handle_any("PUT")
    def do_PATCH(self): self.handle_any("PATCH")
    def do_DELETE(self): self.handle_any("DELETE")


def serve(host="127.0.0.1", port=8765):
    db.init()
    db.recompute_ts_ok()
    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    print(f"IDS SIEM running at http://{host}:{port}  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
