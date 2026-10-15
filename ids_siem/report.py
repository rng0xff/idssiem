"""Printable case report: one self-contained HTML page (no scripts needed, print or save as PDF from the browser)."""
import datetime
from html import escape as e

from . import auth, cases, db, vin as vinmod


def _t(ms, day=False):
    if not ms:
        return "no valid time"
    return datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc).strftime("%Y-%m-%d" if day else "%Y-%m-%d %H:%M UTC")


def _text(s):
    return e(s or "").replace("\n", "<br>")


CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { font: 14px/1.5 Arial, Helvetica, sans-serif; color: #111; margin: 0; background: #eee; }
main { max-width: 900px; margin: 0 auto; padding: 28px 36px 40px; background: #fff; }
.bar { max-width: 900px; margin: 0 auto; padding: 10px 36px; display: flex; gap: 10px; align-items: center; font-size: 13px; }
.bar button { font: inherit; padding: 6px 14px; border: 1px solid #c8412d; background: #c8412d; color: #fff; border-radius: 4px; cursor: pointer; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 15px; margin: 24px 0 8px; padding-bottom: 3px; border-bottom: 2px solid #c8412d; }
.sub { color: #555; margin: 0 0 14px; }
table { border-collapse: collapse; width: 100%; margin: 6px 0; font-size: 13px; }
th, td { border: 1px solid #bbb; padding: 4px 7px; text-align: left; vertical-align: top; }
th { background: #e8e8e8; font-weight: 600; }
td.num, th.num { text-align: right; }
.kv th { width: 170px; }
.mono { font-family: Consolas, Menlo, monospace; font-size: 12px; }
.pill { display: inline-block; padding: 0 7px; border: 1px solid #888; border-radius: 9px; font-size: 12px; }
.muted { color: #666; }
.box { border: 1px solid #bbb; padding: 8px 10px; min-height: 40px; }
.foot { margin-top: 28px; font-size: 12px; color: #555; border-top: 1px solid #bbb; padding-top: 8px; }
tr { page-break-inside: avoid; }
h2 { page-break-after: avoid; }
@media print { body { background: #fff; } main { padding: 0; max-width: none; } .bar { display: none; } @page { margin: 16mm; } }
"""


def render(cid):
    c = db.conn()
    d = cases.get_case(cid)
    who = auth.current_name()
    now = db.now_ms()

    # vehicles: decoded VIN, alerts, events, time span
    veh = []
    for v in d["vehicles"]:
        agg = c.execute("SELECT COUNT(*) n, COALESCE(SUM(a.event_count),0) ev, MIN(a.first_ts) f, MAX(a.last_ts) l "
                        "FROM case_alerts ca JOIN alerts a ON a.id=ca.alert_id WHERE ca.case_id=? AND a.vin=?", (cid, v["vin"])).fetchone()
        veh.append((v["vin"], vinmod.decode(v["vin"]), agg))

    def row(*cells, cls=""):
        return "<tr>" + "".join(f"<td{(' class=%s' % cls) if cls and i else ''}>{x}</td>" for i, x in enumerate(cells)) + "</tr>"

    kv = [("Status", e(d["status_label"]) + (" (overdue)" if d["overdue"] else "")),
          ("Severity", e(d["severity"])),
          ("Owner", e(d["owner"]) or '<span class="muted">none</span>'),
          ("Due date", e(d["due_date"]) or '<span class="muted">none</span>'),
          ("Opened", f"{_t(d['created_at'])} by {e(d['created_by'])}"),
          ("Closed", _t(d["closed_at"]) if d["closed_at"] else '<span class="muted">still open</span>'),
          ("Resolution", e(d["resolution_label"]) if d["resolution_label"] else '<span class="muted">none yet</span>'),
          ("Age", f"{d['age_days']} days"),
          ("Checklist", f"{d['tasks_done']} of {d['tasks_total']} done"),
          ("Alerts", f"{len(d['alerts'])} linked, {d['open_alerts']} still open"),
          ("Vehicles", str(len(veh)) or "0")]

    parts = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
             f"<title>Case #{d['id']} report</title><style>{CSS}</style></head><body>",
             "<div class='bar'><button id='print' type='button'>Print or save as PDF</button><span class='muted'>Use the print dialog and choose Save as PDF.</span></div>",
             "<main>",
             f"<h1>Case #{d['id']}: {e(d['title'])}</h1>",
             f"<p class='sub'>Fleet IDS case report. Created {_t(now)} by {e(who)}. All times are UTC.</p>",
             "<table class='kv'>" + "".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in kv) + "</table>",
             "<h2>Summary</h2><div class='box'>" + (_text(d["summary"]) or "<span class='muted'>No summary written.</span>") + "</div>",
             "<h2>Findings and decision</h2><div class='box'>" + (_text(d["findings"]) or "<span class='muted'>No findings recorded.</span>") + "</div>"]

    parts.append("<h2>Vehicles involved</h2>")
    if veh:
        parts.append("<table><tr><th>VIN</th><th>Vehicle</th><th>Market</th><th class='num'>Alerts</th><th class='num'>Events</th><th>First event</th><th>Last event</th></tr>")
        for v, info, agg in veh:
            parts.append(row(f"<span class='mono'>{e(v)}</span>", e(info["label"]) + ("" if info.get("check_ok", True) else " <b>(check digit wrong)</b>"),
                             e(info.get("market", "")), str(agg["n"]), f"{agg['ev']:,}", _t(agg["f"], True) if agg["f"] else "no valid time",
                             _t(agg["l"], True) if agg["l"] else "no valid time"))
        parts.append("</table>")
    else:
        parts.append("<p class='muted'>None. The alerts are fleet-wide.</p>")

    parts.append("<h2>Linked alerts</h2>")
    if d["alerts"]:
        parts.append("<table><tr><th>#</th><th>Severity</th><th>Alert</th><th>Vehicle</th><th class='num'>Events</th><th>Last event</th><th>Status</th></tr>")
        for a in d["alerts"]:
            parts.append(row(str(a["id"]), e(a["severity"]), e(a["title"]), f"<span class='mono'>{e(a['vin'] or 'fleet')}</span>",
                             f"{a['event_count']:,}", _t(a["last_ts"], True) if a["last_ts"] else "no valid time", e(a["status"].replace("_", " "))))
        parts.append("</table>")
    else:
        parts.append("<p class='muted'>No alerts linked.</p>")

    parts.append("<h2>Checklist</h2>")
    if d["tasks"]:
        parts.append("<table><tr><th style='width:28px'></th><th>Step</th><th>Result</th><th style='width:150px'>Done</th></tr>" + "".join(
            f"<tr><td>{'&#9745;' if t['done'] else '&#9744;'}</td><td>{e(t['title'])}</td>"
            f"<td>{_text(t['result']) if t.get('result') else '<span class=muted>no result recorded</span>'}</td>"
            f"<td>{(e(t['done_by']) + ', ' + _t(t['done_at'])) if t['done'] else ''}</td></tr>" for t in d["tasks"]) + "</table>")
    else:
        parts.append("<p class='muted'>No tasks.</p>")

    parts.append("<h2>Activity</h2>")
    log = list(reversed(d["log"]))
    parts.append("<table><tr><th style='width:130px'>When</th><th style='width:110px'>Who</th><th>What</th></tr>" +
                 "".join(row(_t(x["created_at"]), e(x["author"]), _text(x["body"])) for x in log) + "</table>" if log else "<p class='muted'>No activity.</p>")

    parts.append(f"<div class='foot'>Case #{d['id']}, report generated {_t(now)} by {e(who)}. Vehicle details decoded with INEOS Grenadier VIN decoder Corp-P2-ENG-0128 rev 001. "
                 f"The case record itself is in the local Fleet IDS database; changes to it are in the audit log.</div></main><script src='/print.js'></script></body></html>")
    auth.log(auth.current_actor(), "case.report", "report generated", target=f"case:{cid}")
    return "".join(parts)
