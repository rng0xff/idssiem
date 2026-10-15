"""Case management: group alerts into a case, work it through a checklist, close it with a resolution.

A case has an owner, a due date, a task checklist and an activity log. An alert belongs to at most one
case. Closing a case can resolve its open alerts in one step.
"""
import datetime
import re
import statistics

from . import auth, db
from .catalog import SEVERITIES, SEV_NUM

OPEN_STATUSES = ["open", "investigating", "waiting"]
STATUSES = OPEN_STATUSES + ["closed"]
STATUS_LABEL = {"open": "Open", "investigating": "Investigating", "waiting": "Waiting", "closed": "Closed"}
RESOLUTIONS = {
    "confirmed": "Confirmed incident",
    "false_positive": "False positive",
    "benign": "Benign or expected behaviour",
    "duplicate": "Duplicate of another case",
}
DAY = 86400000


class NotFound(Exception):
    pass


def _who():
    return auth.current_name()


def _log(c, case_id, kind, body, now, author=None, action=None):
    c.execute("INSERT INTO case_log(case_id, author, kind, body, created_at) VALUES(?,?,?,?,?)",
              (case_id, author or ("system" if kind == "system" else _who()), kind, body, now))
    # the same event goes to the audit log, inside the same transaction
    auth.log(auth.current_actor(), action or ("case.comment" if kind == "comment" else "case.update"), body[:300] if kind != "comment" else f"note added ({len(body)} characters)", target=f"case:{case_id}")


def _today():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def _valid_date(v):
    v = (v or "").strip()
    if not v:
        return ""
    try:
        return datetime.date.fromisoformat(v).isoformat()
    except ValueError:
        raise ValueError(f"invalid date {v!r}, expected YYYY-MM-DD")


def _case_or_404(c, cid):
    r = c.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
    if not r:
        raise NotFound("case not found")
    return r


def _decorate(d, today):
    d["overdue"] = bool(d["due_date"]) and d["status"] != "closed" and d["due_date"] < today
    end = d["closed_at"] if d["closed_at"] else db.now_ms()
    d["age_days"] = round((end - d["created_at"]) / DAY, 1)
    d["status_label"] = STATUS_LABEL.get(d["status"], d["status"])
    d["resolution_label"] = RESOLUTIONS.get(d["resolution"], "")
    return d


# ------------------------------------------------------------------ linking
def _link_alerts(c, case_id, alert_ids, now):
    who = _who()
    for aid in alert_ids:
        a = c.execute("SELECT id, title, status FROM alerts WHERE id=?", (aid,)).fetchone()
        c.execute("INSERT INTO case_alerts(case_id, alert_id, linked_at) VALUES(?,?,?)", (case_id, aid, now))
        c.execute("INSERT INTO alert_comments(alert_id, author, body, created_at) VALUES(?,?,?,?)",
                  (aid, "system", f"{who} linked this alert to case #{case_id}", now))
        if a["status"] in ("new", "suppressed"):
            c.execute("UPDATE alerts SET status='in_progress', updated_at=? WHERE id=?", (now, aid))
            c.execute("INSERT INTO alert_comments(alert_id, author, body, created_at) VALUES(?,?,?,?)",
                      (aid, "system", f"{who} changed status: {a['status']} → in_progress (case #{case_id})", now))
        _log(c, case_id, "system", f"Alert #{aid} linked: {a['title']}", now, author=who, action="case.link")


def _check_linkable(c, alert_ids):
    ids = sorted({int(x) for x in alert_ids})
    if not ids:
        return ids
    q = ",".join("?" * len(ids))
    found = {r["id"] for r in c.execute(f"SELECT id FROM alerts WHERE id IN ({q})", ids)}
    missing = [i for i in ids if i not in found]
    if missing:
        raise NotFound(f"alert not found: {missing}")
    taken = c.execute(f"SELECT alert_id, case_id FROM case_alerts WHERE alert_id IN ({q})", ids).fetchall()
    if taken:
        raise ValueError("already in a case: " + ", ".join(f"alert #{r['alert_id']} (case #{r['case_id']})" for r in taken))
    return ids


def default_title(alerts):
    if not alerts:
        return ""
    first = alerts[0]
    t = first["title"] + (f" ({first['vin']})" if first["vin"] else "")
    return t if len(alerts) == 1 else f"{len(alerts)} alerts: {t} and others"


# ------------------------------------------------------------------ create / update
def create_case(body):
    c = db.conn()
    now = db.now_ms()
    try:
        ids = _check_linkable(c, body.get("alert_ids") or [])
        alerts = [c.execute("SELECT * FROM alerts WHERE id=?", (i,)).fetchone() for i in ids]
        title = (body.get("title") or "").strip() or default_title(alerts)
        if not title:
            raise ValueError("a case needs a title")
        sev = body.get("severity")
        if sev not in SEV_NUM:
            sev = max((a["severity"] for a in alerts), key=lambda s: SEV_NUM[s], default="medium")
        owner = str(body.get("owner") or "").strip()[:60]
        due = _valid_date(body.get("due_date"))
        who = _who()
        cur = c.execute(
            "INSERT INTO cases(title, summary, severity, sev_num, status, owner, due_date, created_by, created_at, updated_at) "
            "VALUES(?,?,?,?,'open',?,?,?,?,?)",
            (title[:300], str(body.get("summary") or "")[:20000], sev, SEV_NUM[sev], owner, due, who, now, now))
        cid = cur.lastrowid
        tasks = body.get("tasks")
        if not isinstance(tasks, list):
            tasks = db.get_settings().get("case_tasks", [])
        for i, t in enumerate(str(x).strip()[:200] for x in tasks if str(x).strip()):
            c.execute("INSERT INTO case_tasks(case_id, title, position) VALUES(?,?,?)", (cid, t, i))
        _log(c, cid, "system", f"Case created by {who}: {title}", now, author=who, action="case.create")
        _link_alerts(c, cid, ids, now)
        c.commit()
    except Exception:
        c.rollback()
        raise
    return get_case(cid)


def update_case(cid, body):
    c = db.conn()
    now = db.now_ms()
    try:
        cur = _case_or_404(c, cid)
        who = _who()
        sets, args, notes = [], [], []
        if "title" in body:
            t = str(body["title"]).strip()[:300]
            if not t:
                raise ValueError("a case needs a title")
            if t != cur["title"]:
                sets.append("title=?"); args.append(t); notes.append("changed the title")
        if "summary" in body:
            sets.append("summary=?"); args.append(str(body["summary"])[:20000])
        if "severity" in body and body["severity"] != cur["severity"]:
            if body["severity"] not in SEV_NUM:
                raise ValueError("invalid severity")
            sets += ["severity=?", "sev_num=?"]; args += [body["severity"], SEV_NUM[body["severity"]]]
            notes.append(f"changed severity: {cur['severity']} → {body['severity']}")
        if "owner" in body:
            o = str(body["owner"]).strip()[:60]
            if o != cur["owner"]:
                sets.append("owner=?"); args.append(o)
                notes.append(f"assigned the case to {o}" if o else "removed the owner")
        if "due_date" in body:
            d = _valid_date(body["due_date"])
            if d != cur["due_date"]:
                sets.append("due_date=?"); args.append(d)
                notes.append(f"set the due date to {d}" if d else "removed the due date")
        if "status" in body and body["status"] != cur["status"]:
            if body["status"] == "closed" or cur["status"] == "closed":
                raise ValueError("use Close case or Reopen case to change a closed state")
            if body["status"] not in OPEN_STATUSES:
                raise ValueError("invalid status")
            sets.append("status=?"); args.append(body["status"])
            notes.append(f"changed status: {STATUS_LABEL[cur['status']]} → {STATUS_LABEL[body['status']]}")
        if sets:
            c.execute(f"UPDATE cases SET {', '.join(sets)}, updated_at=? WHERE id=?", args + [now, cid])
        for n in notes:
            _log(c, cid, "system", f"{who} {n}", now, author=who)
        c.commit()
    except Exception:
        c.rollback()
        raise
    return get_case(cid)


def close_case(cid, body):
    c = db.conn()
    now = db.now_ms()
    try:
        cur = _case_or_404(c, cid)
        if cur["status"] == "closed":
            raise ValueError("the case is already closed")
        res = body.get("resolution")
        if res not in RESOLUTIONS:
            raise ValueError("choose a resolution")
        who = _who()
        c.execute("UPDATE cases SET status='closed', resolution=?, findings=?, closed_at=?, updated_at=? WHERE id=?",
                  (res, str(body.get("findings") or "")[:20000], now, now, cid))
        _log(c, cid, "system", f"{who} closed the case: {RESOLUTIONS[res]}", now, author=who, action="case.close")
        n = 0
        if body.get("resolve_alerts", True):
            new_status = "false_positive" if res == "false_positive" else "resolved"
            for a in c.execute("SELECT a.id, a.status FROM alerts a JOIN case_alerts ca ON ca.alert_id=a.id "
                               "WHERE ca.case_id=? AND a.status IN ('new','in_progress')", (cid,)).fetchall():
                c.execute("UPDATE alerts SET status=?, updated_at=? WHERE id=?", (new_status, now, a["id"]))
                c.execute("INSERT INTO alert_comments(alert_id, author, body, created_at) VALUES(?,?,?,?)",
                          (a["id"], "system", f"{who} closed case #{cid} ({RESOLUTIONS[res]}): {a['status']} → {new_status}", now))
                n += 1
            if n:
                _log(c, cid, "system", f"{n} open alert(s) set to {new_status.replace('_', ' ')}", now, action="case.close")
        c.commit()
    except Exception:
        c.rollback()
        raise
    return get_case(cid)


def reopen_case(cid):
    c = db.conn()
    now = db.now_ms()
    try:
        cur = _case_or_404(c, cid)
        if cur["status"] != "closed":
            raise ValueError("the case is not closed")
        c.execute("UPDATE cases SET status='investigating', resolution='', closed_at=NULL, updated_at=? WHERE id=?", (now, cid))
        _log(c, cid, "system", f"{_who()} reopened the case (it was closed as: {RESOLUTIONS.get(cur['resolution'], 'unknown')})", now, action="case.reopen")
        c.commit()
    except Exception:
        c.rollback()
        raise
    return get_case(cid)


def delete_case(cid):
    c = db.conn()
    row = _case_or_404(c, cid)
    auth.log(auth.current_actor(), "case.delete", f"deleted '{row['title']}' (status {row['status']})", target=f"case:{cid}")
    for t in ("case_tasks", "case_log", "case_alerts"):
        c.execute(f"DELETE FROM {t} WHERE case_id=?", (cid,))
    c.execute("DELETE FROM case_links WHERE case_a=? OR case_b=?", (cid, cid))
    c.execute("DELETE FROM cases WHERE id=?", (cid,))
    c.commit()
    return {"deleted": cid}


def add_comment(cid, body):
    text = str(body.get("comment") or "").strip()
    if not text:
        raise ValueError("write something first")
    c = db.conn()
    now = db.now_ms()
    _case_or_404(c, cid)
    _log(c, cid, "comment", text[:5000], now)
    c.execute("UPDATE cases SET updated_at=? WHERE id=?", (now, cid))
    c.commit()
    return get_case(cid)


# ------------------------------------------------------------------ tasks
def add_task(cid, body):
    t = str(body.get("title") or "").strip()[:200]
    if not t:
        raise ValueError("a task needs a title")
    c = db.conn()
    now = db.now_ms()
    _case_or_404(c, cid)
    pos = c.execute("SELECT COALESCE(MAX(position), -1) + 1 FROM case_tasks WHERE case_id=?", (cid,)).fetchone()[0]
    c.execute("INSERT INTO case_tasks(case_id, title, position) VALUES(?,?,?)", (cid, t, pos))
    _log(c, cid, "system", f"{_who()} added the task: {t}", now, action="case.task")
    c.execute("UPDATE cases SET updated_at=? WHERE id=?", (now, cid))
    c.commit()
    return get_case(cid)


TASK_RESULT_MAX = 2000


def update_task(cid, tid, body):
    c = db.conn()
    now = db.now_ms()
    _case_or_404(c, cid)
    t = c.execute("SELECT * FROM case_tasks WHERE id=? AND case_id=?", (tid, cid)).fetchone()
    if not t:
        raise NotFound("task not found")
    who = _who()
    if "done" in body and bool(body["done"]) != bool(t["done"]):
        if body["done"]:
            c.execute("UPDATE case_tasks SET done=1, done_at=?, done_by=? WHERE id=?", (now, who, tid))
            _log(c, cid, "system", f"{who} completed the task: {t['title']}", now, action="case.task")
        else:
            c.execute("UPDATE case_tasks SET done=0, done_at=NULL, done_by='' WHERE id=?", (tid,))
            _log(c, cid, "system", f"{who} reopened the task: {t['title']}", now, action="case.task")
    if "title" in body and str(body["title"]).strip():
        c.execute("UPDATE case_tasks SET title=? WHERE id=?", (str(body["title"]).strip()[:200], tid))
    if "result" in body:
        res = str(body["result"] or "").strip()[:TASK_RESULT_MAX]
        if res != (t["result"] or ""):
            c.execute("UPDATE case_tasks SET result=? WHERE id=?", (res, tid))
            _log(c, cid, "system", f"{who} {'documented the result of' if res else 'cleared the result of'} the task: {t['title']}"
                 + (f" ({len(res)} characters)" if res else ""), now, action="case.task")
    c.execute("UPDATE cases SET updated_at=? WHERE id=?", (now, cid))
    c.commit()
    return get_case(cid)


def reorder_tasks(cid, body):
    """New order of the checklist: body {"ids": [task ids, all of them, in the new order]}."""
    c = db.conn()
    now = db.now_ms()
    _case_or_404(c, cid)
    try:
        ids = [int(x) for x in (body.get("ids") or [])]
    except (TypeError, ValueError):
        raise ValueError("ids must be task numbers")
    have = [r["id"] for r in c.execute("SELECT id FROM case_tasks WHERE case_id=? ORDER BY position, id", (cid,))]
    if sorted(ids) != sorted(have):
        raise ValueError("the list must contain every task of the case exactly once")
    if ids == have:
        return get_case(cid)
    for pos, tid in enumerate(ids):
        c.execute("UPDATE case_tasks SET position=? WHERE id=? AND case_id=?", (pos, tid, cid))
    _log(c, cid, "system", f"{_who()} changed the order of the checklist", now, action="case.task")
    c.execute("UPDATE cases SET updated_at=? WHERE id=?", (now, cid))
    c.commit()
    return get_case(cid)


def delete_task(cid, tid):
    c = db.conn()
    now = db.now_ms()
    _case_or_404(c, cid)
    t = c.execute("SELECT title FROM case_tasks WHERE id=? AND case_id=?", (tid, cid)).fetchone()
    if not t:
        raise NotFound("task not found")
    c.execute("DELETE FROM case_tasks WHERE id=?", (tid,))
    _log(c, cid, "system", f"{_who()} removed the task: {t['title']}", now, action="case.task")
    c.commit()
    return get_case(cid)


# ------------------------------------------------------------------ alerts of a case
def link_alerts(cid, body):
    c = db.conn()
    now = db.now_ms()
    try:
        cur = _case_or_404(c, cid)
        if cur["status"] == "closed":
            raise ValueError("reopen the case before adding alerts")
        ids = _check_linkable(c, body.get("alert_ids") or [])
        if not ids:
            raise ValueError("no alerts given")
        _link_alerts(c, cid, ids, now)
        c.execute("UPDATE cases SET updated_at=? WHERE id=?", (now, cid))
        c.commit()
    except Exception:
        c.rollback()
        raise
    return get_case(cid)


def unlink_alert(cid, aid):
    c = db.conn()
    now = db.now_ms()
    _case_or_404(c, cid)
    if not c.execute("SELECT 1 FROM case_alerts WHERE case_id=? AND alert_id=?", (cid, aid)).fetchone():
        raise NotFound("alert is not linked to this case")
    c.execute("DELETE FROM case_alerts WHERE case_id=? AND alert_id=?", (cid, aid))
    c.execute("INSERT INTO alert_comments(alert_id, author, body, created_at) VALUES(?,?,?,?)",
              (aid, "system", f"{_who()} removed this alert from case #{cid}", now))
    _log(c, cid, "system", f"Alert #{aid} removed from the case", now, author=_who(), action="case.unlink")
    c.execute("UPDATE cases SET updated_at=? WHERE id=?", (now, cid))
    c.commit()
    return get_case(cid)


# ------------------------------------------------------------------ related cases
NOTE_MAX = 300


def link_case(cid, body):
    """Mark two cases as related (both directions, one shared note)."""
    c = db.conn()
    now = db.now_ms()
    try:
        other = int(body.get("case_id"))
    except (TypeError, ValueError):
        raise ValueError("choose a case to link")
    if other == cid:
        raise ValueError("a case cannot be linked to itself")
    note = str(body.get("note") or "").strip()[:NOTE_MAX]
    a = _case_or_404(c, cid)
    b = _case_or_404(c, other)
    lo, hi = sorted((cid, other))
    if c.execute("SELECT 1 FROM case_links WHERE case_a=? AND case_b=?", (lo, hi)).fetchone():
        raise ValueError(f"case #{other} is already linked")
    try:
        c.execute("INSERT INTO case_links(case_a, case_b, note, created_by, created_at) VALUES(?,?,?,?,?)", (lo, hi, note, _who(), now))
        extra = f": {note}" if note else ""
        _log(c, cid, "system", f"Linked to case #{other} ({b['title']}){extra}", now, author=_who(), action="case.link")
        _log(c, other, "system", f"Linked to case #{cid} ({a['title']}){extra}", now, author=_who(), action="case.link")
        c.execute("UPDATE cases SET updated_at=? WHERE id IN (?,?)", (now, cid, other))
        c.commit()
    except Exception:
        c.rollback()
        raise
    return get_case(cid)


def unlink_case(cid, other):
    c = db.conn()
    now = db.now_ms()
    _case_or_404(c, cid)
    lo, hi = sorted((cid, other))
    if not c.execute("SELECT 1 FROM case_links WHERE case_a=? AND case_b=?", (lo, hi)).fetchone():
        raise NotFound("these cases are not linked")
    c.execute("DELETE FROM case_links WHERE case_a=? AND case_b=?", (lo, hi))
    _log(c, cid, "system", f"Link to case #{other} removed", now, author=_who(), action="case.unlink_case")
    if c.execute("SELECT 1 FROM cases WHERE id=?", (other,)).fetchone():
        _log(c, other, "system", f"Link to case #{cid} removed", now, author=_who(), action="case.unlink_case")
    c.commit()
    return get_case(cid)


def related_cases(c, cid):
    return [dict(r) for r in c.execute(
        "SELECT cs.id, cs.title, cs.status, cs.severity, cs.resolution, l.note, l.created_by, l.created_at FROM case_links l "
        "JOIN cases cs ON cs.id = CASE WHEN l.case_a = ? THEN l.case_b ELSE l.case_a END "
        "WHERE l.case_a = ? OR l.case_b = ? ORDER BY cs.updated_at DESC", (cid, cid, cid))]


_WORD = re.compile(r"[A-Za-z0-9_]{4,}")


def similar_cases(c, cid, limit=5):
    """Cases that deal with a similar topic, to be linked by hand. Same event type counts most, then similar title,
    same ECU, same detection and a shared vehicle. Cases that are already linked are left out."""
    mine = c.execute("SELECT a.cat_id, a.ecu_name, a.rule, a.vin FROM case_alerts ca JOIN alerts a ON a.id=ca.alert_id WHERE ca.case_id=?", (cid,)).fetchall()
    cats = {r["cat_id"] for r in mine if r["cat_id"]}
    ecus = {r["ecu_name"] for r in mine if r["ecu_name"]}
    rules = {r["rule"] for r in mine if r["rule"]}
    vins = {r["vin"] for r in mine if r["vin"]}
    title = c.execute("SELECT title FROM cases WHERE id=?", (cid,)).fetchone()["title"]
    words = {w.lower() for w in _WORD.findall(title)}
    linked = {cid} | {r["id"] for r in related_cases(c, cid)}
    names = {r["id"]: r for r in c.execute("SELECT id, title, status, severity FROM cases ORDER BY updated_at DESC LIMIT 1000")}
    score, why = {}, {}

    def add(oid, pts, text):
        if oid in linked or oid not in names:
            return
        score[oid] = score.get(oid, 0) + pts
        why.setdefault(oid, []).append(text)
    per = {}
    for r in c.execute("SELECT ca.case_id, a.cat_id, a.ecu_name, a.rule, a.vin FROM case_alerts ca JOIN alerts a ON a.id=ca.alert_id WHERE ca.case_id<>?", (cid,)):
        p = per.setdefault(r["case_id"], {"cats": set(), "ecus": set(), "rules": set(), "vins": set()})
        for k, v in (("cats", r["cat_id"]), ("ecus", r["ecu_name"]), ("rules", r["rule"]), ("vins", r["vin"])):
            if v:
                p[k].add(v)
    for oid, p in per.items():
        if cats & p["cats"]:
            add(oid, 3, "same event type")
        if ecus & p["ecus"]:
            add(oid, 1, "same ECU")
        if rules & p["rules"]:
            add(oid, 1, "same detection")
        if vins & p["vins"]:
            add(oid, 1, "same vehicle")
    if words:
        for oid, r in names.items():
            ow = {w.lower() for w in _WORD.findall(r["title"])}
            if oid != cid and ow and len(words & ow) / len(words | ow) >= 0.4:
                add(oid, 2, "similar title")
    out = []
    for oid, pts in sorted(score.items(), key=lambda x: (-x[1], -x[0])):
        if pts < 3:
            break
        r = names[oid]
        out.append({"id": oid, "title": r["title"], "status": r["status"], "severity": r["severity"], "basis": ", ".join(why[oid])})
        if len(out) >= limit:
            break
    return out


# ------------------------------------------------------------------ reading
def get_case(cid):
    c = db.conn()
    r = _case_or_404(c, cid)
    d = _decorate(dict(r), _today())
    d["tasks"] = [dict(t) for t in c.execute("SELECT * FROM case_tasks WHERE case_id=? ORDER BY position, id", (cid,))]
    d["tasks_total"] = len(d["tasks"])
    d["tasks_done"] = sum(1 for t in d["tasks"] if t["done"])
    d["alerts"] = [dict(a) for a in c.execute(
        "SELECT a.id, a.title, a.severity, a.status, a.vin, a.rule, a.event_count, a.first_ts, a.last_ts, ca.linked_at "
        "FROM case_alerts ca JOIN alerts a ON a.id=ca.alert_id WHERE ca.case_id=? ORDER BY a.sev_num DESC, a.id", (cid,))]
    d["vehicles"] = [dict(v) for v in c.execute(
        "SELECT a.vin, COUNT(*) AS alerts FROM case_alerts ca JOIN alerts a ON a.id=ca.alert_id "
        "WHERE ca.case_id=? AND a.vin IS NOT NULL GROUP BY a.vin ORDER BY alerts DESC, a.vin", (cid,))]
    d["log"] = [dict(x) for x in c.execute("SELECT * FROM case_log WHERE case_id=? ORDER BY created_at DESC, id DESC", (cid,))]
    d["open_alerts"] = sum(1 for a in d["alerts"] if a["status"] in ("new", "in_progress"))
    d["related"] = related_cases(c, cid)
    d["similar"] = similar_cases(c, cid)
    d["resolutions"] = RESOLUTIONS
    return d


def list_cases(p):
    c = db.conn()

    def many(k):
        return [x for v in p.get(k, []) for x in v.split(",") if x]
    w, a = ["1=1"], []
    st = many("status")
    if st:
        w.append(f"cs.status IN ({','.join('?' * len(st))})"); a += st
    sv = many("severity")
    if sv:
        w.append(f"cs.severity IN ({','.join('?' * len(sv))})"); a += sv
    if p.get("owner"):
        if p["owner"][0] == "none":
            w.append("cs.owner = ''")
        else:
            w.append("cs.owner = ?"); a.append(p["owner"][0])
    if p.get("related") and p["related"][0] in ("any", "none"):
        w.append(("" if p["related"][0] == "any" else "NOT ") + "EXISTS (SELECT 1 FROM case_links l WHERE l.case_a = cs.id OR l.case_b = cs.id)")
    if p.get("overdue"):
        w.append("cs.status <> 'closed' AND cs.due_date <> '' AND cs.due_date < ?"); a.append(_today())
    q = (p.get("q") or [""])[0].strip()
    if q:
        if q.lstrip("#").isdigit():
            w.append("cs.id = ?"); a.append(int(q.lstrip("#")))
        else:
            w.append("(cs.title LIKE ? OR cs.summary LIKE ?)"); a += [f"%{q}%"] * 2
    where = " AND ".join(w)
    sort = {"severity": "cs.sev_num", "updated": "cs.updated_at", "created": "cs.created_at", "id": "cs.id",
            "due": "(cs.due_date = ''), cs.due_date", "owner": "cs.owner", "status": "cs.status"}.get((p.get("sort") or ["severity"])[0], "cs.sev_num")
    d = "ASC" if (p.get("dir") or ["desc"])[0] == "asc" else "DESC"
    page = max(1, int((p.get("page") or ["1"])[0]))
    size = min(200, max(1, int((p.get("size") or ["50"])[0])))
    total = c.execute(f"SELECT COUNT(*) FROM cases cs WHERE {where}", a).fetchone()[0]
    rows = c.execute(
        f"SELECT cs.*, (SELECT COUNT(*) FROM case_alerts ca WHERE ca.case_id=cs.id) AS alerts, "
        f"(SELECT COUNT(*) FROM case_links l WHERE l.case_a=cs.id OR l.case_b=cs.id) AS related, "
        f"(SELECT COUNT(*) FROM case_tasks t WHERE t.case_id=cs.id) AS tasks_total, "
        f"(SELECT COUNT(*) FROM case_tasks t WHERE t.case_id=cs.id AND t.done=1) AS tasks_done "
        f"FROM cases cs WHERE {where} ORDER BY {sort} {d}, cs.updated_at DESC LIMIT ? OFFSET ?", a + [size, (page - 1) * size]).fetchall()
    today = _today()
    counts = {r["status"]: r["n"] for r in c.execute("SELECT status, COUNT(*) n FROM cases GROUP BY status")}
    owners = [r["owner"] for r in c.execute("SELECT DISTINCT owner FROM cases WHERE owner<>'' ORDER BY owner")]
    return {"total": total, "page": page, "size": size, "cases": [_decorate(dict(r), today) for r in rows],
            "status_counts": counts, "owners": owners}


def open_cases_for_picker(everything=False):
    where = "" if everything else "WHERE status<>'closed' "
    return [dict(r) for r in db.conn().execute(
        f"SELECT id, title, severity, status FROM cases {where}ORDER BY updated_at DESC LIMIT 200")]


# ------------------------------------------------------------------ dashboard
def dashboard(weeks=12):
    c = db.conn()
    now = db.now_ms()
    today = _today()
    cases = [dict(r) for r in c.execute("SELECT * FROM cases")]
    open_ = [x for x in cases if x["status"] != "closed"]
    closed = [x for x in cases if x["status"] == "closed" and x["closed_at"]]

    by_status = {s: sum(1 for x in cases if x["status"] == s) for s in STATUSES}
    overdue = [x for x in open_ if x["due_date"] and x["due_date"] < today]
    recent = [x for x in closed if x["closed_at"] >= now - 90 * DAY]
    ttc = [(x["closed_at"] - x["created_at"]) / DAY for x in recent]

    sev = [{"key": s, "label": s, "n": sum(1 for x in open_ if x["severity"] == s), "severity": s} for s in reversed(SEVERITIES)]
    owners = {}
    for x in open_:
        o = owners.setdefault(x["owner"] or "", {"n": 0, "overdue": 0})
        o["n"] += 1
        o["overdue"] += 1 if (x["due_date"] and x["due_date"] < today) else 0
    owner_rows = sorted(({"key": k, "label": k or "Unassigned", "n": v["n"], "overdue": v["overdue"]} for k, v in owners.items()),
                        key=lambda r: (-r["n"], r["label"]))

    buckets = [("Under 1 day", 0, 1), ("1 to 3 days", 1, 3), ("3 to 7 days", 3, 7), ("7 to 30 days", 7, 30), ("Over 30 days", 30, 10 ** 6)]
    ages = []
    for label, lo, hi in buckets:
        ages.append({"key": label, "label": label, "n": sum(1 for x in open_ if lo <= (now - x["created_at"]) / DAY < hi)})

    series = []
    for i in range(weeks - 1, -1, -1):
        end = now - i * 7 * DAY
        start = end - 7 * DAY
        series.append({
            "start": start, "end": end,
            "opened": sum(1 for x in cases if start < x["created_at"] <= end),
            "closed": sum(1 for x in closed if start < x["closed_at"] <= end),
            "backlog": sum(1 for x in cases if x["created_at"] <= end and (x["closed_at"] is None or x["status"] != "closed" or x["closed_at"] > end)),
        })

    res = [{"key": k, "label": v, "n": sum(1 for x in closed if x["resolution"] == k)} for k, v in RESOLUTIONS.items()]

    tasks = c.execute("SELECT COUNT(*) total, COALESCE(SUM(t.done), 0) done FROM case_tasks t JOIN cases cs ON cs.id=t.case_id WHERE cs.status<>'closed'").fetchone()
    uncased = c.execute("SELECT severity, COUNT(*) n FROM alerts WHERE status IN ('new','in_progress') "
                        "AND id NOT IN (SELECT alert_id FROM case_alerts) GROUP BY severity").fetchall()
    uncased_by = {r["severity"]: r["n"] for r in uncased}
    return {
        "total": len(cases), "open": len(open_), "by_status": by_status, "overdue": len(overdue),
        "unassigned": sum(1 for x in open_ if not x["owner"]),
        "closed_30d": sum(1 for x in closed if x["closed_at"] >= now - 30 * DAY),
        "mean_days_to_close": round(statistics.mean(ttc), 1) if ttc else None,
        "median_days_to_close": round(statistics.median(ttc), 1) if ttc else None,
        "closed_sample": len(ttc),
        "severity": sev, "owners": owner_rows, "ages": ages, "weekly": series, "resolutions": res,
        "tasks_total": tasks["total"], "tasks_done": tasks["done"],
        "alerts_without_case": sum(uncased_by.values()), "alerts_without_case_by_severity": uncased_by,
        "oldest_open_days": round(max(((now - x["created_at"]) / DAY for x in open_), default=0), 1),
    }
