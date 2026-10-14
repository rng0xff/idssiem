"""Demonstration helper: creates and works cases for all open alerts at once.

One button creates sensible cases for every alert that is not in a case yet, works through their checklists,
writes notes from the real event data and closes most of them (some end up waiting). It never touches events and
writes nothing to the audit log while it runs. The cases are remembered in a private list so "Remove demo cases"
can undo the run; "Keep these cases" empties that list, after which the cases are ordinary and permanent.
"""
import datetime
import hashlib
import threading

from . import auth, cases, db, vin as vinmod
from .catalog import SEV_NUM

STEPS_PER_CASE = 8  # create, start, five tasks, close: used for the time estimate only

_lock = threading.Lock()
_state = {"tick": 0, "last_error": "", "last_action": "", "ids": []}


def _mine():
    return list(auth._get_private("_wizard", {"cases": []}).get("cases", []))


def _since():
    return auth._get_private("_wizard", {}).get("since") or 0


def _save_mine(ids, since=None):
    auth._put_private("_wizard", {"cases": sorted(set(ids)), "since": (since if since is not None else _since()) if ids else 0})


def _in(ids):
    return ",".join("?" * len(ids)) or "NULL"


# ------------------------------------------------------------------ planning
def _h(*parts):
    return int(hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:8], 16)


def _candidates(c):
    """Alerts that nobody has taken yet: not in a case, not suppressed, not already decided."""
    return [dict(r) for r in c.execute(
        "SELECT a.* FROM alerts a WHERE a.status IN ('new','in_progress') "
        "AND NOT EXISTS (SELECT 1 FROM case_alerts ca WHERE ca.alert_id=a.id) ORDER BY a.sev_num DESC, a.id")]


def _vin_label(v):
    i = vinmod.decode(v)
    return i["label"] if i.get("valid") else "unknown vehicle"


def plan_groups(c):
    """Group open alerts into cases a person would make: one case per fleet-wide alert, one for all
    unclassified event types, one per event type seen on three or more vehicles, one per remaining vehicle."""
    al = _candidates(c)
    groups, used = [], set()

    def add(title, items, kind):
        groups.append({"title": title, "ids": [a["id"] for a in items], "kind": kind,
                       "sev": max((a["severity"] for a in items), key=lambda s: SEV_NUM[s])})
        used.update(a["id"] for a in items)

    unclassified = [a for a in al if a["rule"] == "new_event_type"]
    if unclassified:
        add(f"Classify {len(unclassified)} new event type{'s' if len(unclassified) > 1 else ''} in the catalog", unclassified, "catalog")
    for a in al:
        if a["id"] not in used and not a["vin"]:
            add(a["title"], [a], "fleet")
    by_cat = {}
    for a in al:
        if a["id"] not in used and a["cat_id"]:
            by_cat.setdefault(a["cat_id"], []).append(a)
    for cat, items in sorted(by_cat.items(), key=lambda kv: -len(kv[1])):
        vins = {a["vin"] for a in items if a["vin"]}
        if len(vins) >= 3:
            nm = items[0]["title"].split(" on ")[0]
            ecu = items[0]["ecu_name"]
            add(f"{nm} on {len(vins)} vehicles" + (f" ({ecu})" if ecu else ""), items, "pattern")
    by_vin = {}
    for a in al:
        if a["id"] not in used:
            by_vin.setdefault(a["vin"], []).append(a)
    for v, items in by_vin.items():
        n = len(items)
        add(f"{_vin_label(v)} ({v}): " + (items[0]["title"] if n == 1 else f"{n} alerts"), items, "vehicle")
    groups.sort(key=lambda g: (-SEV_NUM[g["sev"]], -len(g["ids"]), g["title"]))
    return groups


def _owners(c):
    return [r["username"] for r in c.execute("SELECT username FROM users WHERE active=1 AND role IN ('analyst','admin') ORDER BY id")] or [""]


def _due(sev):
    days = {"critical": 3, "high": 5, "medium": 10, "low": 21}.get(sev, 14)
    return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)).strftime("%Y-%m-%d")


# ------------------------------------------------------------------ one step
def _create_next(c):
    groups = plan_groups(c)
    if not groups:
        return False
    g = groups[0]
    owners = _owners(c)
    n_cases = len(_state["ids"])
    ph = ",".join("?" * len(g["ids"]))
    ev = c.execute(f"SELECT COALESCE(SUM(event_count),0) FROM alerts WHERE id IN ({ph})", g["ids"]).fetchone()[0]
    vins = {r[0] for r in c.execute(f"SELECT DISTINCT vin FROM alerts WHERE id IN ({ph}) AND vin IS NOT NULL", g["ids"])}
    summary = (f"Opened from {len(g['ids'])} alert{'s' if len(g['ids']) > 1 else ''} "
               f"covering {ev:,} events on {len(vins)} vehicle{'s' if len(vins) != 1 else ''}. "
               f"Grouped as: {dict(catalog='unclassified event types', fleet='fleet-wide alert', pattern='same event type on several vehicles', vehicle='one vehicle').get(g['kind'])}.")
    cs = cases.create_case({"alert_ids": g["ids"], "title": g["title"], "severity": g["sev"], "owner": owners[n_cases % len(owners)],
                            "due_date": _due(g["sev"]), "summary": summary})
    _state["ids"].append(cs["id"])
    _state["last_action"] = f"opened case #{cs['id']}: {g['title']}"
    return True


def _facts(c, case):
    al = case["alerts"]
    ids = [a["id"] for a in al]
    ph = ",".join("?" * len(ids)) or "NULL"
    row = c.execute(f"SELECT COALESCE(SUM(event_count),0) n, MIN(first_ts) f, MAX(last_ts) l FROM alerts WHERE id IN ({ph})", ids).fetchone()
    cats = [r[0] for r in c.execute(f"SELECT DISTINCT cat_id FROM alerts WHERE id IN ({ph}) AND cat_id IS NOT NULL", ids)]
    vins = [v["vin"] for v in case["vehicles"]]
    others = 0
    if cats:
        q = ",".join("?" * len(cats))
        involved = ",".join("?" * len(vins)) or "NULL"
        others = c.execute(f"SELECT COUNT(DISTINCT vin) FROM events WHERE cat_id IN ({q}) AND vin NOT IN ({involved})", cats + vins).fetchone()[0]
    return {"events": row["n"], "first": row["f"], "last": row["l"], "vins": vins, "others": others, "n_alerts": len(al),
            "rules": sorted({a["rule"] for a in al}), "sev": case["severity"]}


def _day(ms):
    return datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc).strftime("%Y-%m-%d") if ms else "an unknown date"


def _task_note(task, f, cid):
    t = task.lower()
    if "linked events" in t or "vehicle history" in t:
        veh = ", ".join(_vin_label(v) for v in f["vins"][:2]) or "no single vehicle"
        return (f"Reviewed {f['events']:,} events from {f['n_alerts']} alert{'s' if f['n_alerts'] > 1 else ''}, "
                f"{_day(f['first'])} to {_day(f['last'])}. Vehicles: {veh}{' and others' if len(f['vins']) > 2 else ''}.")
    if "other vehicles" in t:
        return (f"The same event type also appears on {f['others']:,} other vehicle{'s' if f['others'] != 1 else ''} in the data."
                if f["others"] else "No other vehicle in the data shows this event type.")
    if "tara" in t or "csms" in t:
        return ("No threat scenario can be linked from the event data alone. Marked for the next TARA review."
                if SEV_NUM[f["sev"]] >= 3 else "No relevance for the TARA threat scenarios identified.")
    return None


def _resolution(case, f):
    kinds = f["rules"]
    r = _h("res", case["id"]) % 100
    if kinds == ["new_event_type"]:
        return "benign", "Event types were classified in the catalog, no further action."
    if SEV_NUM[f["sev"]] >= 3:
        return ("confirmed", "Events are consistent with an attempted access or a faulty ECU state. Follow-up with the ECU owner.") if r < 35 else \
               (("false_positive", "Pattern traced to a test or diagnostic session, not an attack.") if r < 60 else
                ("benign", "Known behaviour after a power cycle or software update, within expectations."))
    return ("benign", "Expected CAN behaviour at start-up or during bus load, no action needed.") if r < 70 else \
           ("duplicate", "Same pattern is already tracked in another case.") if r < 80 else \
           ("confirmed", "Real timing fault, passed to the network team.")


def _advance(c, row):
    cid = row["id"]
    cs = cases.get_case(cid)
    f = _facts(c, cs)
    if cs["status"] == "open":
        cases.update_case(cid, {"status": "investigating"})
        cases.add_comment(cid, {"comment": "Starting with the linked events and the vehicle history."})
        _state["last_action"] = f"started case #{cid}"
        return
    todo = [t for t in cs["tasks"] if not t["done"]]
    stay_open = _h("open", cid) % 100 < 20
    if stay_open and cs["tasks_done"] >= max(2, cs["tasks_total"] // 2):
        cases.update_case(cid, {"status": "waiting"})
        cases.add_comment(cid, {"comment": "Waiting for the ECU owner to confirm the expected behaviour before closing."})
        _state["last_action"] = f"case #{cid} is waiting for input"
        return
    if todo:
        t = todo[0]
        cases.update_task(cid, t["id"], {"done": True})
        note = _task_note(t["title"], f, cid)
        if note:
            cases.add_comment(cid, {"comment": note})
        _state["last_action"] = f"case #{cid}: {t['title'].lower()}"
        return
    res, why = _resolution(cs, f)
    findings = (f"{why} Affected: {len(f['vins'])} vehicle{'s' if len(f['vins']) != 1 else ''}, {f['events']:,} events. "
                f"Same event type on {f['others']:,} other vehicles.")
    cases.close_case(cid, {"resolution": res, "findings": findings, "resolve_alerts": True})
    _state["last_action"] = f"closed case #{cid} ({cases.RESOLUTIONS[res].lower()})"


def tick():
    c = db.conn()
    active = c.execute(f"SELECT id FROM cases WHERE id IN ({_in(_state['ids'])}) AND status IN ('open','investigating') ORDER BY updated_at, id", _state["ids"]).fetchall()
    _state["tick"] += 1
    create_first = _state["tick"] % 2 == 0 or len(active) < 3
    if create_first and _create_next(c):
        return
    if active:
        _advance(c, active[0])
        return
    _create_next(c)


# ------------------------------------------------------------------ run
def _as(user):
    """Do the work as the signed-in administrator, without audit entries."""
    prev = getattr(auth._cur, "user", None)
    auth.set_current({**user, "via": "wizard"})
    return prev


def run(user):
    """Create, work and close cases for every open alert at once."""
    if not _lock.acquire(blocking=False):
        raise ValueError("It is already running.")
    prev = _as(user)
    try:
        _state.update(tick=0, ids=[])
        started = db.now_ms()
        c = db.conn()
        for _ in range(20000):  # safety cap
            if not plan_groups(c) and not c.execute(f"SELECT 1 FROM cases WHERE id IN ({_in(_state['ids'])}) AND status IN ('open','investigating')", _state["ids"]).fetchone():
                break
            tick()
        _save_mine(_mine() + _state["ids"], _since() or started)
        return {**status(), "created": len(_state["ids"])}
    finally:
        auth.set_current(prev)
        _lock.release()


def keep(user):
    """Forget which cases the run made: they are ordinary cases from now on and "Remove" no longer touches them."""
    n = len(_mine())
    _save_mine([])
    auth.log(user["username"], "case.keep", f"{n} generated case(s) made permanent", target="")
    return {"kept": n}


def reset(user):
    """Delete the cases of the run(s) not yet made permanent and put their alerts back to 'new'."""
    if not _lock.acquire(blocking=False):
        raise ValueError("It is running.")
    prev = _as(user)
    try:
        c = db.conn()
        ids = [i for i in _mine() if c.execute("SELECT 1 FROM cases WHERE id=?", (i,)).fetchone()]
        reset_alerts, now, since = 0, db.now_ms(), _since()
        for cid in ids:
            for a in c.execute("SELECT a.id, a.status FROM alerts a JOIN case_alerts ca ON ca.alert_id=a.id WHERE ca.case_id=?", (cid,)).fetchall():
                # take the alert back to how it was: status new and without the history the run wrote
                c.execute("DELETE FROM alert_comments WHERE alert_id=? AND author='system' AND created_at>=?", (a["id"], since))
                if a["status"] != "new":
                    c.execute("UPDATE alerts SET status='new', updated_at=? WHERE id=?", (now, a["id"]))
                    reset_alerts += 1
            cases.delete_case(cid)
        # entries left by an earlier version of this feature
        c.execute("DELETE FROM alert_comments WHERE author='system' AND (body LIKE '%Wizard (demo)%' OR body LIKE 'Reset when the demo cases were removed.%')")
        c.commit()
        _save_mine([])
        return {"removed": len(ids), "alerts_reset": reset_alerts}
    finally:
        auth.set_current(prev)
        _lock.release()


def status():
    c = db.conn()
    ids = [i for i in _mine() if c.execute("SELECT 1 FROM cases WHERE id=?", (i,)).fetchone()]
    cnt = {r["status"]: r["n"] for r in c.execute(f"SELECT status, COUNT(*) n FROM cases WHERE id IN ({_in(ids)}) GROUP BY status", ids)}
    groups = plan_groups(c)
    return {"cases_total": sum(cnt.values()), "cases_closed": cnt.get("closed", 0), "cases_waiting": cnt.get("waiting", 0),
            "cases_active": cnt.get("open", 0) + cnt.get("investigating", 0),
            "pending_groups": len(groups), "pending_alerts": sum(len(g["ids"]) for g in groups)}
