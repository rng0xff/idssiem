"""CycurGUARD sev configuration (the JSON that lists every IDS manager, event and context-data layout).

Optional. When it is loaded, the event drawer shows the configured meaning of an event and turns coded context values
(for example a DTC number) into their names. Events are identified by ECU id plus event id: the same event id means
different things on different ECUs.
"""
import json

from . import auth

KEY = "_sev_config"


def parse(text):
    d = json.loads(text) if isinstance(text, (str, bytes)) else text
    if not isinstance(d, dict) or not isinstance(d.get("idsms"), dict):
        raise ValueError('This is not a sev configuration: the top level "idsms" object is missing.')
    ecus, events = {}, {}
    for eid, m in d["idsms"].items():
        if not isinstance(m, dict):
            continue
        ecus[str(eid)] = {"name": m.get("name") or "", "description": m.get("description") or ""}
        for sens in (m.get("sensors") or {}).values():
            for evid, ev in (sens.get("events") or {}).items():
                if not isinstance(ev, dict):
                    continue
                item = {"d": ev.get("description") or "", "t": ev.get("type_name") or ""}
                if ev.get("type") is not None:
                    item["type"] = ev["type"]
                if ev.get("sub_type") is not None:
                    item["sub"] = ev["sub_type"]
                fields = []
                for f in ((ev.get("data") or {}).get("fields") or []):
                    if isinstance(f, dict) and f.get("name"):
                        fl = {"n": str(f["name"]), "t": str(f.get("type") or "")}
                        if isinstance(f.get("values"), dict):
                            fl["v"] = {str(k).upper(): str(v) for k, v in f["values"].items()}
                        fields.append(fl)
                if fields:
                    item["f"] = fields
                events[f"{eid}:{evid}"] = item
    if not events:
        raise ValueError("The configuration lists no events.")
    return {"ecus": ecus, "events": events}


def load(text, actor):
    cfg = parse(text)
    auth._put_private(KEY, cfg)
    auth.log(actor, "sync.sevconfig", f"loaded: {len(cfg['events'])} events, {len(cfg['ecus'])} ECUs", via="sync")
    return status()


def clear(actor):
    auth._put_private(KEY, {"ecus": {}, "events": {}})
    auth.log(actor, "sync.sevconfig", "removed", via="sync")
    return status()


def _cfg():
    return auth._get_private(KEY, {"ecus": {}, "events": {}})


def status():
    c = _cfg()
    return {"loaded": bool(c["events"]), "events": len(c["events"]), "ecus": len(c["ecus"])}


def _name(spec, v):
    if not spec.get("v") or isinstance(v, bool) or not isinstance(v, int):
        return None
    for k in (format(v, "X"), format(v, "06X"), str(v)):
        if k in spec["v"]:
            return spec["v"][k]
    return None


def describe(ecu_id, event_id, extra):
    """Configured meaning of one event plus its context values with names. None when nothing is known."""
    c = _cfg()
    item = c["events"].get(f"{ecu_id}:{event_id}")
    if not item:
        return None
    spec = {f["n"]: f for f in item.get("f", [])}
    ctx = (extra or {}).get("ctx") or {}
    values = []
    for k, v in ctx.items():
        f = spec.get(k, {})
        values.append({"name": k, "value": v, "type": f.get("t", ""), "meaning": _name(f, v)})
    return {"description": item["d"], "type_name": item["t"], "type": item.get("type"), "sub_type": item.get("sub"),
            "ecu": c["ecus"].get(str(ecu_id), {}).get("name"), "context": values,
            "layout": [{"name": f["n"], "type": f["t"]} for f in item.get("f", [])]}
