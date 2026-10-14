#!/usr/bin/env python3
"""Collect facts about the CycurGUARD backend's answers, to check how the Fleet IDS tool reads them.

Standard library only. Read-only (version, count and search calls). The token is never printed or written.

    export CYCURGUARD_URL=https://cycurguard.example
    export CYCURGUARD_TOKEN=...
    python3 probe_backend.py              # writes probe_result.json and prints a short summary
    python3 probe_backend.py --keep-vin   # keep real VINs (default: VINs are replaced by V1, V2, ...)

Send probe_result.json back. It holds a few complete sample records, no more than 300 records are read.
"""
import argparse
import collections
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

CTX = "report.context_data"


def call(base, token, method, path, body=None):
    req = urllib.request.Request(base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + token, "Accept": "application/json", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120, context=ssl.create_default_context()) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, (e.read() or b"")[:300].decode("utf-8", "replace")
    except Exception as e:  # noqa
        return 0, str(e)


def flat(x, p="", out=None):
    out = {} if out is None else out
    if isinstance(x, dict) and x:
        for k, v in x.items():
            flat(v, f"{p}.{k}" if p else str(k), out)
    elif isinstance(x, list) and x and all(isinstance(i, (dict, list)) for i in x):
        for n, v in enumerate(x[:3]):
            flat(v, f"{p}[{n}]", out)
    else:
        out[p] = x
    return out


def norm(k):
    import re
    return re.sub(r"\.\d+(?=\.|$)", ".#", k)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep-vin", action="store_true")
    ap.add_argument("--out", default="probe_result.json")
    a = ap.parse_args()
    base = os.environ.get("CYCURGUARD_URL", "").rstrip("/")
    token = os.environ.get("CYCURGUARD_TOKEN", "").strip()
    if not base or not token:
        sys.exit("Set CYCURGUARD_URL and CYCURGUARD_TOKEN first.")
    res = {}
    st, v = call(base, token, "GET", "/v1/version")
    res["version"] = v if st == 200 else f"HTTP {st}: {v}"
    if st != 200:
        print("version call failed:", res["version"])
    st, n = call(base, token, "POST", "/v1/stats/count", {})
    res["total_events"] = n if st == 200 else f"HTTP {st}: {n}"

    # 1. complete records, newest ingest first and oldest first, so rare event types have a chance
    recs = []
    for order in ("desc", "asc"):
        st, r = call(base, token, "POST", "/v1/search", {"max_results": 150, "offset": 0, "sort_params": [{"field": "cg_ingest_timestamp", "order": order}]})
        if st == 200 and isinstance(r, dict):
            recs += r.get("results", [])
        else:
            res[f"search_{order}"] = f"HTTP {st}: {r}"
    res["records_read"] = len(recs)

    # 2. what does source_fields return when it names a parent object, a list or a leaf? (CAN and sev events both)
    probe = {}
    tests = {"report_parents": ["report.rule_details", "report.message_info", "report.extra_data", "report.signal_info", CTX],
             "list_parent": ["report.message_info.details.ecus_tx"],
             "leaves": ["report.severity", "report.type_name", "report.rule_details.rule_name", "report.message_info.details.name",
                        CTX + ".can_id", CTX + ".cpu_load", CTX + ".dtc_id"],
             "whole_report": ["report"]}
    for name, fields in tests.items():
        for order in ("desc", "asc"):
            st, r = call(base, token, "POST", "/v1/search", {"max_results": 100, "offset": 0, "source_fields": fields,
                                                           "sort_params": [{"field": "cg_ingest_timestamp", "order": order}]})
            if st == 200 and isinstance(r, dict):
                keys = collections.Counter(norm(k) for x in r.get("results", []) for k in flat(x))
                probe[f"{name}_{order}"] = {"records": len(r.get("results", [])), "keys": dict(sorted(keys.items()))}
            else:
                probe[f"{name}_{order}"] = f"HTTP {st}: {r}"
    res["source_fields_test"] = probe

    # 3. summary over the records
    vins = {}
    def mask(rec):
        if a.keep_vin:
            return rec
        s = json.dumps(rec)
        for vin in {r.get("vin") for r in recs if r.get("vin")}:
            vins.setdefault(vin, f"V{len(vins) + 1}")
            s = s.replace(vin, vins[vin])
        return json.loads(s)

    ctx_types = collections.defaultdict(collections.Counter)
    ctx_examples = collections.defaultdict(list)
    per_event = {}
    null_ts = 0
    for r in recs:
        f = flat(r)
        if f.get("sev_metadata.timestamp") is None:
            null_ts += 1
        for k, val in f.items():
            if k.startswith(CTX + "."):
                ctx_types[k][type(val).__name__] += 1
                if val not in ctx_examples[k] and len(ctx_examples[k]) < 8:
                    ctx_examples[k].append(val)
        key = f"{f.get('ecu_id')}:{f.get('sev_metadata.event_id')}"
        if key not in per_event or (per_event[key].get(CTX + ".dtc_id") is None and f.get(CTX + ".dtc_id") is not None):
            per_event[key] = r
    res["records_without_event_timestamp"] = null_ts
    res["context_fields"] = {k: {"types": dict(ctx_types[k]), "examples": ctx_examples[k]} for k in sorted(ctx_types)}
    res["event_types_seen"] = sorted(per_event)
    # one complete record per ECU+event id, those with context data first, at most 25
    withctx = [r for r in per_event.values() if any(k.startswith(CTX + ".") for k in flat(r))]
    others = [r for r in per_event.values() if r not in withctx]
    res["sample_records"] = [mask(r) for r in (withctx + others)[:25]]
    with open(a.out, "w") as fh:
        json.dump(res, fh, indent=1, default=str)
    print(f"version: {res['version']}\ntotal events: {res['total_events']}\nrecords read: {len(recs)}, without event timestamp: {null_ts}")
    print("context fields:", ", ".join(res["context_fields"]) or "none")
    for k, v in probe.items():
        print(f"source_fields test {k}:", (str(v) if isinstance(v, str) else f"{len(v['keys'])} distinct keys")[:120])
    print(f"\nWrote {a.out} ({os.path.getsize(a.out)} bytes). Send that file back.")


if __name__ == "__main__":
    main()
