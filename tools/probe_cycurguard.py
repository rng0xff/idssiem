#!/usr/bin/env python3
"""Collect what is needed to build the CycurGUARD import. Standard library only. Run it on a machine that can reach the backend.

  python tools/probe_cycurguard.py                      # spec only (no token needed)
  CYCURGUARD_TOKEN=... python tools/probe_cycurguard.py # spec plus a small sample of real responses

Writes everything to ./probe_out/. The token is read from the environment and never written to disk.
The sample responses contain VINs. Look through them before you share them.
"""
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

BASE = (os.environ.get("CYCURGUARD_URL") or "https://ineos.cycurguard.etas.com").rstrip("/")
TOKEN = os.environ.get("CYCURGUARD_TOKEN", "").strip()
OUT = "probe_out"
LIMIT = 200_000  # bytes kept per sample response


def call(method, path, body=None):
    headers = {"Accept": "application/json"}
    if TOKEN and path != "/openapi.json":
        headers["Authorization"] = "Bearer " + TOKEN
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60, context=ssl.create_default_context()) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # noqa
        return 0, str(e).encode()


def save(name, raw):
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(raw[:LIMIT])
    print(f"  saved {OUT}/{name} ({min(len(raw), LIMIT)} bytes{' truncated' if len(raw) > LIMIT else ''})")


def main():
    print(f"Backend: {BASE}   token: {'set' if TOKEN else 'not set (spec only)'}")
    st, raw = call("GET", "/openapi.json")
    print(f"GET /openapi.json -> {st}")
    if st != 200:
        sys.exit(raw.decode(errors="replace")[:300])
    save("openapi.json", raw)
    spec = json.loads(raw)
    schemas = spec.get("components", {}).get("schemas", {})
    wanted = [k for k in schemas if any(w in k for w in ("Search", "Report", "Lookup", "ExportFormat", "TokenResponse", "Filter", "Sort", "Pagination", "Sev"))]
    with open(os.path.join(OUT, "schemas_of_interest.json"), "w") as f:
        json.dump({k: schemas[k] for k in wanted}, f, indent=1)
    print("  saved probe_out/schemas_of_interest.json:", ", ".join(wanted))
    sec = spec.get("components", {}).get("securitySchemes")
    with open(os.path.join(OUT, "security.json"), "w") as f:
        json.dump(sec, f, indent=1)
    print("  security schemes:", json.dumps(sec)[:300])
    if not TOKEN:
        print("\nNo token set, so only the spec was collected. Set CYCURGUARD_TOKEN to also collect sample responses.")
        return
    probes = [("GET", "/v1/version", None, "version.json"), ("GET", "/v1/fields", None, "fields.json"),
              ("POST", "/v1/stats/count", {}, "count.json"), ("POST", "/v1/search", {}, "search_empty_body.json"),
              ("GET", "/v1/auth/settings", None, "auth_settings.json")]
    for m, p, b, name in probes:
        st, raw = call(m, p, b)
        print(f"{m} {p} -> {st}")
        save(name, raw)
        if st == 200:
            try:
                j = json.loads(raw)
                if isinstance(j, dict):
                    print("  top-level keys:", list(j)[:12])
                elif isinstance(j, list):
                    print(f"  list of {len(j)}")
                else:
                    print("  value:", str(j)[:80])
            except ValueError:
                print("  (not JSON)")
        elif st in (401, 403):
            print("  The token was refused here. Tell me which status you got.")
    print("\nDone. Send me probe_out/ (after a look at the VINs).")


if __name__ == "__main__":
    main()
