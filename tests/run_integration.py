"""Integration runs against a real server on a temporary database (loopback, free port).

  python tests/run_integration.py security   # tools/security_test.py (headers, host check, auth, throttle, permissions)
  python tests/run_integration.py mcp        # agent/test_mcp.py with a seeded database (MCP server, token permissions)

Exit code = exit code of the test script. Nothing outside a temporary folder is touched."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PW = "correct horse battery"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def api(base, method, path, body=None, cookie=None):
    h = {"X-SIEM": "1", "Content-Type": "application/json"}
    if cookie:
        h["Cookie"] = "siem_session=" + cookie
    r = urllib.request.urlopen(urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None, method=method, headers=h))
    return json.loads(r.read() or b"null"), r.headers


def seed(base):
    _, h = api(base, "POST", "/api/auth/setup", {"username": "root", "password": PW, "display_name": "Root"})
    ck = h["Set-Cookie"].split(";")[0].split("=")[1]
    t0 = 1_780_000_000_000
    rows = []
    for v in range(8):
        for i in range(6):
            rows.append({"report.event_type": "can", "sev_metadata.timestamp": t0 + v * 3600000 + i * 60000, "vin": "SC6GM1CA0TF%06d" % (v + 1),
                         "ecu_name": "ETGW", "sev_metadata.event_id": 32795 if i % 2 == 0 else 32780, "sev_metadata.name": "IdsMEventConfig_ETGW_x"})
    api(base, "POST", "/api/ingest", rows, ck)
    api(base, "POST", "/api/detections/run", {}, ck)
    alerts, _ = api(base, "GET", "/api/alerts?size=2", None, ck)
    api(base, "POST", "/api/cases", {"title": "Seed case", "alert_ids": [a["id"] for a in alerts["alerts"][:1]]}, ck)


def main(which):
    tmp = tempfile.mkdtemp(prefix="idssiem-it-")
    port = free_port()
    db = os.path.join(tmp, "data", "t.db")
    env = dict(os.environ, IDS_SIEM_DB=db)
    srv = subprocess.Popen([sys.executable, os.path.join(ROOT, "idssiem.py"), "--port", str(port)], env=env, cwd=ROOT,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://localhost:{port}"
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(base + "/api/auth/status", timeout=1)
                break
            except Exception:
                time.sleep(0.1)
        else:
            print("server did not start")
            return 2
        if which == "security":
            cmd = [sys.executable, os.path.join(ROOT, "tools", "security_test.py"), str(port), db]
        elif which == "mcp":
            seed(base)
            env["IDS_SIEM_TEST_URL"] = base
            cmd = [sys.executable, os.path.join(ROOT, "agent", "test_mcp.py")]
        else:
            print("usage: run_integration.py security|mcp")
            return 2
        return subprocess.call(cmd, env=env, cwd=ROOT)
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except Exception:
            srv.kill()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else ""))
