#!/usr/bin/env python3
"""Start the IDS SIEM:  python idssiem.py [--port 8765] [--import FILE ...]"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ids_siem import auth, db, ingest, rules, server  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="Local SIEM for vehicle IDS events")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8765)))
    ap.add_argument("--import", dest="files", nargs="*", default=[], metavar="FILE",
                    help="import CSV/XLSX/JSON file(s) before starting the server")
    ap.add_argument("--reset-password", metavar="USER", help="set a new password for USER (recovery if the administrator is locked out), then exit")
    a = ap.parse_args()
    db.init()
    if a.reset_password:
        import getpass
        r = db.conn().execute("SELECT id FROM users WHERE username=?", (a.reset_password,)).fetchone()
        if not r:
            sys.exit(f"no such user: {a.reset_password}")
        pw = getpass.getpass("New password: ")
        if pw != getpass.getpass("Repeat: "):
            sys.exit("passwords differ")
        try:
            auth.update_user(r["id"], {"password": pw, "active": True, "unlock": True}, "cli")
        except ValueError as e:
            sys.exit(str(e))
        print("password changed, user unlocked and sessions ended")
        return
    for f in a.files:
        with open(f, "rb") as fh:
            s = ingest.import_rows(ingest.rows_for_file(f, fh.read()), filename=os.path.basename(f))
        print(f"imported {f}: {s['rows_new']} new, {s['rows_duplicate']} duplicate, {s['rows_invalid']} invalid")
    if a.files:
        print("detections:", rules.run_all())
    server.serve(port=a.port)


if __name__ == "__main__":
    main()
