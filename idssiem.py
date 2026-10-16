#!/usr/bin/env python3
"""Start Fleet IDS SIEM:  python idssiem.py [--port 8765] [--import FILE ...]"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ids_siem import auth, backup, cycurguard, db, ingest, rules, server  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="Local SIEM for vehicle IDS events")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8765)))
    ap.add_argument("--import", dest="files", nargs="*", default=[], metavar="FILE",
                    help="import CSV/XLSX/JSON file(s) before starting the server")
    ap.add_argument("--reset-password", metavar="USER", help="set a new password for USER (recovery if the administrator is locked out), then exit")
    ap.add_argument("--reset-mfa", metavar="USER", help="remove the authenticator app, passkeys and recovery codes of USER (recovery if the phone is lost), then exit")
    ap.add_argument("--sync", action="store_true", help="pull events from the CycurGUARD backend, then exit (URL and token from the Users page, or CYCURGUARD_URL and CYCURGUARD_TOKEN)")
    ap.add_argument("--days", type=int, default=None, help="with --sync: how far back the very first sync goes (default: everything)")
    ap.add_argument("--restart", action="store_true", help="with --sync: start from the beginning again instead of continuing (stored events are kept)")
    ap.add_argument("--backup", nargs="?", const="", metavar="FILE", help="save a consistent copy of the database (into data/backups, or to FILE), then exit; works while the server runs")
    ap.add_argument("--restore", metavar="FILE", help="replace the database with the backup FILE, then exit. Stop the server first. The current state is kept as a before-restore backup")
    ap.add_argument("--yes", action="store_true", help="with --restore: do not ask for confirmation")
    a = ap.parse_args()
    if a.backup is not None:
        db.init()
        if a.backup:
            backup._snapshot(a.backup)
            print(f"backup written to {a.backup}")
        else:
            i = backup.create("cli")
            print(f"backup written to {os.path.join(backup.folder(), i['name'])} ({i['size'] / 1048576:.1f} MB)")
        return
    if a.restore:
        try:
            s = backup.validate(a.restore)
            print(f"{a.restore}: {s['events']:,} events, {s['alerts']} alerts, {s['cases']} cases, {s['users']} users")
            if not a.yes and input("This replaces the current database. Type RESTORE to continue: ").strip() != "RESTORE":
                sys.exit("cancelled")
            db.init()
            r = backup.restore_file(a.restore, "cli")
        except backup.BackupError as e:
            sys.exit(f"restore failed: {e}")
        print("restored." + (f" The previous state is saved as data/backups/{r['safety_backup']}." if r["safety_backup"] else ""))
        return
    db.init()
    if a.sync:
        if a.restart:
            cycurguard.restart("cli")
        def show(s):
            tot = f" of {s['total']:,}" if s.get("total") is not None else ""
            print(f"  page {s['pages']}: {s['fetched']:,}{tot} events seen, {s['new']:,} new, {s['duplicate']:,} already present", flush=True)
        try:
            res = cycurguard.run(a.days, actor="cli", progress=show)
        except cycurguard.BackendError as e:
            sys.exit(f"sync failed: {e}")
        print(f"done: {res['rows_new']:,} new, {res['rows_duplicate']:,} already present, "
              f"{res['rows_matched_to_earlier_import']:,} matched to earlier file imports")
        print("detections:", res["detections"])
        return
    if a.reset_mfa:
        r = db.conn().execute("SELECT id FROM users WHERE username=?", (a.reset_mfa,)).fetchone()
        if not r:
            sys.exit(f"no such user: {a.reset_mfa}")
        from ids_siem import mfa
        n = mfa.admin_reset(r["id"], "cli")["removed"]
        print(f"{n} two-step method(s) removed and sessions ended")
        return
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
