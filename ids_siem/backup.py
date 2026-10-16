"""Database backup and restore.

A backup is a consistent copy of the whole SQLite file (events, alerts, cases, experts, users, settings, the audit log),
made with SQLite's online backup, so it can be taken while the tool is running. Backups are kept next to the database in
data/backups. The file holds password hashes, API tokens and authenticator secrets: treat it like the database itself.

Restoring replaces the whole database with the backup. Before that the current state is saved as a "before-restore" backup,
so a restore can be undone by restoring that one.
"""
import datetime
import os
import re
import sqlite3
import time

from . import auth, db

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,100}\.db$")
REQUIRED = {"events", "alerts", "cases", "users", "settings", "audit", "case_tasks", "case_log"}
CONFIRM = "RESTORE"


class BackupError(Exception):
    pass


def folder():
    d = os.path.join(os.path.dirname(db.DB_PATH), "backups")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def _path(name):
    if not NAME_RE.match(name or ""):
        raise BackupError("invalid backup name")
    p = os.path.join(folder(), name)
    if not os.path.isfile(p):
        raise BackupError("no such backup")
    return p


def _info(p):
    st = os.stat(p)
    return {"name": os.path.basename(p), "size": st.st_size, "created_at": int(st.st_mtime * 1000)}


def list_backups():
    d = folder()
    out = [_info(os.path.join(d, n)) for n in os.listdir(d) if NAME_RE.match(n) and os.path.isfile(os.path.join(d, n))]
    return sorted(out, key=lambda x: x["created_at"], reverse=True)


def _snapshot(dest):
    src = sqlite3.connect(db.DB_PATH, timeout=30)
    try:
        out = sqlite3.connect(dest)
        try:
            src.backup(out)
            out.execute("PRAGMA journal_mode=DELETE")  # one self-contained file, no -wal or -shm next to it
        finally:
            out.close()
    finally:
        src.close()
    os.chmod(dest, 0o600)


def create(label=""):
    label = re.sub(r"[^A-Za-z0-9-]+", "-", label or "").strip("-")[:30]
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    name = f"siem-{stamp}{'-' + label if label else ''}.db"
    p = os.path.join(folder(), name)
    n = 1
    while os.path.exists(p):  # two backups in the same second
        n += 1
        name = f"siem-{stamp}-{n}{'-' + label if label else ''}.db"
        p = os.path.join(folder(), name)
    tmp = p + ".part"
    try:
        _snapshot(tmp)
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return _info(p)


def validate(path):
    """Is this a backup of this tool? Returns a short summary or raises BackupError."""
    try:
        c = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True, timeout=30)
    except sqlite3.Error as e:
        raise BackupError(f"not a database file: {e}")
    try:
        try:
            ok = c.execute("PRAGMA quick_check").fetchone()[0]
            tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        except sqlite3.DatabaseError as e:
            raise BackupError(f"not a database file: {e}")
        if ok != "ok":
            raise BackupError(f"the file is damaged ({ok})")
        missing = REQUIRED - tables
        if missing:
            raise BackupError("this is not a Fleet IDS SIEM backup (missing: " + ", ".join(sorted(missing)) + ")")
        n = lambda t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        return {"events": n("events"), "alerts": n("alerts"), "cases": n("cases"), "users": n("users")}
    finally:
        c.close()


def restore_file(path, actor="cli"):
    """Replace the database with the backup at `path`. The current state is kept as a before-restore backup."""
    summary = validate(path)
    if not summary["users"]:
        raise BackupError("the backup has no users, nobody could sign in afterwards")
    safety = create("before-restore") if os.path.exists(db.DB_PATH) and os.path.getsize(db.DB_PATH) else None
    src = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True, timeout=30)
    dst = db.conn()
    try:
        dst.commit()
        try:
            src.backup(dst)
        except sqlite3.Error as e:
            raise BackupError(f"restore failed, the database was not changed or can be recovered from {safety['name'] if safety else 'the before-restore backup'}: {e}")
    finally:
        src.close()
    dst.execute("PRAGMA journal_mode=WAL")
    db.init()  # a backup from an older version is brought up to date
    dst.execute("DELETE FROM sessions")  # people sign in again against the restored users
    dst.commit()
    auth.log(actor, "backup.restore", f"database restored ({summary['events']:,} events, {summary['alerts']} alerts, {summary['cases']} cases, {summary['users']} users)"
             + (f"; previous state kept as {safety['name']}" if safety else ""))
    return {"restored": summary, "safety_backup": safety["name"] if safety else None}


def delete(name):
    os.remove(_path(name))


def path_of(name):
    return _path(name)


def save_upload(data):
    """Write an uploaded file next to the backups so it can be validated and restored; returns its path."""
    tmp = os.path.join(folder(), f"upload-{int(time.time() * 1000)}.part")
    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return tmp
