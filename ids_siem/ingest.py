"""Import events from CSV / Excel / JSON into the database.

Every source yields plain dicts keyed by the backend's column names
(report.event_type, sev_metadata.timestamp, vin, ...). A later REST client only has to
produce the same dicts (or POST them as JSON to /api/ingest) and call import_rows().
"""
import csv
import datetime
import hashlib
import io
import json
from collections import Counter

from . import catalog, db

# Accepted header spellings -> internal field
HEADER_ALIASES = {
    "report.event_type": "event_type", "event_type": "event_type", "type": "event_type",
    "sev_metadata.timestamp": "ts", "timestamp": "ts", "ts": "ts", "time": "ts",
    "vin": "vin",
    "ecu_name": "ecu_name", "ecu": "ecu_name",
    "ecu_id": "ecu_id",
    "sev_metadata.event_id": "event_id", "event_id": "event_id",
    "sev_metadata.name": "name", "name": "name", "event_name": "name",
    "sev_metadata.description": "description", "description": "description",
}
FIELDS = ["event_type", "ts", "vin", "ecu_name", "ecu_id", "event_id", "name", "description"]
REQUIRED = ["event_type", "vin"]


class ImportError_(Exception):
    pass


def _canon_header(h):
    return HEADER_ALIASES.get(str(h or "").strip().lower().lstrip("﻿"))


def _map_row(raw):
    out = {}
    for k, v in raw.items():
        f = _canon_header(k)
        if f:
            out[f] = v
    return out


# ---------------------------------------------------------------- sources
def rows_from_csv(data: bytes):
    text = data.decode("utf-8-sig", errors="replace")
    head = text.split("\n", 1)[0]
    delim = max(";,\t|", key=head.count) if any(d in head for d in ";,\t|") else ";"
    reader = csv.DictReader(io.StringIO(text, newline=""), delimiter=delim)
    if not reader.fieldnames or not any(_canon_header(h) for h in reader.fieldnames):
        raise ImportError_("No known column headers found. Expected e.g. report.event_type;sev_metadata.timestamp;vin;ecu_name;...")
    for r in reader:
        yield _map_row(r)


def rows_from_xlsx(data: bytes):
    try:
        import openpyxl
    except ImportError:
        raise ImportError_("Excel import needs the 'openpyxl' package: pip install openpyxl")
    wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    ws = wb.worksheets[0]
    it = ws.iter_rows(values_only=True)
    try:
        header = next(it)
    except StopIteration:
        return
    # Some exports put the whole CSV line into column A: split it
    if header and len([h for h in header if h is not None]) == 1 and ";" in str(header[0]):
        header = str(header[0]).split(";")
        split_single = True
    else:
        split_single = False
    if not any(_canon_header(h) for h in header):
        raise ImportError_("No known column headers found in the first row of the first sheet.")
    for row in it:
        if split_single and row and row[0] is not None:
            row = str(row[0]).split(";")
        yield _map_row(dict(zip(header, row)))


def rows_from_json(data: bytes):
    obj = json.loads(data.decode("utf-8-sig"))
    if isinstance(obj, dict):
        obj = obj.get("events") or obj.get("items") or obj.get("data") or []
    if not isinstance(obj, list):
        raise ImportError_("JSON must be a list of event objects (or {\"events\": [...]})")
    for r in obj:
        if isinstance(r, dict):
            yield _map_row(r)


def rows_for_file(filename: str, data: bytes):
    n = (filename or "").lower()
    if n.endswith((".xlsx", ".xlsm")):
        return rows_from_xlsx(data)
    if n.endswith(".json"):
        return rows_from_json(data)
    if n.endswith((".csv", ".txt", ".tsv")):
        return rows_from_csv(data)
    if data[:2] == b"PK":
        return rows_from_xlsx(data)
    return rows_from_csv(data)


# ---------------------------------------------------------------- normalising
def _parse_ts(v):
    """Return epoch milliseconds or None."""
    if v is None:
        return None
    if isinstance(v, datetime.datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=datetime.timezone.utc)
        return int(v.timestamp() * 1000)
    s = str(v).strip()
    if not s:
        return None
    try:
        return int(float(s)) if s.replace(".", "", 1).lstrip("-").isdigit() else _iso(s)
    except (ValueError, OverflowError):
        return None


def _iso(s):
    try:
        d = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=datetime.timezone.utc)
    return int(d.timestamp() * 1000)


def _s(v):
    if v is None:
        return ""
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v).strip()


def _int(v):
    s = _s(v)
    try:
        return int(float(s))
    except ValueError:
        return None


def normalise(raw):
    """Raw mapped dict -> clean dict, or None if unusable."""
    r = {
        "event_type": _s(raw.get("event_type")).lower(),
        "ts": _parse_ts(raw.get("ts")),
        "vin": _s(raw.get("vin")).upper(),
        "ecu_name": _s(raw.get("ecu_name")),
        "ecu_id": _s(raw.get("ecu_id")),
        "event_id": _int(raw.get("event_id")),
        "name": _s(raw.get("name")),
        "description": _s(raw.get("description")),
    }
    if not r["vin"] or not r["event_type"]:
        return None
    return r


# ---------------------------------------------------------------- import
class Importer:
    """Inserts events into one `imports` record. Two ways of recognising an event that is already stored:

    * files (by_id=False): key = (content hash, n-th occurrence in this file). Genuinely repeated identical rows
      (common when the timestamp is missing) are kept, but re-uploading the same file does not double anything.
    * backend (by_id=True): key = the backend's own event id, which is stable however the windows overlap. Events
      that came in earlier from a file are matched once by content and then carry the backend id.

    add() can be called many times; checkpoint() commits what has been added so far.
    """

    def __init__(self, filename="upload", source="file", by_id=False):
        self.c = db.conn()
        self.by_id = by_id
        self.lo, self.hi = db.ts_bounds()
        self.occurrences = Counter()
        self.seen_cats = {}
        self.total = self.invalid = self.adopted = 0
        self.ts_now = db.now_ms()
        self.legacy = False
        self.c.execute("BEGIN")
        cur = self.c.execute(
            "INSERT INTO imports(filename, source, imported_at, rows_total, rows_new, rows_dup, rows_invalid) VALUES(?,?,?,0,0,0,0)",
            (filename, source, self.ts_now))
        self.import_id = cur.lastrowid
        self.before = self.c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        if by_id:
            self.legacy = self.c.execute("SELECT EXISTS(SELECT 1 FROM events WHERE dedupe_key NOT LIKE 'id:%')").fetchone()[0] == 1
        self.sql = ("INSERT OR IGNORE INTO events(dedupe_key, import_id, event_type, ts, ts_ok, vin, vin_prefix, ecu_name, ecu_id, "
                    "event_id, cat_id, name, description) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")

    @staticmethod
    def _hash(r):
        return hashlib.sha1("\x1f".join(str(r[f]) if r[f] is not None else "" for f in FIELDS).encode()).hexdigest()

    def add(self, rows):
        c, batch = self.c, []
        for raw in rows:
            self.total += 1
            r = normalise(raw)
            if r is None:
                self.invalid += 1
                continue
            h = self._hash(r)
            if self.by_id:
                bid = str(raw.get("backend_id") or "").strip()
                if not bid:
                    self.invalid += 1
                    continue
                key = "id:" + bid
                if self.legacy:
                    if c.execute("SELECT 1 FROM events WHERE dedupe_key=?", (key,)).fetchone():
                        continue
                    old = c.execute("SELECT id FROM events WHERE dedupe_key>=? AND dedupe_key<? LIMIT 1", (h + "#", h + "$")).fetchone()
                    if old:  # the same event arrived earlier from a file: give it the backend id instead of adding a twin
                        c.execute("UPDATE events SET dedupe_key=? WHERE id=?", (key, old["id"]))
                        self.adopted += 1
                        continue
            else:
                self.occurrences[h] += 1
                key = f"{h}#{self.occurrences[h]}"
            cid = catalog.cat_id(r["event_type"], r["event_id"])
            if cid not in self.seen_cats and r["event_id"] is not None:
                self.seen_cats[cid] = r
            ts_ok = 1 if r["ts"] is not None and self.lo <= r["ts"] <= self.hi else 0
            batch.append((key, self.import_id, r["event_type"], r["ts"], ts_ok, r["vin"], r["vin"][:6], r["ecu_name"], r["ecu_id"],
                          r["event_id"], cid, r["name"], r["description"]))
            if len(batch) >= 5000:
                c.executemany(self.sql, batch)
                batch = []
        if batch:
            c.executemany(self.sql, batch)

    def _stats(self):
        c = self.c
        # catalog: register event types not yet known
        for cid, r in self.seen_cats.items():
            if c.execute("SELECT 1 FROM catalog WHERE cat_id=?", (cid,)).fetchone():
                continue
            short, cat, sev, auto = catalog.default_for(r["event_type"], r["event_id"], r["name"], r["ecu_name"])
            c.execute("INSERT INTO catalog(cat_id, event_type, event_id, short_name, category, severity, sev_num, auto, first_seen) "
                      "VALUES(?,?,?,?,?,?,?,?,?)", (cid, r["event_type"], r["event_id"], short, cat, sev, catalog.SEV_NUM[sev], auto, self.ts_now))
        self.seen_cats = {}
        # events without an event_id still need a catalog row for the JOIN
        for (etype,) in c.execute("SELECT DISTINCT event_type FROM events WHERE event_id IS NULL AND import_id=?", (self.import_id,)).fetchall():
            cid = catalog.cat_id(etype, None)
            if not c.execute("SELECT 1 FROM catalog WHERE cat_id=?", (cid,)).fetchone():
                c.execute("INSERT INTO catalog(cat_id, event_type, event_id, short_name, category, severity, sev_num, auto, first_seen) "
                          "VALUES(?,?,NULL,?,?,?,?,1,?)", (cid, etype, f"{etype.upper()}_NO_ID", "Unclassified", "low", 1, self.ts_now))
        new = c.execute("SELECT COUNT(*) FROM events").fetchone()[0] - self.before
        dup = self.total - self.invalid - new
        c.execute("UPDATE imports SET rows_total=?, rows_new=?, rows_dup=?, rows_invalid=? WHERE id=?", (self.total, new, dup, self.invalid, self.import_id))
        return {"import_id": self.import_id, "rows_total": self.total, "rows_new": new, "rows_duplicate": dup,
                "rows_invalid": self.invalid, "rows_matched_to_earlier_import": self.adopted}

    def checkpoint(self, after_commit=None):
        """Commit everything added so far and keep going (long backend syncs)."""
        st = self._stats()
        self.c.execute("COMMIT")
        if after_commit:
            after_commit()
        self.c.execute("BEGIN")
        return st

    def finish(self):
        st = self._stats()
        self.c.execute("COMMIT")
        return st

    def abort(self):
        try:
            self.c.execute("ROLLBACK")
        except Exception:  # noqa
            pass


def import_rows(rows, filename="upload", source="file"):
    """Insert rows from a file or JSON post. Re-importing the same data is a no-op."""
    imp = Importer(filename, source)
    try:
        imp.add(rows)
        st = imp.finish()
    except Exception:
        imp.abort()
        raise
    st["filename"] = filename
    return st
