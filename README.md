# Fleet IDS: a local SIEM for vehicle IDS events

Runs on your machine, nothing leaves it. The look follows the INEOS TARA Workbench (light and dark theme, INEOS logo). Python 3.9+ and the standard library; `openpyxl` is only needed for Excel imports.

```
pip install -r requirements.txt        # only for .xlsx import
python run.py                          # then open http://127.0.0.1:8765
python run.py --import export.csv      # optional: import before starting
```

Data is stored in `data/siem.db` (SQLite). Set `IDS_SIEM_DB` to use another path.

## What it does

| Page | Use |
|---|---|
| Overview | Fleet figures, events over time (drag to select a period), top event types, vehicles and ECUs, open alerts |
| Events | Search with `vin:` `ecu:` `sev:` `name:` `id:` `type:` `cat:` `desc:` `ts:invalid`, `-` to negate, plus facets, time range, detail drawer with analyst notes, CSV export of the current result |
| Vehicles | Risk ranking, per-vehicle timeline, what each ECU reported, alerts |
| Alerts | Triage queue: status (new, in progress, resolved, false positive), assignee, notes, history, bulk actions |
| Detections | Tune the six rules; alerts keep their triage state when rules run again |
| Event catalog | Severity and category per event type. Defaults are a starting point, adjust to your TARA |
| Data | Import (CSV, XLSX, JSON), import history, data quality, settings |

## Detections

High-severity event, event burst (N events of one type on one vehicle in a window), multiple ECUs affected on one day, vehicle outlier (fleet statistics), fleet-wide spike (consecutive days merged), unclassified event type.

## Data handling you should know about

- **Re-importing is safe.** Each row is keyed by its content plus its n-th occurrence in the file, so overlapping exports do not double-count, and genuinely repeated identical rows are kept.
- **Unusable timestamps.** Events with an empty timestamp, or one before 2022-01-01 or in the future (an unsynchronised ECU clock), still count everywhere but cannot sit on a timeline or match a date range. Change the cut-off on the Data page.
- Times are shown and entered in UTC.

## Connecting the REST API later

`ids_siem/ingest.py` turns any source into the same row dicts. A REST client only has to fetch rows with the export's column names and call `import_rows(rows, source="api")`. Today you can also push JSON to `POST /api/ingest` (example on the Data page).

## Security

Binds to 127.0.0.1 only, rejects non-loopback `Host` headers, and requires an `X-SIEM: 1` header on every write so other websites cannot trigger changes. There is no login: anyone with access to your machine's local ports can use it.
