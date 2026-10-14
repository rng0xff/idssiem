# Fleet IDS: a local SIEM for vehicle IDS events

Runs on your machine, nothing leaves it. The look follows the INEOS TARA Workbench (light and dark theme, INEOS logo). Python 3.9+ and the standard library; `openpyxl` is only needed for Excel imports.

```
pip install -r requirements.txt        # only for .xlsx import
python idssiem.py                          # then open http://127.0.0.1:8765
python idssiem.py --import export.csv      # optional: import before starting
```

Data is stored in `data/siem.db` (SQLite). Set `IDS_SIEM_DB` to use another path.

## What it does

| Page | Use |
|---|---|
| Overview | Fleet figures, events over time (drag to select a period), top event types, vehicles and ECUs, open alerts |
| Events | Search with `vin:` `ecu:` `sev:` `name:` `id:` `type:` `cat:` `desc:` `ts:invalid`, `-` to negate, plus facets, time range, detail drawer with analyst notes, CSV export of the current result |
| Vehicles | Risk ranking, per-vehicle timeline, what each ECU reported, alerts |
| Alerts | Triage queue: status (new, in progress, resolved, false positive), assignee, notes, history, bulk actions |
| Cases | Create a case from one or more alerts (alert drawer or bulk action). Checklist (default tasks editable on the Data page), owner, due date, activity log, link or unlink alerts, close with a resolution (open alerts can be resolved with it), reopen. The dashboard shows status, overdue, ownerless, age, opened vs closed per week, time to close, severity, owners and resolutions |
| Detections | Tune the six rules; alerts keep their triage state when rules run again |
| Event catalog | Severity and category per event type. Defaults are a starting point, adjust to your TARA |
| Data | Sync from CycurGUARD, import (CSV, XLSX, JSON), import history, data quality, settings |
| Account | Change your password, create and revoke your own API tokens |
| Users (admin) | Accounts and roles, sign-in and token rules, backend connection, all tokens |
| Audit log (admin) | Who did what and when: search, filter by person, action group or date, export CSV, verify integrity |

## Detections

High-severity event, event burst (N events of one type on one vehicle in a window), multiple ECUs affected on one day, vehicle outlier (fleet statistics), fleet-wide spike (consecutive days merged), unclassified event type.

## Data handling you should know about

- **Re-importing is safe.** Each row is keyed by its content plus its n-th occurrence in the file, so overlapping exports do not double-count, and genuinely repeated identical rows are kept.
- **Unusable timestamps.** Events with an empty timestamp, or one before 2022-01-01 or in the future (an unsynchronised ECU clock), still count everywhere but cannot sit on a timeline or match a date range. Change the cut-off on the Data page.
- Times are shown and entered in UTC.

## Sync from the CycurGUARD backend

An administrator saves the backend address and an API token on the **Users** page (or set `CYCURGUARD_URL` and `CYCURGUARD_TOKEN`). Then **Data → Sync from CycurGUARD** pulls events over the backend's REST API. The command line does the same:

```
python idssiem.py --sync            # first run: everything; later runs: only what is new
python idssiem.py --sync --days 90  # first run: only the last 90 days
```

- **Test connection** on the Users page checks the address and token you typed, before you save them. **Check connection** on the Data page shows the backend version, how many events a sync would pull, and the first three, so you can check the mapping before starting.
- It pages through the backend by ingest time, oldest first, in pages of 5,000 (the backend caps one search at about 10,000). Each page is committed, so stopping or a failure keeps what was downloaded and the next sync continues from there.
- Events are stored under the backend's own event id, so syncing twice never doubles anything. Events you imported from a file earlier are matched to their backend copy once, not duplicated.
- Detections run after every sync, and each sync is written to the audit log.
- Use a CycurGUARD API token with view permission for reports. A short-lived login token stops working after a while and the sync then reports that the token was refused.
- Timing: about 9 seconds for 100,000 events on a synthetic backend, so roughly a minute and a half per million plus network time. The pages of the app stay fast at 100,000 events; at a million, the vehicle ranking and the filters take several seconds.

`POST /api/ingest` still accepts JSON from any other source.

## Sign-in, roles and API tokens

The first start asks for the first administrator. After that everything needs a sign-in.

| Role | May |
|---|---|
| viewer | read everything |
| analyst | viewer, plus triage alerts, work cases, classify events, import data, run detections |
| admin | analyst, plus users, settings, detection tuning, deleting imports, cases or all data, other people's tokens |

API tokens belong to a user and have their own permission (`view`, `modify`, `full`) and expiry. The effective access is the lower of the token and the owner's role. Tokens cannot create tokens or change passwords. The administrator sets the longest lifetime, the default, and can switch tokens off entirely. A token is shown once and only its hash is stored.

```
curl -H "Authorization: Bearer ids_..." http://127.0.0.1:8765/api/summary
```

Notes and cases are attributed to the signed-in user. Locked out? Run `python idssiem.py --reset-password USER` on the machine.

## Audit log

Every state-changing action is recorded with time, person, channel (session or API token), action, target and a short detail:

- sign-ins, failed sign-ins (including unknown usernames), sign-outs, password changes, denied requests
- users and API tokens, rule and backend changes, settings
- alert status, assignee and notes; case creation, changes, tasks, notes, links, close, reopen, delete
- event notes, event catalog changes, detection runs, imports, JSON ingests, import removal, deleting all data, CSV exports

Note text is not copied into the log, only that a note was added. Entries cannot be changed or deleted in the application, and "Delete all data" leaves them alone. Each entry carries a hash of its content and the previous entry, and **Verify integrity** on the Audit log page reports where the chain breaks. That detects edits and deleted entries in the middle of the log. Someone who can write the database file could recompute the chain, and cutting off the newest entries goes unnoticed unless you noted the latest hash, so treat it as evidence, not a vault. Only administrators can read it.

## Security

Binds to 127.0.0.1 only, rejects non-loopback `Host` headers, and requires an `X-SIEM: 1` header on every write so other websites cannot trigger changes. Passwords are stored as scrypt hashes, sessions are HttpOnly SameSite=Strict cookies, an account locks for 5 minutes after 5 wrong passwords, and the database file is created readable by you only. The backend token (Users page) is stored in that database in clear text because it has to be sent to the backend, so protect the file and use a token with the least permission that works. Traffic is plain HTTP on localhost; do not expose the port to a network.
