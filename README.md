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
| Vehicles | Risk ranking, per-vehicle timeline, what each ECU reported, alerts, and the model year, body, engine, hand of drive and market decoded from the VIN |
| Alerts | Triage queue: status (new, in progress, resolved, false positive, suppressed), assignee, notes, history, bulk actions |
| Cases | Create a case from one or more alerts (alert drawer or bulk action). Checklist (default tasks editable on the Data page), owner, due date, activity log, link or unlink alerts, close with a resolution (open alerts can be resolved with it), reopen, **Export report** (printable page, save as PDF from the print dialog). The dashboard shows status, overdue, ownerless, age, opened vs closed per week, time to close, severity, owners and resolutions |
| Detections | Tune the six rules; suppression rules for known-benign patterns; alerts keep their triage state when rules run again |
| Event catalog | Severity and category per event type. Defaults are a starting point, adjust to your TARA |
| Data | Sync from CycurGUARD, import (CSV, XLSX, JSON), import history, data quality, settings |
| Account | Change your password, two-step sign-in (authenticator app, passkeys, recovery codes), create and revoke your own API tokens |
| Users (admin) | Accounts and roles, sign-in and token rules, backend connection, all tokens |
| Audit log (admin) | Who did what and when: search, filter by person, action group or date, export CSV, verify integrity |

## Suggested cases

An alert that is in no case shows **May belong to an existing case** when a case already contains an alert for the same vehicle and event type (for fleet-wide alerts: the same detection) with activity within 30 days of this one. Up to three cases are suggested, open ones first; a closed case is shown with its outcome and has to be reopened before alerts can be added. **Add to case #N** links the alert (analysts and admins; it is written to the audit log). Nothing is ever linked automatically. The alert list shows *maybe #N* in the Case column for new and in-progress alerts with an open suggestion.

## Suppression rules

For patterns you have judged harmless (for example an event type that a bench tool always triggers). Create one from an alert (**Suppress similar alerts**) or on the Detections page. A rule matches on detection, ECU, event type and vehicle; empty fields match anything, at least one is required. It needs a reason and has an expiry (90 days preset, or none).

- Matching alerts get the status **Suppressed**: they leave the open list, stay on the Suppressed tab and carry the rule and reason in their history. Events are never hidden.
- Alerts someone already works on (in progress or in a case) are not suppressed.
- Switching a rule off, deleting it or letting it expire returns its alerts to New.
- Analysts and admins can create, switch off and delete rules. Every change is in the audit log (`suppression.*`).

## Case report

**Export report** on a case opens a printable page: facts, summary, findings and decision, vehicles with their decoded VIN, linked alerts, checklist and the full activity log, all in UTC. Use the browser's print dialog and choose Save as PDF. Each export is written to the audit log (`case.report`). Text from the case is HTML-escaped; the page needs no network.

## VIN decoding

Vehicle details come from the VIN itself, using the INEOS Grenadier VIN decoder (Corp-P2-ENG-0128 rev 001; EU/ROW serial and SVO, US/Canada MPV serial and SVO, US/Canada truck). The code is `ids_siem/vin.py`. The Overview has a "Fleet by" panel (model year, variant, body, engine, hand of drive, market) and clicking a bar lists those vehicles; the Vehicles page also accepts `year`, `variant`, `vehicle_type`, `body`, `engine`, `drive`, `market` and `plant` filters. Each vehicle page shows a Vehicle identity panel with the VIN split by field and a check-digit verdict.

Things to know:
- Codes the document does not list are shown as "Unknown (X)" and flagged, never guessed.
- The EU/ROW and US/Canada tables overlap for the LEVIII petrol engine. A passenger car with engine C and restraint code A matches the US/Canada tables and is shown as US/Canada; trucks are identified by the WMI SH7.
- The document only says "Calculation" (EU) or "Reserved" (US) for position 9. The tool checks it with the standard ISO 3779 algorithm, which holds for every VIN in the sample export. A mismatch is a hint of a typo or a spoofed VIN, not proof.

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
- **Complete sync.** The first sync asks how far back to go; choose *everything*. Later syncs continue where the last one ended. To read everything again (for example to add backend details to events synced earlier), use **Data → Start over…** or `python idssiem.py --sync --restart`. Stored events and cases are kept; events already present are recognised by id and only get missing details. Starting over is written to the audit log (`sync.restart`).
- **Show all fields** on the Data page lists every field the backend returns for up to 200 events (name, type, examples, how many distinct values), fields the tool does not use yet first. Nothing is stored.
- **Backend details.** Each synced event also keeps the backend's own details, reduced to what an analyst reads: the CycurGUARD severity (1 to 3), the decoded values with their names (for example error code `512 ACKERR`), for CAN events the message (name, id, sender, receivers), the violated rule with its limits and measurements, and the signal values, plus the report's counter, batch id and time window. They appear under *Backend details* in the event details; about 0.5 KB per event. For events without an event time the window shows when it happened at the earliest and latest. Events synced by an older version get these details when a later sync meets them again (or after deleting the import and syncing again).
- **Event configuration.** An administrator can load the CycurGUARD sev configuration (JSON) on the Data page. It is optional, because the backend already names most coded values; the event details then also show the configured meaning of the event. Events are matched by ECU id plus event id. Loading and removing it are written to the audit log.
- It pages through the backend by ingest time, oldest first, in pages of 5,000 (the backend caps one search at about 10,000). Each page is committed, so stopping or a failure keeps what was downloaded and the next sync continues from there.
- Events are stored under the backend's own event id, so syncing twice never doubles anything. Events you imported from a file earlier are matched to their backend copy once, not duplicated.
- Detections run after every sync, and each sync is written to the audit log.
- Use a CycurGUARD API token with view permission for reports. A short-lived login token stops working after a while and the sync then reports that the token was refused.
- Timing: about 9 seconds for 100,000 events on a synthetic backend, so roughly a minute and a half per million plus network time. The pages of the app stay fast at 100,000 events; at a million, the vehicle ranking and the filters take several seconds.

**Automatic sync.** An administrator can switch on a schedule under **Users → Backend connection → Automatic sync** (every 5, 15, 30 minutes, or 1, 3, 6, 12, 24 hours). While the tool is running it pulls new events in the background, continuing where the last sync ended. Automatic runs only start once a person has done the first sync (they choose how far back it goes). A run that finds nothing new is not written to the audit log; runs with new events and failures are (actor `schedule`), and so is every change of the schedule (`sync.schedule`). The Data page shows the interval and the next run. If the tool is not running, nothing is pulled; the next run follows after it starts.

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

## Two-step sign-in (MFA and passkeys)

Everyone can add a second step under **Account → Two-step sign-in**. Every change asks for the password again.

- **Authenticator app (TOTP).** Scan the QR code (or type the key) in any authenticator app, then enter the 6-digit code. Codes are 6 digits, 30 seconds, one step of clock drift is tolerated and a code works once.
- **Passkeys (WebAuthn).** Add a platform passkey (Windows Hello, Touch ID, phone) or a security key. A passkey asks for your fingerprint, face or PIN and signs you in on its own (button **Sign in with a passkey**), or answers the second step after your password. ES256 and RS256 keys are supported, attestation is not evaluated (the key is trusted when you add it).
- **Recovery codes.** Ten single-use codes are created with your first method and shown once; they are stored as hashes. New codes make the old ones useless.
- **Sign-in.** With a second step set up, the password leads to a second screen for a code, a recovery code or a passkey. Wrong codes count towards the same lock-out as wrong passwords (5 attempts, 5 minutes), and the sign-in times out after 5 minutes.
- **Policy.** An administrator can require two-step sign-in on the Users page (not allowed until they have it themselves). People without it can then only reach their Account page until they have set it up. API tokens are not affected, they have their own permission and expiry.
- **Lost phone or key.** An administrator resets a person's two-step sign-in in the user's panel; on the computer, `python idssiem.py --reset-mfa USER` does the same. Both sign the person out everywhere. The reset and every change are in the audit log (`mfa.*`).

Passkeys need a domain name as their identity, so they work only when you open the tool as **http://localhost:8765** (not 127.0.0.1) and are bound to that address and port. Authenticator codes work at either address. The TOTP key is stored in the database file in clear text, as it has to be to check codes, like the backend token; protect the file. The code is `ids_siem/mfa.py`, `webauthn.py` (standard library only) and `qr.py`.

## Audit log

Every state-changing action is recorded with time, person, channel (session or API token), action, target and a short detail:

- sign-ins (with the method used), failed sign-ins (including unknown usernames), sign-outs, password changes, two-step changes (authenticator app, passkeys, recovery codes, resets), denied requests
- users and API tokens, rule and backend changes, settings
- alert status, assignee and notes; suppression rules created, switched on or off and deleted; case reports generated; case creation, changes, tasks, notes, links, close, reopen, delete
- event notes, event catalog changes, detection runs, imports, JSON ingests, import removal, deleting all data, CSV exports

Note text is not copied into the log, only that a note was added. Entries cannot be changed or deleted in the application, and "Delete all data" leaves them alone. Each entry carries a hash of its content and the previous entry, and **Verify integrity** on the Audit log page reports where the chain breaks. That detects edits and deleted entries in the middle of the log. Someone who can write the database file could recompute the chain, and cutting off the newest entries goes unnoticed unless you noted the latest hash, so treat it as evidence, not a vault. Only administrators can read it.

## Security

- **Network.** Binds to 127.0.0.1 only and accepts only loopback `Host` headers (exact match, so `localhost.evil.com` is refused). Every write needs an `X-SIEM: 1` header, so other websites cannot trigger changes. Traffic is plain HTTP on localhost; do not expose the port to a network.
- **Browser.** A strict Content-Security-Policy (no inline scripts, `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'none'`), plus `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `nosniff`, and cross-origin isolation headers. Session cookies are HttpOnly and SameSite=Strict. All text from events, backends and users is escaped before it is shown.
- **Sign-in.** Passwords are stored as scrypt hashes (N=32768; older hashes are upgraded at the next sign-in). An account locks for 5 minutes after 5 wrong passwords or codes, and failed sign-ins from all sources together are limited to 40 a minute. Two-step sign-in is described above.
- **Input.** All SQL is parameterised and sort columns are fixed lists. JSON requests are limited to 16 MB, file uploads to 1 GB, and Excel files that unpack to more than 4 GB are refused. Exported CSV files prefix cells that start with `=`, `+`, `-` or `@` with an apostrophe, so a spreadsheet does not run event text as a formula.
- **Errors.** Unexpected errors show a generic message in the browser; the details go to the server console.
- **At rest.** The data folder and database files are readable by you only from the moment they are created. The backend token and the authenticator secrets are stored in the database in clear text because they have to be used; protect the file (disk encryption, restricted account) and give the backend token the least permission that works.
- **Audit.** The audit log is hash-chained: edits and deletions are detected, but someone with write access to the database file could rebuild the chain.
