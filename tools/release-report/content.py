import os, sys
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
from doclib import Doc
HERE=os.path.dirname(os.path.abspath(__file__))
FIG=lambda n: os.path.join(HERE,'figures',n)

# ---- static knowledge per test script (extend when a test script is added) ------------------------------------------
TESTINFO={
 'test_rules':dict(what='The six detection rules with their thresholds (high-severity, burst, multi-ECU, vehicle outlier, fleet spike, unclassified event type), suppression rules, alert re-opening, idempotent re-runs, disabled rules.',
   obj='Each rule raises an alert exactly when its documented condition holds (and not just below the threshold); severity bump and cap; suppression needs scope and reason; a resolved alert re-opens on new events; running the detections twice creates nothing twice.',fm='Missed or false detection',cov=['detect']),
 'test_ingest':dict(what='Import: column aliases, CSV and JSON, normalisation of VIN and event type, de-duplication on re-import, repeated identical rows, backend import by id, timestamp plausibility, registration of unknown event types in the catalog.',
   obj='Re-importing the same file adds nothing; identical rows inside one file are kept; rows without VIN or type are counted invalid; implausible timestamps are flagged; unknown event types become "unclassified"; a file without known headers is rejected.',fm='Event lost, doubled or mis-timed on import',cov=['data']),
 'test_vin':dict(what='VIN decoder: ISO 3779 check digit (reference vector), EU/ROW and US/Canada decoding, malformed VINs, unknown codes.',
   obj='Check digit equals the reference value; malformed VINs are reported, not decoded; an unknown code is listed and does not raise.',fm='Wrong vehicle attributes',cov=['vin']),
 'test_security':dict(what='scrypt password hashing, account set-up, sign-in, lock-out after five failures, sessions stored as hash, role and username validation, last administrator protected, audit hash chain (modification and deletion detected), TOTP (RFC 4226 vectors).',
   obj='Passwords verify only with the right value; unknown user and wrong password give the same answer; five failures lock the account; the audit chain reports an edited or deleted entry; the TOTP implementation reproduces the RFC 4226 test values.',fm='Unauthorised access; undetected change of the audit log',cov=['auth','audit']),
 'security_test':dict(what='Running application (temporary database, loopback): security headers and CSP, Host-header check, malformed requests, role enforcement, token permissions, CSV formula neutralisation, file permissions, sign-in flood limit.',
   obj='All checks of tools/security_test.py pass against a freshly started server: headers present, foreign Host headers refused (403), writes without X-SIEM header refused, roles and tokens enforced, exports neutralised, database file 0600, flood throttled.',fm='Unauthorised access; weak web interface',cov=['auth','web']),
 'test_mcp':dict(what='MCP server for AI agents against a seeded server: tool list, read-only tools, note tools, permission of view and modify tokens, error handling, attribution and audit entry.',
   obj='A view token cannot write; a modify token can only add notes marked "[AI agent]" and cannot change status; invalid tokens and arguments give clear errors; the action is in the audit log.',fm='Misuse of the AI agent interface',cov=['agent']),
}
GENERIC=dict(what='(new test script – describe it in tools/release-report/content.py, TESTINFO)',obj='(new test script – describe it in tools/release-report/content.py, TESTINFO)',fm='to be assigned',cov=[])
KNOWN_INFO={}
MANUAL=[
 ('TC-M01','Start `python idssiem.py` on a PC without network connection, open http://localhost:8765, create the first administrator.','Application starts, no error, no network access needed; sign-in page then dashboard.'),
 ('TC-M02','Import an original IDS report export (CSV and XLSX; `pip install -r requirements.txt` for XLSX). Compare the row counts of the import result with the source file; import the same file again.','Counts equal the source; second import adds no event (all duplicates).'),
 ('TC-M03','Import `tests/data/worked_example.csv` (chapter 6) and run the detections (Data → Run detections).','Exactly one burst alert "3× INVALID_SIG within 45 min", severity high, 3 events; the fourth event is not part of it.'),
 ('TC-M04','Detections page: raise the burst threshold to 4, run detections; then create a suppression rule for the alert with a reason.','Alert no longer reproduced at threshold 4; with the rule the alert shows status Suppressed with the reason in its history; events stay visible.'),
 ('TC-M05','Create a case from an alert, work through a checklist step, document an expert, generate the case report.','Case, step status, expert and report are complete and attributed to the signed-in user.'),
 ('TC-M06','Account: add an authenticator app (TOTP), sign out, sign in with password and code; then sign in with a recovery code.','Both ways work; each recovery code works once; the entries are in the audit log.'),
 ('TC-M07','Audit log (administrator): verify integrity.','Chain reported as intact; the sign-ins and changes of the test are listed.'),
 ('TC-M08','If a CycurGUARD backend is available: Users → Test connection, Data → Check connection, then a small sync (last days).','Connection and event count plausible; imported events carry backend details; a second sync adds nothing.'),
 ('TC-M09','Open the Vehicles page for a VIN of a real vehicle.','Market, year, body, engine and hand of drive agree with the vehicle documentation.'),
 ('TC-M10','On the installation used for analysis run `python tools/release_report.py --hash` and compare with the source-tree checksum of the evidence record.','Checksums equal.'),
]
MANUAL_COV={'detect':['TC-M03','TC-M04'],'data':['TC-M02','TC-M08'],'vin':['TC-M09'],'auth':['TC-M06'],'audit':['TC-M07'],'web':['TC-M01'],'agent':[],'file':['TC-M10']}
COV_LABEL=[('detect','Missed or false detection'),('data','Data loss / duplication'),('vin','Wrong vehicle attributes'),('auth','Unauthorised access'),('audit','Audit log integrity'),('web','Web interface'),('agent','AI agent interface'),('file','Changed tool files')]
WORD={1:'one',2:'two',3:'three',4:'four',5:'five',6:'six',7:'seven',8:'eight',9:'nine',10:'ten',11:'eleven',12:'twelve'}
def nword(n): return WORD.get(n,str(n))

def make(F,cfg):
    T=F['tool']; R=F['run']; D=F['deps']; tests=F['tests']; n=len(tests); S=F['files']
    allok=all(t['exit']==0 for t in tests); ncases=sum(t.get('count',0) for t in tests)
    d=Doc(cfg['title'],cfg['docNumber'],F['revision'],'tm')
    d.h(1,'PURPOSE')
    d.p('This record documents the management of the tool **Fleet IDS SIEM** that supports the evaluation of intrusion detection system (IDS) events reported by vehicles. It shows how the tool is identified, which use it is intended for, how its influence on cybersecurity was assessed, how it is validated and kept under configuration control, and which limitations users have to know. It serves as evidence for the tool management requirements of ISO/SAE 21434 clause 5 (organizational cybersecurity management) for a tool used in the post-development activities (continual cybersecurity activities, clause 8, and operations and maintenance, clause 13).')
    d.note('Note','The classification in chapter 8 and the validation criteria in chapters 9 and 10 are a **proposal of the tool owner**. They become effective when the cybersecurity process owner has reviewed and approved this record (chapter 17). Clause references are to be confirmed by the cybersecurity process owner.')
    d.h(1,'SCOPE')
    d.p('The record applies to the in-house developed tool listed in chapter 4 and to the Python runtime and libraries it needs. It covers its use for the analysis of IDS events of INEOS vehicles.')
    d.bullets(['**In scope:** Fleet IDS SIEM (web application on the analyst PC, database, import, detection rules, case handling, audit log), the MCP interface for AI agents (`agent/mcp_server.py`) and the test scripts.','**Not in scope:** the vehicle IDS and the CycurGUARD backend (data sources), the operating system, the browser, the authenticator apps and the Python runtime itself. They are managed by their owners and by IT and are only listed where the tool depends on them. The incident-response and vulnerability-management process that uses the alerts.'])
    d.h(1,'RESPONSIBILITIES')
    d.table([2600,7607],[['Role','Responsibility'],
        ['Tool owner ('+cfg['owner']+')','Develops and maintains the tool, keeps this record current, performs the validation before each release, decides on tool changes.'],
        ['Administrator of the installation','Creates accounts and assigns roles, sets the sign-in policy and detection parameters, protects the data folder, runs the verification of the audit log.'],
        ['Analyst','Triages alerts, works cases, classifies event types, and verifies the findings with the system or component owners. Reports tool errors to the tool owner.'],
        ['Cybersecurity process owner','Approves this record and the tool classification, decides whether a re-evaluation is needed.']])
    d.h(1,'TOOL IDENTIFICATION')
    d.table([2400,7807],[['Item','Fleet IDS SIEM'],
        ['Programme','`idssiem.py` with the package `ids_siem/`, the web interface `static/` and the AI agent interface `agent/mcp_server.py`'],
        ['Purpose','Import and store IDS events, classify them by severity, detect patterns across the fleet (six rules), manage alerts and cases with checklist, experts and report, keep an audit log.'],
        ['Version',T['version']+(' (git tag)' if T.get('tagged') else ' (the application has no version number; identified by the last commit that changed the tool: `'+T['sourceCommitShort']+'`)')],
        ['Origin','In-house development, repository https://github.com/rng0xff/idssiem'],
        ['Delivery form','Source code; Python 3.9 or later and the standard library. `openpyxl` only for Excel import. No installation, no network access needed; binds to the loopback address.'],
        ['Inputs','CSV, XLSX, JSON exports of vehicle IDS reports; CycurGUARD backend (REST, optional); JSON via `POST /api/ingest`'],
        ['Outputs','Alerts, cases, case report, CSV export of events and of the audit log, MCP answers for an AI agent'],
        ['Data storage','SQLite file (`data/siem.db`, `IDS_SIEM_DB`), readable by the owner only']],bold_first=True)
    d.h(1,'INTENDED USE AND LIMITS OF USE')
    d.p('The tool supports the analyst in finding and documenting conspicuous IDS events of the vehicle fleet. It **proposes** alerts; the analyst decides on status, suppression, case and response.')
    d.bullets(['The tool is used **only** to evaluate and document IDS events. It does not change anything in the vehicle, the IDS configuration or the backend; the backend is only read.','Severity and category per event type are **defaults** of the event catalog (a starting point). They are adjusted to the TARA by the analyst; the tool does not know the real impact on the vehicle.','A **missing alert is not proof of absence of an attack**: the rules find patterns in the data that was imported (chapter 14).','Alerts, cases and exports are valid only together with the data that was imported and the tool version recorded in this record.','The AI agent interface can read and add notes marked `[AI agent]`. It cannot change a status, link, close or delete anything.'])
    d.p('The detection rules are described in chapter 6; the security properties of the tool in chapter 7.')
    d.h(1,'DETECTION METHODOLOGY')
    d.p('This chapter describes how an event reported by a vehicle becomes an alert and how an alert is handled. The description follows the code (`ids_siem/ingest.py`, `catalog.py`, `rules.py`) and the README of the tool.')
    d.img(FIG('fig1.png'),'Overview: from the vehicle report to the case, with access control and audit log',width_in=6.3)
    d.h(2,'Events and import')
    d.bullets(['**Event:** one IDS report with event type, event id, timestamp, VIN, ECU name and id, name and description. Column names of the INEOS / CycurGUARD exports are mapped automatically (aliases such as `report.event_type`, `sev_metadata.timestamp`).','**Normalisation:** VIN in upper case, event type in lower case; a row without VIN or event type is invalid and only counted.','**De-duplication:** a file row is identified by a hash of its content plus its n-th occurrence in the file. Importing the same data again adds nothing; genuinely repeated identical rows are kept. Backend events are identified by the backend event id.','**Timestamp plausibility:** a timestamp before the cut-off date (default 2022-01-01) or more than one day in the future is treated as an unsynchronised ECU clock. Such events count everywhere but do not take part in the time-based rules (burst, multiple ECUs, fleet spike).','**VIN decoder:** market, model year, body, engine, hand of drive and plant are derived from the VIN positions; the ISO 3779 check digit is verified. Unknown codes are listed, not guessed.'])
    d.h(2,'Event catalog and severity')
    d.p('Every event type (type and event id) has a catalog entry with short name, category and severity (info, low, medium, high, critical). The tool ships defaults for the known types of the IDS (for example `UDS_CRIT_NR_NRC` = high, `INVALID_SIG` = medium, `BURST_START` = info). An unknown type is registered as **unclassified** with severity low until an analyst classifies it. The severity of a type is the basis for all rules.')
    d.h(2,'Detection rules')
    d.p('The rules run after every import or sync and on demand. Parameters can be changed by the administrator; the defaults are shown.')
    d.table([2100,4900,3207],[['Rule','Condition','Severity of the alert'],
        ['High-severity event','Event type with catalog severity at or above the chosen minimum (default high); grouped per vehicle, ECU and event type.','Catalog severity'],
        ['Event burst','At least N events (default 3) of the same type on one vehicle within a sliding window (default 60 min). Overlapping windows form one cluster. Events of severity info and events without a valid timestamp are ignored.','Catalog severity raised by one level, at most high'],
        ['Multiple ECUs','At least N different ECUs (default 3) report non-info events on one vehicle on the same UTC day.','High if one event is high or above, otherwise medium'],
        ['Vehicle outlier','Number of non-info events of a vehicle is more than K standard deviations (default 3) above the fleet mean, at least 10 events, at least 5 vehicles in the data.','Medium'],
        ['Fleet-wide spike','A UTC day with more non-info events than the daily mean plus K standard deviations (default 3), at least 30 events, at least 7 days of data. Spike days at most one quiet day apart form one alert.','Medium'],
        ['Unclassified event type','An event type that is not in the built-in catalog and was not yet classified.','Low']],bold_first=True)
    d.h(2,'Alert life cycle')
    d.bullets(['An alert has a stable key (rule and its scope). Running the rules again updates the alert (count, time range, severity) and **never creates it twice**; the triage state of an alert is kept.','Status: new, in progress, resolved, false positive, suppressed. A resolved or false-positive alert is **re-opened** with a system note when new matching events arrive.','**Suppression rules** (detection, ECU, event type, vehicle; at least one) with mandatory reason and expiry (default 90 days) mark matching new alerts as suppressed. Alerts already in work are not suppressed; events are never hidden. Creation and deletion are written to the audit log.','An alert can be linked to a **case** with checklist, documented technical experts, notes and a case report. A case suggests related cases.'])
    d.h(2,'Worked example')
    d.p('One vehicle reports the event type `INVALID_SIG` (catalog severity medium) four times: at minute 0, 20, 45 and 120 (file `tests/data/worked_example.csv`). Burst rule with window 60 min and threshold 3:')
    d.table([2600,5007,2600],[['Step','Rule applied','Result'],
        ['Events 1, 2, 3','Event 3 is 45 min after event 1 (≤ 60 min): three events in the window = threshold','Cluster of **3**'],
        ['Event 4','75 min after event 3, window of event 3 holds only itself','not part of the cluster'],
        ['Severity','medium (catalog) raised by one level','**high**'],
        ['Other rules','High-severity: type is medium, not high. Multiple ECUs: one ECU only.','no alert']],bold_first=True)
    d.p('Result: one alert "3× INVALID_SIG within 45 min", severity high, three events. This example is recomputed with the detection code at every release (last check: '+R['date']+') and is used as manual test case TC-M03 (chapter 10).')
    d.img(FIG('fig2.png'),'Worked example: events, burst cluster and resulting alert severity',width_in=6.3)
    d.h(1,'SECURITY OF THE TOOL')
    d.p('The tool processes vehicle identification numbers and stores credentials of the analysts. The measures below are described in the README; the right-hand column names the automated test that checks them (chapter 11).')
    d.table([2300,5107,2800],[['Area','Measure','Evidence'],
        ['Network','Binds to 127.0.0.1 only; accepts only loopback `Host` headers; every write needs an `X-SIEM` header (cross-site requests cannot change data).','`security_test`'],
        ['Browser','Strict content-security policy (no inline scripts), frame, referrer and sniffing protection; HttpOnly SameSite cookies; output escaped.','`security_test`'],
        ['Authentication','scrypt password hashes; account lock for 5 minutes after 5 failures; global limit of failed sign-ins; same answer for unknown user and wrong password; sessions stored as hash.','`test_security`, `security_test`'],
        ['Two-step sign-in','TOTP (RFC 6238), passkeys (WebAuthn), recovery codes stored as hash; can be required by the administrator.','`test_security` (RFC 4226 vectors); TC-M06'],
        ['Roles and tokens','viewer / analyst / admin; API tokens with own permission and expiry, only hash stored; access = lower of token and role.','`security_test`, `test_mcp`'],
        ['Audit log','Every state-changing action with person, channel, action and target; hash chain over all entries; verification function. Edit and deletion in the middle of the log are detected; rebuilding by someone with write access to the database file is not.','`test_security` (tamper and delete)'],
        ['Input','Parameterised SQL; size limits; exported CSV neutralises formula cells.','`security_test`'],
        ['Data at rest','Data folder and database readable by the owner only. Backend token and authenticator secrets are stored in clear text because they must be used: protect the file.','`security_test` (permissions)']],bold_first=True)
    d.h(1,'TOOL CLASSIFICATION AND ERROR DETECTION')
    d.p('**Influence on cybersecurity.** The tool produces alerts and case records that the analyst reviews before they lead to a decision (for example a vulnerability or incident entry, a change of the TARA or a field action). It has no influence on the vehicle. The influence is therefore **indirect**: a missed or wrongly rated alert could delay a response. The measures below reduce the probability that such an error stays undetected.')
    d.table([2400,3100,4707],[['Potential tool failure','Effect','Measure to prevent or detect it'],
        ['Missed detection (false negative)','A pattern in the data is not reported','Rules are documented with thresholds (chapter 6) and tested at the threshold (`test_rules`); every event stays searchable and countable independent of the rules; fleet figures on the overview page; the analyst can search events directly.'],
        ['False alarm','Effort, alert fatigue','Suppression rules with reason, expiry and audit entry; parameters tunable; events are never hidden by a suppression.'],
        ['Event lost or doubled on import','Counts and rules distorted','Import result shows total / new / duplicate / invalid; tests for re-import, repeated rows and backend ids (`test_ingest`); compare with the source (TC-M02).'],
        ['Wrong timestamp handling','Event missing in a burst or time range','Implausible timestamps are flagged and counted separately (shown with `ts:invalid`); tested (`test_ingest`).'],
        ['Wrong severity of an event type','Alerts too low or too high','Catalog defaults are visible and editable on the Catalog page; unknown types are flagged for classification; changes are in the audit log.'],
        ['Wrong vehicle attributes','Wrong grouping by market or engine','Decoder lists unknown codes instead of guessing; check digit verified; tested with the reference vector (`test_vin`, TC-M09).'],
        ['Unauthorised access or change','Disclosure or manipulation of cases','Chapter 7; audit log; roles.'],
        ['Unnoticed change of the tool','Tool behaves differently than validated','Configuration management and source-tree checksum (chapters 12 and 13).'],
        ['Misuse of the AI agent interface','Wrong statements in cases','Agent can only add notes marked `[AI agent]`, cannot change status; every action is in the audit log; `test_mcp`.']])
    d.p('**Classification (proposal).** Based on the indirect influence and the possibility to detect errors through the independent data (events stay available), the review by the analyst and the audit log, the tool is classified as a **tool with low impact, high error detection**. For this class the tool management consists of identification, controlled use, regression testing and configuration control as described in this record. A qualification beyond that is not planned. This is a proposal of the tool owner and is to be confirmed by the cybersecurity process owner.')
    d.h(1,'TOOL VALIDATION')
    d.p('The tool is validated by an automated regression test that is run before every release and after every change of the source: `python tests/run_tests.py` (unit tests, no server needed) and `python tests/run_integration.py security|mcp` (tests against a real server on a temporary database). The release script runs all of them.')
    d.table([1800,8407],[['Test','What it verifies']]+[[t['name'],TESTINFO.get(t['name'],GENERIC)['what']] for t in tests])
    d.p('**Acceptance criterion:** all '+nword(n)+' test scripts end without error (exit code 0, '+str(ncases)+' test cases in total) and every informational line they print is assessed (chapter 11). A failing test blocks the release.')
    d.p('**Limits of the validation.** The automated tests check the code with synthetic data and one reference vector. They do not use real vehicle data, the CycurGUARD backend (needs a backend; manual case TC-M08) or a browser (user interface is checked manually). Statistical rules (outlier, spike) are tested with constructed data; their usefulness for real fleet data is judged by the analysts. The tests do not replace the review of an alert by an analyst. The unit tests were added together with this record; before that, only the two API tests existed.')
    d.h(1,'TEST PLAN')
    d.p('**Objective.** Show with repeatable tests that the tool imports, detects, stores and protects data as described in chapters 6 and 7 and that the failure modes of chapter 8 are covered. The plan applies to every release and to every re-evaluation (chapter 16).')
    d.p('**Test items.** The tool of the release under test (chapter 4).')
    d.p('**Test environment.** Automated tests: Python '+R['python']+' (any Python 3.9 or later), standard library only, a temporary database per test; integration tests start the application on a free loopback port. Manual tests: a PC with the delivered source, a current browser and real IDS exports; an authenticator app; a CycurGUARD backend for TC-M08.')
    d.p('**Test levels.** (1) Unit tests of detection, import, VIN decoding, authentication, audit chain and TOTP. (2) Integration tests of the web interface and the MCP server. (3) Manual acceptance tests with real data.')
    d.p('**Entry criteria.** Source committed; working tree clean; no open defect that affects a detection, an import or the access control.')
    d.p('**Pass / fail criteria.** Automated: every script ends with exit code 0. Manual: actual result equals expected result. A release needs all cases passed; a failed case blocks the release until the defect is fixed and the whole plan is run again.')
    d.p('**Automated test cases** (run by the release script; results in chapter 11):')
    d.table([1100,1700,4907,2500],[['ID','Script','Objective and expected result','Failure modes (chapter 8)']]+[['TC-A%02d'%(i+1),t['name'],TESTINFO.get(t['name'],GENERIC)['obj'],TESTINFO.get(t['name'],GENERIC)['fm']] for i,t in enumerate(tests)])
    d.p('**Manual test cases** (executed by the tool owner before each release; the result is entered in `tools/release-report/manual-results.json`):')
    def manual_result(tc):
        m=F['manual'].get(tc)
        if m and m.get('version')==T['version'] and m.get('result'):
            return ('Passed' if m['result']=='passed' else 'FAILED')+' ('+m.get('date','')+(', '+m['by'] if m.get('by') else '')+')'
        return 'open'+(' (last: '+m['result']+' for '+m.get('version','?')+')' if m and m.get('result') else '')
    d.table([1100,3300,3407,2400],[['ID','Action','Expected result','Result (this version)']]+[[a,b,c,manual_result(a)] for a,b,c in MANUAL])
    cov=[]
    for key,label in COV_LABEL:
        ids=['TC-A%02d'%(i+1) for i,t in enumerate(tests) if key in TESTINFO.get(t['name'],GENERIC)['cov']]+MANUAL_COV.get(key,[])
        cov.append(label+': '+(', '.join(ids) if ids else '**no test case**')+'.')
    d.p('**Coverage of the failure modes.** '+' '.join(cov))
    d.p('**Defects.** A failed case is recorded with the commit, the data used and the actual result. After the fix the failed case and the complete automated test are repeated. If the defect could have hidden an alert, the tool owner informs the analysts and the affected period is re-evaluated.')
    d.p('**Responsibilities and schedule.** The tool owner prepares and executes the tests and records the results. The plan is executed before every release and on every trigger of chapter 16; the cybersecurity process owner approves changes of the plan.')
    d.h(1,'TEST REPORT')
    d.p('Execution of the automated tests of the test plan (chapter 10) on the release baseline.')
    unassessed=[]; infos=[]
    for t in tests:
        for l in t['info']:
            k=t['name']+'|'+l
            if k in KNOWN_INFO: infos.append((t['name'],l,KNOWN_INFO[k]))
            else: infos.append((t['name'],l,None)); unassessed.append(k)
    status='**PASSED** – all '+nword(n)+' test scripts ended with exit code 0 ('+str(ncases)+' test cases)' if allok else '**FAILED** – '+', '.join(t['name'] for t in tests if t['exit']!=0)+' ended with an error; the release is blocked'
    if unassessed: status+='; **'+str(len(unassessed))+' informational line(s) not yet assessed**'
    d.table([3000,7207],[['Item','Value'],
        ['Executed',R['date']+', '+R['time']+' UTC'],
        ['Source','Version '+T['version']+', HEAD '+T['commitFull']+(' – **working tree not clean**' if T['dirty'] else '')],
        ['Environment','Python '+R['python']+', '+R['platform']+', SQLite '+D['sqlite']+(', openpyxl '+D['openpyxl'] if D['openpyxl'] else ' (openpyxl not installed)')],
        ['Command','`python tools/release_report.py` (unit tests per module, `tests/run_integration.py security`, `tests/run_integration.py mcp`)'],
        ['Overall result',status]],bold_first=True)
    def keys(t):
        parts=[', '.join(t['keys'])+'.' if t['keys'] else '']
        if t['info']: parts.append('Informational: '+', '.join('`'+k+'`' for k in t['info'])+' – see the note below.')
        if t['fail']: parts.append('Failed: '+'; '.join(t['fail']))
        return ' '.join(p for p in parts if p) or '(no status lines)'
    def res(t): return 'Passed' if t['exit']==0 else 'FAILED (exit '+str(t['exit'])+')'
    d.table([2000,1500,6707],[['Test','Result','Output (key lines)']]+[[t['name'],res(t),keys(t)] for t in tests])
    if infos:
        d.p('**Note on informational output.** The tests below printed comparison results that are not failures. The tool owner assessed each line:')
        d.bullets(['**'+a+':** `'+b+'` – '+(c if c else '**not yet assessed** – the tool owner must assess this line before the release') for a,b,c in infos])
    else:
        d.p('The tests print no informational lines: every check either passes or fails the script.')
    d.p('The full console output is reproduced by running the commands above on the commit named in the evidence record.')
    d.h(1,'CONFIGURATION AND CHANGE MANAGEMENT')
    d.bullets(['**Version control:** all source, tests and documents are in one Git repository. Every change is a commit with author and date; the history starts on '+T['firstDate']+'.','**Identification:** the application has no version number of its own. A release is identified by the last commit that changed the tool (or a git tag, if set) and by the SHA-256 checksum over all tool files (`python tools/release_report.py --hash`, chapter 13).','**Change procedure:** change → automated tests → commit → release record. Event catalog defaults and detection parameters are changed on request of the cybersecurity process owner or the analysts and are visible in the audit log of the installation.','**Release checklist:** (1) `python tests/run_tests.py` passes, (2) manual test cases executed and entered, (3) the record is regenerated with `python tools/release_report.py --release`, which runs all tests and writes version, commit, checksum and test report into chapters 11 and 17, (4) the record is reviewed and signed (chapter 17).','**Issue handling:** errors found by users are reported to the tool owner, assessed for their effect on alerts and cases already created, and corrected in a new version.'])
    d.h(1,'SUPPLY CHAIN AND INTEGRITY')
    d.p('The tool uses the Python standard library only, with one optional third-party package. The web interface (`static/`) loads no script, font or stylesheet from the network.')
    d.table([2400,2200,1500,1300,2807],[['Component','Version','Licence','Use','Remark'],
        ['openpyxl',(D['openpyxl'] or 'not installed')+' (requirement: `'+', '.join(D['requirements'])+'`)',D['openpyxlLicense'] or '–','Run time, optional','Reads Excel imports only. The requirement is **not pinned** to an exact version.'],
        ['Python',R['python']+' (3.9 or later required)','PSF','Run time','Provided by the installation, not by the tool.'],
        ['SQLite',D['sqlite'],'Public domain','Run time','Part of Python.']])
    d.p('**Integrity.** The checksum over the '+str(S['treeFiles'])+' tool files (`ids_siem/`, `static/`, `agent/`, `idssiem.py`, `requirements.txt`) is recorded for each release (chapter 17). It can be recomputed on any installation with `python tools/release_report.py --hash`. The tool runs locally; imported data is not transmitted anywhere except the optional read access to the CycurGUARD backend that the administrator configures.')
    d.h(1,'KNOWN LIMITATIONS')
    d.bullets(['The rules only see imported data. Events with an unsynchronised clock do not take part in time-based rules.','Event catalog defaults are a starting point and not an assessment of the impact on the vehicle.','The statistical rules (vehicle outlier, fleet spike) need at least 5 vehicles resp. 7 days of data and are not suitable for small data sets.','The audit log is hash-chained: it detects edits and deletions inside the log, but someone with write access to the database file could rebuild it, and cutting off the newest entries goes unnoticed unless the latest hash was noted.','The backend token and the authenticator secrets are stored in the database in clear text. Protect the database file (disk encryption, restricted account). Traffic is plain HTTP on the loopback address; the port must not be exposed to a network.','Passkeys work only at `http://localhost:<port>`.','The application has no version number, and `openpyxl` is not pinned to an exact version.','The integration with the CycurGUARD backend is checked manually (TC-M08); the automated tests use no backend.'])
    d.h(1,'USAGE INSTRUCTIONS AND TRAINING')
    d.bullets(['The README of the repository describes installation, pages, rules, roles, sign-in, audit log and security properties; `agent/README.md` the AI agent interface.','New analysts are introduced by the tool owner on the analysis PC and work through a training case (import, alerts, suppression, case, report) before they handle real alerts.'])
    d.h(1,'PERIODIC REVIEW AND RE-EVALUATION')
    d.p('This record is reviewed at least once a year and re-evaluated, including a complete test run, when one of the following happens:')
    d.bullets(['the tool is changed after the last release,','the format of the IDS report or the CycurGUARD interface changes,','the Python version or openpyxl is changed on the analysis PC,','an error in the tool is found that hid or distorted an alert,','the incident-response process or the tool management requirements change.'])
    d.h(1,'EVIDENCE RECORD')
    d.p('Baseline for revision 001 of this record. For a new release, repeat the entries and add a row to the revision history.')
    mres=[manual_result(a) for a,_,_ in MANUAL]; mpass=sum(1 for x in mres if x.startswith('Passed')); mfail=sum(1 for x in mres if x.startswith('FAILED'))
    ex=F['example']['alerts']
    d.table([3200,7007],[['Item','Value'],
        ['Tool version',T['version']],
        ['Source commit (last change of the tool)',T['sourceCommit']+(' (working tree not clean)' if T['dirty'] else '')],
        ['Commit date',T['commitDate']],
        ['Date of validation',R['date']],
        ['Test environment','Python '+R['python']+', '+R['platform']+'; '+str(n)+' test scripts, '+str(ncases)+' test cases'],
        ['Test result',('All '+str(n)+' test scripts passed' if allok else 'FAILED: '+', '.join(t['name'] for t in tests if t['exit']!=0))+' ('+', '.join(t['name'] for t in tests)+')'],
        ['Worked example (chapter 6)','Verified with the detection code: '+('; '.join('%s alert "%s", severity %s, %d events'%(a['rule'],a['title'],a['severity'],a['event_count']) for a in ex) if ex else 'no alert')],
        ['SHA-256 of the tool files ('+str(S['treeFiles'])+' files)',S['tree']],
        ['SHA-256 idssiem.py',S['idssiem.py']],
        ['SHA-256 static/index.html',S['static/index.html']],
        ['Manual test cases TC-M01 to TC-M10 (chapter 10)',str(mpass)+' of '+str(len(MANUAL))+' passed for this version'+(', '+str(mfail)+' failed' if mfail else '')+(' – the open cases are executed and entered by the tool owner at the release (tools/release-report/manual-results.json)' if mpass+mfail<len(MANUAL) else '')]],bold_first=True)
    d.h(2,'Approval')
    d.table([2400,3200,2400,2207],[['Role','Name','Signature','Date'],['Tool owner',cfg['owner'],'',''],['Cybersecurity process owner','','','']])
    d.h(1,'DOCUMENTS & RECORDS')
    d.table([700,9507],[['#','Description'],
        ['1','ISO/SAE 21434:2021, clause 5 (organizational cybersecurity management, tool management), clause 8 (continual cybersecurity activities) and clause 13 (operations and maintenance)'],
        ['2','Fleet IDS SIEM README and agent/README.md'],
        ['3','Source repository https://github.com/rng0xff/idssiem (history, tests, release script)'],
        ['4','Tool Management Record – TARA Tools (same format, for the TARA Workbench)']])
    d.h(1,'REVISION HISTORY')
    d.table([1300,4607,2200,2100],[['Revision','Description of Change','Editor','Date']]+[[h['rev'],h['desc'],h['editor'],h['date']] for h in F['history']])
    d.unassessed=unassessed
    return d
