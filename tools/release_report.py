#!/usr/bin/env python3
"""Release report generator – Tool Management Record for Fleet IDS SIEM (ISO/SAE 21434 tool management)

  python tools/release_report.py [--release] [--out DIR] [--allow-dirty] [--editor NAME] [--hash]
  --release      also record the new revision in tools/release-report/history.json (a row is added when the source version is new)
  --hash         only print the source-tree checksum used in the evidence record (to compare a copy of the tool) and exit
Steps: 1 clean working tree (the evidence must belong to a commit) · 2 run the test scripts (unit tests per module, security test,
MCP test) · 3 recompute the worked example of chapter 6 with the detection code · 4 collect version, commit, dependencies and checksums ·
5 tools/release-report/generate.py writes docx and pdf into docs/.
Exit code: 0 all passed, 1 a test or the worked example failed (release blocked), 2 usage or environment problem.
Requirements: Python 3.9+, git; LibreOffice (soffice) and poppler (pdftotext, pdfinfo) for PDF and table-of-contents page numbers."""
import datetime, hashlib, importlib.metadata as md, json, os, platform, re, shutil, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RR = os.path.join(ROOT, 'tools', 'release-report')
args = sys.argv[1:]
flag = lambda n: n in args
def opt(n, d):
    return args[args.index(n) + 1] if n in args and args.index(n) + 1 < len(args) else d
def die(m, c=2):
    print('ERROR: ' + m, file=sys.stderr); sys.exit(c)
def sh(*a):
    return subprocess.run(['git', *a], cwd=ROOT, capture_output=True, text=True).stdout.strip()
def sha(p):
    return hashlib.sha256(open(p, 'rb').read()).hexdigest()
def read_json(p):
    return json.load(open(p, encoding='utf8'))

APP = ['ids_siem', 'static', 'agent', 'idssiem.py', 'requirements.txt']
def tree_hash():
    files = [f for f in sh('ls-files', '--', *APP).split('\n') if f]
    h = hashlib.sha256()
    for f in sorted(files):
        h.update((f + ':' + sha(os.path.join(ROOT, f)) + '\n').encode())
    return h.hexdigest(), len(files)

if flag('--hash'):
    t, n = tree_hash(); print(t, '(%d files)' % n); sys.exit(0)

# ---- 1. repository state. Docs and the record's own bookkeeping files do not count as source changes.
EXCL = [':!docs', ':!tools/release-report/history.json', ':!tools/release-report/manual-results.json']
if sh('rev-parse', '--is-inside-work-tree') != 'true': die('not a git repository')
dirty = [l for l in sh('status', '--porcelain', '--', '.', *EXCL).split('\n') if l]
if dirty and not flag('--allow-dirty'):
    die('the working tree has uncommitted changes – commit them first (or --allow-dirty for a preview):\n  ' + '\n  '.join(dirty))
src = sh('log', '-1', '--format=%H', '--', '.', *EXCL)          # last commit that changed the tool itself
tag = subprocess.run(['git', 'describe', '--tags', '--exact-match', src], cwd=ROOT, capture_output=True, text=True).stdout.strip()
tool = dict(version=tag or 'build ' + src[:7], commitFull=sh('rev-parse', 'HEAD'), commit=sh('rev-parse', '--short', 'HEAD'),
            sourceCommit=src, sourceCommitShort=src[:7], commitDate=sh('log', '-1', '--format=%cI', src),
            firstDate=sh('log', '--format=%cs').split('\n')[-1], dirty=bool(dirty), tagged=bool(tag))
now = datetime.datetime.now(datetime.timezone.utc)
run = dict(date=now.strftime('%Y-%m-%d'), time=now.strftime('%H:%M'), python=platform.python_version(),
           platform={'Linux': 'Linux', 'Windows': 'Windows', 'Darwin': 'macOS'}.get(platform.system(), platform.system()))

# ---- 2. tests
tests = []
def unit():
    r = subprocess.run([sys.executable, os.path.join(ROOT, 'tests', 'run_tests.py')], cwd=ROOT, capture_output=True, text=True)
    out = r.stdout + r.stderr; per = {}
    for m in re.finditer(r'^(\S+) \((test_\w+)\.(\w+)\.\S+\) \.\.\. (\w+)', out, re.M):
        e = per.setdefault(m.group(2), dict(n=0, bad=0, classes=set())); e['n'] += 1; e['classes'].add(m.group(3)); e['bad'] += m.group(4) != 'ok'
    for mod, e in sorted(per.items()):
        tests.append(dict(name=mod, exit=1 if e['bad'] else 0, lines=e['n'], count=e['n'], ok=[], keys=['%d test cases' % e['n']], info=[], fail=[]))
    if r.returncode and not any(t['exit'] for t in tests):
        tests.append(dict(name='unit', exit=r.returncode, lines=0, count=0, ok=[], keys=[], info=[], fail=out.strip().split('\n')[-3:]))
def integration(name, label):
    r = subprocess.run([sys.executable, os.path.join(ROOT, 'tests', 'run_integration.py'), label], cwd=ROOT, capture_output=True, text=True)
    out = r.stdout.strip().split('\n'); n = re.search(r'(\d+)/(\d+) passed', r.stdout)
    tests.append(dict(name=name, exit=r.returncode, lines=len(out), count=int(n.group(2)) if n else 0, ok=[],
                      keys=[n.group(0)] if n else [], info=[], fail=[l[:100] for l in out if l.startswith('FAIL')]))
unit(); integration('security_test', 'security'); integration('test_mcp', 'mcp')
for t in tests: print(('PASS ' if t['exit'] == 0 else 'FAIL ') + t['name'] + '  (%s)' % ', '.join(t['keys']))
if not tests: die('no tests ran')

# ---- 3. worked example (chapter 6): burst rule on a temporary database
tmp = tempfile.mkdtemp(prefix='idssiem-example-')
os.environ['IDS_SIEM_DB'] = os.path.join(tmp, 't.db'); sys.path.insert(0, ROOT)
from ids_siem import db, ingest, rules
db.init(); T0 = 1_780_000_000_000; VIN = 'SC6GM1CA0TF000001'
ingest.import_rows([dict(event_type='can', event_id=32780, vin=VIN, ecu_name='ECU-A', ts=T0 + m * 60000, name='x') for m in (0, 20, 45, 120)], 'example')
rules.run_all()
a = [dict(r) for r in db.conn().execute("SELECT rule, title, severity, event_count FROM alerts WHERE rule IN ('burst','high_sev','multi_ecu') ORDER BY rule")]
example = dict(alerts=a)
expect = dict(alerts=[dict(rule='burst', title='3× INVALID_SIG within 45 min', severity='high', event_count=3)])
ok_ex = example == expect
print(('PASS ' if ok_ex else 'FAIL ') + 'worked example of chapter 6' + ('' if ok_ex else ' – got ' + json.dumps(example, ensure_ascii=False)))
db.conn().close(); shutil.rmtree(tmp, ignore_errors=True)
if not ok_ex:
    print('The detection code gives other values than the worked example in tools/release-report/content.py (chapter 6).', file=sys.stderr); sys.exit(1)

# ---- 4. dependencies and checksums
def dist(n):
    try: m = md.metadata(n); return m['Version'], m.get('License') or next((c.split('::')[-1].strip() for c in m.get_all('Classifier') or [] if c.startswith('License')), '')
    except md.PackageNotFoundError: return '', ''
ov, ol = dist('openpyxl'); import sqlite3
req = [l.strip() for l in open(os.path.join(ROOT, 'requirements.txt')) if l.strip() and not l.startswith('#')]
th, nfiles = tree_hash()
deps = dict(openpyxl=ov, openpyxlLicense=ol, requirements=req, sqlite=sqlite3.sqlite_version)
files = dict(tree=th, treeFiles=nfiles, **{f: sha(os.path.join(ROOT, f)) for f in ('idssiem.py', 'static/index.html')})

# ---- 5. manual results, history
manual = read_json(os.path.join(RR, 'manual-results.json')); manual.pop('_comment', None)
hfile = os.path.join(RR, 'history.json'); history = read_json(hfile); cfg = read_json(os.path.join(RR, 'config.json'))
last = history[-1] if history else None; pending = None
if not last or last['version'] != tool['version']:
    pending = dict(rev='%03d' % (int(last['rev']) + 1 if last else 1),
                   desc=('Re-validation for %s (commit %s); test report, checksums and evidence updated' % (tool['version'], tool['sourceCommitShort'])) if last else 'Creation of document',
                   editor=opt('--editor', cfg['owner']), date=now.strftime('%d.%m.%Y'), version=tool['version'])
shown = history + ([pending] if pending else [])
if 'XXXX' in cfg['docNumber']: print('NOTE: document number is still a placeholder – set docNumber in tools/release-report/config.json')

# ---- 6. generate
facts = dict(tool=tool, run=run, deps=deps, files=files, tests=tests, example=example, manual=manual, history=shown, revision=shown[-1]['rev'])
OUT = os.path.abspath(opt('--out', os.path.join(ROOT, 'docs'))); os.makedirs(OUT, exist_ok=True)
fp = os.path.join(tempfile.mkdtemp(prefix='release-report-'), 'facts.json'); json.dump(facts, open(fp, 'w', encoding='utf8'), indent=1)
g = subprocess.run([sys.executable, os.path.join(RR, 'generate.py'), fp, os.path.join(RR, 'config.json'), OUT])
if g.returncode: die('generate.py failed (exit %d)' % g.returncode)
keep = cfg['docNumber'] + '-' + cfg['fileTitle']
for f in os.listdir(OUT):
    m = re.match(r'^(CORP-.+?)-(.+)\.(docx|pdf)$', f)
    if m and m.group(2) == cfg['fileTitle'] and m.group(1) + '-' + m.group(2) != keep: os.remove(os.path.join(OUT, f)); print('removed old file ' + f)
if flag('--release'):
    if pending: history.append(pending); open(hfile, 'w', encoding='utf8').write(json.dumps(history, indent=2) + '\n'); print('history.json: revision %s added' % pending['rev'])
    else: print('history.json unchanged (version %s already recorded)' % tool['version'])
else: print('preview only – history.json not changed (use --release to record the revision)')
failed = [t for t in tests if t['exit']]
open_m = [k for k in manual if not (manual[k].get('version') == tool['version'] and manual[k].get('result'))]
print('\nSummary: %s, commit %s%s, %d/%d test scripts passed, %d manual test case(s) open' % (tool['version'], tool['commit'], ' (+changes)' if tool['dirty'] else '', len(tests) - len(failed), len(tests), len(open_m)))
if open_m: print('Next: run the manual test cases, enter the results in tools/release-report/manual-results.json and run again with --release.')
if failed: print('RELEASE BLOCKED: ' + ', '.join(t['name'] for t in failed) + ' failed', file=sys.stderr); sys.exit(1)
