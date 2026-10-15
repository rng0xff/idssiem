/* Case management: dashboard, case list, case detail, create case from alerts.
   Loaded before app.js; it registers ROUTES.cases and uses helpers from app.js at call time. */
'use strict';

const CASE_STATUSES = ['open', 'investigating', 'waiting'];
const OPEN_FILTER = CASE_STATUSES.join(',');

function progressHtml(done, total, big = false) {
  if (!total) return '<span class="muted">no tasks</span>';
  const pct = Math.round(done / total * 100);
  return big
    ? `<span class="progress big" role="img" aria-label="${done} of ${total} tasks done"><span style="width:${pct}%"></span></span>`
    : `<span class="prog"><span class="progress" role="img" aria-label="${done} of ${total} tasks done"><span style="width:${pct}%"></span></span><span class="muted">${done}/${total}</span></span>`;
}
const dueHtml = c => !c.due_date ? '<span class="muted">none</span>' : c.overdue ? `<span style="color:var(--err);font-weight:600" title="Overdue">${esc(c.due_date)}</span>` : esc(c.due_date);
const ageHtml = c => c.age_days < 1 ? 'today' : `${Math.round(c.age_days)} d`;
const caseRef = id => `<a href="#/cases/${id}" data-stop>#${id}</a>`;

function niceScale(max) {
  const raw = Math.max(max, 1) / 4, p = 10 ** Math.floor(Math.log10(Math.max(raw, 1))), m = raw / p;
  const step = Math.max(1, (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p);
  const top = step * Math.ceil(Math.max(max, 1) / step);
  return { step, top, n: Math.round(top / step) };
}

/* ---------------------------------------------------------------- route */
ROUTES.cases = async function (arg, P) {
  if (arg) return viewCase(+arg);
  const tab = P.get('tab') || 'dashboard';
  return tab === 'dashboard' ? viewCasesDashboard(P) : viewCasesList(tab, P);
};

function casesHead(tab, counts) {
  const open = (counts.open || 0) + (counts.investigating || 0) + (counts.waiting || 0), closed = counts.closed || 0;
  const tabs = [['dashboard', 'Dashboard', ''], ['open', 'Open', open], ['all', 'All', open + closed], ['closed', 'Closed', closed]];
  return `<div class="page-head"><h1>Cases</h1><span class="spacer"></span><button class="btn primary" data-cact="new-empty">New case</button></div>
  <div class="tabs">${tabs.map(t => `<button data-ctab="${t[0]}" class="${t[0] === tab ? 'on' : ''}">${t[1]}${t[2] !== '' ? `<span class="ct">${fmtN(t[2])}</span>` : ''}</button>`).join('')}</div>`;
}

/* ---------------------------------------------------------------- dashboard */
async function viewCasesDashboard() {
  const [d, list, cnt] = await Promise.all([
    api('/api/cases/dashboard'),
    api('/api/cases?' + qs({ status: OPEN_FILTER, sort: 'severity', size: 12 })),
    api('/api/cases?size=1')]);
  const bs = d.by_status;
  const pct = d.tasks_total ? Math.round(d.tasks_done / d.tasks_total * 100) : 0;
  const sevOpen = d.alerts_without_case_by_severity;
  view.innerHTML = `${casesHead('dashboard', cnt.status_counts)}
  <div class="figures">
    <a class="fig" href="${hashFor('cases', { tab: 'open' })}"><div class="n">${fmtN(d.open)}</div><div class="l">Open cases</div><div class="s">${bs.open} open, ${bs.investigating} investigating, ${bs.waiting} waiting</div></a>
    <a class="fig" href="${hashFor('cases', { tab: 'open', overdue: 1 })}"><div class="n" style="${d.overdue ? 'color:var(--err)' : ''}">${fmtN(d.overdue)}</div><div class="l">Overdue</div><div class="s">past their due date</div></a>
    <a class="fig" href="${hashFor('cases', { tab: 'open', owner: 'none' })}"><div class="n">${fmtN(d.unassigned)}</div><div class="l">Without an owner</div></a>
    <a class="fig" href="${hashFor('alerts', { case: 'none' })}"><div class="n">${fmtN(d.alerts_without_case)}</div><div class="l">Open alerts without a case</div><div class="s">${SEVS.slice().reverse().filter(s => sevOpen[s]).map(s => `${sevOpen[s]} ${s}`).join(', ') || 'none'}</div></a>
    <a class="fig" href="${hashFor('cases', { tab: 'closed' })}"><div class="n">${fmtN(d.closed_30d)}</div><div class="l">Closed in the last 30 days</div></a>
    <div class="fig"><div class="n">${d.mean_days_to_close === null ? 'none' : d.mean_days_to_close + ' d'}</div><div class="l">Mean time to close</div><div class="s">${d.mean_days_to_close === null ? 'no case closed in the last 90 days' : `median ${d.median_days_to_close} d, ${d.closed_sample} case${d.closed_sample > 1 ? 's' : ''} in the last 90 days`}</div></div>
  </div>
  ${d.total ? `
  <div class="grid2" style="grid-template-columns:repeat(auto-fit,minmax(min(420px,100%),1fr))">
    <div class="panel"><h2>Where the cases stand</h2>
      <div class="pipeline" role="img" aria-label="Cases by status">${STATUS_ORDER.map(s => bs[s] ? `<div class="p-${s}" style="flex:${bs[s]}" title="${caseStatusLabel(s)}: ${bs[s]}">${bs[s]}</div>` : '').join('')}</div>
      <div class="statuslegend">${STATUS_ORDER.map(s => `<span><i class="p-${s}" style="background:${STATUS_COLOR[s]}"></i>${caseStatusLabel(s)} ${bs[s]}</span>`).join('')}</div>
      <h3>Checklist progress, open cases</h3>
      ${d.tasks_total ? `${progressHtml(d.tasks_done, d.tasks_total, true)}<p class="muted" style="margin:6px 0 0">${d.tasks_done} of ${d.tasks_total} tasks done (${pct}%)</p>` : '<p class="muted">No tasks on open cases.</p>'}
      <h3>Age of open cases</h3>${barsHtml(d.ages)}
    </div>
    <div class="panel"><h2>Opened and closed per week</h2><div id="wk"></div></div>
  </div>
  <div class="grid2">
    <div class="panel"><h2>Open cases by severity</h2>${barsHtml(d.severity.filter(x => x.n))}</div>
    <div class="panel"><h2>Open cases by owner</h2>${d.owners.length ? `<div class="bars">${d.owners.map(o => `<a class="bar" href="${hashFor('cases', { tab: 'open', owner: o.key || 'none' })}"><span class="lab">${esc(o.label)}</span><span class="track"><span class="fill" style="display:block;width:${(o.n / d.owners[0].n * 100).toFixed(1)}%"></span></span><span class="val">${o.n}${o.overdue ? ` <span style="color:var(--err)" title="overdue">(${o.overdue} late)</span>` : ''}</span></a>`).join('')}</div>` : '<div class="empty">No open cases</div>'}</div>
    <div class="panel"><h2>How closed cases ended</h2>${d.resolutions.some(r => r.n) ? barsHtml(d.resolutions.filter(r => r.n)) : '<div class="empty">No closed cases yet</div>'}</div>
  </div>
  <h2 style="margin:18px 0 8px">Open cases, highest severity first</h2>
  ${list.cases.length ? casesTable(list.cases, {}) : '<div class="panel"><div class="empty"><b>No open cases</b></div></div>'}
  ${list.total > list.cases.length ? `<p style="margin:8px 0 0"><a href="${hashFor('cases', { tab: 'open' })}">All ${list.total} open cases</a></p>` : ''}`
    : `<div class="panel" style="margin-top:14px"><div class="empty"><b>No cases yet</b>Open an alert and choose Create case, or select several alerts in the list and create one case for all of them.<p><a class="btn primary" href="#/alerts">Go to alerts</a></p></div></div>`}`;
  if (d.total) renderWeekly($('#wk'), d.weekly);
  bindCasesCommon();
}
const STATUS_ORDER = ['open', 'investigating', 'waiting', 'closed'];
const STATUS_COLOR = { open: 'var(--accent)', investigating: 'var(--sev-medium)', waiting: 'var(--cat5)', closed: 'var(--ok)' };

function renderWeekly(el, weekly) {
  const W = 700, H = 230, L = 40, R = 10, T = 12, B = 30;
  const max = Math.max(...weekly.map(w => Math.max(w.opened, w.closed, w.backlog)), 1);
  const sc = niceScale(max);
  const y = v => T + (1 - v / sc.top) * (H - T - B);
  const slot = (W - L - R) / weekly.length, bw = Math.max(3, slot / 2 - 3);
  let g = '', bars = '', xl = '', pts = [];
  for (let i = 0; i <= sc.n; i++) g += `<g class="grid"><line x1="${L}" x2="${W - R}" y1="${y(sc.step * i)}" y2="${y(sc.step * i)}"/></g><text x="${L - 6}" y="${y(sc.step * i) + 4}" text-anchor="end">${sc.step * i}</text>`;
  weekly.forEach((w, i) => {
    const x0 = L + i * slot + slot / 2;
    const tip = `Week from ${fmtDay(w.start)}: ${w.opened} opened, ${w.closed} closed, ${w.backlog} open at the end`;
    bars += `<g><title>${esc(tip)}</title><rect class="wk-open" x="${x0 - bw - 1}" y="${y(w.opened)}" width="${bw}" height="${Math.max(0, y(0) - y(w.opened))}"/><rect class="wk-closed" x="${x0 + 1}" y="${y(w.closed)}" width="${bw}" height="${Math.max(0, y(0) - y(w.closed))}"/></g>`;
    pts.push(`${x0},${y(w.backlog)}`);
    if (i % 2 === (weekly.length - 1) % 2) xl += `<text x="${x0}" y="${H - 10}" text-anchor="middle">${fmtDay(w.start).slice(5)}</text>`;
  });
  el.innerHTML = `<div class="chart"><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Cases opened and closed per week">${g}${bars}<polyline class="wk-line" points="${pts.join(' ')}"/>${pts.map(p => `<circle class="wk-dot" cx="${p.split(',')[0]}" cy="${p.split(',')[1]}" r="3"/>`).join('')}<g class="axis"><line x1="${L}" x2="${W - R}" y1="${y(0)}" y2="${y(0)}"/></g>${xl}</svg></div>
    <div class="legend"><span><i style="background:var(--accent)"></i>opened</span><span><i style="background:var(--ok)"></i>closed</span><span><i style="background:var(--ink);border-radius:50%"></i>open at the end of the week</span><span class="muted">last ${weekly.length} weeks, week start (UTC)</span></div>`;
}

/* ---------------------------------------------------------------- list */
function casesTable(cases, { sort, dir } = {}) {
  const sh = (label, key, cls = '') => sort ? sortHeader(label, key, sort, dir, cls) : `<th class="${cls}">${label}</th>`;
  return `<div class="tablewrap"><table><thead><tr>${sh('Case', 'id')}<th>Title</th>${sh('Severity', 'severity')}${sh('Status', 'status')}${sh('Owner', 'owner')}<th class="num">Alerts</th><th>Checklist</th>${sh('Age', 'created', 'num')}${sh('Due', 'due')}${sh('Updated', 'updated')}</tr></thead><tbody>
    ${cases.map(c => `<tr class="row" data-cid="${c.id}"><td class="nowrap">${caseRef(c.id)}</td><td><a class="rowlink" href="${hashFor('cases', {}, c.id)}">${esc(c.title)}</a></td><td>${sevHtml(c.severity)}</td><td>${caseStatusHtml(c.status)}</td><td>${esc(c.owner) || '<span class="muted">none</span>'}</td><td class="num">${c.alerts}</td><td>${progressHtml(c.tasks_done, c.tasks_total)}</td><td class="num nowrap">${ageHtml(c)}</td><td class="nowrap">${dueHtml(c)}</td><td class="nowrap">${fmtDay(c.updated_at)}</td></tr>`).join('')}
  </tbody></table></div>`;
}

async function viewCasesList(tab, P) {
  const raw = paramsObj(P);
  const sort = raw.sort || 'severity', dir = raw.dir || 'desc', page = Math.max(1, +raw.page || 1);
  const status = tab === 'open' ? OPEN_FILTER : tab === 'closed' ? 'closed' : '';
  const res = await api('/api/cases?' + qs({ status, severity: raw.severity, owner: raw.owner, overdue: raw.overdue, q: raw.q, sort, dir, page, size: 50 }));
  view.innerHTML = `${casesHead(tab, res.status_counts)}
  <div class="filters"><input type="search" id="cq" value="${esc(raw.q || '')}" placeholder="Search title, or #number" aria-label="Search cases">
    <select id="csev" aria-label="Severity"><option value="">Any severity</option>${SEVS.slice().reverse().map(s => `<option ${raw.severity === s ? 'selected' : ''}>${s}</option>`).join('')}</select>
    <select id="cowner" aria-label="Owner"><option value="">Any owner</option><option value="none" ${raw.owner === 'none' ? 'selected' : ''}>No owner</option>${res.owners.map(o => `<option ${raw.owner === o ? 'selected' : ''}>${esc(o)}</option>`).join('')}</select>
    <label style="display:inline-flex;gap:6px;align-items:center"><input type="checkbox" id="cover" ${raw.overdue ? 'checked' : ''}> Overdue only</label></div>
  ${res.cases.length ? `${casesTable(res.cases, { sort, dir })}${pagerHtml(res.total, res.page, res.size)}` : '<div class="panel"><div class="empty"><b>No cases here</b>Change the tab or filters, or create a case from an alert.</div></div>'}`;
  const nav = patch => { const n = { tab, q: raw.q, severity: raw.severity, owner: raw.owner, overdue: raw.overdue, sort, dir, ...patch }; Object.keys(n).forEach(k => !n[k] && delete n[k]); go('cases', n); };
  $('#cq').addEventListener('change', e => nav({ q: e.target.value.trim(), page: undefined }));
  $('#csev').addEventListener('change', e => nav({ severity: e.target.value, page: undefined }));
  $('#cowner').addEventListener('change', e => nav({ owner: e.target.value, page: undefined }));
  $('#cover').addEventListener('change', e => nav({ overdue: e.target.checked ? '1' : '', page: undefined }));
  bindCasesCommon((e) => {
    const pg = e.target.closest('[data-page]'); if (pg && !pg.disabled) { nav({ page: pg.dataset.page }); return true; }
    const so = e.target.closest('[data-sort]'); if (so) { const k = so.dataset.sort; nav({ sort: k, dir: sort === k && dir === 'desc' ? 'asc' : 'desc', page: undefined }); return true; }
  });
}

function bindCasesCommon(extra) {
  view.onclick = e => {
    if (extra && extra(e)) return;
    const t = e.target.closest('[data-ctab]'); if (t) { go('cases', t.dataset.ctab === 'dashboard' ? {} : { tab: t.dataset.ctab }); return; }
    if (e.target.closest('[data-cact="new-empty"]')) { openCaseForm([]); return; }
    const row = e.target.closest('tr.row[data-cid]'); if (row) location.hash = hashFor('cases', {}, row.dataset.cid);
  };
}

/* ---------------------------------------------------------------- case detail */
const timelineHtml = c => c.log.map(l => `<li class="${esc(l.kind)}"><div class="meta">${esc(l.author)}, ${esc(fmtMin(l.created_at))} UTC</div><div class="txt" style="white-space:pre-wrap">${esc(l.body)}</div></li>`).join('');
async function viewCase(id, keepScroll = false) {
  const c = await api('/api/cases/' + id);
  const sc = keepScroll ? $('#main').scrollTop : 0;
  const closed = c.status === 'closed';
  view.innerHTML = `<div class="page-head"><a href="#/cases">Cases</a><h1>Case #${c.id}</h1>${caseStatusHtml(c.status)} ${sevHtml(c.severity)}<span class="spacer"></span>
    <a class="btn" href="/api/cases/${c.id}/report" target="_blank" rel="noopener">Export report</a>
    ${closed ? '<button class="btn" data-cact="reopen">Reopen case</button>' : '<button class="btn primary" data-cact="close">Close case</button>'}
    <button class="btn ghost danger" data-cact="delete">Delete</button></div>
  ${closed ? `<div class="closedbox"><h3>Closed: ${esc(c.resolution_label)}</h3><div class="muted">${esc(fmtMin(c.closed_at))} UTC, after ${c.age_days} days</div>${c.findings ? `<p style="margin:8px 0 0;white-space:pre-wrap">${esc(c.findings)}</p>` : ''}</div>` : ''}
  <div class="caselayout">
    <div>
      <div class="panel"><label class="field"><span>Title</span><input type="text" class="big-title" data-f="title" value="${esc(c.title)}"></label>
        <label class="field" style="margin:0"><span>Summary, what happened and what is known</span><textarea data-f="summary" rows="4" placeholder="Describe the situation, the suspected cause and what you have ruled out">${esc(c.summary)}</textarea></label></div>
      <div class="panel"><h2 style="margin-bottom:6px">Checklist</h2>${progressHtml(c.tasks_done, c.tasks_total, true)}
        <p class="muted" style="margin:6px 0 0">${c.tasks_done} of ${c.tasks_total} done</p>
        <ul class="tasklist">${c.tasks.map(t => `<li class="${t.done ? 'done' : ''}"><input type="checkbox" data-task="${t.id}" ${t.done ? 'checked' : ''} aria-label="${esc(t.title)}"><span class="tt">${esc(t.title)}</span>${t.done ? `<span class="who">${esc(t.done_by)}, ${esc(fmtDay(t.done_at))}</span>` : ''}<button class="btn ghost small" data-deltask="${t.id}" title="Remove task" aria-label="Remove task">×</button><textarea class="taskres" data-tres="${t.id}" rows="${t.result ? Math.min(6, Math.max(2, t.result.split('\n').length)) : 1}" maxlength="2000" spellcheck="false" placeholder="Result: what did you find or decide?" aria-label="Result of: ${esc(t.title)}">${esc(t.result || '')}</textarea></li>`).join('') || '<li class="muted">No tasks yet.</li>'}</ul>
        <div class="addrow"><input type="text" id="newtask" placeholder="Add a task" aria-label="New task"><button class="btn" data-cact="addtask">Add task</button></div></div>
      <div class="panel"><div class="page-head" style="margin-bottom:8px"><h2 style="margin:0">Linked alerts</h2><span class="sub">${c.alerts.length} alert${c.alerts.length === 1 ? '' : 's'}, ${c.open_alerts} still open</span><span class="spacer"></span>${closed ? '' : '<button class="btn small" data-cact="addalerts">Add alerts</button>'}</div>
        ${c.alerts.length ? `<div class="tablewrap"><table><thead><tr><th>Severity</th><th>Alert</th><th>Vehicle</th><th class="num">Events</th><th>Status</th><th></th></tr></thead><tbody>${c.alerts.map(a => `<tr class="row" data-goto="${hashFor('alerts', {}, a.id)}"><td>${sevHtml(a.severity)}</td><td><a class="rowlink" href="${hashFor('alerts', {}, a.id)}">${esc(a.title)}</a></td><td class="mono">${a.vin ? `<a href="${hashFor('vehicle', {}, a.vin)}" data-stop>${esc(a.vin)}</a>` : '<span class="muted">fleet</span>'}</td><td class="num">${fmtN(a.event_count)}</td><td>${statusHtml(a.status)}</td><td><button class="btn ghost small" data-unlink="${a.id}" title="Remove from case" aria-label="Remove alert from case">×</button></td></tr>`).join('')}</tbody></table></div>` : '<div class="empty">No alerts linked.</div>'}</div>
      <div class="panel"><h2>Activity</h2><textarea id="newcomment" rows="3" placeholder="Add a note: what you checked, what you found, who you talked to"></textarea>
        <p style="margin:6px 0 0"><button class="btn small" data-cact="addcomment">Add note</button></p>
        <ul class="timeline">${timelineHtml(c)}</ul></div>
    </div>
    <div>
      <div class="panel"><h2>Details</h2>
        <label class="field"><span>Status</span><select data-f="status" ${closed ? 'disabled' : ''}>${closed ? '<option>Closed</option>' : CASE_STATUSES.map(s => `<option value="${s}" ${s === c.status ? 'selected' : ''}>${caseStatusLabel(s)}</option>`).join('')}</select></label>
        <label class="field"><span>Severity</span><select data-f="severity">${SEVS.slice().reverse().map(s => `<option ${s === c.severity ? 'selected' : ''}>${s}</option>`).join('')}</select></label>
        <label class="field"><span>Owner</span><input type="text" data-f="owner" list="userlist" value="${esc(c.owner)}" placeholder="Who works on it"></label>
        <label class="field"><span>Due date${c.overdue ? ' <b style="color:var(--err)">(overdue)</b>' : ''}</span><input type="date" data-f="due_date" value="${esc(c.due_date)}"></label>
        <dl class="kv" style="grid-template-columns:80px minmax(0,1fr)"><dt>Opened</dt><dd>${esc(fmtMin(c.created_at))} UTC by ${esc(c.created_by)}</dd><dt>Age</dt><dd>${c.age_days} days</dd><dt>Updated</dt><dd>${esc(fmtMin(c.updated_at))} UTC</dd></dl></div>
      <div class="panel"><h2>Vehicles involved</h2>${c.vehicles.length ? `<div class="bars" style="gap:2px">${c.vehicles.map(v => `<a class="bar" style="grid-template-columns:minmax(0,1fr) auto" href="${hashFor('vehicle', {}, v.vin)}"><span class="mono">${esc(v.vin)}</span><span class="val">${v.alerts} alert${v.alerts > 1 ? 's' : ''}</span></a>`).join('')}</div>` : '<p class="muted" style="margin:0">None, the alerts are fleet-wide.</p>'}</div>
    </div></div>`;
  if (sc) $('#main').scrollTop = sc;

  const reload = () => viewCase(id, true);
  // text fields are saved in place so typing is not interrupted; status and severity redraw the page header
  const inPlace = ['title', 'summary', 'owner', 'due_date'];
  const patch = async body => {
    try {
      const nc = await api('/api/cases/' + id, { method: 'PATCH', json: body });
      if (inPlace.includes(Object.keys(body)[0])) { $('.timeline').innerHTML = timelineHtml(nc); toast('Saved'); }
      else await reload();
      refreshChrome();
    } catch (e) { toast(e.message, true); reload(); }
  };
  const grow = t => { t.style.height = 'auto'; t.style.height = (t.scrollHeight + 2) + 'px'; };
  view.querySelectorAll('textarea.taskres').forEach(grow);
  view.oninput = e => { if (e.target.classList && e.target.classList.contains('taskres')) grow(e.target); };
  view.onchange = e => {
    const f = e.target.dataset.f; if (f) { patch({ [f]: e.target.value }); return; }
    const tr = e.target.dataset.tres;
    if (tr) { api(`/api/cases/${id}/tasks/${tr}`, { method: 'PATCH', json: { result: e.target.value } }).then(nc => { $('.timeline').innerHTML = timelineHtml(nc); toast('Result saved'); }).catch(err => { toast(err.message, true); reload(); }); return; }
    const t = e.target.dataset.task; if (t) { api(`/api/cases/${id}/tasks/${t}`, { method: 'PATCH', json: { done: e.target.checked } }).then(reload).catch(err => toast(err.message, true)); }
  };
  view.onclick = async e => {
    const goto = e.target.closest('[data-goto]'); const ul = e.target.closest('[data-unlink]'); const dt = e.target.closest('[data-deltask]');
    if (ul) { try { await api(`/api/cases/${id}/alerts/${ul.dataset.unlink}`, { method: 'DELETE' }); toast('Alert removed from the case'); await reload(); } catch (err) { toast(err.message, true); } return; }
    if (dt) { try { await api(`/api/cases/${id}/tasks/${dt.dataset.deltask}`, { method: 'DELETE' }); await reload(); } catch (err) { toast(err.message, true); } return; }
    const act = (e.target.closest('[data-cact]') || {}).dataset;
    if (act) {
      const a = act.cact;
      try {
        if (a === 'addtask') { const v = $('#newtask').value.trim(); if (!v) return; await api(`/api/cases/${id}/tasks`, { method: 'POST', json: { title: v } }); await reload(); }
        else if (a === 'addcomment') { const v = $('#newcomment').value.trim(); if (!v) return; await api(`/api/cases/${id}/comments`, { method: 'POST', json: { comment: v } }); await reload(); }
        else if (a === 'close') openCloseCase(c, reload);
        else if (a === 'reopen') { await api(`/api/cases/${id}/reopen`, { method: 'POST' }); toast('Case reopened'); await reload(); refreshChrome(); }
        else if (a === 'delete') { if (confirm(`Delete case #${id}? Its alerts stay and become free again. This cannot be undone.`)) { await api('/api/cases/' + id, { method: 'DELETE' }); toast('Case deleted'); refreshChrome(); location.hash = '#/cases'; } }
        else if (a === 'addalerts') openAddAlerts(id, reload);
      } catch (err) { toast(err.message, true); }
      return;
    }
    if (goto && !e.target.closest('button')) location.hash = goto.dataset.goto;
  };
  view.onkeydown = e => { if (e.key === 'Enter' && e.target.id === 'newtask') { e.preventDefault(); const b = $('[data-cact="addtask"]'); if (b) b.click(); } };
}

/* ---------------------------------------------------------------- drawers */
function openCloseCase(c, done) {
  const notDone = c.tasks_total - c.tasks_done;
  openDrawer(`Close case #${c.id}`, `
    ${notDone ? `<p class="note">${notDone} checklist task${notDone > 1 ? 's are' : ' is'} not done yet.</p>` : ''}
    <h3>How did it end?</h3>
    <div class="radios">${Object.entries(c.resolutions).map(([k, v], i) => `<label><input type="radio" name="res" value="${k}" ${i === 0 ? 'checked' : ''}> ${esc(v)}</label>`).join('')}</div>
    <label class="field" style="margin-top:10px"><span>Findings and decision</span><textarea id="findings" rows="5" placeholder="Root cause, affected vehicles, what was decided, follow-up actions">${esc(c.findings || '')}</textarea></label>
    ${c.open_alerts ? `<label style="display:flex;gap:8px;align-items:center;margin-bottom:12px"><input type="checkbox" id="resalerts" checked> Also resolve the ${c.open_alerts} open alert${c.open_alerts > 1 ? 's' : ''} of this case</label>` : ''}
    <p style="margin:0"><button class="btn primary" id="doclose">Close case</button> <button class="btn" data-act="close-drawer">Cancel</button></p>`);
  $('#doclose').addEventListener('click', async () => {
    try {
      await api(`/api/cases/${c.id}/close`, { method: 'POST', json: { resolution: $('input[name=res]:checked').value, findings: $('#findings').value, resolve_alerts: $('#resalerts') ? $('#resalerts').checked : false } });
      closeDrawer(); toast(`Case #${c.id} closed`); await done(); refreshChrome();
    } catch (e) { toast(e.message, true); }
  });
}

async function openAddAlerts(caseId, done) {
  const res = await api('/api/alerts?' + qs({ case: 'none', status: 'new,in_progress', sort: 'severity', size: 100 }));
  openDrawer('Add alerts to the case', res.alerts.length ? `
    <p class="muted" style="margin-top:0">Open alerts that are not in a case yet.</p>
    <div class="tablewrap"><table><tbody>${res.alerts.map(a => `<tr><td><input type="checkbox" class="pick" value="${a.id}" aria-label="Select alert ${a.id}"></td><td>${sevHtml(a.severity)}</td><td>${esc(a.title)}<div class="muted mono">${esc(a.vin || 'fleet')}</div></td></tr>`).join('')}</tbody></table></div>
    <p style="margin:12px 0 0"><button class="btn primary" id="doadd">Add selected</button></p>` : '<p class="muted">Every open alert is already in a case.</p>');
  const b = $('#doadd');
  if (b) b.addEventListener('click', async () => {
    const ids = $$('.pick:checked').map(x => +x.value); if (!ids.length) return;
    try { await api(`/api/cases/${caseId}/alerts`, { method: 'POST', json: { alert_ids: ids } }); closeDrawer(); toast(`${ids.length} alert(s) added`); await done(); } catch (e) { toast(e.message, true); }
  });
}

/* create a case from alerts (also used for an empty case) */
async function openCaseForm(alertIds) {
  const [alerts, st] = await Promise.all([Promise.all(alertIds.map(i => api('/api/alerts/' + i))), api('/api/settings')]);
  const bad = alerts.filter(a => a.case);
  if (bad.length) { toast(`Alert #${bad[0].id} is already in case #${bad[0].case.id}`, true); return; }
  const top = alerts.reduce((m, a) => SEVS.indexOf(a.severity) > SEVS.indexOf(m) ? a.severity : m, 'medium');
  const title = !alerts.length ? '' : alerts.length === 1 ? alerts[0].title + (alerts[0].vin ? ` (${alerts[0].vin})` : '') : `${alerts.length} alerts: ${alerts[0].title}${alerts[0].vin ? ` (${alerts[0].vin})` : ''} and others`;
  openDrawer(alerts.length ? 'Create case from alert' + (alerts.length > 1 ? 's' : '') : 'New case', `
    ${alerts.length ? `<div class="tablewrap" style="margin-bottom:12px"><table><tbody>${alerts.map(a => `<tr><td>${sevHtml(a.severity)}</td><td>${esc(a.title)}<div class="muted mono">${esc(a.vin || 'fleet')}</div></td></tr>`).join('')}</tbody></table></div>` : ''}
    <label class="field"><span>Title</span><input type="text" id="cf-title" value="${esc(title)}" placeholder="Short description of the case"></label>
    <label class="field"><span>Severity</span><select id="cf-sev">${SEVS.slice().reverse().map(s => `<option ${s === top ? 'selected' : ''}>${s}</option>`).join('')}</select></label>
    <label class="field"><span>Owner</span><input type="text" id="cf-owner" list="userlist" value="${esc(ME.username)}"></label>
    <label class="field"><span>Due date</span><input type="date" id="cf-due"></label>
    <label class="field"><span>Summary</span><textarea id="cf-sum" rows="4" placeholder="What do you know so far?"></textarea></label>
    <p class="muted">The case starts with the standard checklist (${(st.case_tasks || []).length} tasks). Change it on the Data page.</p>
    <p style="margin:0"><button class="btn primary" id="cf-go">Create case</button> <button class="btn" data-act="close-drawer">Cancel</button></p>`);
  $('#cf-go').addEventListener('click', async () => {
    try {
      const c = await api('/api/cases', { method: 'POST', json: { alert_ids: alertIds, title: $('#cf-title').value, severity: $('#cf-sev').value, owner: $('#cf-owner').value, due_date: $('#cf-due').value, summary: $('#cf-sum').value } });
      closeDrawer(); toast(`Case #${c.id} created`); refreshChrome(); location.hash = hashFor('cases', {}, c.id);
    } catch (e) { toast(e.message, true); }
  });
}

/* add one alert to an existing open case */
async function openLinkCase(alertId) {
  const cs = await api('/api/cases/picker');
  openDrawer('Add alert to a case', cs.length ? `
    <label class="field"><span>Case</span><select id="lk-case">${cs.map(c => `<option value="${c.id}">#${c.id} ${esc(c.title)} (${esc(caseStatusLabel(c.status))})</option>`).join('')}</select></label>
    <p style="margin:0"><button class="btn primary" id="lk-go">Add to case</button> <button class="btn" data-act="close-drawer">Cancel</button></p>` : '<p class="muted">There is no open case yet. Create one instead.</p>');
  const b = $('#lk-go');
  if (b) b.addEventListener('click', async () => {
    const id = +$('#lk-case').value;
    try { await api(`/api/cases/${id}/alerts`, { method: 'POST', json: { alert_ids: [alertId] } }); closeDrawer(); toast(`Alert added to case #${id}`); refreshChrome(); location.hash = hashFor('cases', {}, id); } catch (e) { toast(e.message, true); }
  });
}
