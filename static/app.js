/* Views and routing. */
'use strict';

// Passkeys only work with a host name, so an address typed as 127.0.0.1 is moved to localhost (same computer, same port)
if (location.hostname === '127.0.0.1') location.replace('http://localhost' + (location.port ? ':' + location.port : '') + location.pathname + location.search + location.hash);

const view = $('#view');
const FILTER_KEYS = ['ecu', 'type', 'severity', 'category', 'vin_prefix', 'cat', 'vin', 'import_id', 'from', 'to', 'ts', 'alert', 'case'];
const LIST_KEYS = new Set(['ecu', 'type', 'severity', 'category', 'vin_prefix', 'cat']);
const FACET_TITLES = { severity: 'Severity', ecu: 'ECU', type: 'Report type', category: 'Category', cat: 'Event', vin_prefix: 'VIN prefix (first 6)' };

/* ---------------------------------------------------------------- routing */
function parseHash() {
  const h = location.hash.replace(/^#\/?/, '');
  const [path, query = ''] = h.split('?');
  const parts = path.split('/');
  return { name: parts[0] || 'overview', arg: parts[1] ? decodeURIComponent(parts[1]) : null, params: new URLSearchParams(query) };
}
function hashFor(name, obj = {}, arg) {
  const q = qs(obj);
  return `#/${name}${arg ? '/' + encodeURIComponent(arg) : ''}${q ? '?' + q : ''}`;
}
function go(name, obj, arg) { const h = hashFor(name, obj, arg); if (location.hash === h) render(); else location.hash = h; }
const paramsObj = P => Object.fromEntries(P.entries());

// Renders run one at a time and the newest request wins, so a slow view cannot overwrite a newer one
let rendering = false, renderAgain = false;
async function render() {
  if (!ME) return;
  if (rendering) { renderAgain = true; return; }
  rendering = true;
  try { do { renderAgain = false; await renderOnce(); } while (renderAgain && ME); } finally { rendering = false; }
}
async function renderOnce() {
  closeDrawer();
  clearTimeout(window.__syncTimer);
  view.onclick = view.oninput = view.onchange = view.onkeydown = null;
  window.__reloadAlerts = null;
  const { name, arg, params } = parseHash();
  if (ME.mfa_setup && name !== 'account') { location.hash = '#/account'; return; }
  $$('#nav a').forEach(a => a.classList.toggle('on', a.dataset.r === (name === 'vehicle' ? 'vehicles' : name)));
  const fn = ROUTES[name] || ROUTES.overview;
  view.innerHTML = '<div class="empty">Loading…</div>';
  try { await fn(arg, params); }
  catch (e) { view.innerHTML = `<div class="panel"><h2>Something went wrong</h2><p>${esc(e.message)}</p><p class="muted">Check the terminal running the server for details.</p></div>`; }
  if (ME.level < 2 && !$('.rolenote', view)) view.insertAdjacentHTML('afterbegin', '<p class="note rolenote">You have read-only access. Ask an administrator for the analyst role to triage alerts and work cases.</p>');
  refreshChrome();
}
window.addEventListener('hashchange', () => { if (ME) render(); });

async function refreshChrome() {
  try {
    const s = await api('/api/summary');
    const b = $('#alert-badge');
    b.hidden = !s.open_alerts_total; b.textContent = fmtN(s.open_alerts_total);
    const cb = $('#case-badge'); cb.hidden = !s.open_cases; cb.textContent = fmtN(s.open_cases);
    $('#doc').innerHTML = s.total ? `<b>${fmtN(s.total)}</b> events from <b>${fmtN(s.vins)}</b> vehicles${s.first_ts ? `, ${fmtDay(s.first_ts)} to ${fmtDay(s.last_ts)}` : ''}, times in UTC` : 'No data loaded';
  } catch (_) { /* ignore */ }
}

/* ---------------------------------------------------------------- shared bits */
function coverHtml(e) {
  const al = e.alerts || [];
  if (!al.length) return '<span class="muted">none</span>';
  const cases = [...new Set(al.map(a => a.case_id).filter(Boolean))];
  const shown = al.slice(0, 2).map(a => `<a href="#/alerts/${a.id}" data-stop title="${esc(a.title)} (${esc(a.status)})">#${a.id}</a>`).join(' ');
  return `${shown}${al.length > 2 ? ` <span class="muted">+${al.length - 2}</span>` : ''}${cases.length ? ` <span class="muted">in</span> ${cases.slice(0, 2).map(c => `<a href="#/cases/${c}" data-stop>case #${c}</a>`).join(' ')}${cases.length > 2 ? ` <span class="muted">+${cases.length - 2}</span>` : ''}` : ''}`;
}

function eventRowsHtml(events) {
  return events.map(e => `<tr class="row" data-id="${e.id}">
    <td class="nowrap mono">${fmtTs(e.ts, e.ts_ok)}</td>
    <td>${sevHtml(e.severity)}</td>
    <td title="${esc(e.name)}">${esc(e.short_name)}</td>
    <td>${esc(e.ecu_name) || '<span class="muted">none</span>'}</td>
    <td class="mono"><a href="${hashFor('vehicle', {}, e.vin)}" data-stop>${esc(e.vin)}</a></td>
    <td class="muted">${esc(e.event_type)}</td>
    <td class="nowrap">${coverHtml(e)}</td>
    <td class="desc" title="${esc(e.description)}">${esc(e.description)}</td></tr>`).join('');
}
function pagerHtml(total, page, size) {
  const pages = Math.max(1, Math.ceil(total / size));
  const from = total ? (page - 1) * size + 1 : 0, to = Math.min(total, page * size);
  return `<div class="pager"><span>${fmtN(from)} to ${fmtN(to)} of ${fmtN(total)}</span><span class="spacer"></span>
    <button class="btn small" data-page="${page - 1}" ${page <= 1 ? 'disabled' : ''}>Previous</button>
    <span>Page ${fmtN(page)} of ${fmtN(pages)}</span>
    <button class="btn small" data-page="${page + 1}" ${page >= pages ? 'disabled' : ''}>Next</button></div>`;
}
function sortHeader(label, key, cur, dir, cls = '') {
  return `<th class="sortable ${cls}" data-sort="${key}">${label}${cur === key ? ` <span class="dir">${dir === 'asc' ? '▲' : '▼'}</span>` : ''}</th>`;
}
// stop row-click when a link inside a clickable row is used
document.addEventListener('click', e => {
  if (e.target.closest('[data-stop]')) e.stopPropagation();
  const l = e.target.closest('a.rowlink');
  if (l) { if (e.ctrlKey || e.metaKey || e.shiftKey || e.altKey || e.button === 1) e.stopPropagation(); else e.preventDefault(); }
}, true);
document.addEventListener('auxclick', e => { if (e.target.closest('a.rowlink')) e.stopPropagation(); }, true);

/* ---------------------------------------------------------------- overview */
ROUTES.overview = async function () {
  const [sum, top_ev, top_vin, top_ecu, al] = await Promise.all([
    api('/api/summary'), api('/api/top?by=event&limit=10'), api('/api/top?by=vin&limit=10'), api('/api/top?by=ecu&limit=10'),
    api('/api/alerts?status=new,in_progress&size=8&sort=severity')]);
  if (!sum.total) {
    view.innerHTML = `<div class="page-head"><h1>Overview</h1></div><div class="panel"><div class="empty"><b>No events yet</b>Import an export from the backend to get started.<p><a class="btn primary" href="#/data">Import data</a></p></div></div>`;
    return;
  }
  const oa = sum.open_alerts;
  view.innerHTML = `<div class="page-head"><h1>Overview</h1></div>
  <div class="figures">
    <a class="fig" href="#/events"><div class="n">${fmtN(sum.total)}</div><div class="l">Events</div><div class="s">${fmtN(sum.types)} event types, ${fmtN(sum.ecus)} ECUs</div></a>
    <a class="fig" href="#/vehicles"><div class="n">${fmtN(sum.vins)}</div><div class="l">Vehicles</div></a>
    <a class="fig" href="#/alerts"><div class="n">${fmtN(sum.open_alerts_total)}</div><div class="l">Open alerts</div><div class="s">${SEVS.slice().reverse().filter(s => oa[s]).map(s => `${oa[s]} ${s}`).join(', ') || 'none'}</div></a>
    <a class="fig" href="#/cases"><div class="n">${fmtN(sum.open_cases)}</div><div class="l">Open cases</div></a>
    <a class="fig" href="${hashFor('events', { severity: 'high,critical' })}"><div class="n">${fmtN(sum.high)}</div><div class="l">High or critical events</div></a>
    <a class="fig" href="${hashFor('events', { ts: 'invalid' })}"><div class="n">${fmtN(sum.no_ts)}</div><div class="l">Without usable time</div><div class="s">${(sum.no_ts / sum.total * 100).toFixed(1)}% of events</div></a>
    ${sum.unclassified_types ? `<a class="fig" href="#/catalog"><div class="n">${fmtN(sum.unclassified_types)}</div><div class="l">Unclassified event types</div></a>` : ''}
  </div>
  <div class="panel" style="margin-top:16px">
    <div class="page-head" style="margin-bottom:8px"><h2 style="margin:0">Events over time</h2><span class="spacer"></span>
      <span class="muted">Colour by</span>
      <div class="seg" id="grp">${['severity', 'ecu', 'type', 'category'].map(g => `<button data-g="${g}" class="${g === 'severity' ? 'on' : ''}">${g === 'ecu' ? 'ECU' : g[0].toUpperCase() + g.slice(1)}</button>`).join('')}</div></div>
    <div id="tl"></div>
    <div class="rangebar" id="range"><span id="rangetxt"></span><a class="btn primary small" id="rangego" href="#/events">Show these events</a><button class="btn small" id="rangeclear">Clear</button></div>
    <p class="muted" style="margin:8px 0 0">Drag across the chart to select a period and open its events. ${sum.no_ts ? `${fmtN(sum.no_ts)} events have no usable timestamp and are not on this chart.` : ''}</p>
  </div>
  <div class="panel" style="margin-top:16px" id="fleetpanel"><div class="page-head" style="margin-bottom:8px"><h2 style="margin:0">Fleet by</h2><span class="spacer"></span>
    <div class="seg" id="fdim">${VIN_DIMS.filter(d => !['plant', 'vehicle_type'].includes(d[0])).map(([k, n], i) => `<button data-d="${k}" class="${i ? '' : 'on'}">${n}</button>`).join('')}</div></div>
    <div id="fleetbars" class="muted">Loading</div></div>
  <div class="grid2">
    <div class="panel"><h2>Most frequent event types</h2><div id="b-ev">${barsHtml(top_ev)}</div></div>
    <div class="panel"><h2>Noisiest vehicles</h2><div id="b-vin">${barsHtml(top_vin, { mono: true })}</div></div>
    <div class="panel"><h2>Events per ECU</h2><div id="b-ecu">${barsHtml(top_ecu)}</div></div>
    <div class="panel"><h2>Open alerts, highest severity first</h2>${al.alerts.length ? `<div class="bars" style="gap:0">${al.alerts.map(a => `<a class="bar" style="grid-template-columns:auto minmax(0,1fr) auto;--c:${sevColor(a.severity)}" href="#/alerts/${a.id}">${sevHtml(a.severity)}<span class="lab">${esc(a.title)}</span><span class="val">${a.vin ? `<span class="mono">${esc(a.vin.slice(-6))}</span>` : 'fleet'}</span></a>`).join('')}</div><p style="margin:8px 0 0"><a href="#/alerts">All alerts</a></p>` : '<div class="empty">No open alerts</div>'}</div>
  </div>`;

  const loadTl = async g => {
    const t = await api('/api/timeline?' + qs({ group: g }));
    renderTimeline($('#tl'), t, {
      onSelect: (a, b) => {
        $('#rangetxt').textContent = `${fmtMin(a)} to ${fmtMin(b)} UTC`;
        $('#rangego').href = hashFor('events', { from: a, to: b });
        $('#range').classList.add('on');
      }
    });
    $('#range').classList.remove('on');
  };
  await loadTl('severity');
  api('/api/fleet/profile').then(fp => {
    if (!$('#fleetbars')) return;
    const show = k => {
      const d = fp.dimensions.find(x => x.key === k);
      const max = Math.max(...d.items.map(x => x.vehicles), 1);
      $('#fleetbars').className = '';
      $('#fleetbars').innerHTML = `<div class="bars">${d.items.map(x => `<a class="bar wide" href="${hashFor('vehicles', { [k]: x.value })}"><span class="lab">${esc(x.value)}</span><span class="track"><span class="fill" style="display:block;width:${(x.vehicles / max * 100).toFixed(1)}%"></span></span><span class="val">${fmtN(x.vehicles)} vehicles, ${fmtN(x.events)} events${x.high ? `, ${fmtN(x.high)} high` : ''}</span></a>`).join('')}</div>`
        + (fp.check_failed ? `<p class="muted" style="margin:8px 0 0">${fp.check_failed} VINs fail the check digit.</p>` : '');
    };
    show('year');
    $('#fdim').addEventListener('click', e => { const b = e.target.closest('button'); if (!b) return; $$('#fdim button').forEach(x => x.classList.toggle('on', x === b)); show(b.dataset.d); });
  }).catch(() => { const fb = $('#fleetbars'); if (fb) fb.textContent = 'Fleet breakdown not available.'; });
  $('#grp').addEventListener('click', e => { const b = e.target.closest('button'); if (!b) return; $$('#grp button').forEach(x => x.classList.toggle('on', x === b)); loadTl(b.dataset.g); });
  $('#rangeclear').addEventListener('click', () => { $('#range').classList.remove('on'); const r = $('#selrect'); if (r) r.style.display = 'none'; });
  const barNav = (sel, make) => $(sel).addEventListener('click', e => { const b = e.target.closest('.bar'); if (b && b.dataset.key !== undefined) location.hash = make(b.dataset.key); });
  barNav('#b-ev', k => hashFor('events', { cat: k }));
  barNav('#b-vin', k => hashFor('vehicle', {}, k));
  barNav('#b-ecu', k => hashFor('events', { ecu: k === '' ? '(none)' : k }));
};

/* ---------------------------------------------------------------- events */
ROUTES.events = async function (_, P) {
  const raw = paramsObj(P);
  const page = Math.max(1, +raw.page || 1), sort = raw.sort || 'ts', dir = raw.dir || 'desc';
  const filt = {};
  for (const k of ['q', ...FILTER_KEYS]) if (raw[k]) filt[k] = raw[k];
  const [res, fac] = await Promise.all([
    api('/api/events?' + qs({ ...filt, page, size: 50, sort, dir })),
    api('/api/facets?' + qs(filt))]);
  const catLabel = Object.fromEntries(fac.event.map(x => [x.value, x.label]));

  // chips
  const chips = [];
  for (const k of FILTER_KEYS) {
    if (!filt[k]) continue;
    const vals = LIST_KEYS.has(k) ? filt[k].split(',').filter(Boolean) : [filt[k]];
    for (const v of vals) {
      let label = v;
      if (k === 'cat') label = catLabel[v] || v;
      if ((k === 'from' || k === 'to') && /^\d+$/.test(v)) label = fmtMin(+v) + ' UTC';
      if (k === 'ts') label = v === 'valid' ? 'has valid time' : 'no valid time';
      if (k === 'alert') label = v === 'any' ? 'covered by an alert' : 'not covered by an alert';
      if (k === 'case') label = v === 'any' ? 'in a case' : 'not in a case';
      const name = { vin_prefix: 'VIN prefix', import_id: 'import', cat: 'event', type: 'report type', from: 'from', to: 'to', ts: 'time', alert: 'alert', case: 'case' }[k] || k;
      chips.push(`<span class="chip">${esc(name)}: ${esc(label)}<button data-rm="${esc(k)}|${esc(v)}" aria-label="Remove filter ${esc(name)} ${esc(label)}">×</button></span>`);
    }
  }
  const dateVal = v => !v ? '' : /^\d+$/.test(v) ? fmtMin(+v) : v;
  const exportHref = '/api/export.csv?' + qs(filt);

  view.innerHTML = `<div class="page-head"><h1>Events</h1><span class="sub">${fmtN(res.total)} matching</span><span class="spacer"></span><a class="btn" href="${exportHref}" download>Export CSV</a></div>
  <form class="panel searchbar" id="sf">
    <input type="search" id="q" value="${esc(raw.q || '')}" placeholder='vin:SC6GM1  ecu:BCM  sev:high  name:CRC  -type:autosarsev  "free text"' aria-label="Search events" autocomplete="off">
    <label>From <input type="text" id="from" value="${esc(dateVal(raw.from))}" placeholder="2025-05-01" size="16"></label>
    <label>To <input type="text" id="to" value="${esc(dateVal(raw.to))}" placeholder="2025-05-31" size="16"></label>
    <span class="muted">UTC</span>
    <label>Alert <select id="falert"><option value="">any</option><option value="any" ${raw.alert === 'any' ? 'selected' : ''}>covered</option><option value="none" ${raw.alert === 'none' ? 'selected' : ''}>not covered</option></select></label>
    <label>Case <select id="fcase"><option value="">any</option><option value="any" ${raw.case === 'any' ? 'selected' : ''}>in a case</option><option value="none" ${raw.case === 'none' ? 'selected' : ''}>not in a case</option></select></label>
    <button class="btn primary" type="submit">Search</button>
    ${Object.keys(filt).length ? '<button class="btn" type="button" id="clear">Clear all</button>' : ''}
  </form>
  <div class="chips">${chips.join('')}</div>
  <div class="evlayout">
    <div class="facets" id="facets">${['severity', 'ecu', 'category', 'cat', 'type', 'vin_prefix'].map(k => {
      const items = k === 'cat' ? fac.event : fac[k === 'cat' ? 'event' : k];
      const sel = new Set((filt[k] || '').split(',').filter(Boolean));
      if (!items.length) return '';
      return `<div class="facet"><h4>${FACET_TITLES[k]}</h4>${items.slice(0, k === 'cat' ? 25 : 12).map(i => `<button data-f="${k}" data-v="${esc(i.value)}" class="${sel.has(i.value) ? 'on' : ''}" title="${esc(i.label || i.value)}"><span>${k === 'severity' ? sevHtml(i.value) : esc(i.label || i.value)}</span><span>${fmtN(i.n)}</span></button>`).join('')}</div>`;
    }).join('')}</div>
    <div>
      ${res.events.length ? `<div class="tablewrap"><table><thead><tr>
        ${sortHeader('Time (UTC)', 'ts', sort, dir)}${sortHeader('Severity', 'severity', sort, dir)}${sortHeader('Event', 'event', sort, dir)}${sortHeader('ECU', 'ecu', sort, dir)}${sortHeader('Vehicle', 'vin', sort, dir)}${sortHeader('Type', 'type', sort, dir)}<th>Alert, case</th><th>Description</th></tr></thead>
        <tbody id="tb">${eventRowsHtml(res.events)}</tbody></table></div>${pagerHtml(res.total, res.page, res.size)}`
        : '<div class="panel"><div class="empty"><b>No events match</b>Remove a filter or widen the time range.</div></div>'}
    </div></div>`;

  const nav = patch => { const n = { ...filt, sort, dir, ...patch }; Object.keys(n).forEach(k => (n[k] === '' || n[k] == null) && delete n[k]); go('events', n); };
  $('#sf').addEventListener('submit', e => { e.preventDefault(); nav({ q: $('#q').value.trim(), from: $('#from').value.trim(), to: $('#to').value.trim(), page: undefined }); });
  $('#falert').addEventListener('change', e => nav({ alert: e.target.value, page: undefined }));
  $('#fcase').addEventListener('change', e => nav({ case: e.target.value, page: undefined }));
  const clear = $('#clear'); if (clear) clear.addEventListener('click', () => go('events', {}));
  view.onclick = e => {
    const rm = e.target.closest('[data-rm]');
    if (rm) {
      const [k, v] = rm.dataset.rm.split('|');
      if (LIST_KEYS.has(k)) { const rest = (filt[k] || '').split(',').filter(x => x && x !== v).join(','); nav({ [k]: rest, page: undefined }); }
      else nav({ [k]: '', page: undefined });
      return;
    }
    const f = e.target.closest('[data-f]');
    if (f) {
      const k = f.dataset.f, v = f.dataset.v, cur = (filt[k] || '').split(',').filter(Boolean);
      const next = cur.includes(v) ? cur.filter(x => x !== v) : [...cur, v];
      nav({ [k]: next.join(','), page: undefined }); return;
    }
    const pg = e.target.closest('[data-page]'); if (pg && !pg.disabled) { nav({ page: pg.dataset.page }); return; }
    const so = e.target.closest('[data-sort]'); if (so) { const k = so.dataset.sort; nav({ sort: k, dir: sort === k && dir === 'desc' ? 'asc' : 'desc', page: undefined }); return; }
    const row = e.target.closest('tr.row'); if (row) { $$('tr.sel').forEach(r => r.classList.remove('sel')); row.classList.add('sel'); openEvent(+row.dataset.id); }
  };
};

function backendHtml(e) {
  const b = e.backend || {}, cf = e.configured;
  const kv = (rows) => rows.length ? `<dl class="kv">${rows.map(r => `<dt>${r[0]}</dt><dd>${r[1]}</dd>`).join('')}</dl>` : '';
  const mono = v => `<span class="mono">${esc(v)}</span>`;
  let out = '';
  // what the event is
  const head = [];
  if (b.sev != null) head.push(['CycurGUARD severity', `${esc(b.sev)} <span class="muted">of 1 to 3, set by the backend</span>`]);
  if (b.tn) head.push(['Report type', mono(b.tn)]);
  if (cf && cf.description) head.push(['Configured meaning', esc(cf.description)]);
  if (b.bus) head.push(['Bus', esc(b.bus)]);
  const fields = b.fields || (cf ? cf.context.map(c => ({ n: c.name, v: c.value, vd: c.meaning, type: c.type })) : Object.entries(b.ctx || {}).map(([n, v]) => ({ n, v })));
  for (const f of fields) head.push([esc(f.label || f.n), `${f.v != null ? mono(f.v) : ''}${f.vd ? ` <span class="muted">${esc(f.vd)}</span>` : ''}`]);
  out += kv(head);
  // the CAN message and the rule it broke
  if (b.msg) {
    const m = b.msg;
    out += `<h3>CAN message</h3>` + kv([
      ['Message', `${m.name ? mono(m.name) + ' ' : ''}<span class="muted">id ${esc(m.id)}${m.ext ? ', extended' : ''}, ${esc(m.len)} bytes</span>`],
      ...(m.tx && m.tx.length ? [['Sent by', esc(m.tx.join(', '))]] : []),
      ...(m.rx && m.rx.length ? [['Received by', esc(m.rx.join(', '))]] : []),
      ...(m.groups && m.groups.length ? [['Group', esc(m.groups.join(', '))]] : [])]);
  }
  if (b.rule) {
    const lim = Object.entries(b.rule.limits || {}).map(([k, v]) => `${esc(k.replace(/_/g, ' '))}: <span class="mono">${esc(v)}</span>`).join('<br>');
    const meas = Array.isArray(b.rule.measured) ? b.rule.measured[0] : b.rule.measured;
    const mm = Object.entries(meas || {}).map(([k, v]) => `${esc(k.replace(/_/g, ' '))}: <span class="mono">${esc(v)}</span>`).join('<br>');
    out += `<h3>Violated rule</h3>` + kv([['Check', `${esc(b.rule.type || '')} ${b.rule.name ? mono(b.rule.name) : ''}`],
      ...(lim ? [['Limits', lim]] : []), ...(mm ? [['Measured', mm]] : [])]);
  }
  if (b.xd) out += kv(Object.entries(b.xd).map(([k, v]) => [esc(k.replace(/_/g, ' ')), mono(v)]));
  if (b.sigs && b.sigs.length) {
    const hit = b.sig && b.sig.n;
    out += `<h3>Signals in the message</h3><div class="tablewrap"><table><thead><tr><th>Signal</th><th class="num">Raw</th><th class="num">Value</th></tr></thead><tbody>${b.sigs.map(x => `<tr${x.n === hit ? ' class="row"' : ''}><td class="mono">${esc(x.n)}${x.n === hit ? ' <span class="muted">(checked)</span>' : ''}</td><td class="num">${esc(x.raw)}</td><td class="num">${esc(x.val)}</td></tr>`).join('')}</tbody></table></div>`;
  } else if (b.sig) {
    out += kv([['Signal', `${mono(b.sig.n)} raw ${esc(b.sig.raw)}, value ${esc(b.sig.val)}`]]);
  }
  // report
  const rep = [];
  if (b.count != null) rep.push(['Occurrences in report', esc(b.count)]);
  if (b.nvm_from != null) rep.push([e.ts == null ? 'Happened between (UTC)' : 'Report covers (UTC)', `${fmtTs(b.nvm_from, 1)}${b.nvm_to !== b.nvm_from ? ` to ${b.nvm_to != null ? fmtTs(b.nvm_to, 1) : '?'}` : ''}`]);
  if (b.sent != null) rep.push(['Sent by vehicle (UTC)', fmtTs(b.sent, 1)]);
  if (b.counter != null) rep.push(['Global counter', esc(b.counter)]);
  if (b.batch) rep.push(['Report batch', mono(b.batch)]);
  if (b.raw) rep.push(['Raw bytes (base64)', mono(b.raw)]);
  out += kv(rep);
  return out ? `<h3>Backend details</h3>${out}` : '';
}

async function openEvent(id) {
  const e = await api('/api/events/' + id);
  const filterSimilar = hashFor('events', { cat: e.cat_id ?? `${e.event_type}:${e.event_id}` });
  openDrawer(esc(e.short_name), `
    <p style="margin:0 0 12px">${sevHtml(e.severity)} <span class="muted">${esc(e.category)}</span></p>
    <dl class="kv">
      <dt>Time (UTC)</dt><dd class="mono">${fmtTs(e.ts, e.ts_ok)}${e.ts != null ? ` <span class="muted">raw ${esc(e.ts)}</span>` : ''}</dd>
      <dt>Vehicle</dt><dd class="mono"><a href="${hashFor('vehicle', {}, e.vin)}">${esc(e.vin)}</a></dd>
      <dt>ECU</dt><dd>${esc(e.ecu_name) || '<span class="muted">none</span>'}${e.ecu_id !== '' ? ` <span class="muted">id ${esc(e.ecu_id)}</span>` : ''}</dd>
      <dt>Report type</dt><dd>${esc(e.event_type)}</dd>
      <dt>Alerts and case</dt><dd>${(e.alerts || []).length ? e.alerts.map(a => `<div><a href="#/alerts/${a.id}">#${a.id}</a> ${esc(a.title)} <span class="muted">${esc(statusLabel(a.status))}${a.case_id ? `, <a href="#/cases/${a.case_id}">case #${a.case_id}</a>` : ', no case'}</span></div>`).join('') : '<span class="muted">Not covered by any alert</span>'}</dd>
      <dt>Event ID</dt><dd>${esc(e.event_id)}</dd>
      <dt>Name</dt><dd class="mono">${esc(e.name) || '<span class="muted">empty</span>'}</dd>
      <dt>Description</dt><dd>${esc(e.description) || '<span class="muted">empty</span>'}</dd>
    </dl>
    ${backendHtml(e)}
    <p style="margin:14px 0"><a class="btn small" href="${hashFor('events', { vin: e.vin })}">All events of this vehicle</a> <a class="btn small" href="${filterSimilar}">Same event on all vehicles</a></p>
    <h3>Analyst note</h3>
    <textarea id="note" rows="3" placeholder="Add a note about this event">${esc(e.note)}</textarea>
    <p style="margin:6px 0 0"><button class="btn small" data-act="save-note" data-id="${e.id}">Save note</button></p>
    <h3>${esc(e.related_label)}</h3>
    ${e.related.length ? `<div class="tablewrap"><table><tbody>${e.related.map(r => `<tr class="row" data-open="${r.id}"><td class="nowrap mono">${fmtTs(r.ts, r.ts_ok)}</td><td>${sevHtml(r.severity)}</td><td>${esc(r.short_name)}</td><td>${esc(r.ecu_name)}</td></tr>`).join('')}</tbody></table></div>` : '<p class="muted">No other events.</p>'}`);
}
$('#drawer').addEventListener('click', async e => {
  const open = e.target.closest('[data-open]');
  if (open) { openEvent(+open.dataset.open); return; }
  const sn = e.target.closest('[data-act="save-note"]');
  if (sn) { try { await api(`/api/events/${sn.dataset.id}/note`, { method: 'PUT', json: { note: $('#note').value } }); toast('Note saved'); } catch (err) { toast(err.message, true); } }
});

/* ---------------------------------------------------------------- vehicles */
ROUTES.vehicles = async function (_, P) {
  const raw = paramsObj(P);
  const page = Math.max(1, +raw.page || 1), sort = raw.sort || 'risk', dir = raw.dir || 'desc';
  const f = raw.q ? { q: 'vin:' + raw.q } : {};
  const attrs = {}; VIN_DIMS.forEach(([k]) => { if (raw[k]) attrs[k] = raw[k]; });
  const res = await api('/api/vehicles?' + qs({ ...f, ...attrs, page, size: 50, sort, dir }));
  view.innerHTML = `<div class="page-head"><h1>Vehicles</h1><span class="sub">${fmtN(res.total)} vehicles</span></div>
  <form class="panel searchbar" id="vf"><input type="search" id="vq" value="${esc(raw.q || '')}" placeholder="Find a VIN or part of one" autocomplete="off" aria-label="Find a vehicle"><button class="btn primary" type="submit">Search</button></form>
  ${Object.keys(attrs).length ? `<div class="chips" style="margin:10px 0">${Object.entries(attrs).map(([k, v]) => `<span class="chip">${esc(VIN_DIMS.find(d => d[0] === k)[1])}: ${esc(v)}<button data-unset="${k}" title="Remove this filter" aria-label="Remove filter">&times;</button></span>`).join(' ')}</div>` : ''}
  <p class="muted" style="margin:10px 0">Vehicle details are decoded from the VIN. Risk adds up the severity of every event: low 1, medium 3, high 10, critical 25.</p>
  ${res.vehicles.length ? `<div class="tablewrap"><table><thead><tr>${sortHeader('VIN', 'vin', sort, dir)}<th>Vehicle</th>${sortHeader('Risk', 'risk', sort, dir, 'num')}${sortHeader('Worst severity', 'sev', sort, dir)}${sortHeader('Events', 'events', sort, dir, 'num')}${sortHeader('High or critical', 'high', sort, dir, 'num')}${sortHeader('ECUs', 'ecus', sort, dir, 'num')}<th class="num">Open alerts</th>${sortHeader('First seen', 'first', sort, dir)}${sortHeader('Last seen', 'last', sort, dir)}</tr></thead><tbody>
    ${res.vehicles.map(v => `<tr class="row" data-vin="${esc(v.vin)}"><td class="mono">${esc(v.vin)}</td><td>${esc(v.info.label)}</td><td class="num">${fmtN(v.risk)}</td><td>${sevHtml(v.max_severity)}</td><td class="num">${fmtN(v.events)}</td><td class="num">${fmtN(v.high)}</td><td class="num">${v.ecus}</td><td class="num">${v.open_alerts || ''}</td><td class="nowrap">${fmtDay(v.first_seen) || '<span class="muted">none</span>'}</td><td class="nowrap">${fmtDay(v.last_seen) || '<span class="muted">none</span>'}</td></tr>`).join('')}
    </tbody></table></div>${pagerHtml(res.total, res.page, res.size)}` : '<div class="panel"><div class="empty"><b>No vehicles found</b></div></div>'}`;
  const nav = patch => { const n = { q: raw.q, sort, dir, ...attrs, ...patch }; Object.keys(n).forEach(k => !n[k] && delete n[k]); go('vehicles', n); };
  $('#vf').addEventListener('submit', e => { e.preventDefault(); nav({ q: $('#vq').value.trim(), page: undefined }); });
  view.onclick = e => {
    const pg = e.target.closest('[data-page]'); if (pg && !pg.disabled) return nav({ page: pg.dataset.page });
    const un = e.target.closest('[data-unset]'); if (un) return nav({ [un.dataset.unset]: undefined, page: undefined });
    const so = e.target.closest('[data-sort]'); if (so) { const k = so.dataset.sort; return nav({ sort: k, dir: sort === k && dir === 'desc' ? 'asc' : 'desc', page: undefined }); }
    const row = e.target.closest('tr.row'); if (row) location.hash = hashFor('vehicle', {}, row.dataset.vin);
  };
};

const VIN_DIMS = [['year', 'Model year'], ['variant', 'Variant'], ['vehicle_type', 'Vehicle type'], ['body', 'Body'], ['engine', 'Engine'], ['drive', 'Hand of drive'], ['market', 'Market'], ['plant', 'Plant']];

function vinPanel(i) {
  if (!i.valid) return `<p class="muted" style="margin:0">${esc(i.problem)}. Decoding needs a 17-character VIN.</p>`;
  const link = (k, val) => `<a href="${hashFor('vehicles', { [k]: String(val) })}" title="All vehicles with this value">${esc(val)}</a>`;
  const row = (t, d) => d ? `<dt>${t}</dt><dd>${d}</dd>` : '';
  const vin = i.vin;
  return `<div class="grid2" style="margin:0">
    <dl class="kv">
      ${row('Model', esc(i.manufacturer) + ' ' + esc(i.model) + ' ' + esc(i.vehicle_type || ''))}
      ${row('Variant', link('variant', i.variant || 'n/a'))}
      ${row('Body', link('body', i.body))}
      ${row('Engine', link('engine', i.engine))}
      ${row('Hand of drive', i.drive ? link('drive', i.drive) : '')}
      ${row('Market', link('market', i.market))}
    </dl>
    <dl class="kv">
      ${row('Model year', i.year ? link('year', i.year) : 'Unknown')}
      ${row('Built in', link('plant', i.plant))}
      ${row('Serial number', `<span class="mono">${esc(i.serial)}</span>`)}
      ${i.gvwr ? row('Weight and restraints', esc(i.gvwr)) : ''}
      ${row('Check digit', i.check_ok ? `<span class="mono">${esc(i.check_digit)}</span> is correct` : `<b>Wrong</b>: the VIN has <span class="mono">${esc(i.check_digit)}</span>, calculation gives <span class="mono">${esc(i.check_expected)}</span>. Possible typo or a spoofed VIN.`)}
      ${i.unknown.length ? row('Not in the decoder', esc(i.unknown.join(', ')) + '. Check for a newer decoder revision.') : ''}
    </dl></div>
    <p class="vinstrip mono" aria-label="VIN split by field">${[['WMI', vin.slice(0, 3)], ['Make and line', vin.slice(3, 5)], ['Body', vin[5]], ['Engine', vin[6]], [i.market === 'US/Canada' ? 'GVWR' : 'Drive', vin[7]], ['Check', vin[8]], ['Year', vin[9]], ['Plant', vin[10]], ['Serial', vin.slice(11)]].map(([l, c]) => `<span><b>${esc(c)}</b><small>${l}</small></span>`).join('')}</p>
    <p class="muted" style="margin:6px 0 0">Decoded with INEOS Grenadier VIN decoder Corp-P2-ENG-0128 rev 001. The EU/ROW and US/Canada tables overlap for the LEVIII petrol engine, so a passenger car with engine C and restraint code A is shown as US/Canada.</p>`;
}

ROUTES.vehicle = async function (vin) {
  const [v, t] = await Promise.all([api('/api/vehicles/' + encodeURIComponent(vin)), api('/api/timeline?' + qs({ vin, group: 'severity', buckets: 60 }))]);
  const s = v.summary;
  view.innerHTML = `<div class="page-head"><a href="#/vehicles">Vehicles</a><h1 class="mono" style="font-weight:600">${esc(v.vin)}</h1><span class="spacer"></span><a class="btn" href="${hashFor('events', { vin })}">Open all events</a></div>
  <div class="figures">
    <div class="fig"><div class="n">${fmtN(s.total)}</div><div class="l">Events</div></div>
    <div class="fig"><div class="n">${fmtN(s.high)}</div><div class="l">High or critical</div></div>
    <div class="fig"><div class="n">${s.ecus}</div><div class="l">ECUs reporting</div></div>
    <div class="fig"><div class="n" style="font-size:18px">${fmtDay(s.first_ts) || 'none'}</div><div class="l">First event</div></div>
    <div class="fig"><div class="n" style="font-size:18px">${fmtDay(s.last_ts) || 'none'}</div><div class="l">Last event</div><div class="s">${s.last_ts ? ago(s.last_ts) : ''}</div></div>
    <a class="fig" href="${hashFor('events', { vin, ts: 'invalid' })}"><div class="n">${fmtN(s.no_ts)}</div><div class="l">Without usable time</div></a>
  </div>
  <div class="panel" style="margin-top:16px"><h2>Vehicle identity</h2>${vinPanel(v.info)}</div>
  <div class="panel" style="margin-top:16px"><h2>Timeline</h2><div id="tl"></div></div>
  <div class="grid2">
    <div class="panel"><h2>What this vehicle reported</h2><div class="tablewrap"><table><thead><tr><th>Event</th><th>ECU</th><th class="num">Count</th><th>Last seen</th></tr></thead><tbody>
      ${v.by_event.map(r => `<tr class="row" data-go="${hashFor('events', { vin, cat: r.cat_id, ...(r.ecu_name ? { ecu: r.ecu_name } : {}) })}"><td>${sevHtml(r.severity)} ${esc(r.short_name)}</td><td>${esc(r.ecu_name) || '<span class="muted">none</span>'}</td><td class="num">${fmtN(r.n)}</td><td class="nowrap">${fmtDay(r.last_ts)}</td></tr>`).join('')}</tbody></table></div></div>
    <div class="panel"><h2>Alerts</h2><div id="valerts">${v.alerts.length ? `<div class="tablewrap"><table><tbody>${v.alerts.map(a => `<tr class="row" data-aid="${a.id}"><td>${sevHtml(a.severity)}</td><td><a class="rowlink" href="#/alerts/${a.id}">${esc(a.title)}</a></td><td>${statusHtml(a.status)}</td></tr>`).join('')}</tbody></table></div>` : '<div class="empty">No alerts for this vehicle</div>'}</div></div>
  </div>`;
  renderTimeline($('#tl'), t, { onSelect: (a, b) => { location.hash = hashFor('events', { vin, from: a, to: b }); } });
  window.__reloadAlerts = async () => {
    const nv = await api('/api/vehicles/' + encodeURIComponent(vin));
    const box = $('#valerts'); if (!box) return;
    box.innerHTML = nv.alerts.length ? `<div class="tablewrap"><table><tbody>${nv.alerts.map(a => `<tr class="row" data-aid="${a.id}"><td>${sevHtml(a.severity)}</td><td><a class="rowlink" href="#/alerts/${a.id}">${esc(a.title)}</a></td><td>${statusHtml(a.status)}</td></tr>`).join('')}</tbody></table></div>` : '<div class="empty">No alerts for this vehicle</div>';
  };
  view.onclick = e => {
    const al = e.target.closest('tr[data-aid]');
    if (al) { openAlert(+al.dataset.aid); return; }
    const r = e.target.closest('[data-go]'); if (r) location.hash = r.dataset.go;
  };
};

/* ---------------------------------------------------------------- alerts */
const TABS = [['open', 'Open', 'new,in_progress'], ['all', 'All', ''], ['resolved', 'Resolved', 'resolved'], ['false_positive', 'False positive', 'false_positive'], ['suppressed', 'Suppressed', 'suppressed']];
ROUTES.alerts = async function (arg, P) {
  const raw = paramsObj(P);
  const tab = raw.tab || 'open';
  const status = (TABS.find(t => t[0] === tab) || TABS[0])[2];
  const sort = raw.sort || 'severity', dir = raw.dir || 'desc', page = Math.max(1, +raw.page || 1);
  const rulesList = await api('/api/rules');
  view.innerHTML = `<div class="page-head"><h1>Alerts</h1><span class="spacer"></span><button class="btn" id="rerun">Run detections again</button></div>
  <div class="tabs" id="tabs"></div>
  <div class="filters"><input type="search" id="aq" value="${esc(raw.q || '')}" placeholder="Search title or VIN" aria-label="Search alerts">
    <select id="asev" aria-label="Severity"><option value="">Any severity</option>${SEVS.slice().reverse().map(s => `<option ${raw.severity === s ? 'selected' : ''}>${s}</option>`).join('')}</select>
    <select id="arule" aria-label="Detection"><option value="">Any detection</option>${rulesList.map(r => `<option value="${r.id}" ${raw.rule === r.id ? 'selected' : ''}>${esc(r.title)}</option>`).join('')}</select>
    <select id="acase" aria-label="Case"><option value="">Any case state</option><option value="none" ${raw.case === 'none' ? 'selected' : ''}>Not in a case</option><option value="any" ${raw.case === 'any' ? 'selected' : ''}>In a case</option></select>
    <span class="spacer" style="flex:1"></span>
    <span id="bulk" style="display:none"><span id="bulkn" class="muted"></span> <button class="btn small primary" data-bulkcase="1">Create case</button> <button class="btn small" data-bulk="in_progress">Start</button> <button class="btn small" data-bulk="resolved">Resolve</button> <button class="btn small" data-bulk="false_positive">Mark false positive</button></span></div>
  <div id="alist"></div>`;

  const nav = patch => { const n = { tab, q: raw.q, severity: raw.severity, rule: raw.rule, case: raw.case, sort, dir, ...patch }; Object.keys(n).forEach(k => !n[k] && delete n[k]); go('alerts', n); };
  const load = async () => {
    const res = await api('/api/alerts?' + qs({ status, severity: raw.severity, rule: raw.rule, case: raw.case, q: raw.q, sort, dir, page, size: 50 }));
    const sc = res.status_counts, cnt = k => k === 'all' ? Object.values(sc).reduce((a, b) => a + b, 0) : k === 'open' ? (sc.new || 0) + (sc.in_progress || 0) : (sc[k] || 0);
    $('#tabs').innerHTML = TABS.map(t => `<button data-tab="${t[0]}" class="${t[0] === tab ? 'on' : ''}">${t[1]}<span class="ct">${fmtN(cnt(t[0]))}</span></button>`).join('');
    $('#alist').innerHTML = res.alerts.length ? `<div class="tablewrap"><table><thead><tr><th><input type="checkbox" id="chkall" aria-label="Select all"></th>${sortHeader('Severity', 'severity', sort, dir)}<th>Alert</th><th>Detection</th><th>Vehicle</th><th>Case</th>${sortHeader('Events', 'events', sort, dir, 'num')}${sortHeader('Last event', 'last', sort, dir)}${sortHeader('Status', 'status', sort, dir)}<th>Assignee</th></tr></thead><tbody>
      ${res.alerts.map(a => `<tr class="row" data-aid="${a.id}"><td><input type="checkbox" class="chk" value="${a.id}" aria-label="Select alert ${a.id}"></td><td>${sevHtml(a.severity)}</td><td><a class="rowlink" href="${hashFor('alerts', {}, a.id)}">${esc(a.title)}</a></td><td class="muted">${esc(a.rule_title)}</td><td class="mono">${a.vin ? esc(a.vin) : '<span class="muted">fleet</span>'}</td><td>${a.case_id ? `<a href="#/cases/${a.case_id}" data-stop>#${a.case_id}</a>` : a.suggested_case ? `<span class="muted">maybe </span><a href="#/cases/${a.suggested_case}" data-stop>#${a.suggested_case}</a>` : '<span class="muted">none</span>'}</td><td class="num">${fmtN(a.event_count)}</td><td class="nowrap">${fmtDay(a.last_ts) || '<span class="muted">none</span>'}</td><td>${statusHtml(a.status)}</td><td>${esc(a.assignee)}</td></tr>`).join('')}</tbody></table></div>${pagerHtml(res.total, res.page, res.size)}`
      : `<div class="panel"><div class="empty"><b>${tab === 'open' ? 'No open alerts' : 'No alerts here'}</b>${tab === 'open' ? 'Detections run automatically after every import.' : 'Change the tab or filters.'}</div></div>`;
  };
  await load();
  window.__reloadAlerts = load;

  const updateBulk = () => { const n = $$('.chk:checked').length; $('#bulk').style.display = n ? '' : 'none'; $('#bulkn').textContent = `${n} selected`; };
  view.onclick = async e => {
    const tb = e.target.closest('[data-tab]'); if (tb) return nav({ tab: tb.dataset.tab, page: undefined });
    const pg = e.target.closest('[data-page]'); if (pg && !pg.disabled) return nav({ page: pg.dataset.page });
    const so = e.target.closest('[data-sort]'); if (so) { const k = so.dataset.sort; return nav({ sort: k, dir: sort === k && dir === 'desc' ? 'asc' : 'desc', page: undefined }); }
    if (e.target.id === 'chkall') { $$('.chk').forEach(c => { c.checked = e.target.checked; }); return updateBulk(); }
    if (e.target.classList.contains('chk')) { e.stopPropagation(); return updateBulk(); }
    const bc = e.target.closest('[data-bulkcase]');
    if (bc) { const ids = $$('.chk:checked').map(c => +c.value); if (ids.length) openCaseForm(ids); return; }
    const bk = e.target.closest('[data-bulk]');
    if (bk) { try { const ids = $$('.chk:checked').map(c => +c.value); await api('/api/alerts/bulk', { method: 'POST', json: { ids, status: bk.dataset.bulk } }); toast(`${ids.length} alert(s) updated`); await load(); updateBulk(); refreshChrome(); } catch (err) { toast(err.message, true); } return; }
    if (e.target.id === 'rerun') { try { const r = await api('/api/detections/run', { method: 'POST' }); toast(`Detections done: ${r.created} new, ${r.updated} updated, ${r.reopened} re-opened`); await load(); refreshChrome(); } catch (err) { toast(err.message, true); } return; }
    const row = e.target.closest('tr.row'); if (row) { $$('tr.sel').forEach(r => r.classList.remove('sel')); row.classList.add('sel'); openAlert(+row.dataset.aid); }
  };
  $('#aq').addEventListener('change', () => nav({ q: $('#aq').value.trim(), page: undefined }));
  $('#asev').addEventListener('change', e => nav({ severity: e.target.value, page: undefined }));
  $('#arule').addEventListener('change', e => nav({ rule: e.target.value, page: undefined }));
  $('#acase').addEventListener('change', e => nav({ case: e.target.value, page: undefined }));
  if (arg) openAlert(+arg);
};

async function openAlert(id) {
  const a = await api('/api/alerts/' + id);
  const f = a.filter || {};
  const det = Object.entries(a.details || {}).map(([k, v]) => `<dt>${esc(k.replace(/_/g, ' '))}</dt><dd>${typeof v === 'object' ? `<span class="mono">${esc(JSON.stringify(v))}</span>` : esc(v)}</dd>`).join('');
  openDrawer(esc(a.title), `
    <p style="margin:0 0 10px">${sevHtml(a.severity)} ${statusHtml(a.status)}</p>
    <div class="statusrow" id="stbtns">${['new', 'in_progress', 'resolved', 'false_positive'].map(s => `<button class="btn small ${a.status === s ? 'primary' : ''}" data-act="set-status" data-id="${a.id}" data-status="${s}">${esc(statusLabel(s))}</button>`).join('')}</div>
    <dl class="kv">
      <dt>Detection</dt><dd>${esc(a.rule_title)}<div class="muted">${esc(a.rule_description)}</div></dd>
      <dt>Vehicle</dt><dd>${a.vin ? `<a class="mono" href="${hashFor('vehicle', {}, a.vin)}">${esc(a.vin)}</a>` : 'Whole fleet'}</dd>
      ${a.ecu_name ? `<dt>ECU</dt><dd>${esc(a.ecu_name)}</dd>` : ''}
      <dt>Events</dt><dd>${fmtN(a.event_count)}</dd>
      <dt>First event</dt><dd class="mono">${a.first_ts ? esc(fmtMin(a.first_ts)) + ' UTC' : '<span class="muted">no valid time</span>'}</dd>
      <dt>Last event</dt><dd class="mono">${a.last_ts ? esc(fmtMin(a.last_ts)) + ' UTC' : '<span class="muted">no valid time</span>'}</dd>
      ${det}
    </dl>
    <p style="margin:14px 0"><a class="btn primary" href="${hashFor('events', f)}">Show matching events</a></p>
    <h3>Case</h3>
    ${a.case ? `<p style="margin:0"><a href="${hashFor('cases', {}, a.case.id)}">Case #${a.case.id}: ${esc(a.case.title)}</a> ${caseStatusHtml(a.case.status)}</p>`
      : `${(a.suggested_cases || []).length ? `<div class="note" style="margin:0 0 10px"><b>May belong to an existing case.</b>${a.suggested_cases.map(c => `<div style="margin-top:6px"><a href="${hashFor('cases', {}, c.id)}">Case #${c.id}: ${esc(c.title)}</a> ${caseStatusHtml(c.status)}<div class="muted">${esc(c.basis.charAt(0).toUpperCase() + c.basis.slice(1))}: alert #${c.alert_id} (${esc(statusLabel(c.alert_status))}) is in this case.${c.status === 'closed' ? ` The case is closed${c.resolution ? ' (' + esc(c.resolution.replace(/_/g, ' ')) + ')' : ''}; reopen it to add this alert.` : ''}</div>${c.status !== 'closed' && ME && ME.level >= 2 ? `<button class="btn small" style="margin-top:4px" data-act="add-to-case" data-id="${a.id}" data-case="${c.id}">Add to case #${c.id}</button>` : ''}</div>`).join('')}</div>` : ''}<p style="margin:0"><button class="btn primary" data-act="new-case" data-id="${a.id}">Create case</button> <button class="btn" data-act="link-case" data-id="${a.id}">Add to existing case</button></p>`}
    ${a.status === 'suppressed' ? `<p class="note" style="margin:14px 0 0">A suppression rule hides this alert from the open list. See <a href="#/detections">Detections</a>.</p>` : (ME && ME.level >= 2 ? `<p style="margin:10px 0 0"><button class="btn" data-act="suppress" data-id="${a.id}">Suppress similar alerts</button></p>` : '')}
    <h3>Assignee</h3>
    <p style="margin:0"><input type="text" id="assignee" list="userlist" value="${esc(a.assignee)}" placeholder="Name" style="width:200px"> <button class="btn small" data-act="set-assignee" data-id="${a.id}">Save</button></p>
    <h3>Notes and history</h3>
    <textarea id="cmt" rows="3" placeholder="Write a note, for example what you checked and why you closed it"></textarea>
    <p style="margin:6px 0 10px"><button class="btn small" data-act="add-comment" data-id="${a.id}">Add note</button></p>
    ${a.comments.slice().reverse().map(c => `<div class="comment ${c.author === 'system' ? 'system' : ''}"><div class="who">${esc(c.author)}, ${esc(fmtMin(c.created_at))} UTC</div>${esc(c.body)}</div>`).join('') || '<p class="muted">No notes yet.</p>'}`);
}
$('#drawer').addEventListener('click', async e => {
  const b = e.target.closest('[data-act]'); if (!b) return;
  const id = +b.dataset.id, act = b.dataset.act;
  if (act === 'new-case') { openCaseForm([id]).catch(err => toast(err.message, true)); return; }
  if (act === 'suppress') { openSuppressForm(id).catch(err => toast(err.message, true)); return; }
  if (act === 'add-to-case') {
    try { await api(`/api/cases/${b.dataset.case}/alerts`, { method: 'POST', json: { alert_ids: [id] } }); toast(`Added to case #${b.dataset.case}`); await openAlert(id); if (window.__reloadAlerts) window.__reloadAlerts(); } catch (err) { toast(err.message, true); }
    return;
  }
  if (act === 'link-case') { openLinkCase(id).catch(err => toast(err.message, true)); return; }
  try {
    if (act === 'set-status') await api('/api/alerts/' + id, { method: 'PATCH', json: { status: b.dataset.status } });
    else if (act === 'set-assignee') await api('/api/alerts/' + id, { method: 'PATCH', json: { assignee: $('#assignee').value.trim() } });
    else if (act === 'add-comment') { const v = $('#cmt').value.trim(); if (!v) return; await api('/api/alerts/' + id, { method: 'PATCH', json: { comment: v } }); }
    else return;
    await openAlert(id);
    if (window.__reloadAlerts) window.__reloadAlerts();
    refreshChrome();
  } catch (err) { toast(err.message, true); }
});

/* ---------------------------------------------------------------- detections */
ROUTES.detections = async function () {
  const rules = await api('/api/rules');
  const label = { min_severity: 'Minimum severity', threshold: 'Events needed', window_min: 'Window (minutes)', min_ecus: 'ECUs needed', sigma: 'Standard deviations', min_events: 'Minimum events' };
  view.innerHTML = `<div class="page-head"><h1>Detections</h1><span class="sub">Rules that turn events into alerts</span></div>
  <div class="panel">${rules.map(r => `<div class="ruleblock" data-rule="${r.id}"><input type="checkbox" data-p="enabled" ${r.params.enabled ? 'checked' : ''} aria-label="Enable ${esc(r.title)}"><div><h2 style="margin:0">${esc(r.title)}</h2><p>${esc(r.description)}</p>
    <div class="params">${Object.entries(r.params).filter(([k]) => k !== 'enabled').map(([k, v]) => k === 'min_severity'
      ? `<label>${label[k]}<select data-p="${k}">${SEVS.map(s => `<option ${s === v ? 'selected' : ''}>${s}</option>`).join('')}</select></label>`
      : `<label>${label[k] || esc(k)}<input type="number" step="any" data-p="${k}" value="${esc(v)}"></label>`).join('')}</div></div></div>`).join('')}
    <p style="margin:16px 0 0"><button class="btn primary" id="saverules">Save and run detections</button></p></div>
  <p class="muted">Alerts keep their status, assignee and notes when detections run again. A resolved alert re-opens when new matching events arrive.</p>
  <div class="panel" id="suppanel"></div>`;
  renderSuppressions();
  $('#saverules').addEventListener('click', async () => {
    const out = {};
    $$('.ruleblock').forEach(b => {
      const p = {};
      $$('[data-p]', b).forEach(i => { p[i.dataset.p] = i.type === 'checkbox' ? i.checked : i.type === 'number' ? parseFloat(i.value) : i.value; });
      out[b.dataset.rule] = p;
    });
    try { await api('/api/settings', { method: 'PUT', json: { rules: out } }); const r = await api('/api/detections/run', { method: 'POST' }); toast(`Saved. ${r.created} new alerts, ${r.updated} updated.`); refreshChrome(); }
    catch (e) { toast(e.message, true); }
  });
};

/* ---------------------------------------------------------------- catalog */
ROUTES.catalog = async function () {
  const items = await api('/api/catalog');
  const unc = items.filter(i => i.auto).length;
  view.innerHTML = `<div class="page-head"><h1>Event catalog</h1><span class="sub">${items.length} event types</span><span class="spacer"></span><button class="btn primary" id="savecat" disabled>Save changes</button></div>
  <p class="note" style="margin:0 0 14px">The default severities are a starting point based on what each event means, not a vendor rating. Adjust them to your TARA and threat model. Saving re-runs the detections.</p>
  ${unc ? `<p class="note" style="margin:0 0 14px"><b>${unc} event type${unc > 1 ? 's are' : ' is'} not in the built-in catalog.</b> Set a severity to classify ${unc > 1 ? 'them' : 'it'}.</p>` : ''}
  <div class="tablewrap"><table><thead><tr><th>Event</th><th>Report type</th><th class="num">ID</th><th class="num">Events</th><th>Severity</th><th>Category</th><th>Notes</th></tr></thead><tbody>
  ${items.map(i => `<tr data-cat="${esc(i.cat_id)}"><td>${esc(i.short_name)}${i.auto ? ' <span class="status new">unclassified</span>' : ''}</td><td class="muted">${esc(i.event_type)}</td><td class="num">${esc(i.event_id)}</td><td class="num"><a href="${hashFor('events', { cat: i.cat_id })}">${fmtN(i.events)}</a></td>
    <td><select data-k="severity" aria-label="Severity of ${esc(i.short_name)}">${SEVS.map(s => `<option ${s === i.severity ? 'selected' : ''}>${s}</option>`).join('')}</select></td>
    <td><input type="text" data-k="category" value="${esc(i.category)}" size="16"></td><td><input type="text" data-k="notes" value="${esc(i.notes)}" size="28" placeholder="Why this severity"></td></tr>`).join('')}
  </tbody></table></div>`;
  const dirty = new Set();
  view.oninput = view.onchange = e => { const tr = e.target.closest('tr[data-cat]'); if (!tr) return; dirty.add(tr.dataset.cat); $('#savecat').disabled = false; };
  $('#savecat').addEventListener('click', async () => {
    const body = [...dirty].map(id => { const tr = $(`tr[data-cat="${CSS.escape(id)}"]`); return { cat_id: id, severity: $('[data-k=severity]', tr).value, category: $('[data-k=category]', tr).value, notes: $('[data-k=notes]', tr).value }; });
    try { const r = await api('/api/catalog', { method: 'PUT', json: body }); toast(`Saved ${r.updated} change(s). Detections refreshed.`); render(); }
    catch (e) { toast(e.message, true); }
  });
};

/* ---------------------------------------------------------------- data */
ROUTES.data = async function () {
  const [imps, q, st] = await Promise.all([api('/api/imports'), api('/api/quality'), api('/api/settings')]);
  view.innerHTML = `<div class="page-head"><h1>Data</h1></div>
  ${syncPanelShell()}
  <div class="panel"><h2>Import events</h2>
    <div class="dropzone" id="drop"><p style="margin:0 0 10px">Drop an export here (CSV, Excel .xlsx or JSON), or</p><input type="file" id="file" accept=".csv,.xlsx,.xlsm,.json,.txt" hidden><button class="btn primary" id="pick">Choose a file</button>
    <p class="muted" style="margin:10px 0 0">Importing the same rows again does not create duplicates, so overlapping exports are fine.</p></div><div id="impres"></div></div>
  <div class="panel"><h2>Data quality</h2>
    ${q.total ? `<div class="figures"><div class="fig"><div class="n">${fmtN(q.no_timestamp)}</div><div class="l">No timestamp</div></div>
      <div class="fig"><div class="n">${fmtN(q.implausible_timestamp)}</div><div class="l">Implausible timestamp</div><div class="s">before ${fmtDay(q.plausible_window.from)}, or in the future</div></div>
      <div class="fig"><div class="n">${fmtN(q.no_ecu)}</div><div class="l">No ECU name</div></div>
      <div class="fig"><div class="n">${fmtN(q.vins_not_17_chars)}</div><div class="l">VINs not 17 characters</div></div></div>
      <p class="muted">Events without a plausible time still count everywhere, but they cannot appear on timelines or match a date range. ${q.no_timestamp + q.implausible_timestamp ? `<a href="${hashFor('events', { ts: 'invalid' })}">Show them</a>` : ''}</p>
      ${q.worst_vehicles.length ? `<h3>Vehicles with the most unusable timestamps</h3><div class="tablewrap"><table><tbody>${q.worst_vehicles.map(v => `<tr class="row" data-go="${hashFor('vehicle', {}, v.vin)}"><td class="mono">${esc(v.vin)}</td><td class="num">${fmtN(v.bad)} of ${fmtN(v.n)}</td></tr>`).join('')}</tbody></table></div>` : ''}` : '<div class="empty">Nothing imported yet.</div>'}
  </div>
  <div class="panel"><h2>Import history</h2>${imps.length ? `<div class="tablewrap"><table><thead><tr><th>When (UTC)</th><th>File</th><th class="num">Rows</th><th class="num">New</th><th class="num">Already present</th><th class="num">Unusable</th><th class="num">Still stored</th><th></th></tr></thead><tbody>
    ${imps.map(i => `<tr><td class="nowrap mono">${esc(fmtMin(i.imported_at))}</td><td>${esc(i.filename)}</td><td class="num">${fmtN(i.rows_total)}</td><td class="num">${fmtN(i.rows_new)}</td><td class="num">${fmtN(i.rows_dup)}</td><td class="num">${fmtN(i.rows_invalid)}</td><td class="num">${fmtN(i.events_now)}</td><td><button class="btn small danger" data-delimp="${i.id}">Remove events</button></td></tr>`).join('')}</tbody></table></div>` : '<div class="empty">No imports yet.</div>'}</div>
  <div class="panel"><h2>Settings</h2><div class="params"><label>Earliest plausible event date<input type="text" id="tsmin" value="${esc(st.ts_min)}" placeholder="YYYY-MM-DD"></label></div>
    <label class="field" style="margin-top:14px;max-width:640px"><span>Checklist every new case starts with, one task per line</span><textarea id="casetasks" rows="5">${esc((st.case_tasks || []).join('\n'))}</textarea></label>
    <p class="muted">Vehicles often report an unsynchronised clock (for example 2020 or 1970) until they get a time source. Timestamps before the date above are treated as unusable.</p>
    <p style="margin:0"><button class="btn" id="savest">Save settings</button></p></div>
  <div class="panel"><h2>Feed events from another system</h2><p style="margin-top:0">Post JSON with the same field names as the export. This is the hook for a future REST pull from the backend.</p>
<pre>curl -X POST http://localhost:${location.port || 8765}/api/ingest?source=backend \\
  -H "X-SIEM: 1" -H "Content-Type: application/json" \\
  -d '[{"report.event_type":"can","sev_metadata.timestamp":1754754669000,"vin":"SC6GN3DAXSF023632","ecu_name":"ETGW","ecu_id":1,"sev_metadata.event_id":32775,"sev_metadata.name":"IdsMEventConfig_ETGW_ECY_IDPS_RPRT_FRQ_DELTA_TOO_HI","sev_metadata.description":"..."}]'</pre></div>
  <div class="panel"><h2>Delete all data</h2><p style="margin-top:0">Removes every event, alert, case and note. Catalog and settings stay.</p><input type="text" id="resetconf" placeholder='Type DELETE ALL EVENTS' size="24"> <button class="btn danger" id="reset">Delete everything</button></div>`;

  mountSync();
  const doImport = async file => {
    const box = $('#impres'); box.innerHTML = `<p>Importing ${esc(file.name)} (${(file.size / 1048576).toFixed(1)} MB)…</p>`;
    try {
      const r = await api('/api/import?' + qs({ filename: file.name }), { method: 'POST', body: file });
      box.innerHTML = `<div class="note" style="margin-top:12px"><b>${fmtN(r.rows_new)} new events imported</b> from ${fmtN(r.rows_total)} rows. ${fmtN(r.rows_duplicate)} were already present${r.rows_invalid ? `, ${fmtN(r.rows_invalid)} rows had no VIN or report type and were skipped` : ''}. Detections: ${r.detections.created} new alerts, ${r.detections.updated} updated, ${r.detections.reopened} re-opened. <a href="#/overview">Open overview</a></div>`;
      refreshChrome();
    } catch (e) { box.innerHTML = `<div class="note err" style="margin-top:12px"><b>Import failed.</b> ${esc(e.message)}</div>`; }
  };
  $('#pick').addEventListener('click', () => $('#file').click());
  $('#file').addEventListener('change', e => e.target.files[0] && doImport(e.target.files[0]));
  const drop = $('#drop');
  ['dragenter', 'dragover'].forEach(n => drop.addEventListener(n, e => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach(n => drop.addEventListener(n, e => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', e => { const f = e.dataTransfer.files[0]; if (f) doImport(f); });
  $('#savest').addEventListener('click', async () => { try { await api('/api/settings', { method: 'PUT', json: { ts_min: $('#tsmin').value.trim(), case_tasks: $('#casetasks').value.split('\n').map(x => x.trim()).filter(Boolean) } }); toast('Settings saved'); render(); } catch (e) { toast(e.message, true); } });
  $('#reset').addEventListener('click', async () => { try { await api('/api/reset', { method: 'POST', json: { confirm: $('#resetconf').value } }); toast('All events deleted'); render(); } catch (e) { toast(e.message, true); } });
  view.onclick = async e => {
    const g = e.target.closest('[data-go]'); if (g) { location.hash = g.dataset.go; return; }
    const d = e.target.closest('[data-delimp]');
    if (d && confirm('Remove the events that this import added? Alerts stay until detections run again.')) { try { const r = await api('/api/imports/' + d.dataset.delimp, { method: 'DELETE' }); toast(`${fmtN(r.deleted_events)} events removed`); render(); } catch (err) { toast(err.message, true); } }
  };
};

boot();
