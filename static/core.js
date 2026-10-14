/* Shared helpers: API, formatting, chart, drawer. No inline handlers anywhere (strict CSP). */
'use strict';

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtN = n => new Intl.NumberFormat().format(n ?? 0);
const ROUTES = {};
let ME = null; // the signed-in user, set by users.js
const SEVS = ['info', 'low', 'medium', 'high', 'critical'];
const sevColor = s => `var(--sev-${s})`;
const CATS = ['var(--cat1)', 'var(--cat2)', 'var(--cat3)', 'var(--cat4)', 'var(--cat5)', 'var(--cat6)', 'var(--cat7)', 'var(--cat8)'];

const pad = n => String(n).padStart(2, '0');
function fmtTs(ms, ok = true) {
  if (ms == null) return '<span class="muted">no timestamp</span>';
  if (!ok) return `<span class="muted" title="Raw value ${esc(ms)} is outside the plausible window (unsynchronised ECU clock?)">invalid time</span>`;
  const d = new Date(ms);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}
function fmtDay(ms) { return ms == null ? '' : new Date(ms).toISOString().slice(0, 10); }
function fmtMin(ms) { return new Date(ms).toISOString().slice(0, 16).replace('T', ' '); }
const sevHtml = s => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
const statusLabel = s => ({ new: 'New', in_progress: 'In progress', resolved: 'Resolved', false_positive: 'False positive' }[s] || s);
const caseStatusLabel = s => ({ open: 'Open', investigating: 'Investigating', waiting: 'Waiting', closed: 'Closed' }[s] || s);
const caseStatusHtml = s => `<span class="status ${esc(s)}">${esc(caseStatusLabel(s))}</span>`;
const statusHtml = s => `<span class="status ${esc(s)}">${esc(statusLabel(s))}</span>`;
function ago(ms) {
  if (!ms) return '';
  const d = (Date.now() - ms) / 86400000;
  if (d < 1) return 'today';
  if (d < 60) return `${Math.round(d)} d ago`;
  return `${Math.round(d / 30)} mo ago`;
}

/* ---------- API */
async function api(path, opts = {}) {
  const init = { method: opts.method || 'GET', headers: { 'X-SIEM': '1' } };
  if (opts.json !== undefined) { init.body = JSON.stringify(opts.json); init.headers['Content-Type'] = 'application/json'; }
  if (opts.body !== undefined) init.body = opts.body;
  const res = await fetch(path, init);
  let data = null;
  try { data = await res.json(); } catch (_) { /* non-JSON */ }
  if (res.status === 401 && ME && !path.startsWith('/api/auth/')) { showAuth(false, 'Your session has ended. Sign in again.'); throw new Error('Signed out'); }
  if (!res.ok) throw new Error((data && data.error) || `${res.status} ${res.statusText}`);
  return data;
}
const qs = o => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(o)) if (v !== undefined && v !== null && v !== '') p.set(k, v);
  return p.toString();
};

/* ---------- toast */
let toastTimer;
function toast(msg, err = false) {
  const t = $('#toast');
  t.textContent = msg; t.className = 'on' + (err ? ' err' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = ''; }, err ? 7000 : 3500);
}

/* ---------- drawer */
function openDrawer(title, html) {
  $('#drawer').innerHTML = `<div class="dhead"><h2>${title}</h2><button class="btn small" data-act="close-drawer" aria-label="Close">Close</button></div><div class="dbody">${html}</div>`;
  $('#drawer').classList.add('on'); $('#scrim').classList.add('on');
  $('#drawer').setAttribute('aria-hidden', 'false');
}
function closeDrawer() {
  $('#drawer').classList.remove('on'); $('#scrim').classList.remove('on');
  $('#drawer').setAttribute('aria-hidden', 'true');
  $$('tr.sel').forEach(r => r.classList.remove('sel'));
}
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });
$('#scrim').addEventListener('click', closeDrawer);
$('#drawer').addEventListener('click', e => { if (e.target.closest('[data-act="close-drawer"]')) closeDrawer(); });

/* ---------- tooltip */
const tipEl = document.createElement('div');
tipEl.className = 'tip'; tipEl.style.display = 'none'; document.body.appendChild(tipEl);
function showTip(x, y, html) {
  tipEl.innerHTML = html; tipEl.style.display = 'block';
  const w = tipEl.offsetWidth, h = tipEl.offsetHeight;
  tipEl.style.left = Math.min(x + 14, innerWidth - w - 8) + 'px';
  tipEl.style.top = Math.max(8, y - h - 10) + 'px';
}
const hideTip = () => { tipEl.style.display = 'none'; };

/* ---------- stacked timeline with drag-to-select ---------- */
function groupColor(group, i) {
  return SEVS.includes(group) ? sevColor(group) : CATS[i % CATS.length];
}

/**
 * data: response of /api/timeline. opts.onSelect(fromMs, toMs) is called when the user drags a range.
 */
function renderTimeline(el, data, opts = {}) {
  if (!data.series.length) {
    el.innerHTML = '<div class="empty"><b>No events with a valid timestamp</b>Events without a usable time cannot be placed on the timeline.</div>';
    return;
  }
  const W = 1000, H = 250, L = 44, R = 10, T = 10, B = 26;
  const size = data.bucket_ms;
  const t0 = data.series[0].t, t1 = data.series[data.series.length - 1].t + size;
  const byT = new Map(data.series.map(s => [s.t, s.counts]));
  const totals = data.series.map(s => Object.values(s.counts).reduce((a, b) => a + b, 0));
  const maxV = Math.max(...totals, 1);
  // axis top = a multiple of a 1/2/5 x 10^k step, giving at most five whole-number gridlines
  const step = (() => { const raw = maxV / 4; const p = 10 ** Math.floor(Math.log10(Math.max(raw, 1))); const m = raw / p; return Math.max(1, (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p); })();
  const nice = step * Math.ceil(maxV / step);
  const nTicks = Math.round(nice / step);
  const x = t => L + (t - t0) / (t1 - t0) * (W - L - R);
  const y = v => T + (1 - v / nice) * (H - T - B);
  const bw = Math.max(1, (W - L - R) * size / (t1 - t0) - 1);
  const groups = data.groups;
  let g = '';
  for (let i = 0; i <= nTicks; i++) {
    const v = step * i;
    g += `<g class="grid"><line x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}"/></g><text x="${L - 6}" y="${y(v) + 4}" text-anchor="end">${fmtN(Math.round(v))}</text>`;
  }
  let bars = '';
  for (const s of data.series) {
    let acc = 0;
    groups.forEach((gr, i) => {
      const n = s.counts[gr] || 0;
      if (!n) return;
      const top = y(acc + n), bot = y(acc);
      bars += `<rect x="${x(s.t).toFixed(1)}" y="${top.toFixed(1)}" width="${bw.toFixed(1)}" height="${Math.max(0.5, bot - top).toFixed(1)}" fill="${groupColor(gr, i)}"/>`;
      acc += n;
    });
  }
  const ticks = 6; let xt = '';
  for (let i = 0; i <= ticks; i++) {
    const t = t0 + (t1 - t0) * i / ticks;
    xt += `<text x="${x(t)}" y="${H - 8}" text-anchor="${i === 0 ? 'start' : i === ticks ? 'end' : 'middle'}">${fmtDay(t)}</text>`;
  }
  el.innerHTML = `<div class="chart"><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Events over time">${g}${bars}<g class="axis"><line x1="${L}" x2="${W - R}" y1="${H - B}" y2="${H - B}"/></g>${xt}<rect class="sel" id="selrect" x="0" y="${T}" width="0" height="${H - T - B}" style="display:none"/></svg></div>
    <div class="legend">${groups.map((gr, i) => `<span><i style="background:${groupColor(gr, i)}"></i>${esc(gr)}</span>`).join('')}<span class="muted">bucket: ${esc(data.bucket_label)}</span></div>`;

  const svg = $('svg', el), rect = $('#selrect', el);
  const toT = ev => {
    const r = svg.getBoundingClientRect();
    const px = (ev.clientX - r.left) / r.width * W;
    return Math.min(t1, Math.max(t0, t0 + (px - L) / (W - L - R) * (t1 - t0)));
  };
  let dragA = null;
  svg.addEventListener('pointerdown', ev => { dragA = toT(ev); svg.setPointerCapture(ev.pointerId); hideTip(); });
  svg.addEventListener('pointermove', ev => {
    const t = toT(ev);
    if (dragA !== null) {
      const a = Math.min(dragA, t), b = Math.max(dragA, t);
      rect.style.display = ''; rect.setAttribute('x', x(a)); rect.setAttribute('width', Math.max(1, x(b) - x(a)));
      return;
    }
    const bt = Math.floor((t - t0) / size) * size + t0;
    const c = byT.get(bt);
    if (!c) return hideTip();
    const rows = groups.map((gr, i) => c[gr] ? `<div><i style="display:inline-block;width:8px;height:8px;border-radius:2px;background:${groupColor(gr, i)};margin-right:6px"></i>${esc(gr)}: ${fmtN(c[gr])}</div>` : '').join('');
    showTip(ev.clientX, ev.clientY, `<b>${esc(fmtMin(bt))}</b>${rows}`);
  });
  svg.addEventListener('pointerleave', hideTip);
  svg.addEventListener('pointerup', ev => {
    if (dragA === null) return;
    const a = Math.min(dragA, toT(ev)), b = Math.max(dragA, toT(ev));
    const moved = Math.abs(x(b) - x(a)) > 4;
    dragA = null;
    if (moved && opts.onSelect) opts.onSelect(Math.floor(a), Math.ceil(b));
    else rect.style.display = 'none';
  });
}

/* ---------- horizontal bars */
function barsHtml(items, opts = {}) {
  const max = Math.max(...items.map(i => i.n), 1);
  if (!items.length) return '<div class="empty">No data</div>';
  return `<div class="bars">${items.map(i => `<button class="bar" data-key="${esc(i.key)}" style="--c:${i.severity ? sevColor(i.severity) : 'var(--accent)'}" title="${esc(i.label)}: ${fmtN(i.n)}">
    <span class="lab">${opts.mono ? `<span class="mono">${esc(i.label)}</span>` : esc(i.label)}</span>
    <span class="track"><span class="fill" style="display:block;width:${(i.n / max * 100).toFixed(1)}%"></span></span>
    <span class="val">${fmtN(i.n)}</span></button>`).join('')}</div>`;
}
