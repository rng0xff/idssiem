/* "Sync from CycurGUARD" panel on the Data page. Polls the server while a sync runs in the background. */
'use strict';

let syncWasRunning = false;

function syncPanelShell() {
  return '<div class="panel" id="syncpanel"><h2>Sync from CycurGUARD</h2><div id="syncbody"><div class="empty">Loading…</div></div></div>';
}

async function mountSync() {
  clearTimeout(window.__syncTimer);
  syncWasRunning = false;
  await refreshSync();
}

async function refreshSync() {
  const box = $('#syncbody');
  if (!box) return;  // left the Data page
  let s;
  try { s = await api('/api/sync/status'); } catch (e) { box.innerHTML = `<p class="note err">${esc(e.message)}</p>`; return; }
  drawSync(s);
  const running = s.state.running;
  if (syncWasRunning && !running) {
    if (s.state.error) toast('Sync stopped: ' + s.state.error, true);
    else if (s.state.result) toast(`Sync finished: ${fmtN(s.state.result.rows_new)} new events`);
    refreshChrome();
  }
  syncWasRunning = running;
  if (running) window.__syncTimer = setTimeout(refreshSync, 1500);
}

function drawSync(s) {
  const box = $('#syncbody');
  if (!box) return;
  const st = s.state, canRun = ME.level >= 2;
  if (!s.configured) {
    box.innerHTML = `<p style="margin:0">The backend is not set up yet. ${ME.role === 'admin' ? 'Enter its address and an API token on the <a href="#/users">Users page</a>.' : 'An administrator can set it up on the Users page.'}</p>`;
    return;
  }
  const last = s.last_run ? `Last sync ${esc(fmtMin(s.last_run))} UTC${s.last_result ? `: ${fmtN(s.last_result.rows_new)} new, ${fmtN(s.last_result.rows_duplicate)} already present` : ''}.` : 'Never synced yet.';
  const pos = s.cursor_ms ? ` Data received by the backend up to ${esc(fmtMin(s.cursor_ms))} UTC is in.` : '';
  let body = `<p style="margin-top:0">Pulling from <b>${esc(s.base_url)}</b>. ${last}${pos}</p>`;
  if (st.running) {
    const pct = st.total ? Math.min(100, Math.round(st.fetched / st.total * 100)) : 0;
    body += `<span class="progress big" role="img" aria-label="${pct} percent"><span style="width:${pct}%"></span></span>
      <p class="muted">${esc(st.phase === 'counting' ? 'Counting events…' : st.phase === 'detecting' ? 'Running detections…'
        : `Downloading: ${fmtN(st.fetched)}${st.total != null ? ` of about ${fmtN(st.total)}` : ''} events seen, ${fmtN(st.new)} new, ${fmtN(st.duplicate)} already present${st.matched ? `, ${fmtN(st.matched)} matched to earlier file imports` : ''}.`)}</p>
      <p style="margin:0"><button class="btn danger" id="sync-cancel" ${canRun ? '' : 'disabled'}>Stop</button> <span class="muted">Stopping keeps what is already downloaded. The next sync continues from there.</span></p>`;
  } else {
    if (st.error) body += `<p class="note err" role="alert"><b>The last sync stopped.</b> ${esc(st.error)}</p>`;
    body += `<div class="params">${s.cursor_ms ? '' : `<label>First sync covers<select id="sync-days" style="width:170px"><option value="30">the last 30 days</option><option value="90" selected>the last 90 days</option><option value="365">the last year</option><option value="">everything</option></select></label>`}
      <label>&nbsp;<span><button class="btn" id="sync-check" ${canRun ? '' : 'disabled'}>Check connection</button> <button class="btn primary" id="sync-go" ${canRun ? '' : 'disabled'}>Sync now</button></span></label></div>
      <div id="sync-out"></div>
      <p class="muted" style="margin-bottom:0">Events already stored are recognised by the backend's own id, so syncing twice never doubles anything. Events you imported from a file earlier are matched to their backend copy once.</p>`;
  }
  box.innerHTML = body;
  const days = () => { const d = $('#sync-days'); return d ? (d.value || null) : null; };
  const go = $('#sync-go'), chk = $('#sync-check'), stop = $('#sync-cancel');
  if (chk) chk.addEventListener('click', async () => {
    const out = $('#sync-out'); out.innerHTML = '<p class="muted">Asking the backend…</p>';
    try {
      const p = await api('/api/sync/preview', { method: 'POST', json: { days: days() } });
      out.innerHTML = `<div class="note ok" style="margin:12px 0"><b>Connected.</b> Backend version ${esc(p.version)}. ${esc(p.mode.charAt(0).toUpperCase() + p.mode.slice(1))}: <b>${fmtN(p.total)}</b> events would be pulled.</div>
        ${p.sample.length ? `<div class="tablewrap"><table><thead><tr><th>Type</th><th>Event</th><th>ECU</th><th>VIN</th><th>Event time</th></tr></thead><tbody>${p.sample.map(r => `<tr><td>${esc(r.event_type)}</td><td>${esc(r.name)}</td><td>${esc(r.ecu_name)}</td><td class="mono">${esc(r.vin)}</td><td class="nowrap mono">${r.ts ? esc(fmtTs(r.ts)) : '<span class="muted">none</span>'}</td></tr>`).join('')}</tbody></table></div><p class="muted">The first events the backend would send, to check the mapping.</p>` : ''}`;
    } catch (e) { out.innerHTML = `<p class="note err" role="alert" style="margin:12px 0">${esc(e.message)}</p>`; }
  });
  if (go) go.addEventListener('click', async () => {
    try { await api('/api/sync/start', { method: 'POST', json: { days: days() } }); syncWasRunning = true; refreshSync(); } catch (e) { toast(e.message, true); }
  });
  if (stop) stop.addEventListener('click', async () => { try { await api('/api/sync/cancel', { method: 'POST', json: {} }); toast('Stopping after the current page'); } catch (e) { toast(e.message, true); } });
}
