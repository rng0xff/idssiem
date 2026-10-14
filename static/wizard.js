/* Wizard mode (demo): panel on the Users page, header chip and live refresh while it runs. */
let WIZ = { enabled: false };

function wizChip() {
  const c = $('#wizchip'); if (c) c.hidden = !WIZ.enabled;
}

async function wizPoll() {
  if (!ME) { WIZ = { enabled: false }; wizChip(); return; }
  try { WIZ = await api('/api/wizard'); } catch (_) { return; }
  wizChip();
  if ($('#wizpanel')) wizPaint();
  if (WIZ.enabled) {
    refreshChrome();
    const n = parseHash(), busy = $('#drawer').classList.contains('on') || /^(INPUT|TEXTAREA|SELECT)$/.test((document.activeElement || {}).tagName || '');
    if (!busy && ((n.name === 'overview') || (n.name === 'cases' && !n.arg) || (n.name === 'alerts' && !n.arg))) render();
  }
}
setInterval(wizPoll, 4000);

function wizPaint() {
  const box = $('#wizpanel'); if (!box) return;
  const w = WIZ, sp = w.speeds || { fast: 2, normal: 5, slow: 15 };
  const sel = box.querySelector('#wz-speed') ? box.querySelector('#wz-speed').value : (w.speed || 'normal');
  const label = { fast: 'Fast', normal: 'Normal', slow: 'Slow' };
  const eta = k => { const steps = (w.pending_groups || 0) * 8; const m = steps * sp[k] / 60; return m < 1 ? 'under a minute' : `about ${Math.round(m)} min`; };
  box.innerHTML = `<h2>Wizard mode (demo)</h2>
    <p style="margin-top:0">For demonstrations. It plays an analyst: it makes cases from all open alerts, works through each checklist, writes notes from the real event data and closes most of the cases. Some stay open or waiting, as in real life. Events are never touched. Everything it does is labelled <b>Wizard (demo)</b> and recorded in the audit log, and <b>Remove demo cases</b> undoes it.</p>
    <div class="note ${w.enabled ? 'ok' : ''}" style="margin:0 0 12px">
      ${w.enabled ? `<b>Running.</b> One step every ${w.seconds_per_step} s.` : '<b>Off.</b>'}
      ${w.cases_total ? ` ${fmtN(w.cases_total)} demo cases so far: ${fmtN(w.cases_closed)} closed, ${fmtN(w.cases_waiting)} waiting, ${fmtN(w.cases_active)} in work.` : ''}
      ${w.pending_alerts ? `<br>${fmtN(w.pending_alerts)} open alerts still without a case, in ${fmtN(w.pending_groups)} groups.` : '<br>No open alert without a case.'}
      ${w.enabled && w.pending_alerts ? ` About ${w.eta_minutes} minutes to go.` : ''}
      ${w.last_action ? `<div class="muted">Last step: ${esc(w.last_action)}</div>` : ''}
      ${w.last_error ? `<div class="err" role="alert">Last error: ${esc(w.last_error)}</div>` : ''}</div>
    <p style="margin:0"><label>Speed <select id="wz-speed" ${w.enabled ? 'disabled' : ''}>${Object.keys(sp).map(k => `<option value="${k}" ${k === sel ? 'selected' : ''}>${label[k]}: ${sp[k]} s per step, ${eta(k)} for the current alerts</option>`).join('')}</select></label>
      ${w.enabled ? '<button class="btn primary" id="wz-stop">Stop wizard mode</button>' : '<button class="btn primary" id="wz-start">Start wizard mode</button>'}
      <button class="btn danger" id="wz-reset" ${w.enabled || !w.cases_total ? 'disabled' : ''}>Remove demo cases</button></p>`;
}

async function mountWizard() {
  const box = $('#wizpanel'); if (!box) return;
  box.onclick = async e => {
    const id = e.target.id;
    try {
      if (id === 'wz-start') { WIZ = await api('/api/wizard/start', { method: 'POST', json: { speed: $('#wz-speed').value } }); toast('Wizard mode is on'); }
      else if (id === 'wz-stop') { WIZ = await api('/api/wizard/stop', { method: 'POST' }); toast('Wizard mode is off'); }
      else if (id === 'wz-reset') {
        if (!confirm('Delete every case made by wizard mode and put the alerts it handled back to New?')) return;
        const r = await api('/api/wizard/reset', { method: 'POST' }); toast(`${r.removed} demo case(s) removed, ${r.alerts_reset} alert(s) reset`); refreshChrome(); await wizPoll(); return;
      } else return;
      wizChip(); wizPaint(); refreshChrome();
    } catch (err) { toast(err.message, true); }
  };
  await wizPoll(); wizPaint();
}
