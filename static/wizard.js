/* Wizard mode (demo): one button on the Users page that creates and works cases for all open alerts at once. */
let WIZ = {};

async function wizPaint() {
  const box = $('#wizpanel'); if (!box) return;
  try { WIZ = await api('/api/wizard'); } catch (_) { return; }
  const w = WIZ;
  box.innerHTML = `<h2>Wizard mode (demo)</h2>
    <p style="margin-top:0">For demonstrations. It plays an analyst: it makes cases from all open alerts, works through each checklist, writes notes from the real event data and closes most of the cases. Some stay open or waiting, as in real life. It acts at once and leaves no entries in the audit log. Events are never touched. <b>Remove demo cases</b> undoes the run; <b>Keep these cases</b> makes them permanent, after which they cannot be removed in one go.</p>
    <div class="note ${w.pending_alerts ? '' : 'ok'}" style="margin:0 0 12px">
      ${w.pending_alerts ? `${fmtN(w.pending_alerts)} open alerts without a case, in ${fmtN(w.pending_groups)} groups.` : 'No open alert without a case.'}
      ${w.cases_total ? `<br>${fmtN(w.cases_total)} demo cases: ${fmtN(w.cases_closed)} closed, ${fmtN(w.cases_waiting)} waiting, ${fmtN(w.cases_active)} in work.` : ''}</div>
    <p style="margin:0"><button class="btn primary" id="wz-start" ${w.pending_alerts ? '' : 'disabled'}>Create demo cases now</button>
      <button class="btn" id="wz-keep" ${w.cases_total ? '' : 'disabled'}>Keep these cases</button>
      <button class="btn danger" id="wz-reset" ${w.cases_total ? '' : 'disabled'}>Remove demo cases</button></p>`;
}

async function mountWizard() {
  const box = $('#wizpanel'); if (!box) return;
  box.onclick = async e => {
    const id = e.target.id;
    try {
      if (id === 'wz-start') {
        e.target.disabled = true; e.target.textContent = 'Working…';
        const r = await api('/api/wizard/start', { method: 'POST', json: {} });
        toast(`${r.created} demo case(s) created and worked`);
      } else if (id === 'wz-keep') {
        if (!confirm('Make the generated cases permanent? They become ordinary cases and Remove demo cases no longer touches them. This is recorded in the audit log.')) return;
        const r = await api('/api/wizard/keep', { method: 'POST', json: {} }); toast(`${r.kept} case(s) are now permanent`);
      } else if (id === 'wz-reset') {
        if (!confirm('Delete every case made by wizard mode and put the alerts it handled back to New?')) return;
        const r = await api('/api/wizard/reset', { method: 'POST' }); toast(`${r.removed} demo case(s) removed, ${r.alerts_reset} alert(s) reset`);
      } else return;
      refreshChrome(); await wizPaint();
    } catch (err) { toast(err.message, true); await wizPaint(); }
  };
  await wizPaint();
}
