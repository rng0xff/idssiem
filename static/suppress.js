/* Suppression rules: hide known-benign alert patterns, with a reason and an expiry. */
const SUP_DAYS = [[30, '30 days'], [90, '90 days'], [180, '180 days'], [365, '1 year'], [0, 'No expiry']];

async function openSuppressForm(alertId) {
  const [a, rulesList] = await Promise.all([alertId ? api('/api/alerts/' + alertId) : Promise.resolve(null), api('/api/rules')]);
  const title = a ? 'Suppress similar alerts' : 'New suppression rule';
  openDrawer(esc(title), `
    ${a ? `<p style="margin:0 0 10px">${sevHtml(a.severity)} ${esc(a.title)}${a.vin ? ` <span class="muted mono">${esc(a.vin)}</span>` : ''}</p>` : ''}
    <p class="muted" style="margin-top:0">Alerts that match every filled field below are hidden from the open list and shown on the Suppressed tab. Leave a field empty to match anything. Alerts someone already works on (in progress or in a case) are not touched.</p>
    <label class="field"><span>Detection</span><select id="sp-rule"><option value="">Any detection</option>${rulesList.map(r => `<option value="${esc(r.id)}" ${a && a.rule === r.id ? 'selected' : ''}>${esc(r.title)}</option>`).join('')}</select></label>
    <label class="field"><span>ECU</span><input type="text" id="sp-ecu" value="${esc(a ? a.ecu_name || '' : '')}" placeholder="Any ECU"></label>
    <label class="field"><span>Event type</span><input type="text" id="sp-cat" class="mono" value="${esc(a ? a.cat_id || '' : '')}" placeholder="Any event type"></label>
    <label class="field"><span>Vehicle (VIN)</span><input type="text" id="sp-vin" class="mono" maxlength="17" value="" placeholder="All vehicles"></label>
    ${a && a.vin ? `<p style="margin:-6px 0 12px"><button class="btn small" id="sp-thisvin" type="button">Only this vehicle</button></p>` : ''}
    <label class="field"><span>Reason</span><textarea id="sp-reason" rows="3" placeholder="Why is this safe to ignore? Everyone who sees a suppressed alert reads this."></textarea></label>
    <label class="field"><span>Expires after</span><select id="sp-days">${SUP_DAYS.map(([d, t]) => `<option value="${d}" ${d === 90 ? 'selected' : ''}>${t}</option>`).join('')}</select></label>
    <p style="margin:0"><button class="btn primary" id="sp-go">Create rule</button> <button class="btn" data-act="close-drawer">Cancel</button></p>`);
  const tv = $('#sp-thisvin'); if (tv) tv.addEventListener('click', () => { $('#sp-vin').value = a.vin; });
  $('#sp-go').addEventListener('click', async () => {
    try {
      const r = await api('/api/suppressions', { method: 'POST', json: { rule: $('#sp-rule').value, ecu_name: $('#sp-ecu').value.trim(), cat_id: $('#sp-cat').value.trim(), vin: $('#sp-vin').value.trim(), reason: $('#sp-reason').value, days: +$('#sp-days').value } });
      closeDrawer(); toast(`Rule created. ${fmtN(r.detections.suppressed)} alert(s) suppressed.`); refreshChrome();
      if (window.__reloadAlerts && parseHash().name === 'alerts') window.__reloadAlerts();
      if (parseHash().name === 'detections') renderSuppressions();
    } catch (e) { toast(e.message, true); }
  });
}

async function renderSuppressions() {
  const box = $('#suppanel'); if (!box) return;
  const list = await api('/api/suppressions');
  const can = ME && ME.level >= 2;
  const scope = s => [
    s.rule ? `<span class="chip">${esc(s.rule_title)}</span>` : '', s.ecu_name ? `<span class="chip">ECU ${esc(s.ecu_name)}</span>` : '',
    s.cat_id ? `<span class="chip">${esc(s.event_name || s.cat_id)}</span>` : '', s.vin ? `<span class="chip mono">${esc(s.vin)}</span>` : ''].join(' ');
  const state = s => s.expired ? '<span class="status closed">expired</span>' : s.enabled ? '<span class="status resolved">active</span>' : '<span class="status suppressed">off</span>';
  box.innerHTML = `<div class="page-head" style="margin-bottom:6px"><h2 style="margin:0">Suppression rules</h2><span class="spacer"></span>${can ? '<button class="btn small primary" id="sp-new">New rule</button>' : ''}</div>
    <p class="muted" style="margin-top:0">Hide alerts for known-benign patterns. Suppressed alerts stay on the Alerts page under Suppressed and come back as new when a rule is switched off, deleted or expires.</p>
    ${list.length ? `<div class="tablewrap"><table><thead><tr><th>Applies to</th><th>Reason</th><th>Created by</th><th>Expires</th><th class="num">Alerts now</th><th>State</th><th></th></tr></thead><tbody>
    ${list.map(s => `<tr><td>${scope(s)}</td><td>${esc(s.reason)}</td><td class="nowrap">${esc(s.created_by)}<div class="muted">${esc(fmtDay(s.created_at))}</div></td><td class="nowrap">${s.expires_at ? esc(fmtDay(s.expires_at)) : 'never'}</td><td class="num"><a href="${hashFor('alerts', { tab: 'suppressed' })}">${fmtN(s.alerts_now)}</a></td><td>${state(s)}</td>
      <td class="nowrap">${can ? `<button class="btn small" data-sp="${s.enabled ? 'off' : 'on'}" data-id="${s.id}">${s.enabled ? 'Switch off' : 'Switch on'}</button> <button class="btn small danger" data-sp="del" data-id="${s.id}">Delete</button>` : ''}</td></tr>`).join('')}</tbody></table></div>`
      : '<div class="empty">No suppression rules. Open an alert and choose Suppress similar alerts.</div>'}`;
  const nb = $('#sp-new'); if (nb) nb.addEventListener('click', () => openSuppressForm(null).catch(e => toast(e.message, true)));
  box.onclick = async e => {
    const b = e.target.closest('[data-sp]'); if (!b) return;
    try {
      if (b.dataset.sp === 'del') { if (!confirm('Delete this suppression rule? Alerts it hides come back as new.')) return; await api('/api/suppressions/' + b.dataset.id, { method: 'DELETE' }); }
      else await api('/api/suppressions/' + b.dataset.id, { method: 'PATCH', json: { enabled: b.dataset.sp === 'on' } });
      refreshChrome(); renderSuppressions();
    } catch (err) { toast(err.message, true); }
  };
}
