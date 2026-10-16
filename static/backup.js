/* Backup and restore panel on the Data page (administrator). */
const fmtMB = n => n >= 1073741824 ? (n / 1073741824).toFixed(2) + ' GB' : (n / 1048576).toFixed(1) + ' MB';

async function mountBackup() {
  const box = $('#backuppanel');
  if (!box) return;
  if (!ME || ME.role !== 'admin') { box.hidden = true; return; }
  let r;
  try { r = await api('/api/backups'); } catch (e) { box.innerHTML = `<h2>Backup and restore</h2><p class="note err">${esc(e.message)}</p>`; return; }
  box.innerHTML = `<h2>Backup and restore</h2>
    <p style="margin-top:0">A backup is a consistent copy of the whole database: events, alerts, cases, experts, settings, users and the audit log. It can be made while the tool is running. Backups are kept in <span class="mono">${esc(r.folder)}</span>.</p>
    <p class="note warn" style="margin:0 0 10px"><b>Handle backup files like the database itself.</b> They contain password hashes, API tokens and authenticator secrets.</p>
    <p style="margin:0 0 10px"><button class="btn primary" id="bk-create">Create backup now</button>
      <label class="btn" style="cursor:pointer">Restore from a file...<input type="file" id="bk-file" accept=".db,.sqlite,.sqlite3" hidden></label></p>
    ${r.backups.length ? `<div class="tablewrap"><table><thead><tr><th>Backup</th><th>Created (UTC)</th><th class="num">Size</th><th></th></tr></thead><tbody>${r.backups.map(b => `<tr><td class="mono">${esc(b.name)}</td><td class="nowrap mono">${esc(fmtMin(b.created_at))}</td><td class="num">${fmtMB(b.size)}</td>
      <td class="nowrap"><a class="btn small" href="/api/backups/${encodeURIComponent(b.name)}/download">Download</a> <button class="btn small" data-bkrestore="${esc(b.name)}">Restore</button> <button class="btn ghost small danger" data-bkdel="${esc(b.name)}" aria-label="Delete ${esc(b.name)}">Delete</button></td></tr>`).join('')}</tbody></table></div>` : '<p class="muted" style="margin:0">No backup yet.</p>'}
    <p class="muted" style="margin-bottom:0">Restoring replaces everything with the backup. The current state is saved first as a <i>before-restore</i> backup, so a restore can be undone. Everybody has to sign in again afterwards. On the command line: <span class="mono">python idssiem.py --backup</span> and <span class="mono">python idssiem.py --restore FILE</span> (stop the server first).</p>`;

  const done = res => {
    closeDrawer();
    const s = res.restored;
    showAuth(false, `Database restored (${fmtN(s.events)} events, ${s.cases} cases). Sign in again.`);
  };
  const confirmRestore = (title, what, run) => {
    openDrawer(title, `<p>${what}</p><p class="note warn">This replaces all events, alerts, cases, settings and users. The current state is saved as a before-restore backup first.</p>
      <label class="field"><span>Type RESTORE to confirm</span><input type="text" id="bk-conf" autocomplete="off"></label>
      <p style="margin:0"><button class="btn danger" id="bk-go">Restore</button> <button class="btn" data-act="close-drawer">Cancel</button></p>`);
    $('#bk-go').addEventListener('click', async () => {
      if ($('#bk-conf').value !== 'RESTORE') { toast('Type RESTORE to confirm', true); return; }
      $('#bk-go').disabled = true;
      try { done(await run()); } catch (e) { $('#bk-go').disabled = false; toast(e.message, true); }
    });
  };
  $('#bk-create').addEventListener('click', async e => {
    e.target.disabled = true;
    try { const b = await api('/api/backups', { method: 'POST' }); toast(`Backup ${b.name} created (${fmtMB(b.size)})`); mountBackup(); } catch (err) { toast(err.message, true); e.target.disabled = false; }
  });
  $('#bk-file').addEventListener('change', e => {
    const f = e.target.files[0]; if (!f) return; e.target.value = '';
    confirmRestore('Restore from a file', `Restore the database from <b>${esc(f.name)}</b> (${fmtMB(f.size)})?`,
      () => api('/api/backups/upload-restore?confirm=RESTORE', { method: 'POST', body: f }));
  });
  box.onclick = async e => {
    const rs = e.target.closest('[data-bkrestore]'), dl = e.target.closest('[data-bkdel]');
    if (rs) { const n = rs.dataset.bkrestore; confirmRestore('Restore a backup', `Restore the database from <b>${esc(n)}</b>?`, () => api(`/api/backups/${encodeURIComponent(n)}/restore`, { method: 'POST', json: { confirm: 'RESTORE' } })); }
    if (dl) { const n = dl.dataset.bkdel; if (confirm(`Delete the backup ${n}? This cannot be undone.`)) { try { await api(`/api/backups/${encodeURIComponent(n)}`, { method: 'DELETE' }); toast('Backup deleted'); mountBackup(); } catch (err) { toast(err.message, true); } } }
  };
}
