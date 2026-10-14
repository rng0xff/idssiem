/* Sign-in, account (own password and API tokens) and the administrator's user management. */
'use strict';

const ROLE_ORDER = ['viewer', 'analyst', 'admin'];
const PERM_LEVEL = { view: 1, modify: 2, full: 3 };
const PERM_TEXT = { view: 'View: read only', modify: 'Modify: read and triage, import', full: 'Full: as the owner (admin tasks need an admin)' };
const fmtExp = ms => ms ? fmtDay(ms) : 'never';
const stateHtml = s => `<span class="status ${s === 'active' ? 'resolved' : s === 'revoked' ? 'false_positive' : 'new'}">${esc(s)}</span>`;

/* ---------------------------------------------------------------- boot and sign-in */
async function boot() {
  let st;
  try { st = await api('/api/auth/status'); }
  catch (e) { document.body.classList.add('locked'); $('#auth').innerHTML = `<div class="authbox"><h1>Fleet IDS</h1><p class="note err">${esc(e.message)}</p></div>`; return; }
  if (st.user) startSession(st.user); else showAuth(st.setup_needed);
}

function showAuth(setup, msg) {
  ME = null;
  $('#toast').className = '';
  document.body.classList.add('locked');
  closeDrawer();
  $('#auth').innerHTML = `<form class="authbox" id="authform" autocomplete="on">
    <img class="logo" alt="INEOS" src="/assets/ineos-logo.png"><h1>Fleet IDS</h1>
    ${setup ? '<p class="muted" style="margin-top:0">Nobody has an account yet. Create the first administrator. You can add analysts and viewers afterwards.</p>' : ''}
    ${msg ? `<p class="note" role="alert">${esc(msg)}</p>` : ''}
    <label class="field"><span>Username</span><input type="text" id="au-user" autocomplete="username" required autofocus></label>
    ${setup ? '<label class="field"><span>Display name</span><input type="text" id="au-name" autocomplete="name" placeholder="Used for notes and case history"></label>' : ''}
    <label class="field"><span>Password</span><input type="password" id="au-pw" autocomplete="${setup ? 'new-password' : 'current-password'}" required></label>
    ${setup ? '<label class="field"><span>Repeat password</span><input type="password" id="au-pw2" autocomplete="new-password" required></label>' : ''}
    <p class="note err" id="au-err" role="alert" hidden></p>
    <button class="btn primary" type="submit" style="width:100%">${setup ? 'Create administrator' : 'Sign in'}</button></form>`;
  $('#authform').addEventListener('submit', async e => {
    e.preventDefault();
    const err = $('#au-err'); err.hidden = true;
    try {
      if (setup && $('#au-pw').value !== $('#au-pw2').value) throw new Error('The two passwords differ');
      const body = { username: $('#au-user').value.trim(), password: $('#au-pw').value };
      if (setup) body.display_name = $('#au-name').value.trim();
      const r = await api(setup ? '/api/auth/setup' : '/api/auth/login', { method: 'POST', json: body });
      const st = await api('/api/auth/status');
      startSession(st.user || r.user);
    } catch (ex) { err.textContent = ex.message; err.hidden = false; $('#au-pw').value = ''; if ($('#au-pw2')) $('#au-pw2').value = ''; $('#au-pw').focus(); }
  });
}

async function startSession(user) {
  ME = user;
  document.body.classList.remove('locked');
  document.body.dataset.role = user.role;
  $('#whoami').innerHTML = `<a href="#/account" title="Your account and API tokens"><b>${esc(user.display_name || user.username)}</b></a> <span class="rolechip ${esc(user.role)}">${esc(user.role)}</span>`;
  $$('[data-admin]').forEach(n => { n.hidden = user.role !== 'admin'; });
  try { $('#userlist').innerHTML = (await api('/api/users/names')).map(n => `<option value="${esc(n)}">`).join(''); } catch (_) { /* ignore */ }
  if (!location.hash) location.hash = '#/overview';
  render();
}

document.addEventListener('click', async e => {
  if (!e.target.closest('#btn-logout')) return;
  try { await api('/api/auth/logout', { method: 'POST', json: {} }); } catch (_) { /* already signed out */ }
  location.hash = '#/overview';
  showAuth(false);
});

/* ---------------------------------------------------------------- account */
const tokListHtml = toks => toks.length ? `<div class="tablewrap"><table><thead><tr><th>Name</th><th>Token</th><th>Permission</th><th>Created</th><th>Expires</th><th>Last used</th><th>State</th><th></th></tr></thead><tbody>
  ${toks.map(t => `<tr><td>${esc(t.name)}</td><td class="mono">ids_…${esc(t.preview)}</td><td>${esc(t.perm)}</td><td class="nowrap">${fmtDay(t.created_at)}</td><td class="nowrap">${fmtExp(t.expires_at)}</td><td class="nowrap">${t.last_used ? fmtDay(t.last_used) : '<span class="muted">never</span>'}</td><td>${stateHtml(t.state)}</td><td>${t.state === 'active' ? `<button class="btn small danger" data-revoke="${t.id}">Revoke</button>` : ''}</td></tr>`).join('')}</tbody></table></div>` : '<div class="empty">You have no tokens.</div>';

ROUTES.account = async function () {
  const [pol, toks] = await Promise.all([api('/api/auth/policy'), api('/api/tokens')]);
  const allowed = Object.keys(PERM_LEVEL).filter(p => PERM_LEVEL[p] <= ROLE_ORDER.indexOf(ME.role) + 1);
  view.innerHTML = `<div class="page-head"><h1>Account</h1></div>
  <div class="panel"><h2>${esc(ME.display_name || ME.username)}</h2>
    <p style="margin:0">Signed in as <b>${esc(ME.username)}</b> with the <span class="rolechip ${esc(ME.role)}">${esc(ME.role)}</span> role.</p></div>
  <div class="panel"><h2>Change password</h2><div class="params">
    <label>Current password<input type="password" id="pw-old" autocomplete="current-password"></label>
    <label>New password<input type="password" id="pw-new" autocomplete="new-password"></label>
    <label>Repeat<input type="password" id="pw-new2" autocomplete="new-password"></label></div>
    <p class="muted">At least ${pol.min_password_length} characters. Your other sessions are signed out.</p>
    <p style="margin:0"><button class="btn" id="pw-save">Change password</button></p></div>
  <div class="panel"><h2>API tokens</h2>
    <p style="margin-top:0">A token lets a script or another tool call this application's API as you, without your password. It can never do more than your role, and it cannot create tokens or change passwords.</p>
    ${pol.tokens_enabled ? `<div class="params">
      <label>Name<input type="text" id="tk-name" placeholder="What is it for?" style="width:200px"></label>
      <label>Permission<select id="tk-perm" style="width:260px">${allowed.map(p => `<option value="${p}">${esc(PERM_TEXT[p])}</option>`).join('')}</select></label>
      <label>Valid for (days)<input type="number" id="tk-days" min="${pol.token_max_days ? 1 : 0}" max="${pol.token_max_days || 3650}" value="${pol.token_default_days}"></label>
      <label>&nbsp;<button class="btn primary" id="tk-create">Create token</button></label></div>
    <p class="muted">${pol.token_max_days ? `Tokens expire. The longest lifetime your administrator allows is ${pol.token_max_days} days.` : 'The administrator allows tokens without an expiry date (enter 0).'}</p>
    <div id="tk-new"></div>` : '<p class="note">Your administrator has switched API tokens off.</p>'}
    <div id="tk-list">${tokListHtml(toks)}</div>
  </div>`;
  $('#pw-save').addEventListener('click', async () => {
    if ($('#pw-new').value !== $('#pw-new2').value) { toast('The two new passwords differ', true); return; }
    try { await api('/api/auth/password', { method: 'POST', json: { old_password: $('#pw-old').value, new_password: $('#pw-new').value } }); toast('Password changed'); render(); } catch (e) { toast(e.message, true); }
  });
  const cr = $('#tk-create');
  if (cr) cr.addEventListener('click', async () => {
    try {
      const t = await api('/api/tokens', { method: 'POST', json: { name: $('#tk-name').value, perm: $('#tk-perm').value, expires_days: $('#tk-days').value } });
      const url = `${location.origin}/api/summary`;
      $('#tk-new').innerHTML = `<div class="note" style="margin:0 0 14px"><b>Copy the token now. It is shown only once.</b>
        <div class="tokenbox"><code id="tk-val">${esc(t.token)}</code> <button class="btn small" id="tk-copy">Copy</button></div>
        <pre style="margin:8px 0 0">curl -H "Authorization: Bearer ${esc(t.token)}" ${esc(url)}</pre></div>`;
      $('#tk-copy').addEventListener('click', async () => { try { await navigator.clipboard.writeText(t.token); toast('Token copied'); } catch (_) { toast('Select the token and copy it by hand', true); } });
      $('#tk-name').value = '';
      $('#tk-list').innerHTML = tokListHtml(await api('/api/tokens'));
    } catch (e) { toast(e.message, true); }
  });
  view.onclick = async e => {
    const b = e.target.closest('[data-revoke]');
    if (b && confirm('Revoke this token? Anything using it stops working immediately.')) {
      try { await api('/api/tokens/' + b.dataset.revoke, { method: 'DELETE' }); toast('Token revoked'); render(); } catch (err) { toast(err.message, true); }
    }
  };
};

/* ---------------------------------------------------------------- administration */
ROUTES.users = async function () {
  if (ME.role !== 'admin') { view.innerHTML = '<div class="panel"><h2>Administrators only</h2><p>Your role does not include user management.</p></div>'; return; }
  const [ul, pol, be, alltok, audit] = await Promise.all([api('/api/users'), api('/api/auth/policy'), api('/api/backend'), api('/api/tokens?all=1'), api('/api/audit')]);
  const users = ul.users;
  view.innerHTML = `<div class="page-head"><h1>Users</h1><span class="spacer"></span><button class="btn primary" id="u-new">New user</button></div>
  <div class="panel"><h2>Accounts</h2><div class="tablewrap"><table><thead><tr><th>Username</th><th>Name</th><th>Role</th><th>Status</th><th class="num">Active tokens</th><th>Last sign-in</th></tr></thead><tbody>
    ${users.map(u => `<tr class="row" data-uid="${u.id}"><td class="mono">${esc(u.username)}</td><td>${esc(u.display_name)}</td><td>${esc(u.role)}</td>
      <td>${u.locked ? '<span class="status new">locked</span>' : u.active ? '<span class="status resolved">active</span>' : '<span class="status false_positive">inactive</span>'}</td>
      <td class="num">${u.tokens}</td><td class="nowrap">${u.last_login ? esc(fmtMin(u.last_login)) + ' UTC' : '<span class="muted">never</span>'}</td></tr>`).join('')}</tbody></table></div>
    <p class="muted" style="margin-bottom:0">Select an account to change its role, reset the password, deactivate or delete it.</p></div>
  <div class="panel"><h2>Roles</h2><div class="tablewrap"><table><tbody>${ROLE_ORDER.map(r => `<tr><td><span class="rolechip ${r}">${r}</span></td><td>${esc(ul.roles[r])}</td></tr>`).join('')}</tbody></table></div></div>
  <div class="panel"><h2>Sign-in and token rules</h2><div class="params">
    <label>Session ends after idle (hours)<input type="number" id="pl-sess" min="1" max="168" value="${pol.session_hours}"></label>
    <label>Minimum password length<input type="number" id="pl-pw" min="8" max="128" value="${pol.min_password_length}"></label>
    <label>Default token lifetime (days)<input type="number" id="pl-def" min="1" max="3650" value="${pol.token_default_days}"></label>
    <label>Longest token lifetime (days, 0 = no limit)<input type="number" id="pl-max" min="0" max="3650" value="${pol.token_max_days}"></label></div>
    <p style="margin:12px 0 0"><label><input type="checkbox" id="pl-on" ${pol.tokens_enabled ? 'checked' : ''}> Allow API tokens</label></p>
    <p class="muted">Switching tokens off stops every existing token at once. Changed lifetime limits apply to new tokens only.</p>
    <p style="margin:0"><button class="btn" id="pl-save">Save rules</button></p></div>
  <div class="panel"><h2>Backend connection</h2>
    <p style="margin-top:0">Address and API token of the vehicle backend, for the planned automatic pull. The token is stored on this computer and never shown again.</p>
    <div class="params"><label>Backend URL<input type="text" id="be-url" value="${esc(be.base_url)}" placeholder="https://ineos.cycurguard.etas.com" style="width:340px"></label>
    <label>API token<input type="password" id="be-tok" autocomplete="off" placeholder="${be.token_set ? `saved, ends in ${esc(be.token_preview || '····')}` : 'paste the token'}" style="width:260px"></label></div>
    ${be.token_set ? '<p style="margin:12px 0 0"><label><input type="checkbox" id="be-clear"> Remove the saved token</label></p>' : ''}
    <p style="margin:12px 0 0"><button class="btn" id="be-save">Save connection</button></p></div>
  <div class="panel"><h2>All API tokens</h2>${alltok.length ? `<div class="tablewrap"><table><thead><tr><th>Owner</th><th>Name</th><th>Token</th><th>Permission</th><th>Expires</th><th>Last used</th><th>State</th><th></th></tr></thead><tbody>
    ${alltok.map(t => `<tr><td>${esc(t.owner)}</td><td>${esc(t.name)}</td><td class="mono">ids_…${esc(t.preview)}</td><td>${esc(t.perm)}</td><td class="nowrap">${fmtExp(t.expires_at)}</td><td class="nowrap">${t.last_used ? fmtDay(t.last_used) : '<span class="muted">never</span>'}</td><td>${stateHtml(t.state)}</td><td>${t.state === 'active' ? `<button class="btn small danger" data-revoke="${t.id}">Revoke</button>` : ''}</td></tr>`).join('')}</tbody></table></div>` : '<div class="empty">No tokens yet.</div>'}</div>
  <div class="panel"><h2>Audit log</h2><div class="tablewrap" style="max-height:340px;overflow:auto"><table><thead><tr><th>When (UTC)</th><th>Who</th><th>What</th><th>Detail</th></tr></thead><tbody>
    ${audit.slice(0, 100).map(a => `<tr><td class="nowrap mono">${esc(fmtTs(a.ts))}</td><td>${esc(a.actor)}</td><td>${esc(a.action)}</td><td class="muted">${esc(a.detail)}</td></tr>`).join('')}</tbody></table></div></div>`;

  $('#u-new').addEventListener('click', () => userForm(null));
  $('#pl-save').addEventListener('click', async () => {
    try { await api('/api/auth/policy', { method: 'PUT', json: { session_hours: $('#pl-sess').value, min_password_length: $('#pl-pw').value, token_default_days: $('#pl-def').value, token_max_days: $('#pl-max').value, tokens_enabled: $('#pl-on').checked } }); toast('Rules saved'); render(); } catch (e) { toast(e.message, true); }
  });
  $('#be-save').addEventListener('click', async () => {
    try { await api('/api/backend', { method: 'PUT', json: { base_url: $('#be-url').value, token: $('#be-tok').value, clear_token: !!($('#be-clear') && $('#be-clear').checked) } }); toast('Connection saved'); render(); } catch (e) { toast(e.message, true); }
  });
  view.onclick = async e => {
    const r = e.target.closest('[data-revoke]');
    if (r) { if (confirm('Revoke this token?')) { try { await api('/api/tokens/' + r.dataset.revoke, { method: 'DELETE' }); toast('Token revoked'); render(); } catch (err) { toast(err.message, true); } } return; }
    const row = e.target.closest('[data-uid]');
    if (row) userForm(users.find(u => u.id === +row.dataset.uid));
  };
};

function userForm(u) {
  const roleOpts = sel => ROLE_ORDER.map(r => `<option value="${r}" ${r === sel ? 'selected' : ''}>${r}</option>`).join('');
  openDrawer(u ? esc(u.username) : 'New user', `
    <label class="field"><span>Username</span><input type="text" id="uf-user" value="${esc(u ? u.username : '')}" ${u ? '' : 'autofocus'} autocomplete="off"></label>
    <label class="field"><span>Display name</span><input type="text" id="uf-name" value="${esc(u ? u.display_name : '')}" placeholder="Shown in notes and case history" autocomplete="off"></label>
    <label class="field"><span>Role</span><select id="uf-role">${roleOpts(u ? u.role : 'analyst')}</select></label>
    <label class="field"><span>${u ? 'Set a new password (leave empty to keep)' : 'Password'}</span><input type="password" id="uf-pw" autocomplete="new-password"></label>
    ${u ? `<p><label><input type="checkbox" id="uf-active" ${u.active ? 'checked' : ''}> Account is active</label></p>
      ${u.locked ? '<p><label><input type="checkbox" id="uf-unlock"> Unlock (too many failed sign-ins)</label></p>' : ''}
      <p class="muted">Changing the role, the password or deactivating the account signs the person out everywhere.</p>` : '<p class="muted">Tell the person the password in person. They can change it under Account.</p>'}
    <p style="margin:0"><button class="btn primary" id="uf-save">${u ? 'Save' : 'Create user'}</button> <button class="btn" data-act="close-drawer">Cancel</button>
      ${u ? ' <button class="btn danger" id="uf-del" style="float:right">Delete</button>' : ''}</p>`);
  $('#uf-save').addEventListener('click', async () => {
    const body = { username: $('#uf-user').value.trim(), display_name: $('#uf-name').value.trim(), role: $('#uf-role').value };
    if ($('#uf-pw').value) body.password = $('#uf-pw').value;
    try {
      if (u) { body.active = $('#uf-active').checked; if ($('#uf-unlock')) body.unlock = $('#uf-unlock').checked; await api('/api/users/' + u.id, { method: 'PATCH', json: body }); }
      else await api('/api/users', { method: 'POST', json: body });
      closeDrawer(); toast(u ? 'User saved' : 'User created'); await startUserNames(); render();
    } catch (e) { toast(e.message, true); }
  });
  const d = $('#uf-del');
  if (d) d.addEventListener('click', async () => {
    if (!confirm(`Delete ${u.username}? Their tokens stop working. Notes and cases they wrote keep their name.`)) return;
    try { await api('/api/users/' + u.id, { method: 'DELETE' }); closeDrawer(); toast('User deleted'); await startUserNames(); render(); } catch (e) { toast(e.message, true); }
  });
}
async function startUserNames() {
  try { $('#userlist').innerHTML = (await api('/api/users/names')).map(n => `<option value="${esc(n)}">`).join(''); } catch (_) { /* ignore */ }
}
