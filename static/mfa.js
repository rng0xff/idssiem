/* Two-step sign-in: second step at the sign-in screen, passkey sign-in, and the Account panel to manage it. */
'use strict';

const pkSupported = () => !!(window.PublicKeyCredential && navigator.credentials);
const onLocalhost = () => location.hostname === 'localhost';
const b64uToBuf = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); s += '='.repeat((4 - s.length % 4) % 4); const bin = atob(s); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u.buffer; };
const bufToB64u = b => { let s = ''; new Uint8Array(b).forEach(x => { s += String.fromCharCode(x); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };

async function pkCreate(opts) {
  const pk = opts.publicKey;
  pk.challenge = b64uToBuf(pk.challenge);
  pk.user.id = b64uToBuf(pk.user.id);
  pk.excludeCredentials = (pk.excludeCredentials || []).map(c => ({ ...c, id: b64uToBuf(c.id) }));
  const c = await navigator.credentials.create({ publicKey: pk });
  return { id: c.id, rawId: bufToB64u(c.rawId), type: c.type, response: { clientDataJSON: bufToB64u(c.response.clientDataJSON), attestationObject: bufToB64u(c.response.attestationObject) } };
}
async function pkGet(opts) {
  const pk = opts.publicKey;
  pk.challenge = b64uToBuf(pk.challenge);
  pk.allowCredentials = (pk.allowCredentials || []).map(c => ({ ...c, id: b64uToBuf(c.id) }));
  const c = await navigator.credentials.get({ publicKey: pk });
  const r = c.response;
  return { id: c.id, rawId: bufToB64u(c.rawId), type: c.type, response: { clientDataJSON: bufToB64u(r.clientDataJSON), authenticatorData: bufToB64u(r.authenticatorData), signature: bufToB64u(r.signature), userHandle: r.userHandle ? bufToB64u(r.userHandle) : '' } };
}
const pkErr = e => e && e.name === 'NotAllowedError' ? 'The passkey request was cancelled or timed out.' : (e && e.message) || 'The passkey did not work.';

function qrSvg(rows) {
  const n = rows.length, q = 3;
  let d = '';
  rows.forEach((row, y) => { for (let x = 0; x < n; x++) if (row[x] === '1') d += `M${x + q} ${y + q}h1v1h-1z`; });
  return `<svg class="qr" viewBox="0 0 ${n + 2 * q} ${n + 2 * q}" shape-rendering="crispEdges" role="img" aria-label="QR code for the authenticator app"><rect width="100%" height="100%" fill="#fff"/><path d="${d}" fill="#000"/></svg>`;
}

/* ---------------------------------------------------------------- sign-in screen */
function showMfaStep(r, msg) {
  const hasPk = r.methods.includes('passkey') && pkSupported() && onLocalhost();
  const hasCode = r.methods.includes('totp') || r.methods.includes('recovery');
  $('#auth').innerHTML = `<form class="authbox" id="mfaform" autocomplete="off">
    <img class="logo" alt="INEOS" src="/assets/ineos-logo.png"><h1>Second step</h1>
    ${msg ? `<p class="note err" role="alert">${esc(msg)}</p>` : ''}
    ${hasCode ? `<label class="field"><span>${r.methods.includes('totp') ? 'Code from your authenticator app' : 'Recovery code'}</span><input type="text" id="mf-code" inputmode="text" autocomplete="one-time-code" autocapitalize="off" spellcheck="false" required autofocus></label>
      <p class="muted" style="margin:-6px 0 12px">${r.methods.includes('recovery') ? 'Lost your phone? Enter one of your recovery codes instead.' : ''}</p>` : ''}
    <p class="note err" id="mf-err" role="alert" hidden></p>
    ${hasCode ? '<button class="btn primary" type="submit" style="width:100%">Sign in</button>' : ''}
    ${hasPk ? `<button class="btn ${hasCode ? '' : 'primary'}" type="button" id="mf-pk" style="width:100%;margin-top:8px">Use a passkey</button>` : ''}
    ${r.methods.includes('passkey') && !hasPk ? '<p class="muted">Your passkey works at http://localhost only. Open the tool at that address, or use a recovery code.</p>' : ''}
    <p style="margin:14px 0 0;text-align:center"><a href="#" id="mf-back">Back to sign-in</a></p></form>`;
  const fail = m => { const e = $('#mf-err'); e.textContent = m; e.hidden = false; };
  const done = async () => { const st = await api('/api/auth/status'); startSession(st.user); };
  $('#mf-back').addEventListener('click', e => { e.preventDefault(); showAuth(false); });
  const f = $('#mfaform');
  f.addEventListener('submit', async e => {
    e.preventDefault();
    try { await api('/api/auth/mfa', { method: 'POST', json: { mfa_token: r.mfa_token, code: $('#mf-code').value } }); await done(); }
    catch (ex) { fail(ex.message); const c = $('#mf-code'); c.value = ''; c.focus(); }
  });
  const pk = $('#mf-pk');
  if (pk) pk.addEventListener('click', async () => {
    try {
      const opts = await api('/api/auth/passkey/options', { method: 'POST', json: { mfa_token: r.mfa_token } });
      const cred = await pkGet(opts);
      await api('/api/auth/passkey/verify', { method: 'POST', json: { credential: cred, mfa_token: r.mfa_token } });
      await done();
    } catch (ex) { fail(pkErr(ex)); }
  });
}

async function passkeySignIn() {
  const opts = await api('/api/auth/passkey/options', { method: 'POST', json: {} });
  const cred = await pkGet(opts);
  await api('/api/auth/passkey/verify', { method: 'POST', json: { credential: cred } });
  const st = await api('/api/auth/status');
  startSession(st.user);
}

/* ---------------------------------------------------------------- account panel */
function recoveryBox(codes) {
  return `<div class="note ok" style="margin:12px 0"><b>Save these recovery codes now. They are shown only once.</b>
    <p style="margin:6px 0">Each works once if you lose your phone or passkey. Keep them somewhere safe, apart from your password.</p>
    <pre class="reccodes" id="mf-codes">${codes.map(esc).join('\n')}</pre>
    <button class="btn small" id="mf-copy">Copy</button> <button class="btn small" id="mf-dl">Download .txt</button></div>`;
}
function wireRecovery(box, codes) {
  const c = box.querySelector('#mf-copy'), d = box.querySelector('#mf-dl');
  if (c) c.addEventListener('click', async () => { try { await navigator.clipboard.writeText(codes.join('\n')); toast('Codes copied'); } catch (_) { toast('Select the codes and copy them by hand', true); } });
  if (d) d.addEventListener('click', () => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([`Fleet IDS recovery codes for ${ME.username}\n\n${codes.join('\n')}\n`], { type: 'text/plain' }));
    a.download = 'fleet-ids-recovery-codes.txt'; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });
}

async function mountMfa(box) {
  let st;
  try { st = await api('/api/mfa'); } catch (e) { box.innerHTML = `<h2>Two-step sign-in</h2><p class="note err">${esc(e.message)}</p>`; return; }
  const pw = () => $('#mf-pw').value;
  box.innerHTML = `<h2>Two-step sign-in</h2>
    <p style="margin-top:0">${st.enabled ? 'On. After your password you also give a code or use a passkey.' : 'Off. Add a second step so a stolen password is not enough.'}
      ${st.required ? ' <b>Your administrator requires it.</b>' : ''}</p>
    ${ME.mfa_setup ? '<p class="note" role="alert"><b>Set it up now to continue.</b> Your administrator requires two-step sign-in. Add an authenticator app or a passkey below.</p>' : ''}
    <label class="field" style="max-width:320px"><span>Your password (needed for every change here)</span><input type="password" id="mf-pw" autocomplete="current-password"></label>
    <div id="mf-new"></div>
    <h3 style="margin:14px 0 6px">Authenticator app</h3>
    ${st.totp ? `<p style="margin:0"><span class="status resolved">on</span> since ${fmtDay(st.totp_since)} <button class="btn small danger" id="mf-totp-off">Remove</button></p>`
              : '<p style="margin:0">Works with any authenticator app (Microsoft Authenticator, Google Authenticator, 1Password, Aegis …). <button class="btn small" id="mf-totp-on">Set up</button></p>'}
    <div id="mf-totp-setup"></div>
    <h3 style="margin:14px 0 6px">Passkeys</h3>
    ${st.passkeys.length ? `<div class="tablewrap"><table><thead><tr><th>Name</th><th>Added</th><th>Last used</th><th></th></tr></thead><tbody>${st.passkeys.map(p => `<tr><td>${esc(p.name)}</td><td class="nowrap">${fmtDay(p.created_at)}</td><td class="nowrap">${p.last_used ? fmtDay(p.last_used) : '<span class="muted">never</span>'}</td><td><button class="btn small danger" data-pkdel="${p.id}">Remove</button></td></tr>`).join('')}</tbody></table></div>` : '<p class="muted" style="margin:0 0 8px">None yet.</p>'}
    ${st.passkey_ok && pkSupported() ? `<div class="params" style="margin-top:8px"><label>Name<input type="text" id="mf-pk-name" placeholder="for example Laptop or YubiKey" style="width:220px"></label><label>&nbsp;<button class="btn" id="mf-pk-add">Add a passkey</button></label></div>
      <p class="muted">A passkey signs you in without typing a password. It uses your fingerprint, face or PIN, or a security key.</p>`
      : `<p class="note">${esc(st.passkey_ok ? 'This browser does not support passkeys.' : st.passkey_hint)}</p>`}
    <h3 style="margin:14px 0 6px">Recovery codes</h3>
    <p style="margin:0">${st.enabled ? `${st.recovery_left} of 10 unused. <button class="btn small" id="mf-rec">Create new codes</button>` : 'Created when you add your first method.'}</p>
    <p class="muted" style="margin-bottom:0">Lost everything? An administrator can reset your two-step sign-in, or run <code>python idssiem.py --reset-mfa ${esc(ME.username)}</code> on this computer.</p>`;
  const again = async codes => { await mountMfa(box); if (codes) { const n = box.querySelector('#mf-new'); n.innerHTML = recoveryBox(codes); wireRecovery(n, codes); n.scrollIntoView({ block: 'nearest' }); } };
  const guard = async fn => { try { await fn(); } catch (e) { toast(pkErr(e), true); } };

  const on = $('#mf-totp-on');
  if (on) on.addEventListener('click', () => guard(async () => {
    const r = await api('/api/mfa/totp/begin', { method: 'POST', json: { password: pw() } });
    const s = $('#mf-totp-setup');
    s.innerHTML = `<div class="mfsetup"><div>${qrSvg(r.qr)}</div><div>
      <p style="margin:0 0 6px"><b>1.</b> Scan the code with your authenticator app, or type this key: <code class="mono">${esc(r.secret)}</code></p>
      <p style="margin:0 0 6px"><b>2.</b> Enter the 6-digit code the app shows.</p>
      <div class="params"><label>Code<input type="text" id="mf-totp-code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" style="width:120px"></label>
      <label>&nbsp;<button class="btn primary" id="mf-totp-ok">Turn on</button></label></div></div></div>`;
    $('#mf-totp-ok').addEventListener('click', () => guard(async () => {
      const x = await api('/api/mfa/totp/confirm', { method: 'POST', json: { code: $('#mf-totp-code').value } });
      toast('Authenticator app turned on');
      if (ME.mfa_setup) { ME.mfa_setup = false; }
      await again(x.recovery_codes);
    }));
  }));
  const off = $('#mf-totp-off');
  if (off) off.addEventListener('click', () => guard(async () => {
    if (!confirm('Remove the authenticator app?')) return;
    await api('/api/mfa/totp/remove', { method: 'POST', json: { password: pw() } }); toast('Authenticator app removed'); await again();
  }));
  const add = $('#mf-pk-add');
  if (add) add.addEventListener('click', () => guard(async () => {
    const opts = await api('/api/mfa/passkey/options', { method: 'POST', json: { password: pw() } });
    const cred = await pkCreate(opts);
    const x = await api('/api/mfa/passkey/register', { method: 'POST', json: { credential: cred, name: $('#mf-pk-name').value } });
    toast('Passkey added'); ME.mfa_setup = false; await again(x.recovery_codes);
  }));
  box.querySelectorAll('[data-pkdel]').forEach(b => b.addEventListener('click', () => guard(async () => {
    if (!confirm('Remove this passkey?')) return;
    await api(`/api/mfa/passkey/${b.dataset.pkdel}/remove`, { method: 'POST', json: { password: pw() } }); toast('Passkey removed'); await again();
  })));
  const rec = $('#mf-rec');
  if (rec) rec.addEventListener('click', () => guard(async () => {
    if (!confirm('Create new recovery codes? The old ones stop working.')) return;
    const x = await api('/api/mfa/recovery', { method: 'POST', json: { password: pw() } }); await again(x.recovery_codes);
  }));
}
