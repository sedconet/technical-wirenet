'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  const msg = $('msg');
  const show = (id) => { ['f-login', 'f-mfa', 'f-enroll'].forEach((f) => $(f).classList.toggle('hidden', f !== id)); msg.classList.add('hidden'); };
  const err = (e) => { msg.textContent = e.message || e; msg.classList.remove('hidden'); };
  const busy = (form, on) => form.querySelectorAll('button').forEach((b) => { b.disabled = on; });

  $('f-login').addEventListener('submit', async (ev) => {
    ev.preventDefault(); busy(ev.target, true);
    try {
      const r = await TW.api('POST', '/api/login', { username: $('username').value, password: $('password').value });
      $('password').value = '';
      if (r.next === 'mfa') { show('f-mfa'); $('code').focus(); }
      else {
        const s = await TW.api('GET', '/api/mfa/setup');
        $('qr').src = s.qr; $('secret').textContent = s.secret.replace(/(.{4})/g, '$1 ').trim();
        show('f-enroll'); $('ecode').focus();
      }
    } catch (e) { err(e); } finally { busy(ev.target, false); }
  });
  async function finish(ev, url, input) {
    ev.preventDefault(); busy(ev.target, true);
    try { await TW.api('POST', url, { code: input.value.replace(/\s/g, '') }); location.replace('/'); }
    catch (e) {
      input.value = ''; err(e);
      if (/expired|sign in again/i.test(e.message)) show('f-login');
    } finally { busy(ev.target, false); }
  }
  $('f-mfa').addEventListener('submit', (ev) => finish(ev, '/api/login/mfa', $('code')));
  $('f-enroll').addEventListener('submit', (ev) => finish(ev, '/api/mfa/enroll', $('ecode')));
})();
