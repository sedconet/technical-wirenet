'use strict';
const TW = (() => {
  let csrf = null;
  async function api(method, url, body) {
    const opts = { method, headers: {}, credentials: 'same-origin' };
    if (csrf) opts.headers['X-CSRF-Token'] = csrf;
    if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    const r = await fetch(url, opts);
    const data = await r.json().catch(() => ({}));
    if (r.status === 401 && !url.startsWith('/api/login') && !url.startsWith('/api/mfa')) { location.href = '/login'; throw new Error('Signed out'); }
    if (!r.ok) throw new Error(data.error || 'Request failed');
    if (data.csrf) csrf = data.csrf;
    return data;
  }
  // Safe DOM builder: text only, never innerHTML with data
  function el(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') e.className = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v === true ? '' : v);
    }
    for (const k of kids.flat()) if (k != null && k !== false) e.append(k instanceof Node ? k : document.createTextNode(String(k)));
    return e;
  }
  const fmtDate = (iso) => new Date(iso + 'T00:00:00').toLocaleDateString('en-IE', { day: 'numeric', month: 'short', year: 'numeric' });
  function toast(msg) {
    const t = el('div', { class: 'toast', role: 'status' }, msg);
    document.body.append(t); setTimeout(() => t.remove(), 2600);
  }
  async function session() {
    const me = await api('GET', '/api/me');
    const who = document.getElementById('who');
    if (who) who.textContent = me.user.display_name;
    const mg = document.getElementById('nav-manage');
    if (mg && me.user.role !== 'viewer') mg.classList.remove('hidden');
    const lo = document.getElementById('logout');
    if (lo) lo.addEventListener('click', async () => { await api('POST', '/api/logout').catch(() => {}); location.href = '/login'; });
    return me.user;
  }
  return { api, el, fmtDate, toast, session };
})();
