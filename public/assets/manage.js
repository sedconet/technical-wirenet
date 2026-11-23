'use strict';
(async () => {
  const { api, el, fmtDate, toast } = TW;
  const $ = (id) => document.getElementById(id);
  const me = await TW.session();
  const isAdmin = me.role === 'admin';
  if (isAdmin) document.querySelectorAll('.admin-only').forEach((e) => e.classList.remove('hidden'));
  const fail = (e) => toast(e.message);

  // tabs
  const loaders = { tasks: loadTasks, users: loadUsers, audit: loadAudit, account: () => {} };
  document.querySelectorAll('[role=tab]').forEach((b) => b.addEventListener('click', () => {
    document.querySelectorAll('[role=tab]').forEach((x) => x.setAttribute('aria-selected', String(x === b)));
    Object.keys(loaders).forEach((k) => $('tab-' + k).classList.toggle('hidden', k !== b.dataset.tab));
    loaders[b.dataset.tab]();
  }));

  // ---------------- tasks
  const cats = await api('GET', '/api/categories');
  $('t-category').replaceChildren(...cats.map((c) => el('option', { value: c }, c)));
  $('t-date').max = new Date().toISOString().slice(0, 10);
  let editing = null; let tasks = [];

  function resetForm() {
    editing = null; $('task-form').reset(); $('t-published').checked = true;
    $('task-form-title').textContent = 'Add a completed task'; $('t-save').textContent = 'Add task'; $('t-cancel').classList.add('hidden');
  }
  function edit(t) {
    editing = t.id;
    $('t-title').value = t.title; $('t-category').value = t.category; $('t-date').value = t.completed_on;
    $('t-client').value = t.client || ''; $('t-location').value = t.location || ''; $('t-summary').value = t.summary;
    $('t-tech').value = t.technologies.join(', '); $('t-showclient').checked = t.show_client; $('t-published').checked = t.published;
    $('task-form-title').textContent = 'Edit task'; $('t-save').textContent = 'Save changes'; $('t-cancel').classList.remove('hidden');
    $('task-form').scrollIntoView({ behavior: 'smooth' });
  }
  $('t-cancel').addEventListener('click', resetForm);
  $('task-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const body = {
      title: $('t-title').value, category: $('t-category').value, completed_on: $('t-date').value, client: $('t-client').value,
      location: $('t-location').value, summary: $('t-summary').value, technologies: $('t-tech').value.split(',').map((s) => s.trim()).filter(Boolean),
      show_client: $('t-showclient').checked, published: $('t-published').checked,
    };
    try {
      if (editing) await api('PUT', `/api/tasks/${editing}`, body); else await api('POST', '/api/tasks', body);
      toast(editing ? 'Task updated' : 'Task added'); resetForm(); loadTasks();
    } catch (e) { fail(e); }
  });
  async function loadTasks() {
    tasks = await api('GET', '/api/tasks');
    $('task-rows').replaceChildren(...(tasks.length ? tasks.map((t) => el('tr', {},
      el('td', {}, fmtDate(t.completed_on)),
      el('td', {}, el('b', {}, t.title), t.client ? el('div', { class: 'fine' }, t.client, t.show_client ? ' (shown)' : ' (hidden)') : null),
      el('td', {}, t.category),
      el('td', {}, el('span', { class: 'badge ' + (t.published ? 'green' : 'amber') }, t.published ? 'Published' : 'Draft')),
      el('td', {}, el('button', { class: 'btn sm', onclick: () => edit(t) }, 'Edit'),
        el('button', { class: 'btn sm danger', onclick: async () => {
          if (!confirm(`Delete "${t.title}"? This cannot be undone.`)) return;
          try { await api('DELETE', `/api/tasks/${t.id}`); toast('Task deleted'); loadTasks(); } catch (e) { fail(e); }
        } }, 'Delete')),
    )) : [el('tr', {}, el('td', { colspan: '5', class: 'empty' }, 'No tasks yet. Add the first one above.'))]));
  }

  // ---------------- users
  function genPassword() {
    const a = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
    const r = crypto.getRandomValues(new Uint32Array(16));
    let p = Array.from(r, (n) => a[n % a.length]).join('');
    return p.slice(0, 4) + '-' + p.slice(4, 8) + '-' + p.slice(8, 12) + '-' + p.slice(12) + 'a1B';
  }
  $('u-gen').addEventListener('click', () => { $('u-password').value = genPassword(); $('u-password').type = 'text'; });
  $('user-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      await api('POST', '/api/users', { username: $('u-username').value, display_name: $('u-display').value, role: $('u-role').value, password: $('u-password').value });
      toast('User created'); $('user-form').reset(); $('u-password').type = 'password'; loadUsers();
    } catch (e) { fail(e); }
  });
  async function patchUser(u, body, label) { try { await api('PATCH', `/api/users/${u.id}`, body); toast(label); loadUsers(); } catch (e) { fail(e); } }
  async function loadUsers() {
    if (!isAdmin) return;
    const users = await api('GET', '/api/users');
    $('user-rows').replaceChildren(...users.map((u) => {
      const role = el('select', { 'aria-label': 'Role', onchange: (e) => patchUser(u, { role: e.target.value }, 'Role updated') },
        ['viewer', 'editor', 'admin'].map((r) => { const o = el('option', { value: r }, r); if (r === u.role) o.selected = true; return o; }));
      return el('tr', {},
        el('td', {}, el('b', {}, u.display_name), el('div', { class: 'fine' }, u.username)),
        el('td', {}, role),
        el('td', {}, el('span', { class: 'badge ' + (u.mfa ? 'green' : 'amber') }, u.mfa ? '2FA on' : '2FA pending'), ' ',
          u.locked ? el('span', { class: 'badge red' }, 'Locked') : null, u.disabled ? el('span', { class: 'badge red' }, 'Disabled') : null),
        el('td', {}, u.last_login_at ? new Date(u.last_login_at).toLocaleString('en-IE') : 'Never'),
        el('td', {},
          u.locked ? el('button', { class: 'btn sm', onclick: () => patchUser(u, { unlock: true }, 'Unlocked') }, 'Unlock') : null,
          el('button', { class: 'btn sm', onclick: () => { if (confirm(`Reset 2FA for ${u.username}? They will set it up again at next sign-in.`)) patchUser(u, { reset_mfa: true }, '2FA reset'); } }, 'Reset 2FA'),
          el('button', { class: 'btn sm', onclick: () => { const p = prompt('New temporary password (min 12 chars, upper, lower, number):', genPassword()); if (p) patchUser(u, { password: p }, 'Password reset'); } }, 'Reset password'),
          el('button', { class: 'btn sm danger', onclick: () => patchUser(u, { disabled: !u.disabled }, u.disabled ? 'Enabled' : 'Disabled') }, u.disabled ? 'Enable' : 'Disable')),
      );
    }));
  }

  // ---------------- audit
  async function loadAudit() {
    if (!isAdmin) return;
    const rows = await api('GET', '/api/audit');
    $('audit-rows').replaceChildren(...rows.map((r) => el('tr', {},
      el('td', {}, new Date(r.at).toLocaleString('en-IE')), el('td', {}, r.username || '–'),
      el('td', {}, el('span', { class: 'badge ' + (/fail|lock/.test(r.action) ? 'red' : '') }, r.action)),
      el('td', {}, r.detail || ''), el('td', { class: 'fine' }, r.ip || ''))));
  }

  // ---------------- account
  $('pw-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if ($('pw-new').value !== $('pw-new2').value) return toast('New passwords do not match');
    try { await api('POST', '/api/me/password', { current: $('pw-cur').value, next: $('pw-new').value }); toast('Password updated'); $('pw-form').reset(); }
    catch (e) { fail(e); }
  });

  loadTasks();
})();
