'use strict';
(async () => {
  const { api, el, fmtDate } = TW;
  const $ = (id) => document.getElementById(id);
  await TW.session();
  $('print').addEventListener('click', () => window.print());
  const tasks = await api('GET', '/api/tasks');
  let cat = '';

  // stats
  const thisYear = String(new Date().getFullYear());
  $('s-total').textContent = tasks.length;
  $('s-cats').textContent = new Set(tasks.map((t) => t.category)).size;
  $('s-year').textContent = tasks.filter((t) => t.completed_on.startsWith(thisYear)).length;
  $('s-year-l').textContent = `Completed in ${thisYear}`;
  $('s-latest').textContent = tasks[0] ? fmtDate(tasks[0].completed_on) : '–';

  [...new Set(tasks.map((t) => t.completed_on.slice(0, 4)))].sort().reverse()
    .forEach((y) => $('year').append(el('option', { value: y }, y)));

  const counts = tasks.reduce((m, t) => (m[t.category] = (m[t.category] || 0) + 1, m), {});
  function chips() {
    $('chips').replaceChildren(
      el('button', { class: 'chip', 'aria-pressed': String(cat === ''), onclick: () => { cat = ''; chips(); render(); } }, 'All', el('span', { class: 'n' }, tasks.length)),
      ...Object.keys(counts).sort().map((c) => el('button', { class: 'chip', 'aria-pressed': String(cat === c), onclick: () => { cat = c; chips(); render(); } }, c, el('span', { class: 'n' }, counts[c]))),
    );
  }

  function card(t) {
    const foot = [];
    if (t.client && t.show_client !== false) foot.push(el('span', {}, 'Client: ', t.client));
    if (t.location) foot.push(el('span', {}, 'Location: ', t.location));
    return el('article', { class: 'card' },
      el('div', { class: 'meta' }, el('span', { class: 'cat' }, t.category), el('time', { datetime: t.completed_on }, 'Completed ', fmtDate(t.completed_on))),
      el('h3', {}, t.title),
      el('p', {}, t.summary),
      t.technologies.length ? el('div', { class: 'tags' }, t.technologies.map((x) => el('span', { class: 'tag' }, x))) : null,
      foot.length ? el('div', { class: 'foot' }, foot) : null,
    );
  }

  function render() {
    const q = $('q').value.trim().toLowerCase();
    const y = $('year').value;
    let rows = tasks.filter((t) => (!cat || t.category === cat) && (!y || t.completed_on.startsWith(y)) &&
      (!q || [t.title, t.summary, t.category, t.location, t.client, ...t.technologies].join(' ').toLowerCase().includes(q)));
    if ($('sort').value === 'old') rows = rows.slice().reverse();
    const list = $('list');
    if (!rows.length) return list.replaceChildren(el('div', { class: 'empty' }, tasks.length ? 'No tasks match your filters.' : 'No tasks have been published yet.'));
    const groups = new Map();
    rows.forEach((t) => { const k = t.completed_on.slice(0, 4); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(t); });
    list.replaceChildren(...[...groups].flatMap(([yr, ts]) => [el('div', { class: 'year' }, yr, ' · ', ts.length, ts.length === 1 ? ' task' : ' tasks'), el('div', { class: 'grid' }, ts.map(card))]));
  }
  ['q', 'year', 'sort'].forEach((id) => $(id).addEventListener('input', render));
  chips(); render();
})();
