'use strict';
const EXAMPLES = [
  ['Top issuers today', "SELECT issuer_cn, COUNT(*) AS certs\nFROM certs\nGROUP BY 1\nORDER BY 2 DESC\nLIMIT 20"],
  ['Newest domains in a TLD', "SELECT domain, first_seen, cert_count\nFROM domains\nWHERE domain LIKE '%.de'\nORDER BY first_seen DESC\nLIMIT 100"],
  ['Random sample of first-seen names', "SELECT cn, issuer_cn, not_before\nFROM certs\nWHERE renewal = 'new'\nORDER BY random()\nLIMIT 100"],
];
for (const [label] of EXAMPLES) $('#examples').append(h('option', { value: label }, label));
$('#examples').addEventListener('change', (e) => {
  const x = EXAMPLES.find(([l]) => l === e.target.value);
  if (x) $('#q').value = x[1];
});

async function run() {
  const q = $('#q').value.trim();
  if (!q) return;
  $('#csv').setAttribute('href', '/api/sql?' + new URLSearchParams({ q, format: 'csv', limit: 100000 }));
  $('#state').textContent = 'Running…';
  $('#state').className = 'note';
  const t0 = performance.now();
  const host = clear($('#result'));
  try {
    const r = await getJson('/api/sql?' + new URLSearchParams({ q, limit: 1000 }));
    $('#state').textContent = r.rows.length + (r.truncated ? '+' : '') + ' rows in ' + fmtMs(performance.now() - t0);
    host.append(r.rows.length ? table(r.columns, r.rows, { cell: (c, v) => (v !== null && typeof v === 'object' ? JSON.stringify(v) : v) }) : h('div', { class: 'empty' }, 'No rows'));
  } catch (e) {
    $('#state').textContent = e.message;
    $('#state').className = 'err';
  }
}
$('#run').addEventListener('click', run);
$('#q').addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.ctrlKey) run(); });
getJson('/api/schema').then((tables) => {
  $('#tables').append(...tables.map((t) => h('p', { style: 'margin:0 0 8px' }, h('strong', {}, t.name), h('br'), h('span', { class: 'note' }, t.columns.join(', ')))));
});
