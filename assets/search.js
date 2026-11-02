'use strict';
const isoDay = (ms) => new Date(ms).toISOString().slice(0, 10);

function showCerts(params, title, filters) {
  $('#certs-card').hidden = false;
  $('#certs-title').textContent = title;
  certPanel($('#certs'), params, filters);
}

async function run(ev) {
  ev?.preventDefault();
  const q = $('#q').value.trim();
  if (!q) return;
  const mode = $('#mode').value;
  // A new search starts clean; a page load keeps the filters in its URL.
  const loaded = new URLSearchParams(location.search);
  const filters = ev ? {} : certFiltersFrom(loaded);
  const view = ev ? {} : Object.fromEntries(['sort', 'dir', 'offset'].filter((k) => loaded.get(k)).map((k) => [k, loaded.get(k)]));
  history.replaceState(null, '', '/search?' + new URLSearchParams({ q, mode, ...filters, ...view }));
  $('#hits-card').hidden = true;
  $('#certs-card').hidden = true;
  $('#state').textContent = '';
  if (mode === 'names' || q.includes('%')) { showCerts({ pattern: q }, 'Certificates matching ' + q, filters); return; }
  $('#state').textContent = 'Searching…';
  try {
    const hits = await getJson('/api/search?' + new URLSearchParams({ q, mode, distance: $('#distance').value }));
    $('#state').textContent = hits.length + ' domains';
    $('#hits-card').hidden = false;
    const host = clear($('#hits'));
    if (!hits.length) { host.append(h('div', { class: 'empty' }, 'No domain matches')); return; }
    const narrow = h('input', { type: 'search', placeholder: 'Filter domains', 'aria-label': 'Filter domains' });
    const rowsHost = h('div', {});
    host.append(h('div', { class: 'filters noprint' }, narrow), rowsHost);
    const grid = sortTable(rowsHost, { rows: hits, columns: [
      { id: 'domain', label: 'domain', cell: (x) => h('a', { href: '/domain?d=' + encodeURIComponent(x.domain) }, x.domain) },
      { id: 'score', label: 'score', num: true, cell: (x) => x.score.toFixed(3) },
      { id: 'first_seen_ms', label: 'first seen', cell: (x) => isoDay(x.first_seen_ms) },
      { id: 'last_seen_ms', label: 'last seen', cell: (x) => isoDay(x.last_seen_ms) },
      { id: 'cert_count', label: 'certs', num: true },
    ] });
    narrow.addEventListener('input', () => { const t = narrow.value.trim().toLowerCase(); grid.update(hits.filter((x) => x.domain.includes(t))); });
    if (hits.length === 1) showCerts({ domain: hits[0].domain }, 'Certificates for ' + hits[0].domain, filters);
  } catch (e) {
    $('#state').textContent = e.message;
  }
}

const syncMode = () => { $('#distance').hidden = $('#mode').value !== 'levenshtein'; };
$('#mode').addEventListener('change', syncMode);
$('#form').addEventListener('submit', run);
const initial = new URLSearchParams(location.search);
if (initial.get('q')) {
  $('#q').value = initial.get('q');
  if (initial.get('mode')) $('#mode').value = initial.get('mode');
  syncMode();
  run();
} else if (Object.keys(certFiltersFrom(initial)).length) {
  showCerts({}, 'Filtered certificates', certFiltersFrom(initial));
}
