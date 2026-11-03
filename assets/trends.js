'use strict';
const TIPS = { volume: 'raw', peaks: 'peaks', renewals: 'renewals', state_growth: 'tracker', resources: 'cost', concentration: 'concentration', quality: 'backlog', validity: 'validity', dns: 'dnsshare', dns_changes: 'dnsip', dns_ttd: 'dnsttd' };
const LINES = [
  ['volume', 'Volume', 'Entries per second', null],
  ['peaks', 'Peaks', 'Unique certificates per second: median and p99 minute, highest second', null],
  ['quality', 'Backlog', 'Entries published but not fetched yet', null],
  ['renewals', 'New vs probable renewals', 'Certificates by name match', null],
  ['state_growth', 'State growth', 'Distinct names tracked', null],
  ['resources', 'Resources', 'Bytes', fmtBytes],
  ['concentration', 'Concentration', 'Percent of a day\'s certificates from the top registered domains; after the first nightly run', (v) => v.toFixed(1) + '%'],
  ['dns', 'DNS at first probe', 'Share of names with an address, IPv4, IPv6 and NXDOMAIN when their certificate was seen', (v) => v.toFixed(1) + '%'],
  ['dns_changes', 'IP changes since an earlier day', 'Share of names whose addresses differ from the last answer of an earlier day', (v) => v.toFixed(1) + '%'],
  ['dns_ttd', 'Time to DNS', 'Of names found on a later probe, the share found within each time of the sighting', (v) => v.toFixed(1) + '%'],
];
const BARS = [
  ['issuers', 'Issuers'], ['tlds', 'TLDs'], ['keys', 'Key types'], ['validity', 'Validity'],
  ['san_dist', 'SANs per certificate'], ['der_size', 'Certificate size'],
];
const BAR_FILTER = { issuers: 'issuer', tlds: 'tld', keys: 'key_type', validity: 'validity', san_dist: 'san', der_size: 'size' };
const hoursChosen = () => Number($('#range').value.split(':')[0]);
// The start a bar really counts from: rollups only know whole days.
function barFrom(hours) {
  const start = Date.now() - hours * 3600000;
  if (hours < 24) return start;
  return Math.min(Math.ceil(start / 86400000) * 86400000, Math.floor(Date.now() / 86400000) * 86400000);
}
const barLink = (metric, key, hours) => '/search?' + new URLSearchParams({ [BAR_FILTER[metric]]: key, from: String(barFrom(hours)) });
const params = () => {
  const [hours, bucket] = $('#range').value.split(':');
  return 'hours=' + hours + '&bucket=' + bucket;
};
const fetchTrend = (m) => getJson('/api/trends/' + m + '?' + params());

function card(id, title, sub, metric) {
  return h('div', { class: 'card' }, h('h2', {}, title, TIPS[metric] ? info(TIPS[metric]) : null), h('p', { class: 'sub' }, sub || ''),
    h('div', { id }), h('p', { class: 'note' }, h('a', { href: '/api/trends/' + metric + '?format=csv&' + params() }, 'CSV')));
}

function drawLine(host, r, format) {
  clear(host);
  if (!r.rows.length) { host.append(h('div', { class: 'empty' }, 'No data in this range yet')); return; }
  const cols = r.columns.slice(1).map((_, i) => r.rows.map((row) => row[i + 1] ?? null));
  lineChart(host, { data: [r.rows.map((row) => row[0]), ...cols], series: r.columns.slice(1).map((c) => ({ label: c.replace(/_/g, ' ') })), format, points: r.rows.length < 3, legend: true });
}

function drawBars(host, r, metric) {
  clear(host);
  if (!r.rows.length) { host.append(h('div', { class: 'empty' }, 'No data in this range yet')); return; }
  const top = Math.max(...r.rows.map((x) => x[1]));
  const total = r.rows.reduce((a, x) => a + x[1], 0);
  const hours = hoursChosen();
  host.append(...r.rows.map(([k, v]) => h('a', { class: 'bar-row', href: barLink(metric, k, hours), title: k + ': ' + v + ' (' + (100 * v / total).toFixed(1) + '%)' },
    h('span', { style: 'overflow:hidden;text-overflow:ellipsis;white-space:nowrap' }, k),
    h('div', { class: 'bar-track' }, h('div', { class: 'bar', style: 'width:' + (100 * v / top).toFixed(2) + '%' })),
    h('span', { class: 'n' }, fmt(v)))));
}

let logNames = {};
const logName = (id) => logNames[id] || ('log ' + id);

function drawTable(host, r, opts) {
  clear(host);
  if (!r.rows.length) { host.append(h('div', { class: 'empty' }, 'No data yet')); return; }
  sortTable(host, { rows: r.rows, columns: r.columns.map((c, i) => ({
    id: c, label: c, num: opts.num.includes(c), get: (row) => row[i], cell: (row) => opts.cell(c, row[i]),
  })) });
}

function fmtRow(c, v) {
  if (c === 'log_id') return logName(v);
  if (typeof v !== 'number') return v;
  if (c.endsWith('_ms')) return fmtMs(v);
  if (c.endsWith('pct')) return v.toFixed(2) + '%';
  return fmt(v);
}

async function load() {
  try {
    const live = await getJson('/api/live');
    logNames = Object.fromEntries(live.logs.map((l) => [l.id, l.name]));
    clear($('#charts'));
    for (const [m, title, sub] of LINES) $('#charts').append(card('c-' + m, title, sub, m));
    const hours = hoursChosen();
    const barSub = hours < 24 ? 'Certificates in range. Select one to see them.' : 'Certificates since ' + new Date(barFrom(hours)).toISOString().slice(0, 10) + '. Select one to see them.';
    for (const [m, title] of BARS) $('#charts').append(card('c-' + m, title, barSub, m));
    await Promise.all([
      ...LINES.map(async ([m, , , f]) => drawLine($('#c-' + m), await fetchTrend(m), f)),
      ...BARS.map(async ([m]) => drawBars($('#c-' + m), await fetchTrend(m), m)),
      fetchTrend('stages').then((r) => drawTable($('#stages'), r, { cell: fmtRow, num: r.columns.slice(1) })),
      fetchTrend('coverage').then((r) => drawTable($('#coverage'), r, { cell: fmtRow, num: ['n', 'added_certs', 'cumulative_certs', 'cumulative_pct'] })),
      fetchTrend('lag').then((r) => drawTable($('#lag'), r, { cell: fmtRow, num: r.columns.slice(1) })),
      fetchTrend('catchup').then((r) => drawTable($('#catchup'), r, { cell: fmtRow, num: r.columns.slice(1) })),
      fetchTrend('cost').then((r) => {
        const c = Object.fromEntries(r.columns.map((k, i) => [k, r.rows[0]?.[i]]));
        clear($('#cost')).append(...[
          ['CPU per million certificates', c.cpu_seconds_per_million == null ? '–' : c.cpu_seconds_per_million.toFixed(1) + ' s'],
          ['Disk per million certificates', fmtBytes(c.disk_bytes_per_million)],
          ['Tracker bytes per name', c.tracker_bytes_per_name == null ? '–' : c.tracker_bytes_per_name.toFixed(1)],
          ['Unique certificates in range', fmt(c.unique_certs)],
        ].map(([k, v]) => h('div', { class: 'card tile' }, h('div', { class: 'v' }, v), h('div', { class: 'k' }, k))));
      }),
    ]);
    $('#asof').textContent = 'As of ' + new Date().toISOString().slice(11, 19) + ' UTC';
  } catch (e) {
    $('#asof').textContent = e.message;
    $('#asof').className = 'err';
  }
}
document.querySelectorAll('h2[data-tip]').forEach((e) => e.append(info(e.dataset.tip)));
$('#range').addEventListener('change', load);
load();
setInterval(load, 300000);
