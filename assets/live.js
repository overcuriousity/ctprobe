'use strict';
const tile = (k, v, d, tip) => h('div', { class: 'card tile' }, h('div', { class: 'v' }, v), h('div', { class: 'k' }, k, tip ? info(tip) : null), h('div', { class: 'd' }, d || ''));
const FRAME_KEY = 'timeframe';
const frame = $('#timeframe');
frame.value = localStorage.getItem(FRAME_KEY) || '15';
let chart = null;
let dns = null;
let lastSnap = null;
let lastView = null;

function dnsTiles() {
  if (!dns || !dns.enabled) return [];
  const f = dns.names.first, e = dns.names.earlier_day;
  return [
    tile('Address at first probe', share(f.resolved, f.probes), 'IPv4 ' + share(f.v4, f.probes) + ' · IPv6 ' + share(f.v6, f.probes), 'dnsshare'),
    tile('IP changed since an earlier day', share(e.ip_changed, e.compared), fmt(e.compared) + ' compared', 'dnsip'),
  ];
}

function render(s) {
  lastSnap = s;
  applyStatus(s);
  const rawT = s.raw_total, uniqT = s.unique_total || 0;
  const renewed = s.renew_exact_total + s.renew_name_total;
  clear($('#tiles')).append(
    tile('Unique certificates/s', fmt(s.unique_per_sec), fmt(uniqT) + ' since last restart', 'unique'),
    tile('Raw entries/s', fmt(s.raw_per_sec), fmt(rawT) + ' since last restart', 'raw'),
    tile('Never-seen names/s', fmt(s.new_names_per_sec), fmt(s.new_names_total) + ' since last restart', 'names'),
    tile('Never-seen domains/s', fmt(s.new_domains_per_sec), fmt(s.new_domains_total) + ' since last restart', 'domains'),
    tile('Duplication factor', uniqT ? (rawT / uniqT).toFixed(2) + '×' : '–', 'raw entries per unique', 'dup'),
    tile('Probable renewals', uniqT ? (100 * renewed / uniqT).toFixed(1) + '%' : '–', fmt(s.renew_exact_total) + ' exact · ' + fmt(s.renew_name_total) + ' name', 'renewals'),
    tile('Tracked names', fmt(s.tracker_names), fmtBytes(s.tracker_bytes), 'tracker'),
    tile('Process', fmtBytes(s.rss_bytes), fmtBytes(s.disk_bytes) + ' on disk', 'cost'),
    ...dnsTiles(),
  );
  $('#tiles-note').textContent = 'Rates are 60-second averages. Last restart: ' + new Date(s.started_at_ms).toLocaleString('sv').slice(0, 16);
}

function drawStages(v) {
  lastView = v;
  const t = v.totals;
  const sub = $('#stages-sub');
  clear(sub).append(frame.selectedOptions[0].textContent);
  const host = clear($('#stages'));
  if (!t.seconds) { host.append(h('div', { class: 'empty' }, 'No data in this time frame yet')); return; }
  const top = Math.max(1, t.raw, t.names);
  const row = (k, d, n) => h('div', { class: 'stage' },
    h('div', {}, h('div', {}, k), h('div', { class: 'quiet' }, d)),
    h('div', { class: 'bar-track' }, h('div', { class: 'bar', style: 'width:' + (100 * n / top).toFixed(2) + '%' })),
    h('div', { class: 'n' }, h('div', {}, fmt(n)), h('div', { class: 'quiet' }, fmt(n / t.seconds) + '/s')));
  host.append(
    row('Raw entries', 'What the logs delivered', t.raw),
    row('Unique certificates', t.unique ? '1 in ' + (t.raw / t.unique).toFixed(1) + ' after removing duplicates' : 'After removing duplicates', t.unique),
    h('hr', { class: 'split' }),
    row('Hostnames', 'In those certificates; one can hold many', t.names),
    row('Never-seen hostnames', 'Not seen since collection began', t.new_names),
    row('Never-seen domains', 'Registered domains not seen before', t.new_domains),
  );
  if (dns && dns.enabled) {
    host.append(h('hr', { class: 'split' }),
      row('Names probed in DNS', 'Hostnames asked for A and AAAA when seen', t.dns_probed),
      row('With an address', t.dns_probed ? share(t.dns_resolved, t.dns_probed) + ' had A or AAAA at once' : 'A or AAAA at the first probe', t.dns_resolved));
  }
}

async function loadHistory() {
  const v = await getJson('/api/history?minutes=' + frame.value);
  const data = [v.t, v.raw, v.unique, v.new_names, v.new_domains];
  if (!chart) chart = lineChart($('#rate'), { data, series: [{ label: 'Raw entries' }, { label: 'Unique certificates' }, { label: 'Never-seen names' }, { label: 'Never-seen domains' }] });
  else chart.setData(data);
  drawStages(v);
}

let refresh = 0;
function schedule() {
  clearInterval(refresh);
  refresh = setInterval(() => loadHistory().catch(() => {}), Number(frame.value) <= 60 ? 10000 : 60000);
}
frame.addEventListener('change', () => { localStorage.setItem(FRAME_KEY, frame.value); loadHistory().catch(() => {}); schedule(); });
loadHistory().catch(() => {});
schedule();

$('#stages-h').append(info('stages'));
$('#keeping-h').append(info('keeping'));
keepingCard($('#keeping'));
$('#dns-h').append(info('dnshealth'));
dnsHealthCard($('#dns-health'));
// DNS fills in its tiles and stages when it arrives, without waiting for the next refresh.
onDns((r) => {
  const first = !dns;
  dns = r;
  if (first && lastSnap) render(lastSnap);
  if (first && lastView) drawStages(lastView);
});
coverageSummary($('#coverage'));
logTable($('#logs'), { onCount: (ok, all) => { $('#logsub').textContent = ok + ' of ' + all + ' healthy. Updates every 30 seconds.'; } });

let source = null;
function connect() {
  if (source) source.close();
  const q = $('#filter').value.trim();
  source = new EventSource('/api/stream' + (q ? '?q=' + encodeURIComponent(q) : ''));
  source.addEventListener('snapshot', (e) => render(JSON.parse(e.data)));
  source.addEventListener('cert', (e) => {
    const c = JSON.parse(e.data);
    const feed = $('#feed');
    const link = h('a', { href: '/cert?log=' + c.log + '&index=' + c.index }, c.cn || c.primary_domain || '(no name)');
    feed.prepend(h('div', {}, h('span', { class: 'tag' }, c.renewal), link, ' · ', c.issuer_cn));
    while (feed.children.length > 200) feed.lastChild.remove();
  });
}
let debounce = 0;
$('#filter').addEventListener('input', () => { clearTimeout(debounce); debounce = setTimeout(connect, 300); });
connect();
