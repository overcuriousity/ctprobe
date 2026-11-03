'use strict';
const pct = (n, d) => (d ? (100 * n / d).toFixed(1) + '%' : '–');
// Schedule steps as written in the config: minutes, then hours, then days.
const after = (secs) => (secs === 0 ? 'At sighting' : '+' + (secs < 3600 ? secs / 60 + ' min' : secs < 172800 ? secs / 3600 + ' h' : secs / 86400 + ' d'));
const tile = (k, v, d) => h('div', { class: 'card tile' }, h('div', { class: 'v' }, v), h('div', { class: 'k' }, k), d ? h('div', { class: 'd' }, d) : null);
const NUMS = (n) => ({ num: n });

function outcomeRows(cols) {
  const row = (label, key, tip) => h('tr', {}, h('td', {}, label, tip ? info(tip) : null),
    ...cols.map(([, o]) => h('td', { class: 'num' }, key === 'probes' ? fmt(o.probes) : pct(o[key], o.probes))));
  return h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Outcome'), ...cols.map(([k]) => h('th', { class: 'num' }, k)))),
    h('tbody', {}, row('Names probed', 'probes'), row('Has an address', 'resolved'), row('IPv4', 'v4'), row('IPv6', 'v6'), row('IPv4 and IPv6', 'both'),
      row('Exists, no address', 'nodata'), row('Does not exist', 'nxdomain', 'nxdomain'), row('Resolver failed', 'failed')));
}

function laterCard(g, schedule, waiting) {
  const unresolved = g.first.probes - g.resolved_first;
  const steps = schedule.map((s, i) => [s, g.later_by_attempt[i] || 0]).slice(1);
  const top = Math.max(1, ...steps.map((x) => x[1]), g.never);
  const bar = (k, v) => h('div', { class: 'bar-row' }, h('span', {}, k),
    h('div', { class: 'bar-track' }, h('div', { class: 'bar', style: 'width:' + (100 * v / top).toFixed(2) + '%' })), h('span', { class: 'n' }, fmt(v)));
  const hi = g.time_to_dns, lo = g.time_to_dns_lower;
  return [
    h('p', { class: 'note' }, fmt(unresolved) + ' names had no address at first; ' + fmt(g.resolved_later) + ' found one later, ' + fmt(g.never) + ' never did. Waiting for a later probe: ' + fmt(waiting) + '.'),
    ...steps.map(([s, v]) => bar('Found at ' + after(s), v)),
    bar('Never found', g.never),
    h('p', { class: 'note' }, hi ? 'From sighting to first address, median between ' + fmtMs(lo ? lo.p50_ms : 0) + ' and ' + fmtMs(hi.p50_ms) + ', p90 up to ' + fmtMs(hi.p90_ms) + '.' : 'No name has resolved on a later probe yet.'),
  ];
}

function changesTable(g) {
  const cols = [['An earlier day', g.earlier_day, 'dnsearlier'], ['The same day', g.same_day, 'dnssameday']];
  const row = (label, f, tip) => h('tr', {}, h('td', {}, label, tip ? info(tip) : null), ...cols.map(([, c]) => h('td', { class: 'num' }, f(c))));
  return h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Last answer from'), ...cols.map(([k, , tip]) => h('th', { class: 'num' }, k, info(tip))))),
    h('tbody', {},
      row('Compared', (c) => fmt(c.compared)),
      row('Any change', (c) => pct(c.changed, c.compared), 'dnschanges'),
      row('IPv4 changed', (c) => pct(c.v4_changed, c.v4_compared), 'dnsfamily'),
      row('IPv4 all replaced', (c) => pct(c.v4_replaced, c.v4_replaced_known), 'dnsreplaced'),
      row('IPv6 changed', (c) => pct(c.v6_changed, c.v6_compared), 'dnsfamily'),
      row('IPv6 all replaced', (c) => pct(c.v6_replaced, c.v6_replaced_known), 'dnsreplaced'),
      row('Alias changed', (c) => pct(c.cname_changed, c.compared)),
      row('Network changed', (c) => pct(c.network_changed, c.compared), 'dnsnetwork'),
      row('Outcome changed', (c) => pct(c.status_changed, c.compared))));
}

function flowCard(r) {
  const skipped = r.skipped_busy + r.skipped_stale + r.skipped_queue;
  const items = [
    ['Certificates', r.certs], ['Queued for probing', r.accepted], ['Outside the sample', r.not_sampled],
    ['Already being probed', r.already_pending], ['Skipped, over the query budget', skipped], ['Not valid DNS names', r.invalid],
  ];
  const late = r.retry_late;
  return [
    h('table', {}, h('tbody', {}, ...items.map(([k, v]) => h('tr', {}, h('td', {}, k), h('td', { class: 'num' }, fmt(v)))))),
    h('p', { class: 'note' }, 'Budget ' + fmt(r.max_qps) + ' queries per second, two per probe; sample ' + r.sample_pct + '% of names. Queued ' + fmt(r.queued) + ', in flight ' + fmt(r.in_flight) + '.'),
    h('p', { class: 'note' }, late ? 'Later probes ran late by a median of ' + fmtMs(late.p50_ms) + ', p99 ' + fmtMs(late.p99_ms) + '.' : ''),
    h('p', { class: 'note' }, 'Names with a known last answer: ' + fmt(r.tracked_names) + ' in ' + fmtBytes(r.tracked_bytes) + '.'),
    r.queue_error ? h('p', { class: 'err' }, 'Retry queue: ' + r.queue_error) : null,
  ].filter(Boolean);
}

function resolverTable(x) {
  const lat = (k) => (x.latency ? fmtMs(x.latency[k]) : '–');
  const cols = ['Resolver', 'Queries', 'Answers', 'NXDOMAIN', 'Timeouts', 'Errors', 'Latency p50', 'Latency p99'];
  return table(cols, [[x.addr, fmt(x.queries), pct(x.answers, x.queries), pct(x.nxdomain, x.queries), pct(x.timeouts, x.queries), pct(x.errors, x.queries), lat('p50_ms'), lat('p99_ms')]], NUMS(cols.slice(1)));
}

async function load() {
  const r = await getJson('/api/dns');
  if (!r.enabled) {
    $('#lead').textContent = 'DNS probing is off. Set a resolver under [dns] in the configuration to turn it on.';
    document.querySelectorAll('main .card, main .tiles').forEach((e) => { e.hidden = true; });
    return;
  }
  const g = r.names, f = g.first, e = g.earlier_day;
  $('#lead').textContent = 'Since ' + new Date(r.since_ms).toISOString().slice(0, 16).replace('T', ' ') + ' UTC, through ' + r.resolver.addr + '.';
  clear($('#tiles')).append(
    tile('Probes per second', fmt(r.probes_per_sec)),
    tile('Address at first probe', pct(f.resolved, f.probes), fmt(f.probes) + ' names'),
    tile('IPv4', pct(f.v4, f.probes)),
    tile('IPv6', pct(f.v6, f.probes)),
    tile('Found later', fmt(g.resolved_later), g.time_to_dns ? 'median ' + fmtMs(g.time_to_dns.p50_ms) : null),
    tile('IPv4 changed since an earlier day', pct(e.v4_changed, e.v4_compared), fmt(e.v4_compared) + ' compared'),
    tile('IPv6 changed since an earlier day', pct(e.v6_changed, e.v6_compared), fmt(e.v6_compared) + ' compared'),
  );
  clear($('#first')).append(outcomeRows([['All names', f], ['Never-seen names', g.first_new], ['Names seen before', g.first_renewed]]));
  clear($('#later')).append(...laterCard(g, r.schedule_secs, r.waiting));
  clear($('#changes')).append(changesTable(g));
  clear($('#wild')).append(outcomeRows([['Wildcard record', r.wildcards.first], ['Covered name', r.bases.first]]));
  clear($('#flow')).append(...flowCard(r));
  clear($('#resolver')).append(resolverTable(r.resolver));
}

async function loadTrend() {
  const [hours, bucket] = $('#range').value.split(':');
  const q = 'hours=' + hours + '&bucket=' + bucket;
  $('#trend-csv').href = '/api/trends/dns?format=csv&' + q;
  const t = await getJson('/api/trends/dns?' + q);
  const host = clear($('#trend'));
  if (!t.rows.length) { host.append(h('div', { class: 'empty' }, 'No data in this range yet')); return; }
  const keep = ['resolved_pct', 'v4_pct', 'v6_pct', 'nxdomain_pct', 'v4_changed_pct', 'v6_changed_pct', 'network_changed_pct'];
  const idx = keep.map((c) => t.columns.indexOf(c));
  lineChart(host, { data: [t.rows.map((x) => x[0]), ...idx.map((i) => t.rows.map((x) => x[i] ?? null))],
    series: keep.map((c) => ({ label: c.replace(/_pct$/, '').replace(/_/g, ' ') })), format: (v) => v.toFixed(1) + '%', points: t.rows.length < 3, legend: true, height: 260 });
}

$('#first-h').append(info('dnsfirst'));
$('#later-h').append(info('dnslater'));
$('#changes-h').append(info('dnschanges'));
$('#wild-h').append(info('dnswild'));
$('#flow-h').append(info('dnsflow'));
function fail(err) { $('#lead').textContent = err.message; $('#lead').className = 'err'; }
$('#range').addEventListener('change', () => loadTrend().catch(fail));
load().catch(fail);
loadTrend().catch(() => {});
setInterval(() => load().catch(() => {}), 5000);
setInterval(() => loadTrend().catch(() => {}), 60000);
