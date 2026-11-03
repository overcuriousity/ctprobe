'use strict';
const pct = (n, d) => (d ? (100 * n / d).toFixed(1) + '%' : '–');
const after = (secs) => (secs === 0 ? 'At sighting' : '+' + fmtMs(secs * 1000));
const tile = (k, v, d) => h('div', { class: 'card tile' }, h('div', { class: 'v' }, v), h('div', { class: 'k' }, k), d ? h('div', { class: 'd' }, d) : null);

function outcomeTable(r) {
  const cols = [['All names', r.first], ['Never-seen names', r.first_new], ['Names seen before', r.first_renewed]];
  const row = (label, key, tip) => h('tr', {}, h('td', {}, label, tip ? info(tip) : null),
    ...cols.map(([, o]) => h('td', { class: 'num' }, key === 'probes' ? fmt(o.probes) : pct(o[key], o.probes))));
  return h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Outcome'), ...cols.map(([k]) => h('th', { class: 'num' }, k)))),
    h('tbody', {}, row('Names probed', 'probes'), row('Has an address', 'resolved'), row('IPv4', 'v4'), row('IPv6', 'v6'), row('IPv4 and IPv6', 'both'),
      row('Exists, no address', 'nodata'), row('Does not exist', 'nxdomain', 'nxdomain'), row('Resolver failed', 'failed'), row('No quorum', 'split', 'quorum')));
}

function laterCard(r) {
  const unresolved = r.first.probes - r.resolved_first;
  const done = r.resolved_later + r.never;
  const steps = r.schedule_secs.map((s, i) => [s, r.later_by_attempt[i] || 0]).slice(1);
  const top = Math.max(1, ...steps.map((x) => x[1]), r.never);
  const bar = (k, v) => h('div', { class: 'bar-row' }, h('span', {}, k),
    h('div', { class: 'bar-track' }, h('div', { class: 'bar', style: 'width:' + (100 * v / top).toFixed(2) + '%' })), h('span', { class: 'n' }, fmt(v)));
  const q = r.time_to_dns;
  return [
    h('p', { class: 'note' }, fmt(unresolved) + ' names had no address at first; ' + fmt(done) + ' have finished their probes, ' + fmt(r.waiting) + ' are waiting for the next.'),
    ...steps.map(([s, v]) => bar('Found at ' + after(s), v)),
    bar('Never found', r.never),
    h('p', { class: 'note' }, q ? 'From sighting to first address: median ' + fmtMs(q.p50_ms) + ', p90 ' + fmtMs(q.p90_ms) + ', p99 ' + fmtMs(q.p99_ms) + '. Each is an upper bound: the address appeared at some time since the probe before.' : 'No name has resolved on a later probe yet.'),
  ];
}

function changesTable(r) {
  const row = (label, c, tip) => h('tr', {}, h('td', {}, label, info(tip)), h('td', { class: 'num' }, fmt(c.compared)),
    h('td', { class: 'num' }, pct(c.changed, c.compared)), h('td', { class: 'num' }, pct(c.network_changed, c.compared)));
  return h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Last answer from'), h('th', { class: 'num' }, 'Compared'), h('th', { class: 'num' }, 'Any change'), h('th', { class: 'num' }, 'Network change'))),
    h('tbody', {}, row('An earlier day', r.earlier_day, 'dnsearlier'), row('The same day', r.same_day, 'dnssameday')));
}

function flowCard(r) {
  const skipped = r.skipped_busy + r.skipped_stale + r.skipped_queue;
  const items = [
    ['Certificates', r.certs], ['Names accepted', r.names], ['Wildcards, not probed', r.wildcards],
    ['Already being probed', r.already_pending], ['Skipped, over the query budget', skipped], ['Later probes dropped', r.retries_dropped], ['Not valid DNS names', r.invalid],
  ];
  return [
    h('table', {}, h('tbody', {}, ...items.map(([k, v]) => h('tr', {}, h('td', {}, k), h('td', { class: 'num' }, fmt(v)))))),
    h('p', { class: 'note' }, 'Budget ' + fmt(r.max_qps) + ' queries per second per resolver, two per probe. Queued ' + fmt(r.queued) + ', in flight ' + fmt(r.in_flight) + '. Names with a known last answer: ' + fmt(r.tracked_names) + ' in ' + fmtBytes(r.tracked_bytes) + '.'),
  ];
}

function resolverTable(r) {
  const lat = (x, k) => (x.latency ? fmtMs(x.latency[k]) : '–');
  return table(['Resolver', 'Queries', 'Answers', 'NXDOMAIN', 'Timeouts', 'Errors', 'Disagreed', 'Latency p50', 'Latency p99'],
    r.resolvers.map((x) => [x.addr, fmt(x.queries), pct(x.answers, x.queries), pct(x.nxdomain, x.queries), pct(x.timeouts, x.queries), pct(x.errors, x.queries), fmt(x.disagreed), lat(x, 'p50_ms'), lat(x, 'p99_ms')]),
    { num: ['Queries', 'Answers', 'NXDOMAIN', 'Timeouts', 'Errors', 'Disagreed', 'Latency p50', 'Latency p99'] });
}

async function load() {
  const r = await getJson('/api/dns');
  if (!r.enabled) {
    $('#lead').textContent = 'DNS probing is off. List resolvers under [dns] in the configuration to turn it on.';
    document.querySelectorAll('main .card, main .tiles').forEach((e) => { e.hidden = true; });
    return;
  }
  const f = r.first;
  $('#lead').textContent = 'Since ' + new Date(r.since_ms).toISOString().slice(0, 16).replace('T', ' ') + ' UTC, through ' + r.resolvers.length + ' resolver(s), '
    + (r.resolvers.length > 1 ? r.quorum + ' of which must agree.' : 'without a quorum.');
  clear($('#tiles')).append(
    tile('Probes per second', fmt(r.probes_per_sec)),
    tile('Address at first probe', pct(f.resolved, f.probes), fmt(f.probes) + ' names'),
    tile('IPv4', pct(f.v4, f.probes)),
    tile('IPv6', pct(f.v6, f.probes)),
    tile('Found later', fmt(r.resolved_later), r.time_to_dns ? 'median ' + fmtMs(r.time_to_dns.p50_ms) : null),
    tile('Changed since an earlier day', pct(r.earlier_day.changed, r.earlier_day.compared), fmt(r.earlier_day.compared) + ' compared'),
  );
  clear($('#first')).append(outcomeTable(r));
  clear($('#later')).append(...laterCard(r));
  clear($('#changes')).append(changesTable(r));
  clear($('#flow')).append(...flowCard(r));
  $('#resolvers-sub').textContent = 'Per query, with A and AAAA counted apart';
  clear($('#resolvers')).append(resolverTable(r));
}

async function loadTrend() {
  const [hours, bucket] = $('#range').value.split(':');
  const q = 'hours=' + hours + '&bucket=' + bucket;
  $('#trend-csv').href = '/api/trends/dns?format=csv&' + q;
  const t = await getJson('/api/trends/dns?' + q);
  const host = clear($('#trend'));
  if (!t.rows.length) { host.append(h('div', { class: 'empty' }, 'No data in this range yet')); return; }
  const keep = ['resolved_pct', 'v4_pct', 'v6_pct', 'nxdomain_pct', 'changed_pct', 'network_changed_pct'];
  const idx = keep.map((c) => t.columns.indexOf(c));
  lineChart(host, { data: [t.rows.map((x) => x[0]), ...idx.map((i) => t.rows.map((x) => x[i] ?? null))],
    series: keep.map((c) => ({ label: c.replace(/_pct$/, '').replace(/_/g, ' ') })), format: (v) => v.toFixed(1) + '%', points: t.rows.length < 3, legend: true, height: 260 });
}

$('#first-h').append(info('dnsfirst'));
$('#later-h').append(info('dnslater'));
$('#changes-h').append(info('dnschanges'));
$('#flow-h').append(info('dnsflow'));
$('#resolvers-h').append(info('dnsresolvers'));
function fail(e) { $('#lead').textContent = e.message; $('#lead').className = 'err'; }
$('#range').addEventListener('change', () => loadTrend().catch(fail));
load().catch(fail);
loadTrend().catch(() => {});
setInterval(() => load().catch(() => {}), 5000);
setInterval(() => loadTrend().catch(() => {}), 60000);
