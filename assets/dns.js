'use strict';
const pct = (n, d) => (d ? (100 * n / d).toFixed(1) + '%' : '–');
// Schedule steps as written in the config: minutes, then hours, then days.
const after = (secs) => (secs === 0 ? 'At sighting' : '+' + (secs < 3600 ? secs / 60 + ' min' : secs < 172800 ? secs / 3600 + ' h' : secs / 86400 + ' d'));
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
  const cols = ['Resolver', 'Queries', 'Answers', 'NXDOMAIN', 'Timeouts', 'SERVFAIL', 'Refused', 'Unreachable', 'Latency p50', 'Latency p99'];
  return table(cols, [[x.addr, fmt(x.queries), pct(x.answers, x.queries), pct(x.nxdomain, x.queries), pct(x.timeouts, x.queries),
    pct(x.servfail, x.queries), pct(x.refused, x.queries), pct(x.unreachable, x.queries), lat('p50_ms'), lat('p99_ms')]], NUMS(cols.slice(1)));
}

async function load() {
  const r = await getJson('/api/dns');
  if (!r.enabled) {
    $('#lead').textContent = 'DNS probing is off. Set a resolver under [dns] in the configuration to turn it on.';
    document.querySelectorAll('main .card').forEach((e) => { e.hidden = true; });
    return;
  }
  const g = r.names;
  $('#lead').textContent = 'Since ' + new Date(r.since_ms).toISOString().slice(0, 16).replace('T', ' ') + ' UTC, through ' + r.resolver.addr
    + '. Shares over time are on the Trends page, and each domain and certificate shows its own answers.';
  clear($('#first')).append(outcomeRows([['All names', g.first], ['Never-seen names', g.first_new], ['Names seen before', g.first_renewed]]));
  clear($('#later')).append(...laterCard(g, r.schedule_secs, r.waiting));
  clear($('#changes')).append(changesTable(g));
  clear($('#wild')).append(outcomeRows([['Wildcard record', r.wildcards.first], ['Covered name', r.bases.first]]));
  clear($('#flow')).append(...flowCard(r));
  clear($('#resolver')).append(resolverTable(r.resolver));
}

$('#first-h').append(info('dnsfirst'));
$('#later-h').append(info('dnslater'));
$('#changes-h').append(info('dnschanges'));
$('#wild-h').append(info('dnswild'));
$('#flow-h').append(info('dnsflow'));
function fail(err) { $('#lead').textContent = err.message; $('#lead').className = 'err'; }
load().catch(fail);
setInterval(() => load().catch(() => {}), 5000);
