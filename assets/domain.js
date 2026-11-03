'use strict';
const day = (ms) => (ms === undefined ? '–' : new Date(ms).toISOString().slice(0, 10));
const dtile = (k, v) => h('div', { class: 'card tile' }, h('div', { class: 'v' }, v), h('div', { class: 'k' }, k));
const when = (ms) => (ms === null || ms === undefined ? '–' : new Date(ms).toISOString().slice(0, 16).replace('T', ' '));
const addrs = (...lists) => lists.flatMap((l) => l || []).join(' ') || '–';

// Every name's latest answer, and the changes between certificates.
function dnsSection(r) {
  const names = $('#dns-names'), changes = $('#dns-changes');
  const say = (host, text, cls) => clear(host).append(h('div', { class: cls || 'empty' }, text));
  if (r.dns_error) { say(names, r.dns_error, 'err'); say(changes, r.dns_error, 'err'); return null; }
  const n = r.dns_names, c = r.dns_changes;
  if (!n || !n.rows.length) {
    const why = r.dns_enabled ? 'No DNS probes for names under this domain yet' : 'DNS probing is off';
    say(names, why);
    say(changes, why);
    return null;
  }
  const i = (res, col) => res.columns.indexOf(col);
  clear(names).append(table(['name', 'status', 'addresses', 'first address', 'last probe', 'IP changes'],
    n.rows.map((x) => [x[i(n, 'name')], x[i(n, 'status')], addrs(x[i(n, 'v4')], x[i(n, 'v6')]),
      when(x[i(n, 'first_address_ms')]), when(x[i(n, 'last_probe_ms')]), x[i(n, 'ip_changes')]]),
    { num: ['IP changes'], cell: (col, v) => (col === 'addresses' ? h('span', { style: 'white-space:normal;word-break:break-all', 'data-raw': '' }, v) : v) }));
  if (!c.rows.length) say(changes, 'No changes seen yet');
  else {
    clear(changes).append(table(['when', 'name', 'days since', 'before', 'after'],
      c.rows.map((x) => [when(x[i(c, 't')]), x[i(c, 'name')], x[i(c, 'prev_days')],
        x[i(c, 'prev_status')] + ' ' + addrs(x[i(c, 'prev_v4')], x[i(c, 'prev_v6')]),
        x[i(c, 'status')] + ' ' + addrs(x[i(c, 'v4')], x[i(c, 'v6')])]),
      { num: ['days since'], cell: (col, v) => (col === 'before' || col === 'after' ? h('span', { style: 'white-space:normal;word-break:break-all', 'data-raw': '' }, v) : v) }));
  }
  const resolving = n.rows.filter((x) => x[i(n, 'status')] === 'resolved').length;
  return resolving + ' of ' + n.rows.length;
}
$('#dns-h').append(info('dnsdomain'));
(async () => {
  const d = (new URLSearchParams(location.search).get('d') || '').trim();
  if (!d) { $('#lead').textContent = 'No domain given.'; return; }
  $('#name').textContent = d;
  document.title = d + ' · ctprobe';
  try {
    const r = await getJson('/api/domain?d=' + encodeURIComponent(d));
    const total = r.days.rows.reduce((a, x) => a + x[1], 0);
    $('#lead').textContent = r.hit ? 'Seen in Certificate Transparency since collection began.'
      : 'Not seen since collection began. Platforms such as pages.dev are public suffixes, so each site on them is its own domain.';
    const resolving = dnsSection(r);
    clear($('#tiles')).append(
      dtile('First seen', day(r.hit?.first_seen_ms)), dtile('Last seen', day(r.hit?.last_seen_ms)),
      dtile('Certificates, all time', fmt(r.hit?.cert_count ?? 0)), dtile('Certificates in window', fmt(total)),
      dtile('Names', fmt(r.names.rows.length)), dtile('Issuers', fmt(r.issuers.rows.length)),
      ...(resolving ? [dtile('Names with an address', resolving)] : []));
    const none = (host) => clear(host).append(h('div', { class: 'empty' }, 'None'));
    if (r.days.rows.length) {
      clear($('#days'));
      lineChart($('#days'), { data: [r.days.rows.map((x) => x[0]), r.days.rows.map((x) => x[1])], series: [{ label: 'Certificates' }], points: r.days.rows.length < 3, height: 200 });
    } else none($('#days'));
    if (r.issuers.rows.length) {
      const top = Math.max(...r.issuers.rows.map((x) => x[1]));
      clear($('#issuers')).append(...r.issuers.rows.map(([k, v]) => h('div', { class: 'bar-row', title: k + ': ' + v },
        h('span', { style: 'overflow:hidden;text-overflow:ellipsis;white-space:nowrap' }, k),
        h('div', { class: 'bar-track' }, h('div', { class: 'bar', style: 'width:' + (100 * v / top).toFixed(2) + '%' })),
        h('span', { class: 'n' }, fmt(v)))));
    } else none($('#issuers'));
    if (r.names.rows.length) clear($('#names')).append(table(['name', 'certs'], r.names.rows, { num: ['certs'] }));
    else none($('#names'));
    if (r.similar.length) {
      clear($('#similar')).append(table(['domain', 'score', 'first seen', 'certs'],
        r.similar.map((x) => [x.domain, x.score.toFixed(3), day(x.first_seen_ms), x.cert_count]), {
          num: ['score', 'certs'],
          cell: (c, v) => (c === 'domain' ? h('a', { href: '/domain?d=' + encodeURIComponent(v) }, v) : v),
        }));
    } else none($('#similar'));
    certPanel($('#certs'), { domain: r.domain }, certFiltersFrom(new URLSearchParams(location.search)));
  } catch (e) {
    $('#lead').textContent = e.message;
    $('#lead').className = 'err';
  }
})();
