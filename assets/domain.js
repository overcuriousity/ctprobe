'use strict';
const day = (ms) => (ms === undefined ? '–' : new Date(ms).toISOString().slice(0, 10));
const dtile = (k, v) => h('div', { class: 'card tile' }, h('div', { class: 'v' }, v), h('div', { class: 'k' }, k));
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
    clear($('#tiles')).append(
      dtile('First seen', day(r.hit?.first_seen_ms)), dtile('Last seen', day(r.hit?.last_seen_ms)),
      dtile('Certificates, all time', fmt(r.hit?.cert_count ?? 0)), dtile('Certificates in window', fmt(total)),
      dtile('Names', fmt(r.names.rows.length)), dtile('Issuers', fmt(r.issuers.rows.length)));
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
