'use strict';
(async () => {
  const p = new URLSearchParams(location.search);
  const host = $('#out');
  try {
    const c = await getJson('/api/cert/' + encodeURIComponent(p.get('log')) + '/' + encodeURIComponent(p.get('index')));
    const f = c.parsed;
    const date = (ms) => new Date(ms).toISOString().replace('.000Z', 'Z');
    const rows = [
      ['Type', c.is_precert ? 'Precertificate' : 'Certificate'],
      ['Subject CN', f.subject_cn ?? '(none)'],
      ['Issuer', f.issuer_cn + ' · ' + f.issuer_org],
      ['Serial', f.serial_hex],
      ['Valid', date(f.not_before_ms) + ' to ' + date(f.not_after_ms)],
      ['Key', f.key_type + ' ' + f.key_bits],
      ['Signature', f.sig_type],
      ['SANs', f.san_count],
      ['Names', f.names.join(' ')],
      ['Log', c.log + ', entry ' + c.index],
      ['Logged', date(c.timestamp_ms)],
    ];
    clear(host).append(h('table', {}, h('tbody', {}, ...rows.map(([k, v]) => h('tr', {}, h('th', {}, k), h('td', { class: 'wrap' }, v))))),
      h('h2', { style: 'margin-top:16px' }, 'Original'),
      h('p', { class: 'sub' }, c.is_precert ? 'Fetched from the log. Precertificates are stored as the TBSCertificate.' : 'Fetched from the log.'),
      h('pre', { 'data-raw': '' }, c.pem));
  } catch (e) {
    clear(host).append(h('div', { class: 'err' }, e.message));
  }
})();
