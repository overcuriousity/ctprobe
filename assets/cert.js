'use strict';
const date = (ms) => new Date(ms).toISOString().replace('.000Z', 'Z');
const addrs = (...lists) => lists.flatMap((l) => l || []).join(' ');
const raw = (v) => h('span', { style: 'white-space:normal;word-break:break-all', 'data-raw': '' }, v);

// One row per name: what DNS said when the certificate was seen, when an
// address first appeared, and how that compares with the answer before.
function dnsTable(c, d) {
  const p = d.probes;
  const i = (col) => p.columns.indexOf(col);
  const byName = new Map();
  for (const x of p.rows) {
    const key = x[i('name')] + '\u0000' + x[i('kind')];
    if (!byName.has(key)) byName.set(key, []);
    byName.get(key).push(x);
  }
  const latest = new Map((d.latest?.rows || []).map((x) => [x[0], x]));
  const answer = (x) => {
    const a = addrs(x[i('v4')], x[i('v6')]);
    return x[i('status')] === 'resolved' ? raw(a) : x[i('status')];
  };
  const rows = [];
  const names = [...c.parsed.names];
  for (const n of names) {
    const kinds = n.startsWith('*.') ? [[n, 'wildcard'], [n.slice(2), 'base']] : [[n, 'name']];
    for (const [name, kind] of kinds) {
      const probes = byName.get(name + '\u0000' + kind);
      const label = kind === 'name' ? name : kind === 'wildcard' ? name + ' (wildcard record)' : name + ' (covered name)';
      if (!probes) {
        if (kind === 'base') continue; // Listed on the certificate, so probed as a name.
        const l = latest.get(name);
        rows.push([label, l ? 'Probed for another certificate: ' + (l[1] === 'resolved' ? addrs(l[2], l[3]) : l[1]) + ' (' + date(l[4]) + ')' : 'Not probed', '', '', '']);
        continue;
      }
      const first = probes[0];
      const found = probes.find((x) => x[i('status')] === 'resolved');
      const last = probes[probes.length - 1];
      let appeared;
      if (!found) appeared = 'None in ' + probes.length + ' probe' + (probes.length > 1 ? 's' : '') + ', last ' + date(last[i('probed_ms')]);
      else if (found === first) appeared = 'At sighting';
      else appeared = 'Between ' + fmtMs(probes[probes.indexOf(found) - 1][i('probed_ms')] - found[i('seen_ms')]) + ' and ' + fmtMs(found[i('probed_ms')] - found[i('seen_ms')]) + ' after sighting';
      let before = '–', change = '–';
      if (first[i('prev_days')] !== null) {
        const prev = first[i('prev_status')] === 'resolved' ? addrs(first[i('prev_v4')], first[i('prev_v6')]) : first[i('prev_status')];
        before = raw(prev + ', ' + first[i('prev_days')] + ' days earlier');
        const what = [first[i('v4_changed')] ? 'IPv4' : null, first[i('v6_changed')] ? 'IPv6' : null].filter(Boolean);
        change = what.length ? what.join(' and ') + ' changed' : first[i('changed')] ? 'Alias or outcome changed' : 'Unchanged';
      }
      rows.push([label, answer(first), appeared, before, change]);
    }
  }
  return table(['Name', 'At sighting', 'First address', 'Before this certificate', 'Change'], rows);
}

async function dnsSection(host, c) {
  const q = new URLSearchParams({ hash: c.cert_hash, at: String(c.timestamp_ms), names: c.parsed.names.join(',') });
  try {
    const d = await getJson('/api/dns/cert?' + q);
    clear(host);
    if (!d.probes.rows.length && !(d.latest?.rows || []).length) {
      host.append(h('div', { class: 'empty' }, d.enabled ? 'Not probed. The certificate may predate DNS probing, or its names were outside the sample.' : 'DNS probing is off'));
      return;
    }
    host.append(h('div', { class: 'scroll' }, dnsTable(c, d)));
  } catch (e) {
    clear(host).append(h('div', { class: 'err' }, e.message));
  }
}

(async () => {
  const p = new URLSearchParams(location.search);
  const host = $('#out');
  try {
    const c = await getJson('/api/cert/' + encodeURIComponent(p.get('log')) + '/' + encodeURIComponent(p.get('index')));
    const f = c.parsed;
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
    const dns = h('div', {}, h('div', { class: 'empty' }, 'Loading…'));
    clear(host).append(h('table', {}, h('tbody', {}, ...rows.map(([k, v]) => h('tr', {}, h('th', {}, k), h('td', { class: 'wrap' }, v))))),
      h('h2', { style: 'margin-top:16px' }, 'DNS', info('dnscert')),
      h('p', { class: 'sub' }, 'A and AAAA of each name, from the probes made for this certificate'),
      dns,
      h('h2', { style: 'margin-top:16px' }, 'Original'),
      h('p', { class: 'sub' }, c.is_precert ? 'Fetched from the log. Precertificates are stored as the TBSCertificate.' : 'Fetched from the log.'),
      h('pre', { 'data-raw': '' }, c.pem));
    dnsSection(dns, c);
  } catch (e) {
    clear(host).append(h('div', { class: 'err' }, e.message));
  }
})();
