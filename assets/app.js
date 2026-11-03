// Shared helpers. All values are placed with textContent via h().
'use strict';
function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') e.className = v;
    else if (k === 'on') for (const [ev, f] of Object.entries(v)) e.addEventListener(ev, f);
    else if (k === 'href') { if (/^(\/|\?|#)/.test(v)) e.setAttribute('href', v); }
    else if (k === 'style') e.style.cssText = v;
    else e.setAttribute(k, v);
  }
  for (const c of kids) if (c !== null && c !== undefined) e.append(c.nodeType ? c : String(c));
  return e;
}
const $ = (s) => document.querySelector(s);

// Theme: an explicit choice wins, otherwise the system setting.
(function theme() {
  const saved = localStorage.getItem('theme');
  const dark = saved ? saved === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
})();

const HELP = {
  unique: 'Distinct certificates. A precertificate and its final certificate count once, however many logs carry them. This is the real issuance rate.',
  raw: 'Log entries before removing duplicates. This is what a client must download and parse if it follows every log.',
  dup: 'Raw entries per unique certificate. High values mean following fewer logs would save a lot of work.',
  names: 'Names not seen since collection began. Without backfill, renewing names look new at first, so this falls for months and is an upper bound.',
  domains: 'Registered domains not seen since collection began. Without backfill, it is an upper bound for the first 90 days or more.',
  renewals: 'Certificates whose CN or SANs were seen before. Exact means the same full set of names. Falls short of the truth until a full renewal cycle has been observed.',
  stages: 'From everything the logs delivered down to domains never seen before. Hostnames can exceed certificates, because one certificate can hold many. The later rows matter most for sizing.',
  keeping: 'Compares what the logs published with what we fetched over the last 15 minutes, and names the logs that fall furthest short.',
  assess: 'Worked out every 15 minutes from a sample of the last 24 hours of sightings. It only advises: ctprobe keeps following every log.',
  coverage: 'How many logs are needed to see a share of all certificates, picking the most useful log first. Calculated nightly.',
  concentration: 'Share of certificates from the most active registered domains. High values suggest a pre-filter could remove much of the load.',
  peaks: 'Median and 99th percentile minute, and the highest single second. Size for these, not the average. Only clean minutes are used on the Sizing page.',
  clean: 'A clean minute has a backlog under one minute of volume on logs that accept our request rate, so its rates reflect issuance and not catch-up.',
  backlog: 'Entries published by logs but not yet fetched. Rate-limited logs are shown apart because they stay behind however fast we are.',
  lag: 'Delay from the log timestamp or certificate start to our sighting. It sets the lower limit on how fast anything built on this data can react.',
  capacity: 'What each log published and what we fetched over the range. A log that stays below its published rate falls further behind.',
  cost: 'Measured on this machine, so re-check on the target hardware. Disk figures fall after nightly compaction.',
  tracker: 'Names held in memory for renewal detection. It grows daily.',
  dnsfirst: 'A and AAAA of each name, asked when its certificate is seen. Names seen before belong to probable renewals.',
  dnslater: 'A name without an address is asked again on a schedule from its sighting, up to 30 days, until it resolves. It appeared between the last probe that missed and the first that found it.',
  dnschanges: 'Any change counts a different address, alias or outcome. Only first probes are compared, against the last answer held for the name.',
  dnsfamily: 'Of names that had addresses of this family both times, the share whose set of addresses differs.',
  dnsreplaced: 'No address in common with the earlier answer. Counted where every earlier address is known; the first four IPv4 and two IPv6 addresses are kept.',
  dnsnetwork: 'Ignores addresses rotating behind the same alias and, without an alias, within the same /24 or /48.',
  dnsearlier: 'Mostly renewals and reissues, whose names last resolved on an earlier day.',
  dnssameday: 'Mostly the same name in another certificate on the same day, such as from a second CA.',
  dnswild: 'A wildcard asked as written finds a wildcard record if one exists. The covered name is asked only when the certificate does not list it too.',
  dnsflow: 'Probing never slows ingest. A fixed sample of names, chosen by a hash of the name, is probed on every certificate. Names that do not fit the query budget in a burst are skipped and counted here.',
  nxdomain: 'The resolver says the name does not exist.',
  dnshealth: 'Whether DNS probing works right now, from the last 5 minutes of queries. Failures are timeouts and errors; a few are normal, since some name servers are broken.',
  dnsshare: 'Names with an A or AAAA record when their certificate was seen. On Live, since the last restart.',
  dnsip: 'Names whose IPv4 or IPv6 addresses differ from the last answer of an earlier day, mostly at renewals. On Live, since the last restart.',
  dnscert: 'Each name is asked for A and AAAA when the certificate is seen and, without an address, again for up to 30 days. A name already being probed for another certificate is not probed twice; its latest answer is shown instead.',
  dnsdomain: 'The latest answer for each name, from probes kept in the rolling window. IP changes count first probes whose addresses differ from an earlier day.',
  dnsqps: 'Queries the resolver must answer: an A and an AAAA for each probe, first probes and later ones together.',
  dnsttd: 'Of names that had no address at first and got one on a later probe, the share found within each time of the sighting.',
  dnsfilter: 'What DNS found when the certificate was seen. Certificates seen before DNS probing began, or whose names were outside the sample, match none of these.',
  validity: 'Certificate lifetime. Shorter limits take effect in March 2027 and March 2029, so the same sites will issue more often.',
};
function info(key) {
  return h('span', { class: 'info', 'data-tip': HELP[key] || key, tabindex: '0', role: 'note', 'aria-label': HELP[key] || key }, 'i');
}

const clear = (e) => { e.replaceChildren(); return e; };
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const num = new Intl.NumberFormat('en');
function fmt(n) {
  if (n === null || n === undefined || Number.isNaN(n)) return '–';
  const a = Math.abs(n);
  if (a >= 1e12) return (n / 1e12).toFixed(2) + 'T';
  if (a >= 1e9) return (n / 1e9).toFixed(2) + 'B';
  if (a >= 1e6) return (n / 1e6).toFixed(2) + 'M';
  if (a >= 1e4) return (n / 1e3).toFixed(1) + 'k';
  return num.format(Math.round(n * 10) / 10);
}
function fmtBytes(n) {
  if (n === null || n === undefined) return '–';
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? 1 : 0) + ' ' + u[i];
}
function fmtMs(ms) {
  if (ms === null || ms === undefined) return '–';
  if (ms < 1000) return Math.round(ms) + ' ms';
  if (ms < 120000) return (ms / 1000).toFixed(1) + ' s';
  if (ms < 7200000) return (ms / 60000).toFixed(1) + ' min';
  return (ms / 3600000).toFixed(1) + ' h';
}
const SERIES = ['--s1', '--s2', '--s3', '--s4', '--s5', '--s6', '--s7', '--s8'];

// A line chart with crosshair and legend values on hover.
function lineChart(host, opts) {
  const width = Math.max(320, host.clientWidth || 600);
  const chart = new uPlot({
    width, height: opts.height || 220,
    series: [{ value: (u, v) => (v === null ? '–' : opts.time === false ? fmt(v) : new Date(v * 1000).toISOString().slice(0, 16).replace('T', ' ')) },
      ...opts.series.map((s, i) => ({
        label: s.label, stroke: css(SERIES[i % 8]), width: 2,
        fill: opts.fill ? css(SERIES[i % 8]) + '1f' : undefined,
        points: { show: opts.points === true, size: 8 },
        value: (u, v) => (v === null || v === undefined ? '–' : (opts.format || fmt)(v)),
      }))],
    // One bucket would otherwise stretch the time axis across years.
    scales: { x: { time: opts.time !== false, range: (u, lo, hi) => (lo === hi ? [lo - 1800, hi + 1800] : [lo, hi]) } },
    legend: { show: opts.series.length > 1 || opts.legend === true },
    cursor: { drag: { x: false, y: false } },
    axes: [
      { stroke: css('--muted'), grid: { show: false }, ticks: { stroke: css('--axis') } },
      { stroke: css('--muted'), grid: { stroke: css('--grid'), width: 1 }, ticks: { show: false }, size: 84, values: (u, t) => t.map(opts.format || fmt) },
    ],
  }, opts.data, host);
  new ResizeObserver(() => { const w = host.clientWidth; if (w > 0 && w !== chart.width) chart.setSize({ width: w, height: chart.height }); }).observe(host);
  return chart;
}

function table(columns, rows, opts) {
  opts = opts || {};
  const head = h('tr', {}, ...columns.map((c) => h('th', { class: opts.num && opts.num.includes(c) ? 'num' : '' }, c)));
  const body = rows.map((r) => h('tr', {}, ...r.map((v, i) => {
    const c = columns[i];
    const cell = opts.cell ? opts.cell(c, v, r) : (Array.isArray(v) ? v.join(' ') : v);
    return h('td', { class: opts.num && opts.num.includes(c) ? 'num' : '' }, cell === null || cell === undefined ? '' : cell);
  })));
  return h('table', {}, h('thead', {}, head), h('tbody', {}, ...body));
}

// A table sorted in the browser, for rows that are all present.
// columns: [{ id, label, num, get, cell, tip }]. get gives the value to sort on.
function sortTable(host, opts) {
  const { columns, key, persist } = opts;
  const value = (c, r) => (c.get ? c.get(r) : r[c.id]);
  const load = () => { try { return JSON.parse(localStorage.getItem('sort:' + persist)); } catch { return null; } };
  let sort = (persist && load()) || null;
  if (sort && !columns.some((c) => c.id === sort.id)) sort = null;
  let rows = opts.rows || [];
  const compare = (a, b) => {
    const c = columns.find((x) => x.id === sort.id);
    const [x, y] = [value(c, a), value(c, b)];
    // Unknown values stay last in either direction.
    if (x === null || x === undefined) return y === null || y === undefined ? 0 : 1;
    if (y === null || y === undefined) return -1;
    const d = typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y));
    return sort.dir === 'asc' ? d : -d;
  };
  const body = h('tbody', {});
  const heads = columns.map((c) => h('th', { class: c.num ? 'num sortable' : 'sortable', tabindex: '0', role: 'button', on: {
    click: () => toggle(c), keydown: (e) => { if (e.key === 'Enter') toggle(c); },
  } }, c.label, c.tip ? info(c.tip) : null, h('span', { class: 'arrow' })));
  function paint() {
    heads.forEach((th, i) => {
      const on = sort && sort.id === columns[i].id;
      th.setAttribute('aria-sort', on ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none');
      th.lastChild.textContent = on ? (sort.dir === 'asc' ? ' ▲' : ' ▼') : '';
    });
    const list = sort ? [...rows].sort(compare) : opts.defaultSort ? [...rows].sort(opts.defaultSort) : rows;
    body.replaceChildren(...list.map((r) => h('tr', key ? { 'data-key': key(r) } : {}, ...columns.map((c) => {
      const v = c.cell ? c.cell(r) : value(c, r);
      return h('td', { class: c.num ? 'num' : '' }, v === null || v === undefined ? '' : v);
    }))));
  }
  function toggle(c) {
    sort = sort && sort.id === c.id ? { id: c.id, dir: sort.dir === 'asc' ? 'desc' : 'asc' } : { id: c.id, dir: c.num ? 'desc' : 'asc' };
    if (persist) localStorage.setItem('sort:' + persist, JSON.stringify(sort));
    paint();
  }
  clear(host).append(h('table', {}, h('thead', {}, h('tr', {}, ...heads)), body));
  paint();
  return { update(next) { rows = next; paint(); } };
}

// A hint that is not clipped by scrolling tables. Set data-hint on any element.
const hintBox = h('div', { class: 'hint', hidden: 'hidden' });
document.body.append(hintBox);
document.addEventListener('mouseover', (e) => {
  const t = e.target.closest?.('[data-hint]');
  if (!t) { hintBox.hidden = true; return; }
  hintBox.textContent = t.dataset.hint;
  hintBox.hidden = false;
  const r = t.getBoundingClientRect();
  hintBox.style.left = Math.min(r.left, innerWidth - hintBox.offsetWidth - 12) + 'px';
  const below = r.bottom + 6 + hintBox.offsetHeight < innerHeight;
  hintBox.style.top = (below ? r.bottom + 6 : r.top - hintBox.offsetHeight - 6) + 'px';
});

function fmtCount(count, capped) {
  if (count === null || count === undefined) return 'many';
  return capped ? num.format(count) + '+' : num.format(count);
}
const clock = (ms) => new Date(ms).toTimeString().slice(0, 5);

async function getJson(url) {
  const r = await fetch(url);
  const j = await r.json().catch(() => ({ error: 'HTTP ' + r.status }));
  if (!r.ok) throw new Error(j.error || 'HTTP ' + r.status);
  return j;
}

function applyStatus(s) {
  $('#status').textContent = fmt(s.unique_per_sec) + ' unique/s · ' + s.log_count + ' logs · ' + fmt(s.behind_total) + ' behind';
  const b = $('#banner');
  b.hidden = !s.paused_reason;
  b.textContent = s.paused_reason ? 'Ingest paused: ' + s.paused_reason : '';
}

const langBtn = $('#lang');
langBtn.textContent = LANG === 'de' ? 'EN' : 'DE';
langBtn.addEventListener('click', () => { localStorage.setItem('lang', LANG === 'de' ? 'en' : 'de'); location.reload(); });
const themeBtn = $('#theme');
function syncTheme() { themeBtn.textContent = document.documentElement.dataset.theme === 'dark' ? 'Light' : 'Dark'; }
syncTheme();
themeBtn.addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  localStorage.setItem('theme', next);
  location.reload(); // Charts read their colours when built.
});

// Certificate table with filters, shared by Search and Domain. Sorting, filtering
// and paging happen on the server, and all of it lives in the URL.
const CERT_FILTERS = ['from', 'to', 'issuer', 'issuer_contains', 'tld', 'key_type', 'validity', 'san', 'size', 'renewal', 'wildcard', 'precert', 'dns', 'expires_from', 'expires_to', 'random'];
const CERT_COLUMNS = [
  { id: 'seen_at', sort: true }, { id: 'cn', sort: true }, { id: 'issuer_cn', sort: true }, { id: 'not_after', sort: true },
  { id: 'san_count', sort: true, num: true }, { id: 'key_type', sort: true }, { id: 'renewal', sort: true },
  { id: 'days_since_seen', sort: true, num: true }, { id: 'detail' },
];
const PAGE_ROWS = 100;
const toLocalInput = (v) => {
  if (!v) return '';
  const ms = /^\d+$/.test(v) ? Number(v) : new Date(v).getTime();
  if (Number.isNaN(ms)) return '';
  return new Date(ms - new Date(ms).getTimezoneOffset() * 60000).toISOString().slice(0, 16);
};
const certFiltersFrom = (params) => Object.fromEntries(CERT_FILTERS.filter((k) => params.get(k)).map((k) => [k, params.get(k)]));

function certPanel(host, base, initial) {
  const f = { ...(initial || {}) };
  const url = new URLSearchParams(location.search);
  let sort = url.get('sort') || 'seen_at', dir = url.get('dir') || 'desc', offset = Number(url.get('offset')) || 0;
  let token = 0;
  const choice = (key, label, opts) => h('select', { 'aria-label': label }, h('option', { value: '' }, label), ...opts.map(([v, t]) => h('option', { value: v }, t || v)));
  const fields = {
    from: h('input', { type: 'datetime-local', 'aria-label': 'From', title: 'From' }),
    to: h('input', { type: 'datetime-local', 'aria-label': 'To', title: 'To' }),
    issuer_contains: h('input', { type: 'text', placeholder: 'Issuer contains', style: 'width:170px', 'aria-label': 'Issuer contains' }),
    tld: h('input', { type: 'text', placeholder: 'TLD', style: 'width:90px', 'aria-label': 'TLD' }),
    key_type: h('input', { type: 'text', placeholder: 'Key type', style: 'width:110px', 'aria-label': 'Key type' }),
    validity: choice('validity', 'Any validity', ['<=7d', '<=47d', '<=100d', '<=200d', '>200d'].map((v) => [v])),
    san: choice('san', 'Any SAN count', ['1', '2', '3-5', '6-10', '11-100', '>100'].map((v) => [v])),
    size: choice('size', 'Any size', ['<1 KiB', '1-2 KiB', '2-4 KiB', '4-16 KiB', '>=16 KiB'].map((v) => [v])),
    renewal: choice('renewal', 'Any renewal class', [['new', 'New'], ['name', 'Name match'], ['exact', 'Exact match']]),
    wildcard: choice('wildcard', 'Wildcard or not', [['true', 'Wildcard only'], ['false', 'No wildcard']]),
    precert: choice('precert', 'Certificate or precertificate', [['true', 'Precertificates only'], ['false', 'Final certificates only']]),
    dns: choice('dns', 'DNS: any', [['address', 'DNS: a name had an address'], ['no_address', 'DNS: no name had an address'], ['ip_changed', 'DNS: IP changed']]),
    expires_from: h('input', { type: 'date', 'aria-label': 'Expires from', title: 'Expires from' }),
    expires_to: h('input', { type: 'date', 'aria-label': 'Expires to', title: 'Expires to' }),
    random: h('input', { type: 'number', min: '1', max: '100000', placeholder: 'Random N', style: 'width:100px', 'aria-label': 'Random sample size' }),
  };
  for (const [k, e] of Object.entries(fields)) if (f[k]) e.value = k === 'from' || k === 'to' ? toLocalInput(f[k]) : f[k];
  const collect = () => {
    for (const [k, e] of Object.entries(fields)) {
      if (!e.value) delete f[k];
      else f[k] = k === 'from' || k === 'to' ? String(new Date(e.value).getTime()) : e.value;
    }
  };
  const params = (format) => {
    const p = new URLSearchParams(base);
    Object.entries(f).forEach(([k, v]) => p.set(k, v));
    if (sort !== 'seen_at' || dir !== 'desc') { p.set('sort', sort); p.set('dir', dir); }
    if (format) p.set('format', format);
    else if (offset) p.set('offset', offset);
    return p;
  };
  const csv = h('a', { href: '/' }, 'CSV');
  const chips = h('span', { class: 'chips' });
  const out = h('div', { class: 'scroll' });
  const count = h('span', { class: 'note' });
  const prev = h('button', { type: 'button', class: 'ghost small', on: { click: () => { offset = Math.max(0, offset - PAGE_ROWS); load(); } } }, 'Previous');
  const next = h('button', { type: 'button', class: 'ghost small', on: { click: () => { offset += PAGE_ROWS; load(); } } }, 'Next');
  function keepInUrl() {
    const u = new URLSearchParams(location.search);
    [...CERT_FILTERS, 'sort', 'dir', 'offset'].forEach((k) => u.delete(k));
    Object.entries(f).forEach(([k, v]) => u.set(k, v));
    if (sort !== 'seen_at' || dir !== 'desc') { u.set('sort', sort); u.set('dir', dir); }
    if (offset) u.set('offset', offset);
    history.replaceState(null, '', location.pathname + (String(u) ? '?' + u : ''));
  }
  function showChips() {
    clear(chips);
    if (f.issuer) chips.append(h('button', { type: 'button', class: 'ghost small', title: 'Remove filter', on: { click: () => { delete f.issuer; offset = 0; load(); } } }, 'Issuer: ' + f.issuer + ' ×'));
  }
  function head() {
    const random = Boolean(f.random);
    return h('thead', {}, h('tr', {}, ...CERT_COLUMNS.map((c) => {
      const on = c.id === sort;
      const can = c.sort && !random;
      const toggle = () => {
        dir = on ? (dir === 'asc' ? 'desc' : 'asc') : (c.id === 'seen_at' || c.num ? 'desc' : 'asc');
        sort = c.id;
        offset = 0;
        load();
      };
      return h('th', { class: (c.num ? 'num ' : '') + (can ? 'sortable' : ''), 'aria-sort': on && can ? (dir === 'asc' ? 'ascending' : 'descending') : 'none',
        ...(can ? { tabindex: '0', role: 'button', on: { click: toggle, keydown: (e) => { if (e.key === 'Enter') toggle(); } } } : {}) },
      c.id, h('span', { class: 'arrow' }, on && can ? (dir === 'asc' ? ' ▲' : ' ▼') : ''));
    })));
  }
  async function load() {
    const mine = ++token;
    showChips();
    keepInUrl();
    csv.setAttribute('href', '/api/certs?' + params('csv'));
    clear(out).append(h('div', { class: 'empty' }, 'Loading…'));
    count.textContent = '';
    prev.disabled = true;
    next.disabled = true;
    try {
      const r = await getJson('/api/certs?' + params());
      if (mine !== token) return;
      clear(out);
      // Shows the default bound of an unscoped search, which is otherwise invisible.
      if (r.from_ms && !fields.from.value) fields.from.value = toLocalInput(String(r.from_ms));
      if (!r.rows.length && r.cut_short) { out.append(h('div', { class: 'err' }, 'Timed out. Try a narrower date range or sort by newest first.')); return; }
      if (!r.rows.length) { out.append(h('div', { class: 'empty' }, 'No certificates match in the rolling window')); return; }
      const i = (c) => r.columns.indexOf(c);
      const rows = r.rows.map((row) => CERT_COLUMNS.map((c) => {
        if (c.id === 'detail') return h('a', { href: '/cert?log=' + row[i('log_id')] + '&index=' + row[i('entry_index')] }, 'open');
        return row[i(c.id)];
      }));
      out.append(h('table', {}, head(), h('tbody', {}, ...rows.map((row) => h('tr', {}, ...row.map((v, n) => h('td', { class: CERT_COLUMNS[n].num ? 'num' : '' }, v === null || v === undefined ? '' : v)))))));
      const first = r.offset + 1, last = r.offset + r.rows.length;
      count.textContent = 'Rows ' + first + '–' + last + ' of ' + fmtCount(r.count, r.count_capped);
      prev.disabled = r.offset === 0;
      next.disabled = !r.truncated || r.offset + PAGE_ROWS > 10000 || Boolean(f.random);
      if (r.cut_short) out.append(h('p', { class: 'note' }, 'Cut short by the time limit. Try a narrower date range.'));
    } catch (e) {
      if (mine !== token) return;
      const slow = /timed out/.test(e.message);
      clear(out).append(h('div', { class: 'err' }, slow ? 'Timed out. Try a narrower date range or sort by newest first.' : e.message));
    }
  }
  const apply = h('button', { type: 'button', on: { click: () => { collect(); offset = 0; load(); } } }, 'Apply');
  const more = h('details', { class: 'more-filters noprint' }, h('summary', {}, 'More filters'),
    h('div', { class: 'filters' }, fields.key_type, fields.validity, fields.san, fields.size, fields.precert, fields.expires_from, fields.expires_to, fields.random));
  if (['key_type', 'validity', 'san', 'size', 'precert', 'expires_from', 'expires_to', 'random'].some((k) => f[k])) more.open = true;
  const form = h('form', { class: 'noprint', on: { submit: (e) => { e.preventDefault(); collect(); offset = 0; load(); } } },
    h('div', { class: 'filters' }, fields.from, fields.to, fields.issuer_contains, fields.tld, fields.renewal, fields.wildcard, fields.dns, info('dnsfilter'), apply, csv, chips), more,
    h('button', { type: 'submit', hidden: 'hidden' }));
  clear(host).append(form, out, h('div', { class: 'pager noprint' }, prev, next, count));
  load();
}

// Log health, shared by Live and Sizing. One poll feeds every panel on a page.
const LOG_REFRESH_MS = 30000;
const STATES = {
  failing: ['Failing', 'bad', 0], rate_limited: ['Rate-limited', 'warn', 1], falling_behind: ['Falling behind', 'warn', 2],
  catching_up: ['Catching up', 'good', 3], not_advancing: ['Not advancing', 'warn', 4], paused: ['Paused', 'warn', 5],
  measuring: ['Measuring', '', 6], healthy: ['Healthy', 'good', 7],
};
const logFeed = { subs: [], last: null, started: false };
function onLogs(fn) {
  logFeed.subs.push(fn);
  if (logFeed.last) fn(logFeed.last);
  if (logFeed.started) return;
  logFeed.started = true;
  const poll = () => getJson('/api/logs').then((r) => { logFeed.last = r; logFeed.subs.forEach((f) => f(r)); }).catch(() => {});
  poll();
  setInterval(poll, LOG_REFRESH_MS);
}
const coverageTarget = (r) => Number(localStorage.getItem('coverageTarget')) || r.coverage_target;
const neededFor = (steps, target) => { const i = steps.findIndex((s) => s.cumulative_pct >= target); return i < 0 ? steps.length : i + 1; };

function targetSelect() {
  const sel = h('select', { 'aria-label': 'Coverage target', on: { change: () => {
    localStorage.setItem('coverageTarget', sel.value);
    logFeed.subs.forEach((f) => f(logFeed.last));
  } } });
  onLogs((r) => {
    if (sel.options.length) return;
    const values = [...new Set([90, 95, 99, r.coverage_target])].sort((a, b) => a - b);
    sel.append(...values.map((v) => h('option', { value: v }, v + '%')));
    sel.value = coverageTarget(r);
  });
  return sel;
}

function signed(n) {
  if (n === 0) return '0';
  return (n > 0 ? '▲ +' : '▼ −') + fmt(Math.abs(n));
}

function logTable(host, opts) {
  opts = opts || {};
  const text = h('input', { type: 'search', placeholder: 'Filter by log name', 'aria-label': 'Filter logs by name', style: 'min-width:220px' });
  const pick = h('select', { 'aria-label': 'Filter logs by state' }, h('option', { value: '' }, 'Any state'),
    ...Object.entries(STATES).map(([k, v]) => h('option', { value: k }, v[0])));
  const tableHost = h('div', { class: 'scroll' });
  const empty = h('div', { class: 'empty', hidden: 'hidden' }, opts.emptyText || 'No logs match');
  let last = null, needed = 0;
  const pct = (v) => (v === null || v === undefined ? '–' : v.toFixed(1) + '%');
  const hintOf = (l) => {
    const lines = [tr('Last 15 minutes') + ': ' + tr('fetched') + ' ' + fmt(l.window_fetched_per_sec) + '/s, ' + tr('published') + ' ' + fmt(l.published_per_sec) + '/s'];
    if (l.eta_secs !== null) lines.push(tr('Estimated catch-up') + ': ' + fmtMs(l.eta_secs * 1000));
    if (l.last_error) lines.push(tr('Last problem') + ' ' + clock(l.last_error_ms) + ': ' + l.last_error);
    return lines.join('\n');
  };
  const problemsHint = (l) => [
    tr('Connection or HTTP failures') + ': ' + l.http_failures, tr('Rate-limit refusals') + ': ' + l.rate_limited,
    tr('Undecodable entries') + ': ' + l.undecodable, ...(l.last_error ? [tr('Last problem') + ' ' + clock(l.last_error_ms) + ': ' + l.last_error] : []),
  ].join('\n');
  const columns = [
    { id: 'name', label: 'Log', cell: (l) => h('span', { 'data-hint': [l.operator, l.kind, l.list_state].filter(Boolean).join(' · ') }, l.name) },
    { id: 'state', label: 'State', get: (l) => STATES[l.state][2], cell: (l) => h('span', { class: 'badge ' + STATES[l.state][1], 'data-hint': hintOf(l) }, STATES[l.state][0]) },
    { id: 'needed', label: 'Needed for target', get: (l) => (l.rank === null ? null : l.rank <= needed ? 1 : 0), cell: (l) => (l.rank === null ? '–' : l.rank <= needed ? 'Yes' : 'No') },
    { id: 'share', label: 'Share of certificates', num: true, get: (l) => l.share_pct, cell: (l) => h('span', {}, pct(l.share_pct), l.undercounted && l.share_pct !== null ? h('span', { class: 'quiet' }, ' undercounted') : null), tip: 'assess' },
    { id: 'alone', label: 'Adds alone', num: true, get: (l) => l.alone_pct, cell: (l) => pct(l.alone_pct) },
    { id: 'fetched', label: 'Fetched/s', num: true, get: (l) => l.fetched_per_sec, cell: (l) => fmt(l.fetched_per_sec) },
    { id: 'published', label: 'Published/s', num: true, get: (l) => l.published_per_sec, cell: (l) => fmt(l.published_per_sec) },
    { id: 'behind', label: 'Behind', num: true, get: (l) => l.behind, cell: (l) => fmt(l.behind) },
    { id: 'trend', label: 'Trend', num: true, get: (l) => l.behind_change, cell: (l) => h('span', { 'data-hint': tr('Change in behind over 15 minutes') }, signed(l.behind_change)) },
    { id: 'delay', label: 'Delay p50', num: true, get: (l) => l.delay_p50_ms, cell: (l) => fmtMs(l.delay_p50_ms) },
    { id: 'problems', label: 'Problems', num: true, get: (l) => l.problems, cell: (l) => h('span', { 'data-hint': problemsHint(l) }, l.problems) },
  ];
  const worstFirst = (a, b) => STATES[a.state][2] - STATES[b.state][2] || (b.share_pct ?? -1) - (a.share_pct ?? -1) || a.name.localeCompare(b.name);
  const grid = sortTable(tableHost, { columns, persist: opts.persist || 'logs', defaultSort: worstFirst, key: (l) => l.id });
  function paint() {
    if (!last) return;
    needed = last.coverage ? neededFor(last.coverage.order, coverageTarget(last)) : 0;
    const q = text.value.trim().toLowerCase();
    const rows = last.logs.filter((l) => (!opts.filter || opts.filter(l)) && (!q || l.name.toLowerCase().includes(q)) && (!pick.value || l.state === pick.value));
    grid.update(rows);
    tableHost.hidden = !rows.length;
    empty.hidden = Boolean(rows.length);
    opts.onCount?.(last.logs.filter((l) => l.state === 'healthy').length, last.logs.length);
  }
  text.addEventListener('input', paint);
  pick.addEventListener('change', paint);
  clear(host).append(h('div', { class: 'filters noprint' }, text, pick), tableHost, empty);
  onLogs((r) => { last = r; paint(); });
}

function keepingCard(host) {
  const BADGE = { catching_up: ['Catching up', 'good'], holding_steady: ['Holding steady', 'good'], falling_behind: ['Falling behind', 'bad'], measuring: ['Measuring', ''] };
  const line = (...kids) => h('p', { class: 'line' }, ...kids);
  onLogs((r) => {
    const v = r.verdict;
    const out = [h('div', {}, h('span', { class: 'badge big ' + BADGE[v.status][1] }, BADGE[v.status][0]))];
    if (v.status === 'measuring') {
      out.push(line('A verdict needs 5 minutes of data.'));
    } else {
      out.push(line('Over the last 15 minutes, logs published ' + fmt(v.published_per_sec) + '/s and we fetched ' + fmt(v.fetched_per_sec) + '/s.'));
      out.push(line('Backlog ' + fmt(v.backlog) + ', change ' + (v.backlog_change >= 0 ? '+' : '−') + fmt(Math.abs(v.backlog_change)) + '. On logs that rate-limit us: ' + fmt(v.limited_backlog) + '.'));
      if (v.eta_secs !== null) out.push(line('Estimated catch-up: ' + fmtMs(v.eta_secs * 1000)));
    }
    if (v.status !== 'measuring' && v.bottlenecks.length) {
      out.push(h('p', { class: 'line strong' }, 'Main bottleneck'));
      out.push(h('ul', { class: 'bottlenecks' }, ...v.bottlenecks.map((b) => h('li', {}, b.name + ': ', h('span', { class: 'badge ' + STATES[b.state][1] }, STATES[b.state][0]), ' ', h('span', {}, 'short by ' + fmt(b.shortfall_per_sec) + '/s')))));
    }
    if (v.cause_unclear) out.push(line('The cause is unclear: neither ctprobe nor a single log explains it.'));
    out.push(line(v.ctprobe_limit ? 'ctprobe itself is the limit' : 'ctprobe itself is not the limit', ': ', h('span', {}, 'pipeline ' + v.pipeline_busy_pct.toFixed(0) + '% busy, fetch queue ' + v.queue_full_pct.toFixed(0) + '% full.')));
    clear(host).append(...out);
  });
}

// DNS figures, fetched once for every part of a page that shows them.
const DNS_REFRESH_MS = 10000;
const dnsFeed = { subs: [], last: null, started: false };
function onDns(fn) {
  dnsFeed.subs.push(fn);
  if (dnsFeed.last) fn(dnsFeed.last);
  if (dnsFeed.started) return;
  dnsFeed.started = true;
  const poll = () => getJson('/api/dns').then((r) => { dnsFeed.last = r; dnsFeed.subs.forEach((f) => f(r)); }).catch(() => {});
  poll();
  setInterval(poll, DNS_REFRESH_MS);
}
const share = (n, d) => (d ? (100 * n / d).toFixed(1) + '%' : '–');

// Whether probing works now, and if not, the most likely cause.
function dnsVerdict(r) {
  const x = r.recent;
  if (!x || x.secs < 30) return ['Measuring', ''];
  if (!x.queries) return x.skipped ? ['Failing', 'bad'] : ['Idle', ''];
  const failed = 100 * (x.timeouts + x.errors) / x.queries;
  if (failed >= 50) return ['Failing', 'bad'];
  if (failed >= 5 || x.skipped || r.queue_error) return ['Strained', 'warn'];
  return ['Healthy', 'good'];
}

function dnsCause(r) {
  const x = r.recent, addr = r.resolver.addr;
  const top = Math.max(x.unreachable, x.timeouts, x.servfail, x.refused);
  if (!top || 100 * (x.timeouts + x.errors) / Math.max(1, x.queries) < 5) return null;
  if (top === x.unreachable) return 'Nothing answers at ' + addr + '. Check that the resolver runs.';
  if (top === x.timeouts) return 'The resolver at ' + addr + ' answers too slowly or cannot reach name servers. Check its log and any firewall.';
  if (top === x.servfail) return 'The resolver at ' + addr + ' fails to resolve. Its log says why.';
  return 'The resolver at ' + addr + ' refuses ctprobe. Check its access control.';
}

function dnsHealthCard(host) {
  const line = (...kids) => h('p', { class: 'line' }, ...kids);
  onDns((r) => {
    if (!r.enabled) { clear(host).append(line('DNS probing is off. Set a resolver under [dns] in the configuration to turn it on.')); return; }
    const [label, cls] = dnsVerdict(r);
    const x = r.recent;
    const out = [h('div', {}, h('span', { class: 'badge big ' + cls }, label))];
    if (x && x.secs >= 30) {
      const min = Math.round(x.secs / 60);
      out.push(line('Over the last ' + min + ' min: ' + fmt(x.queries / x.secs) + ' queries/s, ' + share(x.answers + x.nxdomain, x.queries) + ' answered, '
        + share(x.timeouts, x.queries) + ' timed out, ' + share(x.errors, x.queries) + ' errors.'));
      if (x.errors) out.push(line('Errors: SERVFAIL ' + fmt(x.servfail) + ', refused ' + fmt(x.refused) + ', unreachable ' + fmt(x.unreachable) + '.'));
      if (x.skipped) out.push(line('Skipped for lack of capacity: ' + fmt(x.skipped) + ' names.'));
    } else {
      out.push(line('A verdict needs a few minutes of queries.'));
    }
    const cause = dnsCause(r);
    if (cause) out.push(h('p', { class: 'line strong' }, cause));
    if (r.queue_error) out.push(h('p', { class: 'line err' }, 'Retry queue: ' + r.queue_error));
    const late = r.retry_late ? ', running late by a median of ' + fmtMs(r.retry_late.p50_ms) : '';
    out.push(line('Waiting for a later probe: ' + fmt(r.waiting) + ' names' + late + '.'));
    out.push(line(h('a', { href: '/dns' }, 'DNS details')));
    clear(host).append(...out);
  });
}

function coverageSummary(host) {
  const select = targetSelect();
  const text = h('span', {});
  const detail = h('p', { class: 'note' });
  clear(host).append(h('div', { class: 'filters noprint' }, h('label', {}, 'Coverage target', select), text), detail);
  onLogs((r) => {
    const c = r.coverage;
    if (!c) { text.textContent = 'Coverage appears after the first assessment, about 5 minutes after start.'; detail.textContent = ''; return; }
    const target = coverageTarget(r);
    const names = Object.fromEntries(r.logs.map((l) => [l.id, l.name]));
    const n = neededFor(c.order, target), ops = neededFor(c.operators, target);
    text.textContent = n + ' logs or ' + ops + ' operators reach this target.';
    detail.textContent = '';
    detail.append(h('span', {}, 'Operators: ' + c.operators.slice(0, ops).map((o) => o.key || '?').join(', ')), h('br', {}),
      h('span', {}, 'Logs: ' + c.order.slice(0, n).map((s) => names[s.key] || s.key).join(', ')), h('br', {}),
      h('span', {}, 'Based on ' + num.format(c.sampled_certs) + ' sampled certificates from the last 24 hours, worked out at ' + clock(c.computed_ms) + '. Logs we cannot read fully are undercounted.'));
  });
}

document.querySelectorAll('[data-nav]').forEach((a) => {
  if (a.dataset.nav === document.body.dataset.page) a.classList.add('on');
});
if (document.body.dataset.page !== 'live') {
  getJson('/api/live').then(applyStatus).catch(() => {});
  setInterval(() => getJson('/api/live').then(applyStatus).catch(() => {}), 5000);
}
