'use strict';
const WEEKS_2 = 14;
const SETTLE_DAYS = 90;
const BADGE = {
  ok: ['good', '✓ Reliable'],
  early: ['warn', '◐ Provisional'],
  upper: ['warn', '▲ Upper bound'],
  none: ['bad', '– Not yet'],
};
const badge = (k) => h('span', { class: 'badge ' + BADGE[k][0] }, BADGE[k][1]);
let exportRows = [];
const q = () => $('#range').value.split(':');
const trend = (m) => getJson('/api/trends/' + m + '?hours=' + q()[0] + '&bucket=' + q()[1]);
const rate = (v) => (v === null || v === undefined ? '–' : fmt(v) + ' /s');
const num2 = (v, d) => (v === null || v === undefined ? '–' : v.toFixed(d));
const toObj = (r, i) => Object.fromEntries(r.columns.map((c, n) => [c, r.rows[i]?.[n]]));

function logsFor(cov, pct) {
  const row = cov.rows.find((x) => x[4] >= pct);
  return row ? row[0] : null;
}

async function load() {
  const [sz, cost, cov, conc, stageRows, settle, quality, live, report] = await Promise.all(
    ['sizing', 'cost', 'coverage', 'concentration', 'stages', 'settling', 'quality'].map(trend).concat(getJson('/api/live'), getJson('/api/logs')));
  applyStatus(live);
  const s = toObj(sz, 0), c = toObj(cost, 0);
  const days = s.first_ms ? (s.last_ms - s.first_ms) / 86400000 : 0;
  const cleanPct = s.minutes ? 100 * s.clean_minutes / s.minutes : 0;
  const finished = stageRows.rows.filter((r) => r[0] !== 'today');
  const latest = finished[0] || stageRows.rows[0];
  const newPerSec = settle.rows.length ? settle.rows[settle.rows.length - 1][1] : null;
  const dup = latest && latest[2] ? latest[1] / latest[2] : null;
  const uniqueTyp = s.unique_p50 ?? s.unique_p50_all;
  const rawTyp = s.raw_p50 ?? s.raw_p50_all;
  const lastConc = conc.rows[conc.rows.length - 1];
  // Nightly coverage once it exists, the rolling assessment until then.
  const target = coverageTarget(report);
  const assessed = report.coverage;
  const nightlyLogs = logsFor(cov, target);
  const logsNeeded = nightlyLogs ?? (assessed ? neededFor(assessed.order, target) : null);
  const opsNeeded = assessed ? neededFor(assessed.operators, target) : null;

  const volume = days >= WEEKS_2 && cleanPct >= 50 ? 'ok' : 'early';
  const nightly = finished.length >= 7 ? 'ok' : finished.length ? 'early' : 'none';
  const age = days < 1 ? (days * 24).toFixed(1) + ' hours' : days.toFixed(1) + ' days';
  const volWhy = 'Based on ' + age + ' of data, ' + cleanPct.toFixed(0) + '% clean. Needs 14 days to include weekly patterns.';
  const nWhy = finished.length + ' finished days so far; needs 7.';

  const rows = [
    ['Unique certificates, typical', rate(uniqueTyp), volume, volWhy, 'unique'],
    ['Unique certificates, per day', fmt(uniqueTyp === null || uniqueTyp === undefined ? null : uniqueTyp * 86400), volume, 'Typical rate over a full day.', 'unique'],
    ['Unique certificates, p99 minute', rate(s.unique_p99), s.unique_p99 == null ? 'none' : volume, 'Clean minutes only, so catch-up does not count as a burst.', 'peaks'],
    ['Unique certificates, highest second', rate(s.unique_max), s.unique_max == null ? 'none' : volume, 'Clean minutes only.', 'peaks'],
    ['Raw entries, typical', rate(rawTyp), volume, 'Download and parse load for following all logs.', 'raw'],
    ['Duplication factor', dup ? dup.toFixed(1) + '×' : '–', nightly === 'none' ? 'early' : nightly, 'Raw entries per unique certificate.', 'dup'],
    ['Never-seen domains', rate(newPerSec), newPerSec === null ? 'none' : days >= SETTLE_DAYS ? 'ok' : 'upper', 'Includes renewing domains not seen yet. Needs about 90 days to settle.', 'domains'],
    ['Logs for ' + target + '% of certificates', logsNeeded ?? '–', logsNeeded === null ? 'none' : nightlyLogs === null ? 'early' : nightly, nightlyLogs === null ? 'Early assessment from the last 24 hours.' : nWhy, 'coverage'],
    ['Operators for ' + target + '% of certificates', opsNeeded ?? '–', opsNeeded === null ? 'none' : 'early', 'A rule on operators survives log rotation.', 'assess'],
    ['Top 1000 domains, share', lastConc ? lastConc[3].toFixed(1) + '%' : '–', lastConc ? nightly : 'none', nWhy, 'concentration'],
    ['CPU per million certificates', c.cpu_seconds_per_million == null ? '–' : c.cpu_seconds_per_million.toFixed(0) + ' s', 'early', 'Measured on this machine, not the target hardware.', 'cost'],
    ['Disk per million certificates', fmtBytes(c.disk_bytes_per_million), 'early', 'Falls after nightly compaction.', 'cost'],
    ['Tracker memory per name', c.tracker_bytes_per_name == null ? '–' : num2(c.tracker_bytes_per_name, 1) + ' bytes', 'early', 'Rises and falls as tables double.', 'tracker'],
  ];
  exportRows = rows.map((r) => [r[0], r[1], BADGE[r[2]][1], r[3]]);

  $('#lead').textContent = days
    ? 'Measured from ' + new Date(s.first_ms).toISOString().slice(0, 10) + ' to ' + new Date(s.last_ms).toISOString().slice(0, 10) + ', ' + age + ' of collection across ' + live.logs.length + ' logs. '
      + (volume === 'ok' ? 'Volume figures are ready for sizing.' : 'Figures are provisional until 14 days of mostly clean data exist.')
    : 'No measurements yet.';

  const hero = (k, row) => h('div', { class: 'card' }, h('div', { class: 'v' }, row[1]), h('div', { class: 'k' }, k, info(row[4])), badge(row[2]));
  clear($('#hero')).append(hero('Unique certificates, typical', rows[0]), hero('Peak minute, p99', rows[2]), hero('Never-seen domains', rows[6]), hero('Logs for ' + target + '% coverage', rows[7]));

  clear($('#figures')).append(h('table', {},
    h('thead', {}, h('tr', {}, h('th', {}, 'Figure'), h('th', { class: 'num' }, 'Value'), h('th', {}, 'Confidence'), h('th', {}, 'Note'))),
    h('tbody', {}, ...rows.map((r) => h('tr', {}, h('td', {}, r[0], info(r[4])), h('td', { class: 'num' }, r[1]), h('td', {}, badge(r[2])), h('td', { class: 'why' }, r[3]))))));

  const host = clear($('#settling'));
  if (settle.rows.length) lineChart(host, { data: [settle.rows.map((r) => r[0]), settle.rows.map((r) => r[1])], series: [{ label: 'Never-seen domains per second' }], points: settle.rows.length < 3, height: 240 });
  else host.append(h('div', { class: 'empty' }, 'No data yet'));

  $('#stages-sub').textContent = latest ? 'For ' + latest[0] + ', from raw entries to never-seen domains' : '';
  const stages = latest ? [['Raw entries', latest[1]], ['Unique certificates', latest[2]], ['Names', latest[3]], ['Never-seen names', latest[4]], ['Never-seen domains', latest[5]]] : [];
  const top = Math.max(1, ...stages.map((x) => x[1]));
  clear($('#stages')).append(...stages.map(([k, v]) => h('div', { class: 'bar-row' }, h('span', {}, k),
    h('div', { class: 'bar-track' }, h('div', { class: 'bar', style: 'width:' + (100 * v / top).toFixed(2) + '%' })),
    h('span', { class: 'n' }, fmt(v)))));

  const qt = (k, v) => h('div', { class: 'card tile' }, h('div', { class: 'v' }, v), h('div', { class: 'k' }, k));
  clear($('#quality-tiles')).append(qt('Clean minutes', cleanPct.toFixed(0) + '%'), qt('Logs fetching cleanly', fmt(report.logs.filter((l) => l.state !== 'failing').length)), qt('Backlog now', fmt(live.behind_total)));
  const qh = clear($('#quality'));
  if (quality.rows.length) lineChart(qh, { data: [quality.rows.map((r) => r[0]), quality.rows.map((r) => r[1]), quality.rows.map((r) => r[2])], series: [{ label: 'Backlog' }, { label: 'Rate-limited backlog' }], points: quality.rows.length < 3, height: 200 });
  else qh.append(h('div', { class: 'empty' }, 'No data yet'));

}

function exportCsv() {
  const esc = (v) => '"' + String(v).replace(/"/g, '""') + '"';
  const text = [['Figure', 'Value', 'Confidence', 'Note'], ...exportRows].map((r) => r.map((v) => esc(tr(String(v)))).join(LANG === 'de' ? ';' : ',')).join('\n') + '\n';
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: 'text/csv' }));
  a.download = 'ctprobe-sizing.csv';
  a.click();
}

keepingCard($('#keeping'));
coverageSummary($('#coverage'));
logTable($('#logs'), { filter: (l) => l.state !== 'healthy', emptyText: 'All logs are healthy', persist: 'attention' });
$('#keeping-h').append(info('keeping'));
$('#settle-h').append(info('domains'));
$('#stages-h').append(info('stages'));
$('#quality-h').append(info('clean'));
$('#print').addEventListener('click', () => window.print());
$('#csv').addEventListener('click', exportCsv);
$('#range').addEventListener('change', () => load().catch(fail));
function fail(e) { $('#lead').textContent = e.message; $('#lead').className = 'err'; }
load().catch(fail);
setInterval(() => load().catch(() => {}), 300000);
