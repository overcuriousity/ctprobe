// German interface text. English is the source language. Text is swapped by
// exact match on rendered nodes, so page code stays language-neutral. Anything
// under [data-raw] (SQL results, PEM) is left exactly as it came.
'use strict';
// English unless German was chosen with the language button.
const LANG = localStorage.getItem('lang') === 'de' ? 'de' : 'en';
document.documentElement.lang = LANG;

const DE = {
  'DNS': 'DNS', 'First probe': 'Erste Abfrage', 'What each name resolved to when its certificate was seen': 'Wohin jeder Name aufgelöst wurde, als sein Zertifikat gesehen wurde',
  'Time to DNS': 'Zeit bis DNS', 'Names without an address at first, probed again for up to 30 days': 'Namen zunächst ohne Adresse, bis zu 30 Tage lang erneut abgefragt',
  'Changes between certificates': 'Änderungen zwischen Zertifikaten', "A name's first probe against the last answer held for it": 'Erste Abfrage eines Namens gegenüber der zuletzt gespeicherten Antwort',
  'Wildcards': 'Wildcards', 'Asked as written, and for the name they cover when the certificate does not list it': 'Wörtlich abgefragt, und für den abgedeckten Namen, wenn das Zertifikat ihn nicht enthält',
  'Names probed': 'Abgefragte Namen', 'Every name of every unique certificate, renewals included': 'Jeder Name jedes eindeutigen Zertifikats, Erneuerungen eingeschlossen',
  'Resolver': 'Resolver', 'Per query, with A and AAAA counted apart': 'Pro Abfrage, A und AAAA getrennt gezählt',
  'Over time': 'Im Zeitverlauf', 'Shares of first probes, and of answers that changed since an earlier day': 'Anteile der ersten Abfragen und der seit einem früheren Tag geänderten Antworten',
  'All names': 'Alle Namen', 'Names seen before': 'Früher gesehene Namen', 'Outcome': 'Ergebnis', 'Has an address': 'Hat eine Adresse', 'IPv4': 'IPv4', 'IPv6': 'IPv6', 'IPv4 and IPv6': 'IPv4 und IPv6',
  'Exists, no address': 'Existiert, keine Adresse', 'Does not exist': 'Existiert nicht', 'Resolver failed': 'Resolver gescheitert', 'Wildcard record': 'Wildcard-Eintrag', 'Covered name': 'Abgedeckter Name',
  'Never found': 'Nie gefunden', 'At sighting': 'Bei Sichtung', 'No name has resolved on a later probe yet.': 'Noch kein Name wurde bei einer späteren Abfrage aufgelöst.',
  'Last answer from': 'Letzte Antwort von', 'Compared': 'Verglichen', 'Any change': 'Jede Änderung', 'An earlier day': 'Einem früheren Tag', 'The same day': 'Demselben Tag',
  'IPv4 changed': 'IPv4 geändert', 'IPv4 all replaced': 'IPv4 vollständig ersetzt', 'IPv6 changed': 'IPv6 geändert', 'IPv6 all replaced': 'IPv6 vollständig ersetzt',
  'Alias changed': 'Alias geändert', 'Network changed': 'Netz geändert', 'Outcome changed': 'Ergebnis geändert',
  'Certificates': 'Zertifikate', 'Queued for probing': 'Zur Abfrage eingereiht', 'Outside the sample': 'Außerhalb der Stichprobe', 'Already being probed': 'Wird bereits abgefragt',
  'Skipped, over the query budget': 'Übersprungen, über dem Abfragebudget', 'Not valid DNS names': 'Keine gültigen DNS-Namen',
  'Queries': 'Abfragen', 'Answers': 'Antworten', 'NXDOMAIN': 'NXDOMAIN', 'Timeouts': 'Zeitüberschreitungen', 'Latency p50': 'Latenz p50', 'Latency p99': 'Latenz p99',
  'Probes per second': 'Abfragen pro Sekunde', 'Address at first probe': 'Adresse bei erster Abfrage', 'Found later': 'Später gefunden',
  'IPv4 changed since an earlier day': 'IPv4 seit einem früheren Tag geändert', 'IPv6 changed since an earlier day': 'IPv6 seit einem früheren Tag geändert',
  'DNS probing is off. Set a resolver under [dns] in the configuration to turn it on.': 'DNS-Abfragen sind aus. Zum Einschalten einen Resolver unter [dns] in der Konfiguration eintragen.',
  'resolved': 'aufgelöst', 'v4': 'v4', 'v6': 'v6', 'nxdomain': 'NXDOMAIN', 'v4 changed': 'v4 geändert', 'v6 changed': 'v6 geändert', 'network changed': 'Netz geändert',
  'A and AAAA of each name, asked when its certificate is seen. Names seen before belong to probable renewals.': 'A und AAAA jedes Namens, abgefragt, wenn sein Zertifikat gesehen wird. Früher gesehene Namen gehören zu wahrscheinlichen Erneuerungen.',
  'A name without an address is asked again on a schedule from its sighting, up to 30 days, until it resolves. It appeared between the last probe that missed and the first that found it.': 'Ein Name ohne Adresse wird ab seiner Sichtung nach Zeitplan bis zu 30 Tage lang erneut abgefragt, bis er aufgelöst wird. Er erschien zwischen der letzten erfolglosen und der ersten erfolgreichen Abfrage.',
  'Any change counts a different address, alias or outcome. Only first probes are compared, against the last answer held for the name.': 'Jede Änderung zählt eine andere Adresse, einen anderen Alias oder ein anderes Ergebnis. Verglichen werden nur erste Abfragen, mit der zuletzt gespeicherten Antwort des Namens.',
  'Of names that had addresses of this family both times, the share whose set of addresses differs.': 'Von den Namen, die beide Male Adressen dieser Familie hatten, der Anteil mit anderer Adressmenge.',
  'No address in common with the earlier answer. Counted where every earlier address is known; the first four IPv4 and two IPv6 addresses are kept.': 'Keine Adresse gemeinsam mit der früheren Antwort. Gezählt, wo alle früheren Adressen bekannt sind; gespeichert werden die ersten vier IPv4- und zwei IPv6-Adressen.',
  'Ignores addresses rotating behind the same alias and, without an alias, within the same /24 or /48.': 'Übergeht Adressen, die hinter demselben Alias oder ohne Alias innerhalb desselben /24 oder /48 wechseln.',
  'Mostly renewals and reissues, whose names last resolved on an earlier day.': 'Meist Erneuerungen und Neuausstellungen, deren Namen zuletzt an einem früheren Tag aufgelöst wurden.',
  'Mostly the same name in another certificate on the same day, such as from a second CA.': 'Meist derselbe Name in einem anderen Zertifikat desselben Tages, etwa von einer zweiten CA.',
  'A wildcard asked as written finds a wildcard record if one exists. The covered name is asked only when the certificate does not list it too.': 'Eine wörtlich abgefragte Wildcard findet einen Wildcard-Eintrag, falls einer existiert. Der abgedeckte Name wird nur abgefragt, wenn das Zertifikat ihn nicht ebenfalls enthält.',
  'Probing never slows ingest. A fixed sample of names, chosen by a hash of the name, is probed on every certificate. Names that do not fit the query budget in a burst are skipped and counted here.': 'Die Abfragen bremsen die Aufnahme nie. Eine feste, per Hash des Namens gewählte Stichprobe wird bei jedem Zertifikat abgefragt. Namen, die in einer Spitze nicht ins Abfragebudget passen, werden übersprungen und hier gezählt.',
  'The resolver says the name does not exist.': 'Der Resolver meldet, dass der Name nicht existiert.',
  'Live': 'Live', 'Sizing': 'Dimensionierung', 'Trends': 'Trends', 'Search': 'Suche', 'SQL': 'SQL', 'Dark': 'Dunkel', 'Light': 'Hell', 'Domain': 'Domain', 'Certificate': 'Zertifikat',
  'Rates, last 5 minutes': 'Raten, letzte 5 Minuten', 'Entries per second, all logs': 'Einträge pro Sekunde, alle Logs',
  'Processing stages since start': 'Verarbeitungsstufen seit Start', 'What each stage leaves for the next': 'Was jede Stufe für die nächste übrig lässt',
  'New certificates': 'Neue Zertifikate', 'Filtered text feed, at most 200 per second': 'Gefilterter Textfeed, höchstens 200 pro Sekunde', 'Filter by name': 'Nach Name filtern', 'Filter feed': 'Feed filtern', 'Logs': 'Logs',
  'Unique certificates/s': 'Eindeutige Zertifikate/s', 'Raw entries/s': 'Rohe Einträge/s', 'Never-seen names/s': 'Nie gesehene Namen/s', 'Never-seen domains/s': 'Nie gesehene Domains/s',
  'Duplication factor': 'Duplikationsfaktor', 'raw entries per unique': 'rohe Einträge pro eindeutigem Zertifikat', 'Probable renewals': 'Wahrscheinliche Erneuerungen', 'Tracked names': 'Erfasste Namen', 'Process': 'Prozess',
  'Raw entries': 'Rohe Einträge', 'Unique certificates': 'Eindeutige Zertifikate', 'Names': 'Namen', 'Never-seen names': 'Nie gesehene Namen', 'Never-seen domains': 'Nie gesehene Domains',
  'Log': 'Log', 'Type': 'Typ', 'Behind': 'Rückstand', 'Lag p50': 'Verzögerung p50', 'Errors': 'Fehler', '429s': '429er', 'Bad': 'Defekt', 'State': 'Status', 'Rate-limited': 'Ratenbegrenzt', 'Failing': 'Ausgefallen',
  'Range': 'Zeitraum', 'Time range': 'Zeitraum', '6 hours': '6 Stunden', '48 hours': '48 Stunden', '14 days': '14 Tage', '90 days': '90 Tage', 'All': 'Alles',
  'Volume': 'Volumen', 'Entries per second': 'Einträge pro Sekunde', 'Peaks': 'Spitzen', 'Unique certificates per second: median and p99 minute, highest second': 'Eindeutige Zertifikate pro Sekunde: Median- und p99-Minute, höchste Sekunde',
  'Backlog': 'Rückstand', 'Entries published but not fetched yet': 'Veröffentlichte, noch nicht abgerufene Einträge', 'New vs probable renewals': 'Neu gegenüber wahrscheinlichen Erneuerungen', 'Certificates by name match': 'Zertifikate nach Namensübereinstimmung',
  'State growth': 'Zustandswachstum', 'Distinct names tracked': 'Erfasste unterschiedliche Namen', 'Resources': 'Ressourcen', 'Bytes': 'Bytes', 'Concentration': 'Konzentration',
  "Percent of a day's certificates from the top registered domains; after the first nightly run": 'Anteil der Zertifikate eines Tages von den aktivsten registrierten Domains; nach dem ersten Nachtlauf',
  'Issuers': 'Aussteller', 'TLDs': 'TLDs', 'Key types': 'Schlüsseltypen', 'Validity': 'Gültigkeit', 'SANs per certificate': 'SANs pro Zertifikat', 'Certificate size': 'Zertifikatsgröße', 'Certificates in range': 'Zertifikate im Zeitraum',
  'Processing stages by day': 'Verarbeitungsstufen pro Tag', 'Each stage is what the next one must handle': 'Jede Stufe ist das, was die nächste bewältigen muss',
  'Log coverage': 'Log-Abdeckung', 'Best N logs for the last finished day; available after the first nightly run': 'Beste N Logs des letzten abgeschlossenen Tages; verfügbar nach dem ersten Nachtlauf',
  'Detection latency by log': 'Erkennungslatenz pro Log', 'Delay until we saw the entry, from its SCT timestamp and from notBefore': 'Verzögerung bis zur Sichtung des Eintrags, ab SCT-Zeitstempel und ab notBefore',
  'Catch-up capacity by log': 'Aufholkapazität pro Log', 'Capacity is entries per second of active fetching; compare with the live rate': 'Kapazität ist Einträge pro Sekunde aktiven Abrufens; im Vergleich zur Live-Rate',
  'CPU per million certificates': 'CPU pro Million Zertifikate', 'Disk per million certificates': 'Speicher pro Million Zertifikate', 'Tracker bytes per name': 'Tracker-Bytes pro Name', 'Unique certificates in range': 'Eindeutige Zertifikate im Zeitraum',
  'No data in this range yet': 'Noch keine Daten in diesem Zeitraum', 'No data yet': 'Noch keine Daten', 'CSV': 'CSV',
  'raw per sec': 'roh pro s', 'unique per sec': 'eindeutig pro s', 'p50 per sec': 'p50 pro s', 'p99 per sec': 'p99 pro s', 'max per sec': 'Maximum pro s', 'new': 'neu', 'name match': 'Namensübereinstimmung', 'exact match': 'exakte Übereinstimmung', 'exact': 'exakt', 'name': 'Name',
  'names': 'Namen', 'memory bytes': 'Arbeitsspeicher-Bytes', 'disk bytes': 'Speicher-Bytes', 'tracker bytes': 'Tracker-Bytes', 'top 10 pct': 'Top 10 %', 'top 100 pct': 'Top 100 %', 'top 1000 pct': 'Top 1000 %', 'backlog': 'Rückstand', 'rate limited backlog': 'Ratenbegrenzter Rückstand',
  'day': 'Tag', 'raw_entries': 'rohe Einträge', 'unique_certs': 'eindeutige Zertifikate', 'new_names': 'nie gesehene Namen', 'new_domains': 'nie gesehene Domains', 'today': 'heute',
  'n': 'n', 'log_id': 'Log', 'added_certs': 'hinzugefügt', 'cumulative_certs': 'kumuliert', 'cumulative_pct': 'kumuliert %', 'entries': 'Einträge', 'http_429': '429er', 'errors': 'Fehler', 'live_per_sec': 'Live pro s', 'capacity_per_sec': 'Kapazität pro s',
  'sct_p50_ms': 'SCT p50', 'sct_p99_ms': 'SCT p99', 'not_before_p50_ms': 'notBefore p50', 'not_before_p99_ms': 'notBefore p99',
  'Certificate Transparency volume': 'Certificate-Transparency-Volumen', 'Period': 'Zeitraum', 'Last 7 days': 'Letzte 7 Tage', 'Last 30 days': 'Letzte 30 Tage', 'All data': 'Alle Daten', 'Export CSV': 'CSV exportieren', 'Print or save PDF': 'Drucken oder als PDF speichern',
  'All figures': 'Alle Kennzahlen', 'The confidence column says how far each figure can be used for sizing today.': 'Die Spalte Belastbarkeit zeigt, wie weit jede Kennzahl heute für die Dimensionierung taugt.',
  'Figure': 'Kennzahl', 'Value': 'Wert', 'Confidence': 'Belastbarkeit', 'Note': 'Hinweis', '✓ Reliable': '✓ Belastbar', '◐ Provisional': '◐ Vorläufig', '▲ Upper bound': '▲ Obergrenze', '– Not yet': '– Noch nicht',
  'Unique certificates, typical': 'Eindeutige Zertifikate, typisch', 'Unique certificates, per day': 'Eindeutige Zertifikate pro Tag', 'Unique certificates, p99 minute': 'Eindeutige Zertifikate, p99-Minute', 'Unique certificates, highest second': 'Eindeutige Zertifikate, höchste Sekunde',
  'Raw entries, typical': 'Rohe Einträge, typisch', 'Logs for 95% of certificates': 'Logs für 95 % der Zertifikate', 'Logs for 99% of certificates': 'Logs für 99 % der Zertifikate', 'Top 1000 domains, share': 'Anteil der Top-1000-Domains',
  'Tracker memory per name': 'Tracker-Speicher pro Name', 'Peak minute, p99': 'Spitzenminute, p99', 'Logs for 95% coverage': 'Logs für 95 % Abdeckung',
  'Typical rate over a full day.': 'Typische Rate über einen ganzen Tag.', 'Clean minutes only, so catch-up does not count as a burst.': 'Nur saubere Minuten, damit Aufholen nicht als Lastspitze zählt.', 'Clean minutes only.': 'Nur saubere Minuten.',
  'Download and parse load for following all logs.': 'Download- und Parsing-Last, wenn man allen Logs folgt.', 'Raw entries per unique certificate.': 'Rohe Einträge pro eindeutigem Zertifikat.',
  'Includes renewing domains not seen yet. Needs about 90 days to settle.': 'Enthält noch nicht gesehene Erneuerungen. Braucht etwa 90 Tage, um sich einzupendeln.',
  'Measured on this machine, not the target hardware.': 'Auf diesem Rechner gemessen, nicht auf der Zielhardware.', 'Falls after nightly compaction.': 'Sinkt nach der nächtlichen Komprimierung.', 'Rises and falls as tables double.': 'Schwankt, weil sich Tabellen verdoppeln.',
  'Per second. A flattening curve means the figure is reaching its real level.': 'Pro Sekunde. Flacht die Kurve ab, erreicht die Zahl ihr echtes Niveau.', 'Never-seen domains per second': 'Nie gesehene Domains pro Sekunde',
  'Processing stages': 'Verarbeitungsstufen', 'Data quality': 'Datenqualität', 'Backlog over time': 'Rückstand im Zeitverlauf', 'Clean minutes': 'Saubere Minuten', 'Logs fetching cleanly': 'Fehlerfrei abrufende Logs', 'Backlog now': 'Aktueller Rückstand', 'Rate-limited backlog': 'Ratenbegrenzter Rückstand',
  'Logs needing attention': 'Logs mit Handlungsbedarf', 'Logs that are behind, rate-limiting us, or failing': 'Logs mit Rückstand, Ratenbegrenzung oder Ausfall', 'All logs are healthy': 'Alle Logs sind in Ordnung', 'No measurements yet.': 'Noch keine Messwerte.',
  'example.com, paypal, or %.example.com': 'example.com, paypal oder %.example.com', 'Match type': 'Suchart', 'Exact domain': 'Exakte Domain', 'Contains': 'Enthält', 'Levenshtein': 'Levenshtein', 'Homoglyph': 'Homoglyphen', 'All names (slow)': 'Alle Namen (langsam)', 'Edit distance': 'Editierdistanz', 'Distance 1': 'Distanz 1', 'Distance 2': 'Distanz 2',
  "A query without a dot compares against each domain's first label, so": 'Eine Suche ohne Punkt vergleicht mit dem ersten Label jeder Domain, also findet', 'finds lookalikes under any TLD. Use': 'Ähnliche unter jeder TLD. Nutzen Sie', 'as a wildcard in All names.': 'als Platzhalter bei „Alle Namen“.',
  'Domains': 'Domains', 'Closest first. Select one for its full picture.': 'Ähnlichste zuerst. Wählen Sie eine für das Gesamtbild.', 'Certificates': 'Zertifikate', 'Certificates are kept for the rolling window; older ones appear only in domain totals.': 'Zertifikate bleiben für das rollierende Zeitfenster erhalten; ältere erscheinen nur in Domain-Summen.',
  'domain': 'Domain', 'score': 'Wert', 'first seen': 'zuerst gesehen', 'last seen': 'zuletzt gesehen', 'certs': 'Zertifikate', 'No domain matches': 'Keine passende Domain', 'Searching…': 'Suche läuft…', 'Loading…': 'Wird geladen…',
  'From': 'Von', 'To': 'Bis', 'Issuer': 'Aussteller', 'Issuer CN': 'Aussteller-CN', 'Renewal class': 'Erneuerungsklasse', 'Any renewal class': 'Jede Erneuerungsklasse', 'New': 'Neu', 'Name match': 'Namensübereinstimmung', 'Exact match': 'Exakte Übereinstimmung', 'Wildcard': 'Wildcard', 'Wildcard or not': 'Mit oder ohne Wildcard', 'Wildcard only': 'Nur Wildcard', 'No wildcard': 'Keine Wildcard', 'Random N': 'Zufällig N', 'Random sample size': 'Stichprobengröße', 'Apply': 'Anwenden',
  'seen_at': 'gesehen', 'cn': 'CN', 'issuer_cn': 'Aussteller', 'not_after': 'gültig bis', 'san_count': 'SANs', 'renewal': 'Erneuerung', 'days_since_seen': 'Tage seit Sichtung', 'detail': 'Details', 'open': 'öffnen',
  'No certificates match in the rolling window': 'Keine passenden Zertifikate im rollierenden Zeitfenster',
  'First seen': 'Zuerst gesehen', 'Last seen': 'Zuletzt gesehen', 'Certificates, all time': 'Zertifikate, gesamt', 'Certificates in window': 'Zertifikate im Zeitfenster', 'Certificates per day': 'Zertifikate pro Tag', 'Within the rolling window': 'Im rollierenden Zeitfenster', "Names on this domain's certificates": 'Namen auf den Zertifikaten dieser Domain',
  'Similar domains': 'Ähnliche Domains', 'Same label one edit away under any TLD, or visually confusable': 'Gleiches Label eine Änderung entfernt unter jeder TLD, oder optisch verwechselbar', 'None': 'Keine',
  'Only where this is the primary domain. Use All names in Search for certificates that list it as a further SAN.': 'Nur wo dies die primäre Domain ist. Für Zertifikate mit ihr als weiterem SAN nutzen Sie „Alle Namen“ in der Suche.',
  'Seen in Certificate Transparency since collection began.': 'Seit Beginn der Erfassung in Certificate Transparency gesehen.', 'Not seen since collection began. Platforms such as pages.dev are public suffixes, so each site on them is its own domain.': 'Seit Beginn der Erfassung nicht gesehen. Plattformen wie pages.dev sind öffentliche Suffixe, jede Website dort ist also eine eigene Domain.', 'No domain given.': 'Keine Domain angegeben.',
  'Read-only. One SELECT, 30 second limit. Ctrl+Enter runs it.': 'Nur lesend. Ein SELECT, Limit 30 Sekunden. Strg+Enter führt es aus.', 'SQL query': 'SQL-Abfrage', 'Run': 'Ausführen', 'Example queries': 'Beispielabfragen', 'Examples': 'Beispiele', 'Tables': 'Tabellen', 'Running…': 'Läuft…', 'No rows': 'Keine Zeilen',
  'Top issuers today': 'Häufigste Aussteller heute', 'Newest domains in a TLD': 'Neueste Domains einer TLD', 'Random sample of first-seen names': 'Zufallsstichprobe erstmals gesehener Namen',
  'Original': 'Original', 'Subject CN': 'Subject-CN', 'Serial': 'Seriennummer', 'Valid': 'Gültig', 'Key': 'Schlüssel', 'Signature': 'Signatur', 'SANs': 'SANs', 'Logged': 'Geloggt', 'Precertificate': 'Vorzertifikat', '(none)': '(keine)', '(no name)': '(kein Name)',
  'Fetched from the log.': 'Aus dem Log abgerufen.', 'Fetched from the log. Precertificates are stored as the TBSCertificate.': 'Aus dem Log abgerufen. Vorzertifikate liegen als TBSCertificate vor.',
  'Time': 'Zeit', 'Switch colour theme': 'Farbschema wechseln', 'Switch language': 'Sprache wechseln',
  'Distinct certificates. A precertificate and its final certificate count once, however many logs carry them. This is the real issuance rate.': 'Unterschiedliche Zertifikate. Ein Vorzertifikat und sein endgültiges Zertifikat zählen einmal, egal in wie vielen Logs sie stehen. Das ist die echte Ausstellungsrate.',
  'Log entries before removing duplicates. This is what a client must download and parse if it follows every log.': 'Log-Einträge vor dem Entfernen von Duplikaten. So viel muss ein Client laden und parsen, wenn er jedem Log folgt.',
  'Raw entries per unique certificate. High values mean following fewer logs would save a lot of work.': 'Rohe Einträge pro eindeutigem Zertifikat. Hohe Werte heißen: Weniger Logs zu verfolgen spart viel Arbeit.',
  'Names not seen since collection began. Without backfill, renewing names look new at first, so this falls for months and is an upper bound.': 'Namen, die seit Beginn der Erfassung nicht gesehen wurden. Ohne Backfill wirken erneuernde Namen zunächst neu; der Wert sinkt daher über Monate und ist eine Obergrenze.',
  'Registered domains not seen since collection began. Without backfill, it is an upper bound for the first 90 days or more.': 'Registrierte Domains, die seit Beginn der Erfassung nicht gesehen wurden. Ohne Backfill eine Obergrenze für mindestens die ersten 90 Tage.',
  'Certificates whose CN or SANs were seen before. Exact means the same full set of names. Falls short of the truth until a full renewal cycle has been observed.': 'Zertifikate, deren CN oder SANs schon gesehen wurden. Exakt heißt: dieselbe vollständige Namensmenge. Liegt unter dem echten Wert, bis ein ganzer Erneuerungszyklus beobachtet wurde.',
  'Each stage is what the next one has to handle. The later stages are what matter for sizing.': 'Jede Stufe ist das, was die nächste bewältigen muss. Für die Dimensionierung zählen vor allem die späteren Stufen.',
  'How many logs are needed to see a share of all certificates, picking the most useful log first. Calculated nightly.': 'Wie viele Logs nötig sind, um einen Anteil aller Zertifikate zu sehen, das nützlichste Log zuerst. Wird nachts berechnet.',
  'Share of certificates from the most active registered domains. High values suggest a pre-filter could remove much of the load.': 'Anteil der Zertifikate von den aktivsten registrierten Domains. Hohe Werte deuten darauf hin, dass ein Vorfilter viel Last entfernen könnte.',
  'Median and 99th percentile minute, and the highest single second. Size for these, not the average. Only clean minutes are used on the Sizing page.': 'Median- und 99.-Perzentil-Minute sowie die höchste einzelne Sekunde. Dimensionieren Sie dafür, nicht für den Durchschnitt. Die Seite Dimensionierung nutzt nur saubere Minuten.',
  'A clean minute has a backlog under one minute of volume on logs that accept our request rate, so its rates reflect issuance and not catch-up.': 'In einer sauberen Minute liegt der Rückstand der Logs, die unsere Abrufrate akzeptieren, unter einer Minute Volumen. Ihre Raten zeigen also Ausstellung, kein Aufholen.',
  'Entries published by logs but not yet fetched. Rate-limited logs are shown apart because they stay behind however fast we are.': 'Von Logs veröffentlichte, noch nicht abgerufene Einträge. Ratenbegrenzte Logs stehen getrennt, weil sie unabhängig von unserem Tempo im Rückstand bleiben.',
  'Delay from the log timestamp or certificate start to our sighting. It sets the lower limit on how fast anything built on this data can react.': 'Verzögerung vom Log-Zeitstempel oder Zertifikatsbeginn bis zu unserer Sichtung. Sie begrenzt, wie schnell alles reagieren kann, was auf diesen Daten aufbaut.',
  'Entries per second of active fetching. If it is near the live rate, one client from this IP cannot catch up after an outage.': 'Einträge pro Sekunde aktiven Abrufens. Liegt das nahe der Live-Rate, kann ein Client dieser IP nach einem Ausfall nicht aufholen.',
  'Measured on this machine, so re-check on the target hardware. Disk figures fall after nightly compaction.': 'Auf diesem Rechner gemessen, also auf der Zielhardware erneut prüfen. Speicherwerte sinken nach der nächtlichen Komprimierung.',
  'Names held in memory for renewal detection. It grows daily.': 'Namen im Arbeitsspeicher für die Erneuerungserkennung. Wächst täglich.',
  'Certificate lifetime. Shorter limits take effect in March 2027 and March 2029, so the same sites will issue more often.': 'Zertifikatslaufzeit. Kürzere Grenzen gelten ab März 2027 und März 2029, dieselben Websites stellen dann also häufiger aus.',
  "Cut short by the time limit. Try a narrower date range.": "Wegen des Zeitlimits gekürzt. Wählen Sie einen kürzeren Zeitraum.",
  "Rates": "Raten",
  "Entries per second, 60-second average, all logs": "Einträge pro Sekunde, 60-Sekunden-Mittel, alle Logs",
  "Time frame": "Zeitraum",
  "5 minutes": "5 Minuten",
  "15 minutes": "15 Minuten",
  "1 hour": "1 Stunde",
  "12 hours": "12 Stunden",
  "24 hours": "24 Stunden",
  "From log entries to new domains": "Von Log-Einträgen zu neuen Domains",
  "No data in this time frame yet": "Noch keine Daten in diesem Zeitraum",
  "Hostnames": "Hostnamen",
  "Never-seen hostnames": "Nie gesehene Hostnamen",
  "What the logs delivered": "Was die Logs geliefert haben",
  "After removing duplicates": "Nach Entfernen der Duplikate",
  "In those certificates; one can hold many": "In diesen Zertifikaten; eines kann viele enthalten",
  "Not seen since collection began": "Seit Beginn der Erfassung nicht gesehen",
  "Registered domains not seen before": "Bisher nicht gesehene registrierte Domains",
  "Keeping up?": "Halten wir Schritt?",
  "Catching up": "Holt auf",
  "Holding steady": "Hält Schritt",
  "Falling behind": "Fällt zurück",
  "Measuring": "Wird gemessen",
  "Healthy": "In Ordnung",
  "Not advancing": "Wächst nicht",
  "Paused": "Pausiert",
  "A verdict needs 5 minutes of data.": "Eine Aussage braucht 5 Minuten Daten.",
  "Main bottleneck": "Größter Engpass",
  "The cause is unclear: neither ctprobe nor a single log explains it.": "Die Ursache ist unklar: Weder ctprobe noch ein einzelnes Log erklären es.",
  "ctprobe itself is the limit": "ctprobe selbst ist die Grenze",
  "ctprobe itself is not the limit": "ctprobe selbst ist nicht die Grenze",
  "Filter by log name": "Nach Log-Name filtern",
  "Filter logs by name": "Logs nach Name filtern",
  "Filter logs by state": "Logs nach Status filtern",
  "Any state": "Jeder Status",
  "No logs match": "Keine passenden Logs",
  "Needed for target": "Für Ziel nötig",
  "Share of certificates": "Anteil der Zertifikate",
  "Adds alone": "Nur hier",
  "Fetched/s": "Abgerufen/s",
  "Published/s": "Veröffentlicht/s",
  "Trend": "Trend",
  "Delay p50": "Verzögerung p50",
  "Problems": "Probleme",
  "Yes": "Ja",
  "No": "Nein",
  "undercounted": "untererfasst",
  "Last 15 minutes": "Letzte 15 Minuten",
  "fetched": "abgerufen",
  "published": "veröffentlicht",
  "Estimated catch-up": "Geschätztes Aufholen",
  "Last problem": "Letztes Problem",
  "Connection or HTTP failures": "Verbindungs- oder HTTP-Fehler",
  "Rate-limit refusals": "Ablehnungen durch Ratenbegrenzung",
  "Undecodable entries": "Nicht lesbare Einträge",
  "Change in behind over 15 minutes": "Änderung des Rückstands über 15 Minuten",
  "Coverage target": "Abdeckungsziel",
  "Coverage appears after the first assessment, about 5 minutes after start.": "Die Abdeckung erscheint nach der ersten Auswertung, etwa 5 Minuten nach dem Start.",
  "Compares what the logs published with what we fetched over the last 15 minutes, and names the logs that fall furthest short.": "Vergleicht, was die Logs in den letzten 15 Minuten veröffentlicht und wir abgerufen haben, und nennt die Logs mit der größten Lücke.",
  "Worked out every 15 minutes from a sample of the last 24 hours of sightings. It only advises: ctprobe keeps following every log.": "Alle 15 Minuten aus einer Stichprobe der Sichtungen der letzten 24 Stunden berechnet. Das ist nur eine Empfehlung: ctprobe folgt weiter allen Logs.",
  "From everything the logs delivered down to domains never seen before. Hostnames can exceed certificates, because one certificate can hold many. The later rows matter most for sizing.": "Von allem, was die Logs geliefert haben, bis zu nie gesehenen Domains. Hostnamen können die Zertifikate übersteigen, weil ein Zertifikat viele enthalten kann. Für die Dimensionierung zählen vor allem die späteren Zeilen.",
  "What each log published and what we fetched over the range. A log that stays below its published rate falls further behind.": "Was jedes Log im Zeitraum veröffentlicht und was wir abgerufen haben. Ein Log unter seiner Veröffentlichungsrate fällt weiter zurück.",
  "Catch-up by log": "Aufholen pro Log",
  "Fetched and published per second over the range": "Abgerufen und veröffentlicht pro Sekunde im Zeitraum",
  "fetched_per_sec": "abgerufen/s",
  "published_per_sec": "veröffentlicht/s",
  "backlog_change": "Rückstandsänderung",
  "problems": "Probleme",
  "Certificates in range. Select one to see them.": "Zertifikate im Zeitraum. Auswählen, um sie zu sehen.",
  "Filtered certificates": "Gefilterte Zertifikate",
  "Filter domains": "Domains filtern",
  "Issuer contains": "Aussteller enthält",
  "TLD": "TLD",
  "Key type": "Schlüsseltyp",
  "key_type": "Schlüsseltyp",
  "Any validity": "Jede Gültigkeit",
  "Any SAN count": "Jede SAN-Anzahl",
  "Any size": "Jede Größe",
  "Certificate or precertificate": "Zertifikat oder Vorzertifikat",
  "Precertificates only": "Nur Vorzertifikate",
  "Final certificates only": "Nur finale Zertifikate",
  "Expires from": "Läuft ab von",
  "Expires to": "Läuft ab bis",
  "More filters": "Weitere Filter",
  "Previous": "Zurück",
  "Next": "Weiter",
  "Remove filter": "Filter entfernen",
  "Loading…": "Lädt…",
  "many": "viele",
  "Timed out. Try a narrower date range or sort by newest first.": "Zeitüberschreitung. Wählen Sie einen kürzeren Zeitraum oder sortieren Sie nach neuesten zuerst.",
  "Certificates are kept for the rolling window; older ones appear only in totals, so counts can differ from Trends on long ranges.": "Zertifikate bleiben für das rollierende Zeitfenster; ältere erscheinen nur in Summen, daher können Zahlen bei langen Zeiträumen von Trends abweichen.",
  "Early assessment from the last 24 hours.": "Frühe Auswertung der letzten 24 Stunden.",
  "A rule on operators survives log rotation.": "Eine Regel über Betreiber übersteht die Log-Rotation.",
};

const unit = { M: ' Mio.', B: ' Mrd.', T: ' Bio.', k: ' Tsd.' };
// en-style number with optional metric suffix → German.
function deNum(s) {
  return s.replace(/\d[\d,]*(?:\.\d+)?(?:[MBTk](?![a-zäöü]))?/gi, (m) => {
    const u = /[MBTk]$/.exec(m)?.[0];
    const n = u ? m.slice(0, -1) : m;
    if (!/[.,]/.test(n) && !u) return m;
    return n.replace(/[.,]/g, (c) => (c === '.' ? ',' : '.')) + (u ? unit[u] : '');
  });
}

const RULES = [
  [/^Found at \+(.+)$/, (m) => 'Gefunden nach +' + deNum(m[1])],
  [/^(.+) names had no address at first; (.+) found one later, (.+) never did\. Waiting for a later probe: (.+)\.$/, (m) => deNum(m[1]) + ' Namen hatten zunächst keine Adresse; ' + deNum(m[2]) + ' fanden später eine, ' + deNum(m[3]) + ' nie. Warten auf eine spätere Abfrage: ' + deNum(m[4]) + '.'],
  [/^From sighting to first address, median between (.+) and (.+), p90 up to (.+)\.$/, (m) => 'Von der Sichtung bis zur ersten Adresse: Median zwischen ' + deNum(m[1]) + ' und ' + deNum(m[2]) + ', p90 bis ' + deNum(m[3]) + '.'],
  [/^Budget (.+) queries per second, two per probe; sample (.+)% of names\. Queued (.+), in flight (.+)\.$/, (m) => 'Budget ' + deNum(m[1]) + ' Abfragen pro Sekunde, zwei pro Name; Stichprobe ' + deNum(m[2]) + ' % der Namen. Wartend ' + deNum(m[3]) + ', laufend ' + deNum(m[4]) + '.'],
  [/^Later probes ran late by a median of (.+), p99 (.+)\.$/, (m) => 'Spätere Abfragen liefen im Median ' + deNum(m[1]) + ' verspätet, p99 ' + deNum(m[2]) + '.'],
  [/^Names with a known last answer: (.+) in (.+)\.$/, (m) => 'Namen mit bekannter letzter Antwort: ' + deNum(m[1]) + ' in ' + deNum(m[2]) + '.'],
  [/^Since (.+) UTC, through (.+)\.$/, (m) => 'Seit ' + m[1] + ' UTC, über ' + m[2] + '.'],
  [/^Retry queue: (.+)$/, (m) => 'Wiederholungswarteschlange: ' + m[1]],
  [/^(.+) names$/, (m) => deNum(m[1]) + ' Namen'],
  [/^(.+) compared$/, (m) => deNum(m[1]) + ' verglichen'],
  [/^median (.+)$/, (m) => 'Median ' + deNum(m[1])],
  [/^(.+) since last restart$/, (m) => deNum(m[1]) + ' seit dem letzten Neustart'],
  [/^Rates are 60-second averages\. Last restart: (.+)$/, (m) => 'Raten sind 60-Sekunden-Mittel. Letzter Neustart: ' + m[1]],
  [/^1 in ([\d.]+) after removing duplicates$/, (m) => '1 von ' + deNum(m[1]) + ' nach Entfernen der Duplikate'],
  [/^(.+)\/s$/, (m) => (/^[\d.,kMBT–-]+$/.test(m[1]) ? deNum(m[1]) + '/s' : m[0])],
  [/^(\d+) of (\d+) healthy\. Updates every 30 seconds\.$/, (m) => m[1] + ' von ' + m[2] + ' in Ordnung. Aktualisiert alle 30 Sekunden.'],
  [/^Over the last 15 minutes, logs published (.+)\/s and we fetched (.+)\/s\.$/, (m) => 'In den letzten 15 Minuten haben die Logs ' + deNum(m[1]) + '/s veröffentlicht und wir ' + deNum(m[2]) + '/s abgerufen.'],
  [/^Backlog (.+), change (.+)\. On logs that rate-limit us: (.+)\.$/, (m) => 'Rückstand ' + deNum(m[1]) + ', Änderung ' + deNum(m[2]) + '. Auf Logs, die uns begrenzen: ' + deNum(m[3]) + '.'],
  [/^Estimated catch-up: (.+)$/, (m) => 'Geschätztes Aufholen: ' + deNum(m[1])],
  [/^short by (.+)\/s$/, (m) => 'fehlen ' + deNum(m[1]) + '/s'],
  [/^pipeline (\d+)% busy, fetch queue (\d+)% full\.$/, (m) => 'Pipeline ' + m[1] + ' % ausgelastet, Abrufwarteschlange ' + m[2] + ' % voll.'],
  [/^(\d+) logs or (\d+) operators reach this target\.$/, (m) => m[1] + ' Logs oder ' + m[2] + ' Betreiber erreichen dieses Ziel.'],
  [/^Operators: (.*)$/, (m) => 'Betreiber: ' + m[1]],
  [/^Based on (.+) sampled certificates from the last 24 hours, worked out at (.+)\. Logs we cannot read fully are undercounted\.$/, (m) => 'Basiert auf ' + deNum(m[1]) + ' Zertifikaten als Stichprobe der letzten 24 Stunden, berechnet um ' + m[2] + '. Logs, die wir nicht vollständig lesen können, sind untererfasst.'],
  [/^Rows (\d+)–(\d+) of (.+)$/, (m) => 'Zeilen ' + m[1] + '–' + m[2] + ' von ' + (m[3] === 'many' ? 'vielen' : deNum(m[3]))],
  [/^Issuer: (.+) ×$/, (m) => 'Aussteller: ' + m[1] + ' ×'],
  [/^Certificates since (\S+)\. Select one to see them\.$/, (m) => 'Zertifikate seit ' + m[1] + '. Auswählen, um sie zu sehen.'],
  [/^Logs for (\d+)% of certificates$/, (m) => 'Logs für ' + m[1] + ' % der Zertifikate'],
  [/^Operators for (\d+)% of certificates$/, (m) => 'Betreiber für ' + m[1] + ' % der Zertifikate'],
  [/^Logs for (\d+)% coverage$/, (m) => 'Logs für ' + m[1] + ' % Abdeckung'],
  [/^(.+) since start$/, (m) => deNum(m[1]) + ' seit Start'],
  [/^(.+) on disk$/, (m) => deNum(m[1]) + ' auf der Platte'],
  [/^(.+) exact · (.+) name$/, (m) => deNum(m[1]) + ' exakt · ' + deNum(m[2]) + ' Name'],
  [/^(.+) unique\/s · (\d+) logs · (.+) behind$/, (m) => deNum(m[1]) + ' eindeutig/s · ' + m[2] + ' Logs · ' + deNum(m[3]) + ' Rückstand'],
  [/^(\d+) of (\d+) delivering in the last second$/, (m) => m[1] + ' von ' + m[2] + ' lieferten in der letzten Sekunde'],
  [/^Ingest paused: (.+)$/, (m) => 'Erfassung pausiert: ' + m[1]],
  [/^As of (.+) UTC$/, (m) => 'Stand ' + m[1] + ' UTC'],
  [/^(\d+) domains$/, (m) => m[1] + ' Domains'],
  [/^Certificates for (.+)$/, (m) => 'Zertifikate für ' + m[1]],
  [/^Certificates matching (.+)$/, (m) => 'Zertifikate passend zu ' + m[1]],
  [/^Showing the first (\d+) rows\.$/, (m) => 'Die ersten ' + m[1] + ' Zeilen.'],
  [/^(\d+\+?) rows in (.+)$/, (m) => m[1] + ' Zeilen in ' + deNum(m[2])],
  [/^(.+), entry (\d+)$/, (m) => m[1] + ', Eintrag ' + m[2]],
  [/^(.+) to (\d{4}-\d\d-\d\dT.+)$/, (m) => m[1] + ' bis ' + m[2]],
  [/^(\d+) finished days so far; needs 7\.$/, (m) => m[1] + ' abgeschlossene Tage bisher; 7 nötig.'],
  [/^Based on ([\d.]+) (hours|days) of data, (\d+)% clean\. Needs 14 days to include weekly patterns\.$/,
    (m) => 'Basiert auf ' + deNum(m[1]) + (m[2] === 'hours' ? ' Stunden' : ' Tagen') + ' Daten, ' + m[3] + ' % sauber. Braucht 14 Tage für Wochenmuster.'],
  [/^Measured from (\S+) to (\S+), ([\d.]+) (hours|days) of collection across (\d+) logs\. (.+)$/,
    (m) => 'Gemessen von ' + m[1] + ' bis ' + m[2] + ', ' + deNum(m[3]) + (m[4] === 'hours' ? ' Stunden' : ' Tage') + ' Erfassung über ' + m[5] + ' Logs. '
      + (m[6].startsWith('Volume') ? 'Die Volumenzahlen taugen für die Dimensionierung.' : 'Die Zahlen bleiben vorläufig, bis 14 Tage überwiegend sauberer Daten vorliegen.')],
  [/^For (.+), from raw entries to never-seen domains$/, (m) => 'Für ' + (m[1] === 'today' ? 'heute' : m[1]) + ', von rohen Einträgen bis zu nie gesehenen Domains'],
];

const NUMERIC = /^-?\d[\d,]*(?:\.\d+)?\s?(?:[MBTk]|%|×|s|ms|min|h|KiB|MiB|GiB|TiB|B|bytes|\/s)?( \/s)?$/;

// English → displayed text.
function tr(text) {
  if (LANG !== 'de') return text;
  const s = text.trim();
  if (!s) return text;
  if (DE[s] !== undefined) return text.replace(s, DE[s]);
  for (const [re, f] of RULES) {
    const m = re.exec(s);
    if (m) return f(m);
  }
  if (NUMERIC.test(s)) return deNum(s).replace(/(\d)%/, '$1 %').replace(/(\d) ?bytes$/, '$1 Byte');
  return text;
}

const ATTRS = ['placeholder', 'aria-label', 'title', 'data-tip'];
function localise(node) {
  if (node.nodeType === 3) {
    const p = node.parentElement;
    if (p && !p.closest('[data-raw], script, style, code')) {
      const t = tr(node.data);
      if (t !== node.data) node.data = t;
    }
    return;
  }
  if (node.nodeType !== 1 || node.closest('[data-raw]')) return;
  for (const a of ATTRS) {
    if (node.hasAttribute(a)) {
      const t = tr(node.getAttribute(a));
      if (t !== node.getAttribute(a)) node.setAttribute(a, t);
    }
  }
  for (const c of node.childNodes) localise(c);
}

if (LANG === 'de') {
  document.title = tr(document.title.split(' · ')[0]) + ' · ctprobe';
  addEventListener('DOMContentLoaded', () => localise(document.body));
  // Added nodes only: page code replaces text wholesale, and watching text edits
  // would make this react to its own output and loop.
  new MutationObserver((list) => {
    for (const m of list) m.addedNodes.forEach(localise);
  }).observe(document.documentElement, { childList: true, subtree: true });
}
