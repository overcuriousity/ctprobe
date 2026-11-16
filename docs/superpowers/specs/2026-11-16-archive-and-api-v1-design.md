# Tiered archive and `/api/v1`

## Intent

ctprobe is the haystack for a pipeline that detects cybertrading and fraud
sites in near real time. It needs two things from the data:

1. **Hot tier:** about 90 days (configurable) of full certificate and DNS
   detail, searchable as today.
2. **Archive:** a permanent, as-small-as-possible record that a domain had a
   certificate at some time, and which addresses its names resolved to.

Both must be reachable over the API by exact, Levenshtein and homoglyph match.
The existing `/api/*` must not change, because the pipeline reads it.

## Goals

- Contract tests pin every existing `/api/*` response before anything changes.
- A nightly step writes a cert archive and a DNS archive for each finished day.
- Retention by age (`hot_days`, `dns_days`) beside the existing disk budget.
- `/api/v1` with all-domain matching across both tiers, cursor paging,
  uniform errors and its own load limits.

## Non-goals

- Storing DER, serials, fingerprints or `cert_hash` in the archive.
- Recovering days already deleted from the hot tier.
- The collapse job for old archive rows (see Approaches). Only the layout must
  allow it.
- A multi-year index, an OpenAPI spec, authentication.
- Choosing or dropping CT logs at runtime. Deduplication already means a
  dropped log saves almost no storage, and load shedding belongs in the
  consuming pipeline.

## Anti-goals

- An unnoticed change to an existing `/api/*` response. The project is a proof
  of concept, so deliberate changes are allowed; the contract tests exist to
  make every change a visible, intended one.
- Archive queries slowing down the existing endpoints.
- Silent loss of a day that was never archived.

## Constraints found in the code

- Ingest keeps one row per certificate, deduplicated by issuer and serial. The
  row is usually the precertificate entry, for which only the TBS bytes are
  seen. A true SHA-256 fingerprint is therefore not available for most rows.
  `log_id` + `entry_index` identifies the row and points at the public log.
- Hot `certs` daily files are sorted by `primary_domain` with a bloom filter on
  it. Matching any other registered domain of a cert means scanning the day.
- The `domains` table and its FST index (`search/domains.fst`,
  `search/skeleton.fst`) are permanent and cover every registered domain ever
  seen. Fuzzy search over all time already works; it yields domains.
- `expire::enforce` runs nightly and from the pipeline's `check_disk` whenever
  the data directory exceeds `disk_budget`. It measures the whole data
  directory.
- `nightly::pending_days` treats a day as finished when its `domains` marker
  exists.

## Approaches

1. **One archive row per certificate and registered domain, daily files.**
   Simple, written once, every issuance stays individually provable. Renewals
   repeat, so it grows with issuance volume.
2. **One row per name with covered periods, merged across days.** Smallest.
   Loses the per-issuance log pointer and needs a job that rewrites old files.
3. **Approach 1 now; rows older than N years collapse into approach 2 later.**

**Chosen: 3.** Build approach 1 now. The collapse job is not built; the reader
must accept any `*.parquet` file in an archive directory so that a later job
can replace a set of daily files with one collapsed file.

For DNS, the archive keeps a name's first answer of each day and every change
within the day, instead of one row per probe. Each daily file stands on its
own, so no merge across days is needed.

## Design

### Configuration

Three optional top-level keys:

| Key | Meaning | Unset |
|-----|---------|-------|
| `hot_days` | Days of `certs` kept in the hot tier | No age limit, as today |
| `dns_days` | Days of `dns` kept in the hot tier | 365, or `hot_days` if that is larger; no age limit when `hot_days` is unset too |
| `archive_budget` | Size limit of the archive; setting it enables the archive | No archive is written |

With none of them set, behaviour is exactly as today. `hot_days` and
`dns_days` must be at least 1. Full DNS detail is meant to outlive full cert
detail, so a `dns_days` below `hot_days` is accepted but logged as a warning
at start.

### Layout

```
<data>/archive/certs/YYYY-MM-DD.parquet
<data>/archive/dns/YYYY-MM-DD.parquet
```

Written to a `.tmp` name and renamed, zstd, row groups of one million rows,
bloom filter on `reg_domain`.

**`archive/certs`**, sorted by `reg_domain`, `seen_at`:

| Column | Type | Note |
|--------|------|------|
| `reg_domain` | Utf8 | one row per registered domain of the cert |
| `names` | List<Utf8> | only the cert's names under this `reg_domain` |
| `seen_at` | Timestamp(ms) | |
| `not_before`, `not_after` | Timestamp(ms) | |
| `issuer_cn`, `issuer_org` | Utf8 | dictionary encoded |
| `log_id` | Int32 | |
| `entry_index` | Int64 | |
| `primary_domain` | Utf8, nullable | set only where it differs from `reg_domain` |

Certificates with no registered domain are not archived. `primary_domain`
lets a reader fetch the full hot row through the hot file's bloom filter.

**`archive/dns`**, sorted by `reg_domain`, `name`, `probed_at`:

| Column | Type |
|--------|------|
| `reg_domain` | Utf8 |
| `name` | Utf8 |
| `probed_at` | Timestamp(ms) |
| `status` | Utf8 |
| `v4`, `v6` | List<Utf8> |

Source: that day's hot `dns` rows with `kind = 'name'`. Per name, in time
order, the first row of the day is always kept, and a later row is kept when
`status`, `v4` or `v6` differ from the name's previous row that day. The
prober's `prev_*` and `changed` columns are not used: they come from an
in-memory table that can hold answers from days that were never archived, so
relying on them would leave names without a baseline. CNAMEs are not archived.
Names the DNS sampler skips have no history.

### Nightly

Two new steps run after `domains`, only when the archive is enabled:
`archive` for certs (marker `<day>.archive`) and `archive-dns` (marker
`<day>.archive-dns`). `pending_days` then also returns finished days that
lack either marker, so days still in the hot tier when a step first exists
are archived on the next run. Until build step 4 ships, no day has the
`archive-dns` marker.

Before writing, the step compares the archive's size with `archive_budget`.
At or over the budget it writes nothing, sets no marker and logs a warning
that names the day. Nothing in the archive is ever deleted automatically.

Storage is the scarce resource, so after each day the step logs the archive's
total size, that day's bytes per archived row, and the days left until
`archive_budget` at the average of the last 30 days.

### Retention

`enforce` gains the age rules and keeps the budget rule:

1. `sightings` as today.
2. Age: `certs` days older than `hot_days` and `dns` days older than
   `dns_days` are deleted. With the archive enabled, a `certs` day needs the
   `archive` marker and a `dns` day the `archive-dns` marker. A day with no
   hot `dns` directory gets the `archive-dns` marker without a file.
3. Budget: as today, except that the measured size excludes `archive/`. With
   the archive enabled, archived days go first, oldest first. Days are
   removed whole and oldest first as today, so under budget pressure the old
   days that hold only `dns` go before any recent `certs` day. Unarchived
   finished days go only to stay under the hard budget, the same last resort
   that unfinished days are today, and each such deletion is logged as an
   error. **This is a call, see below.**

The pipeline's `disk_bytes` figure also excludes `archive/`. Without an
archive directory it is unchanged.

### `/api/v1`

All responses are JSON. Times are milliseconds. Unknown query parameters are
a 400.

**`GET /api/v1/search?q=&mode=&distance=&limit=`**
Domain hits from the permanent index, same modes as `/api/search`
(`exact`, `contains`, `levenshtein`, `homoglyph`).

**`GET /api/v1/certs`**
Scope, exactly one of:
- `domain=` a name. Rows match when the cert covers its registered domain. If
  the name is deeper than the registered domain, only rows that list that
  exact name or a wildcard covering it.
- `q=&mode=&distance=` a fuzzy search; the 100 best domain hits are looked up.

Filters: `from`, `to`, `expires_from`, `expires_to`, `issuer`,
`issuer_contains`, `tld`, `wildcard`. These work on both tiers. Other filters
of `/api/certs` are not offered in v1. `tld` and `wildcard` are judged per
row in both tiers: `tld` is the public suffix of the row's `reg_domain`, and
`wildcard` is true when one of the row's `names` is a wildcard. This differs
from `/api/certs`, where both describe the whole certificate.

Paging: `limit` (1 to 1000, default 100) and `cursor`. Order is fixed:
`seen_at` descending, then `log_id`, `entry_index`. The cursor is an opaque
encoding of the last row's three values.

Response:

```json
{
  "rows": [
    { "tier": "hot", "reg_domain": "example.com", "names": ["a.example.com"],
      "seen_at": 0, "not_before": 0, "not_after": 0,
      "issuer_cn": "", "issuer_org": "", "log_id": 0, "entry_index": 0,
      "detail": { "...": "every other hot column" } },
    { "tier": "archive", "reg_domain": "example.com", "names": [],
      "seen_at": 0, "not_before": 0, "not_after": 0,
      "issuer_cn": "", "issuer_org": "", "log_id": 0, "entry_index": 0 }
  ],
  "next_cursor": "…",
  "cut_short": false
}
```

A row is `hot` when its day is still in the hot tier, `archive` otherwise.
How rows are found, newest day first, stopping when the page is full:

- Day not yet archived (today, or archive disabled): scan the hot file for
  the domain in `reg_domains`.
- Archived day: look up the archive file by `reg_domain`. If the day is still
  hot, fetch the full rows from the hot file by `primary_domain`, `log_id`
  and `entry_index` for `detail`.

With the archive disabled, every day is a scan, so long ranges are slow.
Only days within the index's `first_seen` and `last_seen` of a searched
domain are walked, plus the days without the `domains` marker, which the
index does not cover yet.
When the time limit ends the walk, the response is a 200 with the rows found,
possibly none, `cut_short: true` and a `next_cursor` that continues after the
last row, or after the last day the walk read to its end. The cursor format
does not change: a position between two days is a cursor value too.

**`GET /api/v1/domain/{domain}`**
For one registered domain: `first_seen`, `last_seen`, `cert_count` from the
index, and `dns`: the address history from hot `dns` and `archive/dns`
merged, each row `{ tier, name, probed_at, status, v4, v6 }`, newest first,
`limit` and `cursor` as above. The walk reads days from the summary's
`first_seen` on, since probes can follow the last cert by weeks, plus days
without the `domains` marker; with no summary, only those. An archived day is read from the archive only.
A day not yet archived is read from hot `dns` and reduced by the archive's
rule at query time, so a day's rows do not change when it is archived.

There is no `cert/{sha256}`. A certificate is identified by `log_id` and
`entry_index`, and list rows already carry everything stored about it.

### Hardening

- **Errors:** `{ "error": { "code": "...", "message": "..." } }` with codes
  `bad_request` (400), `not_found` (404), `busy` (429), `timeout` (504),
  `internal` (500). Unknown `/api/v1/*` paths return the same shape.
- **Load:** a v1 request takes a permit without waiting or gets 429 with
  `Retry-After: 1`. Two permits for v1 overall; one further permit for
  requests that read the archive. Archive queries run on the query runtime but
  outside the limiter the existing endpoints use, so they cannot queue in
  front of them.
- **Input:** domains go through `names::normalize` and
  `names::registered_domain`; anything that fails is a 400. A leading `*.` is
  dropped. `limit` out of range, a malformed `cursor`, a bad date and an
  unknown `mode` are 400s, not clamped.
- **Timeout:** 504 only when the time limit passes before the walk has
  finished one day and with no rows found, or before the fuzzy search or
  summary lookup ends. Otherwise a cut-short page always moves the cursor on,
  so following `next_cursor` cannot loop. `/domain` with a summary in hand
  answers 200 even then, with the cursor it was given.

### Contract tests

`tests/contract.rs`, under the `mock` feature, written and passing on the
unmodified code before any other change. For every route under `/api/` in
`src/web/mod.rs`: status, content type, and the exact set of keys with their
JSON types, for a success and for each distinct error. For `format=csv` the
header line. For `/api/stream` the event names and keys. Values are not
pinned. These tests must stay green through every later step.

## Build order

1. Contract tests.
2. Cert archive, config keys and retention.
3. `/api/v1` with hardening.
4. DNS archive and the `dns` part of `domain/{domain}`.

## Calls made by the author, not decided by the owner

- When the hard `disk_budget` cannot be met otherwise, unarchived days are
  deleted and logged as errors, so that ingest keeps running. The stricter
  alternative is to pause ingest.
- At a full `archive_budget`, archiving stops with a warning; nothing is
  deleted and there is no status endpoint for it.
- `dns_days` defaults to 365 (the owner asked for much longer than `hot_days`;
  the number is the author's).
- Under budget pressure old `dns`-only days go before recent `certs` days.
- CNAMEs are left out of the DNS archive.
- The DNS archive keeps each name's first answer of every day, not only
  changes across days. It costs more rows but every day is self-contained.
- `tld` and `wildcard` in v1 are per row, not per certificate.
- Cert and DNS archives have separate markers, and hot `dns` is not aged out
  until the DNS archive step exists.
- No `cert/{sha256}` or other single-certificate endpoint in v1.
- v1 offers only the filters both tiers can answer.

## Left to the builder

- Cursor encoding, permit plumbing, module layout.
- Parquet encodings per column and bloom filter sizing.
- Caps on list lengths inside a row.
- Test structure beyond the contract tests.
