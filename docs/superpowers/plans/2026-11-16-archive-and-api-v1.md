# Tiered Archive and `/api/v1` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep recent certificates and DNS probes in full detail, keep a small permanent record of every certificate and address change, and serve both through a hardened `/api/v1` without changing `/api/*`.

**Architecture:** Two nightly steps write one narrow Parquet file per finished day into `<data>/archive/{certs,dns}/`, sorted by registered domain with a bloom filter. `expire::enforce` gains age rules that only remove days the archive already holds. `/api/v1` walks days newest first, reading the archive for archived days and the hot files for the rest, behind its own non-waiting permits.

**Tech Stack:** Rust 2021, DataFusion 55, arrow/parquet 59, axum 0.8, tokio. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-16-archive-and-api-v1-design.md`

## Global Constraints

- The project is a proof of concept, so `/api/*` is not frozen (owner's ruling after approval). `tests/contract.rs` (Task 1) is a regression net: it must pass after every task, and a deliberate change to an existing response updates its literal in the same commit and is named in the commit message. No task in this plan needs such a change.
- With `hot_days`, `dns_days` and `archive_budget` all unset, behaviour is exactly as today and no `archive/` directory is created.
- Nothing under `<data>/archive/` is ever deleted by the program.
- Archive files are written to `<name>.tmp` and renamed; zstd level 6; row groups of 1,000,000 rows; bloom filter on `reg_domain`.
- Readers of an archive directory accept every `*.parquet` file in it, whatever its name.
- No DER, serial, fingerprint or `cert_hash` in the archive.
- All tests that start the app need `--features mock`. Full run: `cargo test --features mock`.
- Commit messages: imperative subject, then the two attribution trailers used on this branch.

## Review Focus

1. **A certificate with many registered domains, or names under none.** Each registered domain gets its own row with only its names; a cert with no registered domain produces no row and no error. Test in Task 3.
2. **Round-robin DNS.** The same addresses in a different order are not a change. Test in Task 7.
3. **Rows sharing `seen_at` across a page boundary.** Paging by cursor returns every row once, also when one cert matches several searched domains. Test in Task 6.
4. **Archive enabled on an existing install.** Finished days still in the hot tier are archived on the next run; a crash between rename and marker reruns cleanly. Test in Task 3.
5. **Hostile or odd domain input.** Upper case, trailing dot, `*.` prefix, IDN in Unicode, an apostrophe, an IP address: normalised or a 400, never a 500 and never unquoted in SQL. Test in Task 5.

---

### Task 1: Contract tests for `/api/*`

**Files:**
- Create: `tests/contract.rs`
- Modify: `Cargo.toml` (add `[[test]] name = "contract"`, `required-features = ["mock"]`)

**Interfaces:**
- Consumes: the app harness pattern of `tests/web.rs:13-85` (copy `App`, `app`, `app_with`, `certs`, `wait_rows`, `get_json`).
- Produces: `fn shape(v: &serde_json::Value) -> serde_json::Value`, which replaces every scalar by its type name (`"string"`, `"number"`, `"bool"`, `"null"`), keeps object keys, and reduces an array to the shape of its first element (or `[]`).

- [ ] **Step 1: Write the tests.** One test per route in `src/web/mod.rs:79-93`. Each asserts the status, the `content-type` header, and `shape(body)` against a literal `json!` value. Cover a success and every distinct error per route:

```rust
// names and the cases each must pin
contract_live()            // 200
contract_history()         // 200 on empty store, 200 after entries
contract_logs()            // 200
contract_schema()          // 200
contract_sql()             // 200; 400 for "DROP TABLE certs"; 400 for bad SQL
contract_search()          // 200 per mode exact|contains|levenshtein|homoglyph; 400 unknown mode; 400 empty q
contract_certs()           // 200 domain=; 200 pattern=; 200 filter only; 400 both domain and pattern;
                           // 400 no scope no filter; 400 unknown sort; 400 dir=up; 400 dns=x;
                           // 400 offset=10001; 400 from=x; format=csv -> text/csv and exact header line
contract_domain()          // 200; 400 empty d
contract_dns()             // 200 with dns off
contract_cert_dns()        // 200; 400 hash=x
contract_cert()            // 200; 404 unknown log; 404 index past the tree
contract_trends()          // 200 for one metric; 404 unknown metric; 400 bad range
contract_stream()          // event names seen within 2 s and the key set of each event's data
```

Error bodies are pinned as `{"error": "string"}`. Where a body holds a nullable field, pin the case the test produces and say so in a comment.

- [ ] **Step 2: Run on unmodified code.** Run: `cargo test --features mock --test contract`. Expected: all pass. A failure here means the literal is wrong, not the code: fix the literal.

- [ ] **Step 3: Commit** `Pin the existing API responses with contract tests`.

---

### Task 2: Configuration keys

**Files:**
- Modify: `src/config.rs`, `ctprobe.example.toml`, `README.md` (config table)
- Modify: every literal `Config { .. }` under `tests/` (`grep -rn "Config {" tests/`), adding the three fields as `None`
- Create: `src/nightly/expire.rs` gets the `Retention` type only (logic in Task 4)

**Interfaces:**
- Produces, in `src/config.rs`:
  ```rust
  pub hot_days: Option<u32>,
  pub dns_days: Option<u32>,            // as written in the file
  pub archive_budget_bytes: Option<u64>,
  impl Config { pub fn retention(&self) -> Retention }
  ```
- Produces, in `src/nightly/expire.rs`:
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub struct Retention {
      pub budget: u64,
      pub hot_days: Option<u32>,
      pub dns_days: Option<u32>,   // resolved: explicit, else hot_days.map(|h| h.max(365))
      pub archive: bool,           // archive_budget_bytes.is_some()
  }
  ```

- [ ] **Step 1: Write failing unit tests in `src/config.rs`:**

```rust
keys_default_to_none()        // base config: all three None; retention() == Retention{budget, None, None, false}
dns_days_defaults_to_a_year() // hot_days = 90            -> retention().dns_days == Some(365)
dns_days_follows_long_hot()   // hot_days = 400           -> Some(400)
dns_days_explicit_wins()      // hot_days = 90, dns_days = 30 -> Some(30)   (loads, no error)
zero_days_rejected()          // hot_days = 0 or dns_days = 0 -> Err
archive_budget_parses()       // archive_budget = "2GiB"  -> Some(2 << 30), retention().archive
```

- [ ] **Step 2: Run** `cargo test --lib config`. Expected: FAIL, unknown field `hot_days`.
- [ ] **Step 3: Implement.** `RawConfig` gains `hot_days: Option<u32>`, `dns_days: Option<u32>`, `archive_budget: Option<String>`. `Config::load` logs `tracing::warn!` when `dns_days < hot_days`. Add the three keys, commented out with one line each, to `ctprobe.example.toml` and rows to the README table.
- [ ] **Step 4: Run** `cargo test --features mock`. Expected: PASS.
- [ ] **Step 5: Commit** `Add hot_days, dns_days and archive_budget to the config`.

---

### Task 3: Cert archive step

**Files:**
- Create: `src/nightly/archive.rs`
- Modify: `src/store/schema.rs`, `src/store/mod.rs`, `src/nightly/mod.rs`, `src/nightly/compact.rs` (make `props` `pub(super)`)
- Test: `tests/archive.rs` (no `mock` feature needed; reuse `cfg`, `row`, `day` from `tests/nightly.rs:14-66`)

**Interfaces:**
- Consumes: `Config::archive_budget_bytes`, `compact::props`, `store::{session, register_files, list_day}`, `names::registered_domain`.
- Produces, in `src/store`:
  ```rust
  pub fn archive_certs_schema() -> SchemaRef
  // reg_domain Utf8 !null, names List<Utf8> !null, seen_at ts !null, not_before ts !null,
  // not_after ts !null, issuer_cn Utf8 !null, issuer_org Utf8 !null, log_id Int32 !null,
  // entry_index Int64 !null, primary_domain Utf8 null
  pub fn archive_file(data: &Path, table: &str, day: &str) -> PathBuf   // <data>/archive/<table>/<day>.parquet
  pub fn list_archive(data: &Path, table: &str) -> Vec<PathBuf>         // every *.parquet there, sorted
  ```
- Produces, in `src/nightly/archive.rs`:
  ```rust
  #[derive(Debug, PartialEq, Eq)]
  pub enum Outcome { Written { rows: u64, bytes: u64 }, Empty, BudgetFull }
  pub async fn certs(data: &Path, day: &str, budget: u64) -> Result<Outcome>
  pub fn archive_size(data: &Path) -> u64                               // dir_size of <data>/archive
  ```
- Produces, in `src/nightly/mod.rs`: step `archive` with marker `<day>.archive`; `pending_days(data: &Path, today: NaiveDate, archive: bool)` (new third parameter; update the call in `src/pipeline.rs:280` to pass `cfg2.archive_budget_bytes.is_some()`).

- [ ] **Step 1: Write failing tests in `tests/archive.rs`:**

```rust
one_row_per_registered_domain()
// cert with names [a.one.com, *.one.com, b.two.org], reg_domains [one.com, two.org], primary one.com
// -> 2 rows: (one.com, [*.one.com, a.one.com], primary_domain null),
//            (two.org, [b.two.org],            primary_domain "one.com")
no_registered_domain_no_row()      // reg_domains [] -> Outcome::Empty when it is the only cert; no file
sorted_with_bloom()                // reg_domain column is non-decreasing; row group 0 has a bloom filter on reg_domain
budget_full_writes_nothing()       // budget 1 byte with one earlier archive file present -> BudgetFull, no file, no marker
rerun_after_crash_is_clean()       // leave a stale <day>.parquet.tmp, run twice -> one file, same row count
existing_hot_days_become_pending() // seed two finished days, mark both `domains`; pending_days(.., true) lists both,
                                   // pending_days(.., false) lists none
disabled_writes_no_directory()     // run_nightly with archive_budget None -> <data>/archive does not exist
```

- [ ] **Step 2: Run** `cargo test --test archive`. Expected: FAIL to compile, `archive` not found.
- [ ] **Step 3: Implement `archive::certs`.** Two passes, so memory stays bounded:
  1. Read the day's hot `certs` files with the Parquet reader, projecting only the needed columns. For each cert and each of its `reg_domains`, emit a row whose `names` are the cert's names with `registered_domain(name) == reg_domain`, sorted. Write these unsorted to `<data>/tmp/archive-<day>.parquet`.
  2. Register that file in a `session(data, MEMORY, PARTITIONS)` and stream `ORDER BY reg_domain, seen_at` into `archive_file(..).tmp` with `props(&[("reg_domain", BLOOM_NDV)])`, `sync_all`, rename, delete the temp file.

  Check `archive_size(data) >= budget` first and return `BudgetFull`. Zero rows returns `Empty` and writes no file.
- [ ] **Step 4: Wire into `run_nightly`** after `domains`, only when `cfg.archive_budget_bytes` is `Some`. `Written` and `Empty` set the marker; `BudgetFull` logs `tracing::warn!` naming the day and sets none. After `Written`, log at info: archive total bytes, `bytes / rows` for the day, and days left = `(budget - total) / mean bytes of the newest 30 files`.
- [ ] **Step 5: Run** `cargo test --features mock`. Expected: PASS, including `contract` and `nightly`.
- [ ] **Step 6: Commit** `Write a narrow cert archive for each finished day`.

---

### Task 4: Retention by age

**Files:**
- Modify: `src/nightly/expire.rs`, `src/nightly/mod.rs:41,49`, `src/nightly/compact.rs` (`run` takes `&Retention`), `src/pipeline.rs:789,828-836`, `src/metrics.rs`
- Modify: `tests/nightly.rs:220-270` (the two expiry tests call the new signature)
- Test: `tests/archive.rs`

**Interfaces:**
- Consumes: `Retention` (Task 2), markers `archive` (Task 3) and `archive-dns` (Task 7; until then never present).
- Produces:
  ```rust
  // src/nightly/expire.rs
  pub fn enforce(data: &Path, r: &Retention, today: NaiveDate) -> Result<Option<String>>
  // src/metrics.rs
  pub fn hot_size(data: &Path) -> u64      // dir_size(data) - dir_size(data/archive)
  ```

- [ ] **Step 1: Write failing tests:**

```rust
no_keys_behaves_as_before()          // Retention{budget, None, None, false}: the two existing expiry tests, unchanged outcome
age_removes_old_certs_days()         // hot_days 2, archive off, days today-1..today-4 -> today-3 and today-4 certs gone, dns of those kept
age_waits_for_the_archive()          // hot_days 2, archive on, only today-4 has `.archive` -> only today-4 certs removed
dns_age_waits_for_its_own_marker()   // dns_days 2, archive on, no `.archive-dns` -> no dns day removed;
                                     // with `.archive-dns` on today-4 -> that dns day removed
budget_ignores_archive_bytes()       // large file under archive/, hot under budget -> nothing removed, Ok(None)
budget_takes_archived_days_first()   // over budget, today-3 archived, today-4 not -> today-3 removed first
budget_last_resort_logs_and_removes()// still over budget -> unarchived finished day removed, Ok(None)
archive_dir_untouched()              // after every case above, archive/ file list is unchanged
```

- [ ] **Step 2: Run** `cargo test --test archive`. Expected: FAIL to compile on the `enforce` signature.
- [ ] **Step 3: Implement** in this order inside `enforce`: sightings as today; age rule for `certs` and for `dns` separately; budget rule measuring `hot_size`. In the budget rule, with `r.archive`, order finished days as: has `.archive` (oldest first), then the rest (oldest first, each removal `tracing::error!` naming the day), then unfinished days as today. `remove_day` splits into per-table removal. A day with no `dns` directory needs no marker.
- [ ] **Step 4: Switch `pipeline.rs:789`** to `hot_size`, and `check_disk` to `enforce(.., &self.cfg.retention(), today)`.
- [ ] **Step 5: Run** `cargo test --features mock`. Expected: PASS.
- [ ] **Step 6: Commit** `Expire hot days by age once the archive holds them`.

---

### Task 5: `/api/v1` frame, errors, limits and search

**Files:**
- Create: `src/web/v1/mod.rs`, `src/web/v1/error.rs`, `src/web/v1/input.rs`
- Modify: `src/web/mod.rs` (`mod v1;`, `AppState.v1: Arc<v1::Gate>`, `.nest("/api/v1", v1::router())`)
- Test: `tests/v1.rs` (`mock` feature; add `[[test]]` entry)

**Interfaces:**
- Produces:
  ```rust
  // error.rs
  pub enum ApiError { BadRequest(String), NotFound(String), Busy, Timeout, Internal(String) }
  impl IntoResponse for ApiError   // {"error":{"code","message"}}; codes bad_request|not_found|busy|timeout|internal
                                   // statuses 400|404|429|504|500; Busy adds `Retry-After: 1`
  impl From<QueryError> for ApiError   // Timeout -> Timeout, NotAllowed -> BadRequest, Failed -> Internal
  // input.rs
  pub struct Params<T>(pub T);     // axum extractor over Query<T>; a rejection becomes ApiError::BadRequest
  pub fn domain(raw: &str) -> Result<(String /*name*/, String /*registered domain*/), ApiError>
  pub fn limit(v: Option<usize>) -> Result<usize, ApiError>     // default 100, 1..=1000, else BadRequest
  pub fn when(v: Option<&str>, end: bool, name: &str) -> Result<Option<i64>, ApiError>
  pub fn mode(mode: Option<&str>, distance: Option<u8>) -> Result<Mode, ApiError>  // distance must be 1 or 2
  // mod.rs
  pub struct Gate { all: Semaphore /*2*/, archive: Semaphore /*1*/ }
  impl Gate { pub fn new() -> Gate; pub fn enter(&self, archive: bool) -> Result<Permits, ApiError> }  // try_acquire, never waits
  pub fn router() -> Router<AppState>   // routes + fallback returning ApiError::NotFound
  ```
  Every v1 query struct has `#[serde(deny_unknown_fields)]`.
- `GET /api/v1/search?q=&mode=&distance=&limit=` returns `{"hits":[DomainHit]}` via `engine.search_domains`.

- [ ] **Step 1: Write failing tests in `tests/v1.rs`:**

```rust
unknown_path_is_json_404()      // GET /api/v1/nope -> 404, {"error":{"code":"not_found","message":_}}
unknown_param_is_400()          // /api/v1/search?q=a&bogus=1 -> 400 bad_request
search_modes_work()             // exact, contains, levenshtein, homoglyph -> 200, body has "hits" array
bad_inputs_are_400()            // mode=x; distance=3; limit=0; limit=1001; empty q
busy_is_429_with_retry_after()  // hold both permits via state.v1, request -> 429, code busy, Retry-After: 1
legacy_api_unaffected_when_busy() // same hold, GET /api/search?q=a -> 200
```
and unit tests in `input.rs`:
```rust
domain_normalises()   // "WWW.Example.COM." -> ("www.example.com","example.com"); "*.example.com" -> ("example.com","example.com")
                      // "bücher.de" -> ("xn--bcher-kva.de","xn--bcher-kva.de")
domain_rejects()      // "", "1.2.3.4", "a'b.com", "com", a 300-byte name -> BadRequest
```

- [ ] **Step 2: Run** `cargo test --features mock --test v1`. Expected: FAIL, 404 bodies are empty.
- [ ] **Step 3: Implement.** `domain` uses `names::normalize` then strips `*.`, then `names::registered_domain`; a name with no registered domain is a 400.
- [ ] **Step 4: Run** `cargo test --features mock`. Expected: PASS.
- [ ] **Step 5: Commit** `Add the /api/v1 frame with uniform errors and load limits`.

---

### Task 6: `/api/v1/certs`

**Files:**
- Create: `src/query/tiers.rs`, `src/web/v1/certs.rs`
- Modify: `src/query/mod.rs` (`mod tiers; pub use tiers::*;`), `src/query/sql.rs` (make `quote`, `in_range`, `MS_PER_DAY` reachable from `tiers`), `src/web/v1/mod.rs`
- Test: `tests/v1.rs`, unit tests in `src/query/tiers.rs`

**Interfaces:**
- Consumes: `store::{archive_certs_schema, archive_file, list_archive, list_day, certs_schema}`, `Gate`, `input::*`.
- Produces:
  ```rust
  #[derive(Default, Clone)]
  pub struct TierFilter {
      pub from_ms: Option<i64>, pub to_ms: Option<i64>,
      pub expires_from_ms: Option<i64>, pub expires_to_ms: Option<i64>,
      pub issuer: Option<String>, pub issuer_contains: Option<String>,
      pub tld: Option<String>, pub wildcard: Option<bool>,
  }
  #[derive(Clone, PartialEq, Debug)]
  pub struct CertCursor { pub seen_at_ms: i64, pub log_id: i32, pub entry_index: i64, pub reg_domain: String }
  impl CertCursor { pub fn encode(&self) -> String; pub fn decode(s: &str) -> Option<CertCursor> }  // base64url, no padding
  #[derive(Serialize)]
  pub struct TierPage { pub rows: Vec<serde_json::Value>, pub next_cursor: Option<String>, pub cut_short: bool }
  impl QueryEngine {
      pub fn has_archive(&self) -> bool            // list_archive(certs) or list_archive(dns) non-empty
      pub async fn tier_certs(&self, domains: &[String], exact_name: Option<&str>, f: &TierFilter,
                              limit: usize, after: Option<CertCursor>) -> Result<TierPage, QueryError>
  }
  ```
- Order of rows: `seen_at DESC, log_id DESC, entry_index DESC, reg_domain ASC`.

- [ ] **Step 1: Write failing tests.** Seed with `Writer` at past days before `Pipeline::start` on the same directory, then `nightly::run_nightly` where a test needs an archived day.

```rust
matches_a_non_primary_domain()   // cert primary one.com also covering two.org; ?domain=two.org -> 1 row,
                                 // reg_domain two.org, names [b.two.org]; /api/certs?domain=two.org still returns 0 rows
tier_marks_follow_the_hot_dir()  // archived day still hot -> tier "hot" with "detail" holding key_type, renewal, san_count;
                                 // remove certs/day=<d> -> same row, tier "archive", no "detail" key
unarchived_day_is_scanned()      // archive_budget None, same data -> row found, tier "hot"
deeper_name_filters_rows()       // ?domain=a.one.com -> only rows listing a.one.com or *.one.com
filters_apply_in_both_tiers()    // from/to, expires_from/to, issuer, issuer_contains, tld, wildcard: same row set
                                 // before and after the hot day is removed
tld_and_wildcard_are_per_row()   // the two.org row of the cert above: tld=org matches, tld=com does not; wildcard=true does not
paging_returns_every_row_once()  // 7 rows with equal seen_at across 2 days, limit=3 -> 3 pages, 7 distinct (log_id,entry_index,reg_domain)
fuzzy_scope_looks_up_hits()      // ?q=exampel.com&mode=levenshtein -> rows for example.com
scope_errors()                   // neither domain nor q; both; cursor=garbage -> 400 bad_request
timeout_with_rows_is_cut_short() // engine timeout 1 ms after first day -> 200, cut_short true, next_cursor set
timeout_without_rows_is_504()    // engine timeout zero -> 504, code timeout
```
Unit: `cursor_round_trips()`, `cursor_rejects_garbage()`.

- [ ] **Step 2: Run** `cargo test --features mock --test v1`. Expected: FAIL, route not found.
- [ ] **Step 3: Implement `tier_certs`.** Days = union of hot `certs` days and archive file days inside `from..to`, newest first, starting at the cursor's day. Per day, until `limit + 1` rows are held or the deadline (`self.timeout`) passes:
  - Archive file exists: query it with `reg_domain IN (..)` plus the time, expiry and issuer conditions. This runs on `self.rt` **without** `self.limiter`. If `certs/day=<d>` exists, fetch the hot rows by `primary_domain IN (..) AND (log_id, entry_index) IN (..)`, where the row's primary is `primary_domain` or else `reg_domain`, through the normal limited path, and attach every hot column not already in the row as `detail`.
  - No archive file: scan the hot day with `array_has_any(reg_domains, [..])` through the limited path and split each cert into per-domain rows in Rust, same rule as Task 3.
  - In Rust, for both paths: apply `exact_name` (the name itself or a wildcard one label above it), `tld` (`psl::suffix_str(reg_domain)`), `wildcard` (any of the row's names starts with `*.`), then the cursor.

  All values reach SQL through `quote`. Rows are objects with the keys of the spec's example; times as millisecond integers.
- [ ] **Step 4: Implement the handler** `GET /api/v1/certs`: exactly one of `domain` or `q`; for `q`, take up to 100 hits of `search_domains`; `Gate::enter(engine.has_archive())`.
- [ ] **Step 5: Run** `cargo test --features mock`. Expected: PASS.
- [ ] **Step 6: Commit** `Serve certificates from both tiers under /api/v1/certs`.

---

### Task 7: DNS archive step

**Files:**
- Modify: `src/nightly/archive.rs`, `src/nightly/mod.rs`, `src/store/schema.rs`
- Test: `tests/archive.rs` (seed `dns` rows the way `tests/nightly.rs:271-316` does)

**Interfaces:**
- Produces:
  ```rust
  pub fn archive_dns_schema() -> SchemaRef
  // reg_domain Utf8 !null, name Utf8 !null, probed_at ts !null, status Utf8 !null, v4 List<Utf8> !null, v6 List<Utf8> !null
  pub async fn dns(data: &Path, day: &str, budget: u64) -> Result<Outcome>      // src/nightly/archive.rs
  pub const DNS_CHANGES_SQL: &str   // the reduction below, over a table named `t`; reused by Task 8
  ```
- Step `archive-dns`, marker `<day>.archive-dns`; `pending_days(.., archive = true)` also returns days lacking it.

- [ ] **Step 1: Write failing tests:**

```rust
first_answer_of_the_day_is_kept()     // one probe with prev_status set and changed=false -> 1 row
unchanged_repeats_are_dropped()       // 3 probes, same status/v4/v6 -> 1 row (the earliest)
a_change_adds_a_row()                 // v4 [1.1.1.1] then [2.2.2.2] then [2.2.2.2] -> 2 rows
address_order_is_not_a_change()       // v4 [1.1.1.1,2.2.2.2] then [2.2.2.2,1.1.1.1] -> 1 row
only_name_probes_with_a_domain()      // kind != 'name' or reg_domain null -> no row
dns_sorted_with_bloom()               // (reg_domain, name, probed_at) non-decreasing; bloom on reg_domain
day_without_dns_gets_the_marker()     // no dns/day=<d> -> Outcome::Empty, marker set, no file
dns_budget_full_sets_no_marker()
```

- [ ] **Step 2: Run** `cargo test --test archive`. Expected: FAIL, `archive::dns` not found.
- [ ] **Step 3: Implement** with one DataFusion query over the day's hot `dns` files, streamed to the file as in Task 3:

```sql
SELECT reg_domain, name, probed_at, status, v4, v6 FROM (
  SELECT *, ROW_NUMBER() OVER w AS rn,
         LAG(status || '|' || array_to_string(array_sort(v4), ',') || '|' || array_to_string(array_sort(v6), ','))
           OVER w AS prev,
         status || '|' || array_to_string(array_sort(v4), ',') || '|' || array_to_string(array_sort(v6), ',') AS cur
  FROM t WHERE kind = 'name' AND reg_domain IS NOT NULL
  WINDOW w AS (PARTITION BY name ORDER BY probed_at, attempt)
) WHERE rn = 1 OR cur <> prev
ORDER BY reg_domain, name, probed_at
```

- [ ] **Step 4: Run** `cargo test --features mock`. Expected: PASS, including Task 4's `dns_age_waits_for_its_own_marker`.
- [ ] **Step 5: Commit** `Archive each name's first answer of the day and its changes`.

---

### Task 8: `/api/v1/domain/{domain}`

**Files:**
- Create: `src/web/v1/domain.rs`
- Modify: `src/query/tiers.rs`, `src/web/v1/mod.rs`, `README.md` (a short `/api/v1` section: the three routes, the error shape, the 429 rule)
- Test: `tests/v1.rs`

**Interfaces:**
- Consumes: `DNS_CHANGES_SQL`, `archive_dns_schema`, `archive_file`, `Gate`, `input::domain`.
- Produces:
  ```rust
  #[derive(Clone, PartialEq, Debug)]
  pub struct DnsCursor { pub probed_at_ms: i64, pub name: String }   // encode/decode as CertCursor
  impl QueryEngine {
      pub async fn tier_dns(&self, reg_domain: &str, limit: usize, after: Option<DnsCursor>)
          -> Result<TierPage, QueryError>
  }
  ```
- Response: `{"domain", "first_seen", "last_seen", "cert_count", "dns": {"rows", "next_cursor", "cut_short"}}`. DNS rows: `{tier, name, probed_at, status, v4, v6}`, ordered `probed_at DESC, name ASC`.

- [ ] **Step 1: Write failing tests:**

```rust
domain_summary_from_the_index()     // first_seen, last_seen, cert_count equal /api/search exact hit for the domain
deeper_name_is_reduced()            // /api/v1/domain/www.example.com -> "domain":"example.com"
unknown_domain_is_404()             // never seen, no dns -> 404 not_found
dns_rows_same_before_and_after_archiving() // 3 probes with one change: 2 rows from hot (tier "hot");
                                    // after archive-dns and removing dns/day=<d>: same 2 rows, tier "archive"
archived_day_is_read_from_archive_only()   // day both hot and archived -> 2 rows, not 4
dns_paging_returns_every_row_once()
```

- [ ] **Step 2: Run** `cargo test --features mock --test v1`. Expected: FAIL, route not found.
- [ ] **Step 3: Implement `tier_dns`.** Days newest first as in Task 6. Archive file present: read it by `reg_domain` (outside `self.limiter`); tier is `hot` when `dns/day=<d>` still exists, else `archive`. No archive file: run `DNS_CHANGES_SQL` over that day's hot files filtered to the domain (limited path), tier `hot`.
- [ ] **Step 4: Implement the handler.** Summary from `engine.search_domains(domain, Mode::Exact, 1)`; 404 when there is no hit and no DNS row.
- [ ] **Step 5: Run** `cargo test --features mock`. Expected: PASS.
- [ ] **Step 6: Commit** `Serve a domain's summary and address history under /api/v1`.
