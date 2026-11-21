# ctprobe

Measures the Certificate Transparency ecosystem in real time and searches recent certificates.

ctprobe follows public CT logs, removes duplicates and keeps rolling statistics on what it sees:
issuance rates, log health and coverage, issuers, key types, validity and new names and domains.
It also resolves every name through its own Unbound resolver: how many get DNS, IPv4 and IPv6,
how long a name takes to appear, and how addresses change between certificates.
A web interface shows it live and offers crt.sh-style search.

It runs as one Linux binary and stores everything in one directory. It follows each log from its
current head and does not backfill.

## Install

    curl -fsSL https://raw.githubusercontent.com/overcuriousity/ctprobe/main/install.sh | sh

This installs the latest release for Linux on x86_64 or aarch64 (glibc 2.35 or newer) and, where systemd runs, enables and
starts a `ctprobe` service. It also installs Unbound with apt, dnf or zypper and runs it for ctprobe
alone as `ctprobe-unbound` on `127.0.0.1:5335`, leaving the system's resolver alone, and adds a
`[dns]` section to the config if it has none. It needs root, and uses sudo if you are not root. Then open
http://127.0.0.1:8080. Running it again updates ctprobe and keeps your config.

| Setting | Effect |
|---|---|
| `CTPROBE_NO_SERVICE=1` | Installs the binary only |
| `CTPROBE_INSTALL_DIR=dir` | Installs the binary to `dir`, with no service |
| `CTPROBE_NO_DNS=1` | Sets up no Unbound, so DNS probing stays off |

Set these on `sh`, for example `... | CTPROBE_NO_SERVICE=1 sh`.

The service reads `/etc/ctprobe/config.toml` and listens on `127.0.0.1:8080`. The web interface
has no login or TLS, so expose it only on a protected network.

To run it without the service, create `config.toml`:

    bind = "127.0.0.1:8080"
    data_dir = "./data"
    disk_budget = "4GiB"
    tracker_max = "2GiB"

Then start it:

    ctprobe run --config config.toml

## Configuration

| Key | Meaning |
|---|---|
| `bind` | Address of the web interface |
| `data_dir` | Where all data lives |
| `disk_budget` | Ceiling for `data_dir` without its `archive/` directory, in `GiB` or `MiB`. Old certificates expire to stay under it; ingest pauses if it cannot be met. With the archive on, a day ages out of the hot tier only once it is archived, so a full `archive_budget` also stops age expiry |
| `tracker_max` | Memory cap for renewal tracking. Over it, the oldest names are forgotten, so renewals are undercounted |
| `include_logs`, `exclude_logs` | Substrings of log names, applied to every list |
| `log_list_url` | The required log list. Defaults to Google's trusted list |
| `extra_log_lists` | Further lists, by default Apple's. A log on any list is followed. A list that cannot be read is skipped and its logs are kept |
| `include_test_logs` | Also follows the stateless logs on Google's full list, which appear to be test or staging logs. Off by default, because they then count in every figure except coverage |
| `coverage_target` | Percent of certificates the coverage assessment aims for, default 95. It only advises: ctprobe keeps following every log |
| `hot_days` | Days certificates stay in the hot tier before moving to the archive. Unset by default: certificates are kept until the budget forces expiry |
| `dns_days` | Days of DNS probes kept. Defaults to `hot_days`, at least 365, when `hot_days` is set. A value below `hot_days` logs a warning |
| `archive_budget` | Ceiling for the archive directory, in `GiB` or `MiB`. Unset by default: no archive tier |
| `[dns] resolver` | Recursive resolver for DNS probing, such as `"127.0.0.1:5335"`. Without it, nothing is probed |
| `[dns] max_qps` | Queries per second to the resolver, default 2000. Each probe sends two, A and AAAA. Names that do not fit in a burst are skipped and counted |
| `[dns] sample_pct` | Percent of names probed, default 100. Chosen by a hash of the name, so the same names are probed on every certificate |
| `[dns] state_max` | Approximate disk cap for the last answer per name, default `2GiB`. It is applied as a count, about 19 million names at the default. Over it, the oldest half is forgotten and their changes go undetected. Their space is freed some time later, so the size on disk can stay above the cap for a while |
| `[dns] queue_max` | Names waiting for a later probe, default 20000000 (about 2.5 GiB on disk). Over it, the names seen longest ago are dropped, counted as `dropped_full`, and get no further probes |

DNS probing asks each name when its certificate is seen and, while it has no address, again from
one minute up to 30 days later. Wildcards are asked as written, and for the name they cover when the
certificate does not list it. Probes are in the `dns` table and per-minute totals in `dns_minute`.
The resolver must keep its negative cache short, or later probes repeat a cached NXDOMAIN; the
supplied `deploy/unbound.conf` caps it at 30 seconds.

## Nightly job

Runs at 00:30 UTC, or by hand for a finished day:

    ctprobe nightly --config /etc/ctprobe/config.toml --day 2026-11-02

Do not use `--force` on a data directory the service is writing to. Under `DynamicUser`,
run it as the service's user, because files created as root stop the service reading them:

    sudo systemd-run --wait --pipe -p DynamicUser=yes -p StateDirectory=ctprobe \
      /usr/local/bin/ctprobe nightly --config /etc/ctprobe/config.toml

## API v1

`/api/v1` answers in JSON, with times in milliseconds. Unknown query parameters are a 400.

| Route | Parameters |
|---|---|
| `GET /api/v1/search` | `q`, `mode` (`exact`, `contains`, `levenshtein`, `homoglyph`), `distance`, `limit`. Domain hits from the permanent index |
| `GET /api/v1/certs` | One of `domain` or `q` (with `mode`, `distance`); filters `from`, `to`, `expires_from`, `expires_to`, `issuer`, `issuer_contains`, `tld`, `wildcard`; `limit`, `cursor`. One row per certificate and registered domain, newest first, from both tiers |
| `GET /api/v1/domain/{domain}` | `limit`, `cursor`. `first_seen`, `last_seen` and `cert_count` from the index (null when only DNS rows exist), and `dns`: the address history, newest first, with the same `rows`, `next_cursor` and `cut_short` as certs |
| `GET /api/v1/ip/{ip}` | `limit`, `cursor`. The registered domains whose names resolved to the address, in name order, each with the `first_seen` and `last_seen` day. Kept as long as DNS rows are |
| `GET /api/v1/feed` | `after`, `limit` (default 1000, at most 10000). Every certificate with at least one name ctprobe had not seen, oldest first. See below |

Errors have one shape, `{"error": {"code": "...", "message": "..."}}`, with codes `bad_request` (400),
`not_found` (404), `busy` (429), `timeout` (504) and `internal` (500). Unknown `/api/v1` paths get it too.

A request that finds no free slot is refused at once with 429 and `Retry-After: 1`; it never queues.

### Following new certificates

`/api/v1/feed` is for a program that wants every new certificate exactly once and keeps its own position.
Each row has `seen_at`, `log_id`, `entry_index`, `issuer_cn`, `san_count`, `new_names` and `names`.
A certificate is in the feed when at least one of its names was new to ctprobe; `names` lists all of them.
A row also has:

- `reg_domains`: the registered domains of `names`, sorted; `new_domains`: how many of them were new.
- `new_name_list` and `new_reg_domains`: which names and which registered domains were new. Both are
  `null` for a certificate stored before ctprobe kept them.
- `not_before`, `not_after` in milliseconds, `issuer_org`.
- `renewal`: `exact` (ctprobe had seen this set of names), `name` (some of the names) or `new`.
- `days_since_seen`: days since the most recently seen of its names was last seen, or `null`.
- `is_wildcard`: whether a name starts with `*.`.
- `cert_hash`: ctprobe's 64-bit certificate key as 16 lowercase hex digits, since a JSON number loses
  precision above 2^53.

- Rows come in `seen_at`, `log_id`, `entry_index` order, after the position in `after`.
- `final_through`: every certificate with a `seen_at` at or before it has been stored, and none stored
  later will have one. The feed returns nothing after it. It moves at each commit, about every five minutes.
- `next_cursor` is the `after` of the next request. It is `<seen_at>.<log_id>.<entry_index>`, so a
  client can store the three numbers. When `more` is false the page reached `final_through` and
  `next_cursor` points past it, so quiet minutes move the position too.
- `more: true` means more rows are waiting: ask again at once. Otherwise ask again after a while.
- Without `after` the feed starts at `final_through`, with an empty page.
- The feed reads the hot tier only, so it reaches back as far as `hot_days`.
- It has one slot of its own, apart from the other `/api/v1` routes. A second request in flight gets 429.

```sh
curl -s 'http://127.0.0.1:8080/api/v1/feed?after=1763596800000.0.0&limit=1000'
```
Two requests run at once, and only one of them may read the archive.

`limit` is 1 to 1000, default 100, and a value outside that is a 400. Follow `next_cursor` until it is null.
`cut_short: true` means the time limit ended the walk: `next_cursor` is then always set and continues after the
last row, or after the last day the walk read to its end, so a page can be empty and still move on. Only a walk that
finished no day and found no row is a 504; for `/domain` with a summary it is a 200 with empty `rows`,
`cut_short: true` and a cursor to retry from. The walk reads only the days within the index's first and last
sighting of a searched domain (for `/domain`, from its first sighting on), plus the days the nightly job has not
finished.

Each row has a `tier`: `hot` while its day is still in the hot tier, `archive` once only the archive holds it.
Certificate rows from `hot` also carry `detail`, except when its fetch ran out of time or found no match. DNS rows are the archive's reduction: each name's first answer
of the day and the answers that differ from the one before.

## Build from source

    apt-get install build-essential pkg-config cmake
    cargo build --release

Run the tests with `cargo test --features mock`.

Every merge to `main` is released as `vYYYY.M.N`; `ctprobe --version` prints it.

## License

MIT
