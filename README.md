# ctprobe

Measures the Certificate Transparency ecosystem in real time and searches recent certificates.

ctprobe follows public CT logs, removes duplicates and keeps rolling statistics on what it sees:
issuance rates, log health and coverage, issuers, key types, validity and new names and domains.
A web interface shows it live and offers crt.sh-style search and read-only SQL.

It runs as one Linux binary and stores everything in one directory. It follows each log from its
current head and does not backfill.

## Install

    curl -fsSL https://raw.githubusercontent.com/overcuriousity/ctprobe/main/install.sh | sh

This installs the latest build for Linux on x86_64 or aarch64 and, where systemd runs, enables and
starts a `ctprobe` service. It needs root, and uses sudo if you are not root. Then open
http://127.0.0.1:8080. Running it again updates ctprobe and keeps your config.

| Setting | Effect |
|---|---|
| `CTPROBE_NO_SERVICE=1` | Installs the binary only |
| `CTPROBE_INSTALL_DIR=dir` | Installs the binary to `dir`, with no service |

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
| `disk_budget` | Ceiling for `data_dir`, in `GiB` or `MiB`. Old certificates expire to stay under it; ingest pauses if it cannot be met |
| `tracker_max` | Memory cap for renewal tracking. Over it, the oldest names are forgotten, so renewals are undercounted |
| `include_logs`, `exclude_logs` | Substrings of log names, applied to every list |
| `log_list_url` | The required log list. Defaults to Google's trusted list |
| `extra_log_lists` | Further lists, by default Apple's. A log on any list is followed. A list that cannot be read is skipped and its logs are kept |
| `include_test_logs` | Also follows the stateless logs on Google's full list, which appear to be test or staging logs. Off by default, because they then count in every figure except coverage |
| `coverage_target` | Percent of certificates the coverage assessment aims for, default 95. It only advises: ctprobe keeps following every log |

## Nightly job

Runs at 00:30 UTC, or by hand for a finished day:

    ctprobe nightly --config /etc/ctprobe/config.toml --day 2026-11-02

Do not use `--force` on a data directory the service is writing to. Under `DynamicUser`,
run it as the service's user, because files created as root stop the service reading them:

    sudo systemd-run --wait --pipe -p DynamicUser=yes -p StateDirectory=ctprobe \
      /usr/local/bin/ctprobe nightly --config /etc/ctprobe/config.toml

## Build from source

    apt-get install build-essential pkg-config cmake
    cargo build --release

Run the tests with `cargo test --features mock`.

## License

MIT
