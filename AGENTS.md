# AGENTS.md

ctprobe measures the Certificate Transparency ecosystem and searches recent certificates. Operators run it on an internal network.

## Rules

This app follows the overcuriousity dev manifest **v2026.11.1** as an orientation:
https://github.com/overcuriousity/overcuriousity-dev-manifest/tree/v2026.11.1/manifest

- Profile: workbench look and density, with a top bar only. No rail, facets, inspector or status bar.
- Read the manifest files in number order before changing UI, security or ops.

## Where ctprobe differs, on purpose

- No sign-in, sessions, tokens, SQLite or MCP: there are no users, and data lives in redb and Parquet.
- Pages are static shells filled by vanilla JS from JSON and SSE, with every value placed through `textContent`. No Askama or htmx.
- Charts use the vendored uPlot.
- The interface has a German toggle (`assets/i18n.js`); English is the source language.
- Releases are glibc builds, tagged `vYYYY.M.N` by CI on every merge to main. `Cargo.toml` keeps a placeholder version, and there is no hand-written changelog: release notes come from the merged pull requests.
- No offline bundle: ctprobe needs the internet to follow logs. `install.sh` downloads the latest release and uses sudo.
- Config keys are top-level, not under `[app]`, so existing configs keep working.
- `unsafe_code` is denied, with `#[allow]` where libc or mmap needs it. `unwrap` and `expect` are not yet linted.

## Must not change

- `/api/v1` and the `/api/*` routes the pages use.
- The installer one-liner, the release asset names `ctprobe-linux-<arch>.tar.gz` and their `.sha256` files.

## Layout

- `src/` the collector, store, query engine and web layer (`src/web/`).
- `assets/` pages, scripts, styles, fonts and icons, embedded in the binary.
- `deploy/` systemd units and default configs shipped in each release.

## Commands

- `cargo test --features mock`
- `cargo clippy --all-targets --features mock -- -D warnings`
- `cargo fmt --check`
- `cargo deny check`
- `shellcheck install.sh`
