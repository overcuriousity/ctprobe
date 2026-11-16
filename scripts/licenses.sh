#!/bin/sh
# Writes THIRD-PARTY-LICENSES from the dependency tree and the bundled assets. Needs cargo-about.
set -eu
cd "$(dirname "$0")/.."
cargo about generate --locked about.hbs > THIRD-PARTY-LICENSES
for f in licenses/*.txt; do
    printf '\n\n==== %s ====\n\n' "$f" >> THIRD-PARTY-LICENSES
    cat "$f" >> THIRD-PARTY-LICENSES
done
