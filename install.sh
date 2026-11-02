#!/bin/sh
# Installs the latest ctprobe binary and, where systemd runs, a service that starts it.
#   CTPROBE_NO_SERVICE=1     installs the binary only
#   CTPROBE_INSTALL_DIR=dir  installs the binary there, and no service
set -eu

REPO="overcuriousity/ctprobe"

fail() {
    echo "ctprobe install: $1" >&2
    exit 1
}

# Runs a command as root, through sudo if needed.
as_root() {
    if [ "$(id -u)" = 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

can_be_root() {
    [ "$(id -u)" = 0 ] || command -v sudo >/dev/null
}

# Keeps an existing config, so a reinstall only updates the binary and unit.
install_service() {
    as_root install -d /etc/ctprobe
    if [ ! -e /etc/ctprobe/config.toml ]; then
        as_root install -m 644 "$1/deploy/config.toml" /etc/ctprobe/config.toml
    fi
    as_root install -m 644 "$1/deploy/ctprobe.service" /etc/systemd/system/ctprobe.service
    as_root systemctl daemon-reload
    as_root systemctl enable ctprobe >/dev/null 2>&1
    as_root systemctl restart ctprobe
    echo "Service started. Open http://127.0.0.1:8080"
    echo "Config: /etc/ctprobe/config.toml    Logs: journalctl -u ctprobe"
}

# Everything runs from main, so a download cut short cannot run half a script.
main() {
    [ "$(uname -s)" = "Linux" ] || fail "only Linux is supported"
    case "$(uname -m)" in
        x86_64 | amd64) arch="x86_64" ;;
        aarch64 | arm64) arch="aarch64" ;;
        *) fail "unsupported architecture $(uname -m)" ;;
    esac
    command -v curl >/dev/null || fail "curl is required"
    command -v sha256sum >/dev/null || fail "sha256sum is required"

    name="ctprobe-linux-$arch.tar.gz"
    url="https://github.com/$REPO/releases/latest/download/$name"
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT

    echo "Downloading $name"
    curl -fsSL "$url" -o "$tmp/$name" || fail "download failed: $url"
    curl -fsSL "$url.sha256" -o "$tmp/$name.sha256" || fail "checksum download failed"
    (cd "$tmp" && sha256sum -c "$name.sha256" >/dev/null) || fail "checksum mismatch"
    tar -xzf "$tmp/$name" -C "$tmp"

    if [ -n "${CTPROBE_INSTALL_DIR:-}" ]; then
        dir="$CTPROBE_INSTALL_DIR"
        mkdir -p "$dir"
        install -m 755 "$tmp/ctprobe" "$dir/ctprobe"
    elif can_be_root; then
        dir="/usr/local/bin"
        as_root install -m 755 "$tmp/ctprobe" "$dir/ctprobe"
    else
        dir="$HOME/.local/bin"
        mkdir -p "$dir"
        install -m 755 "$tmp/ctprobe" "$dir/ctprobe"
    fi
    echo "Installed $dir/ctprobe"

    # The unit runs /usr/local/bin/ctprobe, so a service needs that path.
    if [ "$dir" = "/usr/local/bin" ] && [ -z "${CTPROBE_NO_SERVICE:-}" ] && [ -d /run/systemd/system ]; then
        install_service "$tmp"
    else
        echo "No service installed. Start it with: ctprobe run --config config.toml"
    fi
    case ":$PATH:" in
        *":$dir:"*) ;;
        *) echo "Add $dir to your PATH to run ctprobe." ;;
    esac
}

main "$@"
