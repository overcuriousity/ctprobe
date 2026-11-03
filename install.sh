#!/bin/sh
# Installs the latest ctprobe binary and, where systemd runs, a service that starts it.
#   CTPROBE_NO_SERVICE=1     installs the binary only
#   CTPROBE_INSTALL_DIR=dir  installs the binary there, and no service
#   CTPROBE_NO_DNS=1         sets up no Unbound resolver, so DNS probing stays off
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

unbound_path() {
    for p in /usr/sbin/unbound /usr/bin/unbound /usr/local/sbin/unbound; do
        [ -x "$p" ] && echo "$p" && return 0
    done
    command -v unbound 2>/dev/null
}

# Installs Unbound and runs it for ctprobe alone on 127.0.0.1:5335. A distro
# service this installed is stopped, so nothing else starts listening on port
# 53 or takes over the system's resolver. Returns non-zero if it cannot.
install_unbound() {
    if [ -z "$(unbound_path)" ]; then
        echo "Installing Unbound for DNS probing"
        if command -v apt-get >/dev/null; then
            as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -q unbound >/dev/null || return 1
        elif command -v dnf >/dev/null; then
            as_root dnf install -y -q unbound >/dev/null || return 1
        elif command -v zypper >/dev/null; then
            as_root zypper --non-interactive --quiet install unbound >/dev/null || return 1
        else
            echo "No apt-get, dnf or zypper found to install Unbound."
            return 1
        fi
        for unit in unbound.service unbound-resolvconf.service; do
            as_root systemctl disable --now "$unit" >/dev/null 2>&1 || true
        done
    fi
    ub=$(unbound_path)
    [ -n "$ub" ] || return 1
    if [ ! -e /etc/ctprobe/unbound.conf ]; then
        as_root install -m 644 "$1/deploy/unbound.conf" /etc/ctprobe/unbound.conf
        # Without a route to IPv6, asking IPv6 name servers only adds timeouts.
        if [ -z "$(ip -6 route show default 2>/dev/null)" ]; then
            as_root sed -i 's/do-ip6: yes/do-ip6: no/' /etc/ctprobe/unbound.conf
        fi
    fi
    if command -v unbound-checkconf >/dev/null && ! as_root unbound-checkconf /etc/ctprobe/unbound.conf >/dev/null; then
        echo "/etc/ctprobe/unbound.conf does not pass unbound-checkconf."
        return 1
    fi
    sed "s|@UNBOUND@|$ub|" "$1/deploy/ctprobe-unbound.service" > "$1/ctprobe-unbound.service"
    as_root install -m 644 "$1/ctprobe-unbound.service" /etc/systemd/system/ctprobe-unbound.service
    as_root systemctl daemon-reload
    as_root systemctl enable ctprobe-unbound >/dev/null 2>&1
    as_root systemctl restart ctprobe-unbound
}

# Points a config without a [dns] section, new or kept, at the local Unbound.
add_dns_section() {
    if ! grep -q '^\[dns\]' /etc/ctprobe/config.toml; then
        printf '\n[dns]\n# Local Unbound, run by ctprobe-unbound.service.\nresolver = "127.0.0.1:5335"\n' |
            as_root tee -a /etc/ctprobe/config.toml >/dev/null
        echo "DNS probing enabled in /etc/ctprobe/config.toml"
    fi
}

# Keeps an existing config, so a reinstall only updates the binary and unit.
install_service() {
    as_root install -d /etc/ctprobe
    if [ ! -e /etc/ctprobe/config.toml ]; then
        as_root install -m 644 "$1/deploy/config.toml" /etc/ctprobe/config.toml
    fi
    if [ -z "${CTPROBE_NO_DNS:-}" ]; then
        if install_unbound "$1"; then
            add_dns_section
        else
            echo "Unbound is not set up, so DNS probing stays off."
        fi
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
