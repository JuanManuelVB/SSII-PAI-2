#!/usr/bin/env bash
set -euo pipefail
printf 'Distro: '; . /etc/os-release; echo "$PRETTY_NAME"
printf 'TUN: '; test -c /dev/net/tun && echo OK || echo NO_DISPONIBLE
printf 'IP/Interfaces: '; ip -br addr | head -8
printf 'OpenVPN Community: '; command -v openvpn || true
printf 'Access Server: '; systemctl is-active openvpnas 2>/dev/null || true
printf 'Puertos: '; ss -lnt | grep -E ':(943|8443) ' || true
