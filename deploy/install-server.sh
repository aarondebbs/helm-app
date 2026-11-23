#!/usr/bin/env bash
# Run on the Raspberry Pi as root, from the unpacked release folder:
#   sudo ./deploy/install-server.sh
set -euo pipefail
cd "$(dirname "$0")/.."
BIN=out/helm-server-linux-arm64; [[ -f $BIN ]] || BIN=helm-server-linux-arm64
[[ -f $BIN ]] || { echo "helm-server-linux-arm64 not found"; exit 1; }
id helm >/dev/null 2>&1 || useradd --system --home /var/lib/helm --shell /usr/sbin/nologin helm
install -m 0755 "$BIN" /usr/local/bin/helm-server
install -d -o helm -g helm -m 0700 /var/lib/helm
if [[ -d out/server-data ]]; then cp -a out/server-data/. /var/lib/helm/; elif [[ -d server-data ]]; then cp -a server-data/. /var/lib/helm/; fi
chown -R helm:helm /var/lib/helm
install -m 0644 deploy/helm-server.service /etc/systemd/system/helm-server.service
systemctl daemon-reload
echo
echo "Installed. Next:"
echo "  1) sudo -u helm /usr/local/bin/helm-server init-admin -data /var/lib/helm      (creates the admin + shows the 2FA key)"
echo "  2) sudo systemctl enable --now helm-server"
echo "  3) sudo tailscale funnel --bg 8787                                             (publishes it on https://<pi>.<tailnet>.ts.net)"
