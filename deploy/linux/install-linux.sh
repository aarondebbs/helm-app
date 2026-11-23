#!/usr/bin/env bash
# Install the Helm agent on Debian / Ubuntu / Raspberry Pi OS (systemd).
#   curl -fsSL https://<your-helm>/dl/install-linux.sh | sudo bash -s -- --server https://<your-helm> --token <enrollment token>
set -euo pipefail
SERVER=""; TOKEN=""; CONSENT="unattended"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER="${2%/}"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --consent) CONSENT="$2"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo "run as root (use sudo)" >&2; exit 1; }
[[ -n $SERVER && -n $TOKEN ]] || { echo "usage: install-linux.sh --server https://helm.example --token TOKEN" >&2; exit 2; }
[[ $SERVER =~ ^https://[A-Za-z0-9.:-]+$ ]] || { echo "--server must be an https:// address" >&2; exit 2; }
[[ $TOKEN =~ ^[A-Za-z0-9._-]+$ ]] || { echo "the token looks wrong" >&2; exit 2; }
command -v systemctl >/dev/null || { echo "systemd is required" >&2; exit 1; }
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported CPU: $(uname -m) (need 64-bit x86 or arm)" >&2; exit 1 ;;
esac
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
echo "Downloading the agent…"
curl -fsSL "$SERVER/dl/helm-agent-linux-$ARCH" -o "$TMP/helm-agent"
curl -fsSL "$SERVER/dl/helm-agent.service" -o "$TMP/helm-agent.service"
install -m 755 "$TMP/helm-agent" /usr/local/bin/helm-agent
install -m 644 "$TMP/helm-agent.service" /etc/systemd/system/helm-agent.service
/usr/local/bin/helm-agent configure --server "$SERVER" --token "$TOKEN" --consent "$CONSENT"
systemctl daemon-reload
systemctl enable helm-agent >/dev/null
systemctl restart helm-agent
echo "Helm agent $(/usr/local/bin/helm-agent version) installed. It should appear in the console within a minute (approve it there)."
