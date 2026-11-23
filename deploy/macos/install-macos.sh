#!/usr/bin/env bash
# Install the Helm agent on macOS 12 or newer (Intel and Apple silicon).
#   curl -fsSL https://<your-helm>/dl/install-macos.sh | sudo bash -s -- --server https://<your-helm> --token <enrollment token>
# Or download the personalised script from "Add a PC" in the console and run:  sudo bash install-macos-<name>.sh
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
[[ $(uname) == Darwin ]] || { echo "this installer is for macOS" >&2; exit 1; }
[[ $EUID -eq 0 ]] || { echo "run as root (use sudo)" >&2; exit 1; }
[[ -n $SERVER && -n $TOKEN ]] || { echo "usage: install-macos.sh --server https://helm.example --token TOKEN" >&2; exit 2; }
[[ $SERVER =~ ^https://[A-Za-z0-9.:-]+$ ]] || { echo "--server must be an https:// address" >&2; exit 2; }
[[ $TOKEN =~ ^[A-Za-z0-9._-]+$ ]] || { echo "the token looks wrong" >&2; exit 2; }
case "$(uname -m)" in
  x86_64) ARCH=amd64 ;; arm64) ARCH=arm64 ;;
  *) echo "unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
echo "Downloading the agent…"
curl -fsSL "$SERVER/dl/helm-agent-darwin-$ARCH" -o "$TMP/helm-agent"
curl -fsSL "$SERVER/dl/com.helm.agent.plist" -o "$TMP/com.helm.agent.plist"
mkdir -p /usr/local/bin
install -m 755 -o root -g wheel "$TMP/helm-agent" /usr/local/bin/helm-agent
xattr -dr com.apple.quarantine /usr/local/bin/helm-agent 2>/dev/null || true
/usr/local/bin/helm-agent configure --server "$SERVER" --token "$TOKEN" --consent "$CONSENT"
install -m 644 -o root -g wheel "$TMP/com.helm.agent.plist" /Library/LaunchDaemons/com.helm.agent.plist
launchctl bootout system/com.helm.agent 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/com.helm.agent.plist
launchctl enable system/com.helm.agent
echo "Helm agent $(/usr/local/bin/helm-agent version) installed. It should appear in the console within a minute (approve it there)."
echo "Note: for full inventory the agent may need Full Disk Access (System Settings → Privacy & Security)."
