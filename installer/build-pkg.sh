#!/usr/bin/env bash
# Build the macOS installer package. Needs macOS (pkgbuild is an Apple tool).
#   installer/build-pkg.sh <version> <path to helm-agent-darwin-ARCH> <amd64|arm64> <out.pkg>
# The package carries no token. The console offers a small helm-enroll.conf for each enrollment token: put it
# in the same folder as the .pkg and open the package, and the Mac enrols itself. (A .pkg is a signed archive,
# so the server cannot rewrite it per token the way it does for the Windows .msi.)
set -euo pipefail
[[ $(uname) == Darwin ]] || { echo "build-pkg.sh must run on macOS (pkgbuild)" >&2; exit 1; }
VERSION=$1; BIN=$2; ARCH=$3; OUT=$4
ROOT=$(mktemp -d); SCRIPTS=$(mktemp -d); trap 'rm -rf "$ROOT" "$SCRIPTS"' EXIT
mkdir -p "$ROOT/usr/local/bin" "$ROOT/Library/LaunchDaemons"
install -m 755 "$BIN" "$ROOT/usr/local/bin/helm-agent"
install -m 644 "$(dirname "$0")/../deploy/macos/com.helm.agent.plist" "$ROOT/Library/LaunchDaemons/com.helm.agent.plist"
cat > "$SCRIPTS/postinstall" <<'POST'
#!/bin/sh
# $1 is the path of the package being installed. Enrolment settings come from helm-enroll.conf next to it
# (downloaded from "Add a PC" in the console), or from an existing configuration on this Mac.
DIR="/Library/Application Support/Helm"
CONF="$DIR/agent.conf"
for cand in "$(dirname "$1")/helm-enroll.conf" "/Users/Shared/helm-enroll.conf"; do
  if [ -f "$cand" ]; then
    mkdir -p "$DIR"; chmod 700 "$DIR"
    cp "$cand" "$CONF" && chmod 600 "$CONF" && rm -f "$cand"
    break
  fi
done
launchctl bootout system/com.helm.agent 2>/dev/null
if [ -f "$CONF" ]; then
  launchctl bootstrap system /Library/LaunchDaemons/com.helm.agent.plist
  launchctl enable system/com.helm.agent
fi
exit 0
POST
chmod 755 "$SCRIPTS/postinstall"
pkgbuild --root "$ROOT" --scripts "$SCRIPTS" --identifier com.helm.agent --version "$VERSION" \
  --install-location / ${PKG_SIGN_IDENTITY:+--sign "$PKG_SIGN_IDENTITY"} "$OUT"
echo "built $OUT ($ARCH)"
