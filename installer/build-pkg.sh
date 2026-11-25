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
# Menu-bar app: a small Swift program shown at the top of the screen for whoever is signed in. If it cannot be
# compiled the package is still built (the agent works without it).
HERE="$(cd "$(dirname "$0")" && pwd)"
APP="$ROOT/Library/Application Support/Helm/HelmMenu.app"
mkdir -p "$APP/Contents/MacOS" "$ROOT/Library/LaunchAgents"
if swiftc -O -o "$APP/Contents/MacOS/HelmMenu" "$HERE/macos/HelmMenu.swift" 2>/tmp/helm-swift.log; then
  cat > "$APP/Contents/Info.plist" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.helm.menu</string><key>CFBundleName</key><string>Helm</string>
<key>CFBundleExecutable</key><string>HelmMenu</string><key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$VERSION</string><key>LSUIElement</key><true/>
</dict></plist>
PL
  codesign --force --sign - "$APP" >/dev/null 2>&1 || true
  install -m 644 "$HERE/../deploy/macos/com.helm.menu.plist" "$ROOT/Library/LaunchAgents/com.helm.menu.plist"
else
  echo "warning: menu-bar app not built:" >&2; cat /tmp/helm-swift.log >&2
  rm -rf "$APP"
fi
cat > "$SCRIPTS/postinstall" <<'POST'
#!/bin/sh
# $1 is the path of the package being installed. macOS can run a downloaded package from a hidden temporary copy,
# so the enrolment file (helm-enroll.conf, from "Download agent" in the console) is looked for next to the package
# and in every user's Downloads and Desktop, and in /Users/Shared. The newest one wins. An existing configuration on
# this Mac is kept.
DIR="/Library/Application Support/Helm"
CONF="$DIR/agent.conf"
FOUND=""
for cand in "$(dirname "$1")/helm-enroll.conf" /Users/Shared/helm-enroll.conf /Users/*/Downloads/helm-enroll*.conf /Users/*/Desktop/helm-enroll*.conf; do
  [ -f "$cand" ] || continue
  if [ -z "$FOUND" ] || [ "$cand" -nt "$FOUND" ]; then FOUND="$cand"; fi
done
if [ -n "$FOUND" ]; then
  mkdir -p "$DIR"; chmod 755 "$DIR"
  cp "$FOUND" "$CONF" && chmod 600 "$CONF" && rm -f "$FOUND"
fi
# Start the menu-bar app for whoever is signed in now (it starts at every login after this).
U=$(stat -f%Su /dev/console 2>/dev/null)
if [ -n "$U" ] && [ "$U" != root ] && [ -f /Library/LaunchAgents/com.helm.menu.plist ]; then
  UIDN=$(id -u "$U")
  launchctl bootout "gui/$UIDN/com.helm.menu" 2>/dev/null
  launchctl bootstrap "gui/$UIDN" /Library/LaunchAgents/com.helm.menu.plist 2>/dev/null
fi
launchctl bootout system/com.helm.agent 2>/dev/null
if [ -f "$CONF" ]; then
  launchctl bootstrap system /Library/LaunchDaemons/com.helm.agent.plist
  launchctl enable system/com.helm.agent
else
  # Tell the person at the Mac, because an installer that says "installed" and does nothing looks broken.
  U=$(stat -f%Su /dev/console 2>/dev/null)
  if [ -n "$U" ] && [ "$U" != root ]; then
    launchctl asuser "$(id -u "$U")" osascript -e 'display dialog "Helm is installed but this Mac is not connected yet.\n\nIn the Helm console open Download agent, choose macOS, download the enrollment file (helm-enroll.conf), then open this installer again." buttons {"OK"} default button "OK" with title "Helm" with icon caution' >/dev/null 2>&1 &
  fi
fi
exit 0
POST
chmod 755 "$SCRIPTS/postinstall"
pkgbuild --root "$ROOT" --scripts "$SCRIPTS" --identifier com.helm.agent --version "$VERSION" \
  --install-location / ${PKG_SIGN_IDENTITY:+--sign "$PKG_SIGN_IDENTITY"} "$OUT"
echo "built $OUT ($ARCH)"
