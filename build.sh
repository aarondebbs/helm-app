#!/usr/bin/env bash
# Build everything into ./out:
#   out/helm-server-linux-arm64      server for the Raspberry Pi (also -amd64)
#   out/helm-sign                    release signing tool (for this machine)
#   out/server-data/dist/Helm-Agent.msi        served at /dl/Helm-Agent.msi
#   out/server-data/releases/windows-*/        signed self-update releases
#   out/agent/helm-agent-windows-{amd64,arm64}.exe
# Copy out/server-data/* into the server's -data directory (default /var/lib/helm).
#
# usage: ./build.sh [version]        (default: contents of VERSION)
# The release signing key is created once at ./keys/release.key. KEEP IT PRIVATE AND BACKED UP:
# it is the only thing that can publish agent updates. Losing it means re-installing the MSI everywhere.
set -euo pipefail
cd "$(dirname "$0")"
VERSION=${1:-$(cat VERSION)}
OUT=out
rm -rf "$OUT"; mkdir -p "$OUT/agent" "$OUT/server-data/dist" keys
export CGO_ENABLED=0

go build -trimpath -o "$OUT/helm-sign" ./cmd/helm-sign
if [[ ! -f keys/release.key ]]; then
  "$OUT/helm-sign" keygen -out keys/release.key
  chmod 600 keys/release.key
fi
PUB=$("$OUT/helm-sign" pub -key keys/release.key | tail -n1 | tr -d '[:space:]')
[[ $PUB =~ ^[0-9a-f]{64}$ ]] || { echo "could not read the public key (got: $PUB)" >&2; exit 1; }

# Windows/agent binaries keep their symbol tables (no -s -w): stripped Go binaries score worse with
# machine-learning scanners. They also carry a manifest and version block (tools/mkwinres).
LD="-X main.version=$VERSION -X main.updatePubKey=$PUB"
go run ./tools/mkwinres -version "$VERSION" -out cmd/helm-agent

# Optional Authenticode signing. Set HELM_SIGN_PFX (and HELM_SIGN_PASS) to a code-signing certificate
# and install osslsigncode; every Windows .exe and the .msi are then signed and timestamped.
sign_pe() {
  [[ -n ${HELM_SIGN_PFX:-} ]] || return 0
  command -v osslsigncode >/dev/null || { echo "osslsigncode not installed; cannot sign $1" >&2; exit 1; }
  osslsigncode sign -pkcs12 "$HELM_SIGN_PFX" -pass "${HELM_SIGN_PASS:-}" -n "Helm" -h sha256 \
      -t "${HELM_SIGN_TS:-http://timestamp.digicert.com}" -in "$1" -out "$1.signed" && mv "$1.signed" "$1"
}
# Windows server (service build for Windows Server / Windows 10+). Same release key, shipped in the GitHub release.
for arch in amd64 arm64; do
  GOOS=windows GOARCH=$arch go build -trimpath -ldflags "-X main.version=$VERSION -X main.updatePubKey=$PUB" -o "$OUT/helm-server-windows-$arch.exe" ./cmd/helm-server
  sign_pe "$OUT/helm-server-windows-$arch.exe"
done

for arch in amd64 arm64; do
  GOOS=windows GOARCH=$arch go build -trimpath -ldflags "$LD" -o "$OUT/agent/helm-agent-windows-$arch.exe" ./cmd/helm-agent
  sign_pe "$OUT/agent/helm-agent-windows-$arch.exe"
  "$OUT/helm-sign" sign -key keys/release.key -version "$VERSION" -os windows -arch "$arch" \
      -file "$OUT/agent/helm-agent-windows-$arch.exe" -out "$OUT/server-data/releases"
done
for arch in arm64 amd64; do
  GOOS=linux GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=$VERSION -X main.updatePubKey=$PUB" -o "$OUT/helm-server-linux-$arch" ./cmd/helm-server
  # Linux agent: raw binary for the install script, signed self-update release, and a .deb
  GOOS=linux GOARCH=$arch go build -trimpath -ldflags "$LD" -o "$OUT/agent/helm-agent-linux-$arch" ./cmd/helm-agent
  "$OUT/helm-sign" sign -key keys/release.key -version "$VERSION" -os linux -arch "$arch" \
      -file "$OUT/agent/helm-agent-linux-$arch" -out "$OUT/server-data/releases"
  cp "$OUT/agent/helm-agent-linux-$arch" "$OUT/server-data/dist/helm-agent-linux-$arch"
  installer/build-deb.sh "$VERSION" "$OUT/agent/helm-agent-linux-$arch" "$arch" "$OUT/server-data/dist/helm-agent-linux-$arch.deb"
done
cp deploy/linux/install-linux.sh deploy/linux/helm-agent.service "$OUT/server-data/dist/"

# macOS agent (pure Go, cross-compiled): raw binary for install-macos.sh and signed self-update release.
for arch in arm64 amd64; do
  GOOS=darwin GOARCH=$arch go build -trimpath -ldflags "$LD" -o "$OUT/agent/helm-agent-darwin-$arch" ./cmd/helm-agent
  "$OUT/helm-sign" sign -key keys/release.key -version "$VERSION" -os darwin -arch "$arch" \
      -file "$OUT/agent/helm-agent-darwin-$arch" -out "$OUT/server-data/releases"
  cp "$OUT/agent/helm-agent-darwin-$arch" "$OUT/server-data/dist/helm-agent-darwin-$arch"
  # The .pkg needs Apple's pkgbuild, so it is built only when this script runs on a Mac
  # (the GitHub release workflow does that on a macOS runner and drops the files into extra/).
  if [[ $(uname) == Darwin ]]; then
    installer/build-pkg.sh "$VERSION" "$OUT/agent/helm-agent-darwin-$arch" "$arch" "$OUT/server-data/dist/Helm-Agent-macos-$arch.pkg"
  fi
done
if compgen -G "extra/*.pkg" >/dev/null; then cp extra/*.pkg "$OUT/server-data/dist/"; fi
cp deploy/macos/install-macos.sh deploy/macos/com.helm.agent.plist "$OUT/server-data/dist/"

# The MSI carries the x64 agent (it also runs on Windows-on-ARM through emulation).
installer/build-msi.sh "$VERSION" "$OUT/agent/helm-agent-windows-amd64.exe" "$OUT/server-data/dist/Helm-Agent.msi"

sign_pe "$OUT/server-data/dist/Helm-Agent.msi"; sign_pe "$OUT/server-data/dist/Helm-Agent.template.msi"

# ---- GitHub release bundle: everything the cloud updater needs, signed with the release key ----
REL="$OUT/release"; mkdir -p "$REL"
cp "$OUT"/agent/helm-agent-* "$REL/"
cp "$OUT"/helm-server-linux-* "$OUT"/helm-server-windows-*.exe "$REL/"
cp deploy/windows/Install-HelmServer.ps1 "$REL/"
cp "$OUT"/server-data/dist/{Helm-Agent.msi,Helm-Agent.template.msi,helm-agent.service,install-linux.sh,install-macos.sh,com.helm.agent.plist} "$REL/"
cp "$OUT"/server-data/dist/*.deb "$REL/"
for extra in "$OUT"/server-data/dist/*.pkg; do [[ -f $extra ]] && cp "$extra" "$REL/"; done
"$OUT/helm-sign" manifest -key keys/release.key -version "$VERSION" -dir "$REL" -notes "${RELEASE_NOTES:-Helm $VERSION}"

( cd "$OUT" && sha256sum helm-server-linux-* agent/* server-data/dist/*.deb server-data/dist/Helm-Agent.msi > SHA256SUMS )
echo; echo "Done. Version $VERSION, update public key $PUB"; ls -la "$OUT" "$OUT/server-data/releases"/*
