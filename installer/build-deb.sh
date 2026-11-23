#!/usr/bin/env bash
# usage: build-deb.sh VERSION AGENT_BINARY ARCH(amd64|arm64) OUT.deb
# Builds a .deb without dpkg-deb (ar + tar), so it works on any build machine.
set -euo pipefail
VERSION=$1; BIN=$2; ARCH=$3; OUT=$(cd "$(dirname "$4")" && pwd)/$(basename "$4")
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
mkdir -p "$W/root/usr/local/bin" "$W/root/lib/systemd/system" "$W/ctl"
install -m 755 "$BIN" "$W/root/usr/local/bin/helm-agent"
install -m 644 "$HERE/deploy/linux/helm-agent.service" "$W/root/lib/systemd/system/helm-agent.service"
cat > "$W/ctl/control" <<C
Package: helm-agent
Version: $VERSION
Architecture: $ARCH
Maintainer: Helm <root@localhost>
Section: admin
Priority: optional
Description: Helm management agent
 Lets your Helm console manage this machine.
C
cat > "$W/ctl/postinst" <<'C'
#!/bin/sh
set -e
systemctl daemon-reload || true
if [ -f /etc/helm-agent/agent.conf ]; then
  systemctl enable helm-agent >/dev/null 2>&1 || true
  systemctl restart helm-agent || true
else
  echo "Helm agent installed. Enroll it with:"
  echo "  sudo helm-agent configure --server https://YOUR-HELM --token TOKEN && sudo systemctl enable --now helm-agent"
fi
C
cat > "$W/ctl/prerm" <<'C'
#!/bin/sh
if [ "$1" = remove ] || [ "$1" = purge ]; then systemctl disable --now helm-agent >/dev/null 2>&1 || true; fi
C
cat > "$W/ctl/postrm" <<'C'
#!/bin/sh
if [ "$1" = purge ]; then rm -rf /etc/helm-agent /var/lib/helm-agent; fi
systemctl daemon-reload >/dev/null 2>&1 || true
C
chmod 755 "$W/ctl/postinst" "$W/ctl/prerm" "$W/ctl/postrm"
( cd "$W/root" && tar --owner=0 --group=0 -czf "$W/data.tar.gz" . )
( cd "$W/ctl" && tar --owner=0 --group=0 -czf "$W/control.tar.gz" . )
echo 2.0 > "$W/debian-binary"
( cd "$W" && ar rc pkg.deb debian-binary control.tar.gz data.tar.gz )
mv "$W/pkg.deb" "$OUT"
