#!/usr/bin/env bash
# Build Helm-Agent.msi with wixl (msitools) and post-process it with msibuild.
# usage: build-msi.sh <version x.y.z> <helm-agent.exe> <output.msi>
set -euo pipefail
VERSION=${1:?version}; EXE=${2:?agent exe}; OUT=${3:?output msi}
HERE=$(cd "$(dirname "$0")" && pwd)
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version must be x.y.z" >&2; exit 1; }
command -v wixl >/dev/null && command -v msibuild >/dev/null || { echo "install msitools (wixl, msibuild)" >&2; exit 1; }

rm -f "$OUT"
wixl -a x64 -D "VERSION=$VERSION" -D "AgentExe=$EXE" -o "$OUT" "$HERE/helm.wxs"

q() { msibuild "$OUT" -q "$1"; }

# --- component conditions + Permanent (0x10) on the settings components
for pair in "CfgServer:SERVER <> \"\"" "CfgToken:TOKEN <> \"\"" "CfgConsent:CONSENT <> \"\"" "CfgInsecure:ALLOWINSECURE = \"1\""; do
  c=${pair%%:*}; cond=${pair#*:}
  q "UPDATE \`Component\` SET \`Condition\`='$cond', \`Attributes\`=276 WHERE \`Component\`='$c'"
done

# --- launch conditions
q "INSERT INTO \`LaunchCondition\` (\`Condition\`,\`Description\`) VALUES ('Installed OR VersionNT >= 603','Helm Agent needs Windows 8.1 / Server 2012 R2 or newer.')"
q "INSERT INTO \`LaunchCondition\` (\`Condition\`,\`Description\`) VALUES ('Privileged','Helm Agent must be installed by an administrator.')"

# --- public properties may be set from the command line even in restricted (elevated-by-policy) installs
q "UPDATE \`Property\` SET \`Value\`='SERVER;TOKEN;CONSENT;ALLOWINSECURE;WIX_DOWNGRADE_DETECTED;WIX_UPGRADE_DETECTED' WHERE \`Property\`='SecureCustomProperties'"

# --- custom actions (type 3170 = run exe from a directory, deferred, no impersonation, ignore failure)
q "INSERT INTO \`CustomAction\` (\`Action\`,\`Type\`,\`Source\`,\`Target\`) VALUES ('SvcRecovery',3170,'TARGETDIR','\"[System64Folder]sc.exe\" failure HelmAgent reset= 86400 actions= restart/5000/restart/15000/restart/60000')"
q "INSERT INTO \`CustomAction\` (\`Action\`,\`Type\`,\`Source\`,\`Target\`) VALUES ('CleanRegistry',3170,'TARGETDIR','\"[System64Folder]reg.exe\" delete HKLM\\SOFTWARE\\Helm /f /reg:64')"
q "INSERT INTO \`CustomAction\` (\`Action\`,\`Type\`,\`Source\`,\`Target\`) VALUES ('CleanData',3170,'TARGETDIR','\"[System64Folder]cmd.exe\" /c rd /s /q \"[CommonAppDataFolder]Helm\"')"
# before StartServices(5900), after InstallServices(5800); clean-up only on a real uninstall (not an upgrade)
q "INSERT INTO \`InstallExecuteSequence\` (\`Action\`,\`Condition\`,\`Sequence\`) VALUES ('SvcRecovery','NOT REMOVE',5850)"
q "INSERT INTO \`InstallExecuteSequence\` (\`Action\`,\`Condition\`,\`Sequence\`) VALUES ('CleanRegistry','REMOVE=\"ALL\" AND NOT UPGRADINGPRODUCTCODE',3490)"
q "INSERT INTO \`InstallExecuteSequence\` (\`Action\`,\`Condition\`,\`Sequence\`) VALUES ('CleanData','REMOVE=\"ALL\" AND NOT UPGRADINGPRODUCTCODE',3491)"

# --- summary: mark as 64-bit / Windows Installer 5.0
echo "built $OUT ($(stat -c %s "$OUT") bytes)"

# --- personalisable template: the portal replaces these fixed-width placeholders with the server URL, the
#     enrollment token and the consent mode when an admin downloads a ready-to-run installer (see
#     internal/server/installer.go; the lengths there must match). Not served directly.
pad() { printf "$1%.0s" $(seq 1 "$2"); }
PH_SERVER="HELMPH_SERVER_$(pad S 146)"; PH_TOKEN="HELMPH_TOKEN_$(pad T 83)"; PH_CONSENT="HELMPH_CONSENT_$(pad C 17)"
TEMPLATE="${OUT%.msi}.template.msi"
cp "$OUT" "$TEMPLATE"
for pair in "SERVER:$PH_SERVER" "TOKEN:$PH_TOKEN" "CONSENT:$PH_CONSENT"; do
  msibuild "$TEMPLATE" -q "INSERT INTO \`Property\` (\`Property\`,\`Value\`) VALUES ('${pair%%:*}','${pair#*:}')"
done
