# Antivirus and false positives

Remote-management agents look like remote-access tools to heuristics. Helm reduces that risk but cannot guarantee zero detections without a code-signing certificate.

## What the build does
- Windows binaries are not stripped and carry an embedded manifest (asInvoker, supported OS list) and version info (company, product, description).
- PowerShell is run with `-ExecutionPolicy RemoteSigned` for script files and without encoded or hidden-window commands; the terminal uses `-Command -`.
- Updates are verified (ed25519 + SHA-256) before use.

## What it cannot do
- **No Authenticode signature yet.** Unsigned executables get SmartScreen warnings and more heuristic scrutiny.
- The portal-personalised MSI has the token injected into its bytes, so a signature applied at build time would be invalidated. To sign, either deliver the token separately (e.g. a small enrolment file, like the macOS `helm-enroll.conf`) or sign after injection with a certificate held on the server.

## Signing (when you have a certificate)
Install `osslsigncode`, then: `HELM_SIGN_PFX=cert.pfx HELM_SIGN_PASS=... HELM_SIGN_TS=http://timestamp.digicert.com ./build.sh`. An EV or OV certificate builds reputation; EV gives immediate SmartScreen trust.

## If a vendor flags it
Submit the exact file hash as a false positive:
- Microsoft Defender: https://www.microsoft.com/wdsi/filesubmission
- Bitdefender: https://www.bitdefender.com/consumer/support/answers/13700/
- Others: VirusTotal -> "Reanalyse"/contact vendor, or each vendor's sample-submission page.
Add an exclusion for the install folder on managed PCs if needed.
