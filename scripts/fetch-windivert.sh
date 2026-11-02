#!/usr/bin/env bash
# Downloads the WinDivert 2.2.2 driver (signed, LGPLv3/GPLv2) that the Windows
# build ships next to SentinelProxy.exe, and verifies its checksum.
set -euo pipefail
VERSION=2.2.2
SHA256=63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15
DEST="${1:-third_party/windivert}"
mkdir -p "$DEST"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL -o "$TMP/wd.zip" "https://github.com/basil00/WinDivert/releases/download/v${VERSION}/WinDivert-${VERSION}-A.zip"
echo "${SHA256}  $TMP/wd.zip" | sha256sum -c -
unzip -q -o "$TMP/wd.zip" -d "$TMP"
cp "$TMP/WinDivert-${VERSION}-A/x64/WinDivert.dll" "$TMP/WinDivert-${VERSION}-A/x64/WinDivert64.sys" "$DEST/"
cp "$TMP/WinDivert-${VERSION}-A/LICENSE" "$DEST/WinDivert-LICENSE.txt"
echo "WinDivert ${VERSION} -> $DEST"
