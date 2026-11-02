# Downloads the WinDivert 2.2.2 driver (signed, LGPLv3/GPLv2) that the Windows
# build ships next to SentinelProxy.exe, and verifies its checksum.
param([string]$Dest = "third_party/windivert")
$ErrorActionPreference = "Stop"
$Version = "2.2.2"
$Sha256 = "63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15"
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("wd-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  $zip = Join-Path $tmp "wd.zip"
  Invoke-WebRequest "https://github.com/basil00/WinDivert/releases/download/v$Version/WinDivert-$Version-A.zip" -OutFile $zip
  $hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
  if ($hash -ne $Sha256) { throw "WinDivert checksum mismatch: $hash" }
  Expand-Archive $zip -DestinationPath $tmp
  Copy-Item "$tmp/WinDivert-$Version-A/x64/WinDivert.dll", "$tmp/WinDivert-$Version-A/x64/WinDivert64.sys" $Dest
  Copy-Item "$tmp/WinDivert-$Version-A/LICENSE" (Join-Path $Dest "WinDivert-LICENSE.txt")
  Write-Host "WinDivert $Version -> $Dest"
} finally {
  Remove-Item -Recurse -Force $tmp
}
