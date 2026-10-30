# ---------------------------------------------------------------------------
# build.ps1
# PURPOSE:  Reproducible local build for Aegis Wallet Shield on Windows 10/11.
#           Builds two completely standalone, air-gapped tools:
#             1. Aegis Browser Guard (MV3 extension -> extension/dist/extension)
#             2. Aegis Clip Guard (standalone offline Windows desktop cleaner ->
#                clipguard-helper/bin/aegis-clipguard.exe using Windows' built-in
#                C# compiler csc.exe; zero downloads, zero registry, zero IPC)
#             3. Release archives in dist/ (POSIX '/' zip entry paths):
#                - Aegis-BrowserGuard.zip
#                - Aegis-ClipGuard-Windows.zip
#                - aegis-clipguard.exe
#                - SHA256SUMS.txt
# ACCESS:   Local workspace files and local build tools (node/npm + built-in csc.exe).
# NEVER:    No network calls unless npm dependencies are missing and -InstallDeps is set.
# ---------------------------------------------------------------------------
param(
    [switch]$InstallDeps,
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function New-PosixZip([string]$SourceParentDir, [string]$FolderName, [string]$DestZipPath) {
    if (Test-Path -LiteralPath $DestZipPath) {
        Remove-Item -LiteralPath $DestZipPath -Force
    }
    $rootFull = (Resolve-Path -LiteralPath (Join-Path $SourceParentDir $FolderName)).Path
    $fs = [System.IO.File]::Open($DestZipPath, [System.IO.FileMode]::CreateNew)
    try {
        $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            $files = Get-ChildItem -LiteralPath $rootFull -Recurse -File | Sort-Object FullName
            foreach ($file in $files) {
                $rel = $file.FullName.Substring($rootFull.Length + 1).Replace('\', '/')
                $entryName = "$FolderName/$rel"
                [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                    $zip,
                    $file.FullName,
                    $entryName,
                    [System.IO.Compression.CompressionLevel]::Optimal
                ) | Out-Null
            }
        } finally {
            $zip.Dispose()
        }
    } finally {
        $fs.Dispose()
    }
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ExtDir   = Join-Path $RepoRoot 'extension'
$CgDir    = Join-Path $RepoRoot 'clipguard-helper'
$DistDir  = Join-Path $RepoRoot 'dist'

Write-Host "=== Aegis Wallet Shield - Local Open-Source Build ===" -ForegroundColor Cyan

# 1. Extension dependencies & build
Push-Location $ExtDir
try {
    if ($InstallDeps -or -not (Test-Path -LiteralPath (Join-Path $ExtDir 'node_modules'))) {
        Write-Host "`n[1/5] Installing extension dependencies (npm ci)..." -ForegroundColor Yellow
        & npm ci
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }
    } else {
        Write-Host "`n[1/5] Extension node_modules present (skipping npm install)." -ForegroundColor Gray
    }

    Write-Host "`n[2/5] Building Aegis Browser Guard extension..." -ForegroundColor Yellow
    & npm run build
    if ($LASTEXITCODE -ne 0) { throw "Extension build failed" }

    if (-not $SkipTests) {
        Write-Host "      Running TypeScript check and unit tests..." -ForegroundColor Gray
        & npx tsc --noEmit
        if ($LASTEXITCODE -ne 0) { throw "TypeScript check failed" }
        & npm test
        if ($LASTEXITCODE -ne 0) { throw "Extension unit tests failed" }
    }
} finally {
    Pop-Location
}

# 2. Standalone Clip Guard Windows app build (built-in Windows csc.exe - zero SDK downloads)
Write-Host "`n[3/5] Building standalone Aegis Clip Guard Windows cleaner (built-in csc.exe)..." -ForegroundColor Yellow
$CgBuildBat = Join-Path $CgDir 'build.bat'
& cmd.exe /c "`"$CgBuildBat`""
if ($LASTEXITCODE -ne 0) { throw "Clip Guard build.bat failed" }

if (-not $SkipTests) {
    Write-Host "      Running Clip Guard test and stress suite..." -ForegroundColor Gray
    $CgTestBat = Join-Path $CgDir 'tests\run-tests.bat'
    & cmd.exe /c "`"$CgTestBat`""
    if ($LASTEXITCODE -ne 0) { throw "Clip Guard tests failed" }
}

# 3. Automated Security & Zero-Network / Zero-Bridge / Zero-Registry Verification
Write-Host "`n[4/5] Running security and isolation audit..." -ForegroundColor Yellow
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'verify-security.ps1')
if ($LASTEXITCODE -ne 0) { throw "Security verification failed" }

# 4. Package standalone Browser Guard & standalone Clip Guard Windows zips + SHA256SUMS.txt
Write-Host "`n[5/5] Packaging standalone Browser Guard and Clip Guard Windows editions..." -ForegroundColor Yellow
if (Test-Path -LiteralPath $DistDir) {
    Remove-Item -LiteralPath $DistDir -Recurse -Force
}
New-Item -ItemType Directory -Path $DistDir | Out-Null

$BuiltExt = Join-Path $ExtDir 'dist\extension'
$BuiltExe = Join-Path $CgDir 'bin\aegis-clipguard.exe'

# Stage 1: Standalone Browser Extension
$StageBGParent = Join-Path $DistDir 'staging-bg'
$StageBG = Join-Path $StageBGParent 'Aegis-BrowserGuard'
New-Item -ItemType Directory -Path (Join-Path $StageBG 'extension') -Force | Out-Null
Copy-Item -Path (Join-Path $BuiltExt '*') -Destination (Join-Path $StageBG 'extension') -Recurse -Force
@"
AEGIS BROWSER GUARD - STANDALONE EXTENSION QUICKSTART
=====================================================
1. Open Chrome, Brave, or Edge and go to:
     chrome://extensions   (or brave://extensions / edge://extensions)
2. Turn ON "Developer mode" (top-right toggle).
3. Click "Load unpacked" and select the "extension" folder inside this folder.
4. On the welcome page (or Settings), pick a 1-click Free Public Solana RPC
   preset (no API key needed) or keep Offline Static Mode.

SECURITY & ISOLATION:
- 100% open source and non-minified.
- Zero backend servers, zero telemetry, zero native process bridges.
- Clipboard contents never leave your device.
"@ | Set-Content -LiteralPath (Join-Path $StageBG 'QUICKSTART.txt') -Encoding UTF8

# Stage 2: Standalone Offline Windows Ghost Copy & Clipboard Cleaner
$StageCGParent = Join-Path $DistDir 'staging-cg'
$StageCG = Join-Path $StageCGParent 'Aegis-ClipGuard-Windows'
New-Item -ItemType Directory -Path $StageCG -Force | Out-Null
Copy-Item -LiteralPath $BuiltExe -Destination (Join-Path $StageCG 'aegis-clipguard.exe') -Force

@"
@echo off
echo Running Aegis Clip Guard Ghost Copy Scan in terminal mode (masked output only)...
echo.
"%~dp0aegis-clipguard.exe" --ghost-scan
echo.
pause
"@ | Set-Content -LiteralPath (Join-Path $StageCG 'Run-GhostCopyScan-CLI.bat') -Encoding ASCII

@"
AEGIS CLIP GUARD - STANDALONE WINDOWS LOCAL CLEANER
===================================================
100% Air-Gapped Local Cleanup Utility:
  - ZERO network code (no internet access in this binary)
  - ZERO browser connection (completely separate from your browser)
  - ZERO installation & ZERO Windows Registry edits

HOW TO USE:
  Simply double-click "aegis-clipguard.exe" to open the desktop window!
  Click "Scan All Ghost Copies" to check:
    - Windows 11 Notepad unsaved auto-saved tabs (TabState\*.bin)
    - Windows Clipboard History (Win+V)
    - Microsoft Sticky Notes database
    - Desktop, Documents, Downloads, Screenshots, and Recycle Bin

  All findings are shown MASKED ONLY (e.g. shortened public key "7xKp...9Qm4"
  or "12 words, starts with a..."). Delete this file anytime to remove it.

NOTE ON UNSIGNED OPEN-SOURCE SOFTWARE:
  We do not purchase a corporate code-signing certificate. If Windows SmartScreen
  prompts "Windows protected your PC", click "More info -> Run anyway" - OR
  compile aegis-clipguard.exe yourself in 2 seconds by double-clicking
  clipguard-helper\build.bat in the GitHub source repo (uses Windows' built-in
  C# compiler csc.exe, zero downloads required).
"@ | Set-Content -LiteralPath (Join-Path $StageCG 'QUICKSTART.txt') -Encoding UTF8

$ZipBG = Join-Path $DistDir 'Aegis-BrowserGuard.zip'
$ZipCG = Join-Path $DistDir 'Aegis-ClipGuard-Windows.zip'
$OutExeCopy = Join-Path $DistDir 'aegis-clipguard.exe'

Copy-Item -LiteralPath $BuiltExe -Destination $OutExeCopy -Force
New-PosixZip -SourceParentDir $StageBGParent -FolderName 'Aegis-BrowserGuard' -DestZipPath $ZipBG
New-PosixZip -SourceParentDir $StageCGParent -FolderName 'Aegis-ClipGuard-Windows' -DestZipPath $ZipCG

Remove-Item -LiteralPath $StageBGParent -Recurse -Force
Remove-Item -LiteralPath $StageCGParent -Recurse -Force

# Compute SHA-256 sums
$SumLines = @()
foreach ($artifact in @($ZipBG, $ZipCG, $OutExeCopy)) {
    $h = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
    $name = Split-Path -Leaf $artifact
    $SumLines += "$h  $name"
}
$SumsPath = Join-Path $DistDir 'SHA256SUMS.txt'
$SumLines | Set-Content -LiteralPath $SumsPath -Encoding ASCII

Write-Host "`n=== Build Complete - SHA-256 Checksums ===" -ForegroundColor Green
$SumLines | ForEach-Object { Write-Host "  $_" }
Write-Host "`nArtifacts written to: $DistDir" -ForegroundColor Cyan
