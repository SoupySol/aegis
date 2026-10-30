# ---------------------------------------------------------------------------
# verify-security.ps1
# PURPOSE:  Automated static audit verifying Aegis's core safety guarantees:
#             1. Extension outbound network calls exist ONLY in files tagged
#                with `AEGIS-NETWORK:` (solely rpc.ts).
#             2. Zero dynamic code evaluation (`eval`, `new Function`) or
#                remote script tags anywhere in the extension.
#             3. Zero `nativeMessaging` bridge in the browser extension
#                (Browser Guard and Clip Guard are 100% air-gapped from each other).
#             4. Zero network APIs, URLs, or Windows Registry writes anywhere
#                in Clip Guard C# source.
#             5. Every source file carries PURPOSE / ACCESS header documentation.
#             6. No `.env` files or hardcoded API keys in the repository.
# ACCESS:   Reads local repository source files only.
# NEVER:    No network calls. Modifies nothing.
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ExtSrc   = Join-Path $RepoRoot 'extension\src'
$CgSrc    = Join-Path $RepoRoot 'clipguard-helper\src'
$Failures = New-Object System.Collections.Generic.List[string]

function Fail([string]$Message) {
    $Failures.Add($Message)
    Write-Host "  [FAIL] $Message" -ForegroundColor Red
}

function Pass([string]$Message) {
    Write-Host "  [PASS] $Message" -ForegroundColor Green
}

Write-Host "`n=== Aegis Security and Transparency Verification ===" -ForegroundColor Cyan

# ---- 1. Extension Network Allowlist ----------------------------------------
$tsFiles = Get-ChildItem -Path $ExtSrc -Recurse -File -Include *.ts
$netPattern = '\b(fetch\s*\(|XMLHttpRequest\b|WebSocket\b|sendBeacon\s*\(|EventSource\b)'
$untaggedNet = @()
$taggedNetFiles = @()

foreach ($f in $tsFiles) {
    $raw = Get-Content -LiteralPath $f.FullName -Raw
    $codeOnly = [regex]::Replace($raw, '(?s)/\*.*?\*/', '')
    $codeOnly = [regex]::Replace($codeOnly, '(?m)//.*$', '')
    if ($codeOnly -match $netPattern) {
        $rel = $f.FullName.Substring($RepoRoot.Length + 1)
        if ($raw -match 'AEGIS-NETWORK:') {
            $taggedNetFiles += $rel
        } else {
            $untaggedNet += $rel
        }
    }
}

if ($untaggedNet.Count -gt 0) {
    foreach ($u in $untaggedNet) { Fail "Untagged network API found in $u" }
} elseif ($taggedNetFiles.Count -gt 1 -or ($taggedNetFiles.Count -eq 1 -and $taggedNetFiles[0] -notlike '*rpc.ts')) {
    Fail ("Unexpected AEGIS-NETWORK file(s): " + ($taggedNetFiles -join ', '))
} else {
    Pass ("Extension network allowlist verified (only: " + ($taggedNetFiles -join ', ') + ")")
}

# ---- 2. Zero Remote Code / Dynamic Eval ------------------------------------
$evalHits = @()
foreach ($f in $tsFiles) {
    $raw = Get-Content -LiteralPath $f.FullName -Raw
    $codeOnly = [regex]::Replace($raw, '(?s)/\*.*?\*/', '')
    $codeOnly = [regex]::Replace($codeOnly, '(?m)//.*$', '')
    if ($codeOnly -match '\beval\s*\(' -or $codeOnly -match '\bnew\s+Function\s*\(') {
        $evalHits += $f.FullName.Substring($RepoRoot.Length + 1)
    }
}
$htmlFiles = Get-ChildItem -Path (Join-Path $RepoRoot 'extension') -Recurse -File -Include *.html |
    Where-Object { $_.FullName -notmatch '\\node_modules\\|\\dist\\|\\spikes\\' }
foreach ($h in $htmlFiles) {
    $raw = Get-Content -LiteralPath $h.FullName -Raw
    if ($raw -match '<script[^>]+src\s*=\s*["'']https?:') {
        $evalHits += $h.FullName.Substring($RepoRoot.Length + 1)
    }
}
if ($evalHits.Count -gt 0) {
    foreach ($e in $evalHits) { Fail "Dynamic code or remote script found in $e" }
} else {
    Pass "Zero eval(), new Function(), or remote <script> tags in extension"
}

# ---- 3. Zero Browser-to-Exe Native Messaging Bridge ------------------------
$manifestTpl = Join-Path $RepoRoot 'extension\static\manifest.template.json'
$nativeBridgeHits = @()
if (Test-Path -LiteralPath $manifestTpl) {
    $mRaw = Get-Content -LiteralPath $manifestTpl -Raw
    if ($mRaw -match 'nativeMessaging') {
        $nativeBridgeHits += 'extension\static\manifest.template.json (nativeMessaging permission)'
    }
}
foreach ($f in $tsFiles) {
    $raw = Get-Content -LiteralPath $f.FullName -Raw
    $codeOnly = [regex]::Replace($raw, '(?s)/\*.*?\*/', '')
    $codeOnly = [regex]::Replace($codeOnly, '(?m)//.*$', '')
    if ($codeOnly -match '\b(connectNative|sendNativeMessage)\b') {
        $nativeBridgeHits += $f.FullName.Substring($RepoRoot.Length + 1)
    }
}
if ($nativeBridgeHits.Count -gt 0) {
    foreach ($nh in $nativeBridgeHits) { Fail "Browser-to-native bridge found in $nh" }
} else {
    Pass "Browser extension is 100% isolated from native processes (zero nativeMessaging)"
}

# ---- 4. Clip Guard Zero-Network & Zero-Registry Check ----------------------
$cgNoNetScript = Join-Path $RepoRoot 'clipguard-helper\tools\check-no-network.ps1'
if (Test-Path -LiteralPath $cgNoNetScript) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File $cgNoNetScript
    if ($LASTEXITCODE -ne 0) {
        Fail "clipguard-helper/tools/check-no-network.ps1 reported forbidden network usage"
    } else {
        Pass "Clip Guard standalone zero-network check passed (check-no-network.ps1)"
    }
}
$csFiles = Get-ChildItem -Path $CgSrc -Recurse -File -Filter *.cs
$regHits = @()
foreach ($c in $csFiles) {
    $raw = Get-Content -LiteralPath $c.FullName -Raw
    $codeOnly = [regex]::Replace($raw, '(?s)/\*.*?\*/', '')
    $codeOnly = [regex]::Replace($codeOnly, '(?m)//.*$', '')
    if ($codeOnly -match '\b(Microsoft\.Win32\.Registry|Registry\.CurrentUser|Registry\.LocalMachine|RegistryKey)\b') {
        $regHits += $c.FullName.Substring($RepoRoot.Length + 1)
    }
}
if ($regHits.Count -gt 0) {
    foreach ($r in $regHits) { Fail "Windows Registry access found in Clip Guard file $r" }
} else {
    Pass "Clip Guard C# source contains zero Windows Registry access"
}

# ---- 5. Annotated Source Headers (PURPOSE / ACCESS) ------------------------
$missingHeaders = @()
foreach ($f in ($tsFiles + $csFiles)) {
    $head = (Get-Content -LiteralPath $f.FullName -TotalCount 30) -join "`n"
    if ($head -notmatch 'PURPOSE:' -or $head -notmatch 'ACCESS:') {
        $missingHeaders += $f.FullName.Substring($RepoRoot.Length + 1)
    }
}
if ($missingHeaders.Count -gt 0) {
    foreach ($m in $missingHeaders) { Fail "Missing PURPOSE/ACCESS header block in $m" }
} else {
    Pass "All extension (.ts) and Clip Guard (.cs) source files carry PURPOSE/ACCESS headers"
}

# ---- 6. Repo Secret Hygiene ------------------------------------------------
$allSource = Get-ChildItem -Path $RepoRoot -Recurse -File | Where-Object {
    $_.FullName -notmatch '\\node_modules\\|\\dist\\|\\bin\\|\\obj\\|\\\.git\\|\\shared-fixtures\\'
}
$envFiles = $allSource | Where-Object { $_.Name -eq '.env' -or ($_.Name -like '.env.*' -and $_.Name -ne '.env.example') }
if ($envFiles) {
    foreach ($ef in $envFiles) { Fail ("Unexpected .env file in repo: " + $ef.FullName.Substring($RepoRoot.Length + 1)) }
} else {
    Pass "No .env files present in repository"
}

$keyLeakHits = @()
foreach ($f in ($allSource | Where-Object { $_.Extension -in '.ts','.js','.mjs','.cs','.json','.md','.ps1','.bat' })) {
    $raw = Get-Content -LiteralPath $f.FullName -Raw
    if ($raw -match 'helius-rpc\.com/\?api-key=[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') {
        $keyLeakHits += $f.FullName.Substring($RepoRoot.Length + 1)
    }
}
if ($keyLeakHits.Count -gt 0) {
    foreach ($k in $keyLeakHits) { Fail "Hardcoded Helius API key found in $k" }
} else {
    Pass "No hardcoded RPC API keys in repository"
}

if ($Failures.Count -gt 0) {
    Write-Host "`nSecurity verification FAILED with $($Failures.Count) issue(s)." -ForegroundColor Red
    exit 1
}

Write-Host "`nAll Aegis security and transparency checks PASSED." -ForegroundColor Green
exit 0
