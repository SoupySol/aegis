# ---------------------------------------------------------------------------
# check-no-network.ps1
# Verifies that no C# source file under clipguard-helper/src/ references any
# networking APIs, sockets, HTTP clients, or http(s) URLs.
# Exits 0 when clean, 1 if any forbidden pattern is found.
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'

$srcRoot = Join-Path $PSScriptRoot '..\src'
if (-not (Test-Path -LiteralPath $srcRoot)) {
    Write-Error "Source directory not found: $srcRoot"
    exit 1
}

$files = @(Get-ChildItem -LiteralPath $srcRoot -Filter '*.cs' -Recurse -File)
if ($files.Count -eq 0) {
    Write-Error "No .cs files found under $srcRoot"
    exit 1
}

$patterns = @(
    @{ Name = 'System.Net';  Regex = '\bSystem\.Net\b' },
    @{ Name = 'Sockets';     Regex = '\bSockets\b' },
    @{ Name = 'WebClient';   Regex = '\bWebClient\b' },
    @{ Name = 'HttpClient';  Regex = '\bHttpClient\b' },
    @{ Name = 'WebRequest';  Regex = '\bWebRequest\b' },
    @{ Name = 'WinHttp';     Regex = '\bWinHttp\b' },
    @{ Name = 'UrlMon';      Regex = '\bUrlMon\b' },
    @{ Name = 'http(s) URL'; Regex = 'https?://' }
)

$violations = New-Object System.Collections.Generic.List[string]

foreach ($f in $files) {
    $lines = [System.IO.File]::ReadAllLines($f.FullName)
    for ($i = 0; $i -lt $lines.Length; $i++) {
        $line = $lines[$i]
        foreach ($p in $patterns) {
            if ($line -match $p.Regex) {
                $rel = $f.FullName.Substring((Resolve-Path $srcRoot).Path.Length).TrimStart('\', '/')
                $violations.Add(("src/{0}:{1} matched [{2}]: {3}" -f $rel, ($i + 1), $p.Name, $line.Trim()))
            }
        }
    }
}

if ($violations.Count -gt 0) {
    Write-Host "FAIL: Forbidden network-related token(s) found in Clip Guard source:" -ForegroundColor Red
    foreach ($v in $violations) {
        Write-Host ("  " + $v) -ForegroundColor Red
    }
    exit 1
}

Write-Host ("no-network check: {0} source files clean" -f $files.Count)
exit 0
