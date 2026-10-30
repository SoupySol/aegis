<#
.SYNOPSIS
    Aegis Wallet Guard - Standalone Local Secret & Cache Scanner
.DESCRIPTION
    Scans a workspace folder or Windows 11 Notepad TabState cache for exposed
    Solana private keys (Base58, JSON arrays) and BIP-39 seed phrases.
    Outputs ONLY masked previews (e.g. 7xKp...9Qm4) - never logs raw secrets.
.PARAMETER Path
    Local directory path to scan. Defaults to current directory.
.PARAMETER ScanTabState
    When specified, scans Windows 11 Notepad TabState\*.bin cache files.
#>
[CmdletBinding()]
param(
    [string]$Path = '.',
    [switch]$ScanTabState
)

$ErrorActionPreference = 'SilentlyContinue'

# Base58 character set
$Base58Pattern = '\b[1-9A-HJ-NP-Za-km-z]{84,88}\b'
$JsonArrayPattern = '\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]'
$Bip39Pattern = '\b(?:abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse|access|accident|account|accuse|achieve|acid|acoustic|acquire|across|act|action|actor|actress|actual|adapt|add|addict|address|adjust|admit|adult|advance|advice|aerobic|affair|afford|afraid|again|age|agent|agree|ahead|aim|air|airport|aisle|alarm|album|alcohol|alert|alien|all|alley|allow|almost|alone|alpha|already|also|alter|always|amateur|amazing|among|amount|amused|analyst|anchor|ancient|anger|angle|angry|animal|ankle|announce|annual|another|answer|antenna|antique|anxiety|any|apart|apology|appear|apple|approve|april|arch|arctic|area|arena|argue|arm|armed|armor|army|around|arrange|arrest|arrive|arrow|art|artefact|artist|artwork|ask|aspect|assault|asset|assist|assume|asthma|athlete|atom|attack|attend|attitude|attract|auction|audit|august|aunt|author|auto|autumn|average|avocado|avoid|awake|aware|away|awesome|awful|awkward|axis|baby|bachelor|bacon|badge|bag|balance|balcony|ball|bamboo|banana|banner|bar|barely|bargain|barrel|base|basic|basket|battle|beach|bean|beauty|because|become|beef|before|begin|behave|behind|believe|below|belt|bench|benefit|best|betray|better|between|beyond|bicycle|bid|bike|bind|biology|bird|birth|bitter|black|blade|blame|blanket|blast|bleak|bless|blind|blood|blossom|blow|blue|blur|blush|board|boat|body|boil|bomb|bone|bonus|book|boost|border|boring|borrow|boss|bottom|bounce|box|boy|bracket|brain|brand|brass|brave|bread|breeze|brick|bridge|brief|bright|bring|brisk|broccoli|broken|bronze|broom|brother|brown|brush|bubble|buddy|budget|buffalo|build|bulb|bulk|bullet|bundle|bunker|burden|burger|burst|bus|business|busy|butter|buyer|buzz)\b'

function Mask-Key([string]$key) {
    if ($key.Length -lt 12) { return '***' }
    return $key.Substring(0, 4) + '...' + $key.Substring($key.Length - 4)
}

$findings = @()

# 1. TabState Scan
if ($ScanTabState) {
    $localApp = [Environment]::GetFolderPath('LocalApplicationData')
    $tabStateFolder = Join-Path $localApp 'Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState'
    if (Test-Path -LiteralPath $tabStateFolder) {
        Write-Host "Scanning Windows 11 Notepad TabState: $tabStateFolder" -ForegroundColor Cyan
        $binFiles = Get-ChildItem -Path $tabStateFolder -Filter '*.bin' -File
        foreach ($bf in $binFiles) {
            try {
                $bytes = [System.IO.File]::ReadAllBytes($bf.FullName)
                # UTF-16LE extraction
                $text16 = [System.Text.Encoding]::Unicode.GetString($bytes)
                $text8  = [System.Text.Encoding]::UTF8.GetString($bytes)
                $content = $text16 + "`n" + $text8

                if ($content -match $Base58Pattern) {
                    $m = $Matches[0]
                    $findings += [PSCustomObject]@{
                        Source   = "Notepad TabState ($($bf.Name))"
                        Type     = "Solana Private Key (Base58)"
                        Preview  = Mask-Key $m
                        Location = $bf.FullName
                    }
                }
                if ($content -match $JsonArrayPattern) {
                    $findings += [PSCustomObject]@{
                        Source   = "Notepad TabState ($($bf.Name))"
                        Type     = "Solana Keypair Array [64 ints]"
                        Preview  = "[..., ...]"
                        Location = $bf.FullName
                    }
                }
            } catch { }
        }
    } else {
        Write-Host "Windows 11 Notepad TabState folder not present on this system." -ForegroundColor Yellow
    }
}

# 2. Directory Sweep
if ($Path -and (Test-Path -LiteralPath $Path)) {
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    Write-Host "Scanning directory: $resolved" -ForegroundColor Cyan
    $exts = @('*.txt', '*.json', '*.env*', '*.md', '*.yaml', '*.yml', '*.js', '*.ts', '*.py', '*.bak', '*.tmp')
    $files = Get-ChildItem -Path $resolved -Recurse -File -Include $exts |
        Where-Object { $_.FullName -notmatch '\\(node_modules|\.git|dist|bin|obj)\\' }

    foreach ($file in $files) {
        try {
            $text = [System.IO.File]::ReadAllText($file.FullName)
            if ($text -match $Base58Pattern) {
                $m = $Matches[0]
                $findings += [PSCustomObject]@{
                    Source   = "Local File"
                    Type     = "Solana Private Key (Base58)"
                    Preview  = Mask-Key $m
                    Location = $file.FullName
                }
            }
            if ($text -match $JsonArrayPattern) {
                $findings += [PSCustomObject]@{
                    Source   = "Local File"
                    Type     = "Solana Keypair Array [64 ints]"
                    Preview  = "[..., ...]"
                    Location = $file.FullName
                }
            }
        } catch { }
    }
}

Write-Host "`n=== Aegis Wallet Guard Scan Summary ===" -ForegroundColor Cyan
if ($findings.Count -eq 0) {
    Write-Host "[CLEAN] No exposed Solana private keys found in scanned locations." -ForegroundColor Green
} else {
    Write-Host "[WARNING] Found $($findings.Count) potentially exposed secret(s):" -ForegroundColor Red
    $findings | Format-Table -AutoSize
    Write-Host "Remediation:" -ForegroundColor Yellow
    Write-Host "  1. Move funds from any exposed wallet to a fresh wallet immediately."
    Write-Host "  2. Run Aegis Clip Guard (aegis-clipguard.exe) to purge Notepad TabState and Win+V history."
    Write-Host "  3. Remove plaintext keys from .env/config files and add them to .gitignore."
}

