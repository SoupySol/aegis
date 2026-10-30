<#
  AEGIS PHASE 0 - SPIKE 4: Windows clipboard history (Win+V) API access
  -------------------------------------------------------------------
  PURPOSE:  Confirm a normal (unpackaged) desktop process can reach the
            Windows clipboard history API.
  ACCESS:   Reads clipboard history METADATA only (status + item count + format list).
  NEVER:    Does NOT read, print, store, or transmit any clipboard text.
            No network access.
#>

$ErrorActionPreference = 'Stop'

# AEGIS-PERMISSION: registry read of the user's clipboard settings (no content)
$clipKey = 'HKCU:\Software\Microsoft\Clipboard'
$historyEnabled = $null
$cloudSync = $null
if (Test-Path $clipKey) {
    $props = Get-ItemProperty -Path $clipKey -ErrorAction SilentlyContinue
    $historyEnabled = $props.EnableClipboardHistory
    $cloudSync = $props.EnableCloudClipboard
}
Write-Output "Clipboard history setting (1=on, 0/empty=off): $historyEnabled"
Write-Output "Cloud clipboard sync setting (1=on, 0/empty=off): $cloudSync"

# Load WinRT types (works in Windows PowerShell 5.1)
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null = [Windows.ApplicationModel.DataTransfer.Clipboard, Windows.ApplicationModel.DataTransfer, ContentType = WindowsRuntime]

# Helper to await WinRT IAsyncOperation<T> from PowerShell
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
})[0]
function Await($op, [Type]$resultType) {
    $task = $asTaskGeneric.MakeGenericMethod($resultType).Invoke($null, @($op))
    $task.Wait(-1) | Out-Null
    $task.Result
}

Write-Output "IsHistoryEnabled (API): $([Windows.ApplicationModel.DataTransfer.Clipboard]::IsHistoryEnabled())"
Write-Output "IsRoamingEnabled (API): $([Windows.ApplicationModel.DataTransfer.Clipboard]::IsRoamingEnabled())"

$result = Await ([Windows.ApplicationModel.DataTransfer.Clipboard]::GetHistoryItemsAsync()) ([Windows.ApplicationModel.DataTransfer.ClipboardHistoryItemsResult])
Write-Output "GetHistoryItemsAsync status: $($result.Status)"
if ($result.Status -eq 'Success') {
    Write-Output "History item count: $($result.Items.Count)"
    # AEGIS-SECURITY: only the list of data FORMATS per item is printed, never the content.
    $i = 0
    foreach ($item in $result.Items) {
        $formats = ($item.Content.AvailableFormats | Select-Object -First 3) -join ', '
        Write-Output ("  item {0}: formats = {1}" -f $i, $formats)
        $i++
    }
}

