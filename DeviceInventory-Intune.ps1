<#
.SYNOPSIS
  Device inventory + compliance telemetry to Log Analytics.

.DEPLOYMENT
  - Deploy via Intune (Script / Proactive remediation / Win32)
  - Schedule every 6–24 hours
  - Map to a DCR that writes into DeviceInventory_CL
#>

# ================== CONFIGURATION ==================
# TODO: Replace with your workspace details
$CustomerId = "<YOUR-LAWORKSPACE-ID>"          # Workspace ID (GUID)
$SharedKey  = "<YOUR-LAWORKSPACE-PRIMARY-KEY>" # Workspace Primary Key
$LogType    = "DeviceInventory"
$TimeGeneratedField = "TimeGenerated"

# ================== SIGNATURE FUNCTION ==================
function Build-Signature {
    param(
        [string]$CustomerId,
        [string]$SharedKey,
        [string]$Date,
        [int]$ContentLength,
        [string]$Method = "POST",
        [string]$ContentType = "application/json",
        [string]$Resource = "/api/logs"
    )

    $xHeaders = "x-ms-date:" + $Date
    $stringToSign = $Method + "`n" + $ContentLength + "`n" + $ContentType + "`n" + $xHeaders + "`n" + $Resource

    $bytesToSign = [Text.Encoding]::UTF8.GetBytes($stringToSign)
    $keyBytes    = [Convert]::FromBase64String($SharedKey)

    $hmacSha256        = [System.Security.Cryptography.HMACSHA256]::new()
    $hmacSha256.Key    = $keyBytes
    $hash              = $hmacSha256.ComputeHash($bytesToSign)
    $encodedHash       = [Convert]::ToBase64String($hash)

    $signature = "SharedKey ${CustomerId}:${encodedHash}"
    return $signature
}

# ================== HELPER: PENDING REBOOT ==================
function Test-PendingReboot {
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    )

    foreach ($p in $paths) {
        if (Test-Path $p) {
            if ($p -like "*Session Manager") {
                $val = (Get-ItemProperty -Path $p -ErrorAction SilentlyContinue).PendingFileRenameOperations
                if ($val) { return $true }
            }
            else {
                return $true
            }
        }
    }
    return $false
}

# ================== COLLECT SYSTEM INFO ==================
$deviceName = $env:COMPUTERNAME
$serial     = (Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue).SerialNumber
$os         = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$osVersion  = $os.Caption
$osBuild    = $os.BuildNumber
$now        = (Get-Date).ToUniversalTime().ToString("o")

# ---- Patch / Windows Update status & N-1 compliance ----
$lastPatchDate         = $null
$patchesThisMonthCnt   = 0
$isPatchedThisMonth    = $false
$isPrevMonthCompliant  = $false   # OK if last patch >= first of previous month
$needsPatchRemediation = $false   # Last patch < first of previous month

try {
    $hotfixes = Get-HotFix -ErrorAction Stop
    if ($hotfixes) {
        $latest        = $hotfixes | Sort-Object InstalledOn -Descending | Select-Object -First 1
        $lastPatchDate = $latest.InstalledOn

        $today            = Get-Date
        $firstOfThisMonth = Get-Date -Year $today.Year -Month $today.Month -Day 1 -Hour 0 -Minute 0 -Second 0
        $firstOfPrevMonth = $firstOfThisMonth.AddMonths(-1)

        $patchesThisMonth = $hotfixes | Where-Object {
            $_.InstalledOn -ge $firstOfThisMonth -and $_.InstalledOn -lt $firstOfThisMonth.AddMonths(1)
        }
        $patchesThisMonthCnt = $patchesThisMonth.Count
        $isPatchedThisMonth  = $patchesThisMonthCnt -gt 0

        if ($lastPatchDate) {
            if ($lastPatchDate -ge $firstOfPrevMonth) {
                $isPrevMonthCompliant  = $true
                $needsPatchRemediation = $false
            }
            else {
                $isPrevMonthCompliant  = $false
                $needsPatchRemediation = $true
            }
        }
    }
}
catch {
    Write-Host "Could not read hotfix info: $($_.Exception.Message)"
}

# ---- Defender / basic vulnerability signals ----
$defenderEnabled           = $null
$defenderSigAgeDays        = $null
$realTimeProtectionEnabled = $null

try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $defenderEnabled           = $mp.AMServiceEnabled -and $mp.AntivirusEnabled
    $defenderSigAgeDays        = $mp.AntivirusSignatureAge
    $realTimeProtectionEnabled = $mp.RealTimeProtectionEnabled
}
catch {
    Write-Host "Could not read Defender status."
}

$pendingReboot = Test-PendingReboot

# ---- Disk info (one record per drive) ----
$drives  = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue
$records = @()

foreach ($d in $drives) {
    $sizeGB = if ($d.Size)      { [Math]::Round($d.Size / 1GB, 2) } else { 0 }
    $freeGB = if ($d.FreeSpace) { [Math]::Round($d.FreeSpace / 1GB, 2) } else { 0 }
    $freePct = if ($d.Size -and $d.Size -ne 0) {
        [Math]::Round(($d.FreeSpace / $d.Size) * 100, 2)
    } else { 0 }

    $isLowDiskSpace   = $freeGB -lt 10
    $needsDiskCleanup = $isLowDiskSpace

    $records += [PSCustomObject]@{
        TimeGenerated               = $now
        DeviceName                  = $deviceName
        SerialNumber                = $serial
        OSVersion                   = $osVersion
        OSBuild                     = $osBuild

        DriveLetter                 = $d.DeviceID
        TotalSizeGB                 = $sizeGB
        FreeSpaceGB                 = $freeGB
        FreeSpacePct                = $freePct
        IsLowDiskSpace              = $isLowDiskSpace
        NeedsDiskCleanup            = $needsDiskCleanup

        LastPatchInstalledOn        = $lastPatchDate
        PatchesInstalledThisMonth   = $patchesThisMonthCnt
        IsPatchedThisMonth          = $isPatchedThisMonth
        IsPrevMonthCompliant        = $isPrevMonthCompliant
        NeedsPatchRemediation       = $needsPatchRemediation

        PendingReboot               = $pendingReboot

        DefenderEnabled             = $defenderEnabled
        RealTimeProtectionEnabled   = $realTimeProtectionEnabled
        DefenderSignatureAgeDays    = $defenderSigAgeDays
    }
}

if (-not $records -or $records.Count -eq 0) {
    Write-Host "No disk records found, nothing to send."
    exit 0
}

$json = $records | ConvertTo-Json -Depth 5

# ================== SEND TO LOG ANALYTICS ==================
$method        = "POST"
$contentType   = "application/json"
$resource      = "/api/logs"
$date          = [DateTime]::UtcNow.ToString("r")
$bodyBytes     = [System.Text.Encoding]::UTF8.GetBytes($json)
$contentLength = $bodyBytes.Length

$signature = Build-Signature -CustomerId $CustomerId `
                             -SharedKey $SharedKey `
                             -Date $date `
                             -ContentLength $contentLength `
                             -Method $method `
                             -ContentType $contentType `
                             -Resource $resource

$uri = "https://$CustomerId.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

$headers = @{
    "Authorization"        = $signature
    "Log-Type"             = $LogType
    "x-ms-date"            = $date
    "time-generated-field" = $TimeGeneratedField
}

try {
    Invoke-RestMethod -Method $method -Uri $uri -Headers $headers -Body $json -ContentType $contentType
    Write-Host "SUCCESS: Sent $($records.Count) device inventory records to Log Analytics."
}
catch {
    Write-Host "ERROR sending data to Log Analytics:"
    Write-Host $_.Exception.Message
}
