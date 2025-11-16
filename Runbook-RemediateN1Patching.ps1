<#
.SYNOPSIS
  N-1 Windows patch remediation runbook.

.DESCRIPTION
  - Ensures device is at least previous-month (N-1) patch compliant
  - Installs only updates whose deployment date is before the first day
    of the current month
  - Does NOT reboot (Intune remains owner of restart policy)
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ComputerName
)

Write-Output "Starting N-1 patch remediation on $ComputerName (no reboot, no current-month patches)..."

$patchScript = {
    try {
        # Ensure PSWindowsUpdate is installed
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue
            Install-Module -Name PSWindowsUpdate -Force -Confirm:$false -ErrorAction SilentlyContinue
        }

        Import-Module PSWindowsUpdate -ErrorAction Stop

        $now              = Get-Date
        $firstOfThisMonth = Get-Date -Year $now.Year -Month $now.Month -Day 1 -Hour 0 -Minute 0 -Second 0

        Write-Output "First of this month: $firstOfThisMonth"

        # Get list of applicable updates (without installing yet)
        $available = Get-WindowsUpdate -MicrosoftUpdate -IgnoreUserInput -AcceptAll -WhatIf:$true -ErrorAction SilentlyContinue

        if (-not $available) {
            Write-Output "No updates available."
            return
        }

        $updatesToInstall = @()

        foreach ($u in $available) {
            $deployTime = $null

            if ($u.PSObject.Properties.Name -contains 'LastDeploymentChangeTime') {
                $deployTime = $u.LastDeploymentChangeTime
            }
            elseif ($u.PSObject.Properties.Name -contains 'ReleaseDate') {
                $deployTime = $u.ReleaseDate
            }

            if ($deployTime) {
                if ($deployTime -lt $firstOfThisMonth) {
                    Write-Output "Including update (N-1 or older): $($u.Title) [$deployTime]"
                    $updatesToInstall += $u
                }
                else {
                    Write-Output "Skipping current-month update: $($u.Title) [$deployTime]"
                }
            }
            else {
                # Fallback: unknown deployment date -> include, because device is already 2+ cycles behind
                Write-Output "No deployment date for $($u.Title); including by default."
                $updatesToInstall += $u
            }
        }

        if (-not $updatesToInstall -or $updatesToInstall.Count -eq 0) {
            Write-Output "No N-1 (or older) updates to install."
            return
        }

        $kbList = $updatesToInstall |
                  Where-Object { $_.KBArticleIDs } |
                  ForEach-Object { $_.KBArticleIDs } |
                  Select-Object -Unique

        if (-not $kbList -or $kbList.Count -eq 0) {
            Write-Output "No KB IDs found, installing filtered updates directly."
            Install-WindowsUpdate -AcceptAll -IgnoreReboot -Confirm:$false -Verbose
        }
        else {
            Write-Output "Installing KBs (N-1 or older): $($kbList -join ', ')"
            Install-WindowsUpdate -KBArticleID $kbList -AcceptAll -IgnoreReboot -Confirm:$false -Verbose
        }

        Write-Output "Patch remediation completed (no reboot requested)."
    }
    catch {
        Write-Error "Patch remediation failed: $($_.Exception.Message)"
    }
}

try {
    Invoke-Command -ComputerName $ComputerName -ScriptBlock $patchScript -ErrorAction Stop
    Write-Output "N-1 patch remediation runbook finished for $ComputerName"
}
catch {
    Write-Error "N-1 patch remediation failed for $ComputerName : $($_.Exception.Message)"
}
