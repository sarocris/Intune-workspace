<#
.SYNOPSIS
  Low disk space remediation runbook.

.NOTES
  - Designed to be triggered from a Logic App with ComputerName
  - Runs cleanup script on target via WinRM
  - Does NOT reboot the device
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ComputerName
)

Write-Output "Starting low disk remediation on $ComputerName ..."

$cleanupScript = {
    Write-Output "Running low disk cleanup locally on $env:COMPUTERNAME"

    $pathsToClean = @(
        "$env:TEMP\*",
        "C:\Windows\Temp\*",
        "C:\Windows\SoftwareDistribution\Download\*"
    )

    foreach ($path in $pathsToClean) {
        try {
            Write-Output "Cleaning $path"
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning "Failed to clean $path : $($_.Exception.Message)"
        }
    }

    # Optional: empty recycle bin
    try {
        Write-Output "Emptying recycle bin"
        (New-Object -ComObject Shell.Application).NameSpace(0xA).Items() |
            ForEach-Object { $_.InvokeVerb("delete") }
    }
    catch {
        Write-Warning "Failed to clear recycle bin: $($_.Exception.Message)"
    }

    Write-Output "Low disk remediation completed (no reboot requested)."
}

try {
    # If the Hybrid Runbook Worker is installed on the device itself,
    # you can simply call: & $cleanupScript
    Invoke-Command -ComputerName $ComputerName -ScriptBlock $cleanupScript -ErrorAction Stop
    Write-Output "Low disk remediation runbook finished for $ComputerName"
}
catch {
    Write-Error "Low disk remediation failed for $ComputerName : $($_.Exception.Message)"
}
