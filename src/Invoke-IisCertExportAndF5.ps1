#requires -Version 5.1
<#
.SYNOPSIS
    Run the IIS CCS certificate export, then publish the exported PFX files to F5 BIG-IP.

.DESCRIPTION
    Export is nwlterry/iis_cert_automation IIS_Cert_Auto_Package\Export_Cert_CCS_Secure.ps1.
    F5 publish is Publish-PfxToF5.ps1 in this repository.

    Use this for a manual run or as the single scheduled-task action.
    If the existing CertificateExport task already runs the export, do not also point that
    task at this script. Register-F5CertPublishTask.ps1 listens for export success event 1065
    and runs Publish-PfxToF5.ps1 only. Pick one path so the PFX is not exported twice.

.PARAMETER SkipExport
    Publish the PFX files already in the CCS share. Do not call the export script.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$F5ConfigPath = $(Join-Path $PSScriptRoot 'f5-publish.config.json'),
    [string]$ExportScriptPath,
    [string]$CcsConfigPath,
    [switch]$SkipExport,
    [switch]$AllowUntrustedManagementCert,
    [switch]$AllowStandby,
    [switch]$AllowBashCleanup,
    [switch]$Rollback
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Security.Common.ps1')

Assert-SafeTaskPath $F5ConfigPath
if (-not $ExportScriptPath) {
    $sibling = Join-Path $PSScriptRoot 'Export_Cert_CCS_Secure.ps1'
    if (Test-Path -LiteralPath $sibling) {
        $ExportScriptPath = $sibling
    } else {
        $ExportScriptPath = 'C:\Scripts\Export_Cert_CCS_Secure.ps1'
    }
}
Assert-SafeTaskPath $ExportScriptPath

if (-not $CcsConfigPath) {
    $f5Config = Import-AutomationConfig -ConfigPath $F5ConfigPath
    if ($f5Config.ccsConfigPath) { $CcsConfigPath = [string]$f5Config.ccsConfigPath }
}
if (-not $CcsConfigPath) {
    $CcsConfigPath = 'C:\Scripts\iis-cert-automation.config.json'
}
Assert-SafeTaskPath $CcsConfigPath

if (-not $SkipExport -and -not $Rollback) {
    if ($WhatIfPreference) {
        Write-Output "WhatIf: not running $ExportScriptPath. F5 plan uses the PFX already in the CCS share."
    } else {
        if (-not (Test-Path -LiteralPath $ExportScriptPath)) {
            throw "Export script not found: $ExportScriptPath. Copy it from https://github.com/nwlterry/iis_cert_automation"
        }
        Write-Output "Running certificate export: $ExportScriptPath"
        try {
            & $ExportScriptPath -ConfigPath $CcsConfigPath
        } catch {
            Write-Output "Certificate export failed: $($_.Exception.Message)"
            exit 1
        }
    }
}

$publish = Join-Path $PSScriptRoot 'Publish-PfxToF5.ps1'
$params = @{
    ConfigPath = $F5ConfigPath
    StartupDelaySeconds = 0
}
if ($AllowUntrustedManagementCert) { $params.AllowUntrustedManagementCert = $true }
if ($AllowStandby) { $params.AllowStandby = $true }
if ($AllowBashCleanup) { $params.AllowBashCleanup = $true }
if ($Rollback) { $params.Rollback = $true }

& $publish @params -WhatIf:$WhatIfPreference
if ($null -eq $global:F5PublishExitCode) { exit 2 }
exit ([int]$global:F5PublishExitCode)
