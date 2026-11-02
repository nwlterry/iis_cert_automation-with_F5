#requires -Version 5.1
<#
.SYNOPSIS
    Register a SYSTEM task that publishes to F5 after a successful CCS export.

.DESCRIPTION
    Trigger: Application log, source CertificateExport, event 1065
    (Export_Cert_CCS_Secure.ps1 finished with at least one PFX written).

    Action: Publish-PfxToF5.ps1 only. The export task is not modified.
    Register this on exactly one IIS node. Every node that exports would otherwise
    race to update the same virtual server.

    Do not also schedule Invoke-IisCertExportAndF5.ps1 on a renewal trigger, or the
    certificate will be exported twice and this event task will publish twice.
    The second publish is idempotent, but the extra export is unnecessary.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$TaskName = 'IIS-Cert-F5-Publish',
    [string]$PublishScriptPath = $(Join-Path $PSScriptRoot 'Publish-PfxToF5.ps1'),
    [string]$ConfigPath = $(Join-Path $PSScriptRoot 'f5-publish.config.json'),
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Security.Common.ps1')

if ($TaskName -notmatch '^[A-Za-z0-9._-]{1,64}$') {
    throw "Refusing unsafe task name."
}
Assert-SafeTaskPath $PublishScriptPath
Assert-SafeTaskPath $ConfigPath
if (-not (Test-Path -LiteralPath $PublishScriptPath)) {
    throw "Publish script not found: $PublishScriptPath"
}
if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "F5 config not found: $ConfigPath. Copy examples\f5-publish.config.example.json and fill it in. Do not put a password in it."
}

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing -and -not $Force) {
    throw "Scheduled task $TaskName already exists. Pass -Force to replace it."
}

$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
Assert-SafeTaskPath $powershell
$argument = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$PublishScriptPath`" -ConfigPath `"$ConfigPath`""
$action = New-ScheduledTaskAction -Execute $powershell -Argument $argument

$query = @'
<QueryList>
  <Query Id="0" Path="Application">
    <Select Path="Application">*[System[Provider[@Name='CertificateExport'] and (EventID=1065)]]</Select>
  </Query>
</QueryList>
'@
$triggerClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace 'Root/Microsoft/Windows/TaskScheduler'
$trigger = New-CimInstance -CimClass $triggerClass -ClientOnly
$trigger.Enabled = $true
$trigger.Subscription = $query

$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

if (-not $PSCmdlet.ShouldProcess($TaskName, 'Register SYSTEM task on CertificateExport event 1065')) {
    Write-Output "WhatIf: would register $TaskName"
    Write-Output $argument
    return
}
if ($existing) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'After IIS CCS export event 1065, push the PFX to F5 and rebind client-ssl profiles.' | Out-Null
Write-Output "Registered $TaskName as NT AUTHORITY\SYSTEM."
Write-Output "Trigger: CertificateExport event 1065. Action: $PublishScriptPath"
Write-Output "Enable this task on one IIS node only."
