#requires -Version 5.1
<#
.SYNOPSIS
    Store the F5 iControl account in the machine Credential Manager vault.

.DESCRIPTION
    Run once, on the IIS node that will publish certificates, from an elevated interactive session.
    The password is typed. It is not a script parameter, so it is not stored in Task Scheduler history
    or in a shell transcript of the command line.

    Persistence is LocalMachine so NT AUTHORITY\SYSTEM can read target F5-iControl.
    The PFX password remains the existing target PFXCertPassword. This script does not change it.

.PARAMETER Target
    Credential Manager target name. Must match f5.credentialTarget. Default F5-iControl.

.PARAMETER UserName
    BIG-IP local user. Prompted when omitted. Use a dedicated account, not the default admin password in a ticket.
#>
[CmdletBinding()]
param(
    [string]$Target = 'F5-iControl',
    [string]$UserName
)

$ErrorActionPreference = 'Stop'
if (-not [Environment]::UserInteractive) {
    throw "Run this interactively. Do not pass the F5 password on the command line or via a scheduled task."
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run elevated. LocalMachine credentials are stored for NT AUTHORITY\SYSTEM."
}
if ($Target -notmatch '^[A-Za-z0-9._-]{1,64}$') {
    throw "Refusing unsafe Credential Manager target name."
}
if (-not (Get-Module -ListAvailable -Name CredentialManager)) {
    throw "CredentialManager module not found. Use credentialmanager.2.0.0.nupkg from iis_cert_automation."
}
Import-Module CredentialManager -ErrorAction Stop

if (-not $UserName) {
    $UserName = Read-Host 'F5 user name'
}
if ($UserName -notmatch '^[A-Za-z0-9._\\@-]{1,128}$') {
    throw "Refusing unsafe F5 user name."
}
$secure = Read-Host 'F5 password' -AsSecureString
if (-not $secure -or $secure.Length -lt 1) {
    throw "Empty password was not stored."
}
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
$plain = $null
try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    if (Get-Command Remove-StoredCredential -ErrorAction SilentlyContinue) {
        Remove-StoredCredential -Target $Target -ErrorAction SilentlyContinue
    }
    $command = Get-Command New-StoredCredential -ErrorAction Stop
    $splat = @{
        Target = $Target
        UserName = $UserName
        Password = $plain
        Persist = 'LocalMachine'
        Type = 'Generic'
    }
    if ($command.Parameters.ContainsKey('Update')) {
        $splat.Update = $true
    }
    New-StoredCredential @splat | Out-Null
} finally {
    if ($pointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
    $plain = $null
    $secure.Dispose()
}

$check = Get-StoredCredential -Target $Target -ErrorAction Stop
if (-not $check -or $check.UserName -ne $UserName) {
    throw "Credential Manager did not return target $Target after saving it."
}
Write-Output "Stored target $Target for user $UserName in the LocalMachine vault. The password was not written here."
Write-Output "Confirm SYSTEM can read it with the same test pattern as Setup_CCS_and_Task.ps1 before enabling the F5 task."
