# Shared path, config, and package-integrity checks for IIS cert automation.
# Passwords must never be written to this file, to config JSON, or to logs.
# Upstream functions are unchanged from nwlterry/iis_cert_automation so Export_Cert_CCS_Secure.ps1 can dot-source this copy.
# F5 name checks are appended below.


function Test-IsSafeTaskPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Length -gt 240) { return $false }
    if ($Path -match '[''"`$;&|<>\r\n\x00]') { return $false }
    return $Path -match '^(?:[A-Za-z]:\\(?:[^\\/:*?"<>|]+\\)*[^\\/:*?"<>|]+|\\\\[^\\/:*?"<>|]+\\[^\\/:*?"<>|]+(?:\\[^\\/:*?"<>|]+)*)$'
}

function Assert-SafeTaskPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-IsSafeTaskPath $Path)) {
        throw "Refusing unsafe path. Use a drive path or UNC path with no quotes or shell metacharacters."
    }
}

function Assert-SafeHostName {
    param([Parameter(Mandatory = $true)][string]$Name)
    if ($Name -notmatch '^[A-Za-z0-9.-]{1,253}$') {
        throw "Refusing unsafe host name."
    }
}

function Set-TightFileAcl {
    param([Parameter(Mandatory = $true)][string]$Path)
    & icacls.exe $Path /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(F)" "BUILTIN\Administrators:(F)" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to restrict ACL. Secret material was not left world-readable on purpose; stopping."
    }
}

function Assert-NupkgSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedHex
    )
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash
    if ($actual.ToLowerInvariant() -ne $ExpectedHex.ToLowerInvariant()) {
        throw "Package hash mismatch. Refusing to install an unexpected CredentialManager nupkg."
    }
}

function Import-AutomationConfig {
    param([Parameter(Mandatory = $true)][string]$ConfigPath)
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "Missing config file: $ConfigPath. Copy config.example.json and fill in site values. Do not put a PFX password in the config file."
    }
    $raw = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop
    if ($raw -match '(?i)"\s*(pfxPassword|password|passwd|secret|privateKey)\s*"') {
        throw "Config file must not contain a password field. Store the PFX password only in Credential Manager."
    }
    return ($raw | ConvertFrom-Json)
}

function Get-EphemeralKeyStorageFlag {
    $enum = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]
    if (-not [enum]::IsDefined($enum, 'EphemeralKeySet')) {
        throw "EphemeralKeySet is not available. Refusing to import a PFX into a persisted key set."
    }
    return [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
}


function Assert-SafeF5Name {
    param([Parameter(Mandatory = $true)][string]$Name)
    # BIG-IP object names used in iControl paths. No slashes, tildes, or shell characters.
    if ($Name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
        throw "Refusing unsafe F5 object name '$Name'."
    }
}

function Assert-SafeManagementHost {
    param([Parameter(Mandatory = $true)][string]$Name)
    $ipv4 = '^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$'
    if ($Name -match $ipv4) { return }
    Assert-SafeHostName $Name
}
