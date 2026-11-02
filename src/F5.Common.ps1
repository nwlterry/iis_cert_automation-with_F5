# iControl REST helpers for publishing an IIS CCS PFX to F5 BIG-IP.
# The PFX password and the F5 password are never written to logs, events, or config.
# Designed for Windows PowerShell 5.1.

$script:F5Secrets = @()
$script:F5Token = $null
$script:F5BaseUri = $null
$script:F5Tx = $null
$script:F5LogPath = $null
$script:F5EventSource = 'F5CertPublish'
$script:F5EventLog = 'Application'
$script:StagedPfxDeleteFailed = $false

function Protect-LogText {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    foreach ($secret in @($script:F5Secrets)) {
        if ($secret -and $secret.Length -ge 1) {
            $Text = $Text.Replace([string]$secret, '***')
        }
    }
    $Text = [regex]::Replace($Text, '(?i)("passphrase"\s*:\s*")[^"]*(")', '$1***$2')
    $Text = [regex]::Replace($Text, '(?i)("password"\s*:\s*")[^"]*(")', '$1***$2')
    $Text = [regex]::Replace($Text, '(?i)(X-F5-Auth-Token["\s:=]+)[A-Za-z0-9+/=_-]{8,}', '${1}***')
    return $Text
}

function Write-F5Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$Level = 'INFO',
        [int]$EventId = 2100
    )
    $safe = Protect-LogText $Message
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$timestamp] [$Level] $safe"
    if ($script:F5LogPath) {
        for ($i = 0; $i -lt 3; $i++) {
            try {
                Add-Content -LiteralPath $script:F5LogPath -Value $line -ErrorAction Stop
                break
            } catch {
                if ($i -eq 2) { Write-Output "Failed to write log file: $(Protect-LogText $_.Exception.Message)" }
                else { Start-Sleep -Milliseconds 300 }
            }
        }
    }
    try {
        $eventType = switch ($Level) {
            'ERROR' { [System.Diagnostics.EventLogEntryType]::Error }
            'WARNING' { [System.Diagnostics.EventLogEntryType]::Warning }
            default { [System.Diagnostics.EventLogEntryType]::Information }
        }
        if ([System.Diagnostics.EventLog]::SourceExists($script:F5EventSource)) {
            Write-EventLog -LogName $script:F5EventLog -Source $script:F5EventSource -EventId $EventId -EntryType $eventType -Message $line -ErrorAction Stop
        }
    } catch {
        Write-Output "Failed to write event log: $(Protect-LogText $_.Exception.Message)"
    }
    Write-Output $line
}

function Initialize-F5Logging {
    param(
        [Parameter(Mandatory = $true)][string]$LogDirectory,
        [int]$MaxFiles = 5
    )
    Assert-SafeTaskPath $LogDirectory
    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    }
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($script:F5EventSource)) {
            New-EventLog -LogName $script:F5EventLog -Source $script:F5EventSource -ErrorAction Stop
        }
    } catch {
        Write-Output "Event source $($script:F5EventSource) was not created: $(Protect-LogText $_.Exception.Message)"
    }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $script:F5LogPath = Join-Path $LogDirectory "F5CertPublish_$stamp.log"
    $logs = @(Get-ChildItem -LiteralPath $LogDirectory -Filter 'F5CertPublish_*.log' -ErrorAction SilentlyContinue | Sort-Object CreationTime -Descending)
    if ($logs.Count -gt $MaxFiles) {
        foreach ($old in ($logs | Select-Object -Skip $MaxFiles)) {
            Remove-Item -LiteralPath $old.FullName -Force -ErrorAction SilentlyContinue
        }
    }
}

function Import-CredentialManagerModule {
    if (-not (Get-Module -ListAvailable -Name CredentialManager)) {
        throw "CredentialManager module not found. Install the air-gapped module from iis_cert_automation (credentialmanager.2.0.0.nupkg) under WindowsPowerShell\Modules."
    }
    Import-Module CredentialManager -ErrorAction Stop
}

function Get-StoredTargetPassword {
    param(
        [Parameter(Mandatory = $true)][string]$Target,
        [string]$Purpose = 'secret'
    )
    if ($Target -notmatch '^[A-Za-z0-9._-]{1,64}$') {
        throw "Refusing unsafe Credential Manager target name."
    }
    Import-CredentialManagerModule
    $credential = Get-StoredCredential -Target $Target -ErrorAction Stop
    if (-not $credential) {
        throw "No Credential Manager secret for target $Target ($Purpose)."
    }
    $password = $credential.GetNetworkCredential().Password
    if (-not $password) {
        throw "Credential Manager target $Target ($Purpose) is empty."
    }
    if (@($script:F5Secrets) -notcontains $password) {
        $script:F5Secrets += $password
    }
    return @{
        UserName = [string]$credential.UserName
        Password = $password
    }
}

function Enable-F5Tls {
    param(
        [string]$PinnedCertSha256,
        [switch]$AllowUntrusted
    )
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    [System.Net.ServicePointManager]::Expect100Continue = $false
    if ($AllowUntrusted) {
        Write-F5Log -Message 'TLS certificate validation is DISABLED for this process. Lab use only.' -Level 'WARNING' -EventId 2192
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        return
    }
    if ($PinnedCertSha256) {
        $expected = ($PinnedCertSha256 -replace '\s', '').ToUpperInvariant()
        if ($expected -notmatch '^[0-9A-F]{64}$') {
            throw "managementCertSha256 must be 64 hex characters."
        }
        $script:F5PinSha256 = $expected
        Write-F5Log -Message "TLS is pinned to management certificate SHA256 $expected." -Level 'INFO' -EventId 2110
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
            param($sender, $certificate, $chain, $sslPolicyErrors)
            if (-not $certificate) { return $false }
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try {
                $hash = $sha.ComputeHash($certificate.GetRawCertData())
            } finally {
                $sha.Dispose()
            }
            $actual = ([System.BitConverter]::ToString($hash)).Replace('-', '')
            return ($actual -eq $script:F5PinSha256)
        }
    }
}

function ConvertTo-F5Json {
    param($Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) {
        if ($Value) { return 'true' }
        return 'false'
    }
    if ($Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64] -or $Value -is [decimal] -or $Value -is [single] -or $Value -is [double]) {
        return ([string]([System.Convert]::ToString($Value, [System.Globalization.CultureInfo]::InvariantCulture)))
    }
    if ($Value -is [string]) {
        $escaped = $Value.Replace('\', '\\').Replace('"', '\"').Replace("`r", '\r').Replace("`n", '\n').Replace("`t", '\t')
        return '"' + $escaped + '"'
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $pairs = New-Object System.Collections.Generic.List[string]
        foreach ($key in @($Value.Keys)) {
            $pairs.Add((ConvertTo-F5Json ([string]$key)) + ':' + (ConvertTo-F5Json $Value[$key]))
        }
        return '{' + ($pairs -join ',') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = New-Object System.Collections.Generic.List[string]
        foreach ($item in $Value) {
            $items.Add((ConvertTo-F5Json $item))
        }
        return '[' + ($items -join ',') + ']'
    }
    throw "Unsupported JSON value type $($Value.GetType().FullName)."
}

function Invoke-F5Http {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Uri,
        [byte[]]$BodyBytes,
        [string]$ContentType,
        [hashtable]$ExtraHeaders,
        [int]$TimeoutSec = 120
    )
    $request = [System.Net.HttpWebRequest]::Create($Uri)
    $request.Method = $Method
    $request.Timeout = $TimeoutSec * 1000
    $request.ReadWriteTimeout = $TimeoutSec * 1000
    $request.AllowAutoRedirect = $false
    $request.UserAgent = 'iis-cert-automation-f5/1.0'
    $request.KeepAlive = $false
    if ($script:F5Token) {
        $request.Headers.Add('X-F5-Auth-Token', [string]$script:F5Token)
    }
    if ($script:F5Tx) {
        $request.Headers.Add('X-F5-REST-Coordination-Id', [string]$script:F5Tx)
    }
    if ($ExtraHeaders) {
        foreach ($name in @($ExtraHeaders.Keys)) {
            $request.Headers[[string]$name] = [string]$ExtraHeaders[$name]
        }
    }
    if ($BodyBytes -and $BodyBytes.Length -gt 0) {
        if ($ContentType) { $request.ContentType = $ContentType }
        $request.ContentLength = $BodyBytes.Length
        $stream = $request.GetRequestStream()
        try {
            $stream.Write($BodyBytes, 0, $BodyBytes.Length)
        } finally {
            $stream.Dispose()
        }
    } elseif ($Method -eq 'POST' -or $Method -eq 'PATCH' -or $Method -eq 'PUT') {
        $request.ContentLength = 0
    }

    $response = $null
    try {
        $response = $request.GetResponse()
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        try {
            $text = $reader.ReadToEnd()
        } finally {
            $reader.Dispose()
        }
        return @{
            StatusCode = [int]$response.StatusCode
            Body = $text
        }
    } catch [System.Net.WebException] {
        $httpResponse = $_.Exception.Response
        $detail = $_.Exception.Message
        $status = 0
        if ($httpResponse) {
            $status = [int]$httpResponse.StatusCode
            try {
                $reader = New-Object System.IO.StreamReader($httpResponse.GetResponseStream())
                try { $detail = $reader.ReadToEnd() } finally { $reader.Dispose() }
            } catch {
                $detail = $_.Exception.Message
            }
        }
        $safeDetail = Protect-LogText $detail
        throw "HTTP $status $Method $Uri failed. $safeDetail"
    } finally {
        if ($response) { $response.Dispose() }
    }
}

function Invoke-F5Api {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')][string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        $Body = $null,
        [hashtable]$ExtraHeaders,
        [int]$TimeoutSec = 120
    )
    if ($Path -notmatch '^/mgmt/') {
        throw "Refusing F5 path outside /mgmt/."
    }
    $uri = $script:F5BaseUri + $Path
    $bytes = $null
    $contentType = $null
    if ($null -ne $Body) {
        $json = ConvertTo-F5Json $Body
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $contentType = 'application/json; charset=utf-8'
    }
    $result = Invoke-F5Http -Method $Method -Uri $uri -BodyBytes $bytes -ContentType $contentType -ExtraHeaders $ExtraHeaders -TimeoutSec $TimeoutSec
    if ([string]::IsNullOrWhiteSpace($result.Body)) { return $null }
    try {
        return ($result.Body | ConvertFrom-Json)
    } catch {
        throw "F5 returned non-JSON for $Method $Path. $(Protect-LogText $result.Body)"
    }
}

function Test-F5ObjectExists {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        Invoke-F5Api -Method GET -Path $Path | Out-Null
        return $true
    } catch {
        if ($_.Exception.Message -match 'HTTP 404') { return $false }
        throw
    }
}

function Connect-F5Session {
    param(
        [Parameter(Mandatory = $true)][string]$ManagementHost,
        [int]$Port = 443,
        [string]$LoginProviderName = 'tmos',
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)][string]$Password
    )
    Assert-SafeManagementHost $ManagementHost
    if ($Port -lt 1 -or $Port -gt 65535) { throw "Refusing management port $Port." }
    if ($LoginProviderName -notmatch '^[A-Za-z0-9._-]{1,64}$') {
        throw "Refusing unsafe loginProviderName."
    }
    $script:F5BaseUri = "https://${ManagementHost}:$Port"
    $script:F5Token = $null
    $body = @{
        username = $UserName
        password = $Password
        loginProviderName = $LoginProviderName
    }
    $result = Invoke-F5Api -Method POST -Path '/mgmt/shared/authn/login' -Body $body -TimeoutSec 60
    $token = $null
    if ($result -and $result.token -and $result.token.token) {
        $token = [string]$result.token.token
    }
    if (-not $token) {
        throw "F5 login did not return a token. Check the account, loginProviderName, and that iControl REST is enabled."
    }
    $script:F5Token = $token
    if (@($script:F5Secrets) -notcontains $token) {
        $script:F5Secrets += $token
    }
    Write-F5Log -Message "Authenticated to $ManagementHost as $UserName with an iControl token. Token value was not logged." -Level 'INFO' -EventId 2110
}

function Disconnect-F5Session {
    if (-not $script:F5Token) { return }
    try {
        Invoke-F5Api -Method DELETE -Path '/mgmt/shared/authz/tokens/current' -TimeoutSec 30 | Out-Null
        Write-F5Log -Message 'F5 auth token revoked.' -Level 'INFO' -EventId 2112
    } catch {
        Write-F5Log -Message "Failed to revoke F5 auth token: $($_.Exception.Message)" -Level 'WARNING' -EventId 2112
    } finally {
        $script:F5Token = $null
    }
}

function Test-F5DeviceIsActive {
    try {
        $devices = Invoke-F5Api -Method GET -Path '/mgmt/tm/cm/device'
    } catch {
        if ($_.Exception.Message -match 'HTTP 404') {
            Write-F5Log -Message 'No device-trust endpoint. Treating this BIG-IP as standalone.' -Level 'WARNING' -EventId 2120
            return $true
        }
        throw
    }
    $self = $null
    foreach ($item in @($devices.items)) {
        if ([string]$item.selfDevice -eq 'true') { $self = $item; break }
    }
    if (-not $self) {
        Write-F5Log -Message 'Could not identify the self device. Refusing to change a device that may be standby.' -Level 'ERROR' -EventId 2121
        return $false
    }
    $state = [string]$self.failoverState
    Write-F5Log -Message "Self device $($self.name) failoverState=$state." -Level 'INFO' -EventId 2120
    return ($state -eq 'active' -or $state -eq 'standalone')
}

function Send-F5File {
    param(
        [Parameter(Mandatory = $true)][string]$LocalPath,
        [Parameter(Mandatory = $true)][string]$RemoteFileName,
        [int]$ChunkSize = 524288,
        [int]$TimeoutSec = 180
    )
    if ($RemoteFileName -notmatch '^iisauto_[A-Za-z0-9._-]{1,140}$') {
        throw "Refusing unexpected upload name."
    }
    $bytes = [System.IO.File]::ReadAllBytes($LocalPath)
    if ($bytes.Length -lt 1) { throw "Refusing to upload an empty file." }
    if ($bytes.Length -gt 5MB) { throw "Refusing to upload a certificate file larger than 5 MB." }
    $uri = "$($script:F5BaseUri)/mgmt/shared/file-transfer/uploads/$RemoteFileName"
    $offset = [long]0
    while ($offset -lt $bytes.Length) {
        $length = [Math]::Min($ChunkSize, $bytes.Length - $offset)
        $end = $offset + $length - 1
        $slice = New-Object byte[] $length
        [System.Buffer]::BlockCopy($bytes, [int]$offset, $slice, 0, [int]$length)
        $range = "{0}-{1}/{2}" -f $offset, $end, $bytes.Length
        $headers = @{ 'Content-Range' = $range }
        Invoke-F5Http -Method POST -Uri $uri -BodyBytes $slice -ContentType 'application/octet-stream' -ExtraHeaders $headers -TimeoutSec $TimeoutSec | Out-Null
        $offset += $length
    }
    return "/var/config/rest/downloads/$RemoteFileName"
}

function Remove-F5StagedFile {
    param([Parameter(Mandatory = $true)][string]$RemotePath)
    if ($RemotePath -notmatch '^/var/config/rest/downloads/iisauto_[A-Za-z0-9._-]+$') {
        throw "Refusing to delete an unexpected F5 path."
    }
    try {
        Invoke-F5Api -Method POST -Path '/mgmt/tm/util/unix-rm' -Body @{
            command = 'run'
            utilCmdArgs = $RemotePath
        } | Out-Null
        return $true
    } catch {
        Write-F5Log -Message "unix-rm could not delete ${RemotePath}: $($_.Exception.Message)" -Level 'WARNING' -EventId 2144
        return $false
    }
}

function Remove-F5StagedFileWithBash {
    param([Parameter(Mandatory = $true)][string]$RemotePath)
    if ($RemotePath -notmatch '^/var/config/rest/downloads/iisauto_[A-Za-z0-9._-]+$') {
        throw "Refusing bash cleanup of an unexpected path."
    }
    $quoted = $RemotePath.Replace("'", "")
    Invoke-F5Api -Method POST -Path '/mgmt/tm/util/bash' -Body @{
        command = 'run'
        utilCmdArgs = "-c 'rm -f -- $quoted'"
    } | Out-Null
}

function Install-F5Pkcs12 {
    param(
        [Parameter(Mandatory = $true)][string]$ObjectName,
        [Parameter(Mandatory = $true)][string]$RemotePath,
        [Parameter(Mandatory = $true)][string]$Passphrase
    )
    Assert-SafeF5Name $ObjectName
    Invoke-F5Api -Method POST -Path '/mgmt/tm/sys/crypto/pkcs12' -Body @{
        command = 'install'
        name = $ObjectName
        'from-local-file' = $RemotePath
        passphrase = $Passphrase
    } -TimeoutSec 180 | Out-Null
}

function Install-F5PublicCert {
    param(
        [Parameter(Mandatory = $true)][string]$ObjectName,
        [Parameter(Mandatory = $true)][string]$RemotePath
    )
    Assert-SafeF5Name $ObjectName
    Invoke-F5Api -Method POST -Path '/mgmt/tm/sys/crypto/cert' -Body @{
        command = 'install'
        name = $ObjectName
        'from-local-file' = $RemotePath
    } -TimeoutSec 120 | Out-Null
}

function ConvertTo-PemCertificate {
    param([Parameter(Mandatory = $true)]$Certificate)
    $raw = [Convert]::ToBase64String($Certificate.RawData)
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.AppendLine('-----BEGIN CERTIFICATE-----')
    for ($i = 0; $i -lt $raw.Length; $i += 64) {
        $take = [Math]::Min(64, $raw.Length - $i)
        [void]$builder.AppendLine($raw.Substring($i, $take))
    }
    [void]$builder.AppendLine('-----END CERTIFICATE-----')
    return $builder.ToString()
}

function Get-CertificateCommonNameText {
    param($Certificate)
    $match = [regex]::Match([string]$Certificate.Subject, 'CN=([^,]+)')
    if (-not $match.Success) { return $null }
    return $match.Groups[1].Value.Trim().Trim('"')
}

function Get-CertificateDnsNames {
    param($Certificate)
    $names = @()
    foreach ($extension in @($Certificate.Extensions)) {
        if ([string]$extension.Oid.Value -ne '2.5.29.17') { continue }
        $formatted = ''
        try { $formatted = $extension.Format($false) } catch { $formatted = '' }
        foreach ($line in ($formatted -split '\r?\n')) {
            if ($line -match '(?i)DNS\s*Name\s*=\s*(.+)$') { $names += $Matches[1].Trim() }
        }
    }
    return $names
}

function Sort-ChainCertificates {
    param($Leaf, $Others)
    $ordered = @()
    $remaining = New-Object System.Collections.Generic.List[object]
    foreach ($cert in @($Others)) { [void]$remaining.Add($cert) }
    $issuer = [string]$Leaf.Issuer
    while ($remaining.Count -gt 0) {
        $next = $null
        foreach ($cert in @($remaining)) {
            if ([string]$cert.Subject -eq $issuer -and [string]$cert.Subject -ne [string]$cert.Issuer) {
                $next = $cert
                break
            }
        }
        if (-not $next) { break }
        $ordered += $next
        [void]$remaining.Remove($next)
        $issuer = [string]$next.Issuer
    }
    foreach ($cert in @($remaining)) {
        if ([string]$cert.Subject -ne [string]$cert.Issuer) { $ordered += $cert }
    }
    return $ordered
}

function Test-IsCaCertificate {
    param($Certificate)
    foreach ($extension in @($Certificate.Extensions)) {
        if ([string]$extension.Oid.Value -ne '2.5.29.19') { continue }
        $basic = $extension -as [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]
        if ($basic) { return [bool]$basic.CertificateAuthority }
    }
    return $false
}

function Read-PfxMaterial {
    param(
        [Parameter(Mandatory = $true)][string]$PfxPath,
        [Parameter(Mandatory = $true)][string]$Password
    )
    $collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $flags = Get-EphemeralKeyStorageFlag
    $collection.Import($PfxPath, $Password, $flags)
    $leaf = $null
    foreach ($cert in @($collection)) {
        if ($cert.HasPrivateKey) { $leaf = $cert; break }
    }
    if (-not $leaf) {
        # EphemeralKeySet can hide HasPrivateKey on some .NET Framework builds.
        # Prefer a non-CA certificate. F5 PKCS#12 install still rejects a bag with no key.
        foreach ($cert in @($collection)) {
            if (-not (Test-IsCaCertificate $cert)) { $leaf = $cert; break }
        }
    }
    if (-not $leaf) {
        foreach ($cert in @($collection)) { $cert.Dispose() }
        throw "PFX does not contain an end-entity certificate."
    }
    $others = @()
    foreach ($cert in @($collection)) {
        if ($cert.Thumbprint -eq $leaf.Thumbprint) { continue }
        if ([string]$cert.Subject -eq [string]$cert.Issuer) { continue }
        $others += $cert
    }
    return @{
        Leaf = $leaf
        Intermediates = @(Sort-ChainCertificates -Leaf $leaf -Others $others)
        All = @($collection)
    }
}

function ConvertTo-F5ItemPath {
    param(
        [Parameter(Mandatory = $true)][string]$Partition,
        [Parameter(Mandatory = $true)][string]$Name
    )
    Assert-SafeF5Name $Partition
    Assert-SafeF5Name ($Name.TrimStart('.').Split('.')[0])
    if ($Name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,160}$') {
        throw "Refusing unsafe F5 object reference '$Name'."
    }
    return "~$Partition~$Name"
}

function Get-F5CertBaseName {
    param(
        [Parameter(Mandatory = $true)][string]$CommonName,
        [Parameter(Mandatory = $true)][datetime]$NotAfter,
        [Parameter(Mandatory = $true)][string]$Thumbprint
    )
    $safe = $CommonName.ToLowerInvariant().Replace('*', 'wildcard')
    $safe = [regex]::Replace($safe, '[^a-z0-9._-]', '_')
    $safe = $safe.Trim('._-')
    if (-not $safe) { $safe = 'cert' }
    if ($safe -match '^[0-9]') { $safe = "c$safe" }
    if ($safe.Length -gt 40) { $safe = $safe.Substring(0, 40).Trim('._-') }
    $day = $NotAfter.ToUniversalTime().ToString('yyyyMMdd')
    $thumb = $Thumbprint.ToLowerInvariant()
    if ($thumb.Length -lt 8) { throw "Certificate thumbprint is unexpectedly short." }
    return "{0}_{1}_{2}" -f $safe, $day, $thumb.Substring(0, 8)
}

function Save-F5RunningConfig {
    Invoke-F5Api -Method POST -Path '/mgmt/tm/sys/config' -Body @{ command = 'save' } -TimeoutSec 180 | Out-Null
    Write-F5Log -Message 'BIG-IP running configuration saved.' -Level 'INFO' -EventId 2160
}

function Sync-F5ConfigGroup {
    param([Parameter(Mandatory = $true)][string]$DeviceGroup)
    Assert-SafeF5Name $DeviceGroup
    Invoke-F5Api -Method POST -Path '/mgmt/tm/cm/config-sync' -Body @{
        command = 'run'
        options = @(
            @{ 'config-sync-to-group' = $DeviceGroup }
        )
    } -TimeoutSec 180 | Out-Null
    $synced = $false
    for ($i = 0; $i -lt 12; $i++) {
        Start-Sleep -Seconds 5
        try {
            $status = Invoke-F5Api -Method GET -Path '/mgmt/tm/cm/sync-status'
            $text = ''
            if ($status) { $text = $status | ConvertTo-Json -Depth 6 -Compress }
            if ($text -match '"description"\s*:\s*"In Sync"') { $synced = $true; break }
        } catch {
            Write-F5Log -Message "Sync status check failed: $($_.Exception.Message)" -Level 'WARNING' -EventId 2162
        }
    }
    if ($synced) {
        Write-F5Log -Message "Config sync to group $DeviceGroup reported In Sync." -Level 'INFO' -EventId 2161
    } else {
        Write-F5Log -Message "Config sync to group $DeviceGroup was requested but In Sync was not confirmed within 60 seconds." -Level 'WARNING' -EventId 2162
    }
}

function Get-F5StatePath {
    param([Parameter(Mandatory = $true)][string]$LogDirectory)
    Assert-SafeTaskPath $LogDirectory
    return (Join-Path $LogDirectory 'F5CertPublish_state.json')
}

function Read-F5State {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return @{ version = 1; certificates = @{} }
    }
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    $parsed = $raw | ConvertFrom-Json
    $map = @{}
    if ($parsed.certificates) {
        foreach ($property in @($parsed.certificates.PSObject.Properties)) {
            $map[$property.Name] = $property.Value
        }
    }
    return @{ version = 1; certificates = $map }
}

function Write-F5State {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$State
    )
    $certObject = [ordered]@{}
    foreach ($key in @($State.certificates.Keys)) {
        $certObject[$key] = $State.certificates[$key]
    }
    $payload = @{ version = 1; certificates = $certObject }
    $json = $payload | ConvertTo-Json -Depth 8
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($Path, $json, $utf8)
    Set-TightFileAcl -Path $Path
}

function Get-ClientSslProfile {
    param(
        [Parameter(Mandatory = $true)][string]$Partition,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $leaf = $Name.Split('/')[-1]
    Assert-SafeF5Name $Partition
    Assert-SafeF5Name $leaf
    $path = "/mgmt/tm/ltm/profile/client-ssl/$(ConvertTo-F5ItemPath -Partition $Partition -Name $leaf)"
    try {
        return Invoke-F5Api -Method GET -Path $path
    } catch {
        if ($_.Exception.Message -match 'HTTP 404') { return $null }
        throw
    }
}
