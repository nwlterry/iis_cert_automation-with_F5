#requires -Version 5.1
<#
.SYNOPSIS
    Push CCS PFX files to F5 BIG-IP, create a new client-ssl profile, and rebind virtual servers.

.DESCRIPTION
    Runs after IIS_Cert_Auto_Package\Export_Cert_CCS_Secure.ps1. It does not renew or export
    certificates itself. Use Invoke-IisCertExportAndF5.ps1 when this host should do both.

    For each configured certificate the script:
      1. Reads the PFX from the IIS Centralized Certificate Store path (registry).
      2. Uploads that PFX to the BIG-IP over iControl REST (HTTPS, token auth) and deletes the staged copy.
      3. Installs it with sys crypto pkcs12. The PFX password is the Credential Manager target PFXCertPassword.
      4. Installs intermediates, if present, as a separate chain file. The leaf is not used as the chain.
      5. Creates a new client-ssl profile named from the CN, expiry date, and thumbprint.
      6. Points the related virtual server at that profile without removing tcp/http/other profiles.
         The previous client-ssl profile is left on the box so -Rollback can put it back.

    Passwords are never written to the log, the event log, or the config file.
    Windows PowerShell 5.1. Run on one IIS node, as NT AUTHORITY\SYSTEM via the scheduled task.

.PARAMETER ConfigPath
    f5-publish.config.json. Copy examples\f5-publish.config.example.json. No passwords in that file.

.PARAMETER Rollback
    Point each mapped virtual server back at the client-ssl profile recorded in F5CertPublish_state.json.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ConfigPath = $(Join-Path $PSScriptRoot 'f5-publish.config.json'),
    [int]$StartupDelaySeconds = -1,
    [switch]$AllowUntrustedManagementCert,
    [switch]$AllowStandby,
    [switch]$AllowBashCleanup,
    [switch]$Rollback
)

$script:F5PublishExitCode = 0
$global:F5PublishExitCode = 0

. (Join-Path $PSScriptRoot 'Security.Common.ps1')
. (Join-Path $PSScriptRoot 'F5.Common.ps1')

function Set-PublishExit {
    param([int]$Code)
    if ($Code -gt $script:F5PublishExitCode) {
        $script:F5PublishExitCode = $Code
        $global:F5PublishExitCode = $Code
    }
}

function Get-ExportPfxFileName {
    param([string]$ConfiguredName, [string]$CommonName)
    $name = if ($ConfiguredName) { $ConfiguredName } else { $CommonName }
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    foreach ($char in $invalid) {
        $name = $name.Replace([string]$char, '_')
    }
    if (-not $name.ToLowerInvariant().EndsWith('.pfx')) { $name = "$name.pfx" }
    if ($name -notmatch '^[A-Za-z0-9._-]{1,180}$') {
        throw "Refusing PFX file name '$name'."
    }
    return $name
}

function Get-CcsDirectory {
    $registryPath = 'HKLM:\SOFTWARE\Microsoft\IIS\CentralCertProvider'
    $values = Get-ItemProperty -Path $registryPath -ErrorAction Stop
    if ($values.Enabled -ne 1) {
        throw "IIS Centralized Certificate Store is not enabled."
    }
    $path = [string]$values.CertStoreLocation
    Assert-SafeTaskPath $path
    if (-not (Test-Path -LiteralPath $path)) {
        throw "CCS path is not accessible: $path"
    }
    return $path
}

function Get-ProfileShortName {
    param([string]$FullOrShort)
    if (-not $FullOrShort) { return '' }
    $trimmed = $FullOrShort.Trim()
    if ($trimmed -match '/([^/]+)$') { return $Matches[1] }
    return $trimmed
}

function Test-SameProfileName {
    param([string]$Left, [string]$Right)
    $a = Get-ProfileShortName $Left
    $b = Get-ProfileShortName $Right
    return ($a -and $b -and ($a.ToLowerInvariant() -eq $b.ToLowerInvariant()))
}

function Get-VirtualClientSslProfiles {
    param([string]$Partition, [string]$VirtualName)
    $items = Invoke-F5Api -Method GET -Path ("/mgmt/tm/ltm/virtual/{0}/profiles" -f (ConvertTo-F5ItemPath -Partition $Partition -Name $VirtualName))
    $found = @()
    if (-not $items -or -not $items.items) { return ,$found }
    foreach ($item in @($items.items)) {
        $short = Get-ProfileShortName ([string]$item.fullPath)
        if (-not $short) { $short = [string]$item.name }
        if (-not $short) { continue }
        $profilePartition = $Partition
        if ([string]$item.fullPath -match '^/([^/]+)/') { $profilePartition = $Matches[1] }
        $profile = Get-ClientSslProfile -Partition $profilePartition -Name $short
        if (-not $profile) { continue }
        $found += @{
            Name = $short
            Partition = $profilePartition
            Context = [string]$item.context
            ServerName = [string]$profile.serverName
            SniDefault = [string]$profile.sniDefault
            CertKeyChainCount = @($profile.certKeyChain).Count
            Profile = $profile
        }
    }
    return ,$found
}

function Resolve-ProfileToReplace {
    param($Profiles, [string]$ReplaceName, [string]$ServerName)
    if ($ReplaceName) {
        Assert-SafeF5Name (Get-ProfileShortName $ReplaceName)
        $match = @($Profiles | Where-Object { Test-SameProfileName $_.Name $ReplaceName })
        if ($match.Count -ne 1) {
            throw "replaceClientSslProfile '$ReplaceName' is not a client-ssl profile on this virtual server."
        }
        return $match[0]
    }
    $byName = @($Profiles | Where-Object { $_.ServerName -and ($_.ServerName.ToLowerInvariant() -eq $ServerName.ToLowerInvariant()) })
    if ($byName.Count -eq 1) { return $byName[0] }
    if ($byName.Count -gt 1) {
        throw "Multiple client-ssl profiles use server name ${ServerName}: $($byName.Name -join ', '). Set replaceClientSslProfile."
    }
    if ($Profiles.Count -eq 1) { return $Profiles[0] }
    if ($Profiles.Count -eq 0) { return $null }
    throw "Virtual server has $($Profiles.Count) client-ssl profiles and none match server name '$ServerName'. Set replaceClientSslProfile."
}

function New-F5UploadName {
    param([string]$Suffix)
    $random = [Guid]::NewGuid().ToString('N').Substring(0, 12)
    $clean = [regex]::Replace($Suffix.ToLowerInvariant(), '[^a-z0-9._-]', '_')
    if ($clean.Length -gt 60) { $clean = $clean.Substring(0, 60) }
    $name = "iisauto_${random}_$clean"
    if ($name -notmatch '^iisauto_[A-Za-z0-9._-]{1,140}$') {
        throw "Internal upload name was rejected."
    }
    return $name
}

function Send-F5FileWithRetry {
    param([string]$LocalPath, [string]$RemoteFileName)
    $remote = $null
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        try {
            $remote = Send-F5File -LocalPath $LocalPath -RemoteFileName $RemoteFileName
            return $remote
        } catch {
            Write-F5Log -Message "Upload attempt $attempt failed for ${RemoteFileName}: $($_.Exception.Message)" -Level 'WARNING' -EventId 2140
            try { Remove-F5StagedFile -RemotePath "/var/config/rest/downloads/$RemoteFileName" | Out-Null } catch { }
            if ($attempt -eq 2) { throw }
            Start-Sleep -Seconds 2
        }
    }
}

function Remove-StagedOrWarn {
    param([string]$RemotePath, [switch]$PrivateKey)
    $removed = Remove-F5StagedFile -RemotePath $RemotePath
    if ($removed) {
        $id = $(if ($PrivateKey) { 2143 } else { 2142 })
        Write-F5Log -Message "Deleted staged file $RemotePath from BIG-IP." -Level 'INFO' -EventId $id
        return
    }
    if ($AllowBashCleanup) {
        try {
            Remove-F5StagedFileWithBash -RemotePath $RemotePath
            Write-F5Log -Message "Deleted staged file $RemotePath with bash fallback." -Level 'WARNING' -EventId 2143
            return
        } catch {
            Write-F5Log -Message "Bash cleanup failed for ${RemotePath}: $($_.Exception.Message)" -Level 'ERROR' -EventId 2144
        }
    }
    if ($PrivateKey) {
        $script:StagedPfxDeleteFailed = $true
        Set-PublishExit 3
        Write-F5Log -Message "PRIVATE KEY FILE REMAINS on BIG-IP at $RemotePath. Delete it now. unix-rm failed. Re-run with -AllowBashCleanup only if your change policy allows tmsh util bash." -Level 'ERROR' -EventId 2144
    } else {
        Write-F5Log -Message "Public chain file remains on BIG-IP at $RemotePath. Delete it when convenient." -Level 'WARNING' -EventId 2144
    }
}

function Install-CertificateMaterial {
    param(
        [string]$Partition,
        [string]$BaseName,
        [string]$PfxPath,
        [string]$PfxPassword,
        $Intermediates
    )
    $certUri = "/mgmt/tm/sys/file/ssl-cert/$(ConvertTo-F5ItemPath -Partition $Partition -Name ($BaseName + '.crt'))"
    $keyUri = "/mgmt/tm/sys/file/ssl-key/$(ConvertTo-F5ItemPath -Partition $Partition -Name ($BaseName + '.key'))"
    $certExists = Test-F5ObjectExists -Path $certUri
    $keyExists = Test-F5ObjectExists -Path $keyUri
    if ($certExists -xor $keyExists) {
        throw "Partial crypto objects for $BaseName on partition $Partition. Remove the orphan ssl-cert or ssl-key manually. This script does not delete key material."
    }
    if ($certExists -and $keyExists) {
        Write-F5Log -Message "Certificate and key $BaseName already exist. Upload skipped." -Level 'INFO' -EventId 2145
    } else {
        $uploadName = New-F5UploadName -Suffix ($BaseName + '.pfx')
        $remote = $null
        try {
            $remote = Send-F5FileWithRetry -LocalPath $PfxPath -RemoteFileName $uploadName
            Write-F5Log -Message "Uploaded PFX to BIG-IP staging as $uploadName ($((Get-Item -LiteralPath $PfxPath).Length) bytes) over HTTPS." -Level 'INFO' -EventId 2140
            try {
                Install-F5Pkcs12 -ObjectName $BaseName -RemotePath $remote -Passphrase $PfxPassword
            } catch {
                if ($_.Exception.Message -match 'already exists' -and (Test-F5ObjectExists -Path $certUri)) {
                    Write-F5Log -Message "PKCS12 $BaseName already existed when install ran. Continuing." -Level 'WARNING' -EventId 2145
                } else {
                    throw "PKCS12 install failed for $BaseName. Confirm PFXCertPassword matches this file. $($_.Exception.Message)"
                }
            }
            if (-not (Test-F5ObjectExists -Path $certUri) -or -not (Test-F5ObjectExists -Path $keyUri)) {
                throw "PKCS12 install did not create $BaseName.crt and $BaseName.key."
            }
            Write-F5Log -Message "Installed PKCS12 as /$Partition/$BaseName.crt and .key." -Level 'INFO' -EventId 2141
        } finally {
            if ($remote) { Remove-StagedOrWarn -RemotePath $remote -PrivateKey }
        }
    }

    $chainName = $null
    if (@($Intermediates).Count -gt 0) {
        $chainName = "${BaseName}_bundle"
        Assert-SafeF5Name $chainName
        $chainUri = "/mgmt/tm/sys/file/ssl-cert/$(ConvertTo-F5ItemPath -Partition $Partition -Name ($chainName + '.crt'))"
        if (Test-F5ObjectExists -Path $chainUri) {
            Write-F5Log -Message "Chain $chainName already exists." -Level 'INFO' -EventId 2145
        } else {
            $pem = ""
            foreach ($intermediate in @($Intermediates)) {
                $pem += (ConvertTo-PemCertificate -Certificate $intermediate)
                if (-not $pem.EndsWith("`n")) { $pem += "`n" }
            }
            $temp = Join-Path $script:F5StateDirectory ("{0}.chain.crt" -f $chainName)
            $utf8 = New-Object System.Text.UTF8Encoding $false
            [System.IO.File]::WriteAllText($temp, $pem, $utf8)
            Set-TightFileAcl -Path $temp
            $uploadName = New-F5UploadName -Suffix ($chainName + '.crt')
            $remote = $null
            try {
                $remote = Send-F5FileWithRetry -LocalPath $temp -RemoteFileName $uploadName
                Install-F5PublicCert -ObjectName $chainName -RemotePath $remote
                if (-not (Test-F5ObjectExists -Path $chainUri)) {
                    throw "Chain install did not create $chainName.crt."
                }
                Write-F5Log -Message "Installed intermediate chain /$Partition/$chainName.crt ($($Intermediates.Count) certificate(s))." -Level 'INFO' -EventId 2142
            } finally {
                if ($remote) { Remove-StagedOrWarn -RemotePath $remote }
                Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
            }
        }
    }
    return $chainName
}

function Invoke-F5Transaction {
    param([scriptblock]$Action)
    $created = Invoke-F5Api -Method POST -Path '/mgmt/tm/transaction' -Body @{ timeoutSeconds = 120 }
    $script:F5Tx = [string]$created.transId
    if (-not $script:F5Tx) { throw "F5 did not open a transaction." }
    Write-F5Log -Message "Opened F5 transaction $($script:F5Tx)." -Level 'INFO' -EventId 2150
    try {
        & $Action
        Invoke-F5Api -Method PATCH -Path "/mgmt/tm/transaction/$($script:F5Tx)" -Body @{ state = 'VALIDATING' } | Out-Null
        for ($i = 0; $i -lt 30; $i++) {
            try {
                $stateObject = Invoke-F5Api -Method GET -Path "/mgmt/tm/transaction/$($script:F5Tx)"
            } catch {
                if ($_.Exception.Message -match 'HTTP 404') {
                    Write-F5Log -Message "F5 transaction $($script:F5Tx) left the transaction list after validation." -Level 'INFO' -EventId 2151
                    return
                }
                throw
            }
            $state = [string]$stateObject.state
            if ($state -eq 'COMPLETED') {
                Write-F5Log -Message "F5 transaction $($script:F5Tx) completed." -Level 'INFO' -EventId 2151
                return
            }
            if ($state -eq 'FAILED') {
                throw "F5 transaction failed. $(Protect-LogText ($stateObject | ConvertTo-Json -Depth 5 -Compress))"
            }
            Start-Sleep -Seconds 1
        }
        throw "F5 transaction $($script:F5Tx) did not complete."
    } catch {
        $id = $script:F5Tx
        $script:F5Tx = $null
        if ($id) {
            try { Invoke-F5Api -Method DELETE -Path "/mgmt/tm/transaction/$id" | Out-Null } catch { }
        }
        throw
    } finally {
        $script:F5Tx = $null
    }
}

function Update-OneVirtualServer {
    param(
        [string]$Partition,
        [string]$VirtualName,
        [string]$ProfileName,
        [string]$ProfilePartition,
        [string]$ReplaceName,
        [string]$ServerName,
        [bool]$HaveDesiredSni,
        [bool]$DesiredSni,
        [string]$DefaultsFrom,
        [string]$ChainName
    )
    Assert-SafeF5Name $VirtualName
    Assert-SafeF5Name $ProfileName
    $current = @(Get-VirtualClientSslProfiles -Partition $Partition -Name $VirtualName)
    $target = Resolve-ProfileToReplace -Profiles $current -ReplaceName $ReplaceName -ServerName $ServerName
    if ($target -and $target.CertKeyChainCount -gt 1) {
        throw "Refusing to detach $($target.Name) because it has $($target.CertKeyChainCount) cert-key-chain entries. Split that profile before automating it."
    }
    $inheritSni = $false
    if ($target -and -not $HaveDesiredSni) {
        $inheritSni = ($target.SniDefault -eq 'true' -or $target.SniDefault -eq 'True')
    }
    $wantSni = if ($HaveDesiredSni) { $DesiredSni } else { $inheritSni }
    $already = @($current | Where-Object { Test-SameProfileName $_.Name $ProfileName })
    $previous = if ($target) { $target.Name } else { '' }
    if ($already.Count -eq 1 -and ((-not $previous) -or (Test-SameProfileName $previous $ProfileName))) {
        Write-F5Log -Message "Virtual server $Partition/$VirtualName already uses $ProfileName." -Level 'INFO' -EventId 2151
        return @{ Previous = $previous; Changed = $false; SniDefault = $wantSni }
    }

    $createSni = $wantSni
    $flipSniAfter = $false
    if ($wantSni -and $previous -and -not (Test-SameProfileName $previous $ProfileName)) {
        $createSni = $false
        $flipSniAfter = $true
    }

    $profilePath = "/mgmt/tm/ltm/profile/client-ssl/$(ConvertTo-F5ItemPath -Partition $ProfilePartition -Name $ProfileName)"
    Invoke-F5Transaction -Action {
        $existing = Get-ClientSslProfile -Partition $ProfilePartition -Name $ProfileName
        if (-not $existing) {
            $body = @{
                name = $ProfileName
                partition = $ProfilePartition
                defaultsFrom = $DefaultsFrom
                cert = "/$ProfilePartition/$ProfileName.crt"
                key = "/$ProfilePartition/$ProfileName.key"
                serverName = $ServerName
                sniDefault = [bool]$createSni
            }
            if ($ChainName) { $body.chain = "/$ProfilePartition/$ChainName.crt" }
            Invoke-F5Api -Method POST -Path '/mgmt/tm/ltm/profile/client-ssl' -Body $body | Out-Null
            Write-F5Log -Message "Created client-ssl profile /$ProfilePartition/$ProfileName (sniDefault=$createSni, serverName=$ServerName)." -Level 'INFO' -EventId 2150
        } else {
            $certRef = [string]$existing.cert
            if ($certRef -and ($certRef -notmatch [regex]::Escape("$ProfileName.crt"))) {
                throw "Profile $ProfileName exists but references '$certRef' instead of /$ProfileName.crt."
            }
        }
        if ($already.Count -eq 0) {
            Invoke-F5Api -Method POST -Path ("/mgmt/tm/ltm/virtual/{0}/profiles" -f (ConvertTo-F5ItemPath -Partition $Partition -Name $VirtualName)) -Body @{
                name = $ProfileName
                partition = $ProfilePartition
                context = 'clientside'
            } | Out-Null
        }
        if ($previous -and -not (Test-SameProfileName $previous $ProfileName)) {
            $oldPartition = $target.Partition
            Invoke-F5Api -Method DELETE -Path ("/mgmt/tm/ltm/virtual/{0}/profiles/{1}" -f (ConvertTo-F5ItemPath -Partition $Partition -Name $VirtualName), (ConvertTo-F5ItemPath -Partition $oldPartition -Name $previous)) | Out-Null
        }
        if ($flipSniAfter) {
            Invoke-F5Api -Method PATCH -Path $profilePath -Body @{ sniDefault = $true } | Out-Null
        }
    }.GetNewClosure()

    Write-F5Log -Message "Virtual server $Partition/$VirtualName now uses /$ProfilePartition/$ProfileName. Previous client-ssl profile: $(if ($previous) { $previous } else { 'none' })." -Level 'INFO' -EventId 2151
    return @{ Previous = $previous; Changed = $true; SniDefault = $wantSni }
}

function Restore-OneVirtualServer {
    param([string]$Partition, [string]$VirtualName, [string]$PreviousProfile, [string]$NewProfile)
    Assert-SafeF5Name $VirtualName
    if ($NewProfile) { Assert-SafeF5Name $NewProfile }
    if ($PreviousProfile) { Assert-SafeF5Name $PreviousProfile }
    $current = @(Get-VirtualClientSslProfiles -Partition $Partition -Name $VirtualName)
    $hasNew = @($current | Where-Object { Test-SameProfileName $_.Name $NewProfile }).Count -gt 0
    $hasOld = @($current | Where-Object { Test-SameProfileName $_.Name $PreviousProfile }).Count -gt 0
    if (-not $hasNew -and (($hasOld) -or -not $PreviousProfile)) {
        Write-F5Log -Message "Rollback not required for $Partition/$VirtualName." -Level 'INFO' -EventId 2151
        return $false
    }
    if ($PreviousProfile -and -not (Get-ClientSslProfile -Partition $Partition -Name $PreviousProfile)) {
        throw "Previous client-ssl profile $PreviousProfile no longer exists. Refusing to remove $NewProfile."
    }
    Invoke-F5Transaction -Action {
        if ($PreviousProfile -and -not $hasOld) {
            Invoke-F5Api -Method POST -Path ("/mgmt/tm/ltm/virtual/{0}/profiles" -f (ConvertTo-F5ItemPath -Partition $Partition -Name $VirtualName)) -Body @{
                name = $PreviousProfile
                context = 'clientside'
            } | Out-Null
        }
        if ($hasNew) {
            Invoke-F5Api -Method DELETE -Path ("/mgmt/tm/ltm/virtual/{0}/profiles/{1}" -f (ConvertTo-F5ItemPath -Partition $Partition -Name $VirtualName), (ConvertTo-F5ItemPath -Partition $Partition -Name $NewProfile)) | Out-Null
        }
    }.GetNewClosure()
    Write-F5Log -Message "Rolled back $Partition/$VirtualName to $(if ($PreviousProfile) { $PreviousProfile } else { 'no client-ssl profile' })." -Level 'WARNING' -EventId 2151
    return $true
}

function Get-StateRecordVirtualServers {
    param($Record)
    return @($Record.virtualServers)
}

$connected = $false
$material = $null
try {
    Assert-SafeTaskPath $ConfigPath
    $config = Import-AutomationConfig -ConfigPath $ConfigPath
    $f5 = $config.f5
    if (-not $f5 -or -not $f5.managementHost) {
        throw "Config f5.managementHost is required."
    }
    $logDirectory = if ($config.logDirectory) { [string]$config.logDirectory } else { 'C:\Logs' }
    $maxLogFiles = if ($config.maxLogFiles) { [int]$config.maxLogFiles } else { 5 }
    Initialize-F5Logging -LogDirectory $logDirectory -MaxFiles $maxLogFiles
    $script:F5StateDirectory = $logDirectory
    $statePath = Get-F5StatePath -LogDirectory $logDirectory

    $delay = 5
    if ($config.startupDelaySeconds -ne $null -and [string]$config.startupDelaySeconds -ne '') {
        $delay = [int]$config.startupDelaySeconds
    }
    if ($StartupDelaySeconds -ge 0) { $delay = $StartupDelaySeconds }
    if ($delay -lt 0 -or $delay -gt 120) { throw "startupDelaySeconds must be between 0 and 120." }
    if ($delay -gt 0) { Start-Sleep -Seconds $delay }

    $partition = if ($f5.partition) { [string]$f5.partition } else { 'Common' }
    Assert-SafeF5Name $partition
    $managementHost = [string]$f5.managementHost
    Assert-SafeManagementHost $managementHost
    $managementPort = if ($f5.managementPort) { [int]$f5.managementPort } else { 443 }
    $loginProvider = if ($f5.loginProviderName) { [string]$f5.loginProviderName } else { 'tmos' }
    $f5Target = if ($f5.credentialTarget) { [string]$f5.credentialTarget } else { 'F5-iControl' }
    $pfxTarget = if ($f5.pfxCredentialTarget) { [string]$f5.pfxCredentialTarget } else { 'PFXCertPassword' }
    $defaultsFrom = if ($f5.defaultsFrom) { [string]$f5.defaultsFrom } else { "/$partition/clientssl" }
    if ($defaultsFrom -notmatch '^/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$') {
        throw "Refusing defaultsFrom '$defaultsFrom'."
    }
    $deviceGroup = if ($f5.deviceGroup) { [string]$f5.deviceGroup } else { '' }
    if ($deviceGroup) { Assert-SafeF5Name $deviceGroup }
    $saveConfig = $true
    if ($f5.PSObject.Properties.Name -contains 'saveConfig') { $saveConfig = [bool]$f5.saveConfig }
    $requireActive = $true
    if ($f5.PSObject.Properties.Name -contains 'requireActive') { $requireActive = [bool]$f5.requireActive }
    $entries = @($config.certificates)
    if ($entries.Count -eq 0 -or -not $entries[0]) {
        throw "Config certificates must list at least one CN."
    }

    Write-F5Log -Message "F5 publish starting. Host=$managementHost partition=$partition rollback=$Rollback whatIf=$WhatIfPreference entries=$($entries.Count)." -Level 'INFO' -EventId 2100
    Enable-F5Tls -PinnedCertSha256 ([string]$f5.managementCertSha256) -AllowUntrusted:$AllowUntrustedManagementCert

    $ccsDirectory = Get-CcsDirectory
    $pfxSecret = Get-StoredTargetPassword -Target $pfxTarget -Purpose 'PFX password'
    $f5Secret = Get-StoredTargetPassword -Target $f5Target -Purpose 'F5 iControl'
    Write-F5Log -Message "Loaded Credential Manager targets $pfxTarget and $f5Target. Values were not logged." -Level 'INFO' -EventId 2110

    Connect-F5Session -ManagementHost $managementHost -Port $managementPort -LoginProviderName $loginProvider -UserName $f5Secret.UserName -Password $f5Secret.Password
    $connected = $true
    $active = Test-F5DeviceIsActive
    if (-not $active -and $requireActive -and -not $AllowStandby) {
        throw "BIG-IP $managementHost is not the active device. Run against the active member, or pass -AllowStandby for a lab."
    }

    $state = Read-F5State -Path $statePath

    foreach ($entry in $entries) {
        $commonName = [string]$entry.cn
        if (-not $commonName) { throw "A certificates entry is missing cn." }
        Assert-SafeHostName ($commonName.Replace('*', 'x'))
        $serverName = if ($entry.serverName) { [string]$entry.serverName } else { $commonName }
        if ($serverName -notmatch '^[A-Za-z0-9.*-]{1,253}$') {
            throw "Refusing server name '$serverName'."
        }
        $pfxName = Get-ExportPfxFileName -ConfiguredName ([string]$entry.pfxFileName) -CommonName $commonName
        $pfxPath = Join-Path $ccsDirectory $pfxName
        $virtuals = @($entry.virtualServers)
        if ($virtuals.Count -eq 0 -or -not $virtuals[0]) {
            throw "Certificate $commonName has no virtualServers."
        }

        if ($Rollback) {
            $record = $state.certificates[$commonName]
            if (-not $record) {
                Write-F5Log -Message "No state for $commonName. Nothing to roll back." -Level 'WARNING' -EventId 2152
                Set-PublishExit 2
                continue
            }
            $recordVirtuals = Get-StateRecordVirtualServers -Record $record
            $rollbackChanged = $false
            foreach ($virtual in $recordVirtuals) {
                $virtualPartition = if ($virtual.partition) { [string]$virtual.partition } else { $partition }
                $virtualName = [string]$virtual.name
                $targetText = "$virtualPartition/$virtualName"
                if (-not $PSCmdlet.ShouldProcess($targetText, "Roll back client-ssl profile for $commonName")) {
                    Write-F5Log -Message "WhatIf rollback $targetText previous=$($virtual.previousProfile) remove=$($virtual.newProfile)" -Level 'WARNING' -EventId 2192
                    continue
                }
                try {
                    if (Restore-OneVirtualServer -Partition $virtualPartition -VirtualName $virtualName -PreviousProfile ([string]$virtual.previousProfile) -NewProfile ([string]$virtual.newProfile)) {
                        $rollbackChanged = $true
                    }
                } catch {
                    Set-PublishExit 2
                    Write-F5Log -Message "Rollback failed for ${commonName} on ${targetText}: $($_.Exception.Message)" -Level 'ERROR' -EventId 2152
                }
            }
            if ($rollbackChanged -and $saveConfig) {
                Save-F5RunningConfig
                if ($deviceGroup) { Sync-F5ConfigGroup -DeviceGroup $deviceGroup }
            }
            continue
        }

        if (-not (Test-Path -LiteralPath $pfxPath)) {
            Set-PublishExit 2
            Write-F5Log -Message "PFX not found for ${commonName}: $pfxPath. Export must succeed before F5 publish." -Level 'ERROR' -EventId 2131
            continue
        }

        $material = $null
        try {
            $material = Read-PfxMaterial -PfxPath $pfxPath -Password $pfxSecret.Password
            $leaf = $material.Leaf
            $leafCn = Get-CertificateCommonNameText -Certificate $leaf
            $dnsNames = @(Get-CertificateDnsNames -Certificate $leaf)
            $matched = ($leafCn -and ($leafCn.ToLowerInvariant() -eq $commonName.ToLowerInvariant()))
            if (-not $matched) {
                foreach ($dnsName in $dnsNames) {
                    if ($dnsName.ToLowerInvariant() -eq $commonName.ToLowerInvariant()) { $matched = $true }
                }
            }
            if (-not $matched) {
                throw "PFX CN '$leafCn' does not match configured cn '$commonName'."
            }
            $baseName = Get-F5CertBaseName -CommonName $commonName -NotAfter $leaf.NotAfter -Thumbprint $leaf.Thumbprint
            Assert-SafeF5Name $baseName
            $thumb = $leaf.Thumbprint
            $notAfter = $leaf.NotAfter.ToUniversalTime().ToString('yyyy-MM-dd')
            Write-F5Log -Message "PFX $pfxName thumbprint=$thumb notAfter=$notAfter cn=$leafCn base=$baseName chainCerts=$($material.Intermediates.Count)." -Level 'INFO' -EventId 2130

            $haveDesiredSni = $false
            $desiredSni = $false
            if ($entry.PSObject.Properties.Name -contains 'sniDefault') {
                $haveDesiredSni = $true
                $desiredSni = [bool]$entry.sniDefault
            }

            $plan = @()
            foreach ($virtual in $virtuals) {
                $virtualPartition = if ($virtual.partition) { [string]$virtual.partition } else { $partition }
                $virtualName = [string]$virtual.name
                Assert-SafeF5Name $virtualPartition
                Assert-SafeF5Name $virtualName
                $replaceName = [string]$virtual.replaceClientSslProfile
                $profiles = @(Get-VirtualClientSslProfiles -Partition $virtualPartition -Name $virtualName)
                $chosen = $null
                try {
                    $chosen = Resolve-ProfileToReplace -Profiles $profiles -ReplaceName $replaceName -ServerName $serverName
                } catch {
                    $plan += "$virtualPartition/$virtualName ERROR $($_.Exception.Message)"
                    continue
                }
                $chosenName = if ($chosen) { $chosen.Name } else { '(add)' }
                $plan += "$virtualPartition/$virtualName replace=$chosenName with=$baseName"
            }
            Write-F5Log -Message ("Plan for ${commonName}: " + ($plan -join '; ')) -Level 'INFO' -EventId 2192
            $planFailed = $false
            foreach ($line in $plan) {
                if ($line -match ' ERROR ') { $planFailed = $true }
            }

            $mutating = $false
            foreach ($virtual in $virtuals) {
                $virtualName = [string]$virtual.name
                if ($PSCmdlet.ShouldProcess("$partition/$virtualName", "Publish $baseName for $commonName")) {
                    $mutating = $true
                    break
                }
            }
            if (-not $mutating) { continue }
            if ($planFailed) {
                throw "Refusing to upload because the virtual-server plan has an error. See the plan log for $commonName."
            }

            $chainName = Install-CertificateMaterial -Partition $partition -BaseName $baseName -PfxPath $pfxPath -PfxPassword $pfxSecret.Password -Intermediates $material.Intermediates
            $virtualState = @()
            $entryFailed = $false
            $certChanged = $false
            foreach ($virtual in $virtuals) {
                $virtualPartition = if ($virtual.partition) { [string]$virtual.partition } else { $partition }
                $virtualName = [string]$virtual.name
                $replaceName = [string]$virtual.replaceClientSslProfile
                try {
                    $result = Update-OneVirtualServer -Partition $virtualPartition -VirtualName $virtualName -ProfileName $baseName -ProfilePartition $partition -ReplaceName $replaceName -ServerName $serverName -HaveDesiredSni $haveDesiredSni -DesiredSni $desiredSni -DefaultsFrom $defaultsFrom -ChainName $chainName
                    if ($result.Changed) { $certChanged = $true }
                    $virtualState += @{
                        partition = $virtualPartition
                        name = $virtualName
                        previousProfile = [string]$result.Previous
                        newProfile = $baseName
                    }
                } catch {
                    $entryFailed = $true
                    Set-PublishExit 2
                    Write-F5Log -Message "Virtual server update failed for ${commonName} on $virtualPartition/${virtualName}: $($_.Exception.Message)" -Level 'ERROR' -EventId 2152
                }
            }
            if ($virtualState.Count -gt 0) {
                $state.certificates[$commonName] = @{
                    thumbprint = $thumb
                    baseName = $baseName
                    notAfter = $notAfter
                    virtualServers = $virtualState
                    updatedUtc = [DateTime]::UtcNow.ToString('o')
                }
                Write-F5State -Path $statePath -State $state
            }
            if ($certChanged -and $saveConfig) {
                Save-F5RunningConfig
                if ($deviceGroup) { Sync-F5ConfigGroup -DeviceGroup $deviceGroup }
            }
        } catch {
            Set-PublishExit 2
            Write-F5Log -Message "Certificate ${commonName} failed: $($_.Exception.Message)" -Level 'ERROR' -EventId 2191
        } finally {
            if ($material -and $material.All) {
                foreach ($cert in @($material.All)) {
                    try { $cert.Dispose() } catch { }
                }
            }
            $material = $null
        }
    }

    if ($script:StagedPfxDeleteFailed) { Set-PublishExit 3 }
    if ($script:F5PublishExitCode -eq 0) {
        Write-F5Log -Message 'F5 publish finished.' -Level 'INFO' -EventId 2190
    } else {
        Write-F5Log -Message "F5 publish finished with exit code $($script:F5PublishExitCode)." -Level 'ERROR' -EventId 2191
    }
} catch {
    if (-not $script:F5LogPath) {
        Write-Output (Protect-LogText $_.Exception.Message)
    } else {
        Write-F5Log -Message "F5 publish failed: $($_.Exception.Message)" -Level 'ERROR' -EventId 2191
    }
    Set-PublishExit 2
} finally {
    if ($script:F5Token) {
        try { Disconnect-F5Session } catch { }
    }
    $pfxSecret = $null
    $f5Secret = $null
}

if ([string]::IsNullOrEmpty($MyInvocation.ScriptName)) {
    exit $script:F5PublishExitCode
}
