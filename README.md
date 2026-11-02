# IIS certificate automation with F5

After [iis_cert_automation](https://github.com/nwlterry/iis_cert_automation) renews a certificate and exports the PFX into the IIS Centralized Certificate Store, this repository loads that same PFX onto F5 BIG-IP.

For each mapped certificate it:

1. Pushes the PFX to the BIG-IP over iControl REST (HTTPS and a short-lived token). The staged file is deleted after `sys crypto pkcs12 install`.
2. Creates a **new** client-ssl profile. The name is `{cn}_{expiry}_{thumbprint8}`, so a renewal does not overwrite the previous profile.
3. Points the related virtual server at that profile. TCP, HTTP, and other profiles stay. The previous client-ssl profile stays on the box for rollback.

The PFX password stays in Credential Manager target `PFXCertPassword`. The F5 account is a second target, `F5-iControl`. Neither password is written to the config, the command line, the log, or the event log.

## What talks to F5

| File | Role |
|---|---|
| `src/Publish-PfxToF5.ps1` | Upload, install, new client-ssl profile, virtual-server rebind |
| `src/Invoke-IisCertExportAndF5.ps1` | Run `Export_Cert_CCS_Secure.ps1`, then publish |
| `src/Register-F5CertPublishTask.ps1` | SYSTEM task on export success event 1065 |
| `src/Set-F5IControlCredential.ps1` | Store the F5 account for SYSTEM |
| `src/F5.Common.ps1` | iControl REST, redaction, PKCS#12 install |
| `src/Security.Common.ps1` | Same checks as `iis_cert_automation`, plus F5 name checks |

`Security.Common.ps1` in this repo still contains the original functions unchanged. `Export_Cert_CCS_Secure.ps1` can dot-source this copy.

## One node only

Register the F5 task on **one** IIS node. Each node that exports writes event 1065. If every node published, they would race on the same virtual server.

That node must reach the **active** BIG-IP management address on TCP 443. The script refuses a standby unless `-AllowStandby` is set.

## Setup

Windows Server 2019/2022, Windows PowerShell 5.1, IIS CCS already configured by `iis_cert_automation`.

BIG-IP TMOS 14.1 or newer with iControl REST. A dedicated local user that can install keys, edit client-ssl profiles and virtual servers, save the config, and run `unix-rm` (Administrator role on current TMOS). Do not use the default `admin` account.

Copy `src\*` to `C:\Scripts` next to `Export_Cert_CCS_Secure.ps1` from `iis_cert_automation`.

```powershell
Copy-Item .\examples\f5-publish.config.example.json C:\Scripts\f5-publish.config.json
```

Edit the copy. Set the management host, device group (or leave it empty), and each CN's virtual server. `pfxFileName` must be the file the export script wrote (`www.example.com.pfx`). Do not add a password field. The script rejects the file if you do.

On that IIS node, elevated and interactive:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\Set-F5IControlCredential.ps1 -UserName svc_f5_certs
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\Register-F5CertPublishTask.ps1 -ConfigPath C:\Scripts\f5-publish.config.json
```

Leave the existing CCS export task in place. Event 1065 starts the F5 task after the PFX is on the share.

## Manual run

Plan only. This still logs in, so the BIG-IP audit log shows a token login. It does not upload or modify.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\Invoke-IisCertExportAndF5.ps1 -WhatIf
```

Export, then publish:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\Invoke-IisCertExportAndF5.ps1
```

Publish an export that already finished:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\Publish-PfxToF5.ps1 -ConfigPath C:\Scripts\f5-publish.config.json
```

## Virtual servers with more than one certificate

Use one client-ssl profile per certificate (SNI). The script selects the profile whose `serverName` matches the CN. If the virtual server has several client-ssl profiles and none match, set `replaceClientSslProfile` to the short profile name. If it has exactly one, that one is replaced.

A profile that already holds multiple `cert-key-chain` entries is left alone. Split it first. This script will not detach it.

`sniDefault` is copied from the profile being replaced unless the config sets it.

## Rollback

The previous profile name is stored in `C:\Logs\F5CertPublish_state.json` (no secrets; Administrators and SYSTEM only).

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\Publish-PfxToF5.ps1 -Rollback
```

That puts the virtual server back on the previous client-ssl profile. It does not delete the new certificate or profile.

## TLS to the management interface

By default the machine trust store must accept the BIG-IP management certificate.

If the management certificate is a private CA, set `f5.managementCertSha256` to the SHA256 of that leaf certificate. Validation then requires that exact certificate.

`-AllowUntrustedManagementCert` turns validation off for the process. Do not use it on a production task.

## Staged PFX

The upload lands in `/var/config/rest/downloads/` under a random `iisauto_` name and is removed with `unix-rm` after install. Exit code 3 means the certificate may be installed but the PFX is still on the BIG-IP. Delete that path. `-AllowBashCleanup` is off unless your change policy allows `util bash`.

The private key is not extracted to a PEM on the IIS host. Intermediates are uploaded as a separate chain. The leaf certificate is not used as the chain.

## Logs

| Location | Content |
|---|---|
| `C:\Logs\F5CertPublish_*.log` | File log. Passwords are stripped. |
| Application log, source `F5CertPublish` | Same lines. See [docs/F5-EVENTIDS.md](docs/F5-EVENTIDS.md). |

Exit codes: `0` success, `1` export failed, `2` F5 publish failed, `3` publish ran but a staged PFX could not be deleted.

## Not included

This does not replace `iis_cert_automation` and it does not renew the certificate. Renewal stays on the existing CCS task. Node-hostname PFX files used only by IIS are not sent to F5 unless you list them under `certificates`.
