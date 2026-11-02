# F5CertPublish event IDs

Source: `F5CertPublish`. Log: `Application`.

| ID | Level | Meaning |
|---|---|---|
| 2100 | Information | Publish started |
| 2110 | Information | Credential loaded or iControl token issued. The secret is not in the message. |
| 2112 | Information or Warning | Token revoke succeeded or failed |
| 2120 | Information or Warning | Active/standalone device, or no device-trust endpoint |
| 2121 | Error | Device is not active |
| 2130 | Information | PFX read. Thumbprint and expiry only. |
| 2131 | Error | PFX missing or CN does not match the config |
| 2140 | Information or Warning | PFX upload finished, or an upload attempt failed |
| 2141 | Information | PKCS#12 installed |
| 2142 | Information | Intermediate chain installed |
| 2143 | Information | Staged file deleted |
| 2144 | Error or Warning | Staged file remains. Error when the file is a PFX. |
| 2145 | Information | Crypto object already present. Upload skipped. |
| 2150 | Information | Transaction opened or client-ssl profile created |
| 2151 | Information | Virtual server now references the new profile, or rollback finished |
| 2152 | Error | Virtual server update or rollback failed |
| 2160 | Information | `tmsh save sys config` equivalent completed |
| 2161 | Information | Config sync reported In Sync |
| 2162 | Warning | Sync was requested but not confirmed |
| 2190 | Information | Publish finished with no error |
| 2191 | Error | Publish failed |
| 2192 | Warning or Information | WhatIf / plan line, or TLS validation disabled |

Certificate export events stay on source `CertificateExport`. Event **1065** is the trigger for `IIS-Cert-F5-Publish`.
