"""
SCEP Integration for Pytune Windows Device Class

Add this code to device/windows.py to enable SCEP certificate requests during check-in.

INTEGRATION INSTRUCTIONS:
1. Add this import at the top of windows.py:
   from utils.scep import SCEPClient

2. Add this method to the Windows class:
"""

def process_scep_profiles(self, cert_csp_nodes):
    """
    Process SCEP certificate profiles from Intune check-in
    
    Args:
        cert_csp_nodes (dict): Certificate CSP configuration nodes
    
    Returns:
        list: Paths to downloaded SCEP certificate PFX files
    """
    scep_client = SCEPClient(self.logger, self.proxy)
    pfx_files = []
    
    # Parse SCEP configuration from CSP nodes
    scep_config = scep_client.parse_scep_profile_from_cert_csp(cert_csp_nodes)
    
    if scep_config.get('scep_url'):
        self.logger.info("[!] SCEP certificate profile detected!")
        self.logger.info(f"[*] SCEP URL: {scep_config['scep_url']}")
        
        # Request certificate
        pfx_path = scep_client.request_scep_certificate(
            scep_config=scep_config,
            device_name=self.device_name,
            device_id=self.deviceid,
            user_upn=None  # Set to user UPN for user certificates
        )
        
        if pfx_path:
            self.logger.info(f"[+] Successfully obtained SCEP certificate: {pfx_path}")
            pfx_files.append(pfx_path)
        else:
            self.logger.error("[-] Failed to obtain SCEP certificate")
    
    return pfx_files


"""
3. Modify the checkin() method in windows.py to call process_scep_profiles:

   Find the section where configuration profiles are collected (around line 400-500)
   After the existing profile parsing code, add:

   # Collect Certificate CSP nodes
   cert_csp_nodes = {}
   for uri, value in configurations.items():
       if '/ClientCertificateInstall/SCEP/' in uri:
           cert_csp_nodes[uri] = value
   
   # Process SCEP profiles if found
   if cert_csp_nodes:
       scep_pfx_files = self.process_scep_profiles(cert_csp_nodes)
       if scep_pfx_files:
           self.logger.info(f"[+] Downloaded {len(scep_pfx_files)} SCEP certificate(s)")
"""

# Example usage in pytune.py:
"""
def main():
    # ... existing pytune code ...
    
    # When calling checkin:
    python3 pytune.py checkin -o Windows -d Windows_pytune \\
        -c Windows_pytune.pfx -m Windows_pytune_mdm.pfx \\
        -u testuser@tenant.onmicrosoft.com -p password
    
    # SCEP certificates will be automatically requested if SCEP profiles
    # are pushed by Intune during check-in
    
    # Output will show:
    # [!] SCEP certificate profile detected!
    # [*] SCEP URL: https://ndes.corp.com/certsrv/mscep/mscep.dll
    # [*] Requesting SCEP certificate for: CN=device-id
    # [+] Successfully obtained SCEP certificate: Windows_pytune_scep.pfx
    # [*] PFX password: password
"""
