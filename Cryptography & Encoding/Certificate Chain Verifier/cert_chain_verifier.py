#!/usr/bin/env python3
"""
Certificate Chain Verifier

A comprehensive tool for validating SSL/TLS certificate chains from various sources.
This script can verify certificates from files, URLs, or raw certificate data.

Author: Assistant
License: MIT
Version: 1.0.0

Usage Examples:
    # Verify certificate chain from a website
    python cert_chain_verifier.py --url https://www.google.com

    # Verify certificate from a file
    python cert_chain_verifier.py --file /path/to/certificate.pem

    # Verify with custom CA bundle
    python cert_chain_verifier.py --url https://example.com --ca-bundle /path/to/ca-bundle.pem

    # Show detailed certificate information
    python cert_chain_verifier.py --url https://example.com --verbose

    # Export certificate chain to file
    python cert_chain_verifier.py --url https://example.com --export chain.pem
"""

import argparse
import ssl
import socket
import sys
import os
import logging
import json
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import List, Dict, Optional, Tuple
import tempfile
import subprocess


class CertificateInfo:
    """Container for certificate information."""
    
    def __init__(self, cert_der: bytes):
        """Initialize with DER-encoded certificate data."""
        self.cert_der = cert_der
        self.cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
        self._parse_certificate()
    
    def _parse_certificate(self):
        """Parse certificate information using OpenSSL."""
        try:
            # Create temporary file for OpenSSL processing
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_file:
                temp_file.write(self.cert_der)
                temp_path = temp_file.name
            
            try:
                # Use OpenSSL to extract certificate information
                result = subprocess.run([
                    'openssl', 'x509', '-in', temp_path, '-inform', 'DER',
                    '-noout', '-text'
                ], capture_output=True, text=True, check=True)
                
                self._parse_openssl_output(result.stdout)
            finally:
                os.unlink(temp_path)
                
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback to basic parsing if OpenSSL is not available
            self._basic_parse()
    
    def _parse_openssl_output(self, output: str):
        """Parse OpenSSL text output to extract certificate details."""
        lines = output.split('\n')
        self.subject = self._extract_field(lines, 'Subject:')
        self.issuer = self._extract_field(lines, 'Issuer:')
        self.serial_number = self._extract_field(lines, 'Serial Number:')
        self.not_before = self._extract_date(lines, 'Not Before:')
        self.not_after = self._extract_date(lines, 'Not After:')
        self.signature_algorithm = self._extract_field(lines, 'Signature Algorithm:')
        self.public_key_algorithm = self._extract_field(lines, 'Public Key Algorithm:')
        self.san_list = self._extract_san(lines)
    
    def _extract_field(self, lines: List[str], field_name: str) -> str:
        """Extract a specific field from OpenSSL output."""
        for line in lines:
            if field_name in line:
                return line.split(field_name, 1)[1].strip()
        return "Unknown"
    
    def _extract_date(self, lines: List[str], field_name: str) -> Optional[datetime]:
        """Extract and parse date field from OpenSSL output."""
        date_str = self._extract_field(lines, field_name)
        if date_str == "Unknown":
            return None
        try:
            # Parse OpenSSL date format
            return datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
        except ValueError:
            return None
    
    def _extract_san(self, lines: List[str]) -> List[str]:
        """Extract Subject Alternative Names from OpenSSL output."""
        san_list = []
        in_san_section = False
        
        for line in lines:
            if 'X509v3 Subject Alternative Name:' in line:
                in_san_section = True
                continue
            
            if in_san_section:
                if line.strip().startswith('DNS:') or line.strip().startswith('IP:'):
                    # Parse SAN entries
                    entries = line.strip().split(', ')
                    for entry in entries:
                        if ':' in entry:
                            san_list.append(entry)
                    break
        
        return san_list
    
    def _basic_parse(self):
        """Basic certificate parsing when OpenSSL is not available."""
        # This is a simplified fallback - in production, you might want
        # to use a library like cryptography for proper parsing
        self.subject = "Unknown (OpenSSL not available)"
        self.issuer = "Unknown (OpenSSL not available)"
        self.serial_number = "Unknown"
        self.not_before = None
        self.not_after = None
        self.signature_algorithm = "Unknown"
        self.public_key_algorithm = "Unknown"
        self.san_list = []
    
    def is_expired(self) -> bool:
        """Check if certificate is expired."""
        if self.not_after is None:
            return False
        return datetime.now(timezone.utc) > self.not_after.replace(tzinfo=timezone.utc)
    
    def days_until_expiry(self) -> Optional[int]:
        """Calculate days until certificate expires."""
        if self.not_after is None:
            return None
        delta = self.not_after.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)
        return delta.days


class CertificateChainVerifier:
    """Main class for certificate chain verification."""
    
    def __init__(self, ca_bundle_path: Optional[str] = None, verbose: bool = False):
        """
        Initialize the certificate chain verifier.
        
        Args:
            ca_bundle_path: Path to custom CA bundle file
            verbose: Enable verbose logging
        """
        self.ca_bundle_path = ca_bundle_path
        self.verbose = verbose
        self.logger = self._setup_logging()
    
    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration."""
        logger = logging.getLogger('CertChainVerifier')
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        return logger
    
    def verify_url(self, url: str, port: Optional[int] = None) -> Dict:
        """
        Verify certificate chain for a given URL.
        
        Args:
            url: URL to verify (e.g., https://example.com)
            port: Custom port number (defaults to 443 for HTTPS)
            
        Returns:
            Dictionary containing verification results
        """
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        
        if not hostname:
            raise ValueError("Invalid URL provided")
        
        # Determine port
        if port is None:
            port = parsed_url.port or 443
        
        self.logger.info(f"Verifying certificate chain for {hostname}:{port}")
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Load custom CA bundle if provided
            if self.ca_bundle_path:
                context.load_verify_locations(self.ca_bundle_path)
            
            # Connect and get certificate chain
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get peer certificate chain
                    cert_chain = ssock.getpeercert_chain()
                    
                    if not cert_chain:
                        raise ssl.SSLError("No certificate chain received")
                    
                    # Parse certificates
                    certificates = []
                    for cert_der in cert_chain:
                        cert_info = CertificateInfo(cert_der)
                        certificates.append(cert_info)
                    
                    # Verify the chain
                    verification_result = self._verify_chain(certificates, hostname)
                    
                    return {
                        'hostname': hostname,
                        'port': port,
                        'verified': verification_result['verified'],
                        'certificates': certificates,
                        'chain_length': len(certificates),
                        'verification_details': verification_result,
                        'timestamp': datetime.now().isoformat()
                    }
        
        except Exception as e:
            self.logger.error(f"Error verifying {hostname}:{port} - {str(e)}")
            return {
                'hostname': hostname,
                'port': port,
                'verified': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def verify_file(self, file_path: str) -> Dict:
        """
        Verify certificate chain from a PEM file.
        
        Args:
            file_path: Path to certificate file
            
        Returns:
            Dictionary containing verification results
        """
        self.logger.info(f"Verifying certificate from file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                pem_data = f.read()
            
            # Parse PEM certificates
            certificates = self._parse_pem_certificates(pem_data)
            
            if not certificates:
                raise ValueError("No valid certificates found in file")
            
            # Verify the chain
            verification_result = self._verify_chain(certificates)
            
            return {
                'file_path': file_path,
                'verified': verification_result['verified'],
                'certificates': certificates,
                'chain_length': len(certificates),
                'verification_details': verification_result,
                'timestamp': datetime.now().isoformat()
            }
        
        except Exception as e:
            self.logger.error(f"Error verifying file {file_path} - {str(e)}")
            return {
                'file_path': file_path,
                'verified': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _parse_pem_certificates(self, pem_data: str) -> List[CertificateInfo]:
        """Parse PEM-encoded certificates."""
        certificates = []
        cert_blocks = []
        
        lines = pem_data.strip().split('\n')
        current_cert = []
        in_cert = False
        
        for line in lines:
            if '-----BEGIN CERTIFICATE-----' in line:
                in_cert = True
                current_cert = [line]
            elif '-----END CERTIFICATE-----' in line:
                current_cert.append(line)
                cert_blocks.append('\n'.join(current_cert))
                current_cert = []
                in_cert = False
            elif in_cert:
                current_cert.append(line)
        
        # Convert PEM to DER and create CertificateInfo objects
        for pem_cert in cert_blocks:
            try:
                der_cert = ssl.PEM_cert_to_DER_cert(pem_cert)
                certificates.append(CertificateInfo(der_cert))
            except Exception as e:
                self.logger.warning(f"Failed to parse certificate: {e}")
        
        return certificates
    
    def _verify_chain(self, certificates: List[CertificateInfo], 
                     hostname: Optional[str] = None) -> Dict:
        """
        Verify the certificate chain.
        
        Args:
            certificates: List of certificates in the chain
            hostname: Hostname to verify against (for hostname verification)
            
        Returns:
            Dictionary with verification details
        """
        verification_details = {
            'verified': False,
            'issues': [],
            'warnings': []
        }
        
        if not certificates:
            verification_details['issues'].append("No certificates provided")
            return verification_details
        
        # Check each certificate
        for i, cert in enumerate(certificates):
            cert_name = f"Certificate {i+1}"
            
            # Check expiration
            if cert.is_expired():
                verification_details['issues'].append(
                    f"{cert_name} is expired"
                )
            elif cert.days_until_expiry() is not None:
                days_left = cert.days_until_expiry()
                if days_left < 30:
                    verification_details['warnings'].append(
                        f"{cert_name} expires in {days_left} days"
                    )
        
        # Basic chain validation (simplified)
        if len(certificates) > 1:
            # Check if certificates form a proper chain
            for i in range(len(certificates) - 1):
                current_cert = certificates[i]
                next_cert = certificates[i + 1]
                
                # In a proper chain, current cert should be issued by next cert
                if current_cert.issuer != next_cert.subject:
                    verification_details['warnings'].append(
                        f"Certificate {i+1} issuer doesn't match Certificate {i+2} subject"
                    )
        
        # Hostname verification (if hostname provided)
        if hostname and certificates:
            leaf_cert = certificates[0]  # First certificate is the leaf
            if not self._verify_hostname(leaf_cert, hostname):
                verification_details['issues'].append(
                    f"Hostname {hostname} doesn't match certificate"
                )
        
        # Overall verification result
        verification_details['verified'] = len(verification_details['issues']) == 0
        
        return verification_details
    
    def _verify_hostname(self, cert: CertificateInfo, hostname: str) -> bool:
        """Verify if hostname matches certificate."""
        # Extract CN from subject
        subject_cn = None
        if 'CN=' in cert.subject:
            cn_part = cert.subject.split('CN=')[1].split(',')[0].strip()
            subject_cn = cn_part
        
        # Check subject CN
        if subject_cn and self._match_hostname(hostname, subject_cn):
            return True
        
        # Check SAN entries
        for san_entry in cert.san_list:
            if san_entry.startswith('DNS:'):
                san_hostname = san_entry[4:]
                if self._match_hostname(hostname, san_hostname):
                    return True
        
        return False
    
    def _match_hostname(self, hostname: str, cert_hostname: str) -> bool:
        """Check if hostname matches certificate hostname (including wildcards)."""
        if hostname.lower() == cert_hostname.lower():
            return True
        
        # Handle wildcards
        if cert_hostname.startswith('*.'):
            cert_domain = cert_hostname[2:]
            if hostname.endswith('.' + cert_domain):
                return True
        
        return False
    
    def export_chain(self, result: Dict, output_path: str):
        """Export certificate chain to a file."""
        if 'certificates' not in result:
            raise ValueError("No certificates in result to export")
        
        with open(output_path, 'w') as f:
            for i, cert in enumerate(result['certificates']):
                f.write(f"# Certificate {i+1}\n")
                f.write(f"# Subject: {cert.subject}\n")
                f.write(f"# Issuer: {cert.issuer}\n")
                f.write(cert.cert_pem)
                f.write("\n")
        
        self.logger.info(f"Certificate chain exported to {output_path}")


def print_verification_result(result: Dict, verbose: bool = False):
    """Print verification results in a formatted way."""
    print("\n" + "="*60)
    print("CERTIFICATE CHAIN VERIFICATION RESULT")
    print("="*60)
    
    if 'hostname' in result:
        print(f"Hostname: {result['hostname']}")
        print(f"Port: {result['port']}")
    elif 'file_path' in result:
        print(f"File: {result['file_path']}")
    
    print(f"Verification Status: {'✓ PASSED' if result.get('verified') else '✗ FAILED'}")
    
    if 'error' in result:
        print(f"Error: {result['error']}")
        return
    
    print(f"Chain Length: {result.get('chain_length', 0)} certificate(s)")
    print(f"Verification Time: {result['timestamp']}")
    
    # Print verification details
    if 'verification_details' in result:
        details = result['verification_details']
        
        if details.get('issues'):
            print(f"\nISSUES ({len(details['issues'])}):")
            for issue in details['issues']:
                print(f"  ✗ {issue}")
        
        if details.get('warnings'):
            print(f"\nWARNINGS ({len(details['warnings'])}):")
            for warning in details['warnings']:
                print(f"  ⚠ {warning}")
        
        if not details.get('issues') and not details.get('warnings'):
            print("\n✓ No issues found")
    
    # Print certificate details if verbose
    if verbose and 'certificates' in result:
        print(f"\nCERTIFICATE DETAILS:")
        print("-" * 40)
        
        for i, cert in enumerate(result['certificates']):
            print(f"\nCertificate {i+1}:")
            print(f"  Subject: {cert.subject}")
            print(f"  Issuer: {cert.issuer}")
            print(f"  Serial Number: {cert.serial_number}")
            print(f"  Not Before: {cert.not_before}")
            print(f"  Not After: {cert.not_after}")
            print(f"  Signature Algorithm: {cert.signature_algorithm}")
            print(f"  Public Key Algorithm: {cert.public_key_algorithm}")
            
            if cert.san_list:
                print(f"  Subject Alternative Names:")
                for san in cert.san_list:
                    print(f"    {san}")
            
            if cert.days_until_expiry() is not None:
                days = cert.days_until_expiry()
                if days < 0:
                    print(f"  Status: ✗ EXPIRED ({abs(days)} days ago)")
                elif days < 30:
                    print(f"  Status: ⚠ EXPIRES SOON ({days} days)")
                else:
                    print(f"  Status: ✓ VALID ({days} days remaining)")


def main():
    """Main function to handle command line arguments and execute verification."""
    parser = argparse.ArgumentParser(
        description="Certificate Chain Verifier - Validate SSL/TLS certificate chains",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url https://www.google.com
  %(prog)s --file certificate.pem --verbose
  %(prog)s --url https://example.com --ca-bundle custom-ca.pem
  %(prog)s --url https://example.com --export chain.pem
        """
    )
    
    # Input source arguments (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--url', 
        help='URL to verify certificate chain (e.g., https://example.com)'
    )
    input_group.add_argument(
        '--file', 
        help='Path to certificate file (PEM format)'
    )
    
    # Optional arguments
    parser.add_argument(
        '--port',
        type=int,
        help='Custom port number (default: 443 for HTTPS)'
    )
    parser.add_argument(
        '--ca-bundle',
        help='Path to custom CA bundle file'
    )
    parser.add_argument(
        '--export',
        help='Export certificate chain to specified file'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output with detailed certificate information'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results in JSON format'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.ca_bundle and not os.path.isfile(args.ca_bundle):
        print(f"Error: CA bundle file not found: {args.ca_bundle}", file=sys.stderr)
        sys.exit(1)
    
    if args.file and not os.path.isfile(args.file):
        print(f"Error: Certificate file not found: {args.file}", file=sys.stderr)
        sys.exit(1)
    
    # Create verifier instance
    verifier = CertificateChainVerifier(
        ca_bundle_path=args.ca_bundle,
        verbose=args.verbose
    )
    
    # Perform verification
    try:
        if args.url:
            result = verifier.verify_url(args.url, args.port)
        else:  # args.file
            result = verifier.verify_file(args.file)
        
        # Export chain if requested
        if args.export:
            verifier.export_chain(result, args.export)
        
        # Output results
        if args.json:
            # Convert CertificateInfo objects to dictionaries for JSON serialization
            if 'certificates' in result:
                cert_dicts = []
                for cert in result['certificates']:
                    cert_dict = {
                        'subject': cert.subject,
                        'issuer': cert.issuer,
                        'serial_number': cert.serial_number,
                        'not_before': cert.not_before.isoformat() if cert.not_before else None,
                        'not_after': cert.not_after.isoformat() if cert.not_after else None,
                        'signature_algorithm': cert.signature_algorithm,
                        'public_key_algorithm': cert.public_key_algorithm,
                        'san_list': cert.san_list,
                        'is_expired': cert.is_expired(),
                        'days_until_expiry': cert.days_until_expiry()
                    }
                    cert_dicts.append(cert_dict)
                result['certificates'] = cert_dicts
            
            print(json.dumps(result, indent=2, default=str))
        else:
            print_verification_result(result, args.verbose)
        
        # Exit with appropriate code
        sys.exit(0 if result.get('verified', False) else 1)
    
    except KeyboardInterrupt:
        print("\nVerification interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
