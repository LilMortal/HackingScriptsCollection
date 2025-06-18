#!/usr/bin/env python3
"""
RSA Key Size Checker

A comprehensive tool for analyzing RSA keys and certificates to determine their key sizes
and security levels. Supports multiple input formats including PEM, DER, and direct 
public key analysis.

Usage:
    python rsa_key_checker.py --file certificate.pem
    python rsa_key_checker.py --file private_key.pem --key-type private
    python rsa_key_checker.py --url https://example.com --port 443
    python rsa_key_checker.py --modulus 0x1234567890abcdef... --exponent 65537

Author: Claude AI Assistant
License: MIT
Version: 1.0.0
"""

import argparse
import sys
import os
import ssl
import socket
import base64
import binascii
from typing import Optional, Tuple, Dict, Any
from datetime import datetime


class RSAKeyAnalyzer:
    """
    A class for analyzing RSA keys and determining their security characteristics.
    """
    
    # Security level mappings based on NIST recommendations
    SECURITY_LEVELS = {
        512: "Critically Weak - Immediately replace",
        768: "Very Weak - Replace immediately", 
        1024: "Weak - Replace soon",
        2048: "Adequate - Current minimum standard",
        3072: "Good - Recommended for new deployments",
        4096: "Strong - High security applications",
        8192: "Very Strong - Maximum practical security"
    }
    
    def __init__(self):
        """Initialize the RSA Key Analyzer."""
        pass
    
    def analyze_key_size(self, key_size: int) -> Dict[str, Any]:
        """
        Analyze the security level of an RSA key based on its size.
        
        Args:
            key_size (int): The RSA key size in bits
            
        Returns:
            Dict[str, Any]: Analysis results including security level and recommendations
        """
        # Find the closest security level
        closest_level = min(self.SECURITY_LEVELS.keys(), 
                          key=lambda x: abs(x - key_size))
        
        # Determine if the key size is standard
        is_standard = key_size in self.SECURITY_LEVELS
        
        # Calculate equivalent symmetric key strength (rough approximation)
        # RSA key strength is approximately log2(n)/2 where n is the key size
        equivalent_symmetric = max(1, int(key_size ** 0.5 / 10))
        
        analysis = {
            'key_size': key_size,
            'is_standard_size': is_standard,
            'security_level': self.SECURITY_LEVELS.get(closest_level, "Unknown"),
            'closest_standard': closest_level,
            'equivalent_symmetric_bits': equivalent_symmetric,
            'is_secure': key_size >= 2048,
            'recommendation': self._get_recommendation(key_size)
        }
        
        return analysis
    
    def _get_recommendation(self, key_size: int) -> str:
        """
        Get security recommendations based on key size.
        
        Args:
            key_size (int): The RSA key size in bits
            
        Returns:
            str: Security recommendation
        """
        if key_size < 1024:
            return "Replace immediately - cryptographically broken"
        elif key_size < 2048:
            return "Replace as soon as possible - vulnerable to attack"
        elif key_size < 3072:
            return "Acceptable for current use, consider upgrading for new deployments"
        elif key_size < 4096:
            return "Good security level, suitable for most applications"
        else:
            return "Excellent security level, suitable for high-security applications"
    
    def extract_key_from_pem(self, pem_content: str, key_type: str = 'auto') -> Optional[int]:
        """
        Extract RSA key size from PEM formatted content.
        
        Args:
            pem_content (str): PEM formatted key or certificate content
            key_type (str): Type of key ('private', 'public', 'certificate', 'auto')
            
        Returns:
            Optional[int]: RSA key size in bits, or None if extraction failed
        """
        try:
            # Remove PEM headers and decode base64
            lines = pem_content.strip().split('\n')
            b64_content = ''
            in_key = False
            
            for line in lines:
                line = line.strip()
                if line.startswith('-----BEGIN'):
                    in_key = True
                    continue
                elif line.startswith('-----END'):
                    break
                elif in_key:
                    b64_content += line
            
            if not b64_content:
                return None
                
            der_data = base64.b64decode(b64_content)
            return self._extract_key_from_der(der_data, key_type)
            
        except Exception as e:
            print(f"Error extracting key from PEM: {e}")
            return None
    
    def _extract_key_from_der(self, der_data: bytes, key_type: str = 'auto') -> Optional[int]:
        """
        Extract RSA key size from DER formatted data.
        This is a simplified DER parser for RSA keys.
        
        Args:
            der_data (bytes): DER formatted key data
            key_type (str): Type of key
            
        Returns:
            Optional[int]: RSA key size in bits, or None if extraction failed
        """
        try:
            # This is a simplified DER parser - in production, use cryptography library
            # Look for RSA modulus in the DER structure
            
            # For certificates, the public key is embedded deeper in the structure
            # For private keys, the modulus is typically the first large integer after the version
            # For public keys, the modulus is typically the first large integer
            
            modulus_length = self._find_rsa_modulus_length(der_data)
            if modulus_length:
                return modulus_length * 8  # Convert bytes to bits
                
            return None
            
        except Exception as e:
            print(f"Error extracting key from DER: {e}")
            return None
    
    def _find_rsa_modulus_length(self, data: bytes) -> Optional[int]:
        """
        Find the RSA modulus length in DER data by looking for large integers.
        This is a heuristic approach.
        
        Args:
            data (bytes): DER formatted data
            
        Returns:
            Optional[int]: Modulus length in bytes
        """
        try:
            i = 0
            while i < len(data) - 4:
                # Look for INTEGER tag (0x02)
                if data[i] == 0x02:
                    # Get length
                    length_byte = data[i + 1]
                    
                    if length_byte & 0x80:  # Long form length
                        length_bytes = length_byte & 0x7F
                        if i + 1 + length_bytes >= len(data):
                            i += 1
                            continue
                            
                        length = 0
                        for j in range(length_bytes):
                            length = (length << 8) | data[i + 2 + j]
                        
                        # If this looks like an RSA modulus (large integer, typically 128-1024 bytes)
                        if 64 <= length <= 1024:
                            return length
                        
                        i += 2 + length_bytes + length
                    else:
                        # Short form length
                        if 64 <= length_byte <= 255:
                            return length_byte
                        i += 2 + length_byte
                else:
                    i += 1
            
            return None
            
        except Exception:
            return None
    
    def get_key_from_url(self, hostname: str, port: int = 443) -> Optional[int]:
        """
        Extract RSA key size from an SSL/TLS certificate via network connection.
        
        Args:
            hostname (str): The hostname to connect to
            port (int): The port to connect to (default: 443)
            
        Returns:
            Optional[int]: RSA key size in bits, or None if extraction failed
        """
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert_chain()[0]
                    
            # Extract key size from certificate
            return self._extract_key_from_der(cert_der, 'certificate')
            
        except Exception as e:
            print(f"Error connecting to {hostname}:{port}: {e}")
            return None
    
    def analyze_modulus_exponent(self, modulus: int, exponent: int) -> Dict[str, Any]:
        """
        Analyze RSA key given modulus and exponent.
        
        Args:
            modulus (int): RSA modulus (n)
            exponent (int): RSA public exponent (e)
            
        Returns:
            Dict[str, Any]: Complete analysis of the RSA key
        """
        # Calculate key size in bits
        key_size = modulus.bit_length()
        
        # Basic analysis
        analysis = self.analyze_key_size(key_size)
        
        # Add modulus and exponent specific analysis
        analysis.update({
            'modulus': modulus,
            'exponent': exponent,
            'modulus_hex': hex(modulus),
            'exponent_hex': hex(exponent),
            'is_standard_exponent': exponent in [3, 17, 65537],
            'exponent_analysis': self._analyze_exponent(exponent)
        })
        
        return analysis
    
    def _analyze_exponent(self, exponent: int) -> str:
        """
        Analyze the RSA public exponent.
        
        Args:
            exponent (int): RSA public exponent
            
        Returns:
            str: Analysis of the exponent
        """
        if exponent == 65537:
            return "Standard exponent (2^16 + 1) - recommended"
        elif exponent == 3:
            return "Small exponent - fast but potentially vulnerable if not used carefully"
        elif exponent == 17:
            return "Small exponent (2^4 + 1) - reasonable choice"
        elif exponent % 2 == 0:
            return "Even exponent - invalid for RSA"
        elif exponent < 65537:
            return "Small exponent - potentially vulnerable"
        else:
            return "Large exponent - unusual but not necessarily problematic"


def parse_arguments() -> argparse.Namespace:
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Analyze RSA key sizes and security levels",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --file certificate.pem
  %(prog)s --file private_key.pem --key-type private
  %(prog)s --url google.com --port 443
  %(prog)s --key-size 2048
  %(prog)s --modulus 0x1234... --exponent 65537
        """
    )
    
    # Input methods (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--file', '-f',
        help='Path to PEM/DER file containing RSA key or certificate'
    )
    input_group.add_argument(
        '--url', '-u',
        help='URL/hostname to retrieve SSL certificate from'
    )
    input_group.add_argument(
        '--key-size', '-s', type=int,
        help='Directly specify RSA key size in bits for analysis'
    )
    input_group.add_argument(
        '--modulus', '-m',
        help='RSA modulus (as hex string starting with 0x or decimal)'
    )
    
    # Optional arguments
    parser.add_argument(
        '--port', '-p', type=int, default=443,
        help='Port to use for URL connections (default: 443)'
    )
    parser.add_argument(
        '--key-type', '-t', choices=['auto', 'private', 'public', 'certificate'],
        default='auto',
        help='Type of key in file (default: auto-detect)'
    )
    parser.add_argument(
        '--exponent', '-e', type=str, default='65537',
        help='RSA public exponent (required with --modulus, default: 65537)'
    )
    parser.add_argument(
        '--format', choices=['text', 'json'], default='text',
        help='Output format (default: text)'
    )
    parser.add_argument(
        '--verbose', '-v', action='store_true',
        help='Enable verbose output'
    )
    
    return parser.parse_args()


def format_output(analysis: Dict[str, Any], output_format: str, verbose: bool = False) -> str:
    """
    Format the analysis results for output.
    
    Args:
        analysis (Dict[str, Any]): Analysis results
        output_format (str): Output format ('text' or 'json')
        verbose (bool): Whether to include verbose information
        
    Returns:
        str: Formatted output string
    """
    if output_format == 'json':
        import json
        # Remove non-serializable items for JSON output
        json_analysis = {k: v for k, v in analysis.items() 
                        if k not in ['modulus'] or isinstance(v, (int, str, bool, list, dict))}
        return json.dumps(json_analysis, indent=2)
    
    # Text format
    output = []
    output.append("="*60)
    output.append("RSA Key Analysis Results")
    output.append("="*60)
    
    output.append(f"Key Size: {analysis['key_size']} bits")
    output.append(f"Security Level: {analysis['security_level']}")
    output.append(f"Is Standard Size: {'Yes' if analysis['is_standard_size'] else 'No'}")
    output.append(f"Is Secure: {'Yes' if analysis['is_secure'] else 'No'}")
    
    if not analysis['is_standard_size']:
        output.append(f"Closest Standard Size: {analysis['closest_standard']} bits")
    
    output.append(f"Equivalent Symmetric Key Strength: ~{analysis['equivalent_symmetric_bits']} bits")
    output.append("")
    output.append("Recommendation:")
    output.append(f"  {analysis['recommendation']}")
    
    if verbose and 'exponent' in analysis:
        output.append("")
        output.append("Detailed Information:")
        output.append(f"  Public Exponent: {analysis['exponent']}")
        output.append(f"  Exponent Analysis: {analysis['exponent_analysis']}")
        output.append(f"  Standard Exponent: {'Yes' if analysis['is_standard_exponent'] else 'No'}")
        
        if 'modulus_hex' in analysis and len(str(analysis['modulus_hex'])) < 200:
            output.append(f"  Modulus (hex): {analysis['modulus_hex']}")
    
    output.append("")
    output.append("Security Guidelines:")
    output.append("  • Minimum recommended: 2048 bits")
    output.append("  • Good for new deployments: 3072+ bits")
    output.append("  • High security applications: 4096+ bits")
    output.append("  • Keys under 2048 bits should be replaced immediately")
    
    return "\n".join(output)


def main():
    """
    Main function to run the RSA Key Size Checker.
    """
    try:
        args = parse_arguments()
        analyzer = RSAKeyAnalyzer()
        analysis = None
        
        if args.file:
            # Analyze file
            if not os.path.exists(args.file):
                print(f"Error: File '{args.file}' does not exist.")
                sys.exit(1)
            
            try:
                with open(args.file, 'r') as f:
                    content = f.read()
                
                key_size = analyzer.extract_key_from_pem(content, args.key_type)
                if key_size:
                    analysis = analyzer.analyze_key_size(key_size)
                else:
                    print(f"Error: Could not extract RSA key from '{args.file}'")
                    sys.exit(1)
                    
            except Exception as e:
                print(f"Error reading file '{args.file}': {e}")
                sys.exit(1)
        
        elif args.url:
            # Analyze URL certificate
            if args.verbose:
                print(f"Connecting to {args.url}:{args.port}...")
            
            key_size = analyzer.get_key_from_url(args.url, args.port)
            if key_size:
                analysis = analyzer.analyze_key_size(key_size)
            else:
                print(f"Error: Could not retrieve certificate from {args.url}:{args.port}")
                sys.exit(1)
        
        elif args.key_size:
            # Analyze specified key size
            if args.key_size <= 0:
                print("Error: Key size must be positive")
                sys.exit(1)
            
            analysis = analyzer.analyze_key_size(args.key_size)
        
        elif args.modulus:
            # Analyze modulus and exponent
            try:
                # Parse modulus
                if args.modulus.startswith('0x') or args.modulus.startswith('0X'):
                    modulus = int(args.modulus, 16)
                else:
                    modulus = int(args.modulus)
                
                # Parse exponent
                if args.exponent.startswith('0x') or args.exponent.startswith('0X'):
                    exponent = int(args.exponent, 16)
                else:
                    exponent = int(args.exponent)
                
                analysis = analyzer.analyze_modulus_exponent(modulus, exponent)
                
            except ValueError as e:
                print(f"Error parsing modulus or exponent: {e}")
                sys.exit(1)
        
        # Output results
        if analysis:
            output = format_output(analysis, args.format, args.verbose)
            print(output)
        else:
            print("Error: No analysis could be performed")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        if args.verbose if 'args' in locals() else False:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
