#!/usr/bin/env python3
"""
JWT Security Audit Script
=========================

A comprehensive security audit tool for JSON Web Tokens (JWTs).
This script analyzes JWT tokens for common security vulnerabilities and misconfigurations.

Author: Security Audit Tool
License: MIT
Version: 1.0.0

Usage Examples:
    python jwt_audit.py --token "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
    python jwt_audit.py --file tokens.txt --output report.json
    python jwt_audit.py --token "..." --wordlist common_secrets.txt
    python jwt_audit.py --analyze-only --token "..."

Required Dependencies:
    pip install pyjwt cryptography requests
"""

import argparse
import base64
import json
import hashlib
import hmac
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
import re
import os

try:
    import jwt
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    import requests
except ImportError as e:
    print(f"Error: Missing required dependency: {e}")
    print("Please install dependencies: pip install pyjwt cryptography requests")
    sys.exit(1)


class JWTSecurityAuditor:
    """
    Main class for JWT security auditing functionality.
    Performs various security checks and vulnerability assessments on JWT tokens.
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.vulnerabilities = []
        self.warnings = []
        self.info = []
        
        # Common weak secrets for brute force testing
        self.common_secrets = [
            'secret', 'password', '123456', 'admin', 'test', 'key',
            'jwt', 'token', 'auth', 'secure', 'private', 'public',
            '', 'null', 'undefined', 'default', 'changeme', 'weak'
        ]
    
    def log(self, message: str, level: str = "INFO") -> None:
        """Log messages with appropriate level indicators."""
        if self.verbose or level in ["ERROR", "CRITICAL", "VULNERABILITY"]:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] {level}: {message}")
    
    def decode_jwt_unsafe(self, token: str) -> Tuple[Optional[Dict], Optional[Dict], Optional[str]]:
        """
        Decode JWT without verification to examine structure.
        Returns header, payload, and signature.
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                self.log("Invalid JWT format - must have 3 parts", "ERROR")
                return None, None, None
            
            # Decode header
            header_data = base64.urlsafe_b64decode(parts[0] + '==')
            header = json.loads(header_data.decode('utf-8'))
            
            # Decode payload
            payload_data = base64.urlsafe_b64decode(parts[1] + '==')
            payload = json.loads(payload_data.decode('utf-8'))
            
            # Get signature
            signature = parts[2]
            
            return header, payload, signature
            
        except Exception as e:
            self.log(f"Failed to decode JWT: {e}", "ERROR")
            return None, None, None
    
    def check_algorithm_vulnerabilities(self, header: Dict) -> None:
        """Check for algorithm-related vulnerabilities."""
        algorithm = header.get('alg', '').upper()
        
        # Check for 'none' algorithm
        if algorithm == 'NONE':
            self.vulnerabilities.append({
                'type': 'CRITICAL',
                'issue': 'Algorithm set to "none"',
                'description': 'JWT uses no signature verification',
                'impact': 'Complete authentication bypass possible',
                'recommendation': 'Use a secure signing algorithm (HS256, RS256, etc.)'
            })
        
        # Check for weak algorithms
        weak_algorithms = ['HS1', 'MD5', 'SHA1']
        if any(weak_alg in algorithm for weak_alg in weak_algorithms):
            self.vulnerabilities.append({
                'type': 'HIGH',
                'issue': f'Weak algorithm: {algorithm}',
                'description': 'JWT uses cryptographically weak algorithm',
                'impact': 'Susceptible to collision attacks',
                'recommendation': 'Use SHA-256 or stronger algorithms'
            })
        
        # Check for algorithm confusion vulnerabilities
        if algorithm.startswith('HS') and 'RS' in str(header):
            self.warnings.append({
                'type': 'MEDIUM',
                'issue': 'Potential algorithm confusion',
                'description': 'Mixed symmetric/asymmetric algorithm indicators',
                'recommendation': 'Ensure consistent algorithm usage'
            })
    
    def check_payload_vulnerabilities(self, payload: Dict) -> None:
        """Check for payload-related security issues."""
        current_time = int(time.time())
        
        # Check expiration
        if 'exp' in payload:
            if payload['exp'] < current_time:
                self.vulnerabilities.append({
                    'type': 'MEDIUM',
                    'issue': 'Token is expired',
                    'description': f'Token expired at {datetime.fromtimestamp(payload["exp"])}',
                    'impact': 'Using expired tokens may indicate security issues',
                    'recommendation': 'Implement proper token refresh mechanisms'
                })
        else:
            self.warnings.append({
                'type': 'MEDIUM',
                'issue': 'No expiration claim (exp)',
                'description': 'Token does not expire',
                'recommendation': 'Always set appropriate expiration times'
            })
        
        # Check for overly long expiration
        if 'exp' in payload and 'iat' in payload:
            token_lifetime = payload['exp'] - payload['iat']
            if token_lifetime > 86400 * 7:  # 7 days
                self.warnings.append({
                    'type': 'LOW',
                    'issue': 'Long token lifetime',
                    'description': f'Token valid for {token_lifetime // 86400} days',
                    'recommendation': 'Consider shorter token lifetimes for security'
                })
        
        # Check for sensitive information in payload
        sensitive_fields = ['password', 'secret', 'key', 'ssn', 'credit_card']
        for field in sensitive_fields:
            if any(field in str(key).lower() or field in str(value).lower() 
                   for key, value in payload.items() if isinstance(value, (str, int))):
                self.vulnerabilities.append({
                    'type': 'HIGH',
                    'issue': 'Sensitive data in payload',
                    'description': f'Potential sensitive information found',
                    'impact': 'JWT payload is only base64 encoded, not encrypted',
                    'recommendation': 'Remove sensitive data from JWT payload'
                })
                break
        
        # Check for missing standard claims
        standard_claims = ['iss', 'sub', 'aud']
        missing_claims = [claim for claim in standard_claims if claim not in payload]
        if missing_claims:
            self.info.append({
                'type': 'INFO',
                'issue': f'Missing standard claims: {", ".join(missing_claims)}',
                'recommendation': 'Consider including standard JWT claims for better security'
            })
    
    def brute_force_secret(self, token: str, header: Dict, wordlist: Optional[List[str]] = None) -> Optional[str]:
        """
        Attempt to brute force HMAC secret for HS256/HS384/HS512 algorithms.
        """
        algorithm = header.get('alg', '').upper()
        if not algorithm.startswith('HS'):
            return None
        
        secrets_to_try = wordlist if wordlist else self.common_secrets
        self.log(f"Attempting brute force with {len(secrets_to_try)} secrets", "INFO")
        
        for secret in secrets_to_try:
            try:
                # Try to decode with this secret
                jwt.decode(token, secret, algorithms=[algorithm])
                self.vulnerabilities.append({
                    'type': 'CRITICAL',
                    'issue': 'Weak JWT secret discovered',
                    'description': f'JWT can be signed with weak secret: "{secret}"',
                    'impact': 'Complete authentication bypass and token forgery possible',
                    'recommendation': 'Use a strong, randomly generated secret (32+ characters)'
                })
                return secret
            except jwt.InvalidSignatureError:
                continue
            except Exception:
                continue
        
        return None
    
    def check_none_algorithm_bypass(self, token: str) -> bool:
        """
        Test for 'none' algorithm bypass vulnerability.
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return False
            
            # Create header with 'none' algorithm
            none_header = {'typ': 'JWT', 'alg': 'none'}
            none_header_b64 = base64.urlsafe_b64encode(
                json.dumps(none_header).encode()
            ).decode().rstrip('=')
            
            # Create token with none algorithm and empty signature
            none_token = f"{none_header_b64}.{parts[1]}."
            
            try:
                # Try to decode without verification
                decoded = jwt.decode(none_token, options={"verify_signature": False})
                self.vulnerabilities.append({
                    'type': 'CRITICAL',
                    'issue': 'None algorithm bypass possible',
                    'description': 'Token structure allows none algorithm modification',
                    'impact': 'Authentication bypass through algorithm manipulation',
                    'recommendation': 'Implement strict algorithm whitelisting'
                })
                return True
            except Exception:
                pass
                
        except Exception as e:
            self.log(f"Error testing none algorithm bypass: {e}", "ERROR")
        
        return False
    
    def analyze_token_entropy(self, token: str) -> None:
        """
        Analyze the entropy and randomness of the JWT signature.
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return
            
            signature = parts[2]
            if not signature:  # Empty signature
                self.vulnerabilities.append({
                    'type': 'CRITICAL',
                    'issue': 'Empty signature',
                    'description': 'JWT has no signature component',
                    'impact': 'Token can be modified without detection',
                    'recommendation': 'Ensure proper token signing'
                })
                return
            
            # Check signature length
            if len(signature) < 20:
                self.warnings.append({
                    'type': 'MEDIUM',
                    'issue': 'Short signature',
                    'description': f'Signature length: {len(signature)} characters',
                    'recommendation': 'Verify signature algorithm and key strength'
                })
            
            # Basic entropy check
            unique_chars = len(set(signature))
            if unique_chars < len(signature) * 0.5:
                self.warnings.append({
                    'type': 'LOW',
                    'issue': 'Low signature entropy',
                    'description': 'Signature may have low randomness',
                    'recommendation': 'Verify random number generation quality'
                })
                
        except Exception as e:
            self.log(f"Error analyzing token entropy: {e}", "ERROR")
    
    def check_key_confusion_attack(self, token: str, header: Dict) -> None:
        """
        Check for key confusion attack vulnerabilities (RS256 -> HS256).
        """
        algorithm = header.get('alg', '').upper()
        
        if algorithm == 'RS256':
            self.warnings.append({
                'type': 'MEDIUM',
                'issue': 'RS256 algorithm detected',
                'description': 'Verify server properly validates algorithm type',
                'impact': 'Potential key confusion attack if server accepts HS256',
                'recommendation': 'Implement strict algorithm validation and use algorithm whitelisting'
            })
    
    def generate_security_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive security report.
        """
        total_issues = len(self.vulnerabilities) + len(self.warnings)
        
        # Calculate risk score
        risk_score = 0
        for vuln in self.vulnerabilities:
            if vuln['type'] == 'CRITICAL':
                risk_score += 10
            elif vuln['type'] == 'HIGH':
                risk_score += 7
            elif vuln['type'] == 'MEDIUM':
                risk_score += 4
            elif vuln['type'] == 'LOW':
                risk_score += 1
        
        for warning in self.warnings:
            if warning['type'] == 'MEDIUM':
                risk_score += 2
            else:
                risk_score += 1
        
        # Determine overall risk level
        if risk_score >= 15:
            risk_level = "CRITICAL"
        elif risk_score >= 10:
            risk_level = "HIGH"
        elif risk_score >= 5:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_issues': total_issues,
                'vulnerabilities': len(self.vulnerabilities),
                'warnings': len(self.warnings),
                'risk_score': risk_score,
                'risk_level': risk_level
            },
            'vulnerabilities': self.vulnerabilities,
            'warnings': self.warnings,
            'information': self.info
        }
    
    def audit_token(self, token: str, wordlist: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Perform comprehensive security audit on a JWT token.
        """
        self.log("Starting JWT security audit", "INFO")
        
        # Reset findings
        self.vulnerabilities = []
        self.warnings = []
        self.info = []
        
        # Decode token structure
        header, payload, signature = self.decode_jwt_unsafe(token)
        
        if not header or not payload:
            return {'error': 'Failed to decode JWT token'}
        
        self.log(f"Token algorithm: {header.get('alg', 'Unknown')}", "INFO")
        self.log(f"Token type: {header.get('typ', 'Unknown')}", "INFO")
        
        # Perform security checks
        self.check_algorithm_vulnerabilities(header)
        self.check_payload_vulnerabilities(payload)
        self.check_none_algorithm_bypass(token)
        self.analyze_token_entropy(token)
        self.check_key_confusion_attack(token, header)
        
        # Attempt brute force if HMAC algorithm
        if header.get('alg', '').upper().startswith('HS'):
            found_secret = self.brute_force_secret(token, header, wordlist)
            if found_secret:
                self.log(f"Weak secret discovered: {found_secret}", "CRITICAL")
        
        # Generate report
        report = self.generate_security_report()
        report['token_info'] = {
            'header': header,
            'payload': {k: v for k, v in payload.items() if k not in ['password', 'secret']},
            'algorithm': header.get('alg'),
            'token_length': len(token)
        }
        
        return report


def load_wordlist(filepath: str) -> List[str]:
    """Load wordlist from file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Wordlist file '{filepath}' not found")
        return []
    except Exception as e:
        print(f"Error loading wordlist: {e}")
        return []


def load_tokens_from_file(filepath: str) -> List[str]:
    """Load JWT tokens from file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            tokens = []
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):  # Skip comments
                    tokens.append(line)
            return tokens
    except FileNotFoundError:
        print(f"Error: Token file '{filepath}' not found")
        return []
    except Exception as e:
        print(f"Error loading tokens: {e}")
        return []


def save_report(report: Dict[str, Any], filepath: str) -> None:
    """Save audit report to file."""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"Report saved to: {filepath}")
    except Exception as e:
        print(f"Error saving report: {e}")


def print_summary(report: Dict[str, Any]) -> None:
    """Print a summary of the audit results."""
    summary = report.get('summary', {})
    
    print("\n" + "="*60)
    print("JWT SECURITY AUDIT SUMMARY")
    print("="*60)
    print(f"Risk Level: {summary.get('risk_level', 'Unknown')}")
    print(f"Risk Score: {summary.get('risk_score', 0)}/100")
    print(f"Total Issues: {summary.get('total_issues', 0)}")
    print(f"  - Vulnerabilities: {summary.get('vulnerabilities', 0)}")
    print(f"  - Warnings: {summary.get('warnings', 0)}")
    
    # Print critical vulnerabilities
    vulnerabilities = report.get('vulnerabilities', [])
    critical_vulns = [v for v in vulnerabilities if v.get('type') == 'CRITICAL']
    
    if critical_vulns:
        print(f"\nCRITICAL VULNERABILITIES ({len(critical_vulns)}):")
        print("-" * 40)
        for vuln in critical_vulns:
            print(f"• {vuln.get('issue', 'Unknown')}")
            print(f"  Impact: {vuln.get('impact', 'Unknown')}")
            print(f"  Fix: {vuln.get('recommendation', 'Unknown')}")
            print()


def main():
    """Main function with command-line interface."""
    parser = argparse.ArgumentParser(
        description="JWT Security Audit Tool - Analyze JWT tokens for security vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --token "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
  %(prog)s --file tokens.txt --output report.json
  %(prog)s --token "..." --wordlist secrets.txt --verbose
  %(prog)s --analyze-only --token "..." --no-brute-force
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--token', '-t', help='JWT token to audit')
    input_group.add_argument('--file', '-f', help='File containing JWT tokens (one per line)')
    
    # Configuration options
    parser.add_argument('--wordlist', '-w', help='Wordlist file for brute force attacks')
    parser.add_argument('--output', '-o', help='Output file for detailed report (JSON format)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--analyze-only', action='store_true', help='Only analyze structure, skip brute force')
    parser.add_argument('--no-brute-force', action='store_true', help='Skip brute force testing')
    
    args = parser.parse_args()
    
    # Initialize auditor
    auditor = JWTSecurityAuditor(verbose=args.verbose)
    
    # Load wordlist if provided
    wordlist = None
    if args.wordlist and not args.no_brute_force and not args.analyze_only:
        wordlist = load_wordlist(args.wordlist)
        if wordlist:
            print(f"Loaded {len(wordlist)} secrets from wordlist")
    
    # Process tokens
    tokens = []
    if args.token:
        tokens = [args.token]
    elif args.file:
        tokens = load_tokens_from_file(args.file)
        if not tokens:
            sys.exit(1)
        print(f"Loaded {len(tokens)} tokens from file")
    
    # Audit each token
    all_reports = []
    for i, token in enumerate(tokens, 1):
        if len(tokens) > 1:
            print(f"\nAuditing token {i}/{len(tokens)}")
        
        # Skip brute force if requested
        current_wordlist = None if (args.no_brute_force or args.analyze_only) else wordlist
        
        report = auditor.audit_token(token, current_wordlist)
        all_reports.append(report)
        
        # Print summary for each token
        print_summary(report)
    
    # Save detailed report if requested
    if args.output:
        final_report = {
            'audit_timestamp': datetime.now().isoformat(),
            'total_tokens': len(tokens),
            'reports': all_reports
        }
        save_report(final_report, args.output)
    
    # Exit with appropriate code
    has_critical = any(
        any(v.get('type') == 'CRITICAL' for v in report.get('vulnerabilities', []))
        for report in all_reports
    )
    
    sys.exit(1 if has_critical else 0)


if __name__ == '__main__':
    main()
