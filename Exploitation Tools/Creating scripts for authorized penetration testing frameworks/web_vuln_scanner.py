#!/usr/bin/env python3
"""
Authorized Web Vulnerability Scanner
===================================

A legitimate penetration testing tool for authorized security assessments.
This script performs basic web application vulnerability scanning including:
- Directory enumeration
- Common vulnerability checks
- HTTP header analysis
- SSL/TLS configuration assessment

IMPORTANT: Only use this tool on systems you own or have explicit written 
permission to test. Unauthorized scanning is illegal and unethical.

Usage Example:
    python web_vuln_scanner.py -u https://example.com -o report.txt
    python web_vuln_scanner.py -u https://example.com --scan-type full --threads 10
"""

import argparse
import requests
import urllib3
import json
import sys
import threading
import time
from urllib.parse import urljoin, urlparse
from datetime import datetime
import ssl
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Disable SSL warnings for testing purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebVulnScanner:
    """
    A web vulnerability scanner for authorized penetration testing.
    """
    
    def __init__(self, target_url, output_file=None, threads=5, timeout=10):
        """
        Initialize the scanner with target URL and configuration.
        
        Args:
            target_url (str): The target URL to scan
            output_file (str): Optional output file for results
            threads (int): Number of threads for concurrent scanning
            timeout (int): Request timeout in seconds
        """
        self.target_url = target_url.rstrip('/')
        self.output_file = output_file
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.results = []
        
        # Set user agent to identify as a security scanner
        self.session.headers.update({
            'User-Agent': 'Authorized-Security-Scanner/1.0 (Penetration Testing)'
        })
        
        # Common directories to check
        self.common_dirs = [
            'admin', 'administrator', 'login', 'wp-admin', 'wp-login.php',
            'phpmyadmin', 'cpanel', 'webmail', 'mail', 'email',
            'backup', 'backups', 'db', 'database', 'sql',
            'config', 'configuration', 'settings', 'env',
            'test', 'testing', 'dev', 'development', 'staging',
            'api', 'v1', 'v2', 'swagger', 'docs', 'documentation'
        ]
        
        # Common file extensions to check
        self.common_files = [
            'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
            'crossdomain.xml', 'clientaccesspolicy.xml',
            'readme.txt', 'changelog.txt', 'license.txt',
            '.env', '.git/config', '.svn/entries'
        ]

    def log_result(self, severity, category, message, details=None):
        """
        Log a scan result with timestamp and categorization.
        
        Args:
            severity (str): LOW, MEDIUM, HIGH, or INFO
            category (str): Category of the finding
            message (str): Main message
            details (dict): Additional details
        """
        result = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'category': category,
            'message': message,
            'target': self.target_url,
            'details': details or {}
        }
        self.results.append(result)
        
        # Print to console with color coding
        colors = {
            'HIGH': '\033[91m',     # Red
            'MEDIUM': '\033[93m',   # Yellow
            'LOW': '\033[92m',      # Green
            'INFO': '\033[94m',     # Blue
            'ENDC': '\033[0m'       # End color
        }
        
        color = colors.get(severity, colors['INFO'])
        print(f"{color}[{severity}]{colors['ENDC']} {category}: {message}")

    def check_url_accessibility(self, url):
        """
        Check if a URL is accessible and return response details.
        
        Args:
            url (str): URL to check
            
        Returns:
            dict: Response details or None if inaccessible
        """
        try:
            response = self.session.get(
                url, 
                timeout=self.timeout, 
                verify=False, 
                allow_redirects=False
            )
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_length': len(response.content),
                'response_time': response.elapsed.total_seconds()
            }
        except requests.exceptions.RequestException as e:
            return None

    def directory_enumeration(self):
        """
        Perform directory enumeration to find common directories and files.
        """
        print(f"\n[INFO] Starting directory enumeration on {self.target_url}")
        
        found_paths = []
        
        def check_path(path):
            url = urljoin(self.target_url, path)
            result = self.check_url_accessibility(url)
            
            if result and result['status_code'] in [200, 301, 302, 403]:
                found_paths.append((path, result))
                self.log_result(
                    'INFO', 
                    'Directory Found', 
                    f"Found accessible path: {path}",
                    {'url': url, 'status_code': result['status_code']}
                )
        
        # Use ThreadPoolExecutor for concurrent requests
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit directory checks
            futures = [executor.submit(check_path, dir_name) for dir_name in self.common_dirs]
            # Submit file checks
            futures.extend([executor.submit(check_path, file_name) for file_name in self.common_files])
            
            # Wait for completion
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"Error during directory enumeration: {e}")
        
        if found_paths:
            self.log_result(
                'MEDIUM', 
                'Directory Enumeration', 
                f"Found {len(found_paths)} accessible paths",
                {'found_paths': [path for path, _ in found_paths]}
            )

    def check_security_headers(self):
        """
        Analyze HTTP security headers.
        """
        print(f"\n[INFO] Analyzing security headers for {self.target_url}")
        
        response_data = self.check_url_accessibility(self.target_url)
        if not response_data:
            self.log_result('HIGH', 'Connection', 'Unable to connect to target', {})
            return
        
        headers = response_data['headers']
        
        # Define security headers to check
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': None,
            'Content-Security-Policy': None,
            'Referrer-Policy': None,
            'Permissions-Policy': None
        }
        
        missing_headers = []
        weak_headers = []
        
        for header, expected_value in security_headers.items():
            if header not in headers:
                missing_headers.append(header)
            elif expected_value and isinstance(expected_value, list):
                if not any(val in headers[header] for val in expected_value):
                    weak_headers.append(header)
            elif expected_value and expected_value not in headers[header]:
                weak_headers.append(header)
        
        if missing_headers:
            self.log_result(
                'MEDIUM', 
                'Security Headers', 
                f"Missing security headers: {', '.join(missing_headers)}",
                {'missing_headers': missing_headers}
            )
        
        if weak_headers:
            self.log_result(
                'LOW', 
                'Security Headers', 
                f"Weak security headers: {', '.join(weak_headers)}",
                {'weak_headers': weak_headers}
            )
        
        # Check for information disclosure headers
        disclosure_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
        found_disclosure = []
        
        for header in disclosure_headers:
            if header in headers:
                found_disclosure.append(f"{header}: {headers[header]}")
        
        if found_disclosure:
            self.log_result(
                'LOW', 
                'Information Disclosure', 
                f"Server information disclosed: {', '.join(found_disclosure)}",
                {'disclosed_info': found_disclosure}
            )

    def check_ssl_configuration(self):
        """
        Check SSL/TLS configuration if the target uses HTTPS.
        """
        if not self.target_url.startswith('https://'):
            self.log_result('INFO', 'SSL', 'Target does not use HTTPS', {})
            return
        
        print(f"\n[INFO] Analyzing SSL/TLS configuration")
        
        parsed_url = urlparse(self.target_url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate info
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
            
            # Analyze certificate
            if cert:
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (not_after - datetime.now()).days
                
                if days_until_expiry < 30:
                    self.log_result(
                        'HIGH', 
                        'SSL Certificate', 
                        f"Certificate expires in {days_until_expiry} days",
                        {'expiry_date': cert['notAfter']}
                    )
                elif days_until_expiry < 90:
                    self.log_result(
                        'MEDIUM', 
                        'SSL Certificate', 
                        f"Certificate expires in {days_until_expiry} days",
                        {'expiry_date': cert['notAfter']}
                    )
                
                self.log_result(
                    'INFO', 
                    'SSL Configuration', 
                    f"TLS Version: {version}, Cipher: {cipher[0] if cipher else 'Unknown'}",
                    {
                        'tls_version': version,
                        'cipher_suite': cipher[0] if cipher else None,
                        'certificate_subject': cert.get('subject', [])
                    }
                )
        
        except Exception as e:
            self.log_result(
                'MEDIUM', 
                'SSL Error', 
                f"SSL/TLS analysis failed: {str(e)}",
                {'error': str(e)}
            )

    def check_common_vulnerabilities(self):
        """
        Check for common web application vulnerabilities.
        """
        print(f"\n[INFO] Checking for common vulnerabilities")
        
        # Check for clickjacking protection
        response_data = self.check_url_accessibility(self.target_url)
        if response_data and 'X-Frame-Options' not in response_data['headers']:
            self.log_result(
                'MEDIUM', 
                'Clickjacking', 
                'No X-Frame-Options header found - potential clickjacking vulnerability',
                {}
            )
        
        # Check for common backup files
        backup_files = [
            'backup.zip', 'backup.tar.gz', 'backup.sql', 'database.sql',
            'config.bak', 'wp-config.php.bak', '.htaccess.bak'
        ]
        
        for backup_file in backup_files:
            url = urljoin(self.target_url, backup_file)
            result = self.check_url_accessibility(url)
            
            if result and result['status_code'] == 200:
                self.log_result(
                    'HIGH', 
                    'Backup File', 
                    f"Accessible backup file found: {backup_file}",
                    {'url': url}
                )

    def run_scan(self, scan_type='basic'):
        """
        Run the vulnerability scan based on the specified type.
        
        Args:
            scan_type (str): Type of scan to perform ('basic' or 'full')
        """
        print(f"Starting {scan_type} vulnerability scan on {self.target_url}")
        print(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        start_time = time.time()
        
        try:
            # Basic checks
            self.check_security_headers()
            self.check_ssl_configuration()
            self.check_common_vulnerabilities()
            
            # Full scan includes directory enumeration
            if scan_type == 'full':
                self.directory_enumeration()
            
        except KeyboardInterrupt:
            print("\n[INFO] Scan interrupted by user")
        except Exception as e:
            print(f"\n[ERROR] Scan failed: {e}")
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        print("\n" + "=" * 60)
        print(f"Scan completed in {scan_duration:.2f} seconds")
        print(f"Total findings: {len(self.results)}")
        
        # Save results if output file specified
        if self.output_file:
            self.save_results()

    def save_results(self):
        """
        Save scan results to the specified output file.
        """
        try:
            with open(self.output_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            print(f"Results saved to: {self.output_file}")
        except Exception as e:
            print(f"Error saving results: {e}")

def validate_url(url):
    """
    Validate the target URL format.
    
    Args:
        url (str): URL to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        parsed = urlparse(url)
        return all([parsed.scheme in ['http', 'https'], parsed.netloc])
    except Exception:
        return False

def main():
    """
    Main function to handle command-line arguments and run the scanner.
    """
    parser = argparse.ArgumentParser(
        description='Authorized Web Vulnerability Scanner - Use only on systems you own or have permission to test',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python web_vuln_scanner.py -u https://example.com
  python web_vuln_scanner.py -u https://example.com -o results.json --scan-type full
  python web_vuln_scanner.py -u http://testsite.local --threads 10 --timeout 15

LEGAL NOTICE: This tool is for authorized security testing only.
Only use on systems you own or have explicit written permission to test.
        """
    )
    
    parser.add_argument(
        '-u', '--url',
        required=True,
        help='Target URL to scan (required)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file for results (JSON format)'
    )
    
    parser.add_argument(
        '--scan-type',
        choices=['basic', 'full'],
        default='basic',
        help='Type of scan to perform (default: basic)'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=5,
        help='Number of threads for concurrent requests (default: 5)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )
    
    parser.add_argument(
        '--confirm',
        action='store_true',
        help='Confirm that you have authorization to test the target'
    )
    
    args = parser.parse_args()
    
    # Validate URL
    if not validate_url(args.url):
        print("Error: Invalid URL format. Please provide a valid HTTP/HTTPS URL.")
        sys.exit(1)
    
    # Require confirmation for authorization
    if not args.confirm:
        print("\nLEGAL WARNING:")
        print("This tool performs security testing that may be interpreted as")
        print("unauthorized access if used without proper permission.")
        print("\nOnly proceed if you:")
        print("1. Own the target system, OR")
        print("2. Have explicit written permission to test the target system")
        print("\nTo confirm authorization, use the --confirm flag")
        sys.exit(1)
    
    # Validate thread count
    if args.threads < 1 or args.threads > 50:
        print("Error: Thread count must be between 1 and 50")
        sys.exit(1)
    
    # Validate timeout
    if args.timeout < 1 or args.timeout > 60:
        print("Error: Timeout must be between 1 and 60 seconds")
        sys.exit(1)
    
    # Initialize and run scanner
    scanner = WebVulnScanner(
        target_url=args.url,
        output_file=args.output,
        threads=args.threads,
        timeout=args.timeout
    )
    
    scanner.run_scan(scan_type=args.scan_type)

if __name__ == '__main__':
    main()
