#!/usr/bin/env python3
"""
Default Credentials Scanner

A security assessment tool for identifying systems using default credentials.
This script is intended for authorized security testing and vulnerability assessment only.

Author: Security Assessment Tool
License: MIT
Version: 1.0.0

Usage:
    python default_creds_scanner.py -t 192.168.1.100 -p 22,80,443,8080
    python default_creds_scanner.py -t 192.168.1.0/24 -s ssh,http,telnet --timeout 5
    python default_creds_scanner.py -f targets.txt -o results.json --threads 10
"""

import argparse
import json
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from ipaddress import ip_network, ip_address
from urllib.parse import urljoin
import requests
import paramiko
import telnetlib
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for testing purposes
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class DefaultCredentialsScanner:
    """
    Main scanner class for detecting default credentials across various services.
    """
    
    def __init__(self, timeout=3, threads=5, verbose=False):
        """
        Initialize the scanner with configuration parameters.
        
        Args:
            timeout (int): Connection timeout in seconds
            threads (int): Number of concurrent threads
            verbose (bool): Enable verbose output
        """
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.results = []
        self.lock = threading.Lock()
        
        # Default credentials database
        self.default_creds = {
            'ssh': [
                ('admin', 'admin'),
                ('root', 'root'),
                ('admin', 'password'),
                ('admin', ''),
                ('root', ''),
                ('user', 'user'),
                ('admin', '123456'),
                ('root', 'password'),
                ('admin', 'admin123'),
                ('pi', 'raspberry'),
                ('ubuntu', 'ubuntu'),
                ('oracle', 'oracle'),
                ('postgres', 'postgres'),
                ('mysql', 'mysql'),
            ],
            'http': [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('admin', ''),
                ('root', 'root'),
                ('admin', '123456'),
                ('admin', 'admin123'),
                ('administrator', 'administrator'),
                ('user', 'user'),
                ('guest', 'guest'),
                ('admin', 'changeme'),
                ('admin', 'default'),
                ('tomcat', 'tomcat'),
                ('manager', 'manager'),
            ],
            'telnet': [
                ('admin', 'admin'),
                ('root', 'root'),
                ('admin', 'password'),
                ('admin', ''),
                ('root', ''),
                ('user', 'user'),
                ('guest', 'guest'),
                ('cisco', 'cisco'),
                ('admin', '1234'),
            ],
            'ftp': [
                ('admin', 'admin'),
                ('ftp', 'ftp'),
                ('anonymous', ''),
                ('user', 'user'),
                ('admin', 'password'),
                ('root', 'root'),
                ('admin', ''),
            ]
        }
    
    def log_message(self, message, level='INFO'):
        """
        Log messages with timestamp and level.
        
        Args:
            message (str): Message to log
            level (str): Log level (INFO, SUCCESS, ERROR, DEBUG)
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if level == 'SUCCESS':
            print(f"[{timestamp}] [✓] {message}")
        elif level == 'ERROR':
            print(f"[{timestamp}] [✗] {message}")
        elif level == 'DEBUG' and self.verbose:
            print(f"[{timestamp}] [DEBUG] {message}")
        else:
            print(f"[{timestamp}] [INFO] {message}")
    
    def is_port_open(self, host, port):
        """
        Check if a port is open on the target host.
        
        Args:
            host (str): Target hostname or IP address
            port (int): Port number to check
            
        Returns:
            bool: True if port is open, False otherwise
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                return result == 0
        except Exception as e:
            self.log_message(f"Port check error for {host}:{port} - {str(e)}", 'DEBUG')
            return False
    
    def test_ssh_credentials(self, host, port, username, password):
        """
        Test SSH credentials against a target.
        
        Args:
            host (str): Target hostname or IP address
            port (int): SSH port number
            username (str): Username to test
            password (str): Password to test
            
        Returns:
            bool: True if credentials are valid, False otherwise
        """
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout
            )
            client.close()
            return True
        except paramiko.AuthenticationException:
            return False
        except Exception as e:
            self.log_message(f"SSH connection error to {host}:{port} - {str(e)}", 'DEBUG')
            return False
    
    def test_http_credentials(self, host, port, username, password):
        """
        Test HTTP basic authentication credentials.
        
        Args:
            host (str): Target hostname or IP address
            port (int): HTTP port number
            username (str): Username to test
            password (str): Password to test
            
        Returns:
            bool: True if credentials are valid, False otherwise
        """
        try:
            # Common HTTP authentication paths
            paths = ['/', '/admin', '/login', '/manager', '/console', '/api']
            
            for path in paths:
                for scheme in ['http', 'https']:
                    url = f"{scheme}://{host}:{port}{path}"
                    try:
                        response = requests.get(
                            url,
                            auth=HTTPBasicAuth(username, password),
                            timeout=self.timeout,
                            verify=False,
                            allow_redirects=False
                        )
                        # Check for successful authentication
                        if response.status_code in [200, 301, 302] and 'WWW-Authenticate' not in response.headers:
                            return True
                    except requests.exceptions.RequestException:
                        continue
            return False
        except Exception as e:
            self.log_message(f"HTTP test error for {host}:{port} - {str(e)}", 'DEBUG')
            return False
    
    def test_telnet_credentials(self, host, port, username, password):
        """
        Test Telnet credentials against a target.
        
        Args:
            host (str): Target hostname or IP address
            port (int): Telnet port number
            username (str): Username to test
            password (str): Password to test
            
        Returns:
            bool: True if credentials are valid, False otherwise
        """
        try:
            tn = telnetlib.Telnet(host, port, timeout=self.timeout)
            
            # Wait for login prompt
            tn.read_until(b"login:", timeout=self.timeout)
            tn.write(username.encode('ascii') + b"\n")
            
            # Wait for password prompt
            tn.read_until(b"Password:", timeout=self.timeout)
            tn.write(password.encode('ascii') + b"\n")
            
            # Check for successful login
            response = tn.read_until(b"$", timeout=self.timeout).decode('ascii', errors='ignore')
            tn.close()
            
            # Look for shell prompt or successful login indicators
            success_indicators = ['$', '#', '>', 'Welcome', 'Last login']
            return any(indicator in response for indicator in success_indicators)
            
        except Exception as e:
            self.log_message(f"Telnet test error for {host}:{port} - {str(e)}", 'DEBUG')
            return False
    
    def scan_service(self, host, port, service):
        """
        Scan a specific service for default credentials.
        
        Args:
            host (str): Target hostname or IP address
            port (int): Port number
            service (str): Service type (ssh, http, telnet, ftp)
            
        Returns:
            list: List of successful credential combinations
        """
        successful_creds = []
        
        if not self.is_port_open(host, port):
            self.log_message(f"Port {port} closed on {host}", 'DEBUG')
            return successful_creds
        
        self.log_message(f"Testing {service.upper()} on {host}:{port}")
        
        if service not in self.default_creds:
            self.log_message(f"No default credentials defined for service: {service}", 'ERROR')
            return successful_creds
        
        for username, password in self.default_creds[service]:
            try:
                self.log_message(f"Testing {username}:{password} on {host}:{port}", 'DEBUG')
                
                success = False
                if service == 'ssh':
                    success = self.test_ssh_credentials(host, port, username, password)
                elif service == 'http':
                    success = self.test_http_credentials(host, port, username, password)
                elif service == 'telnet':
                    success = self.test_telnet_credentials(host, port, username, password)
                
                if success:
                    cred_info = {
                        'host': host,
                        'port': port,
                        'service': service,
                        'username': username,
                        'password': password,
                        'timestamp': datetime.now().isoformat()
                    }
                    successful_creds.append(cred_info)
                    self.log_message(
                        f"SUCCESS: {service.upper()} {host}:{port} - {username}:{password}",
                        'SUCCESS'
                    )
                    
            except Exception as e:
                self.log_message(f"Error testing {username}:{password} on {host}:{port} - {str(e)}", 'ERROR')
        
        return successful_creds
    
    def scan_target(self, target_info):
        """
        Scan a single target for default credentials.
        
        Args:
            target_info (dict): Dictionary containing host, ports, and services
            
        Returns:
            list: List of successful credential combinations
        """
        host = target_info['host']
        ports = target_info['ports']
        services = target_info['services']
        
        target_results = []
        
        for port in ports:
            for service in services:
                try:
                    results = self.scan_service(host, port, service)
                    target_results.extend(results)
                except Exception as e:
                    self.log_message(f"Error scanning {service} on {host}:{port} - {str(e)}", 'ERROR')
        
        with self.lock:
            self.results.extend(target_results)
        
        return target_results
    
    def parse_targets(self, targets):
        """
        Parse target specifications into individual IP addresses.
        
        Args:
            targets (list): List of target specifications (IPs, ranges, hostnames)
            
        Returns:
            list: List of individual IP addresses/hostnames
        """
        parsed_targets = []
        
        for target in targets:
            try:
                # Try to parse as network range
                if '/' in target:
                    network = ip_network(target, strict=False)
                    parsed_targets.extend([str(ip) for ip in network.hosts()])
                else:
                    # Single IP or hostname
                    parsed_targets.append(target)
            except Exception as e:
                self.log_message(f"Error parsing target {target}: {str(e)}", 'ERROR')
        
        return parsed_targets
    
    def run_scan(self, targets, ports, services):
        """
        Execute the credential scanning process.
        
        Args:
            targets (list): List of target specifications
            ports (list): List of port numbers
            services (list): List of service types
            
        Returns:
            list: List of all successful credential combinations
        """
        self.log_message(f"Starting scan with {self.threads} threads")
        self.log_message(f"Targets: {len(targets)}, Ports: {ports}, Services: {services}")
        
        # Parse targets
        parsed_targets = self.parse_targets(targets)
        self.log_message(f"Parsed {len(parsed_targets)} individual targets")
        
        # Create target information list
        target_list = []
        for host in parsed_targets:
            target_list.append({
                'host': host,
                'ports': ports,
                'services': services
            })
        
        # Execute scans using thread pool
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_target = {executor.submit(self.scan_target, target): target for target in target_list}
            
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    future.result()
                except Exception as e:
                    self.log_message(f"Error scanning target {target['host']}: {str(e)}", 'ERROR')
        
        return self.results
    
    def save_results(self, filename, format_type='json'):
        """
        Save scan results to file.
        
        Args:
            filename (str): Output filename
            format_type (str): Output format (json, txt)
        """
        try:
            if format_type.lower() == 'json':
                with open(filename, 'w') as f:
                    json.dump({
                        'scan_info': {
                            'timestamp': datetime.now().isoformat(),
                            'total_findings': len(self.results)
                        },
                        'results': self.results
                    }, f, indent=2)
            else:
                with open(filename, 'w') as f:
                    f.write(f"Default Credentials Scan Results\n")
                    f.write(f"Generated: {datetime.now().isoformat()}\n")
                    f.write(f"Total Findings: {len(self.results)}\n\n")
                    
                    for result in self.results:
                        f.write(f"Host: {result['host']}:{result['port']}\n")
                        f.write(f"Service: {result['service']}\n")
                        f.write(f"Credentials: {result['username']}:{result['password']}\n")
                        f.write(f"Timestamp: {result['timestamp']}\n")
                        f.write("-" * 50 + "\n")
            
            self.log_message(f"Results saved to {filename}", 'SUCCESS')
            
        except Exception as e:
            self.log_message(f"Error saving results: {str(e)}", 'ERROR')


def main():
    """
    Main function to handle command-line arguments and execute the scan.
    """
    parser = argparse.ArgumentParser(
        description="Default Credentials Scanner - A tool for identifying systems using default credentials",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python default_creds_scanner.py -t 192.168.1.100 -p 22,80,443
  python default_creds_scanner.py -t 192.168.1.0/24 -s ssh,http --timeout 5
  python default_creds_scanner.py -f targets.txt -o results.json --threads 10
  
Services supported: ssh, http, telnet, ftp
        """
    )
    
    # Target specification
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target', nargs='+', 
                             help='Target IP addresses, hostnames, or CIDR ranges')
    target_group.add_argument('-f', '--file', 
                             help='File containing list of targets (one per line)')
    
    # Scan configuration
    parser.add_argument('-p', '--ports', default='22,80,443,23,21',
                       help='Comma-separated list of ports to scan (default: 22,80,443,23,21)')
    parser.add_argument('-s', '--services', default='ssh,http,telnet,ftp',
                       help='Comma-separated list of services to test (default: ssh,http,telnet,ftp)')
    parser.add_argument('--timeout', type=int, default=3,
                       help='Connection timeout in seconds (default: 3)')
    parser.add_argument('--threads', type=int, default=5,
                       help='Number of concurrent threads (default: 5)')
    
    # Output options
    parser.add_argument('-o', '--output',
                       help='Output file for results (JSON format)')
    parser.add_argument('--format', choices=['json', 'txt'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Parse targets
    if args.target:
        targets = args.target
    else:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"Error reading targets file: {e}")
            sys.exit(1)
    
    # Parse ports and services
    try:
        ports = [int(p.strip()) for p in args.ports.split(',')]
        services = [s.strip().lower() for s in args.services.split(',')]
    except ValueError as e:
        print(f"Error parsing ports or services: {e}")
        sys.exit(1)
    
    # Validate services
    valid_services = ['ssh', 'http', 'telnet', 'ftp']
    invalid_services = [s for s in services if s not in valid_services]
    if invalid_services:
        print(f"Invalid services: {invalid_services}")
        print(f"Valid services: {valid_services}")
        sys.exit(1)
    
    # Warning message
    print("\n" + "="*60)
    print("DEFAULT CREDENTIALS SCANNER")
    print("="*60)
    print("WARNING: This tool is for authorized security testing only!")
    print("Ensure you have permission to test the target systems.")
    print("="*60 + "\n")
    
    # Create and run scanner
    scanner = DefaultCredentialsScanner(
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose
    )
    
    try:
        start_time = time.time()
        results = scanner.run_scan(targets, ports, services)
        end_time = time.time()
        
        # Display results summary
        print("\n" + "="*60)
        print("SCAN COMPLETE")
        print("="*60)
        print(f"Scan duration: {end_time - start_time:.2f} seconds")
        print(f"Total findings: {len(results)}")
        
        if results:
            print(f"\nSuccessful default credentials found:")
            for result in results:
                print(f"  {result['host']}:{result['port']} ({result['service']}) - {result['username']}:{result['password']}")
        
        # Save results if output file specified
        if args.output:
            scanner.save_results(args.output, args.format)
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error during scan: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
