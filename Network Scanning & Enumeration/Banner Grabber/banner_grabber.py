#!/usr/bin/env python3
"""
Banner Grabber - Network Service Banner Collection Tool

This script connects to network services and retrieves their banners/headers
to identify service versions and configurations. Useful for network inventory,
security assessment, and system administration.

Usage Examples:
    python banner_grabber.py -t example.com -p 80
    python banner_grabber.py -t 192.168.1.1 -p 22,80,443 -T 5
    python banner_grabber.py -t example.com -p 1-1000 --output results.txt

Author: Network Administrator
License: MIT
Version: 1.0.0
"""

import socket
import sys
import argparse
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import re


class BannerGrabber:
    """
    A class to handle banner grabbing operations for network services.
    """
    
    def __init__(self, timeout=3, max_workers=10, verbose=False):
        """
        Initialize the BannerGrabber.
        
        Args:
            timeout (int): Socket timeout in seconds
            max_workers (int): Maximum number of concurrent threads
            verbose (bool): Enable verbose output
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.verbose = verbose
        self.results = []
        self.lock = threading.Lock()
        
        # Common service probes
        self.service_probes = {
            21: b'',  # FTP
            22: b'',  # SSH
            23: b'',  # Telnet
            25: b'EHLO banner-grabber\r\n',  # SMTP
            53: b'',  # DNS
            80: b'HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n',  # HTTP
            110: b'',  # POP3
            143: b'',  # IMAP
            443: b'HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n',  # HTTPS
            993: b'',  # IMAPS
            995: b'',  # POP3S
        }
    
    def log(self, message, level="INFO"):
        """
        Log messages with timestamp.
        
        Args:
            message (str): Message to log
            level (str): Log level (INFO, ERROR, DEBUG)
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if level == "ERROR" or self.verbose:
            print(f"[{timestamp}] [{level}] {message}")
    
    def parse_port_range(self, port_string):
        """
        Parse port specification into a list of ports.
        
        Args:
            port_string (str): Port specification (e.g., "80", "80,443", "1-100")
            
        Returns:
            list: List of port numbers
        """
        ports = []
        
        try:
            # Handle comma-separated ports
            for part in port_string.split(','):
                part = part.strip()
                
                # Handle port ranges
                if '-' in part:
                    start, end = map(int, part.split('-', 1))
                    if start > end or start < 1 or end > 65535:
                        raise ValueError(f"Invalid port range: {part}")
                    ports.extend(range(start, end + 1))
                else:
                    # Single port
                    port = int(part)
                    if port < 1 or port > 65535:
                        raise ValueError(f"Invalid port: {port}")
                    ports.append(port)
                    
        except ValueError as e:
            raise ValueError(f"Error parsing ports: {e}")
        
        return sorted(list(set(ports)))  # Remove duplicates and sort
    
    def grab_banner(self, target, port):
        """
        Grab banner from a specific target and port.
        
        Args:
            target (str): Target hostname or IP address
            port (int): Target port number
            
        Returns:
            dict: Result dictionary with banner information
        """
        result = {
            'target': target,
            'port': port,
            'status': 'closed',
            'banner': '',
            'service': 'unknown',
            'error': None
        }
        
        try:
            self.log(f"Scanning {target}:{port}", "DEBUG")
            
            # Create socket with timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt connection
            connection_result = sock.connect_ex((target, port))
            
            if connection_result == 0:
                result['status'] = 'open'
                
                # Send appropriate probe based on port
                probe = self.service_probes.get(port, b'')
                if probe and b'{host}' in probe:
                    probe = probe.replace(b'{host}', target.encode())
                
                if probe:
                    sock.send(probe)
                    time.sleep(0.1)  # Brief pause for response
                
                # Receive banner
                try:
                    banner_data = sock.recv(1024)
                    if banner_data:
                        # Decode banner, handling encoding issues
                        try:
                            banner = banner_data.decode('utf-8', errors='ignore').strip()
                        except:
                            banner = str(banner_data)
                        
                        result['banner'] = banner
                        result['service'] = self.identify_service(banner, port)
                        
                        self.log(f"Banner from {target}:{port} - {banner[:100]}...", "DEBUG")
                    
                except socket.timeout:
                    # Some services don't send immediate banners
                    result['banner'] = 'No banner received (timeout)'
                except Exception as e:
                    result['error'] = f"Error receiving banner: {str(e)}"
            
            sock.close()
            
        except socket.timeout:
            result['error'] = 'Connection timeout'
        except socket.gaierror as e:
            result['error'] = f'DNS resolution failed: {str(e)}'
        except Exception as e:
            result['error'] = f'Connection error: {str(e)}'
        
        return result
    
    def identify_service(self, banner, port):
        """
        Attempt to identify service based on banner and port.
        
        Args:
            banner (str): Service banner
            port (int): Port number
            
        Returns:
            str: Identified service name
        """
        banner_lower = banner.lower()
        
        # Service identification patterns
        patterns = {
            'ssh': [r'ssh', r'openssh'],
            'ftp': [r'ftp', r'vsftpd', r'proftpd'],
            'http': [r'http', r'apache', r'nginx', r'iis'],
            'smtp': [r'smtp', r'postfix', r'sendmail', r'exchange'],
            'pop3': [r'pop3', r'\+ok'],
            'imap': [r'imap', r'\* ok'],
            'telnet': [r'telnet', r'login:'],
            'dns': [r'dns'],
        }
        
        # Check banner against patterns
        for service, service_patterns in patterns.items():
            for pattern in service_patterns:
                if re.search(pattern, banner_lower):
                    return service
        
        # Fallback to common port assignments
        port_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 993: 'imaps', 995: 'pop3s'
        }
        
        return port_services.get(port, 'unknown')
    
    def scan_target(self, target, ports):
        """
        Scan a target for banners on specified ports.
        
        Args:
            target (str): Target hostname or IP address
            ports (list): List of ports to scan
            
        Returns:
            list: List of scan results
        """
        self.log(f"Starting banner grab for {target} on {len(ports)} ports")
        
        results = []
        
        # Use thread pool for concurrent scanning
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_port = {
                executor.submit(self.grab_banner, target, port): port 
                for port in ports
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_port):
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Print immediate results for open ports
                    if result['status'] == 'open':
                        banner_preview = result['banner'][:80] + '...' if len(result['banner']) > 80 else result['banner']
                        print(f"[OPEN] {result['target']}:{result['port']} ({result['service']}) - {banner_preview}")
                    
                except Exception as e:
                    port = future_to_port[future]
                    self.log(f"Error scanning {target}:{port} - {str(e)}", "ERROR")
        
        return results
    
    def save_results(self, results, filename):
        """
        Save results to a file.
        
        Args:
            results (list): List of scan results
            filename (str): Output filename
        """
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Banner Grabber Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
                
                for result in results:
                    if result['status'] == 'open':
                        f.write(f"Target: {result['target']}:{result['port']}\n")
                        f.write(f"Status: {result['status']}\n")
                        f.write(f"Service: {result['service']}\n")
                        f.write(f"Banner: {result['banner']}\n")
                        if result['error']:
                            f.write(f"Error: {result['error']}\n")
                        f.write("-" * 40 + "\n\n")
            
            self.log(f"Results saved to {filename}")
            
        except Exception as e:
            self.log(f"Error saving results: {str(e)}", "ERROR")


def main():
    """
    Main function to handle command-line arguments and execute banner grabbing.
    """
    parser = argparse.ArgumentParser(
        description="Banner Grabber - Network Service Banner Collection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t example.com -p 80
  %(prog)s -t 192.168.1.1 -p 22,80,443 -T 5
  %(prog)s -t example.com -p 1-1000 --threads 20
  %(prog)s -t example.com -p 80,443 --output results.txt
        """
    )
    
    # Required arguments
    parser.add_argument('-t', '--target', required=True,
                       help='Target hostname or IP address')
    parser.add_argument('-p', '--ports', required=True,
                       help='Port(s) to scan (e.g., 80, 80,443, 1-1000)')
    
    # Optional arguments
    parser.add_argument('-T', '--timeout', type=int, default=3,
                       help='Socket timeout in seconds (default: 3)')
    parser.add_argument('--threads', type=int, default=10,
                       help='Maximum number of concurrent threads (default: 10)')
    parser.add_argument('-o', '--output',
                       help='Output file to save results')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.timeout < 1 or args.timeout > 30:
        print("Error: Timeout must be between 1 and 30 seconds")
        sys.exit(1)
    
    if args.threads < 1 or args.threads > 100:
        print("Error: Thread count must be between 1 and 100")
        sys.exit(1)
    
    try:
        # Initialize banner grabber
        grabber = BannerGrabber(
            timeout=args.timeout,
            max_workers=args.threads,
            verbose=args.verbose
        )
        
        # Parse ports
        ports = grabber.parse_port_range(args.ports)
        
        if len(ports) > 1000:
            response = input(f"You are about to scan {len(ports)} ports. Continue? (y/N): ")
            if response.lower() != 'y':
                print("Scan cancelled.")
                sys.exit(0)
        
        print(f"\nBanner Grabber v1.0.0")
        print(f"Target: {args.target}")
        print(f"Ports: {len(ports)} ports")
        print(f"Timeout: {args.timeout}s")
        print(f"Threads: {args.threads}")
        print("-" * 50)
        
        # Perform scan
        results = grabber.scan_target(args.target, ports)
        
        # Print summary
        open_ports = sum(1 for r in results if r['status'] == 'open')
        print(f"\nScan completed. Found {open_ports} open ports out of {len(ports)} scanned.")
        
        # Save results if requested
        if args.output:
            grabber.save_results(results, args.output)
    
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
