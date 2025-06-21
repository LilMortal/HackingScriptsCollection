#!/usr/bin/env python3
"""
Network Share Enumerator (SMB)

A Python script for enumerating SMB shares on network hosts.
This tool is designed for legitimate network administration and security assessment.

Usage example:
    python smb_enumerator.py -t 192.168.1.100
    python smb_enumerator.py -t 192.168.1.0/24 -u username -p password
    python smb_enumerator.py -f targets.txt --timeout 5 -o results.txt

Author: Network Security Team
Version: 1.0
License: MIT
"""

import argparse
import ipaddress
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import os


class SMBEnumerator:
    """SMB Share Enumerator class for discovering network shares."""
    
    def __init__(self, timeout=3, max_threads=50):
        """
        Initialize the SMB Enumerator.
        
        Args:
            timeout (int): Connection timeout in seconds
            max_threads (int): Maximum number of concurrent threads
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.results = []
        self.lock = threading.Lock()
    
    def is_port_open(self, host, port):
        """
        Check if a specific port is open on a host.
        
        Args:
            host (str): Target host IP address
            port (int): Port number to check
            
        Returns:
            bool: True if port is open, False otherwise
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                return result == 0
        except Exception:
            return False
    
    def check_smb_ports(self, host):
        """
        Check if SMB ports (139, 445) are open on a host.
        
        Args:
            host (str): Target host IP address
            
        Returns:
            list: List of open SMB ports
        """
        smb_ports = [139, 445]
        open_ports = []
        
        for port in smb_ports:
            if self.is_port_open(host, port):
                open_ports.append(port)
        
        return open_ports
    
    def enumerate_shares_smbclient(self, host, username=None, password=None):
        """
        Enumerate SMB shares using smbclient command.
        
        Args:
            host (str): Target host IP address
            username (str): Username for authentication (optional)
            password (str): Password for authentication (optional)
            
        Returns:
            list: List of discovered shares
        """
        shares = []
        
        try:
            # Build smbclient command
            cmd = ['smbclient', '-L', host, '-N']  # -N for no password prompt
            
            if username:
                cmd.extend(['-U', f"{username}%{password or ''}"])
            
            # Execute command with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout * 2
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                parsing_shares = False
                
                for line in lines:
                    line = line.strip()
                    
                    # Start parsing after "Sharename" header
                    if 'Sharename' in line and 'Type' in line:
                        parsing_shares = True
                        continue
                    
                    # Stop parsing at empty line or separator
                    if parsing_shares and (not line or line.startswith('-')):
                        break
                    
                    # Parse share information
                    if parsing_shares and line:
                        parts = line.split()
                        if len(parts) >= 2:
                            share_name = parts[0]
                            share_type = parts[1] if len(parts) > 1 else 'Unknown'
                            comment = ' '.join(parts[2:]) if len(parts) > 2 else ''
                            
                            shares.append({
                                'name': share_name,
                                'type': share_type,
                                'comment': comment
                            })
            
        except subprocess.TimeoutExpired:
            print(f"[!] Timeout while enumerating shares on {host}")
        except FileNotFoundError:
            print("[!] smbclient not found. Please install samba-client package.")
        except Exception as e:
            print(f"[!] Error enumerating shares on {host}: {e}")
        
        return shares
    
    def enumerate_shares_netbios(self, host):
        """
        Attempt to get NetBIOS information using nmblookup.
        
        Args:
            host (str): Target host IP address
            
        Returns:
            dict: NetBIOS information
        """
        netbios_info = {}
        
        try:
            cmd = ['nmblookup', '-A', host]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    line = line.strip()
                    if '<00>' in line and 'UNIQUE' in line:
                        parts = line.split()
                        if len(parts) > 0:
                            netbios_info['computer_name'] = parts[0]
                            break
                    elif '<20>' in line and 'UNIQUE' in line:
                        parts = line.split()
                        if len(parts) > 0:
                            netbios_info['server_service'] = parts[0]
        
        except Exception:
            pass  # Silently fail for NetBIOS lookup
        
        return netbios_info
    
    def scan_host(self, host, username=None, password=None):
        """
        Scan a single host for SMB shares.
        
        Args:
            host (str): Target host IP address
            username (str): Username for authentication (optional)
            password (str): Password for authentication (optional)
            
        Returns:
            dict: Scan results for the host
        """
        host_result = {
            'host': host,
            'smb_ports': [],
            'shares': [],
            'netbios': {},
            'accessible': False
        }
        
        # Check SMB ports
        open_ports = self.check_smb_ports(host)
        host_result['smb_ports'] = open_ports
        
        if open_ports:
            host_result['accessible'] = True
            
            # Get NetBIOS information
            host_result['netbios'] = self.enumerate_shares_netbios(host)
            
            # Enumerate shares
            shares = self.enumerate_shares_smbclient(host, username, password)
            host_result['shares'] = shares
        
        return host_result
    
    def parse_targets(self, target_input):
        """
        Parse target input and return list of IP addresses.
        
        Args:
            target_input (str): Target specification (IP, CIDR, or range)
            
        Returns:
            list: List of IP addresses to scan
        """
        targets = []
        
        try:
            # Handle CIDR notation
            if '/' in target_input:
                network = ipaddress.ip_network(target_input, strict=False)
                targets = [str(ip) for ip in network.hosts()]
            # Handle single IP
            else:
                # Validate IP address
                ipaddress.ip_address(target_input)
                targets = [target_input]
        
        except ValueError as e:
            print(f"[!] Invalid target format: {e}")
            return []
        
        return targets
    
    def load_targets_from_file(self, filename):
        """
        Load targets from a file.
        
        Args:
            filename (str): Path to file containing targets
            
        Returns:
            list: List of IP addresses to scan
        """
        targets = []
        
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        target_list = self.parse_targets(line)
                        targets.extend(target_list)
        
        except FileNotFoundError:
            print(f"[!] Target file not found: {filename}")
        except Exception as e:
            print(f"[!] Error reading target file: {e}")
        
        return targets
    
    def print_results(self, results):
        """
        Print scan results in a formatted manner.
        
        Args:
            results (list): List of host scan results
        """
        print("\n" + "="*60)
        print("SMB SHARE ENUMERATION RESULTS")
        print("="*60)
        
        accessible_hosts = [r for r in results if r['accessible']]
        
        if not accessible_hosts:
            print("\n[!] No accessible SMB hosts found.")
            return
        
        for result in accessible_hosts:
            print(f"\n[+] Host: {result['host']}")
            print(f"    SMB Ports: {', '.join(map(str, result['smb_ports']))}")
            
            if result['netbios']:
                print(f"    NetBIOS Info:")
                for key, value in result['netbios'].items():
                    print(f"      {key}: {value}")
            
            if result['shares']:
                print(f"    Shares ({len(result['shares'])}):")
                for share in result['shares']:
                    print(f"      - {share['name']} ({share['type']})")
                    if share['comment']:
                        print(f"        Comment: {share['comment']}")
            else:
                print("    No shares found or access denied.")
    
    def save_results(self, results, filename):
        """
        Save results to a file.
        
        Args:
            results (list): List of host scan results
            filename (str): Output filename
        """
        try:
            with open(filename, 'w') as f:
                f.write("SMB Share Enumeration Results\n")
                f.write("="*40 + "\n\n")
                
                accessible_hosts = [r for r in results if r['accessible']]
                
                for result in accessible_hosts:
                    f.write(f"Host: {result['host']}\n")
                    f.write(f"SMB Ports: {', '.join(map(str, result['smb_ports']))}\n")
                    
                    if result['netbios']:
                        f.write("NetBIOS Info:\n")
                        for key, value in result['netbios'].items():
                            f.write(f"  {key}: {value}\n")
                    
                    if result['shares']:
                        f.write(f"Shares ({len(result['shares'])}):\n")
                        for share in result['shares']:
                            f.write(f"  - {share['name']} ({share['type']})")
                            if share['comment']:
                                f.write(f" - {share['comment']}")
                            f.write("\n")
                    else:
                        f.write("No shares found or access denied.\n")
                    
                    f.write("\n" + "-"*40 + "\n\n")
            
            print(f"\n[+] Results saved to: {filename}")
        
        except Exception as e:
            print(f"[!] Error saving results: {e}")
    
    def run_scan(self, targets, username=None, password=None):
        """
        Run SMB enumeration scan on multiple targets.
        
        Args:
            targets (list): List of target IP addresses
            username (str): Username for authentication (optional)
            password (str): Password for authentication (optional)
            
        Returns:
            list: List of scan results
        """
        print(f"[*] Starting SMB enumeration on {len(targets)} targets...")
        print(f"[*] Timeout: {self.timeout}s, Max threads: {self.max_threads}")
        
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all scan tasks
            future_to_host = {
                executor.submit(self.scan_host, target, username, password): target
                for target in targets
            }
            
            # Process completed tasks
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Print progress
                    if result['accessible']:
                        print(f"[+] {host} - SMB accessible ({len(result['shares'])} shares)")
                    else:
                        print(f"[-] {host} - No SMB access")
                
                except Exception as e:
                    print(f"[!] Error scanning {host}: {e}")
                    results.append({
                        'host': host,
                        'smb_ports': [],
                        'shares': [],
                        'netbios': {},
                        'accessible': False,
                        'error': str(e)
                    })
        
        return results


def main():
    """Main function to handle command-line arguments and run the scanner."""
    parser = argparse.ArgumentParser(
        description="SMB Share Enumerator - Discover SMB shares on network hosts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.100
  %(prog)s -t 192.168.1.0/24 -u admin -p password123
  %(prog)s -f targets.txt --timeout 10 -o results.txt
  %(prog)s -t 10.0.0.0/8 --threads 100 --no-auth
        """
    )
    
    # Target specification
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        '-t', '--target',
        help='Target IP address or CIDR range (e.g., 192.168.1.100 or 192.168.1.0/24)'
    )
    target_group.add_argument(
        '-f', '--file',
        help='File containing list of targets (one per line)'
    )
    
    # Authentication options
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument(
        '-u', '--username',
        help='Username for SMB authentication'
    )
    auth_group.add_argument(
        '-p', '--password',
        help='Password for SMB authentication'
    )
    auth_group.add_argument(
        '--no-auth',
        action='store_true',
        help='Skip authentication (use null session)'
    )
    
    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument(
        '--timeout',
        type=int,
        default=3,
        help='Connection timeout in seconds (default: 3)'
    )
    scan_group.add_argument(
        '--threads',
        type=int,
        default=50,
        help='Maximum number of concurrent threads (default: 50)'
    )
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '-o', '--output',
        help='Save results to file'
    )
    output_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Validate dependencies
    try:
        subprocess.run(['smbclient', '--version'], 
                      capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[!] Error: smbclient not found.")
        print("[!] Please install samba-client package:")
        print("    Ubuntu/Debian: sudo apt-get install samba-client")
        print("    CentOS/RHEL: sudo yum install samba-client")
        print("    Fedora: sudo dnf install samba-client")
        sys.exit(1)
    
    # Initialize enumerator
    enumerator = SMBEnumerator(
        timeout=args.timeout,
        max_threads=args.threads
    )
    
    # Parse targets
    if args.target:
        targets = enumerator.parse_targets(args.target)
    else:
        targets = enumerator.load_targets_from_file(args.file)
    
    if not targets:
        print("[!] No valid targets specified.")
        sys.exit(1)
    
    # Handle authentication
    username = None if args.no_auth else args.username
    password = None if args.no_auth else args.password
    
    if username and not password:
        import getpass
        password = getpass.getpass(f"Password for {username}: ")
    
    # Run scan
    try:
        start_time = time.time()
        results = enumerator.run_scan(targets, username, password)
        end_time = time.time()
        
        # Display results
        enumerator.print_results(results)
        
        # Save results if requested
        if args.output:
            enumerator.save_results(results, args.output)
        
        # Print summary
        accessible_count = len([r for r in results if r['accessible']])
        total_shares = sum(len(r['shares']) for r in results)
        
        print(f"\n[*] Scan completed in {end_time - start_time:.2f} seconds")
        print(f"[*] {accessible_count}/{len(targets)} hosts with SMB access")
        print(f"[*] {total_shares} total shares discovered")
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
