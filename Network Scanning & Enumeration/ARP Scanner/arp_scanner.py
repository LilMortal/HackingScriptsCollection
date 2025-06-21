#!/usr/bin/env python3
"""
ARP Scanner - Network Device Discovery Tool

This script performs ARP scanning to discover active devices on a local network.
It sends ARP requests to a range of IP addresses and collects responses to
identify devices that are currently online.

Author: Assistant
License: MIT
Python Version: 3.6+

Usage:
    python3 arp_scanner.py -t 192.168.1.0/24
    python3 arp_scanner.py -t 192.168.1.1-192.168.1.100 -o results.txt
    python3 arp_scanner.py -r 192.168.1.1 192.168.1.254 --timeout 2

Dependencies:
    - scapy: pip install scapy
"""

import argparse
import ipaddress
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple

try:
    from scapy.all import ARP, Ether, srp, conf
    # Disable scapy verbose output
    conf.verb = 0
except ImportError:
    print("Error: scapy library is required but not installed.")
    print("Install it using: pip install scapy")
    sys.exit(1)


class ARPScanner:
    """
    ARP Scanner class for discovering devices on local networks.
    
    This class provides methods to scan network ranges using ARP requests
    and identify active devices with their MAC addresses.
    """
    
    def __init__(self, timeout: float = 1.0, max_workers: int = 50):
        """
        Initialize the ARP Scanner.
        
        Args:
            timeout (float): Timeout for ARP requests in seconds
            max_workers (int): Maximum number of concurrent threads
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.discovered_devices = []
    
    def scan_single_ip(self, ip: str) -> Optional[Dict[str, str]]:
        """
        Scan a single IP address using ARP request.
        
        Args:
            ip (str): IP address to scan
            
        Returns:
            Optional[Dict[str, str]]: Dictionary with IP and MAC if device responds,
                                   None if no response
        """
        try:
            # Create ARP request packet
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send packet and receive response
            answered_list = srp(arp_request_broadcast, timeout=self.timeout, verbose=False)[0]
            
            if answered_list:
                # Extract IP and MAC from response
                response = answered_list[0][1]
                return {
                    'ip': response.psrc,
                    'mac': response.hwsrc
                }
        except Exception as e:
            # Silently handle individual IP scan failures
            pass
        
        return None
    
    def scan_network_range(self, target: str) -> List[Dict[str, str]]:
        """
        Scan a network range using multithreading.
        
        Args:
            target (str): Network range in CIDR notation (e.g., 192.168.1.0/24)
                         or IP range (e.g., 192.168.1.1-192.168.1.100)
            
        Returns:
            List[Dict[str, str]]: List of discovered devices
        """
        ip_list = self._parse_target(target)
        
        if not ip_list:
            return []
        
        print(f"Scanning {len(ip_list)} IP addresses...")
        print(f"Target: {target}")
        print("-" * 50)
        
        discovered = []
        completed_scans = 0
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all scan tasks
            future_to_ip = {executor.submit(self.scan_single_ip, ip): ip 
                           for ip in ip_list}
            
            # Process completed tasks
            for future in as_completed(future_to_ip):
                completed_scans += 1
                
                # Show progress
                if completed_scans % 10 == 0 or completed_scans == len(ip_list):
                    progress = (completed_scans / len(ip_list)) * 100
                    print(f"Progress: {completed_scans}/{len(ip_list)} ({progress:.1f}%)")
                
                result = future.result()
                if result:
                    discovered.append(result)
                    print(f"Found device: {result['ip']} -> {result['mac']}")
        
        self.discovered_devices = discovered
        return discovered
    
    def _parse_target(self, target: str) -> List[str]:
        """
        Parse target string into list of IP addresses.
        
        Args:
            target (str): Target network or IP range
            
        Returns:
            List[str]: List of IP addresses to scan
        """
        ip_list = []
        
        try:
            # Check if target is in CIDR notation
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                ip_list = [str(ip) for ip in network.hosts()]
            
            # Check if target is an IP range (e.g., 192.168.1.1-192.168.1.100)
            elif '-' in target:
                start_ip, end_ip = target.split('-')
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())
                
                # Generate IP range
                current = start
                while current <= end:
                    ip_list.append(str(current))
                    current += 1
            
            # Single IP address
            else:
                # Validate IP address
                ipaddress.ip_address(target)
                ip_list = [target]
                
        except ValueError as e:
            print(f"Error parsing target '{target}': {e}")
            return []
        
        return ip_list
    
    def save_results(self, filename: str, format_type: str = 'txt') -> bool:
        """
        Save scan results to file.
        
        Args:
            filename (str): Output filename
            format_type (str): Output format ('txt' or 'json')
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if format_type.lower() == 'json':
                with open(filename, 'w') as f:
                    json.dump({
                        'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'total_devices': len(self.discovered_devices),
                        'devices': self.discovered_devices
                    }, f, indent=2)
            else:
                with open(filename, 'w') as f:
                    f.write(f"ARP Scan Results - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(f"Total devices found: {len(self.discovered_devices)}\n\n")
                    f.write("IP Address\t\tMAC Address\n")
                    f.write("-" * 40 + "\n")
                    
                    for device in self.discovered_devices:
                        f.write(f"{device['ip']:<15}\t{device['mac']}\n")
            
            print(f"Results saved to: {filename}")
            return True
            
        except IOError as e:
            print(f"Error saving results: {e}")
            return False


def main():
    """Main function to handle command-line arguments and execute ARP scan."""
    
    parser = argparse.ArgumentParser(
        description="ARP Scanner - Discover devices on local networks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.0/24                    # Scan entire subnet
  %(prog)s -t 192.168.1.1-192.168.1.100        # Scan IP range
  %(prog)s -t 192.168.1.1                      # Scan single IP
  %(prog)s -r 192.168.1.1 192.168.1.254        # Scan range with -r option
  %(prog)s -t 192.168.1.0/24 -o results.txt    # Save results to file
  %(prog)s -t 192.168.1.0/24 --timeout 2 -j 30 # Custom timeout and threads
        """
    )
    
    # Target specification options
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        '-t', '--target',
        help='Target network (CIDR notation), IP range (IP1-IP2), or single IP'
    )
    target_group.add_argument(
        '-r', '--range',
        nargs=2,
        metavar=('START_IP', 'END_IP'),
        help='IP range specified as two separate arguments'
    )
    
    # Optional arguments
    parser.add_argument(
        '-o', '--output',
        help='Output file to save results'
    )
    parser.add_argument(
        '--format',
        choices=['txt', 'json'],
        default='txt',
        help='Output format (default: txt)'
    )
    parser.add_argument(
        '--timeout',
        type=float,
        default=1.0,
        help='Timeout for ARP requests in seconds (default: 1.0)'
    )
    parser.add_argument(
        '-j', '--threads',
        type=int,
        default=50,
        help='Maximum number of concurrent threads (default: 50)'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress progress output'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.timeout <= 0:
        print("Error: Timeout must be positive")
        sys.exit(1)
    
    if args.threads <= 0 or args.threads > 200:
        print("Error: Thread count must be between 1 and 200")
        sys.exit(1)
    
    # Determine target
    if args.target:
        target = args.target
    else:
        target = f"{args.range[0]}-{args.range[1]}"
    
    # Initialize scanner
    scanner = ARPScanner(timeout=args.timeout, max_workers=args.threads)
    
    # Suppress progress output if quiet mode
    if args.quiet:
        import io
        import contextlib
        
        # Redirect stdout temporarily for progress messages
        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            devices = scanner.scan_network_range(target)
    else:
        devices = scanner.scan_network_range(target)
    
    # Display results
    print("\n" + "=" * 50)
    print(f"Scan completed! Found {len(devices)} active devices:")
    print("=" * 50)
    
    if devices:
        print(f"{'IP Address':<15} {'MAC Address'}")
        print("-" * 35)
        for device in devices:
            print(f"{device['ip']:<15} {device['mac']}")
    else:
        print("No devices found.")
    
    # Save results if requested
    if args.output:
        scanner.save_results(args.output, args.format)
    
    print(f"\nScan completed in {time.strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(0)
    except PermissionError:
        print("Error: This script requires administrative privileges to send ARP packets.")
        print("Please run with sudo on Linux/macOS or as Administrator on Windows.")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)