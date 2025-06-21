#!/usr/bin/env python3
"""
Ping Sweep Tool

A network discovery tool that performs ICMP ping sweeps to identify active hosts
on a network range. This tool helps network administrators and security professionals
discover live hosts within specified IP ranges.

Usage Example:
    python ping_sweep.py 192.168.1.0/24
    python ping_sweep.py 10.0.0.1-10.0.0.50 --timeout 2 --threads 50
    python ping_sweep.py 172.16.1.1 172.16.1.254 --output results.txt

Author: Network Tools
License: MIT
"""

import argparse
import concurrent.futures
import ipaddress
import os
import platform
import subprocess
import sys
import threading
import time
from typing import List, Set, Tuple


class PingSweepTool:
    """
    A comprehensive ping sweep tool for network host discovery.
    
    This class provides functionality to ping multiple hosts concurrently
    and identify which hosts are active on the network.
    """
    
    def __init__(self, timeout: float = 1.0, max_threads: int = 100):
        """
        Initialize the ping sweep tool.
        
        Args:
            timeout (float): Timeout for each ping in seconds
            max_threads (int): Maximum number of concurrent threads
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.active_hosts: Set[str] = set()
        self.lock = threading.Lock()
        self.total_hosts = 0
        self.completed_hosts = 0
        
        # Determine the ping command based on the operating system
        self.ping_cmd = self._get_ping_command()
    
    def _get_ping_command(self) -> List[str]:
        """
        Get the appropriate ping command for the current operating system.
        
        Returns:
            List[str]: The ping command with appropriate flags
        """
        system = platform.system().lower()
        
        if system == 'windows':
            # Windows ping command
            return ['ping', '-n', '1', '-w', str(int(self.timeout * 1000))]
        else:
            # Unix-like systems (Linux, macOS, etc.)
            return ['ping', '-c', '1', '-W', str(int(self.timeout))]
    
    def _ping_host(self, ip: str) -> bool:
        """
        Ping a single host to check if it's active.
        
        Args:
            ip (str): IP address to ping
            
        Returns:
            bool: True if host is active, False otherwise
        """
        try:
            # Construct the full ping command
            cmd = self.ping_cmd + [ip]
            
            # Execute the ping command
            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout + 1  # Add buffer to subprocess timeout
            )
            
            # Update progress
            with self.lock:
                self.completed_hosts += 1
                if result.returncode == 0:
                    self.active_hosts.add(ip)
                    return True
            
            return result.returncode == 0
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            with self.lock:
                self.completed_hosts += 1
            return False
        except Exception as e:
            with self.lock:
                self.completed_hosts += 1
            print(f"Error pinging {ip}: {e}", file=sys.stderr)
            return False
    
    def _generate_ip_range(self, start_ip: str, end_ip: str = None) -> List[str]:
        """
        Generate a list of IP addresses from a range or CIDR notation.
        
        Args:
            start_ip (str): Starting IP address or CIDR notation
            end_ip (str, optional): Ending IP address for range
            
        Returns:
            List[str]: List of IP addresses to scan
            
        Raises:
            ValueError: If IP addresses or range is invalid
        """
        ip_list = []
        
        try:
            if end_ip is None:
                # Check if it's CIDR notation
                if '/' in start_ip:
                    network = ipaddress.ip_network(start_ip, strict=False)
                    ip_list = [str(ip) for ip in network.hosts()]
                    # For /31 and /32 networks, include all addresses
                    if network.prefixlen >= 31:
                        ip_list = [str(ip) for ip in network]
                else:
                    # Single IP address
                    ipaddress.ip_address(start_ip)  # Validate
                    ip_list = [start_ip]
            else:
                # IP range (start_ip - end_ip)
                start = ipaddress.ip_address(start_ip)
                end = ipaddress.ip_address(end_ip)
                
                if start.version != end.version:
                    raise ValueError("Start and end IP addresses must be the same version")
                
                if start > end:
                    raise ValueError("Start IP must be less than or equal to end IP")
                
                current = start
                while current <= end:
                    ip_list.append(str(current))
                    current += 1
                    
        except ipaddress.AddressValueError as e:
            raise ValueError(f"Invalid IP address: {e}")
        except Exception as e:
            raise ValueError(f"Error generating IP range: {e}")
        
        return ip_list
    
    def _print_progress(self, show_progress: bool):
        """
        Print progress information during the scan.
        
        Args:
            show_progress (bool): Whether to show progress updates
        """
        if not show_progress:
            return
            
        while self.completed_hosts < self.total_hosts:
            with self.lock:
                progress = (self.completed_hosts / self.total_hosts) * 100
                active_count = len(self.active_hosts)
            
            print(f"\rProgress: {progress:.1f}% ({self.completed_hosts}/{self.total_hosts}) | Active hosts: {active_count}", end='', flush=True)
            time.sleep(0.5)
        
        # Final progress update
        with self.lock:
            active_count = len(self.active_hosts)
        print(f"\rProgress: 100.0% ({self.total_hosts}/{self.total_hosts}) | Active hosts: {active_count}")
    
    def sweep(self, ip_range: List[str], show_progress: bool = True) -> Set[str]:
        """
        Perform the ping sweep on the specified IP range.
        
        Args:
            ip_range (List[str]): List of IP addresses to scan
            show_progress (bool): Whether to show progress updates
            
        Returns:
            Set[str]: Set of active IP addresses
        """
        self.total_hosts = len(ip_range)
        self.completed_hosts = 0
        self.active_hosts.clear()
        
        if self.total_hosts == 0:
            print("No hosts to scan.")
            return set()
        
        print(f"Starting ping sweep of {self.total_hosts} hosts...")
        print(f"Timeout: {self.timeout}s | Max threads: {self.max_threads}")
        print("-" * 50)
        
        # Start progress thread
        if show_progress:
            progress_thread = threading.Thread(target=self._print_progress, args=(show_progress,))
            progress_thread.daemon = True
            progress_thread.start()
        
        # Perform concurrent ping sweep
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(self._ping_host, ip_range)
        
        # Wait for progress thread to complete
        if show_progress:
            progress_thread.join(timeout=1)
        
        return self.active_hosts.copy()


def parse_ip_input(ip_input: str) -> Tuple[str, str]:
    """
    Parse IP input to determine if it's a single IP, CIDR, or range.
    
    Args:
        ip_input (str): IP input string
        
    Returns:
        Tuple[str, str]: (start_ip, end_ip) where end_ip is None for single IP or CIDR
    """
    if '-' in ip_input and '/' not in ip_input:
        # IP range format: 192.168.1.1-192.168.1.254
        parts = ip_input.split('-')
        if len(parts) != 2:
            raise ValueError("Invalid IP range format. Use: start-end")
        return parts[0].strip(), parts[1].strip()
    else:
        # Single IP or CIDR notation
        return ip_input.strip(), None


def save_results(active_hosts: Set[str], output_file: str):
    """
    Save the scan results to a file.
    
    Args:
        active_hosts (Set[str]): Set of active hosts
        output_file (str): Path to output file
    """
    try:
        with open(output_file, 'w') as f:
            f.write(f"Ping Sweep Results - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 50 + "\n")
            f.write(f"Total active hosts: {len(active_hosts)}\n\n")
            
            for host in sorted(active_hosts, key=lambda x: ipaddress.ip_address(x)):
                f.write(f"{host}\n")
        
        print(f"\nResults saved to: {output_file}")
        
    except Exception as e:
        print(f"Error saving results: {e}", file=sys.stderr)


def main():
    """
    Main function to handle command-line arguments and execute the ping sweep.
    """
    parser = argparse.ArgumentParser(
        description="Network Ping Sweep Tool - Discover active hosts on a network",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.0/24                    # Scan entire subnet
  %(prog)s 10.0.0.1-10.0.0.50               # Scan IP range
  %(prog)s 172.16.1.1                       # Scan single IP
  %(prog)s 192.168.1.0/24 -t 2 -j 50        # Custom timeout and threads
  %(prog)s 10.0.0.0/24 -o results.txt       # Save results to file
        """
    )
    
    parser.add_argument(
        'target',
        help='Target IP address, CIDR notation, or IP range (e.g., 192.168.1.0/24, 10.0.0.1-10.0.0.50)'
    )
    
    parser.add_argument(
        '-t', '--timeout',
        type=float,
        default=1.0,
        help='Timeout for each ping in seconds (default: 1.0)'
    )
    
    parser.add_argument(
        '-j', '--threads',
        type=int,
        default=100,
        help='Maximum number of concurrent threads (default: 100)'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output file to save results'
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress progress output'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Ping Sweep Tool v1.0'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.timeout <= 0:
        print("Error: Timeout must be greater than 0", file=sys.stderr)
        sys.exit(1)
    
    if args.threads <= 0 or args.threads > 1000:
        print("Error: Thread count must be between 1 and 1000", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Parse IP input
        start_ip, end_ip = parse_ip_input(args.target)
        
        # Initialize ping sweep tool
        ping_tool = PingSweepTool(timeout=args.timeout, max_threads=args.threads)
        
        # Generate IP range
        ip_range = ping_tool._generate_ip_range(start_ip, end_ip)
        
        if len(ip_range) > 65536:  # Reasonable limit
            response = input(f"Warning: Scanning {len(ip_range)} hosts. Continue? (y/N): ")
            if response.lower() not in ['y', 'yes']:
                print("Scan cancelled.")
                sys.exit(0)
        
        # Perform ping sweep
        start_time = time.time()
        active_hosts = ping_tool.sweep(ip_range, show_progress=not args.quiet)
        end_time = time.time()
        
        # Display results
        print("\n" + "=" * 50)
        print("SCAN COMPLETE")
        print("=" * 50)
        print(f"Scan time: {end_time - start_time:.2f} seconds")
        print(f"Hosts scanned: {len(ip_range)}")
        print(f"Active hosts: {len(active_hosts)}")
        
        if active_hosts:
            print("\nActive Hosts:")
            print("-" * 20)
            for host in sorted(active_hosts, key=lambda x: ipaddress.ip_address(x)):
                print(f"  {host}")
        else:
            print("\nNo active hosts found.")
        
        # Save results if output file specified
        if args.output:
            save_results(active_hosts, args.output)
        
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()