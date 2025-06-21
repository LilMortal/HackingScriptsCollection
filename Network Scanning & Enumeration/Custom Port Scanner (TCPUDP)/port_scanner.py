#!/usr/bin/env python3
"""
Custom Port Scanner (TCP/UDP)
A network diagnostic tool for scanning TCP and UDP ports on target hosts.

Usage:
    python port_scanner.py -t 192.168.1.1 -p 80,443,22
    python port_scanner.py -t example.com -p 1-1000 --udp
    python port_scanner.py -t 10.0.0.1 -p 80,443 --timeout 5 --threads 50

Author: Network Security Tool
License: MIT
"""

import socket
import threading
import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import ipaddress


class PortScanner:
    """
    A comprehensive port scanner supporting both TCP and UDP protocols.
    """
    
    def __init__(self, target, timeout=3, max_threads=100, verbose=False):
        """
        Initialize the port scanner.
        
        Args:
            target (str): Target IP address or hostname
            timeout (int): Connection timeout in seconds
            max_threads (int): Maximum number of concurrent threads
            verbose (bool): Enable verbose output
        """
        self.target = target
        self.timeout = timeout
        self.max_threads = max_threads
        self.verbose = verbose
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.lock = threading.Lock()
        
    def resolve_target(self):
        """
        Resolve target hostname to IP address.
        
        Returns:
            str: Resolved IP address
            
        Raises:
            socket.gaierror: If hostname cannot be resolved
        """
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror as e:
            raise socket.gaierror(f"Failed to resolve hostname '{self.target}': {e}")
    
    def validate_target(self, ip):
        """
        Validate target IP address and check if it's a private/local address.
        
        Args:
            ip (str): IP address to validate
            
        Returns:
            bool: True if IP is valid and safe to scan
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Allow scanning of private networks and localhost for legitimate testing
            return True
        except ipaddress.AddressValueError:
            return False
    
    def scan_tcp_port(self, port):
        """
        Scan a single TCP port.
        
        Args:
            port (int): Port number to scan
            
        Returns:
            tuple: (port, status, service_info)
        """
        try:
            # Create socket with timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt connection
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                service = self.get_service_name(port, 'tcp')
                with self.lock:
                    self.open_ports.append((port, 'tcp', service))
                return port, 'open', service
            else:
                with self.lock:
                    self.closed_ports.append((port, 'tcp'))
                return port, 'closed', None
                
        except socket.timeout:
            with self.lock:
                self.filtered_ports.append((port, 'tcp'))
            return port, 'filtered', None
        except Exception as e:
            if self.verbose:
                print(f"Error scanning TCP port {port}: {e}")
            with self.lock:
                self.filtered_ports.append((port, 'tcp'))
            return port, 'error', None
    
    def scan_udp_port(self, port):
        """
        Scan a single UDP port.
        
        Args:
            port (int): Port number to scan
            
        Returns:
            tuple: (port, status, service_info)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send empty UDP packet
            sock.sendto(b'', (self.target, port))
            
            try:
                # Try to receive data
                sock.recvfrom(1024)
                service = self.get_service_name(port, 'udp')
                with self.lock:
                    self.open_ports.append((port, 'udp', service))
                sock.close()
                return port, 'open', service
            except socket.timeout:
                # No response - could be open or filtered
                service = self.get_service_name(port, 'udp')
                with self.lock:
                    self.open_ports.append((port, 'udp', f"{service} (no response)"))
                sock.close()
                return port, 'open|filtered', service
            except ConnectionRefusedError:
                with self.lock:
                    self.closed_ports.append((port, 'udp'))
                sock.close()
                return port, 'closed', None
                
        except Exception as e:
            if self.verbose:
                print(f"Error scanning UDP port {port}: {e}")
            with self.lock:
                self.filtered_ports.append((port, 'udp'))
            return port, 'error', None
    
    def get_service_name(self, port, protocol):
        """
        Get service name for a given port and protocol.
        
        Args:
            port (int): Port number
            protocol (str): Protocol ('tcp' or 'udp')
            
        Returns:
            str: Service name or 'unknown'
        """
        try:
            return socket.getservbyport(port, protocol)
        except OSError:
            return 'unknown'
    
    def parse_port_range(self, port_string):
        """
        Parse port range string into list of ports.
        
        Args:
            port_string (str): Port specification (e.g., "80,443,1000-2000")
            
        Returns:
            list: List of port numbers
        """
        ports = []
        
        for part in port_string.split(','):
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    if start > end:
                        start, end = end, start
                    ports.extend(range(start, end + 1))
                except ValueError:
                    print(f"Invalid port range: {part}")
                    continue
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    print(f"Invalid port: {part}")
                    continue
        
        # Remove duplicates and sort
        return sorted(list(set(ports)))
    
    def scan_ports(self, ports, protocol='tcp'):
        """
        Scan multiple ports using threading.
        
        Args:
            ports (list): List of port numbers
            protocol (str): Protocol to scan ('tcp' or 'udp')
        """
        print(f"\nStarting {protocol.upper()} scan on {self.target}")
        print(f"Scanning {len(ports)} ports with {self.max_threads} threads")
        print(f"Timeout: {self.timeout} seconds")
        print("-" * 50)
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            if protocol.lower() == 'tcp':
                futures = {executor.submit(self.scan_tcp_port, port): port for port in ports}
            else:
                futures = {executor.submit(self.scan_udp_port, port): port for port in ports}
            
            completed = 0
            for future in as_completed(futures):
                port = futures[future]
                try:
                    port_num, status, service = future.result()
                    if self.verbose or status in ['open', 'open|filtered']:
                        service_info = f" ({service})" if service and service != 'unknown' else ""
                        print(f"Port {port_num}/{protocol}: {status}{service_info}")
                except Exception as e:
                    if self.verbose:
                        print(f"Error scanning port {port}: {e}")
                
                completed += 1
                if completed % 100 == 0 or completed == len(ports):
                    progress = (completed / len(ports)) * 100
                    print(f"Progress: {completed}/{len(ports)} ({progress:.1f}%)")
        
        end_time = time.time()
        print(f"\nScan completed in {end_time - start_time:.2f} seconds")
    
    def print_summary(self):
        """Print scan summary."""
        print("\n" + "="*60)
        print(f"SCAN SUMMARY FOR {self.target}")
        print("="*60)
        
        if self.open_ports:
            print(f"\nOPEN PORTS ({len(self.open_ports)}):")
            print("-" * 30)
            for port, protocol, service in sorted(self.open_ports):
                service_info = f" ({service})" if service and service != 'unknown' else ""
                print(f"{port}/{protocol}{service_info}")
        
        if self.verbose and self.closed_ports:
            print(f"\nCLOSED PORTS ({len(self.closed_ports)}):")
            print("-" * 30)
            closed_tcp = [p for p, proto in self.closed_ports if proto == 'tcp']
            closed_udp = [p for p, proto in self.closed_ports if proto == 'udp']
            
            if closed_tcp:
                print(f"TCP: {', '.join(map(str, sorted(closed_tcp)))}")
            if closed_udp:
                print(f"UDP: {', '.join(map(str, sorted(closed_udp)))}")
        
        if self.verbose and self.filtered_ports:
            print(f"\nFILTERED/ERROR PORTS ({len(self.filtered_ports)}):")
            print("-" * 30)
            filtered_tcp = [p for p, proto in self.filtered_ports if proto == 'tcp']
            filtered_udp = [p for p, proto in self.filtered_ports if proto == 'udp']
            
            if filtered_tcp:
                print(f"TCP: {', '.join(map(str, sorted(filtered_tcp)))}")
            if filtered_udp:
                print(f"UDP: {', '.join(map(str, sorted(filtered_udp)))}")
        
        total_scanned = len(self.open_ports) + len(self.closed_ports) + len(self.filtered_ports)
        print(f"\nTotal ports scanned: {total_scanned}")
        print(f"Open ports: {len(self.open_ports)}")
        print(f"Closed ports: {len(self.closed_ports)}")
        print(f"Filtered/Error ports: {len(self.filtered_ports)}")


def validate_arguments(args):
    """
    Validate command line arguments.
    
    Args:
        args: Parsed arguments from argparse
        
    Returns:
        bool: True if arguments are valid
    """
    # Validate timeout
    if args.timeout <= 0:
        print("Error: Timeout must be greater than 0")
        return False
    
    # Validate thread count
    if args.threads <= 0 or args.threads > 1000:
        print("Error: Thread count must be between 1 and 1000")
        return False
    
    # Basic port validation will be done in parse_port_range
    return True


def main():
    """Main function to handle command line arguments and execute scan."""
    parser = argparse.ArgumentParser(
        description="Custom TCP/UDP Port Scanner - A network diagnostic tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner.py -t 192.168.1.1 -p 80,443,22
  python port_scanner.py -t example.com -p 1-1000 --udp
  python port_scanner.py -t 10.0.0.1 -p 80,443 --timeout 5 --threads 50
  python port_scanner.py -t localhost -p 1-65535 --tcp --udp --verbose

Note: This tool is for legitimate network diagnostics only.
Use responsibly and only on networks you own or have permission to test.
        """
    )
    
    parser.add_argument('-t', '--target', required=True,
                       help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', required=True,
                       help='Ports to scan (e.g., 80,443,1000-2000)')
    parser.add_argument('--tcp', action='store_true', default=True,
                       help='Scan TCP ports (default)')
    parser.add_argument('--udp', action='store_true',
                       help='Scan UDP ports')
    parser.add_argument('--timeout', type=int, default=3,
                       help='Connection timeout in seconds (default: 3)')
    parser.add_argument('--threads', type=int, default=100,
                       help='Maximum number of threads (default: 100)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not validate_arguments(args):
        sys.exit(1)
    
    # If both --tcp and --udp are specified, or if only --udp is specified
    if args.udp and not args.tcp:
        args.tcp = False
    
    try:
        # Create scanner instance
        scanner = PortScanner(
            target=args.target,
            timeout=args.timeout,
            max_threads=args.threads,
            verbose=args.verbose
        )
        
        # Resolve target
        print(f"Resolving target: {args.target}")
        resolved_ip = scanner.resolve_target()
        print(f"Target resolved to: {resolved_ip}")
        
        # Validate target
        if not scanner.validate_target(resolved_ip):
            print(f"Error: Invalid IP address: {resolved_ip}")
            sys.exit(1)
        
        # Update scanner target to resolved IP
        scanner.target = resolved_ip
        
        # Parse ports
        ports = scanner.parse_port_range(args.ports)
        if not ports:
            print("Error: No valid ports specified")
            sys.exit(1)
        
        # Validate port range
        invalid_ports = [p for p in ports if p < 1 or p > 65535]
        if invalid_ports:
            print(f"Error: Invalid port numbers: {invalid_ports}")
            sys.exit(1)
        
        print(f"Scan target: {args.target} ({resolved_ip})")
        print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Perform scans
        if args.tcp:
            scanner.scan_ports(ports, 'tcp')
        
        if args.udp:
            scanner.scan_ports(ports, 'udp')
        
        # Print results
        scanner.print_summary()
        
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(1)
    except socket.gaierror as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
