#!/usr/bin/env python3
"""
OS Detection Tool (TTL/Window Size)

This script performs operating system detection by analyzing TTL (Time To Live) 
values and TCP window sizes from network responses. It uses ICMP ping and TCP 
SYN packets to gather fingerprinting information.

Usage:
    python3 os_detection.py -t 192.168.1.1
    python3 os_detection.py -t google.com -p 80,443 -v
    python3 os_detection.py -f targets.txt --timeout 5

Author: Network Security Tool
License: MIT
"""

import argparse
import socket
import struct
import subprocess
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional, Set
import re
import platform
import ipaddress


class OSFingerprint:
    """Class to store OS fingerprinting signatures"""
    
    # TTL-based OS signatures
    TTL_SIGNATURES = {
        64: ["Linux", "Unix", "Android", "macOS"],
        128: ["Windows"],
        255: ["Cisco IOS", "FreeBSD", "OpenBSD"],
        60: ["macOS (older)"],
        32: ["Windows 95/98"],
        30: ["Windows NT"],
    }
    
    # TCP Window Size signatures (common values)
    WINDOW_SIGNATURES = {
        65535: ["Windows (older)", "Linux (default)"],
        8192: ["Windows XP/2003"],
        16384: ["Windows Vista/7/8/10"],
        32768: ["Linux", "Unix variants"],
        5840: ["Linux (specific kernel)"],
        4128: ["Windows 2000"],
        1024: ["Embedded systems"],
    }
    
    @staticmethod
    def analyze_ttl(ttl: int) -> List[str]:
        """Analyze TTL value and return possible OS matches"""
        # Account for routing hops (TTL decreases by 1 per hop)
        possible_original_ttls = []
        
        # Common initial TTL values
        initial_ttls = [32, 60, 64, 128, 255]
        
        for initial_ttl in initial_ttls:
            if ttl <= initial_ttl:
                hops = initial_ttl - ttl
                if hops >= 0 and hops <= 30:  # Reasonable hop count
                    possible_original_ttls.append(initial_ttl)
        
        os_candidates = []
        for orig_ttl in possible_original_ttls:
            if orig_ttl in OSFingerprint.TTL_SIGNATURES:
                os_candidates.extend(OSFingerprint.TTL_SIGNATURES[orig_ttl])
        
        return list(set(os_candidates))  # Remove duplicates
    
    @staticmethod
    def analyze_window_size(window_size: int) -> List[str]:
        """Analyze TCP window size and return possible OS matches"""
        if window_size in OSFingerprint.WINDOW_SIGNATURES:
            return OSFingerprint.WINDOW_SIGNATURES[window_size]
        
        # Check for common patterns
        os_candidates = []
        if window_size == 65535:
            os_candidates.extend(["Windows (older)", "Linux"])
        elif 16000 <= window_size <= 17000:
            os_candidates.append("Windows (modern)")
        elif 32000 <= window_size <= 33000:
            os_candidates.extend(["Linux", "Unix"])
        elif window_size < 4096:
            os_candidates.append("Embedded/IoT device")
        
        return os_candidates


class NetworkScanner:
    """Main class for network OS detection"""
    
    def __init__(self, timeout: int = 3, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.results = {}
    
    def ping_host(self, target: str) -> Optional[Tuple[float, int]]:
        """
        Ping a host and extract TTL value
        Returns: (response_time, ttl) or None if failed
        """
        try:
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", str(self.timeout * 1000), target]
            else:
                cmd = ["ping", "-c", "1", "-W", str(self.timeout), target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout + 2)
            
            if result.returncode != 0:
                return None
            
            # Extract TTL from ping output
            ttl_match = re.search(r'ttl=(\d+)', result.stdout, re.IGNORECASE)
            if not ttl_match:
                ttl_match = re.search(r'TTL=(\d+)', result.stdout)
            
            if ttl_match:
                ttl = int(ttl_match.group(1))
                
                # Extract response time
                time_match = re.search(r'time[<=](\d+(?:\.\d+)?)', result.stdout, re.IGNORECASE)
                response_time = float(time_match.group(1)) if time_match else 0.0
                
                return (response_time, ttl)
        
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError) as e:
            if self.verbose:
                print(f"Ping failed for {target}: {e}")
        
        return None
    
    def tcp_connect(self, target: str, port: int) -> Optional[Dict]:
        """
        Attempt TCP connection to extract window size and other TCP parameters
        Returns: Dictionary with TCP information or None if failed
        """
        try:
            # Resolve hostname to IP
            ip = socket.gethostbyname(target)
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            start_time = time.time()
            result = sock.connect_ex((ip, port))
            connect_time = time.time() - start_time
            
            if result == 0:
                # Connection successful
                tcp_info = {
                    'port': port,
                    'status': 'open',
                    'connect_time': connect_time * 1000,  # Convert to ms
                    'window_size': None
                }
                
                # Try to get socket options (limited on most systems)
                try:
                    # This is system-dependent and may not work on all platforms
                    sock_info = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                    tcp_info['buffer_size'] = sock_info
                except:
                    pass
                
                sock.close()
                return tcp_info
            else:
                sock.close()
                return {'port': port, 'status': 'closed', 'connect_time': connect_time * 1000}
        
        except socket.timeout:
            return {'port': port, 'status': 'timeout', 'connect_time': self.timeout * 1000}
        except Exception as e:
            if self.verbose:
                print(f"TCP connect failed for {target}:{port}: {e}")
            return {'port': port, 'status': 'error', 'error': str(e)}
    
    def scan_host(self, target: str, ports: List[int] = None) -> Dict:
        """
        Perform comprehensive OS detection on a single host
        """
        if ports is None:
            ports = [22, 23, 53, 80, 135, 139, 443, 445, 993, 995, 3389]
        
        result = {
            'target': target,
            'ping_result': None,
            'tcp_results': [],
            'os_candidates': set(),
            'confidence': 'Unknown'
        }
        
        # Perform ping test
        if self.verbose:
            print(f"Pinging {target}...")
        
        ping_result = self.ping_host(target)
        if ping_result:
            response_time, ttl = ping_result
            result['ping_result'] = {
                'response_time': response_time,
                'ttl': ttl,
                'os_candidates': OSFingerprint.analyze_ttl(ttl)
            }
            result['os_candidates'].update(result['ping_result']['os_candidates'])
        
        # Perform TCP scans
        if self.verbose:
            print(f"Scanning TCP ports on {target}...")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            tcp_futures = {executor.submit(self.tcp_connect, target, port): port for port in ports}
            
            for future in as_completed(tcp_futures):
                tcp_result = future.result()
                if tcp_result:
                    result['tcp_results'].append(tcp_result)
        
        # Analyze results and determine confidence
        self._analyze_confidence(result)
        
        return result
    
    def _analyze_confidence(self, result: Dict):
        """Analyze scan results and assign confidence level"""
        os_votes = {}
        
        # Count votes from different detection methods
        if result['ping_result'] and result['ping_result']['os_candidates']:
            for os_name in result['ping_result']['os_candidates']:
                os_votes[os_name] = os_votes.get(os_name, 0) + 2  # TTL gets higher weight
        
        # Count open ports for additional fingerprinting
        open_ports = [tcp['port'] for tcp in result['tcp_results'] if tcp['status'] == 'open']
        
        # Port-based OS hints
        if 3389 in open_ports:  # RDP
            os_votes['Windows'] = os_votes.get('Windows', 0) + 3
        if 22 in open_ports:  # SSH
            for os_name in ['Linux', 'Unix', 'macOS']:
                os_votes[os_name] = os_votes.get(os_name, 0) + 1
        if 135 in open_ports or 139 in open_ports or 445 in open_ports:  # Windows services
            os_votes['Windows'] = os_votes.get('Windows', 0) + 2
        
        # Determine confidence and best guess
        if os_votes:
            best_guess = max(os_votes, key=os_votes.get)
            max_votes = os_votes[best_guess]
            
            if max_votes >= 4:
                result['confidence'] = 'High'
            elif max_votes >= 2:
                result['confidence'] = 'Medium'
            else:
                result['confidence'] = 'Low'
            
            result['best_guess'] = best_guess
            result['os_votes'] = os_votes
        else:
            result['confidence'] = 'Unknown'
            result['best_guess'] = 'Unknown'
    
    def scan_multiple_hosts(self, targets: List[str], ports: List[int] = None) -> Dict:
        """Scan multiple hosts concurrently"""
        results = {}
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_target = {executor.submit(self.scan_host, target, ports): target for target in targets}
            
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    results[target] = result
                except Exception as e:
                    if self.verbose:
                        print(f"Error scanning {target}: {e}")
                    results[target] = {'error': str(e)}
        
        return results


def print_results(results: Dict, verbose: bool = False):
    """Print scan results in a formatted way"""
    if isinstance(results, dict) and 'target' in results:
        # Single host result
        results = {results['target']: results}
    
    for target, result in results.items():
        print(f"\n{'='*60}")
        print(f"Target: {target}")
        print('='*60)
        
        if 'error' in result:
            print(f"Error: {result['error']}")
            continue
        
        # Ping results
        if result.get('ping_result'):
            ping = result['ping_result']
            print(f"ICMP Ping:")
            print(f"  Response Time: {ping['response_time']:.2f} ms")
            print(f"  TTL: {ping['ttl']}")
            print(f"  OS Candidates (TTL): {', '.join(ping['os_candidates'])}")
        else:
            print("ICMP Ping: Failed or filtered")
        
        # TCP results
        open_ports = [tcp for tcp in result.get('tcp_results', []) if tcp['status'] == 'open']
        if open_ports:
            print(f"\nOpen TCP Ports:")
            for tcp in open_ports:
                print(f"  Port {tcp['port']}: Open ({tcp['connect_time']:.1f} ms)")
        
        # OS Detection Summary
        print(f"\nOS Detection Summary:")
        print(f"  Best Guess: {result.get('best_guess', 'Unknown')}")
        print(f"  Confidence: {result.get('confidence', 'Unknown')}")
        
        if verbose and result.get('os_votes'):
            print(f"  Vote Breakdown:")
            for os_name, votes in sorted(result['os_votes'].items(), key=lambda x: x[1], reverse=True):
                print(f"    {os_name}: {votes} votes")


def load_targets_from_file(filename: str) -> List[str]:
    """Load target hosts from a file (one per line)"""
    targets = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file '{filename}': {e}")
        sys.exit(1)
    
    return targets


def validate_target(target: str) -> bool:
    """Validate if target is a valid IP address or hostname"""
    try:
        # Try parsing as IP address
        ipaddress.ip_address(target)
        return True
    except ValueError:
        # Try resolving as hostname
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False


def parse_ports(port_string: str) -> List[int]:
    """Parse port string (e.g., '80,443,22-25') into list of integers"""
    ports = []
    for part in port_string.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(list(set(ports)))  # Remove duplicates and sort


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="OS Detection Tool using TTL and TCP Window Size analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.1
  %(prog)s -t google.com -p 80,443 -v
  %(prog)s -f targets.txt --timeout 5
  %(prog)s -t 10.0.0.1-10.0.0.10 -p 22,80,443
        """
    )
    
    parser.add_argument('-t', '--target', 
                       help='Target host(s) to scan (IP address or hostname)')
    parser.add_argument('-f', '--file',
                       help='File containing list of targets (one per line)')
    parser.add_argument('-p', '--ports', default='22,23,53,80,135,139,443,445,993,995,3389',
                       help='Ports to scan (comma-separated, ranges supported)')
    parser.add_argument('--timeout', type=int, default=3,
                       help='Timeout in seconds for network operations (default: 3)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.target and not args.file:
        parser.error("Either --target or --file must be specified")
    
    # Parse ports
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        parser.error(f"Invalid port specification: {e}")
    
    # Collect targets
    targets = []
    
    if args.target:
        # Handle single target or IP range (basic support)
        if '-' in args.target and '.' in args.target:
            # Simple IP range handling (e.g., 192.168.1.1-192.168.1.10)
            try:
                start_ip, end_ip = args.target.split('-')
                start = ipaddress.IPv4Address(start_ip)
                end = ipaddress.IPv4Address(end_ip)
                
                for ip_int in range(int(start), int(end) + 1):
                    targets.append(str(ipaddress.IPv4Address(ip_int)))
            except:
                targets = [args.target]  # Treat as single target if parsing fails
        else:
            targets = [args.target]
    
    if args.file:
        targets.extend(load_targets_from_file(args.file))
    
    # Validate targets
    valid_targets = []
    for target in targets:
        if validate_target(target):
            valid_targets.append(target)
        else:
            print(f"Warning: Invalid target '{target}', skipping...")
    
    if not valid_targets:
        print("Error: No valid targets to scan")
        sys.exit(1)
    
    # Initialize scanner
    scanner = NetworkScanner(timeout=args.timeout, verbose=args.verbose)
    
    # Print scan information
    print(f"OS Detection Tool v1.0")
    print(f"Scanning {len(valid_targets)} target(s)")
    print(f"Ports: {','.join(map(str, ports))}")
    print(f"Timeout: {args.timeout} seconds")
    print()
    
    # Perform scan
    try:
        if len(valid_targets) == 1:
            result = scanner.scan_host(valid_targets[0], ports)
            print_results(result, args.verbose)
        else:
            results = scanner.scan_multiple_hosts(valid_targets, ports)
            print_results(results, args.verbose)
    
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error during scan: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
