#!/usr/bin/env python3
"""
Traceroute Script - A Python implementation of the traceroute network diagnostic tool.

This script traces the route packets take from your computer to a destination host,
showing each hop along the way with timing information.

Usage:
    python traceroute.py google.com
    python traceroute.py -m 20 -t 2 8.8.8.8
    python traceroute.py --help

Author: Python Traceroute Implementation
License: MIT
"""

import argparse
import socket
import struct
import time
import sys
import os
from typing import Optional, Tuple, List


class TracerouteError(Exception):
    """Custom exception for traceroute-specific errors."""
    pass


class Traceroute:
    """
    A Python implementation of the traceroute network diagnostic tool.
    
    This class provides functionality to trace the network path to a destination
    by sending packets with incrementally increasing TTL values.
    """
    
    def __init__(self, destination: str, max_hops: int = 30, timeout: float = 5.0):
        """
        Initialize the Traceroute object.
        
        Args:
            destination (str): Target hostname or IP address
            max_hops (int): Maximum number of hops to trace (default: 30)
            timeout (float): Timeout for each probe in seconds (default: 5.0)
        """
        self.destination = destination
        self.max_hops = max_hops
        self.timeout = timeout
        self.dest_ip = None
        
    def resolve_destination(self) -> str:
        """
        Resolve the destination hostname to an IP address.
        
        Returns:
            str: The resolved IP address
            
        Raises:
            TracerouteError: If hostname resolution fails
        """
        try:
            self.dest_ip = socket.gethostbyname(self.destination)
            return self.dest_ip
        except socket.gaierror as e:
            raise TracerouteError(f"Cannot resolve hostname '{self.destination}': {e}")
    
    def create_icmp_socket(self) -> socket.socket:
        """
        Create an ICMP socket for receiving responses.
        
        Returns:
            socket.socket: Configured ICMP socket
            
        Raises:
            TracerouteError: If socket creation fails
        """
        try:
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            icmp_socket.settimeout(self.timeout)
            return icmp_socket
        except PermissionError:
            raise TracerouteError(
                "Permission denied: ICMP sockets require root privileges. "
                "Try running with sudo or use UDP mode."
            )
        except Exception as e:
            raise TracerouteError(f"Failed to create ICMP socket: {e}")
    
    def create_udp_socket(self, ttl: int) -> socket.socket:
        """
        Create a UDP socket with specified TTL for sending probes.
        
        Args:
            ttl (int): Time-to-live value for the packet
            
        Returns:
            socket.socket: Configured UDP socket
            
        Raises:
            TracerouteError: If socket creation fails
        """
        try:
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            return udp_socket
        except Exception as e:
            raise TracerouteError(f"Failed to create UDP socket: {e}")
    
    def send_probe(self, udp_socket: socket.socket, port: int) -> float:
        """
        Send a UDP probe packet to the destination.
        
        Args:
            udp_socket (socket.socket): UDP socket to send from
            port (int): Destination port number
            
        Returns:
            float: Timestamp when packet was sent
        """
        try:
            send_time = time.time()
            udp_socket.sendto(b'', (self.dest_ip, port))
            return send_time
        except Exception as e:
            raise TracerouteError(f"Failed to send probe: {e}")
    
    def receive_response(self, icmp_socket: socket.socket) -> Tuple[Optional[str], Optional[float]]:
        """
        Receive and parse ICMP response.
        
        Args:
            icmp_socket (socket.socket): ICMP socket to receive from
            
        Returns:
            Tuple[Optional[str], Optional[float]]: (source_ip, round_trip_time) or (None, None)
        """
        try:
            recv_time = time.time()
            packet, addr = icmp_socket.recvfrom(1024)
            return addr[0], recv_time
        except socket.timeout:
            return None, None
        except Exception:
            return None, None
    
    def get_hostname(self, ip: str) -> str:
        """
        Attempt to resolve IP address to hostname.
        
        Args:
            ip (str): IP address to resolve
            
        Returns:
            str: Hostname if resolved, otherwise the IP address
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return f"{hostname} ({ip})"
        except (socket.herror, socket.timeout):
            return ip
    
    def trace(self, resolve_hostnames: bool = True, num_probes: int = 3) -> List[dict]:
        """
        Perform the traceroute operation.
        
        Args:
            resolve_hostnames (bool): Whether to resolve IP addresses to hostnames
            num_probes (int): Number of probes to send per hop
            
        Returns:
            List[dict]: List of hop information dictionaries
            
        Raises:
            TracerouteError: If traceroute operation fails
        """
        # Resolve destination
        dest_ip = self.resolve_destination()
        print(f"traceroute to {self.destination} ({dest_ip}), {self.max_hops} hops max")
        
        # Check if running as root for ICMP
        use_icmp = os.geteuid() == 0
        if not use_icmp:
            print("Note: Running without root privileges, using UDP probes")
        
        results = []
        base_port = 33434  # Standard traceroute base port
        
        for ttl in range(1, self.max_hops + 1):
            hop_info = {
                'hop': ttl,
                'responses': [],
                'reached_destination': False
            }
            
            # Create sockets for this hop
            try:
                if use_icmp:
                    icmp_socket = self.create_icmp_socket()
                udp_socket = self.create_udp_socket(ttl)
            except TracerouteError as e:
                print(f"Error creating sockets: {e}")
                return results
            
            print(f"{ttl:2d}  ", end="", flush=True)
            
            # Send probes for this hop
            hop_responses = []
            for probe in range(num_probes):
                port = base_port + ttl + probe
                
                try:
                    # Send probe
                    send_time = self.send_probe(udp_socket, port)
                    
                    # Receive response (only if using ICMP)
                    if use_icmp:
                        source_ip, recv_time = self.receive_response(icmp_socket)
                        
                        if source_ip and recv_time:
                            rtt = (recv_time - send_time) * 1000  # Convert to milliseconds
                            
                            # Check if we reached the destination
                            if source_ip == dest_ip:
                                hop_info['reached_destination'] = True
                            
                            # Resolve hostname if requested
                            if resolve_hostnames and source_ip not in [r.get('ip') for r in hop_responses]:
                                hostname = self.get_hostname(source_ip)
                            else:
                                hostname = source_ip
                            
                            response = {
                                'ip': source_ip,
                                'hostname': hostname,
                                'rtt': rtt
                            }
                            hop_responses.append(response)
                            
                            # Print this probe's result
                            if probe == 0:
                                print(f"{hostname}  {rtt:.3f} ms", end="")
                            else:
                                print(f"  {rtt:.3f} ms", end="")
                        else:
                            print("  *", end="")
                            hop_responses.append({'timeout': True})
                    else:
                        # Without ICMP, we can't get responses, so just show attempt
                        print("  *", end="")
                        hop_responses.append({'udp_probe': True})
                        
                except TracerouteError as e:
                    print(f"  Error: {e}", end="")
                    hop_responses.append({'error': str(e)})
                
                # Small delay between probes
                time.sleep(0.1)
            
            print()  # New line after hop
            
            hop_info['responses'] = hop_responses
            results.append(hop_info)
            
            # Close sockets
            udp_socket.close()
            if use_icmp:
                icmp_socket.close()
            
            # Check if we reached the destination
            if hop_info['reached_destination']:
                print(f"Reached destination {self.destination} ({dest_ip})")
                break
        
        return results


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Trace the network path to a destination host",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s google.com
  %(prog)s -m 20 -t 2 8.8.8.8
  %(prog)s --no-resolve example.com
  sudo %(prog)s --icmp google.com
        """
    )
    
    parser.add_argument(
        'destination',
        help='Target hostname or IP address'
    )
    
    parser.add_argument(
        '-m', '--max-hops',
        type=int,
        default=30,
        help='Maximum number of hops to trace (default: 30)'
    )
    
    parser.add_argument(
        '-t', '--timeout',
        type=float,
        default=5.0,
        help='Timeout for each probe in seconds (default: 5.0)'
    )
    
    parser.add_argument(
        '-p', '--probes',
        type=int,
        default=3,
        help='Number of probes per hop (default: 3)'
    )
    
    parser.add_argument(
        '--no-resolve',
        action='store_true',
        help='Do not resolve IP addresses to hostnames'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Traceroute Script v1.0'
    )
    
    return parser.parse_args()


def main():
    """
    Main function to run the traceroute script.
    """
    try:
        # Parse command-line arguments
        args = parse_arguments()
        
        # Validate arguments
        if args.max_hops < 1 or args.max_hops > 255:
            raise ValueError("Max hops must be between 1 and 255")
        
        if args.timeout <= 0:
            raise ValueError("Timeout must be positive")
        
        if args.probes < 1:
            raise ValueError("Number of probes must be at least 1")
        
        # Create and run traceroute
        tracer = Traceroute(
            destination=args.destination,
            max_hops=args.max_hops,
            timeout=args.timeout
        )
        
        # Perform the trace
        results = tracer.trace(
            resolve_hostnames=not args.no_resolve,
            num_probes=args.probes
        )
        
        # Print summary if verbose mode would be implemented
        print(f"\nTraceroute completed with {len(results)} hops")
        
    except KeyboardInterrupt:
        print("\nTraceroute interrupted by user")
        sys.exit(1)
    except (TracerouteError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()