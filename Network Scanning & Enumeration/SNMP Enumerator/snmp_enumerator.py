#!/usr/bin/env python3
"""
SNMP Enumerator

A comprehensive SNMP enumeration tool for network administration and security testing.
This script allows you to query SNMP-enabled devices to gather system information,
network interfaces, and other valuable data for legitimate network management purposes.

Usage:
    python snmp_enumerator.py -t 192.168.1.1 -c public
    python snmp_enumerator.py -t 192.168.1.0/24 -c public private -v 2c --timeout 3

Author: Network Security Tool
License: MIT
"""

import argparse
import ipaddress
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple
import subprocess
import re


class SNMPEnumerator:
    """
    SNMP Enumeration class that handles SNMP queries and data collection.
    """
    
    # Common SNMP OIDs for system information
    SYSTEM_OIDS = {
        'sysDescr': '1.3.6.1.2.1.1.1.0',        # System description
        'sysObjectID': '1.3.6.1.2.1.1.2.0',     # System object identifier
        'sysUpTime': '1.3.6.1.2.1.1.3.0',       # System uptime
        'sysContact': '1.3.6.1.2.1.1.4.0',      # System contact
        'sysName': '1.3.6.1.2.1.1.5.0',         # System name
        'sysLocation': '1.3.6.1.2.1.1.6.0',     # System location
        'sysServices': '1.3.6.1.2.1.1.7.0'      # System services
    }
    
    # Network interface OIDs
    INTERFACE_OIDS = {
        'ifIndex': '1.3.6.1.2.1.2.2.1.1',       # Interface index
        'ifDescr': '1.3.6.1.2.1.2.2.1.2',       # Interface description
        'ifType': '1.3.6.1.2.1.2.2.1.3',        # Interface type
        'ifMtu': '1.3.6.1.2.1.2.2.1.4',         # Interface MTU
        'ifSpeed': '1.3.6.1.2.1.2.2.1.5',       # Interface speed
        'ifPhysAddress': '1.3.6.1.2.1.2.2.1.6', # Interface MAC address
        'ifAdminStatus': '1.3.6.1.2.1.2.2.1.7', # Interface admin status
        'ifOperStatus': '1.3.6.1.2.1.2.2.1.8'   # Interface operational status
    }
    
    # TCP connection table OIDs
    TCP_OIDS = {
        'tcpConnState': '1.3.6.1.2.1.6.13.1.1',    # TCP connection state
        'tcpConnLocalAddress': '1.3.6.1.2.1.6.13.1.2',  # Local IP address
        'tcpConnLocalPort': '1.3.6.1.2.1.6.13.1.3',     # Local port
        'tcpConnRemAddress': '1.3.6.1.2.1.6.13.1.4',    # Remote IP address
        'tcpConnRemPort': '1.3.6.1.2.1.6.13.1.5'        # Remote port
    }

    def __init__(self, timeout: int = 2, retries: int = 1):
        """
        Initialize the SNMP Enumerator.
        
        Args:
            timeout (int): SNMP query timeout in seconds
            retries (int): Number of retries for failed queries
        """
        self.timeout = timeout
        self.retries = retries
        self.results = {}

    def check_snmp_availability(self) -> bool:
        """
        Check if snmpwalk and snmpget commands are available on the system.
        
        Returns:
            bool: True if SNMP tools are available, False otherwise
        """
        try:
            subprocess.run(['which', 'snmpwalk'], 
                          capture_output=True, check=True, timeout=5)
            subprocess.run(['which', 'snmpget'], 
                          capture_output=True, check=True, timeout=5)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def snmp_get(self, target: str, community: str, oid: str, version: str = '2c') -> Optional[str]:
        """
        Perform an SNMP GET operation.
        
        Args:
            target (str): Target IP address
            community (str): SNMP community string
            oid (str): SNMP OID to query
            version (str): SNMP version (1, 2c, 3)
            
        Returns:
            Optional[str]: SNMP response value or None if failed
        """
        try:
            cmd = [
                'snmpget', '-v', version, '-c', community,
                '-t', str(self.timeout), '-r', str(self.retries),
                target, oid
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and result.stdout:
                # Parse the output to extract the value
                output = result.stdout.strip()
                if '=' in output:
                    value = output.split('=', 1)[1].strip()
                    # Remove common SNMP type indicators
                    value = re.sub(r'^(STRING:|INTEGER:|Gauge32:|Counter32:|Counter64:|Timeticks:|OID:|IpAddress:)\s*', '', value)
                    # Remove quotes if present
                    value = value.strip('"\'')
                    return value
                    
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, Exception) as e:
            pass
            
        return None

    def snmp_walk(self, target: str, community: str, oid: str, version: str = '2c') -> Dict[str, str]:
        """
        Perform an SNMP WALK operation.
        
        Args:
            target (str): Target IP address
            community (str): SNMP community string
            oid (str): SNMP OID to walk
            version (str): SNMP version (1, 2c, 3)
            
        Returns:
            Dict[str, str]: Dictionary of OID -> value mappings
        """
        results = {}
        
        try:
            cmd = [
                'snmpwalk', '-v', version, '-c', community,
                '-t', str(self.timeout), '-r', str(self.retries),
                target, oid
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if '=' in line:
                        oid_part, value_part = line.split('=', 1)
                        oid_clean = oid_part.strip()
                        value_clean = value_part.strip()
                        # Remove common SNMP type indicators
                        value_clean = re.sub(r'^(STRING:|INTEGER:|Gauge32:|Counter32:|Counter64:|Timeticks:|OID:|IpAddress:)\s*', '', value_clean)
                        # Remove quotes if present
                        value_clean = value_clean.strip('"\'')
                        results[oid_clean] = value_clean
                        
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, Exception) as e:
            pass
            
        return results

    def test_snmp_access(self, target: str, communities: List[str], version: str = '2c') -> Optional[str]:
        """
        Test SNMP access with different community strings.
        
        Args:
            target (str): Target IP address
            communities (List[str]): List of community strings to test
            version (str): SNMP version to use
            
        Returns:
            Optional[str]: Valid community string or None if none work
        """
        test_oid = self.SYSTEM_OIDS['sysDescr']
        
        for community in communities:
            result = self.snmp_get(target, community, test_oid, version)
            if result:
                return community
                
        return None

    def get_system_info(self, target: str, community: str, version: str = '2c') -> Dict[str, str]:
        """
        Gather system information via SNMP.
        
        Args:
            target (str): Target IP address
            community (str): SNMP community string
            version (str): SNMP version to use
            
        Returns:
            Dict[str, str]: System information dictionary
        """
        system_info = {}
        
        for name, oid in self.SYSTEM_OIDS.items():
            value = self.snmp_get(target, community, oid, version)
            if value:
                system_info[name] = value
                
        return system_info

    def get_network_interfaces(self, target: str, community: str, version: str = '2c') -> List[Dict[str, str]]:
        """
        Gather network interface information via SNMP.
        
        Args:
            target (str): Target IP address
            community (str): SNMP community string
            version (str): SNMP version to use
            
        Returns:
            List[Dict[str, str]]: List of interface information dictionaries
        """
        interfaces = []
        
        # Get interface indices first
        indices_data = self.snmp_walk(target, community, self.INTERFACE_OIDS['ifIndex'], version)
        
        if not indices_data:
            return interfaces
            
        # Extract interface indices
        interface_indices = []
        for oid, value in indices_data.items():
            try:
                index = int(value)
                interface_indices.append(index)
            except ValueError:
                continue
                
        # Get information for each interface
        for index in interface_indices:
            interface_info = {'ifIndex': str(index)}
            
            for name, base_oid in self.INTERFACE_OIDS.items():
                if name == 'ifIndex':
                    continue
                    
                oid = f"{base_oid}.{index}"
                value = self.snmp_get(target, community, oid, version)
                if value:
                    interface_info[name] = value
                    
            if len(interface_info) > 1:  # More than just the index
                interfaces.append(interface_info)
                
        return interfaces

    def get_tcp_connections(self, target: str, community: str, version: str = '2c') -> List[Dict[str, str]]:
        """
        Gather TCP connection information via SNMP.
        
        Args:
            target (str): Target IP address
            community (str): SNMP community string
            version (str): SNMP version to use
            
        Returns:
            List[Dict[str, str]]: List of TCP connection dictionaries
        """
        connections = []
        
        # Get TCP connection state information
        conn_data = self.snmp_walk(target, community, self.TCP_OIDS['tcpConnState'], version)
        
        if not conn_data:
            return connections
            
        # Parse connection information
        for oid, state in conn_data.items():
            # Extract connection identifier from OID
            oid_parts = oid.split('.')
            if len(oid_parts) >= 4:
                try:
                    # The connection identifier is typically the last part of the OID
                    conn_id = '.'.join(oid_parts[-4:])
                    
                    connection_info = {
                        'state': state,
                        'connection_id': conn_id
                    }
                    
                    connections.append(connection_info)
                except (ValueError, IndexError):
                    continue
                    
        return connections

    def enumerate_target(self, target: str, communities: List[str], version: str = '2c', 
                        get_interfaces: bool = True, get_tcp: bool = False) -> Dict:
        """
        Perform comprehensive SNMP enumeration on a target.
        
        Args:
            target (str): Target IP address
            communities (List[str]): List of community strings to test
            version (str): SNMP version to use
            get_interfaces (bool): Whether to enumerate network interfaces
            get_tcp (bool): Whether to enumerate TCP connections
            
        Returns:
            Dict: Complete enumeration results
        """
        result = {
            'target': target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'snmp_accessible': False,
            'community': None,
            'system_info': {},
            'interfaces': [],
            'tcp_connections': []
        }
        
        # Test SNMP access
        valid_community = self.test_snmp_access(target, communities, version)
        
        if not valid_community:
            return result
            
        result['snmp_accessible'] = True
        result['community'] = valid_community
        
        # Get system information
        system_info = self.get_system_info(target, valid_community, version)
        result['system_info'] = system_info
        
        # Get network interfaces if requested
        if get_interfaces:
            interfaces = self.get_network_interfaces(target, valid_community, version)
            result['interfaces'] = interfaces
            
        # Get TCP connections if requested
        if get_tcp:
            tcp_connections = self.get_tcp_connections(target, valid_community, version)
            result['tcp_connections'] = tcp_connections
            
        return result

    def print_results(self, results: Dict):
        """
        Print enumeration results in a formatted way.
        
        Args:
            results (Dict): Enumeration results dictionary
        """
        print(f"\n{'='*60}")
        print(f"SNMP Enumeration Results for {results['target']}")
        print(f"Timestamp: {results['timestamp']}")
        print(f"{'='*60}")
        
        if not results['snmp_accessible']:
            print("❌ SNMP not accessible or no valid community string found")
            return
            
        print(f"✅ SNMP accessible with community: '{results['community']}'")
        
        # System Information
        if results['system_info']:
            print(f"\n📋 System Information:")
            print("-" * 30)
            for key, value in results['system_info'].items():
                print(f"  {key}: {value}")
                
        # Network Interfaces
        if results['interfaces']:
            print(f"\n🌐 Network Interfaces ({len(results['interfaces'])} found):")
            print("-" * 40)
            for i, interface in enumerate(results['interfaces'], 1):
                print(f"  Interface {i}:")
                for key, value in interface.items():
                    print(f"    {key}: {value}")
                print()
                
        # TCP Connections
        if results['tcp_connections']:
            print(f"\n🔗 TCP Connections ({len(results['tcp_connections'])} found):")
            print("-" * 35)
            for i, conn in enumerate(results['tcp_connections'], 1):
                print(f"  Connection {i}:")
                for key, value in conn.items():
                    print(f"    {key}: {value}")
                print()


def parse_targets(target_input: str) -> List[str]:
    """
    Parse target input and return list of IP addresses.
    
    Args:
        target_input (str): Target specification (IP, CIDR, or range)
        
    Returns:
        List[str]: List of IP addresses
    """
    targets = []
    
    try:
        # Check if it's a CIDR notation
        if '/' in target_input:
            network = ipaddress.ip_network(target_input, strict=False)
            targets = [str(ip) for ip in network.hosts()]
        else:
            # Single IP address
            ip = ipaddress.ip_address(target_input)
            targets = [str(ip)]
    except ValueError:
        # If parsing fails, treat as single target
        targets = [target_input]
        
    return targets


def main():
    """
    Main function to handle command-line arguments and execute SNMP enumeration.
    """
    parser = argparse.ArgumentParser(
        description='SNMP Enumerator - A tool for legitimate SNMP enumeration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python snmp_enumerator.py -t 192.168.1.1 -c public
  python snmp_enumerator.py -t 192.168.1.0/24 -c public private -v 2c
  python snmp_enumerator.py -t 10.0.0.1 -c public --no-interfaces --tcp
  python snmp_enumerator.py -t 192.168.1.1 -c public --timeout 5 --threads 10

Note: This tool is intended for legitimate network administration and 
security testing purposes only. Ensure you have proper authorization 
before scanning networks you do not own.
        '''
    )
    
    parser.add_argument('-t', '--target', required=True,
                       help='Target IP address or CIDR range (e.g., 192.168.1.1 or 192.168.1.0/24)')
    
    parser.add_argument('-c', '--communities', nargs='+', default=['public'],
                       help='SNMP community strings to test (default: public)')
    
    parser.add_argument('-v', '--version', choices=['1', '2c', '3'], default='2c',
                       help='SNMP version to use (default: 2c)')
    
    parser.add_argument('--timeout', type=int, default=2,
                       help='SNMP timeout in seconds (default: 2)')
    
    parser.add_argument('--retries', type=int, default=1,
                       help='Number of retries for failed queries (default: 1)')
    
    parser.add_argument('--threads', type=int, default=5,
                       help='Number of threads for concurrent scanning (default: 5)')
    
    parser.add_argument('--no-interfaces', action='store_true',
                       help='Skip network interface enumeration')
    
    parser.add_argument('--tcp', action='store_true',
                       help='Include TCP connection enumeration')
    
    parser.add_argument('--quiet', action='store_true',
                       help='Suppress banner and only show results')
    
    args = parser.parse_args()
    
    # Print banner
    if not args.quiet:
        print("SNMP Enumerator v1.0")
        print("=" * 50)
        print("For legitimate network administration use only!")
        print("=" * 50)
    
    # Initialize SNMP enumerator
    enumerator = SNMPEnumerator(timeout=args.timeout, retries=args.retries)
    
    # Check if SNMP tools are available
    if not enumerator.check_snmp_availability():
        print("❌ Error: SNMP tools (snmpwalk, snmpget) not found!")
        print("Please install net-snmp or net-snmp-utils package.")
        print("\nInstallation commands:")
        print("  Ubuntu/Debian: sudo apt-get install snmp snmp-mibs-downloader")
        print("  CentOS/RHEL:   sudo yum install net-snmp-utils")
        print("  macOS:         brew install net-snmp")
        sys.exit(1)
    
    # Parse targets
    targets = parse_targets(args.target)
    
    if not args.quiet:
        print(f"Scanning {len(targets)} target(s)...")
        print(f"Communities: {args.communities}")
        print(f"SNMP Version: {args.version}")
        print(f"Timeout: {args.timeout}s, Retries: {args.retries}")
        print()
    
    # Perform enumeration
    results = []
    
    if len(targets) == 1:
        # Single target - no threading needed
        result = enumerator.enumerate_target(
            targets[0], args.communities, args.version,
            get_interfaces=not args.no_interfaces,
            get_tcp=args.tcp
        )
        results.append(result)
    else:
        # Multiple targets - use threading
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = []
            
            for target in targets:
                future = executor.submit(
                    enumerator.enumerate_target,
                    target, args.communities, args.version,
                    not args.no_interfaces, args.tcp
                )
                futures.append(future)
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    print(f"Error processing target: {e}")
    
    # Print results
    accessible_count = 0
    for result in results:
        if result['snmp_accessible']:
            accessible_count += 1
            enumerator.print_results(result)
    
    # Summary
    if not args.quiet:
        print(f"\n{'='*60}")
        print(f"Scan Summary:")
        print(f"  Total targets scanned: {len(targets)}")
        print(f"  SNMP accessible: {accessible_count}")
        print(f"  SNMP inaccessible: {len(targets) - accessible_count}")
        print(f"{'='*60}")


if __name__ == '__main__':
    main()
