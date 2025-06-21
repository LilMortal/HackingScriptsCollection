#!/usr/bin/env python3
"""
Nmap Automation Wrapper

A Python wrapper script for automating Nmap network scans with predefined scan types,
output formatting, and result processing capabilities.

Author: Network Security Tools
License: MIT
Version: 1.0.0

Usage Example:
    python nmap_wrapper.py -t 192.168.1.0/24 -s quick
    python nmap_wrapper.py -t example.com -s comprehensive -o results.xml
    python nmap_wrapper.py -t 10.0.0.1-10 -s port-scan -p 80,443,22
"""

import argparse
import subprocess
import sys
import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict, Optional, Union
import re
import ipaddress


class NmapWrapper:
    """
    A wrapper class for automating Nmap scans with various predefined configurations.
    """
    
    def __init__(self):
        """Initialize the NmapWrapper with predefined scan types."""
        self.scan_types = {
            'quick': '-T4 -F',
            'comprehensive': '-sS -sV -O -A -T4',
            'stealth': '-sS -T2',
            'port-scan': '-sS -T4',
            'udp-scan': '-sU -T4',
            'version-detect': '-sV -T4',
            'os-detect': '-O -T4',
            'vuln-scan': '-sV --script vuln -T4'
        }
        
        self.output_formats = ['xml', 'json', 'txt', 'grepable']
        
    def validate_target(self, target: str) -> bool:
        """
        Validate if the target is a valid IP address, IP range, or hostname.
        
        Args:
            target (str): The target to validate
            
        Returns:
            bool: True if target is valid, False otherwise
        """
        try:
            # Check if it's a valid IP address or network
            ipaddress.ip_address(target)
            return True
        except ValueError:
            try:
                # Check if it's a valid network (CIDR notation)
                ipaddress.ip_network(target, strict=False)
                return True
            except ValueError:
                # Check if it's a valid hostname/domain pattern
                hostname_pattern = re.compile(
                    r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
                    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
                )
                # Check for IP ranges (e.g., 192.168.1.1-10)
                range_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$')
                
                return bool(hostname_pattern.match(target) or range_pattern.match(target))
    
    def check_nmap_installed(self) -> bool:
        """
        Check if Nmap is installed and accessible.
        
        Returns:
            bool: True if Nmap is installed, False otherwise
        """
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def build_nmap_command(self, target: str, scan_type: str, 
                          ports: Optional[str] = None, 
                          output_file: Optional[str] = None,
                          output_format: str = 'xml',
                          additional_args: Optional[str] = None) -> List[str]:
        """
        Build the Nmap command based on provided parameters.
        
        Args:
            target (str): Target IP, hostname, or network
            scan_type (str): Type of scan to perform
            ports (str, optional): Specific ports to scan
            output_file (str, optional): Output file path
            output_format (str): Output format (xml, json, txt, grepable)
            additional_args (str, optional): Additional Nmap arguments
            
        Returns:
            List[str]: Complete Nmap command as list of arguments
        """
        cmd = ['nmap']
        
        # Add scan type parameters
        if scan_type in self.scan_types:
            cmd.extend(self.scan_types[scan_type].split())
        else:
            raise ValueError(f"Unknown scan type: {scan_type}")
        
        # Add port specification
        if ports:
            cmd.extend(['-p', ports])
        
        # Add output format and file
        if output_file:
            if output_format == 'xml':
                cmd.extend(['-oX', output_file])
            elif output_format == 'json':
                cmd.extend(['-oX', output_file])  # XML first, convert to JSON later
            elif output_format == 'txt':
                cmd.extend(['-oN', output_file])
            elif output_format == 'grepable':
                cmd.extend(['-oG', output_file])
        
        # Add additional arguments
        if additional_args:
            cmd.extend(additional_args.split())
        
        # Add target
        cmd.append(target)
        
        return cmd
    
    def parse_xml_results(self, xml_file: str) -> Dict:
        """
        Parse Nmap XML output and extract key information.
        
        Args:
            xml_file (str): Path to XML output file
            
        Returns:
            Dict: Parsed scan results
        """
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            results = {
                'scan_info': {},
                'hosts': []
            }
            
            # Extract scan information
            scan_info = root.find('scaninfo')
            if scan_info is not None:
                results['scan_info'] = {
                    'type': scan_info.get('type'),
                    'protocol': scan_info.get('protocol'),
                    'numservices': scan_info.get('numservices'),
                    'services': scan_info.get('services')
                }
            
            # Extract host information
            for host in root.findall('host'):
                host_info = {'addresses': [], 'ports': [], 'os': None}
                
                # Get addresses
                for address in host.findall('address'):
                    host_info['addresses'].append({
                        'addr': address.get('addr'),
                        'addrtype': address.get('addrtype')
                    })
                
                # Get ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        port_info = {
                            'portid': port.get('portid'),
                            'protocol': port.get('protocol'),
                            'state': None,
                            'service': None
                        }
                        
                        state = port.find('state')
                        if state is not None:
                            port_info['state'] = state.get('state')
                        
                        service = port.find('service')
                        if service is not None:
                            port_info['service'] = {
                                'name': service.get('name'),
                                'product': service.get('product'),
                                'version': service.get('version')
                            }
                        
                        host_info['ports'].append(port_info)
                
                # Get OS information
                os_elem = host.find('os')
                if os_elem is not None:
                    osmatch = os_elem.find('osmatch')
                    if osmatch is not None:
                        host_info['os'] = {
                            'name': osmatch.get('name'),
                            'accuracy': osmatch.get('accuracy')
                        }
                
                results['hosts'].append(host_info)
            
            return results
            
        except ET.ParseError as e:
            raise ValueError(f"Failed to parse XML file: {e}")
    
    def convert_xml_to_json(self, xml_file: str, json_file: str) -> None:
        """
        Convert XML output to JSON format.
        
        Args:
            xml_file (str): Path to XML input file
            json_file (str): Path to JSON output file
        """
        results = self.parse_xml_results(xml_file)
        
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
    
    def run_scan(self, target: str, scan_type: str, 
                ports: Optional[str] = None, 
                output_file: Optional[str] = None,
                output_format: str = 'xml',
                additional_args: Optional[str] = None,
                verbose: bool = False) -> Dict:
        """
        Execute the Nmap scan with specified parameters.
        
        Args:
            target (str): Target to scan
            scan_type (str): Type of scan to perform
            ports (str, optional): Specific ports to scan
            output_file (str, optional): Output file path
            output_format (str): Output format
            additional_args (str, optional): Additional Nmap arguments
            verbose (bool): Enable verbose output
            
        Returns:
            Dict: Scan results and metadata
        """
        # Validate inputs
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")
        
        if not self.check_nmap_installed():
            raise RuntimeError("Nmap is not installed or not accessible")
        
        # Create temporary XML file if JSON output is requested
        temp_xml_file = None
        if output_format == 'json' and output_file:
            temp_xml_file = output_file.replace('.json', '_temp.xml')
            cmd = self.build_nmap_command(target, scan_type, ports, 
                                        temp_xml_file, 'xml', additional_args)
        else:
            cmd = self.build_nmap_command(target, scan_type, ports, 
                                        output_file, output_format, additional_args)
        
        if verbose:
            print(f"Executing command: {' '.join(cmd)}")
        
        # Execute the scan
        start_time = datetime.now()
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            end_time = datetime.now()
            
            scan_result = {
                'command': ' '.join(cmd),
                'target': target,
                'scan_type': scan_type,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration': str(end_time - start_time),
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'success': result.returncode == 0
            }
            
            # Handle JSON conversion if needed
            if output_format == 'json' and output_file and temp_xml_file:
                if result.returncode == 0:
                    try:
                        self.convert_xml_to_json(temp_xml_file, output_file)
                        os.remove(temp_xml_file)  # Clean up temp file
                    except Exception as e:
                        scan_result['conversion_error'] = str(e)
            
            return scan_result
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("Scan timed out (1 hour limit)")
        except KeyboardInterrupt:
            raise RuntimeError("Scan interrupted by user")


def main():
    """Main function to handle command-line interface."""
    parser = argparse.ArgumentParser(
        description='Nmap Automation Wrapper - Simplify network scanning with predefined configurations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scan Types:
  quick          Fast scan of most common ports
  comprehensive  Complete scan with version detection, OS detection, and scripts
  stealth        Slow, stealthy scan to avoid detection
  port-scan      Standard port scan
  udp-scan       UDP port scan
  version-detect Service version detection
  os-detect      Operating system detection
  vuln-scan      Vulnerability scanning with NSE scripts

Examples:
  %(prog)s -t 192.168.1.0/24 -s quick
  %(prog)s -t example.com -s comprehensive -o results.xml
  %(prog)s -t 10.0.0.1-10 -s port-scan -p 80,443,22 -f json
        """
    )
    
    parser.add_argument('-t', '--target', required=True,
                       help='Target IP address, hostname, or network (e.g., 192.168.1.1, example.com, 192.168.1.0/24)')
    
    parser.add_argument('-s', '--scan-type', required=True,
                       choices=['quick', 'comprehensive', 'stealth', 'port-scan', 
                               'udp-scan', 'version-detect', 'os-detect', 'vuln-scan'],
                       help='Type of scan to perform')
    
    parser.add_argument('-p', '--ports',
                       help='Specific ports to scan (e.g., 80,443,22 or 1-1000)')
    
    parser.add_argument('-o', '--output',
                       help='Output file path')
    
    parser.add_argument('-f', '--format', choices=['xml', 'json', 'txt', 'grepable'],
                       default='xml', help='Output format (default: xml)')
    
    parser.add_argument('-a', '--additional-args',
                       help='Additional Nmap arguments (use quotes for multiple args)')
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    
    parser.add_argument('--version', action='version', version='Nmap Wrapper 1.0.0')
    
    args = parser.parse_args()
    
    # Create wrapper instance
    nmap_wrapper = NmapWrapper()
    
    try:
        # Run the scan
        result = nmap_wrapper.run_scan(
            target=args.target,
            scan_type=args.scan_type,
            ports=args.ports,
            output_file=args.output,
            output_format=args.format,
            additional_args=args.additional_args,
            verbose=args.verbose
        )
        
        # Display results
        if args.verbose:
            print(f"\nScan completed in {result['duration']}")
            print(f"Return code: {result['return_code']}")
        
        if result['success']:
            print("Scan completed successfully!")
            if args.output:
                print(f"Results saved to: {args.output}")
            else:
                print("\nScan output:")
                print(result['stdout'])
        else:
            print("Scan failed!")
            if result['stderr']:
                print(f"Error: {result['stderr']}")
            sys.exit(1)
            
    except ValueError as e:
        print(f"Input validation error: {e}", file=sys.stderr)
        sys.exit(1)
    except RuntimeError as e:
        print(f"Runtime error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nScan interrupted by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
