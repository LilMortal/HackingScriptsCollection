#!/usr/bin/env python3
"""
WHOIS Lookup Script

A command-line tool for performing WHOIS lookups on domain names and IP addresses.
This script provides detailed domain registration information including registrar,
creation date, expiration date, name servers, and contact information.

Usage:
    python whois_lookup.py example.com
    python whois_lookup.py --domain example.com --output json
    python whois_lookup.py --domain example.com --save results.txt

Author: Your Name
License: MIT
Version: 1.0.0
"""

import argparse
import json
import re
import socket
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Union


class WHOISLookup:
    """
    A class for performing WHOIS lookups on domains and IP addresses.
    """
    
    # Common WHOIS servers for different TLDs
    WHOIS_SERVERS = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'info': 'whois.afilias.net',
        'biz': 'whois.neulevel.biz',
        'us': 'whois.nic.us',
        'uk': 'whois.nic.uk',
        'de': 'whois.denic.de',
        'fr': 'whois.afnic.fr',
        'jp': 'whois.jprs.jp',
        'au': 'whois.auda.org.au',
        'ca': 'whois.cira.ca',
        'br': 'whois.registro.br',
        'ru': 'whois.tcinet.ru',
        'cn': 'whois.cnnic.cn',
        'in': 'whois.registry.in',
        'mx': 'whois.mx',
        'nl': 'whois.domain-registry.nl',
        'io': 'whois.nic.io',
        'co': 'whois.nic.co',
        'me': 'whois.nic.me',
        'tv': 'whois.nic.tv',
        'cc': 'whois.nic.cc',
        'ly': 'whois.nic.ly',
        'be': 'whois.dns.be',
        'it': 'whois.nic.it',
        'es': 'whois.nic.es',
        'ch': 'whois.nic.ch',
        'se': 'whois.iis.se',
        'no': 'whois.norid.no',
    }
    
    def __init__(self, timeout: int = 10):
        """
        Initialize the WHOIS lookup client.
        
        Args:
            timeout (int): Socket timeout in seconds
        """
        self.timeout = timeout
    
    def get_tld(self, domain: str) -> str:
        """
        Extract the top-level domain from a domain name.
        
        Args:
            domain (str): The domain name
            
        Returns:
            str: The TLD (e.g., 'com', 'org', 'co.uk')
        """
        parts = domain.lower().split('.')
        if len(parts) >= 2:
            # Handle cases like .co.uk, .com.au
            if len(parts) >= 3 and parts[-2] in ['co', 'com', 'net', 'org', 'gov', 'edu', 'ac']:
                return f"{parts[-2]}.{parts[-1]}"
            return parts[-1]
        return parts[0] if parts else ''
    
    def get_whois_server(self, domain: str) -> str:
        """
        Determine the appropriate WHOIS server for a domain.
        
        Args:
            domain (str): The domain name
            
        Returns:
            str: The WHOIS server hostname
        """
        tld = self.get_tld(domain)
        return self.WHOIS_SERVERS.get(tld, 'whois.iana.org')
    
    def query_whois_server(self, server: str, query: str) -> str:
        """
        Query a WHOIS server for domain information.
        
        Args:
            server (str): WHOIS server hostname
            query (str): Domain or IP to query
            
        Returns:
            str: Raw WHOIS response
            
        Raises:
            socket.error: If connection fails
            socket.timeout: If query times out
        """
        try:
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Connect to WHOIS server (port 43)
            sock.connect((server, 43))
            
            # Send query
            sock.send(f"{query}\r\n".encode('utf-8'))
            
            # Receive response
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            sock.close()
            return response.decode('utf-8', errors='ignore')
            
        except Exception as e:
            raise socket.error(f"Failed to query WHOIS server {server}: {str(e)}")
    
    def parse_whois_data(self, raw_data: str) -> Dict[str, Union[str, List[str]]]:
        """
        Parse raw WHOIS data into structured information.
        
        Args:
            raw_data (str): Raw WHOIS response
            
        Returns:
            Dict: Parsed WHOIS information
        """
        parsed_data = {
            'domain': '',
            'registrar': '',
            'creation_date': '',
            'expiration_date': '',
            'updated_date': '',
            'status': [],
            'name_servers': [],
            'registrant': '',
            'admin_contact': '',
            'tech_contact': '',
            'raw_data': raw_data
        }
        
        lines = raw_data.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('%') or line.startswith('#'):
                continue
            
            # Split on first colon
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                # Map common field names
                if key in ['domain name', 'domain']:
                    parsed_data['domain'] = value
                elif key in ['registrar', 'sponsoring registrar']:
                    parsed_data['registrar'] = value
                elif key in ['creation date', 'created', 'registered']:
                    parsed_data['creation_date'] = value
                elif key in ['expiration date', 'expires', 'registry expiry date']:
                    parsed_data['expiration_date'] = value
                elif key in ['updated date', 'last updated', 'modified']:
                    parsed_data['updated_date'] = value
                elif key in ['status', 'domain status']:
                    if value not in parsed_data['status']:
                        parsed_data['status'].append(value)
                elif key in ['name server', 'nameserver', 'nserver']:
                    if value not in parsed_data['name_servers']:
                        parsed_data['name_servers'].append(value)
                elif key in ['registrant', 'registrant name']:
                    parsed_data['registrant'] = value
                elif key in ['admin contact', 'administrative contact']:
                    parsed_data['admin_contact'] = value
                elif key in ['tech contact', 'technical contact']:
                    parsed_data['tech_contact'] = value
        
        return parsed_data
    
    def lookup(self, domain: str) -> Dict[str, Union[str, List[str]]]:
        """
        Perform a complete WHOIS lookup for a domain.
        
        Args:
            domain (str): The domain name to lookup
            
        Returns:
            Dict: Parsed WHOIS information
            
        Raises:
            ValueError: If domain format is invalid
            socket.error: If WHOIS query fails
        """
        # Validate domain format
        if not self.is_valid_domain(domain):
            raise ValueError(f"Invalid domain format: {domain}")
        
        # Get appropriate WHOIS server
        whois_server = self.get_whois_server(domain)
        
        # Query WHOIS server
        raw_data = self.query_whois_server(whois_server, domain)
        
        # Parse the response
        parsed_data = self.parse_whois_data(raw_data)
        
        # If we got a referral to another server, try that
        if not parsed_data['domain'] and 'whois server' in raw_data.lower():
            referral_match = re.search(r'whois server:\s*([^\s\n]+)', raw_data, re.IGNORECASE)
            if referral_match:
                referral_server = referral_match.group(1)
                try:
                    raw_data = self.query_whois_server(referral_server, domain)
                    parsed_data = self.parse_whois_data(raw_data)
                except:
                    pass  # Use original data if referral fails
        
        return parsed_data
    
    def is_valid_domain(self, domain: str) -> bool:
        """
        Validate domain name format.
        
        Args:
            domain (str): Domain name to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        # Basic domain validation regex
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, domain)) and len(domain) <= 253


def format_output(data: Dict, output_format: str = 'text') -> str:
    """
    Format WHOIS data for output.
    
    Args:
        data (Dict): Parsed WHOIS data
        output_format (str): Output format ('text', 'json')
        
    Returns:
        str: Formatted output
    """
    if output_format.lower() == 'json':
        return json.dumps(data, indent=2, ensure_ascii=False)
    
    # Text format
    output = []
    output.append("=" * 50)
    output.append("WHOIS LOOKUP RESULTS")
    output.append("=" * 50)
    
    if data.get('domain'):
        output.append(f"Domain: {data['domain']}")
    if data.get('registrar'):
        output.append(f"Registrar: {data['registrar']}")
    if data.get('creation_date'):
        output.append(f"Created: {data['creation_date']}")
    if data.get('expiration_date'):
        output.append(f"Expires: {data['expiration_date']}")
    if data.get('updated_date'):
        output.append(f"Updated: {data['updated_date']}")
    
    if data.get('status'):
        output.append(f"Status: {', '.join(data['status'])}")
    
    if data.get('name_servers'):
        output.append("Name Servers:")
        for ns in data['name_servers']:
            output.append(f"  - {ns}")
    
    if data.get('registrant'):
        output.append(f"Registrant: {data['registrant']}")
    
    output.append("=" * 50)
    
    return '\n'.join(output)


def main():
    """
    Main function to handle command-line interface.
    """
    parser = argparse.ArgumentParser(
        description='Perform WHOIS lookups on domain names',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python whois_lookup.py example.com
  python whois_lookup.py --domain google.com --output json
  python whois_lookup.py --domain github.com --save results.txt
  python whois_lookup.py --domain stackoverflow.com --output json --save data.json
        '''
    )
    
    parser.add_argument(
        'domain',
        nargs='?',
        help='Domain name to lookup (can also use --domain)'
    )
    
    parser.add_argument(
        '-d', '--domain',
        help='Domain name to lookup'
    )
    
    parser.add_argument(
        '-o', '--output',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )
    
    parser.add_argument(
        '-s', '--save',
        help='Save output to file'
    )
    
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=10,
        help='Connection timeout in seconds (default: 10)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='WHOIS Lookup Script 1.0.0'
    )
    
    args = parser.parse_args()
    
    # Determine domain to lookup
    domain = args.domain or args.domain
    if not domain:
        parser.error("Domain name is required. Use positional argument or --domain option.")
    
    try:
        # Create WHOIS lookup instance
        whois = WHOISLookup(timeout=args.timeout)
        
        print(f"Looking up WHOIS information for: {domain}")
        print("Please wait...")
        
        # Perform lookup
        start_time = time.time()
        data = whois.lookup(domain)
        elapsed_time = time.time() - start_time
        
        # Format output
        output = format_output(data, args.output)
        
        # Display results
        print(f"\nLookup completed in {elapsed_time:.2f} seconds\n")
        print(output)
        
        # Save to file if requested
        if args.save:
            try:
                with open(args.save, 'w', encoding='utf-8') as f:
                    f.write(output)
                print(f"\nResults saved to: {args.save}")
            except IOError as e:
                print(f"Error saving to file: {e}", file=sys.stderr)
        
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    except socket.error as e:
        print(f"Network error: {e}", file=sys.stderr)
        sys.exit(1)
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
