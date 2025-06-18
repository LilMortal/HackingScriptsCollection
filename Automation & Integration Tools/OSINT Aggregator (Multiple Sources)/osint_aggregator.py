#!/usr/bin/env python3
"""
OSINT Aggregator (Multiple Sources)

A Python script for aggregating Open Source Intelligence (OSINT) from multiple public sources.
This tool is designed for legitimate research, cybersecurity, and investigative purposes only.

Author: Assistant
License: MIT
Version: 1.0.0

Usage:
    python osint_aggregator.py --target example.com --output results.json
    python osint_aggregator.py --target example.com --sources whois,dns --format csv
    python osint_aggregator.py --target 8.8.8.8 --all-sources --verbose

Requirements:
    - requests
    - dnspython
    - python-whois
    - shodan (optional, requires API key)

ETHICAL USE NOTICE:
This tool is intended for legitimate research, cybersecurity analysis, and authorized
penetration testing only. Users are responsible for ensuring their use complies with
all applicable laws and regulations. Do not use this tool for unauthorized access,
harassment, or any malicious activities.
"""

import argparse
import json
import csv
import sys
import time
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
import socket
import subprocess
import re

# Third-party imports (install via pip)
try:
    import requests
    import dns.resolver
    import whois
except ImportError as e:
    print(f"Error: Missing required dependency: {e}")
    print("Please install required packages: pip install requests dnspython python-whois")
    sys.exit(1)

# Optional imports
try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False


class OSINTAggregator:
    """
    Main class for aggregating OSINT data from multiple sources.
    """
    
    def __init__(self, target: str, verbose: bool = False):
        """
        Initialize the OSINT aggregator.
        
        Args:
            target (str): Target domain, IP, or URL to investigate
            verbose (bool): Enable verbose logging
        """
        self.target = self._sanitize_target(target)
        self.verbose = verbose
        self.results = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'sources': {}
        }
        
        # Setup logging
        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Rate limiting
        self.request_delay = 1  # seconds between requests
        
    def _sanitize_target(self, target: str) -> str:
        """
        Sanitize and validate the target input.
        
        Args:
            target (str): Raw target input
            
        Returns:
            str: Sanitized target
        """
        # Remove protocol if present
        if target.startswith(('http://', 'https://')):
            target = urlparse(target).netloc
        
        # Basic validation
        if not target or len(target) > 253:
            raise ValueError("Invalid target format")
            
        return target.lower().strip()
    
    def _is_ip_address(self, target: str) -> bool:
        """
        Check if target is an IP address.
        
        Args:
            target (str): Target to check
            
        Returns:
            bool: True if target is an IP address
        """
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False
    
    def _make_request(self, url: str, headers: Dict = None, timeout: int = 10) -> Optional[requests.Response]:
        """
        Make HTTP request with error handling and rate limiting.
        
        Args:
            url (str): URL to request
            headers (Dict): Optional headers
            timeout (int): Request timeout
            
        Returns:
            Optional[requests.Response]: Response object or None if failed
        """
        default_headers = {
            'User-Agent': 'OSINT-Aggregator/1.0 (Research Tool)'
        }
        if headers:
            default_headers.update(headers)
            
        try:
            time.sleep(self.request_delay)  # Rate limiting
            response = requests.get(url, headers=default_headers, timeout=timeout)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            self.logger.error(f"Request failed for {url}: {e}")
            return None
    
    def gather_whois_info(self) -> Dict[str, Any]:
        """
        Gather WHOIS information for the target.
        
        Returns:
            Dict[str, Any]: WHOIS data
        """
        self.logger.info("Gathering WHOIS information...")
        whois_data = {}
        
        try:
            if self._is_ip_address(self.target):
                # For IP addresses, use a different approach
                whois_data['type'] = 'ip'
                whois_data['note'] = 'IP WHOIS lookup not implemented in basic version'
            else:
                # Domain WHOIS lookup
                domain_info = whois.whois(self.target)
                whois_data = {
                    'type': 'domain',
                    'registrar': getattr(domain_info, 'registrar', None),
                    'creation_date': str(getattr(domain_info, 'creation_date', None)),
                    'expiration_date': str(getattr(domain_info, 'expiration_date', None)),
                    'name_servers': getattr(domain_info, 'name_servers', []),
                    'status': getattr(domain_info, 'status', []),
                    'country': getattr(domain_info, 'country', None),
                    'organization': getattr(domain_info, 'org', None)
                }
        except Exception as e:
            self.logger.error(f"WHOIS lookup failed: {e}")
            whois_data['error'] = str(e)
        
        return whois_data
    
    def gather_dns_info(self) -> Dict[str, Any]:
        """
        Gather DNS information for the target.
        
        Returns:
            Dict[str, Any]: DNS data
        """
        self.logger.info("Gathering DNS information...")
        dns_data = {}
        
        if self._is_ip_address(self.target):
            # Reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(self.target)[0]
                dns_data['reverse_dns'] = hostname
            except socket.herror:
                dns_data['reverse_dns'] = None
            return dns_data
        
        # DNS record types to query
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                dns_data[record_type] = [str(answer) for answer in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
                dns_data[record_type] = []
            except Exception as e:
                self.logger.error(f"DNS query failed for {record_type}: {e}")
                dns_data[record_type] = []
        
        return dns_data
    
    def gather_http_info(self) -> Dict[str, Any]:
        """
        Gather HTTP information for the target.
        
        Returns:
            Dict[str, Any]: HTTP data
        """
        self.logger.info("Gathering HTTP information...")
        http_data = {}
        
        if self._is_ip_address(self.target):
            urls = [f"http://{self.target}", f"https://{self.target}"]
        else:
            urls = [f"https://{self.target}", f"http://{self.target}"]
        
        for url in urls:
            try:
                response = self._make_request(url, timeout=5)
                if response:
                    protocol = urlparse(url).scheme
                    http_data[protocol] = {
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'server': response.headers.get('Server', 'Unknown'),
                        'content_length': len(response.content),
                        'final_url': response.url
                    }
                    
                    # Extract title from HTML
                    title_match = re.search(r'<title[^>]*>([^<]+)</title>', 
                                          response.text, re.IGNORECASE)
                    if title_match:
                        http_data[protocol]['title'] = title_match.group(1).strip()
                    
                    break  # Stop after first successful connection
            except Exception as e:
                self.logger.error(f"HTTP request failed for {url}: {e}")
        
        return http_data
    
    def gather_subdomain_info(self) -> Dict[str, Any]:
        """
        Gather basic subdomain information using DNS.
        
        Returns:
            Dict[str, Any]: Subdomain data
        """
        self.logger.info("Gathering subdomain information...")
        
        if self._is_ip_address(self.target):
            return {'note': 'Subdomain enumeration not applicable for IP addresses'}
        
        # Common subdomain prefixes
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'forum', 'shop', 'api',
            'dev', 'staging', 'test', 'vpn', 'secure', 'support', 'help'
        ]
        
        found_subdomains = []
        
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{self.target}"
            try:
                answers = dns.resolver.resolve(full_domain, 'A')
                ips = [str(answer) for answer in answers]
                found_subdomains.append({
                    'subdomain': full_domain,
                    'ips': ips
                })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except Exception as e:
                self.logger.error(f"Subdomain check failed for {full_domain}: {e}")
        
        return {'subdomains': found_subdomains}
    
    def gather_geolocation_info(self) -> Dict[str, Any]:
        """
        Gather geolocation information for IP addresses.
        
        Returns:
            Dict[str, Any]: Geolocation data
        """
        self.logger.info("Gathering geolocation information...")
        
        # Resolve domain to IP if necessary
        if not self._is_ip_address(self.target):
            try:
                ip = socket.gethostbyname(self.target)
            except socket.gaierror:
                return {'error': 'Could not resolve domain to IP'}
        else:
            ip = self.target
        
        # Use a free IP geolocation service
        try:
            response = self._make_request(f"http://ip-api.com/json/{ip}")
            if response:
                geo_data = response.json()
                if geo_data.get('status') == 'success':
                    return {
                        'ip': ip,
                        'country': geo_data.get('country'),
                        'country_code': geo_data.get('countryCode'),
                        'region': geo_data.get('regionName'),
                        'city': geo_data.get('city'),
                        'zip': geo_data.get('zip'),
                        'lat': geo_data.get('lat'),
                        'lon': geo_data.get('lon'),
                        'timezone': geo_data.get('timezone'),
                        'isp': geo_data.get('isp'),
                        'org': geo_data.get('org'),
                        'as': geo_data.get('as')
                    }
        except Exception as e:
            self.logger.error(f"Geolocation lookup failed: {e}")
        
        return {'error': 'Geolocation lookup failed'}
    
    def gather_shodan_info(self, api_key: str) -> Dict[str, Any]:
        """
        Gather information from Shodan (requires API key).
        
        Args:
            api_key (str): Shodan API key
            
        Returns:
            Dict[str, Any]: Shodan data
        """
        if not SHODAN_AVAILABLE:
            return {'error': 'Shodan library not available'}
        
        self.logger.info("Gathering Shodan information...")
        
        try:
            api = shodan.Shodan(api_key)
            
            # Resolve domain to IP if necessary
            if not self._is_ip_address(self.target):
                try:
                    ip = socket.gethostbyname(self.target)
                except socket.gaierror:
                    return {'error': 'Could not resolve domain to IP'}
            else:
                ip = self.target
            
            host_info = api.host(ip)
            
            return {
                'ip': ip,
                'hostnames': host_info.get('hostnames', []),
                'ports': host_info.get('ports', []),
                'vulns': list(host_info.get('vulns', [])),
                'os': host_info.get('os'),
                'org': host_info.get('org'),
                'isp': host_info.get('isp'),
                'country_name': host_info.get('country_name'),
                'city': host_info.get('city'),
                'last_update': host_info.get('last_update')
            }
            
        except Exception as e:
            self.logger.error(f"Shodan lookup failed: {e}")
            return {'error': str(e)}
    
    def run_aggregation(self, sources: List[str], shodan_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Run the complete OSINT aggregation.
        
        Args:
            sources (List[str]): List of sources to query
            shodan_key (Optional[str]): Shodan API key
            
        Returns:
            Dict[str, Any]: Complete results
        """
        self.logger.info(f"Starting OSINT aggregation for target: {self.target}")
        
        source_methods = {
            'whois': self.gather_whois_info,
            'dns': self.gather_dns_info,
            'http': self.gather_http_info,
            'subdomains': self.gather_subdomain_info,
            'geolocation': self.gather_geolocation_info,
        }
        
        for source in sources:
            if source == 'shodan' and shodan_key:
                self.results['sources'][source] = self.gather_shodan_info(shodan_key)
            elif source in source_methods:
                self.results['sources'][source] = source_methods[source]()
            else:
                self.logger.warning(f"Unknown source: {source}")
        
        self.logger.info("OSINT aggregation completed")
        return self.results
    
    def export_results(self, output_file: str, format_type: str = 'json'):
        """
        Export results to file.
        
        Args:
            output_file (str): Output file path
            format_type (str): Export format ('json' or 'csv')
        """
        self.logger.info(f"Exporting results to {output_file} in {format_type} format")
        
        if format_type.lower() == 'json':
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        elif format_type.lower() == 'csv':
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Source', 'Key', 'Value'])
                
                for source, data in self.results['sources'].items():
                    self._write_dict_to_csv(writer, source, data)
        
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    def _write_dict_to_csv(self, writer, source: str, data: Dict, prefix: str = ''):
        """
        Recursively write dictionary data to CSV.
        
        Args:
            writer: CSV writer object
            source (str): Source name
            data (Dict): Data to write
            prefix (str): Key prefix for nested data
        """
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            
            if isinstance(value, dict):
                self._write_dict_to_csv(writer, source, value, full_key)
            elif isinstance(value, list):
                writer.writerow([source, full_key, '; '.join(map(str, value))])
            else:
                writer.writerow([source, full_key, str(value)])


def main():
    """
    Main function to handle command-line interface.
    """
    parser = argparse.ArgumentParser(
        description='OSINT Aggregator - Collect public information from multiple sources',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target example.com --output results.json
  %(prog)s --target 8.8.8.8 --sources whois,dns,http --format csv
  %(prog)s --target example.com --all-sources --verbose
  %(prog)s --target example.com --shodan-key YOUR_API_KEY
        """
    )
    
    parser.add_argument(
        '--target', '-t',
        required=True,
        help='Target domain, IP address, or URL to investigate'
    )
    
    parser.add_argument(
        '--sources', '-s',
        default='whois,dns,http,geolocation',
        help='Comma-separated list of sources (whois,dns,http,subdomains,geolocation,shodan)'
    )
    
    parser.add_argument(
        '--all-sources', '-a',
        action='store_true',
        help='Use all available sources'
    )
    
    parser.add_argument(
        '--output', '-o',
        default='osint_results.json',
        help='Output file path (default: osint_results.json)'
    )
    
    parser.add_argument(
        '--format', '-f',
        choices=['json', 'csv'],
        default='json',
        help='Output format (default: json)'
    )
    
    parser.add_argument(
        '--shodan-key',
        help='Shodan API key (required for Shodan integration)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Determine sources to use
    if args.all_sources:
        sources = ['whois', 'dns', 'http', 'subdomains', 'geolocation']
        if args.shodan_key:
            sources.append('shodan')
    else:
        sources = [s.strip() for s in args.sources.split(',')]
    
    try:
        # Initialize aggregator
        aggregator = OSINTAggregator(args.target, verbose=args.verbose)
        
        # Run aggregation
        results = aggregator.run_aggregation(sources, args.shodan_key)
        
        # Export results
        aggregator.export_results(args.output, args.format)
        
        print(f"\nOSINT aggregation completed successfully!")
        print(f"Results saved to: {args.output}")
        print(f"Target: {args.target}")
        print(f"Sources used: {', '.join(sources)}")
        
        if not args.verbose:
            print(f"\nSummary:")
            for source, data in results['sources'].items():
                if 'error' in data:
                    print(f"  {source}: Failed ({data['error']})")
                else:
                    print(f"  {source}: Success")
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
