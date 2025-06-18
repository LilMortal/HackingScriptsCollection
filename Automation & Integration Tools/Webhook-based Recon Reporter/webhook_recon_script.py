#!/usr/bin/env python3
"""
Webhook-based Recon Reporter

A comprehensive reconnaissance tool that performs various network and security
reconnaissance tasks and reports findings via webhooks.

Author: Security Automation Script
License: MIT
Version: 1.0.0

Usage:
    python webhook_recon_reporter.py --target example.com --webhook-url https://your-webhook.com/endpoint
    python webhook_recon_reporter.py --target-file targets.txt --webhook-url https://discord.com/api/webhooks/xxx --scan-type basic
    python webhook_recon_reporter.py --target 192.168.1.0/24 --webhook-url https://slack.com/hooks/xxx --output results.json

Dependencies:
    - requests: pip install requests
    - python-nmap: pip install python-nmap (optional, for advanced port scanning)
"""

import argparse
import json
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("Warning: 'requests' library not found. Using urllib for HTTP requests.")

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False


class ReconReporter:
    """Main class for performing reconnaissance and reporting via webhooks."""
    
    def __init__(self, webhook_url: str, timeout: int = 10):
        """
        Initialize the ReconReporter.
        
        Args:
            webhook_url: URL of the webhook endpoint
            timeout: Timeout for network operations in seconds
        """
        self.webhook_url = webhook_url
        self.timeout = timeout
        self.results = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'scanner': 'Webhook-based Recon Reporter v1.0.0'
            },
            'targets': [],
            'summary': {
                'total_targets': 0,
                'successful_scans': 0,
                'failed_scans': 0
            }
        }
    
    def validate_webhook_url(self) -> bool:
        """
        Validate the webhook URL format.
        
        Returns:
            bool: True if URL is valid, False otherwise
        """
        try:
            parsed = urllib.parse.urlparse(self.webhook_url)
            return bool(parsed.netloc and parsed.scheme in ('http', 'https'))
        except Exception:
            return False
    
    def dns_lookup(self, target: str) -> Dict[str, Union[str, List[str]]]:
        """
        Perform DNS lookups for the target.
        
        Args:
            target: Target hostname or IP address
            
        Returns:
            Dict containing DNS information
        """
        dns_info = {
            'hostname': target,
            'ip_addresses': [],
            'reverse_dns': None,
            'error': None
        }
        
        try:
            # Forward DNS lookup
            if not self._is_ip_address(target):
                addr_info = socket.getaddrinfo(target, None)
                dns_info['ip_addresses'] = list(set([info[4][0] for info in addr_info]))
            else:
                dns_info['ip_addresses'] = [target]
                
            # Reverse DNS lookup
            if dns_info['ip_addresses']:
                try:
                    dns_info['reverse_dns'] = socket.gethostbyaddr(dns_info['ip_addresses'][0])[0]
                except socket.herror:
                    pass
                    
        except Exception as e:
            dns_info['error'] = str(e)
            
        return dns_info
    
    def port_scan_basic(self, target: str, ports: List[int] = None) -> Dict[str, Union[str, List[Dict]]]:
        """
        Perform basic port scanning using socket connections.
        
        Args:
            target: Target IP address
            ports: List of ports to scan (default: common ports)
            
        Returns:
            Dict containing port scan results
        """
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080]
        
        scan_results = {
            'target': target,
            'open_ports': [],
            'closed_ports': [],
            'scan_time': datetime.now().isoformat()
        }
        
        def scan_port(port: int) -> Tuple[int, bool]:
            """Scan a single port."""
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    result = sock.connect_ex((target, port))
                    return port, result == 0
            except Exception:
                return port, False
        
        # Use ThreadPoolExecutor for concurrent port scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(scan_port, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                port, is_open = future.result()
                if is_open:
                    scan_results['open_ports'].append({
                        'port': port,
                        'service': self._get_service_name(port)
                    })
                else:
                    scan_results['closed_ports'].append(port)
        
        # Sort results
        scan_results['open_ports'].sort(key=lambda x: x['port'])
        scan_results['closed_ports'].sort()
        
        return scan_results
    
    def http_reconnaissance(self, target: str) -> Dict[str, Union[str, Dict]]:
        """
        Perform HTTP reconnaissance on the target.
        
        Args:
            target: Target hostname or IP address
            
        Returns:
            Dict containing HTTP reconnaissance results
        """
        http_info = {
            'target': target,
            'http_status': None,
            'https_status': None,
            'headers': {},
            'server_info': None,
            'title': None,
            'redirects': [],
            'error': None
        }
        
        for scheme in ['http', 'https']:
            url = f"{scheme}://{target}"
            try:
                if REQUESTS_AVAILABLE:
                    response = requests.get(url, timeout=self.timeout, allow_redirects=True, verify=False)
                    status_key = f'{scheme}_status'
                    http_info[status_key] = response.status_code
                    
                    if scheme == 'https':  # Store headers from HTTPS if available, otherwise HTTP
                        http_info['headers'] = dict(response.headers)
                        http_info['server_info'] = response.headers.get('Server')
                        
                        # Extract title from HTML
                        if 'text/html' in response.headers.get('content-type', '').lower():
                            content = response.text.lower()
                            title_start = content.find('<title>')
                            if title_start != -1:
                                title_end = content.find('</title>', title_start)
                                if title_end != -1:
                                    http_info['title'] = response.text[title_start + 7:title_end].strip()
                    
                    # Track redirects
                    if response.history:
                        http_info['redirects'] = [r.url for r in response.history]
                else:
                    # Fallback to urllib if requests is not available
                    req = urllib.request.Request(url)
                    with urllib.request.urlopen(req, timeout=self.timeout) as response:
                        status_key = f'{scheme}_status'
                        http_info[status_key] = response.getcode()
                        
                        if scheme == 'https':
                            http_info['headers'] = dict(response.headers)
                            http_info['server_info'] = response.headers.get('Server')
                            
            except Exception as e:
                if http_info['error'] is None:
                    http_info['error'] = str(e)
        
        return http_info
    
    def whois_lookup(self, target: str) -> Dict[str, Union[str, None]]:
        """
        Perform basic WHOIS lookup using system whois command.
        
        Args:
            target: Target domain or IP address
            
        Returns:
            Dict containing WHOIS information
        """
        whois_info = {
            'target': target,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'nameservers': [],
            'raw_output': None,
            'error': None
        }
        
        try:
            # Try to use system whois command
            result = subprocess.run(['whois', target], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                whois_info['raw_output'] = result.stdout
                
                # Parse basic information
                lines = result.stdout.lower().split('\n')
                for line in lines:
                    if 'registrar:' in line:
                        whois_info['registrar'] = line.split(':', 1)[1].strip()
                    elif 'creation date:' in line or 'created:' in line:
                        whois_info['creation_date'] = line.split(':', 1)[1].strip()
                    elif 'expiration date:' in line or 'expires:' in line:
                        whois_info['expiration_date'] = line.split(':', 1)[1].strip()
                    elif 'name server:' in line or 'nameserver:' in line:
                        ns = line.split(':', 1)[1].strip()
                        if ns and ns not in whois_info['nameservers']:
                            whois_info['nameservers'].append(ns)
            else:
                whois_info['error'] = f"WHOIS command failed: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            whois_info['error'] = "WHOIS lookup timed out"
        except FileNotFoundError:
            whois_info['error'] = "WHOIS command not found on system"
        except Exception as e:
            whois_info['error'] = str(e)
        
        return whois_info
    
    def scan_target(self, target: str, scan_type: str = 'full') -> Dict:
        """
        Perform comprehensive reconnaissance on a single target.
        
        Args:
            target: Target hostname or IP address
            scan_type: Type of scan ('basic', 'full', 'port-only', 'web-only')
            
        Returns:
            Dict containing all reconnaissance results for the target
        """
        target_results = {
            'target': target,
            'scan_type': scan_type,
            'start_time': datetime.now().isoformat(),
            'dns_info': None,
            'port_scan': None,
            'http_info': None,
            'whois_info': None,
            'status': 'in_progress'
        }
        
        try:
            # DNS lookup (always performed)
            target_results['dns_info'] = self.dns_lookup(target)
            
            # Get IP address for further scanning
            ip_addresses = target_results['dns_info'].get('ip_addresses', [])
            scan_ip = ip_addresses[0] if ip_addresses else target
            
            # Perform scans based on scan type
            if scan_type in ['full', 'basic', 'port-only']:
                target_results['port_scan'] = self.port_scan_basic(scan_ip)
            
            if scan_type in ['full', 'basic', 'web-only']:
                target_results['http_info'] = self.http_reconnaissance(target)
            
            if scan_type == 'full':
                target_results['whois_info'] = self.whois_lookup(target)
            
            target_results['status'] = 'completed'
            target_results['end_time'] = datetime.now().isoformat()
            
        except Exception as e:
            target_results['status'] = 'failed'
            target_results['error'] = str(e)
            target_results['end_time'] = datetime.now().isoformat()
        
        return target_results
    
    def send_webhook_report(self, data: Dict) -> bool:
        """
        Send reconnaissance results to the webhook endpoint.
        
        Args:
            data: Dictionary containing the reconnaissance results
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Format the data for webhook
            webhook_payload = {
                'content': self._format_webhook_message(data),
                'embeds': self._create_discord_embed(data) if 'discord' in self.webhook_url else None
            }
            
            # Remove None values
            webhook_payload = {k: v for k, v in webhook_payload.items() if v is not None}
            
            if REQUESTS_AVAILABLE:
                response = requests.post(
                    self.webhook_url,
                    json=webhook_payload,
                    timeout=self.timeout
                )
                return response.status_code in [200, 204]
            else:
                # Fallback to urllib
                data_bytes = json.dumps(webhook_payload).encode('utf-8')
                req = urllib.request.Request(
                    self.webhook_url,
                    data=data_bytes,
                    headers={'Content-Type': 'application/json'}
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    return response.getcode() in [200, 204]
                    
        except Exception as e:
            print(f"Failed to send webhook: {e}")
            return False
    
    def _format_webhook_message(self, data: Dict) -> str:
        """Format reconnaissance data into a readable message."""
        message_parts = []
        message_parts.append("🔍 **Reconnaissance Report**")
        message_parts.append(f"📅 Scan Time: {data['scan_info']['timestamp']}")
        message_parts.append(f"🎯 Total Targets: {data['summary']['total_targets']}")
        message_parts.append(f"✅ Successful: {data['summary']['successful_scans']}")
        message_parts.append(f"❌ Failed: {data['summary']['failed_scans']}")
        message_parts.append("")
        
        for target_data in data['targets'][:5]:  # Limit to first 5 targets for webhook
            message_parts.append(f"**Target: {target_data['target']}**")
            
            if target_data.get('dns_info', {}).get('ip_addresses'):
                ips = ', '.join(target_data['dns_info']['ip_addresses'][:3])
                message_parts.append(f"🌐 IPs: {ips}")
            
            if target_data.get('port_scan', {}).get('open_ports'):
                open_ports = [str(p['port']) for p in target_data['port_scan']['open_ports'][:10]]
                message_parts.append(f"🔓 Open Ports: {', '.join(open_ports)}")
            
            if target_data.get('http_info'):
                http_status = target_data['http_info'].get('https_status') or target_data['http_info'].get('http_status')
                if http_status:
                    message_parts.append(f"🌍 HTTP Status: {http_status}")
            
            message_parts.append("")
        
        if len(data['targets']) > 5:
            message_parts.append(f"... and {len(data['targets']) - 5} more targets")
        
        return '\n'.join(message_parts)
    
    def _create_discord_embed(self, data: Dict) -> List[Dict]:
        """Create Discord-formatted embed for richer display."""
        embed = {
            "title": "🔍 Reconnaissance Report",
            "color": 0x00ff00 if data['summary']['failed_scans'] == 0 else 0xff9900,
            "timestamp": datetime.now().isoformat(),
            "fields": [
                {
                    "name": "📊 Summary",
                    "value": f"**Targets:** {data['summary']['total_targets']}\n**Successful:** {data['summary']['successful_scans']}\n**Failed:** {data['summary']['failed_scans']}",
                    "inline": True
                }
            ]
        }
        
        # Add top findings
        if data['targets']:
            findings = []
            for target_data in data['targets'][:3]:
                open_ports = target_data.get('port_scan', {}).get('open_ports', [])
                if open_ports:
                    ports_str = ', '.join([str(p['port']) for p in open_ports[:5]])
                    findings.append(f"**{target_data['target']}**: {ports_str}")
            
            if findings:
                embed['fields'].append({
                    "name": "🔓 Key Findings",
                    "value": '\n'.join(findings),
                    "inline": False
                })
        
        return [embed]
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address."""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False
    
    def _get_service_name(self, port: int) -> str:
        """Get common service name for a port."""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Alt'
        }
        return services.get(port, 'Unknown')
    
    def run_reconnaissance(self, targets: List[str], scan_type: str = 'full') -> Dict:
        """
        Run reconnaissance on multiple targets.
        
        Args:
            targets: List of target hostnames or IP addresses
            scan_type: Type of scan to perform
            
        Returns:
            Dict containing all results
        """
        self.results['summary']['total_targets'] = len(targets)
        
        print(f"Starting reconnaissance on {len(targets)} targets...")
        
        for i, target in enumerate(targets, 1):
            print(f"[{i}/{len(targets)}] Scanning {target}...")
            
            target_results = self.scan_target(target, scan_type)
            self.results['targets'].append(target_results)
            
            if target_results['status'] == 'completed':
                self.results['summary']['successful_scans'] += 1
            else:
                self.results['summary']['failed_scans'] += 1
            
            # Small delay between targets to be respectful
            time.sleep(0.5)
        
        print(f"Reconnaissance completed. Successful: {self.results['summary']['successful_scans']}, Failed: {self.results['summary']['failed_scans']}")
        
        return self.results


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Webhook-based Recon Reporter - Perform reconnaissance and report via webhooks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target example.com --webhook-url https://discord.com/api/webhooks/xxx
  %(prog)s --target-file targets.txt --webhook-url https://hooks.slack.com/xxx --scan-type basic
  %(prog)s --target 192.168.1.1 --webhook-url https://your-webhook.com --output results.json
        """
    )
    
    # Target specification (mutually exclusive)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        '--target', '-t',
        help='Single target hostname or IP address'
    )
    target_group.add_argument(
        '--target-file', '-f',
        help='File containing list of targets (one per line)'
    )
    
    # Required webhook URL
    parser.add_argument(
        '--webhook-url', '-w',
        required=True,
        help='Webhook URL for sending reports'
    )
    
    # Optional arguments
    parser.add_argument(
        '--scan-type', '-s',
        choices=['basic', 'full', 'port-only', 'web-only'],
        default='full',
        help='Type of reconnaissance scan (default: full)'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output file to save detailed results (JSON format)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Timeout for network operations in seconds (default: 10)'
    )
    
    parser.add_argument(
        '--no-webhook',
        action='store_true',
        help='Skip sending webhook report (useful for testing)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Webhook-based Recon Reporter v1.0.0'
    )
    
    return parser.parse_args()


def load_targets_from_file(filepath: str) -> List[str]:
    """
    Load targets from a file.
    
    Args:
        filepath: Path to the file containing targets
        
    Returns:
        List of target hostnames/IPs
    """
    try:
        with open(filepath, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return targets
    except Exception as e:
        print(f"Error reading targets file: {e}")
        sys.exit(1)


def save_results_to_file(results: Dict, filepath: str) -> None:
    """
    Save results to a JSON file.
    
    Args:
        results: Results dictionary
        filepath: Output file path
    """
    try:
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {filepath}")
    except Exception as e:
        print(f"Error saving results: {e}")


def main():
    """Main function."""
    args = parse_arguments()
    
    # Validate dependencies
    if not REQUESTS_AVAILABLE:
        print("Warning: 'requests' library not installed. Some features may be limited.")
        print("Install with: pip install requests")
    
    # Load targets
    if args.target:
        targets = [args.target]
    else:
        targets = load_targets_from_file(args.target_file)
    
    if not targets:
        print("No targets specified or found.")
        sys.exit(1)
    
    print(f"Loaded {len(targets)} targets")
    
    # Initialize reporter
    reporter = ReconReporter(args.webhook_url, args.timeout)
    
    # Validate webhook URL
    if not args.no_webhook and not reporter.validate_webhook_url():
        print("Error: Invalid webhook URL format")
        sys.exit(1)
    
    # Run reconnaissance
    try:
        results = reporter.run_reconnaissance(targets, args.scan_type)
        
        # Send webhook report
        if not args.no_webhook:
            print("Sending webhook report...")
            if reporter.send_webhook_report(results):
                print("✅ Webhook report sent successfully")
            else:
                print("❌ Failed to send webhook report")
        
        # Save to file if specified
        if args.output:
            save_results_to_file(results, args.output)
        
        print("\nReconnaissance completed!")
        
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error during reconnaissance: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
