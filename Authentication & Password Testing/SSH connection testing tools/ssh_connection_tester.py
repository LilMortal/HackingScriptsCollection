#!/usr/bin/env python3
"""
SSH Connection Testing Tool

A professional tool for testing SSH connectivity to authorized systems.
This script helps network administrators and security professionals verify
SSH connections, test authentication methods, and diagnose connectivity issues.

Usage Example:
    python ssh_connection_tester.py -H 192.168.1.100 -u admin -p password
    python ssh_connection_tester.py -H server.example.com -u user -k ~/.ssh/id_rsa
    python ssh_connection_tester.py -H 10.0.0.1 -u root --key-file /path/to/key --port 2222

Author: SSH Connection Tester
License: MIT
"""

import argparse
import socket
import sys
import time
import logging
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
import getpass

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False


class SSHConnectionTester:
    """
    SSH Connection Testing class for verifying connectivity and authentication
    to authorized systems.
    """
    
    def __init__(self, host: str, port: int = 22, timeout: int = 10):
        """
        Initialize the SSH connection tester.
        
        Args:
            host (str): Target hostname or IP address
            port (int): SSH port (default: 22)
            timeout (int): Connection timeout in seconds (default: 10)
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.logger = self._setup_logging()
        
    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration."""
        logger = logging.getLogger('ssh_tester')
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger
    
    def test_port_connectivity(self) -> bool:
        """
        Test basic TCP connectivity to the SSH port.
        
        Returns:
            bool: True if port is reachable, False otherwise
        """
        self.logger.info(f"Testing TCP connectivity to {self.host}:{self.port}")
        
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout):
                self.logger.info("✓ Port is reachable")
                return True
        except socket.timeout:
            self.logger.error("✗ Connection timeout")
        except socket.gaierror as e:
            self.logger.error(f"✗ DNS resolution failed: {e}")
        except ConnectionRefusedError:
            self.logger.error("✗ Connection refused")
        except Exception as e:
            self.logger.error(f"✗ Connection failed: {e}")
        
        return False
    
    def test_ssh_banner(self) -> Optional[str]:
        """
        Retrieve SSH server banner information.
        
        Returns:
            str: SSH banner string if successful, None otherwise
        """
        if not PARAMIKO_AVAILABLE:
            self.logger.warning("Paramiko not available, skipping SSH banner test")
            return None
            
        self.logger.info("Testing SSH banner retrieval")
        
        try:
            transport = paramiko.Transport((self.host, self.port))
            transport.start_client(timeout=self.timeout)
            banner = transport.remote_version
            transport.close()
            
            self.logger.info(f"✓ SSH banner: {banner}")
            return banner
        except Exception as e:
            self.logger.error(f"✗ Failed to retrieve SSH banner: {e}")
            return None
    
    def test_authentication_methods(self) -> Optional[list]:
        """
        Test available authentication methods.
        
        Returns:
            list: Available authentication methods if successful, None otherwise
        """
        if not PARAMIKO_AVAILABLE:
            self.logger.warning("Paramiko not available, skipping auth methods test")
            return None
            
        self.logger.info("Testing available authentication methods")
        
        try:
            transport = paramiko.Transport((self.host, self.port))
            transport.start_client(timeout=self.timeout)
            
            # Try to authenticate with a dummy username to get auth methods
            try:
                transport.auth_none("dummy_user")
            except paramiko.BadAuthenticationType as e:
                auth_methods = e.allowed_types
                transport.close()
                self.logger.info(f"✓ Available auth methods: {auth_methods}")
                return auth_methods
            except Exception:
                pass
                
            transport.close()
            return ["none"]  # If no exception, "none" auth is allowed
            
        except Exception as e:
            self.logger.error(f"✗ Failed to retrieve auth methods: {e}")
            return None
    
    def test_password_authentication(self, username: str, password: str) -> bool:
        """
        Test password-based authentication.
        
        Args:
            username (str): Username for authentication
            password (str): Password for authentication
            
        Returns:
            bool: True if authentication successful, False otherwise
        """
        if not PARAMIKO_AVAILABLE:
            self.logger.error("Paramiko not available for SSH authentication")
            return False
            
        self.logger.info(f"Testing password authentication for user: {username}")
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddHostKeyPolicy())
            
            client.connect(
                hostname=self.host,
                port=self.port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False
            )
            
            client.close()
            self.logger.info("✓ Password authentication successful")
            return True
            
        except paramiko.AuthenticationException:
            self.logger.error("✗ Password authentication failed")
        except Exception as e:
            self.logger.error(f"✗ Connection failed: {e}")
            
        return False
    
    def test_key_authentication(self, username: str, key_file: str, 
                              passphrase: Optional[str] = None) -> bool:
        """
        Test key-based authentication.
        
        Args:
            username (str): Username for authentication
            key_file (str): Path to private key file
            passphrase (str, optional): Passphrase for encrypted key
            
        Returns:
            bool: True if authentication successful, False otherwise
        """
        if not PARAMIKO_AVAILABLE:
            self.logger.error("Paramiko not available for SSH authentication")
            return False
            
        key_path = Path(key_file)
        if not key_path.exists():
            self.logger.error(f"✗ Key file not found: {key_file}")
            return False
            
        self.logger.info(f"Testing key authentication for user: {username}")
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddHostKeyPolicy())
            
            client.connect(
                hostname=self.host,
                port=self.port,
                username=username,
                key_filename=key_file,
                passphrase=passphrase,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False
            )
            
            client.close()
            self.logger.info("✓ Key authentication successful")
            return True
            
        except paramiko.AuthenticationException:
            self.logger.error("✗ Key authentication failed")
        except Exception as e:
            self.logger.error(f"✗ Connection failed: {e}")
            
        return False
    
    def run_comprehensive_test(self, username: Optional[str] = None, 
                             password: Optional[str] = None,
                             key_file: Optional[str] = None,
                             key_passphrase: Optional[str] = None) -> Dict[str, Any]:
        """
        Run a comprehensive SSH connection test.
        
        Args:
            username (str, optional): Username for authentication testing
            password (str, optional): Password for authentication testing
            key_file (str, optional): Private key file for authentication testing
            key_passphrase (str, optional): Passphrase for encrypted key
            
        Returns:
            dict: Test results summary
        """
        results = {
            'host': self.host,
            'port': self.port,
            'port_reachable': False,
            'ssh_banner': None,
            'auth_methods': None,
            'password_auth': None,
            'key_auth': None,
            'overall_status': 'FAILED'
        }
        
        print(f"\n{'='*60}")
        print(f"SSH Connection Test Report for {self.host}:{self.port}")
        print(f"{'='*60}")
        
        # Test 1: Port connectivity
        results['port_reachable'] = self.test_port_connectivity()
        if not results['port_reachable']:
            print(f"\n⚠️  Cannot establish basic connectivity to {self.host}:{self.port}")
            return results
        
        # Test 2: SSH banner
        results['ssh_banner'] = self.test_ssh_banner()
        
        # Test 3: Authentication methods
        results['auth_methods'] = self.test_authentication_methods()
        
        # Test 4: Password authentication (if credentials provided)
        if username and password:
            results['password_auth'] = self.test_password_authentication(username, password)
        
        # Test 5: Key authentication (if key provided)
        if username and key_file:
            results['key_auth'] = self.test_key_authentication(
                username, key_file, key_passphrase
            )
        
        # Determine overall status
        if results['port_reachable'] and results['ssh_banner']:
            if results['password_auth'] or results['key_auth']:
                results['overall_status'] = 'SUCCESS'
            elif username and (password or key_file):
                results['overall_status'] = 'PARTIAL'
            else:
                results['overall_status'] = 'CONNECTED'
        
        self._print_summary(results)
        return results
    
    def _print_summary(self, results: Dict[str, Any]) -> None:
        """Print test results summary."""
        print(f"\n{'='*60}")
        print("TEST SUMMARY")
        print(f"{'='*60}")
        print(f"Host: {results['host']}:{results['port']}")
        print(f"Port Reachable: {'✓' if results['port_reachable'] else '✗'}")
        
        if results['ssh_banner']:
            print(f"SSH Banner: {results['ssh_banner']}")
        
        if results['auth_methods']:
            print(f"Auth Methods: {', '.join(results['auth_methods'])}")
        
        if results['password_auth'] is not None:
            print(f"Password Auth: {'✓' if results['password_auth'] else '✗'}")
        
        if results['key_auth'] is not None:
            print(f"Key Auth: {'✓' if results['key_auth'] else '✗'}")
        
        status_emoji = {
            'SUCCESS': '✅',
            'PARTIAL': '⚠️',
            'CONNECTED': '🔗',
            'FAILED': '❌'
        }
        
        print(f"\nOverall Status: {status_emoji.get(results['overall_status'], '❓')} {results['overall_status']}")
        print(f"{'='*60}")


def validate_args(args: argparse.Namespace) -> bool:
    """
    Validate command line arguments.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        bool: True if arguments are valid, False otherwise
    """
    if not args.host:
        print("Error: Host is required")
        return False
    
    if args.port < 1 or args.port > 65535:
        print("Error: Port must be between 1 and 65535")
        return False
    
    if args.key_file and not Path(args.key_file).exists():
        print(f"Error: Key file not found: {args.key_file}")
        return False
    
    return True


def main():
    """Main function to run the SSH connection tester."""
    parser = argparse.ArgumentParser(
        description="SSH Connection Testing Tool - Test SSH connectivity to authorized systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -H 192.168.1.100 -u admin -p mypassword
  %(prog)s -H server.example.com -u user -k ~/.ssh/id_rsa
  %(prog)s -H 10.0.0.1 -u root --key-file /path/to/key --port 2222 -v

Note: Only test systems you own or have explicit permission to test.
        """
    )
    
    # Required arguments
    parser.add_argument('-H', '--host', required=True,
                       help='Target hostname or IP address')
    
    # Optional arguments
    parser.add_argument('-p', '--port', type=int, default=22,
                       help='SSH port (default: 22)')
    parser.add_argument('-u', '--username',
                       help='Username for authentication testing')
    parser.add_argument('-P', '--password',
                       help='Password for authentication (prompted if not provided)')
    parser.add_argument('-k', '--key-file',
                       help='Private key file path for key-based authentication')
    parser.add_argument('--key-passphrase',
                       help='Passphrase for encrypted private key')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                       help='Connection timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--prompt-password', action='store_true',
                       help='Prompt for password securely')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not validate_args(args):
        sys.exit(1)
    
    # Check for paramiko availability
    if not PARAMIKO_AVAILABLE:
        print("Warning: paramiko library not found.")
        print("Install it with: pip install paramiko")
        print("Some features will be limited to basic connectivity testing.\n")
    
    # Set up logging level
    if args.verbose:
        logging.getLogger('ssh_tester').setLevel(logging.INFO)
    else:
        logging.getLogger('ssh_tester').setLevel(logging.WARNING)
    
    # Handle password prompt
    password = args.password
    if args.username and args.prompt_password:
        password = getpass.getpass(f"Enter password for {args.username}: ")
    elif args.username and not args.password and not args.key_file:
        password = getpass.getpass(f"Enter password for {args.username}: ")
    
    # Handle key passphrase prompt
    key_passphrase = args.key_passphrase
    if args.key_file and not key_passphrase:
        try:
            # Try to load key without passphrase first
            if PARAMIKO_AVAILABLE:
                paramiko.RSAKey.from_private_key_file(args.key_file)
        except paramiko.PasswordRequiredException:
            key_passphrase = getpass.getpass("Enter passphrase for private key: ")
        except Exception:
            pass  # Will be handled during actual authentication
    
    # Create and run tester
    tester = SSHConnectionTester(args.host, args.port, args.timeout)
    
    try:
        results = tester.run_comprehensive_test(
            username=args.username,
            password=password,
            key_file=args.key_file,
            key_passphrase=key_passphrase
        )
        
        # Exit with appropriate code
        if results['overall_status'] in ['SUCCESS', 'CONNECTED']:
            sys.exit(0)
        else:
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
