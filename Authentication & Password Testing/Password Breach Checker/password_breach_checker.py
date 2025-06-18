#!/usr/bin/env python3
"""
Password Breach Checker

A tool to check if passwords have appeared in known data breaches using the
HaveIBeenPwned API. This tool uses k-anonymity to protect password privacy
by only sending the first 5 characters of the password's SHA-1 hash.

Usage:
    python password_breach_checker.py --password "mypassword123"
    python password_breach_checker.py --file passwords.txt
    python password_breach_checker.py --interactive

Example:
    $ python password_breach_checker.py --password "password123"
    WARNING: Password "password123" found in 2,417,804 breaches!
    
    $ python password_breach_checker.py --password "MyVerySecureP@ssw0rd2024!"
    Good news! Password appears to be safe (not found in known breaches).

Author: Generated Script
License: MIT
"""

import argparse
import getpass
import hashlib
import requests
import sys
import time
from pathlib import Path
from typing import List, Tuple, Optional


class PasswordBreachChecker:
    """
    A class to check passwords against the HaveIBeenPwned database using k-anonymity.
    
    The HaveIBeenPwned API uses k-anonymity to protect password privacy. Only the first
    5 characters of the SHA-1 hash are sent to the API, and the full hash is matched
    locally against the returned list of hash suffixes.
    """
    
    def __init__(self, user_agent: str = "Password-Breach-Checker/1.0"):
        """
        Initialize the password breach checker.
        
        Args:
            user_agent (str): User agent string for API requests
        """
        self.api_url = "https://api.pwnedpasswords.com/range/"
        self.user_agent = user_agent
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Add-Padding': 'true'  # Adds padding to responses for additional privacy
        })
    
    def _get_sha1_hash(self, password: str) -> str:
        """
        Generate SHA-1 hash of the password.
        
        Args:
            password (str): The password to hash
            
        Returns:
            str: SHA-1 hash in uppercase hexadecimal format
        """
        return hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    def _query_api(self, hash_prefix: str) -> Optional[str]:
        """
        Query the HaveIBeenPwned API with the hash prefix.
        
        Args:
            hash_prefix (str): First 5 characters of the SHA-1 hash
            
        Returns:
            Optional[str]: API response text or None if request failed
        """
        try:
            response = self.session.get(
                f"{self.api_url}{hash_prefix}",
                timeout=10
            )
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            print(f"Error querying API: {e}", file=sys.stderr)
            return None
    
    def check_password(self, password: str) -> Tuple[bool, int]:
        """
        Check if a password appears in known breaches.
        
        Args:
            password (str): The password to check
            
        Returns:
            Tuple[bool, int]: (is_breached, breach_count)
                - is_breached: True if password found in breaches
                - breach_count: Number of times password appeared in breaches
        """
        if not password:
            return False, 0
        
        # Generate SHA-1 hash and split into prefix and suffix
        full_hash = self._get_sha1_hash(password)
        hash_prefix = full_hash[:5]
        hash_suffix = full_hash[5:]
        
        # Query the API
        response = self._query_api(hash_prefix)
        if response is None:
            return False, 0
        
        # Parse response to find matching hash suffix
        for line in response.strip().split('\n'):
            if ':' in line:
                suffix, count = line.split(':', 1)
                if suffix == hash_suffix:
                    return True, int(count)
        
        return False, 0
    
    def check_multiple_passwords(self, passwords: List[str], delay: float = 0.1) -> List[Tuple[str, bool, int]]:
        """
        Check multiple passwords with rate limiting.
        
        Args:
            passwords (List[str]): List of passwords to check
            delay (float): Delay between requests in seconds
            
        Returns:
            List[Tuple[str, bool, int]]: List of (password, is_breached, breach_count)
        """
        results = []
        
        for i, password in enumerate(passwords):
            if i > 0:
                time.sleep(delay)  # Rate limiting
            
            is_breached, count = self.check_password(password)
            results.append((password, is_breached, count))
            
            # Progress indicator for large lists
            if len(passwords) > 10 and (i + 1) % 10 == 0:
                print(f"Checked {i + 1}/{len(passwords)} passwords...", file=sys.stderr)
        
        return results


def load_passwords_from_file(file_path: str) -> List[str]:
    """
    Load passwords from a text file (one password per line).
    
    Args:
        file_path (str): Path to the password file
        
    Returns:
        List[str]: List of passwords
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        IOError: If there's an error reading the file
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            passwords = [line.strip() for line in file if line.strip()]
        return passwords
    except FileNotFoundError:
        raise FileNotFoundError(f"Password file not found: {file_path}")
    except IOError as e:
        raise IOError(f"Error reading password file: {e}")


def format_result(password: str, is_breached: bool, breach_count: int, show_password: bool = True) -> str:
    """
    Format the result of a password check.
    
    Args:
        password (str): The password that was checked
        is_breached (bool): Whether the password was found in breaches
        breach_count (int): Number of times the password appeared in breaches
        show_password (bool): Whether to show the actual password in output
        
    Returns:
        str: Formatted result string
    """
    password_display = password if show_password else "*" * len(password)
    
    if is_breached:
        return f"⚠️  WARNING: Password \"{password_display}\" found in {breach_count:,} breaches!"
    else:
        return f"✅ Good news! Password \"{password_display}\" appears to be safe (not found in known breaches)."


def interactive_mode():
    """Run the tool in interactive mode for checking individual passwords."""
    checker = PasswordBreachChecker()
    
    print("Password Breach Checker - Interactive Mode")
    print("=========================================")
    print("Enter passwords to check (Ctrl+C to exit)")
    print("Passwords are hidden as you type for security.\n")
    
    try:
        while True:
            try:
                password = getpass.getpass("Enter password to check: ")
                if not password:
                    print("Please enter a password.\n")
                    continue
                
                print("Checking password...", end="", flush=True)
                is_breached, count = checker.check_password(password)
                print("\r" + " " * 20 + "\r", end="")  # Clear the "Checking..." message
                
                result = format_result(password, is_breached, count, show_password=False)
                print(result)
                print()
                
            except KeyboardInterrupt:
                print("\n\nGoodbye!")
                break
            except Exception as e:
                print(f"\nError checking password: {e}")
                print()
    
    except KeyboardInterrupt:
        print("\n\nGoodbye!")


def main():
    """Main function to handle command-line arguments and execute the appropriate mode."""
    parser = argparse.ArgumentParser(
        description="Check if passwords have appeared in known data breaches using HaveIBeenPwned API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --password "mypassword123"
  %(prog)s --file passwords.txt
  %(prog)s --interactive
  %(prog)s --file passwords.txt --hide-passwords --delay 0.2

Notes:
  - This tool uses k-anonymity to protect password privacy
  - Only the first 5 characters of the SHA-1 hash are sent to the API
  - Use responsibly and only check passwords you own or have permission to check
        """
    )
    
    # Mutually exclusive group for input methods
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--password', '-p',
        type=str,
        help='Single password to check'
    )
    input_group.add_argument(
        '--file', '-f',
        type=str,
        help='File containing passwords to check (one per line)'
    )
    input_group.add_argument(
        '--interactive', '-i',
        action='store_true',
        help='Run in interactive mode'
    )
    
    # Optional arguments
    parser.add_argument(
        '--hide-passwords',
        action='store_true',
        help='Hide passwords in output (show asterisks instead)'
    )
    parser.add_argument(
        '--delay',
        type=float,
        default=0.1,
        help='Delay between API requests in seconds (default: 0.1)'
    )
    parser.add_argument(
        '--user-agent',
        type=str,
        default="Password-Breach-Checker/1.0",
        help='Custom User-Agent string for API requests'
    )
    
    args = parser.parse_args()
    
    # Validate delay argument
    if args.delay < 0:
        print("Error: Delay must be non-negative", file=sys.stderr)
        sys.exit(1)
    
    # Initialize the checker
    checker = PasswordBreachChecker(user_agent=args.user_agent)
    
    try:
        if args.interactive:
            interactive_mode()
        
        elif args.password:
            # Check single password
            print("Checking password...", end="", flush=True)
            is_breached, count = checker.check_password(args.password)
            print("\r" + " " * 20 + "\r", end="")  # Clear the "Checking..." message
            
            result = format_result(args.password, is_breached, count, not args.hide_passwords)
            print(result)
            
            # Exit with appropriate code
            sys.exit(1 if is_breached else 0)
        
        elif args.file:
            # Check passwords from file
            try:
                passwords = load_passwords_from_file(args.file)
                if not passwords:
                    print("No passwords found in file", file=sys.stderr)
                    sys.exit(1)
                
                print(f"Checking {len(passwords)} passwords from {args.file}...")
                results = checker.check_multiple_passwords(passwords, args.delay)
                
                # Display results
                breached_count = 0
                for password, is_breached, count in results:
                    result = format_result(password, is_breached, count, not args.hide_passwords)
                    print(result)
                    if is_breached:
                        breached_count += 1
                
                # Summary
                print(f"\nSummary: {breached_count}/{len(passwords)} passwords found in breaches")
                
                # Exit with appropriate code
                sys.exit(1 if breached_count > 0 else 0)
                
            except (FileNotFoundError, IOError) as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
