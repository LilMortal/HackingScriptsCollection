#!/usr/bin/env python3
"""
Dictionary-based Login Tester

A Python script for testing password strength against common password dictionaries.
This tool is designed for educational purposes and authorized security testing only.

Author: Security Education Tool
License: MIT
Version: 1.0

Usage:
    python login_tester.py -u username -d dictionary.txt [options]
    python login_tester.py -u admin -d common_passwords.txt --delay 0.5 --max-attempts 100

IMPORTANT: This tool should only be used for:
- Testing your own accounts
- Authorized penetration testing
- Educational purposes
- Security awareness training

Do NOT use this tool for unauthorized access attempts.
"""

import argparse
import sys
import time
import hashlib
import os
from typing import List, Optional, Tuple
import itertools
import threading
from datetime import datetime


class LoginTester:
    """
    A class for testing login credentials against password dictionaries.
    
    This class provides methods to test passwords from dictionaries,
    with rate limiting and attempt tracking for responsible testing.
    """
    
    def __init__(self, username: str, delay: float = 1.0, max_attempts: int = 1000):
        """
        Initialize the LoginTester.
        
        Args:
            username (str): The username to test
            delay (float): Delay between attempts in seconds
            max_attempts (int): Maximum number of attempts before stopping
        """
        self.username = username
        self.delay = delay
        self.max_attempts = max_attempts
        self.attempts = 0
        self.start_time = datetime.now()
        self.found_password = None
        self.stop_testing = False
        
    def load_dictionary(self, dictionary_path: str) -> List[str]:
        """
        Load passwords from a dictionary file.
        
        Args:
            dictionary_path (str): Path to the dictionary file
            
        Returns:
            List[str]: List of passwords from the dictionary
            
        Raises:
            FileNotFoundError: If the dictionary file doesn't exist
            IOError: If there's an error reading the file
        """
        if not os.path.exists(dictionary_path):
            raise FileNotFoundError(f"Dictionary file not found: {dictionary_path}")
        
        passwords = []
        try:
            with open(dictionary_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    password = line.strip()
                    if password and not password.startswith('#'):  # Skip empty lines and comments
                        passwords.append(password)
        except Exception as e:
            raise IOError(f"Error reading dictionary file: {e}")
        
        return passwords
    
    def simulate_login_attempt(self, username: str, password: str) -> bool:
        """
        Simulate a login attempt.
        
        In a real scenario, this would connect to the actual service.
        For this educational tool, we simulate different responses.
        
        Args:
            username (str): Username to test
            password (str): Password to test
            
        Returns:
            bool: True if login appears successful, False otherwise
        """
        # Simulate network delay
        time.sleep(0.1)
        
        # For demonstration purposes, we'll consider some common weak passwords as "successful"
        # In real testing, this would be replaced with actual authentication logic
        weak_passwords = [
            'password', '123456', 'admin', 'root', 'test', 'guest',
            'user', 'welcome', 'qwerty', 'letmein', 'monkey', 'dragon'
        ]
        
        # Simulate a "successful" login for demonstration
        if password.lower() in [p.lower() for p in weak_passwords]:
            return True
        
        # Simulate random success for very weak passwords (for demo purposes)
        password_hash = hashlib.md5(password.encode()).hexdigest()
        if password_hash.startswith('00'):  # Very rare condition for demo
            return True
            
        return False
    
    def test_password_list(self, passwords: List[str], verbose: bool = False) -> Optional[str]:
        """
        Test a list of passwords against the target.
        
        Args:
            passwords (List[str]): List of passwords to test
            verbose (bool): Whether to print verbose output
            
        Returns:
            Optional[str]: The successful password if found, None otherwise
        """
        print(f"Starting dictionary attack on username: {self.username}")
        print(f"Total passwords to test: {len(passwords)}")
        print(f"Delay between attempts: {self.delay} seconds")
        print(f"Maximum attempts: {self.max_attempts}")
        print("-" * 50)
        
        for i, password in enumerate(passwords):
            if self.stop_testing or self.attempts >= self.max_attempts:
                break
                
            self.attempts += 1
            
            if verbose:
                print(f"Attempt {self.attempts}: Testing '{password}'")
            elif self.attempts % 10 == 0:
                print(f"Tested {self.attempts} passwords...")
            
            # Simulate the login attempt
            success = self.simulate_login_attempt(self.username, password)
            
            if success:
                self.found_password = password
                print(f"\n[SUCCESS] Password found: '{password}'")
                print(f"Found after {self.attempts} attempts")
                return password
            
            # Rate limiting
            if self.delay > 0:
                time.sleep(self.delay)
        
        print(f"\n[FAILED] No password found after {self.attempts} attempts")
        return None
    
    def generate_common_variations(self, base_passwords: List[str]) -> List[str]:
        """
        Generate common password variations.
        
        Args:
            base_passwords (List[str]): Base passwords to generate variations from
            
        Returns:
            List[str]: List of password variations
        """
        variations = []
        
        for password in base_passwords:
            # Add original password
            variations.append(password)
            
            # Add common variations
            variations.extend([
                password.capitalize(),
                password.upper(),
                password.lower(),
                password + '123',
                password + '1',
                password + '!',
                '123' + password,
                password + '2023',
                password + '2024',
                password + '2025'
            ])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_variations = []
        for password in variations:
            if password not in seen:
                seen.add(password)
                unique_variations.append(password)
        
        return unique_variations
    
    def print_statistics(self):
        """Print testing statistics."""
        elapsed_time = datetime.now() - self.start_time
        print(f"\nStatistics:")
        print(f"Total attempts: {self.attempts}")
        print(f"Time elapsed: {elapsed_time}")
        print(f"Average attempts per second: {self.attempts / elapsed_time.total_seconds():.2f}")
        if self.found_password:
            print(f"Password found: {self.found_password}")
        else:
            print("No password found")


def create_sample_dictionary(filename: str) -> None:
    """
    Create a sample dictionary file for testing purposes.
    
    Args:
        filename (str): Name of the dictionary file to create
    """
    common_passwords = [
        'password', '123456', 'password123', 'admin', 'root', 'test',
        'guest', 'user', 'welcome', 'qwerty', 'letmein', 'monkey',
        'dragon', 'master', 'shadow', 'azerty', 'trustno1', 'football',
        'baseball', 'superman', 'batman', 'michael', 'jennifer', 'computer',
        'internet', 'service', 'canada', 'hello', 'ranger', 'tigger',
        'secret', 'jordan', 'michelle', 'maggie', 'mindy', 'patrick',
        'mustang', 'letmein', 'access', 'hockey', 'george', 'shadow',
        'princess', 'qwerty', 'freedom', 'sunshine', 'iloveyou', 'nicole'
    ]
    
    with open(filename, 'w') as f:
        f.write("# Common passwords dictionary\n")
        f.write("# Generated for educational purposes\n")
        f.write("# Each line contains one password\n\n")
        for password in common_passwords:
            f.write(password + '\n')
    
    print(f"Sample dictionary created: {filename}")


def main():
    """Main function to handle command-line arguments and execute the testing."""
    parser = argparse.ArgumentParser(
        description='Dictionary-based Login Tester - Educational Security Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u admin -d common_passwords.txt
  %(prog)s -u root -d dictionary.txt --delay 0.5 --max-attempts 100 --verbose
  %(prog)s --create-sample-dict sample_dict.txt
  %(prog)s -u test -d sample_dict.txt --variations

IMPORTANT: Use this tool responsibly and only for authorized testing!
        """
    )
    
    parser.add_argument(
        '-u', '--username',
        type=str,
        help='Username to test (required unless creating sample dictionary)'
    )
    
    parser.add_argument(
        '-d', '--dictionary',
        type=str,
        help='Path to password dictionary file (required unless creating sample dictionary)'
    )
    
    parser.add_argument(
        '--delay',
        type=float,
        default=1.0,
        help='Delay between attempts in seconds (default: 1.0)'
    )
    
    parser.add_argument(
        '--max-attempts',
        type=int,
        default=1000,
        help='Maximum number of attempts (default: 1000)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--variations',
        action='store_true',
        help='Generate common password variations'
    )
    
    parser.add_argument(
        '--create-sample-dict',
        type=str,
        metavar='FILENAME',
        help='Create a sample dictionary file and exit'
    )
    
    args = parser.parse_args()
    
    # Handle sample dictionary creation
    if args.create_sample_dict:
        create_sample_dictionary(args.create_sample_dict)
        return
    
    # Validate required arguments
    if not args.username or not args.dictionary:
        parser.error("Username (-u) and dictionary (-d) are required unless creating a sample dictionary")
    
    # Validate delay and max_attempts
    if args.delay < 0:
        parser.error("Delay must be non-negative")
    
    if args.max_attempts <= 0:
        parser.error("Max attempts must be positive")
    
    try:
        # Initialize the login tester
        tester = LoginTester(
            username=args.username,
            delay=args.delay,
            max_attempts=args.max_attempts
        )
        
        # Load the dictionary
        print(f"Loading dictionary from: {args.dictionary}")
        passwords = tester.load_dictionary(args.dictionary)
        print(f"Loaded {len(passwords)} passwords from dictionary")
        
        # Generate variations if requested
        if args.variations:
            print("Generating password variations...")
            passwords = tester.generate_common_variations(passwords)
            print(f"Generated {len(passwords)} total passwords (including variations)")
        
        # Limit passwords to max_attempts
        if len(passwords) > args.max_attempts:
            passwords = passwords[:args.max_attempts]
            print(f"Limited to first {args.max_attempts} passwords")
        
        # Start the testing
        result = tester.test_password_list(passwords, verbose=args.verbose)
        
        # Print statistics
        tester.print_statistics()
        
        # Exit with appropriate code
        sys.exit(0 if result else 1)
        
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Testing stopped by user")
        sys.exit(130)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
