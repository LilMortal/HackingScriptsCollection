#!/usr/bin/env python3
"""
PDF Password Recovery Tool

A tool for recovering passwords from password-protected PDF files using dictionary attacks.
This tool should only be used on PDF files you own or have explicit permission to access.

Author: Assistant
License: MIT
Version: 1.0.0

Usage:
    python pdf_password_recovery.py input.pdf -w wordlist.txt
    python pdf_password_recovery.py input.pdf -n 4 --charset digits
    python pdf_password_recovery.py input.pdf -c password1 password2 password3

External Dependencies:
    - PyPDF2: pip install PyPDF2
"""

import argparse
import itertools
import string
import sys
import time
from pathlib import Path
from typing import List, Optional, Generator

try:
    import PyPDF2
except ImportError:
    print("Error: PyPDF2 is required but not installed.")
    print("Install it using: pip install PyPDF2")
    sys.exit(1)


class PDFPasswordRecovery:
    """
    A class for attempting to recover passwords from password-protected PDF files.
    """
    
    def __init__(self, pdf_path: str):
        """
        Initialize the PDF password recovery tool.
        
        Args:
            pdf_path (str): Path to the password-protected PDF file
        """
        self.pdf_path = Path(pdf_path)
        self.reader = None
        self.attempts = 0
        self.start_time = None
        
        if not self.pdf_path.exists():
            raise FileNotFoundError(f"PDF file not found: {pdf_path}")
        
        self._load_pdf()
    
    def _load_pdf(self) -> None:
        """
        Load the PDF file and check if it's password protected.
        
        Raises:
            ValueError: If the file is not a valid PDF or not password protected
        """
        try:
            with open(self.pdf_path, 'rb') as file:
                self.reader = PyPDF2.PdfReader(file)
                
                # Check if PDF is encrypted
                if not self.reader.is_encrypted:
                    raise ValueError("PDF file is not password protected")
                    
        except Exception as e:
            raise ValueError(f"Error loading PDF: {str(e)}")
    
    def test_password(self, password: str) -> bool:
        """
        Test a single password against the PDF.
        
        Args:
            password (str): Password to test
            
        Returns:
            bool: True if password is correct, False otherwise
        """
        self.attempts += 1
        
        try:
            with open(self.pdf_path, 'rb') as file:
                reader = PyPDF2.PdfReader(file)
                if reader.decrypt(password):
                    return True
        except Exception:
            pass
        
        return False
    
    def dictionary_attack(self, wordlist_path: str, max_attempts: Optional[int] = None) -> Optional[str]:
        """
        Perform a dictionary attack using a wordlist file.
        
        Args:
            wordlist_path (str): Path to the wordlist file
            max_attempts (Optional[int]): Maximum number of attempts (None for unlimited)
            
        Returns:
            Optional[str]: The correct password if found, None otherwise
        """
        wordlist_file = Path(wordlist_path)
        if not wordlist_file.exists():
            raise FileNotFoundError(f"Wordlist file not found: {wordlist_path}")
        
        print(f"Starting dictionary attack using: {wordlist_path}")
        self.start_time = time.time()
        
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as file:
                for line_num, password in enumerate(file, 1):
                    password = password.strip()
                    
                    if not password:  # Skip empty lines
                        continue
                    
                    if max_attempts and self.attempts >= max_attempts:
                        print(f"\nMax attempts ({max_attempts}) reached.")
                        break
                    
                    if self.attempts % 100 == 0:
                        self._print_progress(password)
                    
                    if self.test_password(password):
                        return self._success(password)
                        
        except KeyboardInterrupt:
            print("\n\nAttack interrupted by user.")
            return None
        except Exception as e:
            print(f"\nError reading wordlist: {str(e)}")
            return None
        
        print(f"\nDictionary attack completed. Password not found in wordlist.")
        return None
    
    def brute_force_attack(self, max_length: int, charset: str = 'all', 
                          max_attempts: Optional[int] = None) -> Optional[str]:
        """
        Perform a brute force attack.
        
        Args:
            max_length (int): Maximum password length to try
            charset (str): Character set to use ('digits', 'letters', 'alphanumeric', 'all')
            max_attempts (Optional[int]): Maximum number of attempts (None for unlimited)
            
        Returns:
            Optional[str]: The correct password if found, None otherwise
        """
        charset_map = {
            'digits': string.digits,
            'letters': string.ascii_letters,
            'alphanumeric': string.ascii_letters + string.digits,
            'all': string.ascii_letters + string.digits + string.punctuation
        }
        
        if charset not in charset_map:
            raise ValueError(f"Invalid charset. Choose from: {list(charset_map.keys())}")
        
        chars = charset_map[charset]
        print(f"Starting brute force attack (max length: {max_length}, charset: {charset})")
        print(f"Character set: {chars}")
        self.start_time = time.time()
        
        try:
            for length in range(1, max_length + 1):
                print(f"\nTrying passwords of length {length}...")
                
                for password_tuple in itertools.product(chars, repeat=length):
                    password = ''.join(password_tuple)
                    
                    if max_attempts and self.attempts >= max_attempts:
                        print(f"\nMax attempts ({max_attempts}) reached.")
                        return None
                    
                    if self.attempts % 1000 == 0:
                        self._print_progress(password)
                    
                    if self.test_password(password):
                        return self._success(password)
                        
        except KeyboardInterrupt:
            print("\n\nAttack interrupted by user.")
            return None
        
        print(f"\nBrute force attack completed. Password not found.")
        return None
    
    def custom_list_attack(self, passwords: List[str]) -> Optional[str]:
        """
        Test a custom list of passwords.
        
        Args:
            passwords (List[str]): List of passwords to test
            
        Returns:
            Optional[str]: The correct password if found, None otherwise
        """
        print(f"Testing {len(passwords)} custom passwords...")
        self.start_time = time.time()
        
        try:
            for i, password in enumerate(passwords, 1):
                if i % 10 == 0:
                    self._print_progress(password)
                
                if self.test_password(password):
                    return self._success(password)
                    
        except KeyboardInterrupt:
            print("\n\nAttack interrupted by user.")
            return None
        
        print(f"\nCustom list attack completed. Password not found.")
        return None
    
    def _print_progress(self, current_password: str) -> None:
        """Print current progress."""
        elapsed = time.time() - self.start_time
        rate = self.attempts / elapsed if elapsed > 0 else 0
        
        # Truncate password for display if too long
        display_password = current_password[:20] + "..." if len(current_password) > 20 else current_password
        
        print(f"\rAttempts: {self.attempts:,} | Rate: {rate:.1f}/sec | "
              f"Current: {display_password:<25}", end='', flush=True)
    
    def _success(self, password: str) -> str:
        """Handle successful password discovery."""
        elapsed = time.time() - self.start_time
        print(f"\n\n✓ PASSWORD FOUND: '{password}'")
        print(f"  Attempts: {self.attempts:,}")
        print(f"  Time elapsed: {elapsed:.2f} seconds")
        return password


def create_sample_wordlist() -> None:
    """Create a sample wordlist file for testing."""
    sample_passwords = [
        "password", "123456", "password123", "admin", "letmein",
        "welcome", "monkey", "dragon", "master", "hello",
        "freedom", "whatever", "qwerty", "trustno1", "jordan",
        "harley", "robert", "matthew", "jordan23", "1000000"
    ]
    
    with open("sample_wordlist.txt", 'w') as f:
        for pwd in sample_passwords:
            f.write(pwd + '\n')
    
    print("Sample wordlist created: sample_wordlist.txt")


def main():
    """Main function to handle command-line interface."""
    parser = argparse.ArgumentParser(
        description="PDF Password Recovery Tool - Recover passwords from password-protected PDFs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s document.pdf -w wordlist.txt
  %(prog)s document.pdf -n 4 --charset digits
  %(prog)s document.pdf -c password123 admin letmein
  %(prog)s --create-sample-wordlist
        """
    )
    
    parser.add_argument('pdf_file', nargs='?', help='Path to the password-protected PDF file')
    
    # Attack methods (mutually exclusive)
    attack_group = parser.add_mutually_exclusive_group(required=False)
    attack_group.add_argument('-w', '--wordlist', help='Path to wordlist file for dictionary attack')
    attack_group.add_argument('-n', '--brute-force', type=int, metavar='LENGTH',
                             help='Maximum length for brute force attack')
    attack_group.add_argument('-c', '--custom', nargs='+', metavar='PASSWORD',
                             help='Custom list of passwords to test')
    
    # Brute force options
    parser.add_argument('--charset', choices=['digits', 'letters', 'alphanumeric', 'all'],
                       default='alphanumeric', help='Character set for brute force attack')
    
    # General options
    parser.add_argument('--max-attempts', type=int, help='Maximum number of attempts')
    parser.add_argument('--create-sample-wordlist', action='store_true',
                       help='Create a sample wordlist file and exit')
    
    args = parser.parse_args()
    
    if args.create_sample_wordlist:
        create_sample_wordlist()
        return
    
    if not args.pdf_file:
        parser.error("PDF file is required unless using --create-sample-wordlist")
    
    if not any([args.wordlist, args.brute_force, args.custom]):
        parser.error("Must specify one attack method: -w, -n, or -c")
    
    try:
        # Initialize the password recovery tool
        pdf_tool = PDFPasswordRecovery(args.pdf_file)
        print(f"Loaded PDF: {args.pdf_file}")
        print("PDF is password protected. Starting password recovery...\n")
        
        password = None
        
        # Execute the chosen attack method
        if args.wordlist:
            password = pdf_tool.dictionary_attack(args.wordlist, args.max_attempts)
        elif args.brute_force:
            password = pdf_tool.brute_force_attack(args.brute_force, args.charset, args.max_attempts)
        elif args.custom:
            password = pdf_tool.custom_list_attack(args.custom)
        
        if password:
            print(f"\nSUCCESS! The password is: {password}")
            sys.exit(0)
        else:
            print("\nPassword not found.")
            sys.exit(1)
            
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
