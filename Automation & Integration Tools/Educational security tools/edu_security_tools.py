#!/usr/bin/env python3
"""
Educational Security Tools

A collection of educational tools for learning about cybersecurity concepts.
This script demonstrates password analysis, basic cryptography, and secure
random generation in a safe, educational environment.

Author: Educational Security Tools
Version: 1.0.0
License: MIT

Usage Examples:
    python edu_security_tools.py password-check --password "MyPassword123!"
    python edu_security_tools.py generate-password --length 16
    python edu_security_tools.py hash-demo --text "Hello World"
    python edu_security_tools.py cipher-demo --text "Secret Message" --key "mykey"
"""

import argparse
import hashlib
import secrets
import string
import re
import base64
import sys
from typing import Dict, List, Tuple, Optional
import json


class PasswordAnalyzer:
    """Analyzes password strength and provides feedback."""
    
    def __init__(self):
        self.common_passwords = {
            'password', '123456', 'password123', 'admin', 'qwerty',
            'letmein', 'welcome', 'monkey', '1234567890', 'abc123'
        }
    
    def analyze_password(self, password: str) -> Dict[str, any]:
        """
        Analyze password strength and return detailed feedback.
        
        Args:
            password (str): Password to analyze
            
        Returns:
            Dict containing analysis results
        """
        analysis = {
            'password': password,
            'length': len(password),
            'strength_score': 0,
            'strength_level': 'Very Weak',
            'checks': {},
            'suggestions': []
        }
        
        # Length check
        if len(password) >= 8:
            analysis['checks']['length'] = True
            analysis['strength_score'] += 2
        else:
            analysis['checks']['length'] = False
            analysis['suggestions'].append('Use at least 8 characters')
        
        # Character variety checks
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        analysis['checks']['lowercase'] = has_lower
        analysis['checks']['uppercase'] = has_upper
        analysis['checks']['digits'] = has_digit
        analysis['checks']['special_chars'] = has_special
        
        # Score based on character variety
        char_variety = sum([has_lower, has_upper, has_digit, has_special])
        analysis['strength_score'] += char_variety
        
        if not has_lower:
            analysis['suggestions'].append('Include lowercase letters')
        if not has_upper:
            analysis['suggestions'].append('Include uppercase letters')
        if not has_digit:
            analysis['suggestions'].append('Include numbers')
        if not has_special:
            analysis['suggestions'].append('Include special characters')
        
        # Common password check
        if password.lower() in self.common_passwords:
            analysis['checks']['not_common'] = False
            analysis['suggestions'].append('Avoid common passwords')
        else:
            analysis['checks']['not_common'] = True
            analysis['strength_score'] += 1
        
        # Repeated characters check
        if len(set(password)) < len(password) * 0.7:
            analysis['checks']['no_repetition'] = False
            analysis['suggestions'].append('Avoid too many repeated characters')
        else:
            analysis['checks']['no_repetition'] = True
            analysis['strength_score'] += 1
        
        # Determine strength level
        if analysis['strength_score'] >= 7:
            analysis['strength_level'] = 'Very Strong'
        elif analysis['strength_score'] >= 5:
            analysis['strength_level'] = 'Strong'
        elif analysis['strength_score'] >= 3:
            analysis['strength_level'] = 'Medium'
        elif analysis['strength_score'] >= 1:
            analysis['strength_level'] = 'Weak'
        
        return analysis


class SecureGenerator:
    """Generates secure passwords and random data."""
    
    @staticmethod
    def generate_password(length: int = 12, 
                         include_symbols: bool = True,
                         exclude_ambiguous: bool = True) -> str:
        """
        Generate a cryptographically secure password.
        
        Args:
            length (int): Password length
            include_symbols (bool): Include special characters
            exclude_ambiguous (bool): Exclude ambiguous characters (0, O, l, 1, etc.)
            
        Returns:
            str: Generated password
        """
        if length < 4:
            raise ValueError("Password length must be at least 4 characters")
        
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if exclude_ambiguous:
            # Remove ambiguous characters
            lowercase = lowercase.replace('l', '').replace('o', '')
            uppercase = uppercase.replace('I', '').replace('O', '')
            digits = digits.replace('0', '').replace('1', '')
        
        # Build character set
        chars = lowercase + uppercase + digits
        if include_symbols:
            chars += symbols
        
        # Ensure at least one character from each category
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits)
        ]
        
        if include_symbols:
            password.append(secrets.choice(symbols))
        
        # Fill remaining length
        for _ in range(length - len(password)):
            password.append(secrets.choice(chars))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    @staticmethod
    def generate_random_bytes(length: int) -> bytes:
        """Generate cryptographically secure random bytes."""
        return secrets.token_bytes(length)
    
    @staticmethod
    def generate_token(length: int = 32) -> str:
        """Generate a secure URL-safe token."""
        return secrets.token_urlsafe(length)


class HashDemo:
    """Demonstrates various hashing algorithms."""
    
    @staticmethod
    def hash_text(text: str, algorithm: str = 'sha256') -> Dict[str, str]:
        """
        Hash text using specified algorithm.
        
        Args:
            text (str): Text to hash
            algorithm (str): Hash algorithm to use
            
        Returns:
            Dict containing hash results
        """
        algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
        
        if algorithm not in algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        hash_func = algorithms[algorithm]
        hash_obj = hash_func(text.encode('utf-8'))
        
        return {
            'original_text': text,
            'algorithm': algorithm,
            'hash_hex': hash_obj.hexdigest(),
            'hash_base64': base64.b64encode(hash_obj.digest()).decode('utf-8')
        }
    
    @staticmethod
    def compare_hashes(text1: str, text2: str, algorithm: str = 'sha256') -> Dict[str, any]:
        """Compare hashes of two texts."""
        hash1 = HashDemo.hash_text(text1, algorithm)
        hash2 = HashDemo.hash_text(text2, algorithm)
        
        return {
            'text1': text1,
            'text2': text2,
            'hash1': hash1['hash_hex'],
            'hash2': hash2['hash_hex'],
            'match': hash1['hash_hex'] == hash2['hash_hex']
        }


class SimpleCipher:
    """Simple cipher demonstrations for educational purposes."""
    
    @staticmethod
    def caesar_cipher(text: str, shift: int, decrypt: bool = False) -> str:
        """
        Apply Caesar cipher to text.
        
        Args:
            text (str): Text to cipher
            shift (int): Shift amount
            decrypt (bool): Whether to decrypt instead of encrypt
            
        Returns:
            str: Ciphered text
        """
        if decrypt:
            shift = -shift
        
        result = []
        for char in text:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - ascii_offset + shift) % 26
                result.append(chr(shifted + ascii_offset))
            else:
                result.append(char)
        
        return ''.join(result)
    
    @staticmethod
    def simple_xor(text: str, key: str) -> str:
        """
        Simple XOR cipher (educational only - not secure).
        
        Args:
            text (str): Text to cipher
            key (str): Key for XOR operation
            
        Returns:
            str: Base64 encoded ciphered text
        """
        if not key:
            raise ValueError("Key cannot be empty")
        
        # Repeat key to match text length
        extended_key = (key * (len(text) // len(key) + 1))[:len(text)]
        
        # XOR operation
        result = []
        for i, char in enumerate(text):
            xor_result = ord(char) ^ ord(extended_key[i])
            result.append(xor_result)
        
        # Return as base64 to handle binary data
        return base64.b64encode(bytes(result)).decode('utf-8')


def print_password_analysis(analysis: Dict[str, any]) -> None:
    """Print formatted password analysis results."""
    print(f"\n{'='*50}")
    print(f"PASSWORD ANALYSIS")
    print(f"{'='*50}")
    print(f"Password: {'*' * len(analysis['password'])}")
    print(f"Length: {analysis['length']} characters")
    print(f"Strength: {analysis['strength_level']} (Score: {analysis['strength_score']}/8)")
    
    print(f"\nSecurity Checks:")
    for check, passed in analysis['checks'].items():
        status = "✓" if passed else "✗"
        print(f"  {status} {check.replace('_', ' ').title()}")
    
    if analysis['suggestions']:
        print(f"\nSuggestions for improvement:")
        for suggestion in analysis['suggestions']:
            print(f"  • {suggestion}")


def main():
    """Main function to handle command line arguments and execute tools."""
    parser = argparse.ArgumentParser(
        description="Educational Security Tools - Learn cybersecurity concepts safely",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s password-check --password "MyPassword123!"
  %(prog)s generate-password --length 16 --no-symbols
  %(prog)s hash-demo --text "Hello World" --algorithm sha256
  %(prog)s cipher-demo --text "Secret" --key "mykey" --cipher caesar --shift 3
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Password analysis command
    password_parser = subparsers.add_parser('password-check', 
                                          help='Analyze password strength')
    password_parser.add_argument('--password', required=True,
                               help='Password to analyze')
    
    # Password generation command
    generate_parser = subparsers.add_parser('generate-password',
                                          help='Generate secure password')
    generate_parser.add_argument('--length', type=int, default=12,
                               help='Password length (default: 12)')
    generate_parser.add_argument('--no-symbols', action='store_true',
                               help='Exclude special symbols')
    generate_parser.add_argument('--allow-ambiguous', action='store_true',
                               help='Allow ambiguous characters')
    generate_parser.add_argument('--count', type=int, default=1,
                               help='Number of passwords to generate')
    
    # Hash demonstration command
    hash_parser = subparsers.add_parser('hash-demo',
                                      help='Demonstrate hashing algorithms')
    hash_parser.add_argument('--text', required=True,
                           help='Text to hash')
    hash_parser.add_argument('--algorithm', default='sha256',
                           choices=['md5', 'sha1', 'sha256', 'sha512'],
                           help='Hash algorithm to use')
    hash_parser.add_argument('--compare', 
                           help='Compare with another text')
    
    # Cipher demonstration command
    cipher_parser = subparsers.add_parser('cipher-demo',
                                        help='Demonstrate simple ciphers')
    cipher_parser.add_argument('--text', required=True,
                             help='Text to cipher')
    cipher_parser.add_argument('--cipher', default='caesar',
                             choices=['caesar', 'xor'],
                             help='Cipher type to use')
    cipher_parser.add_argument('--key', 
                             help='Key for cipher (required for XOR)')
    cipher_parser.add_argument('--shift', type=int, default=3,
                             help='Shift amount for Caesar cipher')
    cipher_parser.add_argument('--decrypt', action='store_true',
                             help='Decrypt instead of encrypt')
    
    # Token generation command
    token_parser = subparsers.add_parser('generate-token',
                                       help='Generate secure tokens')
    token_parser.add_argument('--length', type=int, default=32,
                            help='Token length (default: 32)')
    token_parser.add_argument('--format', default='urlsafe',
                            choices=['urlsafe', 'hex', 'bytes'],
                            help='Token format')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'password-check':
            analyzer = PasswordAnalyzer()
            analysis = analyzer.analyze_password(args.password)
            print_password_analysis(analysis)
        
        elif args.command == 'generate-password':
            generator = SecureGenerator()
            print(f"\nGenerated Password{'s' if args.count > 1 else ''}:")
            print("=" * 40)
            for i in range(args.count):
                password = generator.generate_password(
                    length=args.length,
                    include_symbols=not args.no_symbols,
                    exclude_ambiguous=not args.allow_ambiguous
                )
                print(f"{i+1:2d}. {password}")
        
        elif args.command == 'hash-demo':
            hash_demo = HashDemo()
            if args.compare:
                result = hash_demo.compare_hashes(args.text, args.compare, args.algorithm)
                print(f"\nHash Comparison ({args.algorithm.upper()}):")
                print("=" * 40)
                print(f"Text 1: {result['text1']}")
                print(f"Hash 1: {result['hash1']}")
                print(f"Text 2: {result['text2']}")
                print(f"Hash 2: {result['hash2']}")
                print(f"Match:  {'Yes' if result['match'] else 'No'}")
            else:
                result = hash_demo.hash_text(args.text, args.algorithm)
                print(f"\nHash Result ({args.algorithm.upper()}):")
                print("=" * 40)
                print(f"Original: {result['original_text']}")
                print(f"Hex:      {result['hash_hex']}")
                print(f"Base64:   {result['hash_base64']}")
        
        elif args.command == 'cipher-demo':
            cipher = SimpleCipher()
            if args.cipher == 'caesar':
                result = cipher.caesar_cipher(args.text, args.shift, args.decrypt)
                operation = "Decrypted" if args.decrypt else "Encrypted"
                print(f"\nCaesar Cipher {operation} (shift: {args.shift}):")
                print("=" * 40)
                print(f"Original: {args.text}")
                print(f"Result:   {result}")
            
            elif args.cipher == 'xor':
                if not args.key:
                    print("Error: XOR cipher requires a key (--key)")
                    return
                result = cipher.simple_xor(args.text, args.key)
                print(f"\nXOR Cipher Result:")
                print("=" * 40)
                print(f"Original: {args.text}")
                print(f"Key:      {args.key}")
                print(f"Result:   {result}")
                print("\nNote: XOR is symmetric - run again with result as input to decrypt")
        
        elif args.command == 'generate-token':
            generator = SecureGenerator()
            if args.format == 'urlsafe':
                token = generator.generate_token(args.length)
            elif args.format == 'hex':
                token = generator.generate_random_bytes(args.length).hex()
            elif args.format == 'bytes':
                token = str(generator.generate_random_bytes(args.length))
            
            print(f"\nGenerated Token ({args.format}):")
            print("=" * 40)
            print(token)
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
