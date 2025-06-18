#!/usr/bin/env python3
"""
Hash Cracking Educational Tool

This educational script demonstrates how password hashing works and shows
the importance of using strong passwords. It supports multiple hash algorithms
and can perform dictionary attacks against hashes for educational purposes.

Usage:
    python hash_cracker.py --hash <hash_value> --algorithm <algorithm> --wordlist <file>
    python hash_cracker.py --generate <password> --algorithm <algorithm>
    python hash_cracker.py --analyze <password>

Example:
    # Generate a hash
    python hash_cracker.py --generate "mypassword" --algorithm md5
    
    # Crack a hash using a wordlist
    python hash_cracker.py --hash "5d41402abc4b2a76b9719d911017c592" --algorithm md5 --wordlist common_passwords.txt
    
    # Analyze password strength
    python hash_cracker.py --analyze "mypassword123"

Author: Educational Tool
License: MIT
"""

import argparse
import hashlib
import time
import sys
import re
from typing import Optional, List, Dict, Any
import itertools
import string


class HashCracker:
    """
    Educational hash cracking tool that demonstrates password security concepts.
    """
    
    # Supported hash algorithms
    SUPPORTED_ALGORITHMS = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512
    }
    
    def __init__(self):
        """Initialize the hash cracker."""
        self.attempts = 0
        self.start_time = 0
        
    def generate_hash(self, password: str, algorithm: str) -> str:
        """
        Generate a hash for a given password using the specified algorithm.
        
        Args:
            password (str): The password to hash
            algorithm (str): The hashing algorithm to use
            
        Returns:
            str: The hexadecimal hash value
            
        Raises:
            ValueError: If the algorithm is not supported
        """
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
            
        hash_func = self.SUPPORTED_ALGORITHMS[algorithm]
        return hash_func(password.encode('utf-8')).hexdigest()
    
    def verify_hash(self, password: str, target_hash: str, algorithm: str) -> bool:
        """
        Verify if a password matches the target hash.
        
        Args:
            password (str): The password to test
            target_hash (str): The target hash to match
            algorithm (str): The hashing algorithm used
            
        Returns:
            bool: True if the password matches the hash
        """
        self.attempts += 1
        generated_hash = self.generate_hash(password, algorithm)
        return generated_hash.lower() == target_hash.lower()
    
    def dictionary_attack(self, target_hash: str, algorithm: str, wordlist_file: str) -> Optional[str]:
        """
        Perform a dictionary attack against a hash using a wordlist.
        
        Args:
            target_hash (str): The hash to crack
            algorithm (str): The hashing algorithm used
            wordlist_file (str): Path to the wordlist file
            
        Returns:
            Optional[str]: The cracked password or None if not found
        """
        print(f"Starting dictionary attack on {algorithm.upper()} hash: {target_hash}")
        print(f"Using wordlist: {wordlist_file}")
        print("-" * 60)
        
        self.attempts = 0
        self.start_time = time.time()
        
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    password = line.strip()
                    if not password:
                        continue
                        
                    if self.verify_hash(password, target_hash, algorithm):
                        elapsed_time = time.time() - self.start_time
                        print(f"\n✅ PASSWORD FOUND!")
                        print(f"Password: {password}")
                        print(f"Attempts: {self.attempts:,}")
                        print(f"Time elapsed: {elapsed_time:.2f} seconds")
                        print(f"Rate: {self.attempts/elapsed_time:.2f} attempts/second")
                        return password
                    
                    # Progress update every 10000 attempts
                    if self.attempts % 10000 == 0:
                        elapsed_time = time.time() - self.start_time
                        rate = self.attempts / elapsed_time if elapsed_time > 0 else 0
                        print(f"Attempts: {self.attempts:,} | Rate: {rate:.2f}/sec | Current: {password[:20]}...")
                        
        except FileNotFoundError:
            print(f"❌ Error: Wordlist file '{wordlist_file}' not found.")
            return None
        except Exception as e:
            print(f"❌ Error reading wordlist: {e}")
            return None
        
        elapsed_time = time.time() - self.start_time
        print(f"\n❌ Password not found in wordlist.")
        print(f"Total attempts: {self.attempts:,}")
        print(f"Time elapsed: {elapsed_time:.2f} seconds")
        return None
    
    def brute_force_attack(self, target_hash: str, algorithm: str, max_length: int = 4, 
                          charset: str = None) -> Optional[str]:
        """
        Perform a brute force attack (limited for educational purposes).
        
        Args:
            target_hash (str): The hash to crack
            algorithm (str): The hashing algorithm used
            max_length (int): Maximum password length to try (limited to 6 for safety)
            charset (str): Character set to use (default: lowercase + digits)
            
        Returns:
            Optional[str]: The cracked password or None if not found
        """
        # Limit max_length for educational purposes and to prevent excessive computation
        max_length = min(max_length, 6)
        
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        print(f"Starting brute force attack on {algorithm.upper()} hash: {target_hash}")
        print(f"Character set: {charset}")
        print(f"Max length: {max_length}")
        print("⚠️  Note: This is limited for educational purposes only!")
        print("-" * 60)
        
        self.attempts = 0
        self.start_time = time.time()
        
        for length in range(1, max_length + 1):
            print(f"Trying passwords of length {length}...")
            
            for password_tuple in itertools.product(charset, repeat=length):
                password = ''.join(password_tuple)
                
                if self.verify_hash(password, target_hash, algorithm):
                    elapsed_time = time.time() - self.start_time
                    print(f"\n✅ PASSWORD FOUND!")
                    print(f"Password: {password}")
                    print(f"Attempts: {self.attempts:,}")
                    print(f"Time elapsed: {elapsed_time:.2f} seconds")
                    return password
                
                # Progress update every 10000 attempts
                if self.attempts % 10000 == 0:
                    elapsed_time = time.time() - self.start_time
                    rate = self.attempts / elapsed_time if elapsed_time > 0 else 0
                    print(f"Attempts: {self.attempts:,} | Rate: {rate:.2f}/sec | Current: {password}")
        
        elapsed_time = time.time() - self.start_time
        print(f"\n❌ Password not found within length limit.")
        print(f"Total attempts: {self.attempts:,}")
        print(f"Time elapsed: {elapsed_time:.2f} seconds")
        return None
    
    def analyze_password_strength(self, password: str) -> Dict[str, Any]:
        """
        Analyze the strength of a password.
        
        Args:
            password (str): The password to analyze
            
        Returns:
            Dict[str, Any]: Analysis results
        """
        analysis = {
            'length': len(password),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_digits': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
            'common_patterns': [],
            'strength_score': 0,
            'strength_level': 'Very Weak'
        }
        
        # Check for common patterns
        if re.search(r'123', password):
            analysis['common_patterns'].append('Sequential numbers (123)')
        if re.search(r'abc', password, re.IGNORECASE):
            analysis['common_patterns'].append('Sequential letters (abc)')
        if re.search(r'password', password, re.IGNORECASE):
            analysis['common_patterns'].append('Contains "password"')
        if re.search(r'admin', password, re.IGNORECASE):
            analysis['common_patterns'].append('Contains "admin"')
        if re.search(r'qwerty', password, re.IGNORECASE):
            analysis['common_patterns'].append('Keyboard pattern (qwerty)')
        
        # Calculate strength score
        score = 0
        if analysis['length'] >= 8:
            score += 2
        elif analysis['length'] >= 6:
            score += 1
            
        if analysis['has_lowercase']:
            score += 1
        if analysis['has_uppercase']:
            score += 1
        if analysis['has_digits']:
            score += 1
        if analysis['has_special']:
            score += 2
            
        # Penalty for common patterns
        score -= len(analysis['common_patterns'])
        
        analysis['strength_score'] = max(0, score)
        
        # Determine strength level
        if score >= 7:
            analysis['strength_level'] = 'Very Strong'
        elif score >= 5:
            analysis['strength_level'] = 'Strong'
        elif score >= 3:
            analysis['strength_level'] = 'Moderate'
        elif score >= 1:
            analysis['strength_level'] = 'Weak'
        else:
            analysis['strength_level'] = 'Very Weak'
            
        return analysis
    
    def print_password_analysis(self, password: str) -> None:
        """
        Print a detailed password strength analysis.
        
        Args:
            password (str): The password to analyze
        """
        analysis = self.analyze_password_strength(password)
        
        print(f"Password Analysis for: {'*' * len(password)}")
        print("-" * 50)
        print(f"Length: {analysis['length']} characters")
        print(f"Contains lowercase: {'✅' if analysis['has_lowercase'] else '❌'}")
        print(f"Contains uppercase: {'✅' if analysis['has_uppercase'] else '❌'}")
        print(f"Contains digits: {'✅' if analysis['has_digits'] else '❌'}")
        print(f"Contains special chars: {'✅' if analysis['has_special'] else '❌'}")
        
        if analysis['common_patterns']:
            print(f"\n⚠️  Common patterns detected:")
            for pattern in analysis['common_patterns']:
                print(f"  - {pattern}")
        
        print(f"\nStrength Score: {analysis['strength_score']}/7")
        print(f"Strength Level: {analysis['strength_level']}")
        
        # Recommendations
        print(f"\n💡 Recommendations:")
        if analysis['length'] < 8:
            print("  - Use at least 8 characters")
        if not analysis['has_uppercase']:
            print("  - Add uppercase letters")
        if not analysis['has_lowercase']:
            print("  - Add lowercase letters")
        if not analysis['has_digits']:
            print("  - Add numbers")
        if not analysis['has_special']:
            print("  - Add special characters (!@#$%^&*)")
        if analysis['common_patterns']:
            print("  - Avoid common patterns and dictionary words")


def create_sample_wordlist() -> None:
    """Create a sample wordlist for testing purposes."""
    sample_passwords = [
        "password", "123456", "password123", "admin", "letmein", "welcome",
        "monkey", "1234567890", "qwerty", "abc123", "Password1", "admin123",
        "root", "toor", "pass", "test", "guest", "user", "demo", "default",
        "changeme", "secret", "login", "administrator", "passw0rd", "12345678"
    ]
    
    with open('sample_wordlist.txt', 'w') as f:
        for password in sample_passwords:
            f.write(password + '\n')
    
    print("✅ Created sample_wordlist.txt with common passwords for testing.")


def main():
    """Main function to handle command line arguments and execute the appropriate action."""
    parser = argparse.ArgumentParser(
        description="Educational Hash Cracking Tool - Learn about password security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Generate a hash:
    python hash_cracker.py --generate "mypassword" --algorithm md5
    
  Dictionary attack:
    python hash_cracker.py --hash "5d41402abc4b2a76b9719d911017c592" --algorithm md5 --wordlist sample_wordlist.txt
    
  Brute force attack (limited):
    python hash_cracker.py --hash "098f6bcd4621d373cade4e832627b4f6" --algorithm md5 --brute --max-length 4
    
  Analyze password:
    python hash_cracker.py --analyze "mypassword123"
    
  Create sample wordlist:
    python hash_cracker.py --create-wordlist
        """
    )
    
    # Main action arguments (mutually exclusive)
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument('--generate', type=str, metavar='PASSWORD',
                             help='Generate a hash for the given password')
    action_group.add_argument('--hash', type=str, metavar='HASH',
                             help='Hash to crack')
    action_group.add_argument('--analyze', type=str, metavar='PASSWORD',
                             help='Analyze password strength')
    action_group.add_argument('--create-wordlist', action='store_true',
                             help='Create a sample wordlist for testing')
    
    # Algorithm selection
    parser.add_argument('--algorithm', type=str, default='md5',
                       choices=list(HashCracker.SUPPORTED_ALGORITHMS.keys()),
                       help='Hashing algorithm to use (default: md5)')
    
    # Attack method arguments
    parser.add_argument('--wordlist', type=str, metavar='FILE',
                       help='Wordlist file for dictionary attack')
    parser.add_argument('--brute', action='store_true',
                       help='Perform brute force attack (limited for education)')
    parser.add_argument('--max-length', type=int, default=4, metavar='N',
                       help='Maximum password length for brute force (max 6, default 4)')
    parser.add_argument('--charset', type=str, metavar='CHARS',
                       help='Character set for brute force (default: a-z0-9)')
    
    args = parser.parse_args()
    
    # Create hash cracker instance
    cracker = HashCracker()
    
    try:
        if args.create_wordlist:
            create_sample_wordlist()
            
        elif args.generate:
            hash_value = cracker.generate_hash(args.generate, args.algorithm)
            print(f"Password: {args.generate}")
            print(f"Algorithm: {args.algorithm.upper()}")
            print(f"Hash: {hash_value}")
            
        elif args.analyze:
            cracker.print_password_analysis(args.analyze)
            
        elif args.hash:
            if args.wordlist:
                # Dictionary attack
                result = cracker.dictionary_attack(args.hash, args.algorithm, args.wordlist)
            elif args.brute:
                # Brute force attack
                result = cracker.brute_force_attack(args.hash, args.algorithm, 
                                                  args.max_length, args.charset)
            else:
                print("❌ Error: Please specify either --wordlist or --brute for hash cracking.")
                sys.exit(1)
                
            if result:
                print(f"\n🎯 Educational Lesson:")
                print(f"This demonstrates why '{result}' is not a secure password!")
                analysis = cracker.analyze_password_strength(result)
                print(f"Password strength: {analysis['strength_level']}")
            else:
                print(f"\n🛡️  Educational Lesson:")
                print(f"This hash was not cracked, which might indicate:")
                print(f"  - The password is not in common wordlists")
                print(f"  - The password is longer or more complex")
                print(f"  - A stronger hashing algorithm should be used")
                
    except KeyboardInterrupt:
        print(f"\n\n⏹️  Attack interrupted by user.")
        if cracker.attempts > 0:
            elapsed_time = time.time() - cracker.start_time
            print(f"Attempts made: {cracker.attempts:,}")
            print(f"Time elapsed: {elapsed_time:.2f} seconds")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
