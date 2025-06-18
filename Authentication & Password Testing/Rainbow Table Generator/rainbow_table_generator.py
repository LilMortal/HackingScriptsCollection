#!/usr/bin/env python3
"""
Rainbow Table Generator - Educational Implementation

This script generates rainbow tables for educational purposes to demonstrate
how precomputed hash tables work in cryptography and security research.

WARNING: This tool is for educational and authorized security testing only.
Use responsibly and in accordance with applicable laws and policies.

Usage:
    python rainbow_table_generator.py -a md5 -c abcdefghijklmnopqrstuvwxyz -l 4 -t 1000 -o rainbow_table.json

Author: Educational Implementation
License: MIT
"""

import argparse
import hashlib
import json
import random
import string
import sys
from typing import Dict, List, Set, Tuple
import time
from pathlib import Path


class RainbowTableGenerator:
    """
    A class to generate rainbow tables using reduction functions and hash chains.
    
    Rainbow tables are precomputed tables used to reverse cryptographic hash functions.
    They use a time-memory tradeoff to store precomputed hash chains instead of
    all possible hash-plaintext pairs.
    """
    
    def __init__(self, hash_algorithm: str, charset: str, max_length: int, 
                 table_count: int, chain_length: int = 1000):
        """
        Initialize the rainbow table generator.
        
        Args:
            hash_algorithm: Hash algorithm to use (md5, sha1, sha256)
            charset: Character set for password generation
            max_length: Maximum password length
            table_count: Number of chains to generate
            chain_length: Length of each hash chain
        """
        self.hash_algorithm = hash_algorithm.lower()
        self.charset = charset
        self.max_length = max_length
        self.table_count = table_count
        self.chain_length = chain_length
        self.rainbow_table: Dict[str, str] = {}
        
        # Validate hash algorithm
        if self.hash_algorithm not in ['md5', 'sha1', 'sha256']:
            raise ValueError("Unsupported hash algorithm. Use: md5, sha1, sha256")
        
        # Set up hash function
        self.hash_func = getattr(hashlib, self.hash_algorithm)
    
    def _hash_password(self, password: str) -> str:
        """
        Hash a password using the specified algorithm.
        
        Args:
            password: Plain text password
            
        Returns:
            Hexadecimal digest of the hash
        """
        return self.hash_func(password.encode('utf-8')).hexdigest()
    
    def _reduce(self, hash_value: str, position: int) -> str:
        """
        Reduction function to convert hash back to a password-like string.
        
        This function maps hash values back to the password space.
        Different positions use different reduction functions to avoid cycles.
        
        Args:
            hash_value: Hash value to reduce
            position: Position in the chain (affects reduction function)
            
        Returns:
            Reduced password string
        """
        # Use hash value and position to create a seed for deterministic reduction
        seed = int(hash_value[:8], 16) + position
        random.seed(seed)
        
        # Generate password of random length (1 to max_length)
        length = random.randint(1, self.max_length)
        password = ''.join(random.choices(self.charset, k=length))
        
        return password
    
    def _generate_chain(self, start_password: str) -> Tuple[str, str]:
        """
        Generate a single hash chain.
        
        Args:
            start_password: Starting password for the chain
            
        Returns:
            Tuple of (start_password, end_password)
        """
        current_password = start_password
        
        # Create chain: password -> hash -> reduce -> password -> hash -> ...
        for i in range(self.chain_length):
            hash_value = self._hash_password(current_password)
            current_password = self._reduce(hash_value, i)
        
        return start_password, current_password
    
    def _generate_random_password(self) -> str:
        """
        Generate a random password from the charset.
        
        Returns:
            Random password string
        """
        length = random.randint(1, self.max_length)
        return ''.join(random.choices(self.charset, k=length))
    
    def generate_table(self, progress_callback=None) -> None:
        """
        Generate the complete rainbow table.
        
        Args:
            progress_callback: Optional callback function for progress updates
        """
        print(f"Generating rainbow table with {self.table_count} chains...")
        print(f"Algorithm: {self.hash_algorithm.upper()}")
        print(f"Charset: {self.charset[:20]}{'...' if len(self.charset) > 20 else ''}")
        print(f"Max length: {self.max_length}")
        print(f"Chain length: {self.chain_length}")
        print("-" * 50)
        
        start_time = time.time()
        generated_chains = 0
        duplicate_endpoints = 0
        
        # Keep track of endpoints to avoid duplicates
        used_endpoints: Set[str] = set()
        
        while generated_chains < self.table_count:
            # Generate random starting password
            start_password = self._generate_random_password()
            
            try:
                # Generate chain
                start, end = self._generate_chain(start_password)
                
                # Check for duplicate endpoints (merging chains)
                if end in used_endpoints:
                    duplicate_endpoints += 1
                    continue
                
                # Store chain in rainbow table
                self.rainbow_table[end] = start
                used_endpoints.add(end)
                generated_chains += 1
                
                # Progress update
                if progress_callback:
                    progress_callback(generated_chains, self.table_count)
                elif generated_chains % (self.table_count // 10) == 0:
                    progress = (generated_chains / self.table_count) * 100
                    print(f"Progress: {progress:.1f}% ({generated_chains}/{self.table_count})")
                    
            except Exception as e:
                print(f"Error generating chain: {e}")
                continue
        
        elapsed_time = time.time() - start_time
        print(f"\nTable generation complete!")
        print(f"Generated chains: {generated_chains}")
        print(f"Duplicate endpoints avoided: {duplicate_endpoints}")
        print(f"Time elapsed: {elapsed_time:.2f} seconds")
        print(f"Coverage estimate: {len(self.rainbow_table)} unique endpoints")
    
    def lookup_hash(self, target_hash: str) -> str | None:
        """
        Attempt to find the plaintext for a given hash using the rainbow table.
        
        Args:
            target_hash: Hash to lookup
            
        Returns:
            Plaintext password if found, None otherwise
        """
        print(f"Looking up hash: {target_hash}")
        
        # Try each position in the chain
        for position in range(self.chain_length):
            current_hash = target_hash
            
            # Reduce from current position to end of chain
            for i in range(position, self.chain_length):
                current_password = self._reduce(current_hash, i)
                if i < self.chain_length - 1:
                    current_hash = self._hash_password(current_password)
            
            # Check if final password is in our table
            if current_password in self.rainbow_table:
                # Found potential chain, now verify by regenerating
                start_password = self.rainbow_table[current_password]
                
                # Regenerate chain from start to find actual password
                test_password = start_password
                for i in range(self.chain_length):
                    if self._hash_password(test_password) == target_hash:
                        return test_password
                    
                    # Continue chain
                    hash_value = self._hash_password(test_password)
                    test_password = self._reduce(hash_value, i)
        
        return None
    
    def save_table(self, filename: str) -> None:
        """
        Save the rainbow table to a JSON file.
        
        Args:
            filename: Output filename
        """
        table_data = {
            'metadata': {
                'hash_algorithm': self.hash_algorithm,
                'charset': self.charset,
                'max_length': self.max_length,
                'table_count': self.table_count,
                'chain_length': self.chain_length,
                'actual_chains': len(self.rainbow_table)
            },
            'table': self.rainbow_table
        }
        
        with open(filename, 'w') as f:
            json.dump(table_data, f, indent=2)
        
        print(f"Rainbow table saved to: {filename}")
        print(f"File size: {Path(filename).stat().st_size / 1024:.2f} KB")
    
    def load_table(self, filename: str) -> None:
        """
        Load a rainbow table from a JSON file.
        
        Args:
            filename: Input filename
        """
        with open(filename, 'r') as f:
            table_data = json.load(f)
        
        # Restore metadata
        metadata = table_data['metadata']
        self.hash_algorithm = metadata['hash_algorithm']
        self.charset = metadata['charset']
        self.max_length = metadata['max_length']
        self.table_count = metadata['table_count']
        self.chain_length = metadata['chain_length']
        
        # Restore table
        self.rainbow_table = table_data['table']
        
        # Update hash function
        self.hash_func = getattr(hashlib, self.hash_algorithm)
        
        print(f"Rainbow table loaded from: {filename}")
        print(f"Chains loaded: {len(self.rainbow_table)}")


def main():
    """Main function to handle command line arguments and execute the program."""
    parser = argparse.ArgumentParser(
        description="Generate rainbow tables for educational cryptographic research",
        epilog="""
Examples:
  # Generate MD5 rainbow table for lowercase letters, length 4
  python rainbow_table_generator.py -a md5 -c abcdefghijklmnopqrstuvwxyz -l 4 -t 1000

  # Generate SHA256 table with numbers and letters
  python rainbow_table_generator.py -a sha256 -c abcdefghijklmnopqrstuvwxyz0123456789 -l 6 -t 5000

  # Lookup a hash in existing table
  python rainbow_table_generator.py --lookup 5d41402abc4b2a76b9719d911017c592 --load rainbow_table.json
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-a', '--algorithm', 
                       choices=['md5', 'sha1', 'sha256'],
                       default='md5',
                       help='Hash algorithm to use (default: md5)')
    
    parser.add_argument('-c', '--charset',
                       default='abcdefghijklmnopqrstuvwxyz',
                       help='Character set for passwords (default: lowercase letters)')
    
    parser.add_argument('-l', '--max-length',
                       type=int,
                       default=4,
                       help='Maximum password length (default: 4)')
    
    parser.add_argument('-t', '--table-count',
                       type=int,
                       default=1000,
                       help='Number of chains to generate (default: 1000)')
    
    parser.add_argument('--chain-length',
                       type=int,
                       default=1000,
                       help='Length of each hash chain (default: 1000)')
    
    parser.add_argument('-o', '--output',
                       default='rainbow_table.json',
                       help='Output filename (default: rainbow_table.json)')
    
    parser.add_argument('--load',
                       help='Load existing rainbow table from file')
    
    parser.add_argument('--lookup',
                       help='Hash to lookup in the rainbow table')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.max_length <= 0:
        print("Error: Maximum length must be positive")
        sys.exit(1)
    
    if args.table_count <= 0:
        print("Error: Table count must be positive")
        sys.exit(1)
    
    if args.chain_length <= 0:
        print("Error: Chain length must be positive")
        sys.exit(1)
    
    try:
        # Create rainbow table generator
        if args.load:
            # Load existing table
            rt_gen = RainbowTableGenerator(args.algorithm, args.charset, 
                                         args.max_length, args.table_count,
                                         args.chain_length)
            rt_gen.load_table(args.load)
        else:
            # Create new table
            rt_gen = RainbowTableGenerator(args.algorithm, args.charset,
                                         args.max_length, args.table_count,
                                         args.chain_length)
        
        # Handle lookup operation
        if args.lookup:
            if not args.load:
                print("Error: Must load a table (--load) to perform lookup")
                sys.exit(1)
            
            result = rt_gen.lookup_hash(args.lookup)
            if result:
                print(f"Found: {result}")
                # Verify the result
                verification = rt_gen._hash_password(result)
                print(f"Verification: {verification}")
                if verification.lower() == args.lookup.lower():
                    print("✓ Hash verified successfully!")
                else:
                    print("✗ Hash verification failed!")
            else:
                print("Hash not found in rainbow table")
        else:
            # Generate new table
            if args.load:
                print("Table loaded successfully. Use --lookup to search for hashes.")
            else:
                print("=" * 60)
                print("EDUCATIONAL RAINBOW TABLE GENERATOR")
                print("=" * 60)
                print("WARNING: Use only for authorized security testing!")
                print("=" * 60)
                
                rt_gen.generate_table()
                rt_gen.save_table(args.output)
                
                print(f"\nRainbow table generation complete!")
                print(f"Use --load {args.output} --lookup <hash> to search")
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
