#!/usr/bin/env python3
"""
Hash Collision Detector

A Python script to detect hash collisions by comparing hash values of multiple inputs
using various hashing algorithms. Useful for security research, data integrity verification,
and educational purposes.

Usage:
    python hash_collision_detector.py -a md5 -f file1.txt file2.txt
    python hash_collision_detector.py -a sha256 -s "hello" "world" "hello"
    python hash_collision_detector.py -a all -d /path/to/directory --recursive

Author: Hash Collision Detector
License: MIT
"""

import argparse
import hashlib
import os
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional


class HashCollisionDetector:
    """
    A class to detect hash collisions using various hashing algorithms.
    """
    
    # Supported hash algorithms
    SUPPORTED_ALGORITHMS = [
        'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
        'blake2b', 'blake2s', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512'
    ]
    
    def __init__(self, algorithm: str = 'sha256'):
        """
        Initialize the Hash Collision Detector.
        
        Args:
            algorithm (str): The hashing algorithm to use
        """
        self.algorithm = algorithm.lower()
        self.validate_algorithm()
        self.hash_table = defaultdict(list)
        self.processed_items = 0
        
    def validate_algorithm(self) -> None:
        """
        Validate that the specified algorithm is supported.
        
        Raises:
            ValueError: If the algorithm is not supported
        """
        if self.algorithm not in self.SUPPORTED_ALGORITHMS:
            available = ', '.join(self.SUPPORTED_ALGORITHMS)
            raise ValueError(f"Unsupported algorithm '{self.algorithm}'. "
                           f"Available algorithms: {available}")
    
    def calculate_hash(self, data: bytes) -> str:
        """
        Calculate hash for the given data using the specified algorithm.
        
        Args:
            data (bytes): The data to hash
            
        Returns:
            str: The hexadecimal hash value
            
        Raises:
            RuntimeError: If hash calculation fails
        """
        try:
            hash_obj = hashlib.new(self.algorithm)
            hash_obj.update(data)
            return hash_obj.hexdigest()
        except Exception as e:
            raise RuntimeError(f"Failed to calculate {self.algorithm} hash: {e}")
    
    def hash_string(self, text: str, identifier: str = None) -> str:
        """
        Hash a string and store it in the hash table.
        
        Args:
            text (str): The string to hash
            identifier (str): Optional identifier for the string
            
        Returns:
            str: The calculated hash value
        """
        if identifier is None:
            identifier = f"String_{self.processed_items + 1}"
            
        try:
            data = text.encode('utf-8')
            hash_value = self.calculate_hash(data)
            self.hash_table[hash_value].append({
                'type': 'string',
                'identifier': identifier,
                'content': text[:100] + ('...' if len(text) > 100 else ''),
                'size': len(data)
            })
            self.processed_items += 1
            return hash_value
        except Exception as e:
            print(f"Error hashing string '{identifier}': {e}", file=sys.stderr)
            return None
    
    def hash_file(self, file_path: str) -> Optional[str]:
        """
        Hash a file and store it in the hash table.
        
        Args:
            file_path (str): Path to the file to hash
            
        Returns:
            str: The calculated hash value, or None if failed
        """
        try:
            path = Path(file_path)
            if not path.exists():
                print(f"File not found: {file_path}", file=sys.stderr)
                return None
                
            if not path.is_file():
                print(f"Not a file: {file_path}", file=sys.stderr)
                return None
            
            # Read file in chunks to handle large files efficiently
            hash_obj = hashlib.new(self.algorithm)
            with open(path, 'rb') as f:
                while chunk := f.read(8192):
                    hash_obj.update(chunk)
            
            hash_value = hash_obj.hexdigest()
            file_size = path.stat().st_size
            
            self.hash_table[hash_value].append({
                'type': 'file',
                'identifier': str(path.absolute()),
                'content': path.name,
                'size': file_size
            })
            self.processed_items += 1
            return hash_value
            
        except PermissionError:
            print(f"Permission denied: {file_path}", file=sys.stderr)
            return None
        except Exception as e:
            print(f"Error hashing file '{file_path}': {e}", file=sys.stderr)
            return None
    
    def hash_directory(self, directory_path: str, recursive: bool = False) -> int:
        """
        Hash all files in a directory.
        
        Args:
            directory_path (str): Path to the directory
            recursive (bool): Whether to process subdirectories recursively
            
        Returns:
            int: Number of files processed
        """
        try:
            path = Path(directory_path)
            if not path.exists():
                print(f"Directory not found: {directory_path}", file=sys.stderr)
                return 0
                
            if not path.is_dir():
                print(f"Not a directory: {directory_path}", file=sys.stderr)
                return 0
            
            files_processed = 0
            pattern = '**/*' if recursive else '*'
            
            for item in path.glob(pattern):
                if item.is_file():
                    if self.hash_file(str(item)):
                        files_processed += 1
                        if files_processed % 100 == 0:
                            print(f"Processed {files_processed} files...", file=sys.stderr)
            
            return files_processed
            
        except Exception as e:
            print(f"Error processing directory '{directory_path}': {e}", file=sys.stderr)
            return 0
    
    def find_collisions(self) -> Dict[str, List[Dict]]:
        """
        Find hash collisions in the processed data.
        
        Returns:
            Dict[str, List[Dict]]: Dictionary of hash values with multiple items
        """
        collisions = {}
        for hash_value, items in self.hash_table.items():
            if len(items) > 1:
                collisions[hash_value] = items
        return collisions
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get statistics about the processed data.
        
        Returns:
            Dict[str, int]: Statistics dictionary
        """
        total_hashes = len(self.hash_table)
        total_items = sum(len(items) for items in self.hash_table.values())
        collisions = len(self.find_collisions())
        
        return {
            'total_items': total_items,
            'unique_hashes': total_hashes,
            'collision_groups': collisions,
            'collision_rate': (collisions / total_hashes * 100) if total_hashes > 0 else 0
        }
    
    def print_results(self, show_all: bool = False) -> None:
        """
        Print the results of collision detection.
        
        Args:
            show_all (bool): Whether to show all hashes or just collisions
        """
        collisions = self.find_collisions()
        stats = self.get_statistics()
        
        print(f"\n{'='*60}")
        print(f"HASH COLLISION DETECTION RESULTS ({self.algorithm.upper()})")
        print(f"{'='*60}")
        
        print(f"Total items processed: {stats['total_items']}")
        print(f"Unique hash values: {stats['unique_hashes']}")
        print(f"Collision groups found: {stats['collision_groups']}")
        print(f"Collision rate: {stats['collision_rate']:.2f}%")
        
        if collisions:
            print(f"\n{'='*60}")
            print("COLLISIONS DETECTED:")
            print(f"{'='*60}")
            
            for i, (hash_value, items) in enumerate(collisions.items(), 1):
                print(f"\nCollision Group #{i}")
                print(f"Hash: {hash_value}")
                print(f"Items with identical hash ({len(items)}):")
                
                for j, item in enumerate(items, 1):
                    print(f"  {j}. Type: {item['type']}")
                    print(f"     Identifier: {item['identifier']}")
                    print(f"     Content: {item['content']}")
                    print(f"     Size: {item['size']} bytes")
                    
        elif show_all and self.hash_table:
            print(f"\n{'='*60}")
            print("ALL HASH VALUES:")
            print(f"{'='*60}")
            
            for hash_value, items in sorted(self.hash_table.items()):
                for item in items:
                    print(f"{hash_value} | {item['type']} | {item['identifier']}")
        else:
            print(f"\n✓ No hash collisions detected!")


def main():
    """
    Main function to handle command-line arguments and run the hash collision detector.
    """
    parser = argparse.ArgumentParser(
        description="Detect hash collisions using various hashing algorithms",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -a md5 -f file1.txt file2.txt
  %(prog)s -a sha256 -s "hello" "world" "hello"
  %(prog)s -a sha1 -d /path/to/directory --recursive
  %(prog)s -a all -f *.txt --show-all
        """
    )
    
    # Algorithm selection
    parser.add_argument('-a', '--algorithm', 
                       choices=HashCollisionDetector.SUPPORTED_ALGORITHMS + ['all'],
                       default='sha256',
                       help='Hashing algorithm to use (default: sha256)')
    
    # Input sources
    parser.add_argument('-f', '--files', nargs='+', metavar='FILE',
                       help='Files to hash and check for collisions')
    
    parser.add_argument('-s', '--strings', nargs='+', metavar='STRING',
                       help='Strings to hash and check for collisions')
    
    parser.add_argument('-d', '--directory', metavar='DIR',
                       help='Directory containing files to hash')
    
    parser.add_argument('--recursive', action='store_true',
                       help='Process directories recursively')
    
    # Output options
    parser.add_argument('--show-all', action='store_true',
                       help='Show all hash values, not just collisions')
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Validate that at least one input source is provided
    if not any([args.files, args.strings, args.directory]):
        parser.error("At least one input source must be specified (--files, --strings, or --directory)")
    
    # Handle 'all' algorithm option
    algorithms = HashCollisionDetector.SUPPORTED_ALGORITHMS if args.algorithm == 'all' else [args.algorithm]
    
    try:
        for algorithm in algorithms:
            if len(algorithms) > 1:
                print(f"\n{'='*20} TESTING {algorithm.upper()} {'='*20}")
            
            detector = HashCollisionDetector(algorithm)
            
            # Process strings
            if args.strings:
                if args.verbose:
                    print(f"Processing {len(args.strings)} strings...")
                for i, string in enumerate(args.strings):
                    detector.hash_string(string, f"String_{i+1}")
            
            # Process files
            if args.files:
                if args.verbose:
                    print(f"Processing {len(args.files)} files...")
                for file_path in args.files:
                    # Handle glob patterns
                    if '*' in file_path or '?' in file_path:
                        from glob import glob
                        for matched_file in glob(file_path):
                            detector.hash_file(matched_file)
                    else:
                        detector.hash_file(file_path)
            
            # Process directory
            if args.directory:
                if args.verbose:
                    print(f"Processing directory: {args.directory}")
                files_processed = detector.hash_directory(args.directory, args.recursive)
                if args.verbose:
                    print(f"Processed {files_processed} files from directory")
            
            # Display results
            detector.print_results(args.show_all)
            
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
