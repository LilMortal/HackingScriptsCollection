#!/usr/bin/env python3
"""
File Integrity Checker (Hashes)

A comprehensive tool for computing and verifying file hashes to ensure file integrity.
Supports multiple hash algorithms including MD5, SHA1, SHA256, SHA512, and Blake2b.

Usage Examples:
    # Compute SHA256 hash of a single file
    python file_integrity_checker.py compute --file document.pdf --algorithm sha256
    
    # Compute hashes for all files in a directory
    python file_integrity_checker.py compute --directory /path/to/files --algorithm sha256
    
    # Save hashes to a file
    python file_integrity_checker.py compute --directory /path/to/files --output hashes.txt
    
    # Verify files against saved hashes
    python file_integrity_checker.py verify --hashfile hashes.txt
    
    # Compare two files
    python file_integrity_checker.py compare --file1 original.txt --file2 copy.txt

Author: File Integrity Checker Script
License: MIT
"""

import argparse
import hashlib
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional


class FileIntegrityChecker:
    """
    A class to handle file integrity checking operations including hash computation,
    verification, and comparison.
    """
    
    # Supported hash algorithms
    SUPPORTED_ALGORITHMS = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512,
        'blake2b': hashlib.blake2b,
        'blake2s': hashlib.blake2s
    }
    
    def __init__(self, algorithm: str = 'sha256', chunk_size: int = 65536):
        """
        Initialize the File Integrity Checker.
        
        Args:
            algorithm (str): Hash algorithm to use (default: sha256)
            chunk_size (int): Size of chunks to read from files (default: 64KB)
        """
        if algorithm.lower() not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        self.algorithm = algorithm.lower()
        self.chunk_size = chunk_size
    
    def compute_file_hash(self, file_path: str) -> str:
        """
        Compute the hash of a single file.
        
        Args:
            file_path (str): Path to the file
            
        Returns:
            str: Hexadecimal hash string
            
        Raises:
            FileNotFoundError: If the file doesn't exist
            PermissionError: If the file can't be read
            IOError: If there's an error reading the file
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not os.path.isfile(file_path):
            raise ValueError(f"Path is not a file: {file_path}")
        
        hash_obj = self.SUPPORTED_ALGORITHMS[self.algorithm]()
        
        try:
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files efficiently
                while chunk := f.read(self.chunk_size):
                    hash_obj.update(chunk)
        except PermissionError:
            raise PermissionError(f"Permission denied reading file: {file_path}")
        except IOError as e:
            raise IOError(f"Error reading file {file_path}: {e}")
        
        return hash_obj.hexdigest()
    
    def compute_directory_hashes(self, directory_path: str, recursive: bool = True) -> Dict[str, str]:
        """
        Compute hashes for all files in a directory.
        
        Args:
            directory_path (str): Path to the directory
            recursive (bool): Whether to include subdirectories
            
        Returns:
            Dict[str, str]: Dictionary mapping file paths to their hashes
        """
        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Directory not found: {directory_path}")
        
        if not os.path.isdir(directory_path):
            raise ValueError(f"Path is not a directory: {directory_path}")
        
        file_hashes = {}
        path_obj = Path(directory_path)
        
        # Use glob pattern based on recursive flag
        pattern = "**/*" if recursive else "*"
        
        for file_path in path_obj.glob(pattern):
            if file_path.is_file():
                try:
                    relative_path = str(file_path.relative_to(path_obj))
                    hash_value = self.compute_file_hash(str(file_path))
                    file_hashes[relative_path] = hash_value
                    print(f"Computed hash for: {relative_path}")
                except (PermissionError, IOError) as e:
                    print(f"Warning: Skipping {file_path}: {e}", file=sys.stderr)
                    continue
        
        return file_hashes
    
    def save_hashes_to_file(self, file_hashes: Dict[str, str], output_file: str) -> None:
        """
        Save computed hashes to a file.
        
        Args:
            file_hashes (Dict[str, str]): Dictionary of file paths and hashes
            output_file (str): Path to the output file
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                # Write header with metadata
                f.write(f"# File Integrity Hashes\n")
                f.write(f"# Algorithm: {self.algorithm.upper()}\n")
                f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Format: hash_value filename\n\n")
                
                # Write hashes in a format similar to standard hash tools
                for file_path, hash_value in sorted(file_hashes.items()):
                    f.write(f"{hash_value}  {file_path}\n")
                    
            print(f"Hashes saved to: {output_file}")
        except IOError as e:
            raise IOError(f"Error writing to file {output_file}: {e}")
    
    def load_hashes_from_file(self, hash_file: str) -> Dict[str, str]:
        """
        Load hashes from a file.
        
        Args:
            hash_file (str): Path to the hash file
            
        Returns:
            Dict[str, str]: Dictionary mapping file paths to their hashes
        """
        if not os.path.exists(hash_file):
            raise FileNotFoundError(f"Hash file not found: {hash_file}")
        
        file_hashes = {}
        
        try:
            with open(hash_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse hash and filename (format: hash  filename)
                    parts = line.split('  ', 1)
                    if len(parts) != 2:
                        print(f"Warning: Invalid format on line {line_num}: {line}", file=sys.stderr)
                        continue
                    
                    hash_value, file_path = parts
                    file_hashes[file_path] = hash_value
                    
        except IOError as e:
            raise IOError(f"Error reading hash file {hash_file}: {e}")
        
        return file_hashes
    
    def verify_files(self, hash_file: str, base_directory: str = ".") -> Tuple[List[str], List[str], List[str]]:
        """
        Verify files against stored hashes.
        
        Args:
            hash_file (str): Path to the hash file
            base_directory (str): Base directory for relative file paths
            
        Returns:
            Tuple[List[str], List[str], List[str]]: Lists of (verified, modified, missing) files
        """
        stored_hashes = self.load_hashes_from_file(hash_file)
        verified_files = []
        modified_files = []
        missing_files = []
        
        base_path = Path(base_directory)
        
        for file_path, stored_hash in stored_hashes.items():
            full_path = base_path / file_path
            
            if not full_path.exists():
                missing_files.append(file_path)
                continue
            
            try:
                current_hash = self.compute_file_hash(str(full_path))
                if current_hash == stored_hash:
                    verified_files.append(file_path)
                else:
                    modified_files.append(file_path)
            except (PermissionError, IOError) as e:
                print(f"Warning: Could not verify {file_path}: {e}", file=sys.stderr)
                continue
        
        return verified_files, modified_files, missing_files
    
    def compare_files(self, file1: str, file2: str) -> bool:
        """
        Compare two files by their hashes.
        
        Args:
            file1 (str): Path to the first file
            file2 (str): Path to the second file
            
        Returns:
            bool: True if files are identical, False otherwise
        """
        try:
            hash1 = self.compute_file_hash(file1)
            hash2 = self.compute_file_hash(file2)
            return hash1 == hash2
        except (FileNotFoundError, PermissionError, IOError) as e:
            raise e


def main():
    """Main function to handle command-line interface."""
    parser = argparse.ArgumentParser(
        description="File Integrity Checker - Compute and verify file hashes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s compute --file document.pdf --algorithm sha256
  %(prog)s compute --directory /path/to/files --output hashes.txt
  %(prog)s verify --hashfile hashes.txt
  %(prog)s compare --file1 original.txt --file2 copy.txt
        """
    )
    
    # Create subparsers for different operations
    subparsers = parser.add_subparsers(dest='operation', help='Operation to perform')
    
    # Compute command
    compute_parser = subparsers.add_parser('compute', help='Compute file hashes')
    compute_group = compute_parser.add_mutually_exclusive_group(required=True)
    compute_group.add_argument('--file', '-f', help='Single file to hash')
    compute_group.add_argument('--directory', '-d', help='Directory to hash (all files)')
    
    compute_parser.add_argument('--algorithm', '-a', default='sha256',
                               choices=list(FileIntegrityChecker.SUPPORTED_ALGORITHMS.keys()),
                               help='Hash algorithm to use (default: sha256)')
    compute_parser.add_argument('--output', '-o', help='Output file for hashes')
    compute_parser.add_argument('--recursive', '-r', action='store_true', default=True,
                               help='Include subdirectories (default: True)')
    compute_parser.add_argument('--no-recursive', action='store_false', dest='recursive',
                               help='Do not include subdirectories')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify files against stored hashes')
    verify_parser.add_argument('--hashfile', '-H', required=True,
                             help='File containing stored hashes')
    verify_parser.add_argument('--directory', '-d', default='.',
                             help='Base directory for relative paths (default: current directory)')
    verify_parser.add_argument('--algorithm', '-a', default='sha256',
                             choices=list(FileIntegrityChecker.SUPPORTED_ALGORITHMS.keys()),
                             help='Hash algorithm to use (default: sha256)')
    
    # Compare command
    compare_parser = subparsers.add_parser('compare', help='Compare two files')
    compare_parser.add_argument('--file1', required=True, help='First file to compare')
    compare_parser.add_argument('--file2', required=True, help='Second file to compare')
    compare_parser.add_argument('--algorithm', '-a', default='sha256',
                               choices=list(FileIntegrityChecker.SUPPORTED_ALGORITHMS.keys()),
                               help='Hash algorithm to use (default: sha256)')
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.operation:
        parser.print_help()
        return 1
    
    try:
        # Initialize the checker
        checker = FileIntegrityChecker(algorithm=args.algorithm)
        
        if args.operation == 'compute':
            if args.file:
                # Compute hash for single file
                hash_value = checker.compute_file_hash(args.file)
                print(f"{hash_value}  {args.file}")
                
                if args.output:
                    file_hashes = {args.file: hash_value}
                    checker.save_hashes_to_file(file_hashes, args.output)
            
            elif args.directory:
                # Compute hashes for directory
                print(f"Computing {args.algorithm.upper()} hashes for files in: {args.directory}")
                file_hashes = checker.compute_directory_hashes(args.directory, args.recursive)
                
                if not file_hashes:
                    print("No files found to hash.")
                    return 0
                
                print(f"\nComputed hashes for {len(file_hashes)} files:")
                for file_path, hash_value in sorted(file_hashes.items()):
                    print(f"{hash_value}  {file_path}")
                
                if args.output:
                    checker.save_hashes_to_file(file_hashes, args.output)
        
        elif args.operation == 'verify':
            print(f"Verifying files against hashes in: {args.hashfile}")
            verified, modified, missing = checker.verify_files(args.hashfile, args.directory)
            
            print(f"\nVerification Results:")
            print(f"  Verified: {len(verified)} files")
            print(f"  Modified: {len(modified)} files")
            print(f"  Missing:  {len(missing)} files")
            
            if modified:
                print(f"\nModified files:")
                for file_path in modified:
                    print(f"  - {file_path}")
            
            if missing:
                print(f"\nMissing files:")
                for file_path in missing:
                    print(f"  - {file_path}")
            
            # Return non-zero exit code if there are issues
            if modified or missing:
                return 1
        
        elif args.operation == 'compare':
            print(f"Comparing files using {args.algorithm.upper()}...")
            
            if checker.compare_files(args.file1, args.file2):
                print("Files are identical.")
                return 0
            else:
                print("Files are different.")
                return 1
    
    except (FileNotFoundError, PermissionError, ValueError, IOError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())