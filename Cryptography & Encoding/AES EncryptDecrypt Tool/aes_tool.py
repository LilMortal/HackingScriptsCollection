#!/usr/bin/env python3
"""
AES EncryptDecrypt Tool

A secure command-line tool for encrypting and decrypting files or text using AES-256 encryption.
This tool uses PBKDF2 for key derivation and includes proper authentication via HMAC.

Usage Examples:
    # Encrypt a file
    python aes_tool.py encrypt -i input.txt -o encrypted.bin -p mypassword

    # Decrypt a file
    python aes_tool.py decrypt -i encrypted.bin -o decrypted.txt -p mypassword

    # Encrypt text directly
    python aes_tool.py encrypt -t "Hello World" -o encrypted.bin -p mypassword

    # Decrypt and print to stdout
    python aes_tool.py decrypt -i encrypted.bin -p mypassword

Requirements:
    - Python 3.6+
    - pycryptodome library: pip install pycryptodome

Author: AES EncryptDecrypt Tool
License: MIT
"""

import argparse
import sys
import os
import getpass
import hashlib
import secrets
from typing import Optional, Tuple

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA256, HMAC
    from Crypto.Random import get_random_bytes
except ImportError:
    print("Error: pycryptodome library is required.")
    print("Please install it using: pip install pycryptodome")
    sys.exit(1)


class AESCrypto:
    """
    AES encryption/decryption class with authenticated encryption.
    
    Uses AES-256 in GCM mode for encryption with PBKDF2 key derivation.
    Includes HMAC for additional authentication and integrity checking.
    """
    
    # Constants for encryption parameters
    SALT_SIZE = 32          # Size of salt for PBKDF2
    IV_SIZE = 16            # Size of initialization vector
    TAG_SIZE = 16           # Size of GCM authentication tag
    HMAC_SIZE = 32          # Size of HMAC digest
    KEY_SIZE = 32           # Size of AES key (256 bits)
    PBKDF2_ITERATIONS = 100000  # Number of PBKDF2 iterations
    
    def __init__(self):
        """Initialize the AESCrypto instance."""
        pass
    
    def _derive_keys(self, password: str, salt: bytes) -> Tuple[bytes, bytes]:
        """
        Derive encryption and HMAC keys from password using PBKDF2.
        
        Args:
            password (str): The password to derive keys from
            salt (bytes): Salt for key derivation
            
        Returns:
            Tuple[bytes, bytes]: (encryption_key, hmac_key)
        """
        # Derive a master key using PBKDF2
        master_key = PBKDF2(
            password, 
            salt, 
            dkLen=self.KEY_SIZE * 2,  # Double size for two keys
            count=self.PBKDF2_ITERATIONS,
            hmac_hash_module=SHA256
        )
        
        # Split the master key into encryption and HMAC keys
        encryption_key = master_key[:self.KEY_SIZE]
        hmac_key = master_key[self.KEY_SIZE:]
        
        return encryption_key, hmac_key
    
    def encrypt(self, data: bytes, password: str) -> bytes:
        """
        Encrypt data using AES-256-GCM with password-based key derivation.
        
        Args:
            data (bytes): The data to encrypt
            password (str): The password for encryption
            
        Returns:
            bytes: Encrypted data with salt, IV, tag, and HMAC
            
        Format: salt(32) + iv(16) + tag(16) + encrypted_data + hmac(32)
        """
        # Generate random salt and IV
        salt = get_random_bytes(self.SALT_SIZE)
        iv = get_random_bytes(self.IV_SIZE)
        
        # Derive keys from password
        encryption_key, hmac_key = self._derive_keys(password, salt)
        
        # Create AES cipher in GCM mode
        cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=iv)
        
        # Encrypt the data
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        # Combine all components
        encrypted_package = salt + iv + tag + ciphertext
        
        # Generate HMAC for integrity verification
        hmac_obj = HMAC.new(hmac_key, digestmod=SHA256)
        hmac_obj.update(encrypted_package)
        hmac_digest = hmac_obj.digest()
        
        # Return the complete encrypted package
        return encrypted_package + hmac_digest
    
    def decrypt(self, encrypted_data: bytes, password: str) -> bytes:
        """
        Decrypt data that was encrypted with the encrypt method.
        
        Args:
            encrypted_data (bytes): The encrypted data package
            password (str): The password for decryption
            
        Returns:
            bytes: The decrypted data
            
        Raises:
            ValueError: If decryption fails or data is corrupted
        """
        # Validate minimum size
        min_size = self.SALT_SIZE + self.IV_SIZE + self.TAG_SIZE + self.HMAC_SIZE
        if len(encrypted_data) < min_size:
            raise ValueError("Encrypted data is too short to be valid")
        
        # Extract HMAC from the end
        hmac_digest = encrypted_data[-self.HMAC_SIZE:]
        encrypted_package = encrypted_data[:-self.HMAC_SIZE]
        
        # Extract components from the encrypted package
        salt = encrypted_package[:self.SALT_SIZE]
        iv = encrypted_package[self.SALT_SIZE:self.SALT_SIZE + self.IV_SIZE]
        tag = encrypted_package[self.SALT_SIZE + self.IV_SIZE:self.SALT_SIZE + self.IV_SIZE + self.TAG_SIZE]
        ciphertext = encrypted_package[self.SALT_SIZE + self.IV_SIZE + self.TAG_SIZE:]
        
        # Derive keys from password
        encryption_key, hmac_key = self._derive_keys(password, salt)
        
        # Verify HMAC
        hmac_obj = HMAC.new(hmac_key, digestmod=SHA256)
        hmac_obj.update(encrypted_package)
        try:
            hmac_obj.verify(hmac_digest)
        except ValueError:
            raise ValueError("HMAC verification failed - data may be corrupted or password incorrect")
        
        # Create AES cipher and decrypt
        cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=iv)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise ValueError("Decryption failed - password may be incorrect or data corrupted")
        
        return plaintext


def secure_file_write(filepath: str, data: bytes) -> None:
    """
    Securely write data to a file with proper error handling.
    
    Args:
        filepath (str): Path to the output file
        data (bytes): Data to write
        
    Raises:
        IOError: If file writing fails
    """
    try:
        with open(filepath, 'wb') as f:
            f.write(data)
    except IOError as e:
        raise IOError(f"Failed to write to file '{filepath}': {e}")


def secure_file_read(filepath: str) -> bytes:
    """
    Securely read data from a file with proper error handling.
    
    Args:
        filepath (str): Path to the input file
        
    Returns:
        bytes: File contents
        
    Raises:
        IOError: If file reading fails
    """
    try:
        with open(filepath, 'rb') as f:
            return f.read()
    except IOError as e:
        raise IOError(f"Failed to read file '{filepath}': {e}")


def get_password_securely(prompt: str = "Enter password: ") -> str:
    """
    Get password securely without echoing to terminal.
    
    Args:
        prompt (str): Prompt message for password input
        
    Returns:
        str: The entered password
    """
    try:
        password = getpass.getpass(prompt)
        if not password:
            raise ValueError("Password cannot be empty")
        return password
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)


def validate_file_path(filepath: str, must_exist: bool = True) -> None:
    """
    Validate file path and permissions.
    
    Args:
        filepath (str): Path to validate
        must_exist (bool): Whether the file must already exist
        
    Raises:
        FileNotFoundError: If file must exist but doesn't
        PermissionError: If insufficient permissions
    """
    if must_exist:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Input file '{filepath}' does not exist")
        if not os.access(filepath, os.R_OK):
            raise PermissionError(f"No read permission for file '{filepath}'")
    else:
        # Check write permission for output file directory
        directory = os.path.dirname(os.path.abspath(filepath))
        if not os.access(directory, os.W_OK):
            raise PermissionError(f"No write permission for directory '{directory}'")


def encrypt_command(args) -> None:
    """
    Handle the encrypt command.
    
    Args:
        args: Parsed command line arguments
    """
    crypto = AESCrypto()
    
    try:
        # Get input data
        if args.text:
            data = args.text.encode('utf-8')
            print("Encrypting provided text...")
        elif args.input:
            validate_file_path(args.input, must_exist=True)
            data = secure_file_read(args.input)
            print(f"Encrypting file: {args.input}")
        else:
            # Read from stdin
            print("Reading data from stdin... (Press Ctrl+D when finished)")
            data = sys.stdin.buffer.read()
            if not data:
                raise ValueError("No input data provided")
        
        # Get password
        if args.password:
            password = args.password
            print("Warning: Using password from command line is insecure!")
        else:
            password = get_password_securely("Enter encryption password: ")
        
        # Encrypt data
        encrypted_data = crypto.encrypt(data, password)
        
        # Output encrypted data
        if args.output:
            validate_file_path(args.output, must_exist=False)
            secure_file_write(args.output, encrypted_data)
            print(f"Encryption complete. Output saved to: {args.output}")
        else:
            # Output to stdout (base64 encoded for readability)
            import base64
            encoded_data = base64.b64encode(encrypted_data).decode('ascii')
            print("Encrypted data (base64):")
            print(encoded_data)
    
    except Exception as e:
        print(f"Encryption failed: {e}", file=sys.stderr)
        sys.exit(1)


def decrypt_command(args) -> None:
    """
    Handle the decrypt command.
    
    Args:
        args: Parsed command line arguments
    """
    crypto = AESCrypto()
    
    try:
        # Get input data
        if args.input:
            validate_file_path(args.input, must_exist=True)
            encrypted_data = secure_file_read(args.input)
            print(f"Decrypting file: {args.input}")
        else:
            # Read from stdin (assume base64 encoded)
            print("Reading encrypted data from stdin...")
            import base64
            stdin_data = sys.stdin.read().strip()
            try:
                encrypted_data = base64.b64decode(stdin_data)
            except Exception:
                raise ValueError("Invalid base64 input from stdin")
        
        # Get password
        if args.password:
            password = args.password
            print("Warning: Using password from command line is insecure!")
        else:
            password = get_password_securely("Enter decryption password: ")
        
        # Decrypt data
        decrypted_data = crypto.decrypt(encrypted_data, password)
        
        # Output decrypted data
        if args.output:
            validate_file_path(args.output, must_exist=False)
            secure_file_write(args.output, decrypted_data)
            print(f"Decryption complete. Output saved to: {args.output}")
        else:
            # Output to stdout
            try:
                # Try to decode as text
                text_output = decrypted_data.decode('utf-8')
                print("Decrypted text:")
                print(text_output)
            except UnicodeDecodeError:
                print("Decrypted data contains binary content, cannot display as text.")
                print("Use -o option to save to a file.")
    
    except Exception as e:
        print(f"Decryption failed: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """Main function to handle command line arguments and dispatch commands."""
    parser = argparse.ArgumentParser(
        description='AES EncryptDecrypt Tool - Secure file and text encryption/decryption',
        epilog="""
Examples:
  %(prog)s encrypt -i document.txt -o document.enc
  %(prog)s decrypt -i document.enc -o document.txt
  %(prog)s encrypt -t "Secret message" -o message.enc
  %(prog)s decrypt -i message.enc
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Add subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    subparsers.required = True
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt data')
    encrypt_group = encrypt_parser.add_mutually_exclusive_group(required=True)
    encrypt_group.add_argument('-i', '--input', help='Input file to encrypt')
    encrypt_group.add_argument('-t', '--text', help='Text string to encrypt')
    encrypt_parser.add_argument('-o', '--output', help='Output file for encrypted data')
    encrypt_parser.add_argument('-p', '--password', help='Encryption password (insecure, use with caution)')
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt data')
    decrypt_parser.add_argument('-i', '--input', help='Input file to decrypt')
    decrypt_parser.add_argument('-o', '--output', help='Output file for decrypted data')
    decrypt_parser.add_argument('-p', '--password', help='Decryption password (insecure, use with caution)')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Dispatch to appropriate command handler
    if args.command == 'encrypt':
        encrypt_command(args)
    elif args.command == 'decrypt':
        decrypt_command(args)


if __name__ == '__main__':
    main()
