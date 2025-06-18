#!/usr/bin/env python3
"""
Base64ROT13Hex Encoder & Decoder

A comprehensive encoding/decoding utility that supports Base64, ROT13, and Hexadecimal
transformations. The script can chain multiple encoding operations and reverse them
with decoding operations.

Usage Examples:
    # Encode text with Base64
    python base64rot13hex.py encode --input "Hello World" --method base64
    
    # Decode Base64 text
    python base64rot13hex.py decode --input "SGVsbG8gV29ybGQ=" --method base64
    
    # Chain multiple encodings
    python base64rot13hex.py encode --input "Secret" --method base64 --method rot13 --method hex
    
    # Process file
    python base64rot13hex.py encode --file input.txt --method base64 --output encoded.txt
    
    # Interactive mode
    python base64rot13hex.py interactive

Author: Assistant
License: MIT
Version: 1.0.0
"""

import argparse
import base64
import binascii
import sys
import os
from typing import List, Optional, Union


class EncodingError(Exception):
    """Custom exception for encoding/decoding errors."""
    pass


class Base64ROT13HexProcessor:
    """
    A class to handle Base64, ROT13, and Hexadecimal encoding/decoding operations.
    
    Supports chaining multiple encoding operations and provides methods for
    both individual transformations and batch processing.
    """
    
    @staticmethod
    def rot13_encode(text: str) -> str:
        """
        Apply ROT13 encoding to the input text.
        
        Args:
            text (str): Input text to encode
            
        Returns:
            str: ROT13 encoded text
        """
        result = []
        for char in text:
            if 'a' <= char <= 'z':
                # Rotate lowercase letters
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                # Rotate uppercase letters
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                # Keep non-alphabetic characters unchanged
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def rot13_decode(text: str) -> str:
        """
        Apply ROT13 decoding to the input text.
        Note: ROT13 is its own inverse, so this is identical to encoding.
        
        Args:
            text (str): Input text to decode
            
        Returns:
            str: ROT13 decoded text
        """
        return Base64ROT13HexProcessor.rot13_encode(text)
    
    @staticmethod
    def base64_encode(text: str) -> str:
        """
        Encode text using Base64 encoding.
        
        Args:
            text (str): Input text to encode
            
        Returns:
            str: Base64 encoded text
            
        Raises:
            EncodingError: If encoding fails
        """
        try:
            encoded_bytes = base64.b64encode(text.encode('utf-8'))
            return encoded_bytes.decode('ascii')
        except Exception as e:
            raise EncodingError(f"Base64 encoding failed: {str(e)}")
    
    @staticmethod
    def base64_decode(text: str) -> str:
        """
        Decode Base64 encoded text.
        
        Args:
            text (str): Base64 encoded text to decode
            
        Returns:
            str: Decoded text
            
        Raises:
            EncodingError: If decoding fails
        """
        try:
            decoded_bytes = base64.b64decode(text.encode('ascii'))
            return decoded_bytes.decode('utf-8')
        except Exception as e:
            raise EncodingError(f"Base64 decoding failed: {str(e)}")
    
    @staticmethod
    def hex_encode(text: str) -> str:
        """
        Encode text to hexadecimal representation.
        
        Args:
            text (str): Input text to encode
            
        Returns:
            str: Hexadecimal encoded text
            
        Raises:
            EncodingError: If encoding fails
        """
        try:
            return text.encode('utf-8').hex()
        except Exception as e:
            raise EncodingError(f"Hex encoding failed: {str(e)}")
    
    @staticmethod
    def hex_decode(text: str) -> str:
        """
        Decode hexadecimal encoded text.
        
        Args:
            text (str): Hexadecimal encoded text to decode
            
        Returns:
            str: Decoded text
            
        Raises:
            EncodingError: If decoding fails
        """
        try:
            return bytes.fromhex(text).decode('utf-8')
        except Exception as e:
            raise EncodingError(f"Hex decoding failed: {str(e)}")
    
    def encode_chain(self, text: str, methods: List[str]) -> str:
        """
        Apply multiple encoding methods in sequence.
        
        Args:
            text (str): Input text to encode
            methods (List[str]): List of encoding methods to apply in order
            
        Returns:
            str: Final encoded text after applying all methods
            
        Raises:
            EncodingError: If any encoding step fails
        """
        result = text
        
        for method in methods:
            if method.lower() == 'base64':
                result = self.base64_encode(result)
            elif method.lower() == 'rot13':
                result = self.rot13_encode(result)
            elif method.lower() == 'hex':
                result = self.hex_encode(result)
            else:
                raise EncodingError(f"Unknown encoding method: {method}")
        
        return result
    
    def decode_chain(self, text: str, methods: List[str]) -> str:
        """
        Apply multiple decoding methods in reverse sequence.
        
        Args:
            text (str): Input text to decode
            methods (List[str]): List of encoding methods to reverse (in original order)
            
        Returns:
            str: Final decoded text after reversing all methods
            
        Raises:
            EncodingError: If any decoding step fails
        """
        result = text
        
        # Reverse the order of methods for decoding
        for method in reversed(methods):
            if method.lower() == 'base64':
                result = self.base64_decode(result)
            elif method.lower() == 'rot13':
                result = self.rot13_decode(result)
            elif method.lower() == 'hex':
                result = self.hex_decode(result)
            else:
                raise EncodingError(f"Unknown decoding method: {method}")
        
        return result


def read_file(filepath: str) -> str:
    """
    Read content from a file.
    
    Args:
        filepath (str): Path to the file to read
        
    Returns:
        str: File content
        
    Raises:
        FileNotFoundError: If file doesn't exist
        IOError: If file cannot be read
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            return file.read().strip()
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {filepath}")
    except Exception as e:
        raise IOError(f"Error reading file {filepath}: {str(e)}")


def write_file(filepath: str, content: str) -> None:
    """
    Write content to a file.
    
    Args:
        filepath (str): Path to the file to write
        content (str): Content to write
        
    Raises:
        IOError: If file cannot be written
    """
    try:
        with open(filepath, 'w', encoding='utf-8') as file:
            file.write(content)
    except Exception as e:
        raise IOError(f"Error writing file {filepath}: {str(e)}")


def interactive_mode():
    """
    Run the script in interactive mode, allowing users to perform
    multiple operations without command-line arguments.
    """
    processor = Base64ROT13HexProcessor()
    
    print("=== Base64ROT13Hex Encoder & Decoder - Interactive Mode ===")
    print("Available methods: base64, rot13, hex")
    print("Type 'quit' or 'exit' to leave interactive mode.\n")
    
    while True:
        try:
            # Get operation type
            operation = input("Choose operation (encode/decode): ").strip().lower()
            if operation in ['quit', 'exit']:
                break
            
            if operation not in ['encode', 'decode']:
                print("Invalid operation. Please choose 'encode' or 'decode'.")
                continue
            
            # Get input text
            text = input("Enter text: ").strip()
            if not text:
                print("Empty input. Please enter some text.")
                continue
            
            # Get methods
            methods_input = input("Enter methods (comma-separated, e.g., base64,rot13,hex): ").strip()
            methods = [method.strip() for method in methods_input.split(',')]
            
            # Validate methods
            valid_methods = ['base64', 'rot13', 'hex']
            invalid_methods = [m for m in methods if m.lower() not in valid_methods]
            if invalid_methods:
                print(f"Invalid methods: {', '.join(invalid_methods)}")
                print(f"Valid methods: {', '.join(valid_methods)}")
                continue
            
            # Process the text
            if operation == 'encode':
                result = processor.encode_chain(text, methods)
            else:
                result = processor.decode_chain(text, methods)
            
            print(f"\nResult: {result}\n")
            
        except KeyboardInterrupt:
            print("\nExiting interactive mode...")
            break
        except Exception as e:
            print(f"Error: {str(e)}\n")


def main():
    """
    Main function to handle command-line arguments and execute the appropriate operations.
    """
    parser = argparse.ArgumentParser(
        description="Base64ROT13Hex Encoder & Decoder - A utility for encoding/decoding text using Base64, ROT13, and Hexadecimal methods.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encode with Base64
  python %(prog)s encode --input "Hello World" --method base64
  
  # Decode Base64
  python %(prog)s decode --input "SGVsbG8gV29ybGQ=" --method base64
  
  # Chain multiple encodings
  python %(prog)s encode --input "Secret" --method base64 --method rot13 --method hex
  
  # Process file
  python %(prog)s encode --file input.txt --method base64 --output encoded.txt
  
  # Interactive mode
  python %(prog)s interactive
        """
    )
    
    # Add subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Encode command
    encode_parser = subparsers.add_parser('encode', help='Encode text using specified methods')
    encode_parser.add_argument('--input', '-i', type=str, help='Input text to encode')
    encode_parser.add_argument('--file', '-f', type=str, help='Input file to read text from')
    encode_parser.add_argument('--method', '-m', action='append', choices=['base64', 'rot13', 'hex'],
                              required=True, help='Encoding method(s) to apply (can be used multiple times)')
    encode_parser.add_argument('--output', '-o', type=str, help='Output file to write result')
    
    # Decode command
    decode_parser = subparsers.add_parser('decode', help='Decode text using specified methods')
    decode_parser.add_argument('--input', '-i', type=str, help='Input text to decode')
    decode_parser.add_argument('--file', '-f', type=str, help='Input file to read text from')
    decode_parser.add_argument('--method', '-m', action='append', choices=['base64', 'rot13', 'hex'],
                              required=True, help='Decoding method(s) to reverse (can be used multiple times)')
    decode_parser.add_argument('--output', '-o', type=str, help='Output file to write result')
    
    # Interactive command
    interactive_parser = subparsers.add_parser('interactive', help='Run in interactive mode')
    
    args = parser.parse_args()
    
    # Handle interactive mode
    if args.command == 'interactive':
        interactive_mode()
        return
    
    # Validate command
    if not args.command:
        parser.print_help()
        return
    
    try:
        processor = Base64ROT13HexProcessor()
        
        # Get input text
        if args.input and args.file:
            print("Error: Cannot specify both --input and --file options.")
            sys.exit(1)
        elif args.input:
            input_text = args.input
        elif args.file:
            input_text = read_file(args.file)
        else:
            print("Error: Must specify either --input or --file option.")
            sys.exit(1)
        
        # Process the text
        if args.command == 'encode':
            result = processor.encode_chain(input_text, args.method)
        elif args.command == 'decode':
            result = processor.decode_chain(input_text, args.method)
        else:
            print(f"Error: Unknown command '{args.command}'")
            sys.exit(1)
        
        # Output the result
        if args.output:
            write_file(args.output, result)
            print(f"Result written to: {args.output}")
        else:
            print(f"Result: {result}")
    
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
