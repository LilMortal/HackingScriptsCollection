#!/usr/bin/env python3
"""
Caesar Cipher Cracker

A comprehensive tool for cracking Caesar cipher encrypted text using multiple methods:
1. Brute force attack (tries all possible shifts 0-25)
2. Frequency analysis (analyzes letter frequency to find most likely shift)
3. Interactive mode for manual shift testing

Usage Examples:
    python caesar_cipher_cracker.py -t "KHOOR ZRUOG" -m brute
    python caesar_cipher_cracker.py -f encrypted.txt -m frequency
    python caesar_cipher_cracker.py -t "ENCRYPTED TEXT" -m interactive
    python caesar_cipher_cracker.py -t "KHOOR ZRUOG" -s 3

Author: Caesar Cipher Cracker Tool
License: MIT
"""

import argparse
import sys
import os
from collections import Counter
from typing import List, Tuple, Dict, Optional


class CaesarCipherCracker:
    """
    A class to crack Caesar cipher encrypted text using various methods.
    """
    
    # English letter frequency (approximate percentages)
    ENGLISH_FREQ = {
        'A': 8.12, 'B': 1.49, 'C': 2.78, 'D': 4.25, 'E': 12.02, 'F': 2.23,
        'G': 2.02, 'H': 6.09, 'I': 6.97, 'J': 0.15, 'K': 0.77, 'L': 4.03,
        'M': 2.41, 'N': 6.75, 'O': 7.51, 'P': 1.93, 'Q': 0.10, 'R': 5.99,
        'S': 6.33, 'T': 9.06, 'U': 2.76, 'V': 0.98, 'W': 2.36, 'X': 0.15,
        'Y': 1.97, 'Z': 0.07
    }
    
    def __init__(self):
        """Initialize the Caesar Cipher Cracker."""
        pass
    
    def decrypt_with_shift(self, text: str, shift: int) -> str:
        """
        Decrypt text using a specific Caesar cipher shift.
        
        Args:
            text (str): The encrypted text to decrypt
            shift (int): The shift value to use for decryption
            
        Returns:
            str: The decrypted text
        """
        result = []
        
        for char in text:
            if char.isalpha():
                # Determine if uppercase or lowercase
                is_upper = char.isupper()
                char = char.upper()
                
                # Apply reverse Caesar shift
                shifted_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                
                # Restore original case
                if not is_upper:
                    shifted_char = shifted_char.lower()
                    
                result.append(shifted_char)
            else:
                # Keep non-alphabetic characters unchanged
                result.append(char)
        
        return ''.join(result)
    
    def brute_force_crack(self, text: str) -> List[Tuple[int, str]]:
        """
        Perform brute force attack by trying all possible shifts (0-25).
        
        Args:
            text (str): The encrypted text to crack
            
        Returns:
            List[Tuple[int, str]]: List of tuples containing (shift, decrypted_text)
        """
        results = []
        
        print("Brute Force Analysis:")
        print("=" * 50)
        
        for shift in range(26):
            decrypted = self.decrypt_with_shift(text, shift)
            results.append((shift, decrypted))
            print(f"Shift {shift:2d}: {decrypted}")
        
        return results
    
    def calculate_chi_squared(self, text: str) -> float:
        """
        Calculate chi-squared statistic for text against English letter frequency.
        Lower values indicate text more similar to English.
        
        Args:
            text (str): Text to analyze
            
        Returns:
            float: Chi-squared statistic
        """
        # Count letter frequencies in the text
        letter_count = Counter()
        total_letters = 0
        
        for char in text.upper():
            if char.isalpha():
                letter_count[char] += 1
                total_letters += 1
        
        if total_letters == 0:
            return float('inf')
        
        # Calculate chi-squared statistic
        chi_squared = 0.0
        
        for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            observed = letter_count.get(letter, 0)
            expected = (self.ENGLISH_FREQ[letter] / 100.0) * total_letters
            
            if expected > 0:
                chi_squared += ((observed - expected) ** 2) / expected
        
        return chi_squared
    
    def frequency_analysis_crack(self, text: str) -> List[Tuple[int, str, float]]:
        """
        Crack cipher using frequency analysis based on English letter frequency.
        
        Args:
            text (str): The encrypted text to crack
            
        Returns:
            List[Tuple[int, str, float]]: List of tuples containing 
                                        (shift, decrypted_text, chi_squared_score)
                                        sorted by likelihood (lower chi-squared is better)
        """
        results = []
        
        for shift in range(26):
            decrypted = self.decrypt_with_shift(text, shift)
            chi_squared = self.calculate_chi_squared(decrypted)
            results.append((shift, decrypted, chi_squared))
        
        # Sort by chi-squared score (lower is better)
        results.sort(key=lambda x: x[2])
        
        print("Frequency Analysis Results (sorted by likelihood):")
        print("=" * 60)
        print(f"{'Rank':<4} {'Shift':<5} {'Chi²':<8} {'Decrypted Text'}")
        print("-" * 60)
        
        for i, (shift, decrypted, chi_squared) in enumerate(results[:10]):  # Show top 10
            print(f"{i+1:<4} {shift:<5} {chi_squared:<8.2f} {decrypted}")
        
        return results
    
    def interactive_mode(self, text: str) -> None:
        """
        Interactive mode allowing user to test different shifts manually.
        
        Args:
            text (str): The encrypted text to work with
        """
        print("Interactive Mode - Caesar Cipher Cracker")
        print("=" * 40)
        print(f"Original text: {text}")
        print("\nEnter shift values to test (0-25), or 'q' to quit:")
        
        while True:
            try:
                user_input = input("\nEnter shift value: ").strip().lower()
                
                if user_input == 'q' or user_input == 'quit':
                    print("Exiting interactive mode.")
                    break
                
                shift = int(user_input)
                
                if 0 <= shift <= 25:
                    decrypted = self.decrypt_with_shift(text, shift)
                    print(f"Shift {shift}: {decrypted}")
                else:
                    print("Please enter a shift value between 0 and 25.")
                    
            except ValueError:
                print("Invalid input. Please enter a number or 'q' to quit.")
            except KeyboardInterrupt:
                print("\nExiting interactive mode.")
                break


def read_file(filepath: str) -> str:
    """
    Read text from a file with error handling.
    
    Args:
        filepath (str): Path to the file to read
        
    Returns:
        str: Content of the file
        
    Raises:
        FileNotFoundError: If file doesn't exist
        IOError: If file cannot be read
    """
    try:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        
        with open(filepath, 'r', encoding='utf-8') as file:
            content = file.read().strip()
            
        if not content:
            raise ValueError(f"File is empty: {filepath}")
            
        return content
        
    except Exception as e:
        raise IOError(f"Error reading file {filepath}: {str(e)}")


def validate_input(text: str) -> str:
    """
    Validate and clean input text.
    
    Args:
        text (str): Input text to validate
        
    Returns:
        str: Cleaned text
        
    Raises:
        ValueError: If text is empty or contains no letters
    """
    if not text or not text.strip():
        raise ValueError("Input text cannot be empty")
    
    # Check if text contains at least some letters
    if not any(c.isalpha() for c in text):
        raise ValueError("Input text must contain at least some letters")
    
    return text.strip()


def main():
    """Main function to handle command line arguments and execute the cracker."""
    parser = argparse.ArgumentParser(
        description="Caesar Cipher Cracker - Decrypt Caesar cipher encrypted text",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t "KHOOR ZRUOG" -m brute
  %(prog)s -f encrypted.txt -m frequency
  %(prog)s -t "ENCRYPTED TEXT" -m interactive
  %(prog)s -t "KHOOR ZRUOG" -s 3
        """
    )
    
    # Input source (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '-t', '--text',
        type=str,
        help='Encrypted text to crack (use quotes for text with spaces)'
    )
    input_group.add_argument(
        '-f', '--file',
        type=str,
        help='Path to file containing encrypted text'
    )
    
    # Method selection
    parser.add_argument(
        '-m', '--method',
        choices=['brute', 'frequency', 'interactive'],
        default='frequency',
        help='Cracking method to use (default: frequency)'
    )
    
    # Specific shift (optional)
    parser.add_argument(
        '-s', '--shift',
        type=int,
        help='Decrypt using a specific shift value (0-25)'
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    try:
        # Get input text
        if args.text:
            text = validate_input(args.text)
        else:  # args.file
            text = validate_input(read_file(args.file))
        
        # Initialize cracker
        cracker = CaesarCipherCracker()
        
        print(f"Input text: {text}")
        print()
        
        # Handle specific shift
        if args.shift is not None:
            if 0 <= args.shift <= 25:
                decrypted = cracker.decrypt_with_shift(text, args.shift)
                print(f"Decrypted with shift {args.shift}: {decrypted}")
            else:
                print("Error: Shift value must be between 0 and 25")
                sys.exit(1)
            return
        
        # Execute chosen method
        if args.method == 'brute':
            cracker.brute_force_crack(text)
            
        elif args.method == 'frequency':
            results = cracker.frequency_analysis_crack(text)
            if results:
                print(f"\nMost likely decryption (shift {results[0][0]}): {results[0][1]}")
                
        elif args.method == 'interactive':
            cracker.interactive_mode(text)
    
    except (ValueError, IOError, FileNotFoundError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()