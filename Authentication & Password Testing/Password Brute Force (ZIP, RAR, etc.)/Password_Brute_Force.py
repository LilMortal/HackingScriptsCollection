#!/usr/bin/env python3
"""
Password Brute Force Script

This script attempts to brute force a password by trying all combinations
of characters within a specified charset and length range until it finds the
correct password.

Usage example:
    python password_bruteforce.py --target_password secret123 --min_length 3 --max_length 8

Note: Brute forcing passwords can be very slow and is only meant for educational
or authorized penetration testing purposes. Do not use this script for illegal activities.
"""

import argparse
import itertools
import sys

def validate_args(args):
    """
    Validate command-line arguments to ensure correctness.
    """
    if args.min_length < 1:
        raise ValueError("Minimum length must be at least 1.")
    if args.max_length < args.min_length:
        raise ValueError("Maximum length must be greater than or equal to minimum length.")
    if not args.target_password:
        raise ValueError("Target password must not be empty.")
    if not args.charset:
        raise ValueError("Character set must not be empty.")

def brute_force_password(target_password, charset, min_length, max_length):
    """
    Attempt to brute force the target password by generating all possible
    strings within the given charset and length range.

    Args:
        target_password (str): The password to find.
        charset (str): Characters to use for brute forcing.
        min_length (int): Minimum length of the password to try.
        max_length (int): Maximum length of the password to try.

    Returns:
        str: The found password if successful, None otherwise.
    """
    print(f"Starting brute force attack for password: '{target_password}'")
    print(f"Charset: '{charset}'")
    print(f"Trying lengths from {min_length} to {max_length}")

    try:
        for length in range(min_length, max_length + 1):
            print(f"Trying length: {length}")
            # itertools.product generates cartesian product (all combinations)
            for attempt_tuple in itertools.product(charset, repeat=length):
                attempt = ''.join(attempt_tuple)
                if attempt == target_password:
                    print(f"\nPassword found: {attempt}")
                    return attempt
    except KeyboardInterrupt:
        print("\nBrute force attack interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred during brute force: {e}")
        sys.exit(1)

    print("\nPassword not found within given parameters.")
    return None

def main():
    """
    Main function to parse arguments and start brute forcing.
    """
    parser = argparse.ArgumentParser(
        description="Password Brute Force Script - Attempts to find the target password by brute force."
    )
    parser.add_argument(
        "--target_password", type=str, required=True,
        help="The password to brute force."
    )
    parser.add_argument(
        "--charset", type=str,
        default="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        help="Characters to use for brute forcing. Default is alphanumeric."
    )
    parser.add_argument(
        "--min_length", type=int, default=1,
        help="Minimum length of password to try. Default is 1."
    )
    parser.add_argument(
        "--max_length", type=int, default=8,
        help="Maximum length of password to try. Default is 8."
    )

    args = parser.parse_args()

    try:
        validate_args(args)
    except ValueError as ve:
        print(f"Argument error: {ve}")
        sys.exit(1)

    brute_force_password(
        target_password=args.target_password,
        charset=args.charset,
        min_length=args.min_length,
        max_length=args.max_length
    )

if __name__ == "__main__":
    main()
