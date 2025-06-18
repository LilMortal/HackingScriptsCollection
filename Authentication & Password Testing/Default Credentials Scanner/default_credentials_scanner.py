"""
default_credentials_scanner.py - A Python script to simulate scanning for default credentials.

This script attempts to connect to a specified host and port and simulates
an attempt to log in with common default credentials or a custom wordlist.
It's designed as a framework to be extended with actual protocol-specific
authentication logic (e.g., HTTP, SSH, FTP).

Usage Example:
    python default_credentials_scanner.py --host example.com --port 22
    python default_credentials_scanner.py --host 192.168.1.1 --port 80 --wordlist common_creds.txt
    python default_credentials_scanner.py --host localhost --port 8080 --timeout 5
"""

import argparse
import socket
import sys
import os
import time

# --- Configuration Constants ---
DEFAULT_TIMEOUT = 3  # seconds for socket connection timeout
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("user", "user"),
    ("guest", "guest"),
    ("cisco", "cisco"),
    ("operator", "operator"),
    ("telecomadmin", "admintelecom"), # Common router default
    ("admin", ""), # Admin with empty password
]
# Define a placeholder message for simulated login attempts
SIMULATED_LOGIN_MESSAGE = (
    "  [SIMULATED]: Attempted login with '{}:{}'. "
    "Actual login logic would be implemented here for the specific service protocol (e.g., HTTP, SSH)."
)
SUCCESS_MESSAGE = "[SUCCESS]: Potentially found default credentials! Host: {}, Port: {}, User: {}, Pass: {}"
FAILURE_MESSAGE = "[INFO]: No default credentials found for {}:{}. All simulated attempts failed."
CONNECTION_ERROR_MESSAGE = "[ERROR]: Could not connect to {}:{}. Reason: {}"
INVALID_WORDLIST_MESSAGE = "[ERROR]: Wordlist file '{}' not found or is unreadable."
INVALID_CREDENTIAL_FORMAT_MESSAGE = "[WARNING]: Skipping malformed line in wordlist: '{}'. Expected 'username:password'."

def load_credentials(wordlist_path=None):
    """
    Loads username-password pairs from a specified wordlist file, or uses
    a hardcoded list of default credentials if no path is provided.

    Args:
        wordlist_path (str, optional): Path to a text file where each line
                                       is in the format 'username:password'.

    Returns:
        list: A list of (username, password) tuples.
    """
    if wordlist_path:
        credentials = []
        if not os.path.exists(wordlist_path):
            print(INVALID_WORDLIST_MESSAGE.format(wordlist_path), file=sys.stderr)
            return []
        try:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            credentials.append((parts[0], parts[1]))
                        else:
                            print(INVALID_CREDENTIAL_FORMAT_MESSAGE.format(line), file=sys.stderr)
                    elif line: # Non-empty but malformed line
                        print(INVALID_CREDENTIAL_FORMAT_MESSAGE.format(line), file=sys.stderr)
            if not credentials:
                print(f"[WARNING]: Wordlist '{wordlist_path}' was empty or contained no valid credentials.", file=sys.stderr)
            return credentials
        except IOError as e:
            print(INVALID_WORDLIST_MESSAGE.format(wordlist_path), file=sys.stderr)
            print(f"  Details: {e}", file=sys.stderr)
            return []
    else:
        return DEFAULT_CREDENTIALS

def scan_target(host, port, credentials, timeout):
    """
    Attempts to connect to the target host and port, then simulates login
    attempts with the provided credentials.

    Args:
        host (str): The target IP address or hostname.
        port (int): The target port number.
        credentials (list): A list of (username, password) tuples to try.
        timeout (int): Socket connection timeout in seconds.

    Returns:
        bool: True if a simulated successful login occurs (or could be extended
              to indicate actual success), False otherwise.
    """
    print(f"\n[INFO]: Scanning {host}:{port} with {len(credentials)} credential pairs...")

    try:
        # Attempt to establish a TCP connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            print(f"[INFO]: Attempting to connect to {host}:{port}...")
            sock.connect((host, port))
            print(f"[INFO]: Successfully connected to {host}:{port}. Proceeding with simulated credential attempts.")

            # Simulate credential attempts
            for username, password in credentials:
                print(SIMULATED_LOGIN_MESSAGE.format(username, password))
                # In a real scenario, this is where you'd send data
                # over `sock` according to the service's protocol
                # (e.g., send HTTP POST request, SSH handshake, etc.)
                # and parse the response to determine login success.

                # For this script, we'll assume the *first* credential
                # from the DEFAULT_CREDENTIALS list is "successful" for demonstration
                # purposes if no wordlist is provided, or we can make it
                # random for more dynamic simulation.
                # Let's make it simple for now: if a wordlist is used,
                # we just simulate trying all of them. If default,
                # let's say the first one "works" if no wordlist is given.

                # This is a placeholder for actual credential validation logic.
                # For demonstration, we'll "find" the first credential pair if it's from the default list
                # or if the wordlist is not used. In a real scenario, you would
                # have actual logic here that sets `login_successful` based on the response.
                if not args.wordlist and (username, password) == DEFAULT_CREDENTIALS[0]:
                    print(SUCCESS_MESSAGE.format(host, port, username, password))
                    return True # Simulated success

                # Add a small delay to simulate network latency or server processing
                time.sleep(0.1)

            print(FAILURE_MESSAGE.format(host, port))
            return False # All simulated attempts failed

    except socket.timeout:
        print(CONNECTION_ERROR_MESSAGE.format(host, port, "Connection timed out."), file=sys.stderr)
        return False
    except (socket.error, OSError) as e:
        print(CONNECTION_ERROR_MESSAGE.format(host, port, f"Network error - {e}"), file=sys.stderr)
        return False
    except Exception as e:
        print(f"[ERROR]: An unexpected error occurred during scan: {e}", file=sys.stderr)
        return False

def main():
    """
    Parses command-line arguments and initiates the scanning process.
    """
    parser = argparse.ArgumentParser(
        description="Simulate scanning for default credentials on a target host and port.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python default_credentials_scanner.py --host example.com --port 22
  python default_credentials_scanner.py --host 192.168.1.1 --port 80 --wordlist my_custom_creds.txt
  python default_credentials_scanner.py --host localhost --port 8080 --timeout 5

Note: This script currently *simulates* the login attempt. For real-world use,
      you would need to extend the `scan_target` function with actual protocol-specific
      authentication logic (e.g., using 'requests' for HTTP, 'paramiko' for SSH, etc.).
"""
    )
    parser.add_argument(
        '--host',
        type=str,
        required=True,
        help='The target IP address or hostname (e.g., 192.168.1.1, example.com).'
    )
    parser.add_argument(
        '--port',
        type=int,
        required=True,
        help='The target port number (e.g., 22 for SSH, 80 for HTTP, 443 for HTTPS).'
    )
    parser.add_argument(
        '--wordlist',
        type=str,
        help='Optional: Path to a file containing username:password pairs, one per line. '
             'If not provided, a hardcoded list of common default credentials will be used.'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f'Optional: Connection timeout in seconds. Default is {DEFAULT_TIMEOUT} seconds.'
    )

    global args # Make args accessible in scan_target for the simulation logic
    args = parser.parse_args()

    # Input Validation
    if not (1 <= args.port <= 65535):
        print(f"[ERROR]: Invalid port number '{args.port}'. Port must be between 1 and 65535.", file=sys.stderr)
        sys.exit(1)
    if args.timeout <= 0:
        print(f"[ERROR]: Invalid timeout '{args.timeout}'. Timeout must be a positive integer.", file=sys.stderr)
        sys.exit(1)

    # Load credentials
    credentials_to_try = load_credentials(args.wordlist)
    if not credentials_to_try and args.wordlist: # If wordlist was specified but failed to load
        sys.exit(1)
    elif not credentials_to_try and not args.wordlist: # If default list is empty (shouldn't happen but for robustness)
        print("[ERROR]: No credentials available to try. Exiting.", file=sys.stderr)
        sys.exit(1)

    # Perform the scan
    scan_target(args.host, args.port, credentials_to_try, args.timeout)

if __name__ == "__main__":
    main()
