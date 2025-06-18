#!/usr/bin/env python3
"""
JWT Parser & Verifier

A comprehensive tool for parsing, validating, and verifying JSON Web Tokens (JWTs).
Supports various algorithms including HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512.

Usage Examples:
    # Parse a JWT without verification
    python jwt_parser.py --token "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

    # Verify a JWT with a secret key
    python jwt_parser.py --token "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." --secret "your-secret-key"

    # Verify a JWT with a public key file
    python jwt_parser.py --token "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..." --public-key public_key.pem

    # Parse JWT from file
    python jwt_parser.py --token-file token.txt --secret "your-secret-key"

Author: Assistant
License: MIT
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union, Tuple

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
    from cryptography.exceptions import InvalidSignature
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


class JWTError(Exception):
    """Base exception for JWT-related errors."""
    pass


class JWTDecodeError(JWTError):
    """Exception raised when JWT cannot be decoded."""
    pass


class JWTVerificationError(JWTError):
    """Exception raised when JWT verification fails."""
    pass


class JWTExpiredSignatureError(JWTError):
    """Exception raised when JWT signature has expired."""
    pass


class JWTParser:
    """
    A class for parsing and verifying JSON Web Tokens (JWTs).
    
    Supports HMAC-based algorithms (HS256, HS384, HS512) and RSA/ECDSA algorithms
    when cryptography library is available.
    """
    
    SUPPORTED_ALGORITHMS = {
        'HS256': hashlib.sha256,
        'HS384': hashlib.sha384,
        'HS512': hashlib.sha512,
    }
    
    def __init__(self):
        """Initialize the JWT parser."""
        if CRYPTOGRAPHY_AVAILABLE:
            self.SUPPORTED_ALGORITHMS.update({
                'RS256': 'rsa_sha256',
                'RS384': 'rsa_sha384',
                'RS512': 'rsa_sha512',
                'ES256': 'ecdsa_sha256',
                'ES384': 'ecdsa_sha384',
                'ES512': 'ecdsa_sha512',
            })
    
    @staticmethod
    def _base64url_decode(data: str) -> bytes:
        """
        Decode base64url encoded data.
        
        Args:
            data: Base64url encoded string
            
        Returns:
            Decoded bytes
            
        Raises:
            JWTDecodeError: If decoding fails
        """
        try:
            # Add padding if necessary
            missing_padding = len(data) % 4
            if missing_padding:
                data += '=' * (4 - missing_padding)
            
            return base64.urlsafe_b64decode(data.encode('utf-8'))
        except Exception as e:
            raise JWTDecodeError(f"Failed to decode base64url data: {e}")
    
    @staticmethod
    def _base64url_encode(data: bytes) -> str:
        """
        Encode data to base64url format.
        
        Args:
            data: Bytes to encode
            
        Returns:
            Base64url encoded string
        """
        return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')
    
    def parse_token(self, token: str) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
        """
        Parse a JWT token into its components without verification.
        
        Args:
            token: JWT token string
            
        Returns:
            Tuple of (header, payload, signature)
            
        Raises:
            JWTDecodeError: If token format is invalid
        """
        # Remove 'Bearer ' prefix if present
        if token.startswith('Bearer '):
            token = token[7:]
        
        # Split token into parts
        try:
            parts = token.split('.')
            if len(parts) != 3:
                raise JWTDecodeError("JWT must have three parts separated by dots")
        except Exception as e:
            raise JWTDecodeError(f"Invalid JWT format: {e}")
        
        header_data, payload_data, signature_data = parts
        
        # Decode header
        try:
            header_bytes = self._base64url_decode(header_data)
            header = json.loads(header_bytes.decode('utf-8'))
        except Exception as e:
            raise JWTDecodeError(f"Failed to decode JWT header: {e}")
        
        # Decode payload
        try:
            payload_bytes = self._base64url_decode(payload_data)
            payload = json.loads(payload_bytes.decode('utf-8'))
        except Exception as e:
            raise JWTDecodeError(f"Failed to decode JWT payload: {e}")
        
        return header, payload, signature_data
    
    def _verify_hmac_signature(self, message: bytes, signature: bytes, 
                              secret: str, algorithm: str) -> bool:
        """
        Verify HMAC signature.
        
        Args:
            message: Message that was signed
            signature: Signature to verify
            secret: Secret key
            algorithm: HMAC algorithm
            
        Returns:
            True if signature is valid
        """
        hash_func = self.SUPPORTED_ALGORITHMS[algorithm]
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            message,
            hash_func
        ).digest()
        
        return hmac.compare_digest(signature, expected_signature)
    
    def _verify_rsa_signature(self, message: bytes, signature: bytes,
                             public_key, algorithm: str) -> bool:
        """
        Verify RSA signature.
        
        Args:
            message: Message that was signed
            signature: Signature to verify
            public_key: RSA public key
            algorithm: RSA algorithm
            
        Returns:
            True if signature is valid
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            raise JWTVerificationError("cryptography library required for RSA verification")
        
        hash_algorithms = {
            'RS256': hashes.SHA256(),
            'RS384': hashes.SHA384(),
            'RS512': hashes.SHA512(),
        }
        
        try:
            public_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hash_algorithms[algorithm]
            )
            return True
        except InvalidSignature:
            return False
    
    def _verify_ecdsa_signature(self, message: bytes, signature: bytes,
                               public_key, algorithm: str) -> bool:
        """
        Verify ECDSA signature.
        
        Args:
            message: Message that was signed
            signature: Signature to verify
            public_key: ECDSA public key
            algorithm: ECDSA algorithm
            
        Returns:
            True if signature is valid
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            raise JWTVerificationError("cryptography library required for ECDSA verification")
        
        hash_algorithms = {
            'ES256': hashes.SHA256(),
            'ES384': hashes.SHA384(),
            'ES512': hashes.SHA512(),
        }
        
        try:
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hash_algorithms[algorithm])
            )
            return True
        except InvalidSignature:
            return False
    
    def verify_token(self, token: str, secret: Optional[str] = None,
                    public_key_path: Optional[str] = None,
                    verify_exp: bool = True, verify_nbf: bool = True,
                    leeway: int = 0) -> Dict[str, Any]:
        """
        Verify a JWT token and return its payload.
        
        Args:
            token: JWT token string
            secret: Secret key for HMAC algorithms
            public_key_path: Path to public key file for RSA/ECDSA algorithms
            verify_exp: Whether to verify expiration time
            verify_nbf: Whether to verify not-before time
            leeway: Allowed time drift in seconds
            
        Returns:
            Decoded payload if verification succeeds
            
        Raises:
            JWTVerificationError: If verification fails
            JWTExpiredSignatureError: If token has expired
        """
        # Parse token
        header, payload, signature_data = self.parse_token(token)
        
        # Get algorithm
        algorithm = header.get('alg')
        if not algorithm:
            raise JWTVerificationError("Missing algorithm in JWT header")
        
        if algorithm == 'none':
            if secret or public_key_path:
                raise JWTVerificationError("Cannot verify 'none' algorithm with key")
            return payload
        
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise JWTVerificationError(f"Unsupported algorithm: {algorithm}")
        
        # Prepare message for verification
        token_parts = token.split('.')
        message = f"{token_parts[0]}.{token_parts[1]}".encode('utf-8')
        
        # Decode signature
        try:
            signature = self._base64url_decode(signature_data)
        except Exception as e:
            raise JWTVerificationError(f"Failed to decode signature: {e}")
        
        # Verify signature based on algorithm type
        signature_valid = False
        
        if algorithm.startswith('HS'):
            # HMAC algorithms
            if not secret:
                raise JWTVerificationError(f"Secret key required for {algorithm}")
            signature_valid = self._verify_hmac_signature(message, signature, secret, algorithm)
        
        elif algorithm.startswith(('RS', 'ES')):
            # RSA/ECDSA algorithms
            if not public_key_path:
                raise JWTVerificationError(f"Public key required for {algorithm}")
            
            try:
                with open(public_key_path, 'rb') as key_file:
                    public_key = serialization.load_pem_public_key(key_file.read())
            except Exception as e:
                raise JWTVerificationError(f"Failed to load public key: {e}")
            
            if algorithm.startswith('RS'):
                signature_valid = self._verify_rsa_signature(message, signature, public_key, algorithm)
            else:  # ES algorithms
                signature_valid = self._verify_ecdsa_signature(message, signature, public_key, algorithm)
        
        if not signature_valid:
            raise JWTVerificationError("Invalid signature")
        
        # Verify time-based claims
        current_time = int(time.time())
        
        if verify_exp and 'exp' in payload:
            exp_time = payload['exp']
            if current_time > exp_time + leeway:
                raise JWTExpiredSignatureError("Token has expired")
        
        if verify_nbf and 'nbf' in payload:
            nbf_time = payload['nbf']
            if current_time < nbf_time - leeway:
                raise JWTVerificationError("Token not yet valid (nbf)")
        
        return payload
    
    def format_token_info(self, header: Dict[str, Any], payload: Dict[str, Any]) -> str:
        """
        Format token information for display.
        
        Args:
            header: JWT header
            payload: JWT payload
            
        Returns:
            Formatted string with token information
        """
        output = []
        output.append("=" * 50)
        output.append("JWT HEADER:")
        output.append("=" * 50)
        output.append(json.dumps(header, indent=2))
        
        output.append("\n" + "=" * 50)
        output.append("JWT PAYLOAD:")
        output.append("=" * 50)
        output.append(json.dumps(payload, indent=2))
        
        # Add human-readable time information
        if any(claim in payload for claim in ['iat', 'exp', 'nbf']):
            output.append("\n" + "=" * 50)
            output.append("TIME CLAIMS (Human Readable):")
            output.append("=" * 50)
            
            time_claims = {
                'iat': 'Issued At',
                'exp': 'Expires At',
                'nbf': 'Not Before'
            }
            
            for claim, description in time_claims.items():
                if claim in payload:
                    timestamp = payload[claim]
                    dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                    output.append(f"{description}: {dt.strftime('%Y-%m-%d %H:%M:%S UTC')} ({timestamp})")
                    
                    if claim == 'exp':
                        current_time = time.time()
                        if timestamp < current_time:
                            output.append("  ⚠️  TOKEN HAS EXPIRED")
                        else:
                            remaining = timestamp - current_time
                            if remaining < 3600:  # Less than 1 hour
                                output.append(f"  ⚠️  TOKEN EXPIRES IN {int(remaining/60)} MINUTES")
        
        return "\n".join(output)


def main():
    """Main function to handle command-line arguments and execute JWT operations."""
    parser = argparse.ArgumentParser(
        description="JWT Parser & Verifier - Parse and verify JSON Web Tokens",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Parse JWT without verification
  %(prog)s --token "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
  
  # Verify JWT with secret
  %(prog)s --token "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." --secret "your-secret"
  
  # Verify JWT with public key
  %(prog)s --token "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..." --public-key public.pem
  
  # Parse JWT from file
  %(prog)s --token-file token.txt --secret "your-secret"
  
  # Skip expiration verification
  %(prog)s --token "token..." --secret "secret" --no-verify-exp
        """
    )
    
    # Token input options
    token_group = parser.add_mutually_exclusive_group(required=True)
    token_group.add_argument(
        '--token', '-t',
        help='JWT token string'
    )
    token_group.add_argument(
        '--token-file', '-f',
        help='File containing JWT token'
    )
    
    # Verification options
    key_group = parser.add_mutually_exclusive_group()
    key_group.add_argument(
        '--secret', '-s',
        help='Secret key for HMAC algorithms (HS256, HS384, HS512)'
    )
    key_group.add_argument(
        '--public-key', '-k',
        help='Path to public key file for RSA/ECDSA algorithms'
    )
    
    # Time verification options
    parser.add_argument(
        '--no-verify-exp',
        action='store_true',
        help='Skip expiration time verification'
    )
    parser.add_argument(
        '--no-verify-nbf',
        action='store_true',
        help='Skip not-before time verification'
    )
    parser.add_argument(
        '--leeway',
        type=int,
        default=0,
        help='Allowed time drift in seconds (default: 0)'
    )
    
    # Output options
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Only output payload (useful for scripting)'
    )
    parser.add_argument(
        '--raw',
        action='store_true',
        help='Output raw JSON without formatting'
    )
    
    args = parser.parse_args()
    
    # Get token
    if args.token:
        token = args.token
    else:
        try:
            with open(args.token_file, 'r') as f:
                token = f.read().strip()
        except FileNotFoundError:
            print(f"Error: Token file '{args.token_file}' not found", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error reading token file: {e}", file=sys.stderr)
            sys.exit(1)
    
    # Initialize parser
    jwt_parser = JWTParser()
    
    try:
        # Parse token
        header, payload, signature = jwt_parser.parse_token(token)
        
        # Verify if key provided
        if args.secret or args.public_key:
            try:
                verified_payload = jwt_parser.verify_token(
                    token,
                    secret=args.secret,
                    public_key_path=args.public_key,
                    verify_exp=not args.no_verify_exp,
                    verify_nbf=not args.no_verify_nbf,
                    leeway=args.leeway
                )
                
                if not args.quiet:
                    print("✅ JWT signature verified successfully!")
                    if not args.raw:
                        print()
                
            except JWTExpiredSignatureError as e:
                print(f"❌ JWT Verification Failed: {e}", file=sys.stderr)
                if not args.quiet:
                    print("Token information (unverified):")
            except JWTVerificationError as e:
                print(f"❌ JWT Verification Failed: {e}", file=sys.stderr)
                if not args.quiet:
                    print("Token information (unverified):")
            except Exception as e:
                print(f"❌ Verification Error: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            if not args.quiet:
                print("ℹ️  Token parsed successfully (signature not verified)")
                if not args.raw:
                    print()
        
        # Output results
        if args.quiet:
            print(json.dumps(payload))
        elif args.raw:
            print("Header:", json.dumps(header))
            print("Payload:", json.dumps(payload))
        else:
            print(jwt_parser.format_token_info(header, payload))
    
    except JWTDecodeError as e:
        print(f"❌ JWT Decode Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
