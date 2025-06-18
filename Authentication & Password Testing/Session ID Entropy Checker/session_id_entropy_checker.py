#!/usr/bin/env python3
"""
Session ID Entropy Checker

A comprehensive tool for analyzing the entropy and security characteristics of session identifiers.
This script helps security professionals and developers assess whether their session IDs provide
adequate randomness and security against prediction attacks.

Author: Claude (Anthropic)
License: MIT
Version: 1.0.0

Usage Examples:
    # Analyze a single session ID
    python session_entropy_checker.py --session-id "abc123def456ghi789"
    
    # Analyze multiple session IDs from a file
    python session_entropy_checker.py --file session_ids.txt
    
    # Generate and analyze test session IDs
    python session_entropy_checker.py --generate 100 --length 32
    
    # Set custom entropy thresholds
    python session_entropy_checker.py --file sessions.txt --min-entropy 4.0 --min-length 16
"""

import argparse
import sys
import os
import math
import re
import secrets
import string
from collections import Counter, defaultdict
from typing import List, Dict, Tuple, Optional
import json


class SessionIDAnalyzer:
    """
    A class to analyze session ID entropy and security characteristics.
    """
    
    def __init__(self, min_entropy: float = 3.5, min_length: int = 16):
        """
        Initialize the analyzer with security thresholds.
        
        Args:
            min_entropy (float): Minimum acceptable entropy per character
            min_length (int): Minimum acceptable session ID length
        """
        self.min_entropy = min_entropy
        self.min_length = min_length
        
        # Character sets for analysis
        self.char_sets = {
            'lowercase': set(string.ascii_lowercase),
            'uppercase': set(string.ascii_uppercase),
            'digits': set(string.digits),
            'special': set('!@#$%^&*()-_=+[]{}|;:,.<>?/~`'),
            'hex': set('0123456789abcdefABCDEF'),
            'base64': set(string.ascii_letters + string.digits + '+/=')
        }
    
    def calculate_shannon_entropy(self, session_id: str) -> float:
        """
        Calculate Shannon entropy of a session ID.
        
        Args:
            session_id (str): The session ID to analyze
            
        Returns:
            float: Shannon entropy value
        """
        if not session_id:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(session_id)
        length = len(session_id)
        
        # Calculate Shannon entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_character_distribution(self, session_id: str) -> Dict:
        """
        Analyze the character distribution and patterns in a session ID.
        
        Args:
            session_id (str): The session ID to analyze
            
        Returns:
            Dict: Analysis results including character sets used, patterns, etc.
        """
        analysis = {
            'length': len(session_id),
            'unique_chars': len(set(session_id)),
            'char_sets_used': [],
            'repetition_score': 0.0,
            'pattern_detected': False,
            'sequential_chars': 0,
            'encoding_guess': 'unknown'
        }
        
        if not session_id:
            return analysis
        
        chars = set(session_id)
        
        # Identify character sets used
        for set_name, char_set in self.char_sets.items():
            if chars.issubset(char_set):
                analysis['char_sets_used'].append(set_name)
        
        # If no specific set matches, identify general categories
        if not analysis['char_sets_used']:
            if chars.issubset(self.char_sets['lowercase'] | self.char_sets['digits']):
                analysis['char_sets_used'].append('lowercase_digits')
            elif chars.issubset(self.char_sets['uppercase'] | self.char_sets['digits']):
                analysis['char_sets_used'].append('uppercase_digits')
            elif chars.issubset(self.char_sets['lowercase'] | self.char_sets['uppercase'] | self.char_sets['digits']):
                analysis['char_sets_used'].append('alphanumeric')
        
        # Guess encoding
        if chars.issubset(self.char_sets['hex']):
            analysis['encoding_guess'] = 'hexadecimal'
        elif chars.issubset(self.char_sets['base64']):
            analysis['encoding_guess'] = 'base64'
        elif chars.issubset(self.char_sets['digits']):
            analysis['encoding_guess'] = 'numeric'
        
        # Check for repetition patterns
        char_counts = Counter(session_id)
        max_count = max(char_counts.values()) if char_counts else 0
        analysis['repetition_score'] = max_count / len(session_id) if session_id else 0
        
        # Check for sequential characters
        sequential_count = 0
        for i in range(len(session_id) - 1):
            if ord(session_id[i + 1]) == ord(session_id[i]) + 1:
                sequential_count += 1
        analysis['sequential_chars'] = sequential_count
        
        # Simple pattern detection
        patterns = [
            r'(.)\1{2,}',  # Repeated characters
            r'(.)(.)\1\2',  # ABAB pattern
            r'123|abc|ABC',  # Sequential patterns
            r'000|111|aaa|AAA'  # Obvious weak patterns
        ]
        
        for pattern in patterns:
            if re.search(pattern, session_id):
                analysis['pattern_detected'] = True
                break
        
        return analysis
    
    def assess_security_level(self, session_id: str) -> Dict:
        """
        Assess the overall security level of a session ID.
        
        Args:
            session_id (str): The session ID to assess
            
        Returns:
            Dict: Security assessment including score and recommendations
        """
        entropy = self.calculate_shannon_entropy(session_id)
        char_analysis = self.analyze_character_distribution(session_id)
        
        # Calculate security score (0-100)
        score = 0
        issues = []
        recommendations = []
        
        # Length check (0-25 points)
        if char_analysis['length'] >= 32:
            score += 25
        elif char_analysis['length'] >= self.min_length:
            score += 15
        elif char_analysis['length'] >= 8:
            score += 10
        else:
            issues.append(f"Session ID too short ({char_analysis['length']} chars)")
            recommendations.append(f"Use at least {self.min_length} characters")
        
        # Entropy check (0-30 points)
        if entropy >= 4.5:
            score += 30
        elif entropy >= self.min_entropy:
            score += 20
        elif entropy >= 2.0:
            score += 10
        else:
            issues.append(f"Low entropy ({entropy:.2f} bits per char)")
            recommendations.append(f"Increase randomness (target: >{self.min_entropy} bits per char)")
        
        # Character diversity (0-20 points)
        if char_analysis['unique_chars'] / char_analysis['length'] >= 0.8:
            score += 20
        elif char_analysis['unique_chars'] / char_analysis['length'] >= 0.6:
            score += 15
        elif char_analysis['unique_chars'] / char_analysis['length'] >= 0.4:
            score += 10
        else:
            issues.append("Low character diversity")
            recommendations.append("Use more diverse character sets")
        
        # Pattern detection (0-15 points)
        if not char_analysis['pattern_detected'] and char_analysis['repetition_score'] < 0.3:
            score += 15
        elif char_analysis['repetition_score'] < 0.5:
            score += 10
        else:
            issues.append("Patterns or excessive repetition detected")
            recommendations.append("Avoid predictable patterns")
        
        # Character set usage (0-10 points)
        if len(char_analysis['char_sets_used']) >= 2 or 'base64' in char_analysis['char_sets_used']:
            score += 10
        elif char_analysis['char_sets_used']:
            score += 5
        else:
            issues.append("Limited character set usage")
            recommendations.append("Use mixed character sets (letters, numbers, symbols)")
        
        # Determine security level
        if score >= 80:
            level = "STRONG"
        elif score >= 60:
            level = "MODERATE"
        elif score >= 40:
            level = "WEAK"
        else:
            level = "VERY WEAK"
        
        return {
            'security_level': level,
            'score': score,
            'issues': issues,
            'recommendations': recommendations
        }
    
    def analyze_session_id(self, session_id: str) -> Dict:
        """
        Perform complete analysis of a session ID.
        
        Args:
            session_id (str): The session ID to analyze
            
        Returns:
            Dict: Complete analysis results
        """
        if not session_id or not isinstance(session_id, str):
            return {
                'error': 'Invalid session ID provided',
                'session_id': session_id
            }
        
        entropy = self.calculate_shannon_entropy(session_id)
        char_analysis = self.analyze_character_distribution(session_id)
        security_assessment = self.assess_security_level(session_id)
        
        return {
            'session_id': session_id,
            'entropy': entropy,
            'character_analysis': char_analysis,
            'security_assessment': security_assessment,
            'meets_minimum_requirements': (
                entropy >= self.min_entropy and 
                char_analysis['length'] >= self.min_length and
                not char_analysis['pattern_detected']
            )
        }
    
    def generate_secure_session_id(self, length: int = 32, use_base64: bool = True) -> str:
        """
        Generate a cryptographically secure session ID for comparison.
        
        Args:
            length (int): Desired length of the session ID
            use_base64 (bool): Whether to use base64 encoding
            
        Returns:
            str: A secure session ID
        """
        if use_base64:
            # Generate random bytes and base64 encode
            random_bytes = secrets.token_bytes(length * 3 // 4)
            session_id = secrets.token_urlsafe(len(random_bytes))[:length]
        else:
            # Generate using alphanumeric characters
            alphabet = string.ascii_letters + string.digits
            session_id = ''.join(secrets.choice(alphabet) for _ in range(length))
        
        return session_id


def load_session_ids_from_file(filepath: str) -> List[str]:
    """
    Load session IDs from a text file (one per line).
    
    Args:
        filepath (str): Path to the file containing session IDs
        
    Returns:
        List[str]: List of session IDs
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        IOError: If there's an error reading the file
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    
    session_ids = []
    with open(filepath, 'r', encoding='utf-8') as file:
        for line_num, line in enumerate(file, 1):
            line = line.strip()
            if line and not line.startswith('#'):  # Skip empty lines and comments
                session_ids.append(line)
    
    if not session_ids:
        raise ValueError(f"No valid session IDs found in {filepath}")
    
    return session_ids


def print_analysis_results(results: List[Dict], verbose: bool = False):
    """
    Print analysis results in a formatted manner.
    
    Args:
        results (List[Dict]): List of analysis results
        verbose (bool): Whether to print detailed information
    """
    print("\n" + "="*60)
    print("SESSION ID ENTROPY ANALYSIS RESULTS")
    print("="*60)
    
    total_analyzed = len(results)
    strong_count = sum(1 for r in results if r.get('security_assessment', {}).get('security_level') == 'STRONG')
    moderate_count = sum(1 for r in results if r.get('security_assessment', {}).get('security_level') == 'MODERATE')
    weak_count = sum(1 for r in results if r.get('security_assessment', {}).get('security_level') in ['WEAK', 'VERY WEAK'])
    
    print(f"\nSUMMARY:")
    print(f"Total Session IDs Analyzed: {total_analyzed}")
    print(f"Strong Security: {strong_count} ({strong_count/total_analyzed*100:.1f}%)")
    print(f"Moderate Security: {moderate_count} ({moderate_count/total_analyzed*100:.1f}%)")
    print(f"Weak Security: {weak_count} ({weak_count/total_analyzed*100:.1f}%)")
    
    if verbose:
        print(f"\nDETAILED RESULTS:")
        print("-" * 60)
        
        for i, result in enumerate(results, 1):
            if 'error' in result:
                print(f"\n{i}. ERROR: {result['error']}")
                continue
                
            session_id = result['session_id']
            entropy = result['entropy']
            char_analysis = result['character_analysis']
            security = result['security_assessment']
            
            # Truncate very long session IDs for display
            display_id = session_id if len(session_id) <= 50 else session_id[:47] + "..."
            
            print(f"\n{i}. Session ID: {display_id}")
            print(f"   Security Level: {security['security_level']} (Score: {security['score']}/100)")
            print(f"   Entropy: {entropy:.2f} bits per character")
            print(f"   Length: {char_analysis['length']} characters")
            print(f"   Unique Characters: {char_analysis['unique_chars']}")
            print(f"   Character Sets: {', '.join(char_analysis['char_sets_used']) or 'Unknown'}")
            print(f"   Encoding Guess: {char_analysis['encoding_guess']}")
            
            if security['issues']:
                print(f"   Issues: {'; '.join(security['issues'])}")
            
            if security['recommendations']:
                print(f"   Recommendations: {'; '.join(security['recommendations'])}")
    else:
        # Show only weak/problematic session IDs
        weak_results = [r for r in results if r.get('security_assessment', {}).get('security_level') in ['WEAK', 'VERY WEAK']]
        
        if weak_results:
            print(f"\nWEAK SESSION IDs FOUND ({len(weak_results)}):")
            print("-" * 40)
            
            for result in weak_results[:10]:  # Show first 10 weak ones
                if 'error' in result:
                    continue
                    
                session_id = result['session_id']
                security = result['security_assessment']
                
                display_id = session_id if len(session_id) <= 30 else session_id[:27] + "..."
                print(f"• {display_id} - {security['security_level']} ({security['score']}/100)")
                if security['issues']:
                    print(f"  Issues: {'; '.join(security['issues'][:2])}")  # Show first 2 issues
            
            if len(weak_results) > 10:
                print(f"  ... and {len(weak_results) - 10} more weak session IDs")


def main():
    """
    Main function to handle command-line arguments and execute the analysis.
    """
    parser = argparse.ArgumentParser(
        description="Analyze session ID entropy and security characteristics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --session-id "abc123def456"
  %(prog)s --file session_ids.txt --verbose
  %(prog)s --generate 50 --length 24
  %(prog)s --file sessions.txt --min-entropy 4.0 --output results.json
        """
    )
    
    # Input options (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--session-id', '-s',
        type=str,
        help='Single session ID to analyze'
    )
    input_group.add_argument(
        '--file', '-f',
        type=str,
        help='File containing session IDs (one per line)'
    )
    input_group.add_argument(
        '--generate', '-g',
        type=int,
        metavar='COUNT',
        help='Generate and analyze COUNT secure session IDs for comparison'
    )
    
    # Analysis options
    parser.add_argument(
        '--min-entropy',
        type=float,
        default=3.5,
        help='Minimum acceptable entropy per character (default: 3.5)'
    )
    parser.add_argument(
        '--min-length',
        type=int,
        default=16,
        help='Minimum acceptable session ID length (default: 16)'
    )
    parser.add_argument(
        '--length',
        type=int,
        default=32,
        help='Length for generated session IDs (default: 32)'
    )
    
    # Output options
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed analysis for all session IDs'
    )
    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Save results to JSON file'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Only show summary statistics'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.min_entropy <= 0:
        print("Error: Minimum entropy must be positive", file=sys.stderr)
        sys.exit(1)
    
    if args.min_length <= 0:
        print("Error: Minimum length must be positive", file=sys.stderr)
        sys.exit(1)
    
    # Initialize analyzer
    analyzer = SessionIDAnalyzer(min_entropy=args.min_entropy, min_length=args.min_length)
    
    # Collect session IDs to analyze
    session_ids = []
    
    try:
        if args.session_id:
            session_ids = [args.session_id]
        elif args.file:
            session_ids = load_session_ids_from_file(args.file)
            print(f"Loaded {len(session_ids)} session IDs from {args.file}")
        elif args.generate:
            print(f"Generating {args.generate} secure session IDs for analysis...")
            session_ids = [
                analyzer.generate_secure_session_id(length=args.length) 
                for _ in range(args.generate)
            ]
    
    except (FileNotFoundError, IOError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Perform analysis
    print(f"Analyzing {len(session_ids)} session ID(s)...")
    results = []
    
    for session_id in session_ids:
        try:
            result = analyzer.analyze_session_id(session_id)
            results.append(result)
        except Exception as e:
            results.append({
                'error': f"Analysis failed: {str(e)}",
                'session_id': session_id
            })
    
    # Save results if requested
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"Results saved to {args.output}")
        except IOError as e:
            print(f"Warning: Could not save results to {args.output}: {e}", file=sys.stderr)
    
    # Display results
    if not args.quiet:
        print_analysis_results(results, verbose=args.verbose)
    else:
        # Quiet mode - only summary
        total = len(results)
        strong = sum(1 for r in results if r.get('security_assessment', {}).get('security_level') == 'STRONG')
        print(f"Analyzed: {total}, Strong: {strong}, Pass Rate: {strong/total*100:.1f}%")


if __name__ == "__main__":
    main()
