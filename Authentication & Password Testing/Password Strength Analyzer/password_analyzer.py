#!/usr/bin/env python3
"""
Password Strength Analyzer

A comprehensive tool for analyzing password strength based on multiple criteria
including length, character variety, entropy, and common password checks.

Usage:
    python password_analyzer.py "mypassword123"
    python password_analyzer.py --file passwords.txt
    python password_analyzer.py --interactive
    python password_analyzer.py "password" --verbose --json

Author: Password Security Tool
License: MIT
"""

import argparse
import re
import math
import sys
import json
import getpass
from typing import Dict, List, Tuple, Optional
from pathlib import Path


class PasswordAnalyzer:
    """
    A class to analyze password strength based on various security criteria.
    """
    
    def __init__(self):
        """Initialize the password analyzer with common weak passwords."""
        # Common weak passwords (subset for demonstration)
        self.common_passwords = {
            'password', '123456', 'password123', 'admin', 'qwerty',
            'letmein', 'welcome', 'monkey', '1234567890', 'abc123',
            'Password1', 'password1', '12345678', 'welcome123',
            'admin123', 'root', 'toor', 'pass', 'test', 'guest'
        }
        
        # Character sets for entropy calculation
        self.char_sets = {
            'lowercase': set('abcdefghijklmnopqrstuvwxyz'),
            'uppercase': set('ABCDEFGHIJKLMNOPQRSTUVWXYZ'),
            'digits': set('0123456789'),
            'special': set('!@#$%^&*()_+-=[]{}|;:,.<>?~`'),
            'space': {' '}
        }
    
    def analyze_password(self, password: str) -> Dict:
        """
        Perform comprehensive password analysis.
        
        Args:
            password (str): The password to analyze
            
        Returns:
            Dict: Analysis results including strength score and recommendations
        """
        if not isinstance(password, str):
            raise ValueError("Password must be a string")
        
        analysis = {
            'password_length': len(password),
            'character_analysis': self._analyze_characters(password),
            'entropy': self._calculate_entropy(password),
            'strength_score': 0,
            'strength_level': '',
            'is_common': password.lower() in self.common_passwords,
            'pattern_analysis': self._analyze_patterns(password),
            'recommendations': [],
            'estimated_crack_time': '',
            'security_issues': []
        }
        
        # Calculate overall strength score
        analysis['strength_score'] = self._calculate_strength_score(analysis)
        analysis['strength_level'] = self._get_strength_level(analysis['strength_score'])
        analysis['estimated_crack_time'] = self._estimate_crack_time(analysis['entropy'])
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        return analysis
    
    def _analyze_characters(self, password: str) -> Dict:
        """Analyze character composition of the password."""
        char_analysis = {
            'has_lowercase': False,
            'has_uppercase': False,
            'has_digits': False,
            'has_special': False,
            'has_space': False,
            'unique_chars': len(set(password)),
            'repeated_chars': len(password) - len(set(password)),
            'char_variety_score': 0
        }
        
        password_set = set(password)
        
        # Check character types
        char_analysis['has_lowercase'] = bool(password_set & self.char_sets['lowercase'])
        char_analysis['has_uppercase'] = bool(password_set & self.char_sets['uppercase'])
        char_analysis['has_digits'] = bool(password_set & self.char_sets['digits'])
        char_analysis['has_special'] = bool(password_set & self.char_sets['special'])
        char_analysis['has_space'] = bool(password_set & self.char_sets['space'])
        
        # Calculate character variety score
        variety_count = sum([
            char_analysis['has_lowercase'],
            char_analysis['has_uppercase'],
            char_analysis['has_digits'],
            char_analysis['has_special']
        ])
        char_analysis['char_variety_score'] = variety_count
        
        return char_analysis
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits."""
        if not password:
            return 0.0
        
        # Determine character space size
        char_space = 0
        password_set = set(password)
        
        if password_set & self.char_sets['lowercase']:
            char_space += 26
        if password_set & self.char_sets['uppercase']:
            char_space += 26
        if password_set & self.char_sets['digits']:
            char_space += 10
        if password_set & self.char_sets['special']:
            char_space += len(self.char_sets['special'])
        if password_set & self.char_sets['space']:
            char_space += 1
        
        # Calculate entropy: log2(char_space^length)
        if char_space > 0:
            entropy = len(password) * math.log2(char_space)
        else:
            entropy = 0.0
        
        return round(entropy, 2)
    
    def _analyze_patterns(self, password: str) -> Dict:
        """Analyze common patterns in the password."""
        patterns = {
            'has_sequential_chars': False,
            'has_repeated_sequences': False,
            'has_keyboard_patterns': False,
            'has_common_substitutions': False,
            'pattern_details': []
        }
        
        # Check for sequential characters (abc, 123, etc.)
        sequential_patterns = ['abc', '123', 'qwe', 'asd', 'zxc']
        for pattern in sequential_patterns:
            if pattern in password.lower():
                patterns['has_sequential_chars'] = True
                patterns['pattern_details'].append(f"Sequential pattern: {pattern}")
        
        # Check for repeated sequences (aa, 11, etc.)
        if re.search(r'(.)\1{2,}', password):
            patterns['has_repeated_sequences'] = True
            patterns['pattern_details'].append("Repeated character sequences found")
        
        # Check for keyboard patterns
        keyboard_patterns = ['qwerty', 'asdf', 'zxcv', '1234', '!@#$']
        for pattern in keyboard_patterns:
            if pattern in password.lower():
                patterns['has_keyboard_patterns'] = True
                patterns['pattern_details'].append(f"Keyboard pattern: {pattern}")
        
        # Check for common substitutions (@ for a, 3 for e, etc.)
        if re.search(r'[@43!1$5]', password):
            patterns['has_common_substitutions'] = True
            patterns['pattern_details'].append("Common character substitutions detected")
        
        return patterns
    
    def _calculate_strength_score(self, analysis: Dict) -> int:
        """Calculate overall password strength score (0-100)."""
        score = 0
        
        # Length scoring (0-25 points)
        length = analysis['password_length']
        if length >= 12:
            score += 25
        elif length >= 8:
            score += 20
        elif length >= 6:
            score += 15
        elif length >= 4:
            score += 10
        else:
            score += 5
        
        # Character variety scoring (0-25 points)
        char_score = analysis['character_analysis']['char_variety_score']
        score += min(char_score * 6, 25)
        
        # Entropy scoring (0-25 points)
        entropy = analysis['entropy']
        if entropy >= 60:
            score += 25
        elif entropy >= 40:
            score += 20
        elif entropy >= 25:
            score += 15
        elif entropy >= 15:
            score += 10
        else:
            score += 5
        
        # Pattern and uniqueness scoring (0-25 points)
        pattern_penalties = 0
        if analysis['pattern_analysis']['has_sequential_chars']:
            pattern_penalties += 5
        if analysis['pattern_analysis']['has_repeated_sequences']:
            pattern_penalties += 5
        if analysis['pattern_analysis']['has_keyboard_patterns']:
            pattern_penalties += 5
        if analysis['is_common']:
            pattern_penalties += 10
        
        score += max(25 - pattern_penalties, 0)
        
        return min(score, 100)
    
    def _get_strength_level(self, score: int) -> str:
        """Convert numeric score to strength level."""
        if score >= 80:
            return "Very Strong"
        elif score >= 60:
            return "Strong"
        elif score >= 40:
            return "Moderate"
        elif score >= 20:
            return "Weak"
        else:
            return "Very Weak"
    
    def _estimate_crack_time(self, entropy: float) -> str:
        """Estimate time to crack password based on entropy."""
        if entropy < 20:
            return "Instantly - Few seconds"
        elif entropy < 30:
            return "Minutes to hours"
        elif entropy < 40:
            return "Days to weeks"
        elif entropy < 50:
            return "Months to years"
        elif entropy < 60:
            return "Decades"
        else:
            return "Centuries or more"
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate recommendations for password improvement."""
        recommendations = []
        
        # Length recommendations
        if analysis['password_length'] < 8:
            recommendations.append("Increase password length to at least 8 characters")
        elif analysis['password_length'] < 12:
            recommendations.append("Consider using 12+ characters for better security")
        
        # Character variety recommendations
        char_analysis = analysis['character_analysis']
        if not char_analysis['has_lowercase']:
            recommendations.append("Add lowercase letters")
        if not char_analysis['has_uppercase']:
            recommendations.append("Add uppercase letters")
        if not char_analysis['has_digits']:
            recommendations.append("Add numbers")
        if not char_analysis['has_special']:
            recommendations.append("Add special characters (!@#$%^&*)")
        
        # Pattern recommendations
        if analysis['is_common']:
            recommendations.append("Avoid common passwords")
        if analysis['pattern_analysis']['has_sequential_chars']:
            recommendations.append("Avoid sequential characters (abc, 123)")
        if analysis['pattern_analysis']['has_repeated_sequences']:
            recommendations.append("Avoid repeated character sequences")
        if analysis['pattern_analysis']['has_keyboard_patterns']:
            recommendations.append("Avoid keyboard patterns (qwerty, asdf)")
        
        # Entropy recommendations
        if analysis['entropy'] < 40:
            recommendations.append("Increase complexity and randomness")
        
        return recommendations


def format_analysis_output(analysis: Dict, verbose: bool = False) -> str:
    """Format analysis results for display."""
    output = []
    
    # Basic strength information
    output.append("=" * 50)
    output.append("PASSWORD STRENGTH ANALYSIS")
    output.append("=" * 50)
    output.append(f"Strength Level: {analysis['strength_level']}")
    output.append(f"Strength Score: {analysis['strength_score']}/100")
    output.append(f"Estimated Crack Time: {analysis['estimated_crack_time']}")
    output.append("")
    
    if verbose:
        # Detailed analysis
        output.append("DETAILED ANALYSIS:")
        output.append("-" * 20)
        output.append(f"Password Length: {analysis['password_length']} characters")
        output.append(f"Entropy: {analysis['entropy']} bits")
        output.append(f"Unique Characters: {analysis['character_analysis']['unique_chars']}")
        output.append(f"Common Password: {'Yes' if analysis['is_common'] else 'No'}")
        output.append("")
        
        # Character composition
        char_analysis = analysis['character_analysis']
        output.append("CHARACTER COMPOSITION:")
        output.append("-" * 22)
        output.append(f"Lowercase Letters: {'✓' if char_analysis['has_lowercase'] else '✗'}")
        output.append(f"Uppercase Letters: {'✓' if char_analysis['has_uppercase'] else '✗'}")
        output.append(f"Numbers: {'✓' if char_analysis['has_digits'] else '✗'}")
        output.append(f"Special Characters: {'✓' if char_analysis['has_special'] else '✗'}")
        output.append("")
        
        # Pattern analysis
        if analysis['pattern_analysis']['pattern_details']:
            output.append("PATTERN ISSUES:")
            output.append("-" * 15)
            for detail in analysis['pattern_analysis']['pattern_details']:
                output.append(f"• {detail}")
            output.append("")
    
    # Recommendations
    if analysis['recommendations']:
        output.append("RECOMMENDATIONS:")
        output.append("-" * 16)
        for i, rec in enumerate(analysis['recommendations'], 1):
            output.append(f"{i}. {rec}")
    else:
        output.append("RECOMMENDATIONS:")
        output.append("-" * 16)
        output.append("No specific recommendations - password meets security criteria!")
    
    return "\n".join(output)


def main():
    """Main function to handle command line arguments and execute analysis."""
    parser = argparse.ArgumentParser(
        description="Analyze password strength and security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python password_analyzer.py "mypassword123"
  python password_analyzer.py --interactive
  python password_analyzer.py --file passwords.txt
  python password_analyzer.py "password" --verbose --json
        """
    )
    
    # Password input options (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('password', nargs='?', help='Password to analyze')
    input_group.add_argument('--interactive', '-i', action='store_true',
                           help='Enter password interactively (hidden input)')
    input_group.add_argument('--file', '-f', type=str,
                           help='File containing passwords to analyze (one per line)')
    
    # Output options
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed analysis')
    parser.add_argument('--json', '-j', action='store_true',
                       help='Output results in JSON format')
    parser.add_argument('--output', '-o', type=str,
                       help='Save results to file')
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = PasswordAnalyzer()
    results = []
    
    try:
        # Handle different input methods
        if args.interactive:
            password = getpass.getpass("Enter password to analyze: ")
            if not password:
                print("Error: No password entered", file=sys.stderr)
                return 1
            analysis = analyzer.analyze_password(password)
            results.append(analysis)
            
        elif args.file:
            file_path = Path(args.file)
            if not file_path.exists():
                print(f"Error: File '{args.file}' not found", file=sys.stderr)
                return 1
            
            with open(file_path, 'r', encoding='utf-8') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            if not passwords:
                print("Error: No passwords found in file", file=sys.stderr)
                return 1
            
            for i, password in enumerate(passwords, 1):
                try:
                    analysis = analyzer.analyze_password(password)
                    analysis['password_index'] = i
                    results.append(analysis)
                except Exception as e:
                    print(f"Error analyzing password {i}: {e}", file=sys.stderr)
                    
        else:
            # Direct password argument
            analysis = analyzer.analyze_password(args.password)
            results.append(analysis)
        
        # Format and output results
        output_content = []
        
        for i, analysis in enumerate(results):
            if len(results) > 1:
                output_content.append(f"\n{'='*20} PASSWORD {i+1} {'='*20}")
            
            if args.json:
                output_content.append(json.dumps(analysis, indent=2))
            else:
                output_content.append(format_analysis_output(analysis, args.verbose))
        
        final_output = "\n".join(output_content)
        
        # Output to file or stdout
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(final_output)
            print(f"Results saved to {args.output}")
        else:
            print(final_output)
    
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())