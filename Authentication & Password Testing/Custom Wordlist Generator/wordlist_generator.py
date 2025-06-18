#!/usr/bin/env python3
"""
CustomWordlistGenerator - A comprehensive wordlist generation tool

This script generates custom wordlists based on various input sources and transformation rules.
It supports multiple generation modes including:
- Base word combinations and permutations
- Pattern-based generation
- Transformation rules (l33t speak, case variations, etc.)
- Dictionary-based generation with custom rules

Usage:
    python CustomWordlistGenerator.py -w base_words.txt -o output.txt --min-length 6 --max-length 12
    python CustomWordlistGenerator.py -p "admin,user,test" -t leet,case,append_numbers -o wordlist.txt

Author: CustomWordlistGenerator
License: MIT
"""

import argparse
import itertools
import re
import sys
from pathlib import Path
from typing import List, Set, Iterator, Dict, Any
import logging


class WordlistGenerator:
    """
    A comprehensive wordlist generator with multiple transformation capabilities.
    """
    
    def __init__(self, min_length: int = 1, max_length: int = 50, 
                 output_limit: int = 1000000):
        """
        Initialize the wordlist generator.
        
        Args:
            min_length: Minimum word length to include
            max_length: Maximum word length to include
            output_limit: Maximum number of words to generate (safety limit)
        """
        self.min_length = min_length
        self.max_length = max_length
        self.output_limit = output_limit
        self.generated_words: Set[str] = set()
        
        # Common transformation mappings
        self.leet_map = {
            'a': ['@', '4'], 'e': ['3'], 'i': ['1', '!'], 'o': ['0'],
            's': ['$', '5'], 't': ['7'], 'l': ['1'], 'g': ['9'],
            'A': ['@', '4'], 'E': ['3'], 'I': ['1', '!'], 'O': ['0'],
            'S': ['$', '5'], 'T': ['7'], 'L': ['1'], 'G': ['9']
        }
        
        self.common_suffixes = [
            '1', '12', '123', '1234', '12345',
            '01', '02', '03', '04', '05',
            '2020', '2021', '2022', '2023', '2024', '2025',
            '!', '!!', '!!!', '@', '#', '$'
        ]
        
        self.common_prefixes = [
            '1', '12', '123', 'the', 'my', 'new', 'old'
        ]

    def load_wordlist_file(self, filepath: str) -> List[str]:
        """
        Load words from a text file.
        
        Args:
            filepath: Path to the wordlist file
            
        Returns:
            List of words from the file
            
        Raises:
            FileNotFoundError: If the file doesn't exist
            IOError: If there's an error reading the file
        """
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
                logging.info(f"Loaded {len(words)} words from {filepath}")
                return words
        except FileNotFoundError:
            raise FileNotFoundError(f"Wordlist file not found: {filepath}")
        except IOError as e:
            raise IOError(f"Error reading file {filepath}: {e}")

    def parse_word_patterns(self, patterns: str) -> List[str]:
        """
        Parse comma-separated word patterns.
        
        Args:
            patterns: Comma-separated string of base words
            
        Returns:
            List of base words
        """
        return [word.strip() for word in patterns.split(',') if word.strip()]

    def apply_case_variations(self, word: str) -> Iterator[str]:
        """
        Generate case variations of a word.
        
        Args:
            word: Input word
            
        Yields:
            Different case variations of the word
        """
        yield word.lower()
        yield word.upper()
        yield word.capitalize()
        yield word.title()
        # First letter uppercase, rest lowercase
        if len(word) > 1:
            yield word[0].upper() + word[1:].lower()

    def apply_leet_speak(self, word: str, max_replacements: int = 3) -> Iterator[str]:
        """
        Apply leet speak transformations to a word.
        
        Args:
            word: Input word
            max_replacements: Maximum number of character replacements
            
        Yields:
            Leet speak variations of the word
        """
        # Find positions where leet replacements can be made
        replacement_positions = []
        for i, char in enumerate(word):
            if char in self.leet_map:
                replacement_positions.append((i, char))
        
        # Generate combinations of replacements
        for r in range(1, min(len(replacement_positions), max_replacements) + 1):
            for positions in itertools.combinations(replacement_positions, r):
                for replacements in itertools.product(*[self.leet_map[char] for _, char in positions]):
                    new_word = list(word)
                    for (pos, _), replacement in zip(positions, replacements):
                        new_word[pos] = replacement
                    yield ''.join(new_word)

    def apply_number_appending(self, word: str) -> Iterator[str]:
        """
        Append common number patterns to words.
        
        Args:
            word: Input word
            
        Yields:
            Words with appended numbers
        """
        for suffix in self.common_suffixes:
            yield word + suffix

    def apply_number_prepending(self, word: str) -> Iterator[str]:
        """
        Prepend common patterns to words.
        
        Args:
            word: Input word
            
        Yields:
            Words with prepended patterns
        """
        for prefix in self.common_prefixes:
            yield prefix + word

    def generate_word_combinations(self, words: List[str], max_combinations: int = 2) -> Iterator[str]:
        """
        Generate combinations of words.
        
        Args:
            words: List of base words
            max_combinations: Maximum number of words to combine
            
        Yields:
            Combined words
        """
        for r in range(2, max_combinations + 1):
            for combination in itertools.combinations(words, r):
                # Direct concatenation
                yield ''.join(combination)
                # With separators
                for separator in ['', '-', '_', '.']:
                    if separator:  # Skip empty separator as it's already done
                        yield separator.join(combination)

    def apply_transformations(self, words: List[str], transformations: List[str]) -> Iterator[str]:
        """
        Apply specified transformations to a list of words.
        
        Args:
            words: List of base words
            transformations: List of transformation names
            
        Yields:
            Transformed words
        """
        for word in words:
            # Always yield the original word
            yield word
            
            for transform in transformations:
                if transform == 'case':
                    yield from self.apply_case_variations(word)
                elif transform == 'leet':
                    yield from self.apply_leet_speak(word)
                elif transform == 'append_numbers':
                    yield from self.apply_number_appending(word)
                elif transform == 'prepend_numbers':
                    yield from self.apply_number_prepending(word)

    def generate_pattern_based(self, pattern: str, charset: str = 'abcdefghijklmnopqrstuvwxyz0123456789') -> Iterator[str]:
        """
        Generate words based on a pattern.
        Pattern format: ? = any character, # = any digit, @ = any letter
        
        Args:
            pattern: Pattern string (e.g., "admin???", "user###")
            charset: Characters to use for pattern replacement
            
        Yields:
            Words matching the pattern
        """
        if not pattern:
            return
        
        # Calculate total combinations to avoid memory issues
        wildcard_count = pattern.count('?') + pattern.count('#') + pattern.count('@')
        if wildcard_count > 4:  # Limit to prevent excessive generation
            logging.warning(f"Pattern '{pattern}' has too many wildcards ({wildcard_count}), limiting generation")
            return
        
        def generate_recursive(current_pattern: str, pos: int = 0) -> Iterator[str]:
            if pos >= len(current_pattern):
                yield current_pattern
                return
            
            char = current_pattern[pos]
            if char == '?':
                for c in charset:
                    new_pattern = current_pattern[:pos] + c + current_pattern[pos+1:]
                    yield from generate_recursive(new_pattern, pos + 1)
            elif char == '#':
                for c in '0123456789':
                    new_pattern = current_pattern[:pos] + c + current_pattern[pos+1:]
                    yield from generate_recursive(new_pattern, pos + 1)
            elif char == '@':
                for c in 'abcdefghijklmnopqrstuvwxyz':
                    new_pattern = current_pattern[:pos] + c + current_pattern[pos+1:]
                    yield from generate_recursive(new_pattern, pos + 1)
            else:
                yield from generate_recursive(current_pattern, pos + 1)
        
        yield from generate_recursive(pattern)

    def filter_words(self, words: Iterator[str]) -> Iterator[str]:
        """
        Filter words based on length constraints and duplicates.
        
        Args:
            words: Iterator of words to filter
            
        Yields:
            Filtered words
        """
        count = 0
        for word in words:
            if count >= self.output_limit:
                logging.warning(f"Reached output limit of {self.output_limit} words")
                break
            
            if (self.min_length <= len(word) <= self.max_length and 
                word not in self.generated_words):
                self.generated_words.add(word)
                yield word
                count += 1

    def generate_wordlist(self, base_words: List[str], transformations: List[str], 
                         patterns: List[str] = None, combinations: bool = False) -> Iterator[str]:
        """
        Main wordlist generation method.
        
        Args:
            base_words: List of base words
            transformations: List of transformations to apply
            patterns: List of patterns to generate
            combinations: Whether to generate word combinations
            
        Yields:
            Generated words
        """
        all_words = []
        
        # Add base words
        all_words.extend(base_words)
        
        # Apply transformations to base words
        if transformations:
            transformed_words = list(self.apply_transformations(base_words, transformations))
            all_words.extend(transformed_words)
        
        # Generate word combinations if requested
        if combinations and len(base_words) > 1:
            combination_words = list(self.generate_word_combinations(base_words))
            all_words.extend(combination_words)
            
            # Apply transformations to combinations too
            if transformations:
                transformed_combinations = list(self.apply_transformations(combination_words, transformations))
                all_words.extend(transformed_combinations)
        
        # Generate pattern-based words
        if patterns:
            for pattern in patterns:
                pattern_words = list(self.generate_pattern_based(pattern))
                all_words.extend(pattern_words)
        
        # Filter and yield words
        yield from self.filter_words(iter(all_words))

    def save_wordlist(self, words: Iterator[str], output_file: str) -> int:
        """
        Save generated words to a file.
        
        Args:
            words: Iterator of words to save
            output_file: Output file path
            
        Returns:
            Number of words saved
        """
        count = 0
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                for word in words:
                    f.write(word + '\n')
                    count += 1
            logging.info(f"Saved {count} words to {output_file}")
            return count
        except IOError as e:
            raise IOError(f"Error writing to file {output_file}: {e}")


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def main():
    """Main function to handle command-line interface."""
    parser = argparse.ArgumentParser(
        description="Custom Wordlist Generator - Generate wordlists with various transformations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate from word file with transformations
  python CustomWordlistGenerator.py -w words.txt -t case,leet,append_numbers -o output.txt
  
  # Generate from pattern words
  python CustomWordlistGenerator.py -p "admin,user,test" -t case,append_numbers -o wordlist.txt
  
  # Generate with patterns and combinations
  python CustomWordlistGenerator.py -p "admin,user" -pt "pass###" -c -o combined.txt
  
  # Generate from file with length constraints
  python CustomWordlistGenerator.py -w base.txt --min-length 8 --max-length 16 -o filtered.txt
        """
    )
    
    # Input options
    parser.add_argument('-w', '--wordlist', type=str, 
                       help='Path to input wordlist file')
    parser.add_argument('-p', '--patterns', type=str,
                       help='Comma-separated base words/patterns')
    parser.add_argument('-pt', '--pattern-templates', type=str,
                       help='Comma-separated pattern templates (e.g., "admin???,user###")')
    
    # Transformation options
    parser.add_argument('-t', '--transformations', type=str,
                       help='Comma-separated transformations: case,leet,append_numbers,prepend_numbers')
    parser.add_argument('-c', '--combinations', action='store_true',
                       help='Generate word combinations')
    
    # Output options
    parser.add_argument('-o', '--output', type=str, required=True,
                       help='Output wordlist file')
    
    # Filtering options
    parser.add_argument('--min-length', type=int, default=1,
                       help='Minimum word length (default: 1)')
    parser.add_argument('--max-length', type=int, default=50,
                       help='Maximum word length (default: 50)')
    parser.add_argument('--max-words', type=int, default=1000000,
                       help='Maximum number of words to generate (default: 1000000)')
    
    # Other options
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Validate input
    if not args.wordlist and not args.patterns and not args.pattern_templates:
        parser.error("Must specify either --wordlist, --patterns, or --pattern-templates")
    
    try:
        # Initialize generator
        generator = WordlistGenerator(
            min_length=args.min_length,
            max_length=args.max_length,
            output_limit=args.max_words
        )
        
        # Collect base words
        base_words = []
        
        if args.wordlist:
            base_words.extend(generator.load_wordlist_file(args.wordlist))
        
        if args.patterns:
            base_words.extend(generator.parse_word_patterns(args.patterns))
        
        # Parse transformations
        transformations = []
        if args.transformations:
            transformations = [t.strip() for t in args.transformations.split(',')]
            valid_transforms = {'case', 'leet', 'append_numbers', 'prepend_numbers'}
            invalid_transforms = set(transformations) - valid_transforms
            if invalid_transforms:
                logging.error(f"Invalid transformations: {invalid_transforms}")
                logging.error(f"Valid transformations: {valid_transforms}")
                sys.exit(1)
        
        # Parse pattern templates
        pattern_templates = []
        if args.pattern_templates:
            pattern_templates = [p.strip() for p in args.pattern_templates.split(',')]
        
        logging.info(f"Starting wordlist generation...")
        logging.info(f"Base words: {len(base_words)}")
        logging.info(f"Transformations: {transformations}")
        logging.info(f"Pattern templates: {pattern_templates}")
        logging.info(f"Generate combinations: {args.combinations}")
        
        # Generate wordlist
        wordlist = generator.generate_wordlist(
            base_words=base_words,
            transformations=transformations,
            patterns=pattern_templates,
            combinations=args.combinations
        )
        
        # Save to file
        word_count = generator.save_wordlist(wordlist, args.output)
        
        print(f"Successfully generated {word_count} words and saved to {args.output}")
        
    except Exception as e:
        logging.error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
