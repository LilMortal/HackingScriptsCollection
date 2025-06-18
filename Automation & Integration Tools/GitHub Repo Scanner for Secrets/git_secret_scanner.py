#!/usr/bin/env python3
"""
Local Git Repository Secret Scanner

A security tool for scanning your own local Git repositories to detect
accidentally committed secrets, API keys, passwords, and other sensitive data.

This script helps developers identify potential security issues in their own
codebase by scanning for common patterns that might indicate exposed secrets.

Usage:
    python git_secret_scanner.py /path/to/repo --output secrets_report.json
    python git_secret_scanner.py . --format table --severity high
    python git_secret_scanner.py /path/to/repo --exclude "*.log,*.tmp" --verbose

Author: Security-focused development tool
License: MIT
"""

import os
import re
import json
import argparse
import fnmatch
import hashlib
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import subprocess
import sys


@dataclass
class SecretMatch:
    """Data class to represent a found secret."""
    file_path: str
    line_number: int
    matched_text: str
    secret_type: str
    severity: str
    context: str
    confidence: float


class SecretPattern:
    """Class to define secret detection patterns."""
    
    def __init__(self, name: str, pattern: str, severity: str = "medium", confidence: float = 0.8):
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.severity = severity
        self.confidence = confidence


class GitSecretScanner:
    """Main scanner class for detecting secrets in Git repositories."""
    
    def __init__(self, repo_path: str, exclude_patterns: List[str] = None):
        """
        Initialize the scanner.
        
        Args:
            repo_path: Path to the Git repository to scan
            exclude_patterns: List of file patterns to exclude from scanning
        """
        self.repo_path = Path(repo_path).resolve()
        self.exclude_patterns = exclude_patterns or []
        self.secret_patterns = self._initialize_patterns()
        self.findings: List[SecretMatch] = []
        
        # Validate repository
        if not self._is_git_repository():
            raise ValueError(f"Directory {self.repo_path} is not a Git repository")
    
    def _is_git_repository(self) -> bool:
        """Check if the given path is a Git repository."""
        git_dir = self.repo_path / '.git'
        return git_dir.exists() and (git_dir.is_dir() or git_dir.is_file())
    
    def _initialize_patterns(self) -> List[SecretPattern]:
        """Initialize secret detection patterns."""
        patterns = [
            # API Keys and Tokens
            SecretPattern(
                "Generic API Key", 
                r'(?i)(?:api[_-]?key|apikey|api[_-]?token|access[_-]?token)["\s]*[=:]["\s]*([a-zA-Z0-9_\-]{20,})',
                "high", 0.9
            ),
            SecretPattern(
                "AWS Access Key", 
                r'(?i)(?:aws[_-]?access[_-]?key[_-]?id|aws[_-]?key)["\s]*[=:]["\s]*([A-Z0-9]{20})',
                "critical", 0.95
            ),
            SecretPattern(
                "AWS Secret Key", 
                r'(?i)(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret)["\s]*[=:]["\s]*([A-Za-z0-9/+=]{40})',
                "critical", 0.95
            ),
            SecretPattern(
                "GitHub Token", 
                r'(?i)(?:github[_-]?token|gh[_-]?token)["\s]*[=:]["\s]*([a-zA-Z0-9_]{40})',
                "high", 0.9
            ),
            SecretPattern(
                "Google API Key", 
                r'(?i)(?:google[_-]?api[_-]?key|gcp[_-]?key)["\s]*[=:]["\s]*([A-Za-z0-9_-]{39})',
                "high", 0.9
            ),
            
            # Database Credentials
            SecretPattern(
                "Database URL", 
                r'(?i)(?:database[_-]?url|db[_-]?url)["\s]*[=:]["\s]*([a-zA-Z]+://[^"\s]+)',
                "high", 0.85
            ),
            SecretPattern(
                "MongoDB Connection", 
                r'mongodb://[^"\s]+',
                "medium", 0.8
            ),
            SecretPattern(
                "MySQL Connection", 
                r'mysql://[^"\s]+',
                "medium", 0.8
            ),
            
            # Generic Passwords
            SecretPattern(
                "Password Field", 
                r'(?i)(?:password|passwd|pwd)["\s]*[=:]["\s]*["\']([^"\']{8,})["\']',
                "medium", 0.7
            ),
            
            # Private Keys
            SecretPattern(
                "Private Key", 
                r'-----BEGIN [A-Z ]*PRIVATE KEY-----',
                "critical", 0.95
            ),
            SecretPattern(
                "SSH Private Key", 
                r'-----BEGIN OPENSSH PRIVATE KEY-----',
                "critical", 0.95
            ),
            
            # JWT Tokens
            SecretPattern(
                "JWT Token", 
                r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
                "high", 0.9
            ),
            
            # Slack Tokens
            SecretPattern(
                "Slack Token", 
                r'xox[baprs]-[0-9a-zA-Z-]+',
                "high", 0.9
            ),
            
            # Generic Secrets
            SecretPattern(
                "Generic Secret", 
                r'(?i)(?:secret|token|key)["\s]*[=:]["\s]*["\']([a-zA-Z0-9_\-+=]{16,})["\']',
                "low", 0.6
            ),
        ]
        
        return patterns
    
    def _should_exclude_file(self, file_path: Path) -> bool:
        """Check if a file should be excluded from scanning."""
        relative_path = file_path.relative_to(self.repo_path)
        
        # Default exclusions
        default_excludes = [
            '.git/*', '*.pyc', '*.pyo', '__pycache__/*', 
            '*.jpg', '*.jpeg', '*.png', '*.gif', '*.pdf',
            '*.zip', '*.tar', '*.gz', '*.exe', '*.dll',
            'node_modules/*', '.venv/*', 'venv/*',
            '*.min.js', '*.min.css', 'package-lock.json'
        ]
        
        all_patterns = self.exclude_patterns + default_excludes
        
        for pattern in all_patterns:
            if fnmatch.fnmatch(str(relative_path), pattern):
                return True
        
        return False
    
    def _get_file_context(self, file_path: Path, line_number: int, context_lines: int = 2) -> str:
        """Get context lines around a match."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            start = max(0, line_number - context_lines - 1)
            end = min(len(lines), line_number + context_lines)
            
            context = []
            for i, line in enumerate(lines[start:end], start + 1):
                prefix = ">>> " if i == line_number else "    "
                context.append(f"{prefix}{i:4d}: {line.rstrip()}")
            
            return "\n".join(context)
        except Exception:
            return "Unable to retrieve context"
    
    def _scan_file(self, file_path: Path) -> List[SecretMatch]:
        """Scan a single file for secrets."""
        matches = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Warning: Could not read file {file_path}: {e}")
            return matches
        
        for line_num, line in enumerate(lines, 1):
            for pattern in self.secret_patterns:
                for match in pattern.pattern.finditer(line):
                    # Get the matched text (use group 1 if available, otherwise group 0)
                    matched_text = match.group(1) if match.groups() else match.group(0)
                    
                    # Skip very short matches or common false positives
                    if len(matched_text) < 8 or matched_text.lower() in ['password', 'secret', 'token', 'key']:
                        continue
                    
                    # Create the match object
                    secret_match = SecretMatch(
                        file_path=str(file_path.relative_to(self.repo_path)),
                        line_number=line_num,
                        matched_text=matched_text[:50] + "..." if len(matched_text) > 50 else matched_text,
                        secret_type=pattern.name,
                        severity=pattern.severity,
                        context=self._get_file_context(file_path, line_num),
                        confidence=pattern.confidence
                    )
                    
                    matches.append(secret_match)
        
        return matches
    
    def _get_all_files(self) -> List[Path]:
        """Get all files in the repository that should be scanned."""
        all_files = []
        
        for root, dirs, files in os.walk(self.repo_path):
            # Skip .git directory
            if '.git' in dirs:
                dirs.remove('.git')
            
            for file in files:
                file_path = Path(root) / file
                if not self._should_exclude_file(file_path):
                    all_files.append(file_path)
        
        return all_files
    
    def scan(self, verbose: bool = False) -> List[SecretMatch]:
        """
        Perform the secret scan on the repository.
        
        Args:
            verbose: Whether to print verbose output
            
        Returns:
            List of SecretMatch objects representing found secrets
        """
        print(f"Scanning repository: {self.repo_path}")
        
        files_to_scan = self._get_all_files()
        print(f"Found {len(files_to_scan)} files to scan")
        
        self.findings = []
        
        for i, file_path in enumerate(files_to_scan):
            if verbose:
                print(f"Scanning ({i+1}/{len(files_to_scan)}): {file_path.relative_to(self.repo_path)}")
            
            file_matches = self._scan_file(file_path)
            self.findings.extend(file_matches)
        
        # Sort findings by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        self.findings.sort(key=lambda x: (severity_order.get(x.severity, 4), x.file_path, x.line_number))
        
        return self.findings
    
    def get_summary(self) -> Dict:
        """Get a summary of the scan results."""
        if not self.findings:
            return {"total": 0, "by_severity": {}, "by_type": {}}
        
        by_severity = {}
        by_type = {}
        
        for finding in self.findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_type[finding.secret_type] = by_type.get(finding.secret_type, 0) + 1
        
        return {
            "total": len(self.findings),
            "by_severity": by_severity,
            "by_type": by_type
        }


def format_output_table(findings: List[SecretMatch], show_context: bool = False) -> str:
    """Format findings as a table."""
    if not findings:
        return "No secrets found!"
    
    output = []
    output.append("=" * 80)
    output.append("SECRET SCAN RESULTS")
    output.append("=" * 80)
    
    for i, finding in enumerate(findings, 1):
        output.append(f"\n{i}. {finding.secret_type} ({finding.severity.upper()})")
        output.append(f"   File: {finding.file_path}:{finding.line_number}")
        output.append(f"   Match: {finding.matched_text}")
        output.append(f"   Confidence: {finding.confidence:.1%}")
        
        if show_context:
            output.append(f"   Context:")
            for line in finding.context.split('\n'):
                output.append(f"   {line}")
    
    return "\n".join(output)


def format_output_json(findings: List[SecretMatch], summary: Dict) -> str:
    """Format findings as JSON."""
    return json.dumps({
        "scan_timestamp": datetime.now().isoformat(),
        "summary": summary,
        "findings": [asdict(finding) for finding in findings]
    }, indent=2)


def main():
    """Main function to run the secret scanner."""
    parser = argparse.ArgumentParser(
        description="Scan local Git repositories for accidentally committed secrets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/repo
  %(prog)s . --format json --output secrets.json
  %(prog)s /path/to/repo --exclude "*.log,*.tmp" --severity high
  %(prog)s . --verbose --show-context
        """
    )
    
    parser.add_argument(
        'repository',
        help='Path to the Git repository to scan'
    )
    
    parser.add_argument(
        '--format',
        choices=['table', 'json'],
        default='table',
        help='Output format (default: table)'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output file path (default: stdout)'
    )
    
    parser.add_argument(
        '--exclude',
        help='Comma-separated list of file patterns to exclude'
    )
    
    parser.add_argument(
        '--severity',
        choices=['critical', 'high', 'medium', 'low'],
        help='Minimum severity level to report'
    )
    
    parser.add_argument(
        '--show-context',
        action='store_true',
        help='Show code context around matches (table format only)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Parse exclude patterns
    exclude_patterns = []
    if args.exclude:
        exclude_patterns = [pattern.strip() for pattern in args.exclude.split(',')]
    
    try:
        # Initialize and run scanner
        scanner = GitSecretScanner(args.repository, exclude_patterns)
        findings = scanner.scan(verbose=args.verbose)
        
        # Filter by severity if specified
        if args.severity:
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            min_severity = severity_order[args.severity]
            findings = [f for f in findings if severity_order.get(f.severity, 4) <= min_severity]
        
        # Get summary
        summary = scanner.get_summary()
        
        # Format output
        if args.format == 'json':
            output = format_output_json(findings, summary)
        else:
            output = format_output_table(findings, args.show_context)
            output += f"\n\nSummary: {summary['total']} potential secrets found"
            if summary['by_severity']:
                output += f" ({', '.join(f'{count} {severity}' for severity, count in summary['by_severity'].items())})"
        
        # Write output
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Results written to {args.output}")
        else:
            print(output)
        
        # Set exit code based on findings
        if findings:
            print(f"\nWarning: {len(findings)} potential secrets found!")
            sys.exit(1)
        else:
            print("\nNo secrets detected.")
            sys.exit(0)
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
