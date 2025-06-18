#!/usr/bin/env python3
"""
Cronjob Security Auditor
========================

A comprehensive security auditing tool for analyzing cron configurations
and identifying potential security vulnerabilities and misconfigurations.

Author: Security Auditing Tool
License: MIT
Version: 1.0.0

Usage Examples:
    # Audit system-wide crontabs
    python3 cronjob_security_auditor.py --system-wide

    # Audit specific user's crontab
    python3 cronjob_security_auditor.py --user username

    # Audit custom cron file with verbose output
    python3 cronjob_security_auditor.py --file /path/to/cronfile --verbose

    # Generate detailed report in JSON format
    python3 cronjob_security_auditor.py --system-wide --output report.json --format json
"""

import argparse
import json
import os
import pwd
import re
import stat
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union


class CronSecurityAuditor:
    """Main class for auditing cron job security configurations."""
    
    def __init__(self, verbose: bool = False):
        """
        Initialize the Cron Security Auditor.
        
        Args:
            verbose (bool): Enable verbose output for detailed logging
        """
        self.verbose = verbose
        self.findings = []
        self.statistics = {
            'total_jobs': 0,
            'high_risk': 0,
            'medium_risk': 0,
            'low_risk': 0,
            'info': 0
        }
        
        # Define security patterns and rules
        self.security_patterns = {
            'world_writable_paths': re.compile(r'/tmp/|/var/tmp/'),
            'dangerous_commands': re.compile(r'\b(rm\s+-rf|chmod\s+777|wget|curl)\b'),
            'shell_injection': re.compile(r'[\$`]|\$\(|\${'),
            'root_paths': re.compile(r'^/(bin|sbin|usr/(bin|sbin))/'),
            'relative_paths': re.compile(r'^[^/]'),
            'wildcard_usage': re.compile(r'\*'),
            'network_commands': re.compile(r'\b(wget|curl|nc|netcat|ssh|scp|rsync)\b')
        }
    
    def log(self, message: str, level: str = "INFO") -> None:
        """
        Log messages with timestamp and level.
        
        Args:
            message (str): Message to log
            level (str): Log level (INFO, WARNING, ERROR)
        """
        if self.verbose or level != "INFO":
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] {level}: {message}")
    
    def add_finding(self, severity: str, title: str, description: str, 
                   job_line: str = "", user: str = "", file_path: str = "") -> None:
        """
        Add a security finding to the results.
        
        Args:
            severity (str): Severity level (HIGH, MEDIUM, LOW, INFO)
            title (str): Short title of the finding
            description (str): Detailed description
            job_line (str): The cron job line that triggered the finding
            user (str): User associated with the cron job
            file_path (str): Path to the cron file
        """
        finding = {
            'severity': severity,
            'title': title,
            'description': description,
            'job_line': job_line.strip(),
            'user': user,
            'file_path': file_path,
            'timestamp': datetime.now().isoformat()
        }
        
        self.findings.append(finding)
        self.statistics[severity.lower() + '_risk'] += 1
        
        if self.verbose:
            self.log(f"{severity}: {title} - {description}")
    
    def check_file_permissions(self, file_path: str) -> None:
        """
        Check file permissions for security issues.
        
        Args:
            file_path (str): Path to the file to check
        """
        try:
            file_stat = os.stat(file_path)
            mode = file_stat.st_mode
            
            # Check if file is world-writable
            if mode & stat.S_IWOTH:
                self.add_finding(
                    "HIGH",
                    "World-writable cron file",
                    f"File {file_path} is writable by all users, allowing potential privilege escalation",
                    file_path=file_path
                )
            
            # Check if file is group-writable (medium risk)
            elif mode & stat.S_IWGRP:
                self.add_finding(
                    "MEDIUM",
                    "Group-writable cron file",
                    f"File {file_path} is writable by group members",
                    file_path=file_path
                )
            
            # Check file ownership
            file_owner = pwd.getpwuid(file_stat.st_uid).pw_name
            if file_owner != 'root' and '/etc/cron' in file_path:
                self.add_finding(
                    "HIGH",
                    "System cron file not owned by root",
                    f"System cron file {file_path} is owned by {file_owner} instead of root",
                    file_path=file_path
                )
                
        except (OSError, KeyError) as e:
            self.log(f"Error checking permissions for {file_path}: {e}", "ERROR")
    
    def analyze_cron_job(self, job_line: str, user: str = "", file_path: str = "") -> None:
        """
        Analyze a single cron job line for security issues.
        
        Args:
            job_line (str): The cron job line to analyze
            user (str): User associated with the job
            file_path (str): Path to the cron file
        """
        if not job_line.strip() or job_line.strip().startswith('#'):
            return
        
        self.statistics['total_jobs'] += 1
        command_part = self.extract_command_from_cron_line(job_line)
        
        if not command_part:
            return
        
        # Check for dangerous commands
        if self.security_patterns['dangerous_commands'].search(command_part):
            self.add_finding(
                "HIGH",
                "Dangerous command detected",
                "Job contains potentially dangerous commands like 'rm -rf', 'chmod 777', or network utilities",
                job_line, user, file_path
            )
        
        # Check for shell injection vulnerabilities
        if self.security_patterns['shell_injection'].search(command_part):
            self.add_finding(
                "MEDIUM",
                "Potential shell injection vulnerability",
                "Job contains shell metacharacters that could be exploited",
                job_line, user, file_path
            )
        
        # Check for world-writable paths
        if self.security_patterns['world_writable_paths'].search(command_part):
            self.add_finding(
                "MEDIUM",
                "Usage of world-writable directories",
                "Job uses world-writable directories like /tmp/ which could be exploited",
                job_line, user, file_path
            )
        
        # Check for relative paths
        if self.security_patterns['relative_paths'].search(command_part.split()[0]):
            self.add_finding(
                "LOW",
                "Relative path usage",
                "Job uses relative paths which can be unreliable and potentially insecure",
                job_line, user, file_path
            )
        
        # Check for network commands
        if self.security_patterns['network_commands'].search(command_part):
            self.add_finding(
                "INFO",
                "Network command detected",
                "Job contains network-related commands that may require monitoring",
                job_line, user, file_path
            )
        
        # Check if running as root with high-risk commands
        if user == 'root' and any(cmd in command_part.lower() for cmd in ['rm', 'chmod', 'chown', 'mv']):
            self.add_finding(
                "MEDIUM",
                "Root user executing file system commands",
                "Root user is executing potentially destructive file system commands",
                job_line, user, file_path
            )
        
        # Check for missing PATH or using system paths
        if not self.security_patterns['root_paths'].match(command_part.split()[0]):
            if '/' not in command_part.split()[0]:  # Command without path
                self.add_finding(
                    "LOW",
                    "Command without absolute path",
                    "Command relies on PATH variable which could be manipulated",
                    job_line, user, file_path
                )
    
    def extract_command_from_cron_line(self, line: str) -> str:
        """
        Extract the command portion from a cron job line.
        
        Args:
            line (str): Full cron job line
            
        Returns:
            str: Command portion of the cron job
        """
        parts = line.strip().split()
        if len(parts) < 6:
            return ""
        
        # Standard cron format: minute hour day month weekday command
        # Skip first 5 fields (time specification)
        return ' '.join(parts[5:])
    
    def audit_cron_file(self, file_path: str, user: str = "") -> None:
        """
        Audit a specific cron file.
        
        Args:
            file_path (str): Path to the cron file
            user (str): User associated with the cron file
        """
        try:
            if not os.path.exists(file_path):
                self.log(f"File not found: {file_path}", "WARNING")
                return
            
            self.log(f"Auditing cron file: {file_path}")
            self.check_file_permissions(file_path)
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        self.analyze_cron_job(line, user, file_path)
                    except Exception as e:
                        self.log(f"Error analyzing line {line_num} in {file_path}: {e}", "ERROR")
                        
        except PermissionError:
            self.log(f"Permission denied accessing {file_path}", "ERROR")
        except Exception as e:
            self.log(f"Error reading {file_path}: {e}", "ERROR")
    
    def audit_user_crontab(self, username: str) -> None:
        """
        Audit a specific user's crontab.
        
        Args:
            username (str): Username to audit
        """
        try:
            result = subprocess.run(
                ['crontab', '-l', '-u', username],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self.log(f"Auditing crontab for user: {username}")
                for line in result.stdout.splitlines():
                    self.analyze_cron_job(line, username, f"/var/spool/cron/crontabs/{username}")
            else:
                self.log(f"No crontab found for user {username}", "INFO")
                
        except subprocess.TimeoutExpired:
            self.log(f"Timeout while accessing crontab for {username}", "ERROR")
        except Exception as e:
            self.log(f"Error accessing crontab for {username}: {e}", "ERROR")
    
    def audit_system_crontabs(self) -> None:
        """Audit all system-wide crontab files."""
        system_cron_paths = [
            '/etc/crontab',
            '/etc/cron.d/',
            '/etc/cron.hourly/',
            '/etc/cron.daily/',
            '/etc/cron.weekly/',
            '/etc/cron.monthly/'
        ]
        
        for path in system_cron_paths:
            if os.path.isfile(path):
                self.audit_cron_file(path, 'root')
            elif os.path.isdir(path):
                try:
                    for file_name in os.listdir(path):
                        file_path = os.path.join(path, file_name)
                        if os.path.isfile(file_path):
                            self.audit_cron_file(file_path, 'root')
                except PermissionError:
                    self.log(f"Permission denied accessing directory {path}", "ERROR")
    
    def audit_all_user_crontabs(self) -> None:
        """Audit crontabs for all system users."""
        try:
            # Get list of all users
            users = [user.pw_name for user in pwd.getpwall() if user.pw_uid >= 1000 or user.pw_name == 'root']
            
            for username in users:
                self.audit_user_crontab(username)
                
        except Exception as e:
            self.log(f"Error getting user list: {e}", "ERROR")
    
    def generate_report(self, format_type: str = "text") -> Union[str, Dict]:
        """
        Generate a security audit report.
        
        Args:
            format_type (str): Output format ('text' or 'json')
            
        Returns:
            Union[str, Dict]: Formatted report
        """
        if format_type.lower() == "json":
            return {
                'summary': self.statistics,
                'findings': self.findings,
                'generated_at': datetime.now().isoformat(),
                'total_findings': len(self.findings)
            }
        
        # Text format
        report = []
        report.append("=" * 60)
        report.append("CRONJOB SECURITY AUDIT REPORT")
        report.append("=" * 60)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Summary
        report.append("SUMMARY:")
        report.append(f"  Total Jobs Analyzed: {self.statistics['total_jobs']}")
        report.append(f"  Total Findings: {len(self.findings)}")
        report.append(f"  High Risk: {self.statistics['high_risk']}")
        report.append(f"  Medium Risk: {self.statistics['medium_risk']}")
        report.append(f"  Low Risk: {self.statistics['low_risk']}")
        report.append(f"  Informational: {self.statistics['info']}")
        report.append("")
        
        # Detailed findings
        if self.findings:
            report.append("DETAILED FINDINGS:")
            report.append("-" * 40)
            
            for i, finding in enumerate(self.findings, 1):
                report.append(f"{i}. [{finding['severity']}] {finding['title']}")
                report.append(f"   Description: {finding['description']}")
                if finding['user']:
                    report.append(f"   User: {finding['user']}")
                if finding['file_path']:
                    report.append(f"   File: {finding['file_path']}")
                if finding['job_line']:
                    report.append(f"   Job: {finding['job_line']}")
                report.append("")
        else:
            report.append("No security issues found!")
        
        return "\n".join(report)


def main():
    """Main function to handle command-line arguments and execute the audit."""
    parser = argparse.ArgumentParser(
        description="Cronjob Security Auditor - Analyze cron configurations for security vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --system-wide                    # Audit all system crontabs
  %(prog)s --user john                      # Audit specific user's crontab
  %(prog)s --file /path/to/cronfile         # Audit custom cron file
  %(prog)s --all-users --verbose            # Audit all users with verbose output
  %(prog)s --system-wide --output report.json --format json  # JSON report
        """
    )
    
    # Audit scope options
    scope_group = parser.add_mutually_exclusive_group(required=True)
    scope_group.add_argument(
        '--system-wide',
        action='store_true',
        help='Audit system-wide crontab files (/etc/cron*)'
    )
    scope_group.add_argument(
        '--user',
        type=str,
        help='Audit specific user\'s crontab'
    )
    scope_group.add_argument(
        '--file',
        type=str,
        help='Audit specific cron file'
    )
    scope_group.add_argument(
        '--all-users',
        action='store_true',
        help='Audit all user crontabs'
    )
    
    # Output options
    parser.add_argument(
        '--output',
        type=str,
        help='Output file path for the report'
    )
    parser.add_argument(
        '--format',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Check if running with sufficient privileges for system audits
    if (args.system_wide or args.all_users) and os.geteuid() != 0:
        print("Warning: Running without root privileges. Some system files may not be accessible.")
        print("Consider running with sudo for complete system audit.")
        print()
    
    # Initialize auditor
    auditor = CronSecurityAuditor(verbose=args.verbose)
    
    try:
        # Perform audit based on selected scope
        if args.system_wide:
            auditor.audit_system_crontabs()
        elif args.user:
            auditor.audit_user_crontab(args.user)
        elif args.file:
            if not os.path.exists(args.file):
                print(f"Error: File '{args.file}' not found.")
                sys.exit(1)
            auditor.audit_cron_file(args.file)
        elif args.all_users:
            auditor.audit_all_user_crontabs()
        
        # Generate and output report
        report = auditor.generate_report(args.format)
        
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    if args.format.lower() == 'json':
                        json.dump(report, f, indent=2)
                    else:
                        f.write(report)
                print(f"Report saved to: {args.output}")
            except Exception as e:
                print(f"Error saving report: {e}")
                sys.exit(1)
        else:
            if args.format.lower() == 'json':
                print(json.dumps(report, indent=2))
            else:
                print(report)
        
        # Exit with appropriate code based on findings
        high_risk_count = auditor.statistics['high_risk']
        if high_risk_count > 0:
            sys.exit(2)  # High risk findings found
        elif len(auditor.findings) > 0:
            sys.exit(1)  # Other findings found
        else:
            sys.exit(0)  # No issues found
            
    except KeyboardInterrupt:
        print("\nAudit interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
