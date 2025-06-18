#!/usr/bin/env python3
"""
HackerOne Public Report Analyzer

A comprehensive tool for analyzing publicly disclosed vulnerability reports from HackerOne.
This script fetches public reports via HackerOne's API and provides statistical analysis
including vulnerability types, severity distribution, bounty amounts, and timeline analysis.

Author: Security Research Tool
Version: 1.0.0
License: MIT

Usage Example:
    python hackerone_analyzer.py --limit 100 --output json --save-reports
    python hackerone_analyzer.py --program "example-program" --severity critical,high
    python hackerone_analyzer.py --date-range 2023-01-01 2023-12-31 --analyze-trends
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import csv
import os


class HackerOneAnalyzer:
    """
    Main class for analyzing HackerOne public reports.
    
    This class handles API interactions, data processing, and analysis
    of vulnerability reports from HackerOne's public disclosure API.
    """
    
    BASE_URL = "https://hackerone.com/reports.json"
    
    def __init__(self, rate_limit_delay: float = 1.0):
        """
        Initialize the analyzer with rate limiting.
        
        Args:
            rate_limit_delay: Delay between API requests to respect rate limits
        """
        self.rate_limit_delay = rate_limit_delay
        self.reports_cache = []
        
    def fetch_public_reports(self, 
                           limit: int = 100, 
                           program: Optional[str] = None,
                           severity: Optional[List[str]] = None,
                           date_range: Optional[Tuple[str, str]] = None) -> List[Dict[str, Any]]:
        """
        Fetch public reports from HackerOne API with filtering options.
        
        Args:
            limit: Maximum number of reports to fetch
            program: Specific program to filter by
            severity: List of severity levels to filter by
            date_range: Tuple of (start_date, end_date) in YYYY-MM-DD format
            
        Returns:
            List of report dictionaries
            
        Raises:
            ValueError: If API request fails or returns invalid data
        """
        print(f"Fetching public reports from HackerOne (limit: {limit})...")
        
        reports = []
        page = 1
        per_page = min(100, limit)  # HackerOne API typically limits to 100 per page
        
        while len(reports) < limit:
            try:
                # Build URL with parameters
                params = {
                    'page': page,
                    'per_page': per_page
                }
                
                if program:
                    params['program'] = program
                    
                url = f"{self.BASE_URL}?{urllib.parse.urlencode(params)}"
                
                print(f"Fetching page {page}...")
                
                # Make API request with error handling
                request = urllib.request.Request(url)
                request.add_header('User-Agent', 'HackerOne-Public-Report-Analyzer/1.0')
                
                with urllib.request.urlopen(request, timeout=30) as response:
                    if response.status != 200:
                        raise ValueError(f"API request failed with status {response.status}")
                    
                    data = json.loads(response.read().decode('utf-8'))
                    
                    if not isinstance(data, dict) or 'reports' not in data:
                        raise ValueError("Invalid API response format")
                    
                    page_reports = data['reports']
                    
                    if not page_reports:
                        break  # No more reports available
                    
                    # Apply filters
                    filtered_reports = self._filter_reports(page_reports, severity, date_range)
                    reports.extend(filtered_reports)
                    
                    # Check if we've reached the limit
                    if len(reports) >= limit:
                        reports = reports[:limit]
                        break
                    
                    page += 1
                    
                    # Rate limiting
                    time.sleep(self.rate_limit_delay)
                    
            except urllib.error.URLError as e:
                print(f"Network error: {e}")
                break
            except json.JSONDecodeError as e:
                print(f"JSON parsing error: {e}")
                break
            except Exception as e:
                print(f"Unexpected error: {e}")
                break
        
        self.reports_cache = reports
        print(f"Successfully fetched {len(reports)} reports")
        return reports
    
    def _filter_reports(self, 
                       reports: List[Dict[str, Any]], 
                       severity: Optional[List[str]] = None,
                       date_range: Optional[Tuple[str, str]] = None) -> List[Dict[str, Any]]:
        """
        Apply filters to a list of reports.
        
        Args:
            reports: List of report dictionaries
            severity: List of severity levels to include
            date_range: Tuple of (start_date, end_date)
            
        Returns:
            Filtered list of reports
        """
        filtered = reports
        
        # Filter by severity
        if severity:
            severity_lower = [s.lower() for s in severity]
            filtered = [r for r in filtered 
                       if r.get('severity', '').lower() in severity_lower]
        
        # Filter by date range
        if date_range:
            start_date, end_date = date_range
            try:
                start_dt = datetime.strptime(start_date, '%Y-%m-%d')
                end_dt = datetime.strptime(end_date, '%Y-%m-%d')
                
                filtered = []
                for report in reports:
                    disclosed_at = report.get('disclosed_at')
                    if disclosed_at:
                        try:
                            report_date = datetime.strptime(disclosed_at[:10], '%Y-%m-%d')
                            if start_dt <= report_date <= end_dt:
                                filtered.append(report)
                        except (ValueError, TypeError):
                            continue
            except ValueError:
                print("Warning: Invalid date format. Expected YYYY-MM-DD")
        
        return filtered
    
    def analyze_severity_distribution(self, reports: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Analyze the distribution of vulnerability severities.
        
        Args:
            reports: List of report dictionaries
            
        Returns:
            Dictionary mapping severity levels to counts
        """
        severity_counts = Counter()
        
        for report in reports:
            severity = report.get('severity', 'Unknown')
            if severity:
                severity_counts[severity.title()] += 1
            else:
                severity_counts['Unknown'] += 1
        
        return dict(severity_counts)
    
    def analyze_vulnerability_types(self, reports: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Analyze the distribution of vulnerability types/categories.
        
        Args:
            reports: List of report dictionaries
            
        Returns:
            Dictionary mapping vulnerability types to counts
        """
        vuln_types = Counter()
        
        for report in reports:
            # Check various fields that might contain vulnerability type information
            weakness = report.get('weakness', {})
            if isinstance(weakness, dict):
                name = weakness.get('name', 'Unknown')
                vuln_types[name] += 1
            else:
                vuln_types['Unknown'] += 1
        
        return dict(vuln_types)
    
    def analyze_bounty_statistics(self, reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze bounty payment statistics.
        
        Args:
            reports: List of report dictionaries
            
        Returns:
            Dictionary containing bounty statistics
        """
        bounties = []
        bounty_currency_counts = Counter()
        
        for report in reports:
            bounty_amount = report.get('bounty_amount')
            bounty_currency = report.get('bounty_currency', 'USD')
            
            if bounty_amount and isinstance(bounty_amount, (int, float)) and bounty_amount > 0:
                bounties.append(bounty_amount)
                bounty_currency_counts[bounty_currency] += 1
        
        if not bounties:
            return {
                'total_reports_with_bounty': 0,
                'total_bounty_amount': 0,
                'average_bounty': 0,
                'median_bounty': 0,
                'min_bounty': 0,
                'max_bounty': 0,
                'currency_distribution': dict(bounty_currency_counts)
            }
        
        bounties.sort()
        n = len(bounties)
        median = bounties[n//2] if n % 2 == 1 else (bounties[n//2-1] + bounties[n//2]) / 2
        
        return {
            'total_reports_with_bounty': len(bounties),
            'total_bounty_amount': sum(bounties),
            'average_bounty': sum(bounties) / len(bounties),
            'median_bounty': median,
            'min_bounty': min(bounties),
            'max_bounty': max(bounties),
            'currency_distribution': dict(bounty_currency_counts)
        }
    
    def analyze_timeline_trends(self, reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze timeline trends in vulnerability disclosures.
        
        Args:
            reports: List of report dictionaries
            
        Returns:
            Dictionary containing timeline analysis
        """
        monthly_counts = defaultdict(int)
        yearly_counts = defaultdict(int)
        
        for report in reports:
            disclosed_at = report.get('disclosed_at')
            if disclosed_at:
                try:
                    date_obj = datetime.strptime(disclosed_at[:10], '%Y-%m-%d')
                    month_key = date_obj.strftime('%Y-%m')
                    year_key = str(date_obj.year)
                    
                    monthly_counts[month_key] += 1
                    yearly_counts[year_key] += 1
                except (ValueError, TypeError):
                    continue
        
        return {
            'monthly_distribution': dict(monthly_counts),
            'yearly_distribution': dict(yearly_counts),
            'total_analyzed_reports': len(reports)
        }
    
    def analyze_programs(self, reports: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Analyze distribution of reports across different programs.
        
        Args:
            reports: List of report dictionaries
            
        Returns:
            Dictionary mapping program names to report counts
        """
        program_counts = Counter()
        
        for report in reports:
            program = report.get('team', {})
            if isinstance(program, dict):
                program_name = program.get('name', 'Unknown')
                program_counts[program_name] += 1
            else:
                program_counts['Unknown'] += 1
        
        return dict(program_counts)
    
    def generate_comprehensive_report(self, reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a comprehensive analysis report.
        
        Args:
            reports: List of report dictionaries
            
        Returns:
            Dictionary containing all analysis results
        """
        print("Generating comprehensive analysis...")
        
        analysis = {
            'summary': {
                'total_reports': len(reports),
                'analysis_date': datetime.now().isoformat(),
                'data_source': 'HackerOne Public Reports API'
            },
            'severity_distribution': self.analyze_severity_distribution(reports),
            'vulnerability_types': self.analyze_vulnerability_types(reports),
            'bounty_statistics': self.analyze_bounty_statistics(reports),
            'timeline_trends': self.analyze_timeline_trends(reports),
            'program_distribution': self.analyze_programs(reports)
        }
        
        return analysis
    
    def save_reports_to_file(self, reports: List[Dict[str, Any]], filename: str) -> None:
        """
        Save raw reports data to a JSON file.
        
        Args:
            reports: List of report dictionaries
            filename: Output filename
        """
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(reports, f, indent=2, ensure_ascii=False)
            print(f"Raw reports saved to {filename}")
        except IOError as e:
            print(f"Error saving reports to file: {e}")
    
    def save_analysis_to_csv(self, analysis: Dict[str, Any], base_filename: str) -> None:
        """
        Save analysis results to CSV files.
        
        Args:
            analysis: Analysis results dictionary
            base_filename: Base filename for CSV files
        """
        try:
            # Save severity distribution
            with open(f"{base_filename}_severity.csv", 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Severity', 'Count'])
                for severity, count in analysis['severity_distribution'].items():
                    writer.writerow([severity, count])
            
            # Save vulnerability types
            with open(f"{base_filename}_vuln_types.csv", 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Vulnerability Type', 'Count'])
                for vuln_type, count in analysis['vulnerability_types'].items():
                    writer.writerow([vuln_type, count])
            
            # Save program distribution
            with open(f"{base_filename}_programs.csv", 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Program', 'Report Count'])
                for program, count in analysis['program_distribution'].items():
                    writer.writerow([program, count])
            
            print(f"Analysis results saved to CSV files with prefix '{base_filename}'")
            
        except IOError as e:
            print(f"Error saving analysis to CSV: {e}")


def print_analysis_summary(analysis: Dict[str, Any]) -> None:
    """
    Print a formatted summary of the analysis results.
    
    Args:
        analysis: Analysis results dictionary
    """
    print("\n" + "="*60)
    print("HACKERONE PUBLIC REPORTS ANALYSIS SUMMARY")
    print("="*60)
    
    # Summary statistics
    summary = analysis['summary']
    print(f"\nTotal Reports Analyzed: {summary['total_reports']}")
    print(f"Analysis Date: {summary['analysis_date'][:19]}")
    
    # Severity distribution
    print(f"\n{'SEVERITY DISTRIBUTION':^40}")
    print("-" * 40)
    severity_dist = analysis['severity_distribution']
    for severity, count in sorted(severity_dist.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / summary['total_reports']) * 100
        print(f"{severity:<15} {count:>6} ({percentage:5.1f}%)")
    
    # Top vulnerability types
    print(f"\n{'TOP VULNERABILITY TYPES':^40}")
    print("-" * 40)
    vuln_types = analysis['vulnerability_types']
    top_vulns = sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:10]
    for vuln_type, count in top_vulns:
        percentage = (count / summary['total_reports']) * 100
        # Truncate long vulnerability type names
        vuln_display = vuln_type[:25] + "..." if len(vuln_type) > 28 else vuln_type
        print(f"{vuln_display:<28} {count:>6} ({percentage:5.1f}%)")
    
    # Bounty statistics
    print(f"\n{'BOUNTY STATISTICS':^40}")
    print("-" * 40)
    bounty_stats = analysis['bounty_statistics']
    if bounty_stats['total_reports_with_bounty'] > 0:
        print(f"Reports with Bounty: {bounty_stats['total_reports_with_bounty']}")
        print(f"Total Bounty Amount: ${bounty_stats['total_bounty_amount']:,.2f}")
        print(f"Average Bounty: ${bounty_stats['average_bounty']:,.2f}")
        print(f"Median Bounty: ${bounty_stats['median_bounty']:,.2f}")
        print(f"Min Bounty: ${bounty_stats['min_bounty']:,.2f}")
        print(f"Max Bounty: ${bounty_stats['max_bounty']:,.2f}")
    else:
        print("No bounty information available in analyzed reports")
    
    # Top programs
    print(f"\n{'TOP PROGRAMS':^40}")
    print("-" * 40)
    programs = analysis['program_distribution']
    top_programs = sorted(programs.items(), key=lambda x: x[1], reverse=True)[:10]
    for program, count in top_programs:
        percentage = (count / summary['total_reports']) * 100
        # Truncate long program names
        program_display = program[:25] + "..." if len(program) > 28 else program
        print(f"{program_display:<28} {count:>6} ({percentage:5.1f}%)")
    
    print("\n" + "="*60)


def main():
    """
    Main function to handle command line arguments and execute analysis.
    """
    parser = argparse.ArgumentParser(
        description="Analyze public vulnerability reports from HackerOne",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --limit 200 --output json
  %(prog)s --program "example-program" --severity critical,high
  %(prog)s --date-range 2023-01-01 2023-12-31 --save-reports
  %(prog)s --limit 500 --output csv --analyze-trends
        """
    )
    
    parser.add_argument(
        '--limit', 
        type=int, 
        default=100,
        help='Maximum number of reports to fetch (default: 100)'
    )
    
    parser.add_argument(
        '--program',
        type=str,
        help='Filter reports by specific program name'
    )
    
    parser.add_argument(
        '--severity',
        type=str,
        help='Filter by severity levels (comma-separated: none,low,medium,high,critical)'
    )
    
    parser.add_argument(
        '--date-range',
        nargs=2,
        metavar=('START_DATE', 'END_DATE'),
        help='Filter reports by date range (format: YYYY-MM-DD YYYY-MM-DD)'
    )
    
    parser.add_argument(
        '--output',
        choices=['json', 'csv', 'both'],
        default='json',
        help='Output format for analysis results (default: json)'
    )
    
    parser.add_argument(
        '--save-reports',
        action='store_true',
        help='Save raw report data to JSON file'
    )
    
    parser.add_argument(
        '--analyze-trends',
        action='store_true',
        help='Include detailed timeline trend analysis'
    )
    
    parser.add_argument(
        '--rate-limit',
        type=float,
        default=1.0,
        help='Delay between API requests in seconds (default: 1.0)'
    )
    
    parser.add_argument(
        '--output-dir',
        type=str,
        default='.',
        help='Directory to save output files (default: current directory)'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.limit <= 0:
        print("Error: Limit must be positive")
        sys.exit(1)
    
    severity_list = None
    if args.severity:
        severity_list = [s.strip() for s in args.severity.split(',')]
        valid_severities = {'none', 'low', 'medium', 'high', 'critical'}
        for sev in severity_list:
            if sev.lower() not in valid_severities:
                print(f"Error: Invalid severity '{sev}'. Valid options: {', '.join(valid_severities)}")
                sys.exit(1)
    
    date_range = None
    if args.date_range:
        try:
            # Validate date format
            datetime.strptime(args.date_range[0], '%Y-%m-%d')
            datetime.strptime(args.date_range[1], '%Y-%m-%d')
            date_range = tuple(args.date_range)
        except ValueError:
            print("Error: Invalid date format. Use YYYY-MM-DD")
            sys.exit(1)
    
    # Create output directory if it doesn't exist
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
    
    # Initialize analyzer
    analyzer = HackerOneAnalyzer(rate_limit_delay=args.rate_limit)
    
    try:
        # Fetch reports
        reports = analyzer.fetch_public_reports(
            limit=args.limit,
            program=args.program,
            severity=severity_list,
            date_range=date_range
        )
        
        if not reports:
            print("No reports found matching the specified criteria.")
            sys.exit(0)
        
        # Generate analysis
        analysis = analyzer.generate_comprehensive_report(reports)
        
        # Print summary to console
        print_analysis_summary(analysis)
        
        # Generate timestamp for filenames
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_filename = os.path.join(args.output_dir, f"hackerone_analysis_{timestamp}")
        
        # Save results based on output format
        if args.output in ['json', 'both']:
            with open(f"{base_filename}.json", 'w', encoding='utf-8') as f:
                json.dump(analysis, f, indent=2, ensure_ascii=False)
            print(f"\nAnalysis saved to {base_filename}.json")
        
        if args.output in ['csv', 'both']:
            analyzer.save_analysis_to_csv(analysis, base_filename)
        
        # Save raw reports if requested
        if args.save_reports:
            analyzer.save_reports_to_file(reports, f"{base_filename}_raw_reports.json")
        
        print(f"\nAnalysis complete! Processed {len(reports)} reports.")
        
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error during analysis: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
