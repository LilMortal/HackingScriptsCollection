# HackerOne Public Report Analyzer

A comprehensive Python tool for analyzing publicly disclosed vulnerability reports from HackerOne's bug bounty platform. This script fetches public reports via HackerOne's API and provides detailed statistical analysis including vulnerability types, severity distribution, bounty amounts, timeline trends, and program statistics.

## Features

- **Comprehensive Data Analysis**: Analyze vulnerability severity distribution, types, bounty statistics, and timeline trends
- **Flexible Filtering**: Filter reports by program, severity level, and date range
- **Multiple Output Formats**: Export results as JSON or CSV files
- **Rate Limiting**: Built-in rate limiting to respect API constraints
- **Command Line Interface**: Easy-to-use CLI with extensive options
- **Raw Data Export**: Option to save raw report data for further analysis
- **Statistical Insights**: Generate detailed statistics including averages, medians, and distributions

## Installation

### Prerequisites

- Python 3.6 or higher
- Internet connection for API access

### Dependencies

This script uses only Python standard libraries, so no external packages need to be installed:

- `argparse` - Command line argument parsing
- `json` - JSON data handling
- `urllib` - HTTP requests to HackerOne API
- `csv` - CSV file generation
- `datetime` - Date/time processing
- `collections` - Data structure utilities
- `typing` - Type hints

### Setup

1. **Download the Script**:
   ```bash
   # Download or clone the script
   wget https://raw.githubusercontent.com/your-repo/hackerone_analyzer.py
   # OR
   curl -O https://raw.githubusercontent.com/your-repo/hackerone_analyzer.py
   ```

2. **Make it Executable** (Linux/macOS):
   ```bash
   chmod +x hackerone_analyzer.py
   ```

3. **Verify Installation**:
   ```bash
   python3 hackerone_analyzer.py --help
   ```

## Usage

### Basic Usage

```bash
# Analyze 100 recent public reports
python3 hackerone_analyzer.py

# Analyze 500 reports with JSON output
python3 hackerone_analyzer.py --limit 500 --output json
```

### Advanced Usage Examples

```bash
# Filter by specific program
python3 hackerone_analyzer.py --program "twitter" --limit 200

# Filter by severity levels
python3 hackerone_analyzer.py --severity "critical,high" --limit 150

# Filter by date range
python3 hackerone_analyzer.py --date-range 2023-01-01 2023-12-31 --limit 300

# Save raw reports and analysis in CSV format
python3 hackerone_analyzer.py --limit 250 --save-reports --output csv

# Comprehensive analysis with trend analysis
python3 hackerone_analyzer.py --limit 1000 --analyze-trends --output both --save-reports

# Custom output directory and rate limiting
python3 hackerone_analyzer.py --limit 200 --output-dir ./results --rate-limit 2.0
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--limit` | Maximum number of reports to fetch | 100 |
| `--program` | Filter by specific program name | None |
| `--severity` | Filter by severity (none,low,medium,high,critical) | None |
| `--date-range` | Date range filter (YYYY-MM-DD YYYY-MM-DD) | None |
| `--output` | Output format (json, csv, both) | json |
| `--save-reports` | Save raw report data to JSON file | False |
| `--analyze-trends` | Include detailed timeline analysis | False |
| `--rate-limit` | Delay between API requests (seconds) | 1.0 |
| `--output-dir` | Directory for output files | Current directory |

## Output Files

The script generates several types of output files:

### Analysis Files
- `hackerone_analysis_TIMESTAMP.json` - Complete analysis in JSON format
- `hackerone_analysis_TIMESTAMP_severity.csv` - Severity distribution
- `hackerone_analysis_TIMESTAMP_vuln_types.csv` - Vulnerability types
- `hackerone_analysis_TIMESTAMP_programs.csv` - Program distribution

### Raw Data Files (if `--save-reports` is used)
- `hackerone_analysis_TIMESTAMP_raw_reports.json` - Raw report data

## Analysis Components

### 1. Severity Distribution
- Breakdown of reports by severity level (None, Low, Medium, High, Critical)
- Percentage distribution and counts

### 2. Vulnerability Types
- Analysis of vulnerability categories and weakness types
- Most common vulnerability patterns

### 3. Bounty Statistics
- Total bounty amounts and distribution
- Average, median, minimum, and maximum bounty values
- Currency distribution analysis

### 4. Timeline Trends
- Monthly and yearly report disclosure patterns
- Trend analysis over time periods

### 5. Program Analysis
- Distribution of reports across different bug bounty programs
- Most active programs by report volume

## Example Output

```
============================================================
HACKERONE PUBLIC REPORTS ANALYSIS SUMMARY
============================================================

Total Reports Analyzed: 250
Analysis Date: 2024-01-15T10:30:45

                SEVERITY DISTRIBUTION                
----------------------------------------
High            89 ( 35.6%)
Medium          76 ( 30.4%)
Critical        45 ( 18.0%)
Low             25 ( 10.0%)
None            15 (  6.0%)

              TOP VULNERABILITY TYPES              
----------------------------------------
Cross-site Scripting (XSS)     67 ( 26.8%)
SQL Injection                   34 ( 13.6%)
Cross-Site Request Forgery      28 ( 11.2%)
Information Disclosure          23 (  9.2%)
Server-Side Request Forgery     19 (  7.6%)
```

## Data Source and Limitations

### Data Source
- **API**: HackerOne Public Reports API (`https://hackerone.com/reports.json`)
- **Scope**: Only publicly disclosed reports are analyzed
- **Limitations**: API rate limits may affect large-scale analysis

### Important Notes
1. **Public Data Only**: This tool only accesses publicly disclosed reports
2. **Rate Limiting**: Built-in delays prevent API abuse
3. **Data Accuracy**: Analysis is based on data provided by HackerOne's API
4. **Historical Data**: Some older reports may have limited metadata

## Ethical Use and Responsible Disclosure

### Ethical Guidelines
- **Educational Purpose**: This tool is intended for security research and education
- **Responsible Use**: Do not use insights to exploit vulnerabilities
- **Privacy Respect**: Only analyzes publicly disclosed information
- **API Respect**: Built-in rate limiting respects HackerOne's resources

### Legal Considerations
- Only accesses publicly available information
- Complies with HackerOne's Terms of Service
- Does not attempt to access private or confidential data
- Users are responsible for compliance with local laws

## Troubleshooting

### Common Issues

1. **Network Errors**:
   ```
   Error: Network error: <urlopen error [Errno -2] Name or service not known>
   ```
   - Check internet connection
   - Verify HackerOne API accessibility

2. **Rate Limiting**:
   ```
   Warning: Request rate limited
   ```
   - Increase `--rate-limit` value
   - Reduce `--limit` for smaller datasets

3. **No Reports Found**:
   ```
   No reports found matching the specified criteria.
   ```
   - Adjust filter criteria
   - Check date range validity
   - Verify program name spelling

4. **Permission Errors**:
   ```
   Error saving reports to file: [Errno 13] Permission denied
   ```
   - Check directory write permissions
   - Use `--output-dir` for alternative location

### Performance Tips

- Use reasonable `--limit` values (100-1000) for balanced performance
- Increase `--rate-limit` if encountering API restrictions
- Use CSV output for large datasets to reduce file size
- Consider filtering by date range for focused analysis

## Development and Contributing

### Code Structure

The script follows Python best practices with:

- **Modular Design**: Separate classes and functions for different functionalities
- **Type Hints**: Comprehensive type annotations for better code maintainability
- **Error Handling**: Robust error handling for network and data processing issues
- **Documentation**: Detailed docstrings and comments throughout the code
- **PEP 8 Compliance**: Follows Python style guidelines

### Architecture Overview

```
HackerOneAnalyzer Class
├── fetch_public_reports()     # API interaction and data fetching
├── _filter_reports()          # Data filtering logic
├── analyze_severity_distribution()    # Severity analysis
├── analyze_vulnerability_types()      # Vulnerability categorization
├── analyze_bounty_statistics()        # Financial analysis
├── analyze_timeline_trends()          # Temporal analysis
├── analyze_programs()                 # Program distribution
├── generate_comprehensive_report()    # Main analysis orchestration
├── save_reports_to_file()            # Raw data export
└── save_analysis_to_csv()            # CSV export functionality
```

### Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the Repository**
2. **Create a Feature Branch**: `git checkout -b feature/new-analysis`
3. **Follow Code Style**: Maintain PEP 8 compliance
4. **Add Tests**: Include appropriate test cases
5. **Update Documentation**: Update README for new features
6. **Submit Pull Request**: Provide clear description of changes

### Feature Requests

Potential enhancements and feature requests:

- **Visualization**: Add matplotlib/plotly integration for charts
- **Database Storage**: PostgreSQL/SQLite integration for persistent storage
- **Advanced Filtering**: More sophisticated filtering options
- **Export Formats**: Additional export formats (Excel, PDF reports)
- **Scheduled Analysis**: Cron job integration for automated analysis
- **API Authentication**: Support for authenticated API access
- **Machine Learning**: Vulnerability prediction and clustering analysis

## Version History

### Version 1.0.0 (Current)
- Initial release with core functionality
- Basic statistical analysis
- JSON and CSV export capabilities
- Command-line interface
- Rate limiting and error handling

### Planned Features (Future Versions)
- **v1.1.0**: Visualization capabilities with charts and graphs
- **v1.2.0**: Database integration and persistent storage
- **v1.3.0**: Advanced filtering and search capabilities
- **v2.0.0**: Machine learning integration for predictive analysis

## API Reference

### HackerOneAnalyzer Class Methods

#### `fetch_public_reports(limit, program, severity, date_range)`
Fetches public reports from HackerOne API with filtering options.

**Parameters:**
- `limit` (int): Maximum number of reports to fetch
- `program` (str, optional): Program name filter
- `severity` (list, optional): Severity level filters
- `date_range` (tuple, optional): Date range filter (start, end)

**Returns:** List of report dictionaries

#### `analyze_severity_distribution(reports)`
Analyzes the distribution of vulnerability severities.

**Parameters:**
- `reports` (list): List of report dictionaries

**Returns:** Dictionary mapping severity levels to counts

#### `analyze_bounty_statistics(reports)`
Analyzes bounty payment statistics.

**Parameters:**
- `reports` (list): List of report dictionaries

**Returns:** Dictionary containing comprehensive bounty statistics

## Data Schema

### Report Structure
Each report contains the following key fields:
```json
{
  "id": "report_id",
  "title": "Vulnerability Title",
  "severity": "high",
  "disclosed_at": "2024-01-15T10:30:45.000Z",
  "bounty_amount": 1500.0,
  "bounty_currency": "USD",
  "team": {
    "name": "program_name"
  },
  "weakness": {
    "name": "Cross-site Scripting (XSS)"
  }
}
```

### Analysis Output Schema
```json
{
  "summary": {
    "total_reports": 250,
    "analysis_date": "2024-01-15T10:30:45",
    "data_source": "HackerOne Public Reports API"
  },
  "severity_distribution": {
    "High": 89,
    "Medium": 76
  },
  "vulnerability_types": {
    "Cross-site Scripting (XSS)": 67
  },
  "bounty_statistics": {
    "total_reports_with_bounty": 180,
    "average_bounty": 856.75
  }
}
```

## Security Considerations

### Data Privacy
- **Public Data Only**: Only processes publicly disclosed information
- **No Sensitive Data**: Does not access or store sensitive information
- **Local Processing**: All analysis performed locally

### API Security
- **Rate Limiting**: Respects API rate limits to prevent abuse
- **Error Handling**: Graceful handling of API errors and timeouts
- **User Agent**: Identifies requests appropriately

### File Security
- **Safe File Operations**: Validates file paths and handles permissions
- **Data Sanitization**: Cleans data before processing and storage
- **Secure Defaults**: Uses secure default configurations

## FAQ

### General Questions

**Q: How often is the data updated?**
A: The script fetches real-time data from HackerOne's public API, so results reflect the most current publicly disclosed reports.

**Q: Can I analyze private reports?**
A: No, this tool only accesses publicly disclosed reports available through HackerOne's public API.

**Q: What's the maximum number of reports I can analyze?**
A: There's no hard limit, but practical limits depend on API rate limiting and processing time. Start with smaller datasets (100-500 reports) for testing.

### Technical Questions

**Q: Why am I getting network errors?**
A: Network errors can occur due to connectivity issues, API maintenance, or rate limiting. Try reducing the request rate with `--rate-limit 2.0` or higher.

**Q: How can I speed up the analysis?**
A: Use smaller datasets, filter by specific criteria (program, date range), and ensure stable network connectivity.

**Q: Can I run this on a schedule?**
A: Yes, you can use cron jobs (Linux/macOS) or Task Scheduler (Windows) to run periodic analyses.

### Data Questions

**Q: Are bounty amounts accurate?**
A: Bounty amounts reflect what's reported in the public disclosure. Some reports may not include bounty information.

**Q: Why do some reports show 'Unknown' categories?**
A: This occurs when reports don't include complete metadata or use non-standard categorization.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

```
MIT License

Copyright (c) 2024 HackerOne Public Report Analyzer

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Disclaimer

This tool is provided for educational and research purposes only. Users are responsible for:

- Complying with HackerOne's Terms of Service
- Respecting API rate limits and usage policies
- Using the information responsibly and ethically
- Following applicable laws and regulations in their jurisdiction

The authors are not responsible for any misuse of this tool or any consequences arising from its use.

## Support and Contact

### Getting Help

1. **Check Documentation**: Review this README and the script's help output
2. **Search Issues**: Look for similar issues in the project repository
3. **Create Issue**: Submit detailed bug reports or feature requests
4. **Community Support**: Join security research communities for broader discussions

### Reporting Issues

When reporting issues, please include:

- Python version (`python3 --version`)
- Operating system and version
- Full command used
- Complete error message
- Expected vs. actual behavior

### Feature Requests

We welcome feature requests! Please provide:

- Clear description of the proposed feature
- Use case and rationale
- Potential implementation approach
- Willingness to contribute to development

---

**Happy Bug Bounty Analysis!** 🐛🔍

For the latest updates and additional resources, visit the project repository.