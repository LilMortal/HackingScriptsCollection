# Local Git Repository Secret Scanner

A security tool for scanning your own local Git repositories to detect accidentally committed secrets, API keys, passwords, and other sensitive data.

## ⚠️ Important Notice

This tool is designed for scanning **your own repositories only**. It should be used as part of your security practices to identify and remediate accidentally committed secrets in your own codebase. Do not use this tool to scan repositories you don't own without explicit permission.

## Description

The Git Secret Scanner helps developers identify potential security issues in their local repositories by scanning for common patterns that might indicate exposed secrets such as:

- API keys and tokens (AWS, GitHub, Google, etc.)
- Database connection strings
- Private keys and certificates
- JWT tokens
- Passwords and other credentials
- Generic secret patterns

## Features

- 🔍 **Comprehensive Pattern Detection**: Detects various types of secrets using regex patterns
- 📊 **Multiple Output Formats**: Support for table and JSON output formats
- 🎯 **Severity Levels**: Categorizes findings by severity (critical, high, medium, low)
- 📁 **Smart File Filtering**: Automatically excludes binary files, dependencies, and common non-source files
- 🚫 **Customizable Exclusions**: Ability to exclude specific file patterns
- 📝 **Context Display**: Shows code context around detected secrets
- 💻 **Command Line Interface**: Easy to use CLI with comprehensive options

## Installation

### Prerequisites

- Python 3.6 or higher
- Git repository to scan

### Dependencies

This script uses only Python standard libraries, so no additional packages need to be installed.

### Setup

1. Download the script:
```bash
curl -O https://raw.githubusercontent.com/your-repo/git-secret-scanner.py
```

2. Make it executable:
```bash
chmod +x git_secret_scanner.py
```

## Usage

### Basic Usage

```bash
# Scan current directory (must be a Git repository)
python git_secret_scanner.py .

# Scan a specific repository
python git_secret_scanner.py /path/to/your/repo
```

### Advanced Usage

```bash
# Output as JSON to a file
python git_secret_scanner.py . --format json --output secrets_report.json

# Show only high and critical severity findings
python git_secret_scanner.py . --severity high

# Exclude specific file patterns
python git_secret_scanner.py . --exclude "*.log,*.tmp,test_*"

# Verbose mode with context
python git_secret_scanner.py . --verbose --show-context

# Combine multiple options
python git_secret_scanner.py /path/to/repo --format json --severity medium --exclude "*.min.js,dist/*" --output report.json
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `repository` | Path to the Git repository to scan (required) |
| `--format` | Output format: `table` (default) or `json` |
| `--output`, `-o` | Output file path (default: stdout) |
| `--exclude` | Comma-separated list of file patterns to exclude |
| `--severity` | Minimum severity level: `critical`, `high`, `medium`, `low` |
| `--show-context` | Show code context around matches (table format only) |
| `--verbose`, `-v` | Enable verbose output during scanning |

## Detected Secret Types

The scanner detects the following types of secrets:

### Critical Severity
- AWS Access Keys and Secret Keys
- Private Keys (RSA, SSH, etc.)

### High Severity
- GitHub Tokens
- Google API Keys
- Generic API Keys and Tokens
- JWT Tokens
- Slack Tokens
- Database URLs

### Medium Severity
- Database Connection Strings (MongoDB, MySQL)
- Password Fields

### Low Severity
- Generic Secret Patterns

## Output Examples

### Table Format (Default)
```
================================================================================
SECRET SCAN RESULTS
================================================================================

1. AWS Access Key (CRITICAL)
   File: config/settings.py:15
   Match: AKIAIOSFODNN7EXAMPLE
   Confidence: 95.0%

2. GitHub Token (HIGH)
   File: scripts/deploy.sh:8
   Match: ghp_1234567890abcdef1234567890abcdef12345678
   Confidence: 90.0%

Summary: 2 potential secrets found (1 critical, 1 high)
```

### JSON Format
```json
{
  "scan_timestamp": "2025-06-18T10:30:00.000000",
  "summary": {
    "total": 2,
    "by_severity": {
      "critical": 1,
      "high": 1
    },
    "by_type": {
      "AWS Access Key": 1,
      "GitHub Token": 1
    }
  },
  "findings": [
    {
      "file_path": "config/settings.py",
      "line_number": 15,
      "matched_text": "AKIAIOSFODNN7EXAMPLE",
      "secret_type": "AWS Access Key",
      "severity": "critical",
      "confidence": 0.95
    }
  ]
}
```

## Best Practices

1. **Run Before Commits**: Integrate this tool into your pre-commit hooks
2. **Regular Scans**: Periodically scan your repositories for secrets
3. **Review Results**: Always manually review findings as there may be false positives
4. **Remediation**: If secrets are found:
   - Remove them from the code
   - Rotate the compromised credentials
   - Consider using environment variables or secret management tools
   - Use `git filter-branch` or BFG Repo-Cleaner to remove from history

## Integration with CI/CD

You can integrate this scanner into your CI/CD pipeline:

```yaml
# Example GitHub Actions workflow
name: Secret Scan
on: [push, pull_request]
jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Scan for secrets
      run: |
        python git_secret_scanner.py . --format json --output secrets.json
        if [ -s secrets.json ]; then
          echo "Secrets detected! Check the artifacts."
          exit 1
        fi
```

## Limitations

- **Pattern-based Detection**: Uses regex patterns which may produce false positives
- **Local Scanning Only**: Only scans local file system, not remote repositories
- **File Type Limitations**: Some binary or encoded files may not be scanned properly
- **No Historical Analysis**: Only scans current file state, not git history

## False Positives

The scanner may flag:
- Example or dummy credentials in documentation
- Test data that resembles real secrets
- Encoded or hashed values that match patterns

Always review findings manually and use the `--exclude` option to skip files containing legitimate test data.

## Contributing

If you find bugs or want to add new secret patterns:

1. Fork the repository
2. Create a feature branch
3. Add new patterns to the `_initialize_patterns()` method
4. Test thoroughly to minimize false positives
5. Submit a pull request

## Security Considerations

- This tool is for defensive security purposes only
- Only scan repositories you own or have explicit permission to scan
- Be careful when sharing scan results as they may contain actual secrets
- Consider the sensitivity of your scan outputs and store them securely

## License

MIT License

Copyright (c) 2025

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

## Disclaimer

This tool is provided for educational and security improvement purposes. Users are responsible for ensuring they have proper authorization before scanning any repositories. The authors are not responsible for any misuse of this tool.
