# Session ID Entropy Checker

A comprehensive Python tool for analyzing the entropy and security characteristics of session identifiers. This tool helps security professionals, developers, and system administrators assess whether their session IDs provide adequate randomness and security against prediction attacks.

## Features

- **Shannon Entropy Analysis**: Calculate the information entropy of session IDs
- **Character Distribution Analysis**: Analyze character usage patterns and diversity
- **Security Assessment**: Comprehensive scoring system (0-100) with security levels
- **Pattern Detection**: Identify predictable patterns and weaknesses
- **Encoding Detection**: Automatically detect likely encoding schemes (hex, base64, etc.)
- **Batch Analysis**: Process multiple session IDs from files
- **Secure ID Generation**: Generate cryptographically secure session IDs for comparison
- **Flexible Output**: Console output, JSON export, verbose and quiet modes
- **Customizable Thresholds**: Adjust minimum entropy and length requirements

## Installation

### Prerequisites

- Python 3.6 or higher
- No external dependencies required (uses only standard library)

### Quick Install

1. Download the script:
   ```bash
   wget https://raw.githubusercontent.com/your-repo/session-entropy-checker/main/session_entropy_checker.py
   ```

2. Make it executable:
   ```bash
   chmod +x session_entropy_checker.py
   ```

3. Run it:
   ```bash
   python3 session_entropy_checker.py --help
   ```

### Alternative Installation

Clone the repository:
```bash
git clone https://github.com/your-repo/session-entropy-checker.git
cd session-entropy-checker
python3 session_entropy_checker.py --help
```

## Usage

### Basic Usage

#### Analyze a Single Session ID
```bash
python3 session_entropy_checker.py --session-id "abc123def456ghi789"
```

#### Analyze Multiple Session IDs from a File
```bash
python3 session_entropy_checker.py --file session_ids.txt
```

#### Generate and Analyze Secure Session IDs
```bash
python3 session_entropy_checker.py --generate 100 --length 32
```

### Advanced Usage

#### Custom Security Thresholds
```bash
python3 session_entropy_checker.py --file sessions.txt --min-entropy 4.0 --min-length 24
```

#### Verbose Output with Detailed Analysis
```bash
python3 session_entropy_checker.py --file sessions.txt --verbose
```

#### Export Results to JSON
```bash
python3 session_entropy_checker.py --file sessions.txt --output results.json
```

#### Quiet Mode (Summary Only)
```bash
python3 session_entropy_checker.py --file sessions.txt --quiet
```

### File Format

When using the `--file` option, create a text file with one session ID per line:

```
abc123def456
SESSIONID_8a7b6c5d4e3f2g1h
base64encodedstring==
0123456789abcdef
# This is a comment and will be ignored
another-session-id-here
```

## Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--session-id` | `-s` | Single session ID to analyze |
| `--file` | `-f` | File containing session IDs (one per line) |
| `--generate` | `-g` | Generate and analyze COUNT secure session IDs |
| `--min-entropy` | | Minimum acceptable entropy per character (default: 3.5) |
| `--min-length` | | Minimum acceptable session ID length (default: 16) |
| `--length` | | Length for generated session IDs (default: 32) |
| `--verbose` | `-v` | Show detailed analysis for all session IDs |
| `--output` | `-o` | Save results to JSON file |
| `--quiet` | `-q` | Only show summary statistics |
| `--help` | `-h` | Show help message and exit |

## Security Assessment Criteria

The tool evaluates session IDs based on multiple factors:

### Security Levels

- **STRONG** (80-100 points): Highly secure, meets all best practices
- **MODERATE** (60-79 points): Acceptable security with minor issues
- **WEAK** (40-59 points): Multiple security concerns present
- **VERY WEAK** (0-39 points): Critical security vulnerabilities

### Scoring Factors

1. **Length** (0-25 points)
   - 32+ characters: 25 points
   - 16+ characters: 15 points
   - 8+ characters: 10 points
   - <8 characters: 0 points

2. **Entropy** (0-30 points)
   - 4.5+ bits/char: 30 points
   - 3.5+ bits/char: 20 points
   - 2.0+ bits/char: 10 points
   - <2.0 bits/char: 0 points

3. **Character Diversity** (0-20 points)
   - Based on ratio of unique characters to total length

4. **Pattern Detection** (0-15 points)
   - Penalizes predictable patterns and excessive repetition

5. **Character Set Usage** (0-10 points)
   - Rewards use of multiple character sets

## Understanding the Output

### Sample Output

```
==============================
SESSION ID ENTROPY ANALYSIS RESULTS
==============================

SUMMARY:
Total Session IDs Analyzed: 5
Strong Security: 2 (40.0%)
Moderate Security: 1 (20.0%)
Weak Security: 2 (40.0%)

WEAK SESSION IDs FOUND (2):
----------------------------------------
• abc123 - VERY WEAK (25/100)
  Issues: Session ID too short (6 chars); Low entropy (2.58 bits per char)
• password123 - WEAK (35/100)
  Issues: Patterns or excessive repetition detected
```

### Detailed Analysis Fields

When using `--verbose`, each session ID shows:

- **Security Level**: Overall assessment and numerical score
- **Entropy**: Shannon entropy in bits per character
- **Length**: Total character count
- **Unique Characters**: Number of distinct characters used
- **Character Sets**: Types of characters detected (lowercase, digits, etc.)
- **Encoding Guess**: Likely encoding scheme (hex, base64, etc.)
- **Issues**: Specific security problems identified
- **Recommendations**: Suggestions for improvement

## Best Practices for Session IDs

Based on the analysis, here are recommended practices:

1. **Minimum Length**: Use at least 16 characters, preferably 32+
2. **High Entropy**: Target 3.5+ bits per character (4.5+ for high security)
3. **Character Diversity**: Use mixed character sets (letters, numbers, symbols)
4. **Avoid Patterns**: No predictable sequences or repetitive characters
5. **Cryptographic Generation**: Use secure random number generators
6. **Regular Rotation**: Implement session timeout and regeneration

## Example Session ID Analysis

```bash
# Weak session ID
python3 session_entropy_checker.py --session-id "user123session"

# Output:
# Security Level: WEAK (45/100)
# Entropy: 3.12 bits per character
# Issues: Low entropy; Limited character set usage
# Recommendations: Increase randomness; Use mixed character sets

# Strong session ID
python3 session_entropy_checker.py --session-id "7Kj9mN4pQ8xR2vL6sT3nH9cB5fG1dA"

# Output:
# Security Level: STRONG (85/100)
# Entropy: 4.73 bits per character
# No issues detected
```

## Limitations and Considerations

### Limitations

- **Static Analysis Only**: Cannot detect runtime vulnerabilities or implementation flaws
- **Pattern Recognition**: May not catch all sophisticated attack patterns
- **Context Unaware**: Doesn't consider specific application requirements
- **Historical Analysis**: Cannot assess session lifecycle or rotation practices

### Ethical Use

This tool is intended for:
- ✅ Auditing your own systems and applications
- ✅ Educational and research purposes
- ✅ Security testing with proper authorization
- ✅ Compliance and security assessments

This tool should NOT be used for:
- ❌ Unauthorized analysis of third-party systems
- ❌ Attempting to predict or crack active sessions
- ❌ Any illegal or unethical activities

### Security Notes

- Session ID strength is just one aspect of session security
- Consider additional protections: HTTPS, secure cookies, CSRF protection
- Implement proper session management: timeouts, regeneration, secure storage
- Regular security audits and penetration testing are recommended

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

```
MIT License

Copyright (c) 2025 Session ID Entropy Checker

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

## Changelog

### Version 1.0.0
- Initial release
- Shannon entropy calculation
- Character distribution analysis
- Security assessment scoring
- Pattern detection
- Batch processing support
- JSON export functionality
- Secure session ID generation

## Support

For support, questions, or issues:

- **GitHub Issues**: Submit bug reports and feature requests
- **Documentation**: Check this README and inline code comments
- **Security Issues**: Report security vulnerabilities privately

## Troubleshooting

### Common Issues

#### "No valid session IDs found in file"
- Ensure your file contains at least one non-empty, non-comment line
- Check file encoding (should be UTF-8)
- Verify file path is correct

#### "FileNotFoundError"
- Check that the specified file exists
- Verify you have read permissions for the file
- Use absolute path if relative path doesn't work

#### Low entropy warnings on seemingly random strings
- Some patterns may not be as random as they appear
- Consider the generation method used
- Check for repeated characters or predictable sequences

### Performance Notes

- Large files (>10,000 session IDs) may take several minutes to process
- Use `--quiet` mode for faster processing of large datasets
- JSON output generation adds minimal overhead

## Related Tools

- **OpenSSL**: `openssl rand -base64 32` for generating secure random strings
- **OWASP ZAP**: Web application security testing
- **Burp Suite**: Professional web vulnerability scanner
- **hashcat**: Password recovery tool (for testing session ID strength)

## References

- [OWASP Session Management Cheat Sheet](https://owasp.org/www-project-cheat-sheets/cheatsheets/Session_Management_Cheat_Sheet.html)
- [RFC 4086: Randomness Requirements for Security](https://tools.ietf.org/html/rfc4086)
- [NIST SP 800-90A: Recommendation for Random Number Generation](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
- [Shannon Entropy on Wikipedia](https://en.wikipedia.org/wiki/Entropy_(information_theory))

---

**Disclaimer**: This tool is provided for educational and legitimate security testing purposes only. Users are responsible for ensuring their use complies with applicable laws and regulations. The authors assume no liability for misuse of this software.
