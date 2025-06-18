# Password Strength Analyzer

A comprehensive Python tool for analyzing password strength and security based on multiple criteria including length, character variety, entropy calculation, pattern detection, and common password checking.

## Features

- **Comprehensive Analysis**: Evaluates passwords based on length, character variety, entropy, and patterns
- **Multiple Input Methods**: Direct input, interactive mode, or batch processing from files
- **Detailed Scoring**: 0-100 strength score with clear strength levels
- **Security Recommendations**: Specific suggestions for password improvement
- **Pattern Detection**: Identifies common weak patterns like sequential characters and keyboard patterns
- **Crack Time Estimation**: Estimates how long it would take to crack the password
- **Flexible Output**: Standard text output or JSON format for integration
- **Batch Processing**: Analyze multiple passwords from a file
- **Secure Input**: Interactive mode with hidden password input

## Installation

### Requirements

- Python 3.6 or higher
- No external dependencies required (uses only standard library)

### Setup

1. Download the `password_analyzer.py` script
2. Make it executable (optional):
   ```bash
   chmod +x password_analyzer.py
   ```

## Usage

### Basic Usage

Analyze a single password directly:
```bash
python password_analyzer.py "mypassword123"
```

### Interactive Mode

Enter password securely (hidden input):
```bash
python password_analyzer.py --interactive
```

### Batch Analysis

Analyze multiple passwords from a file:
```bash
python password_analyzer.py --file passwords.txt
```

### Detailed Analysis

Get verbose output with detailed breakdown:
```bash
python password_analyzer.py "mypassword123" --verbose
```

### JSON Output

Output results in JSON format:
```bash
python password_analyzer.py "mypassword123" --json
```

### Save Results

Save analysis results to a file:
```bash
python password_analyzer.py "mypassword123" --output results.txt
```

## Command Line Arguments

### Input Options (mutually exclusive)
- `password`: Password to analyze (positional argument)
- `--interactive`, `-i`: Enter password interactively with hidden input
- `--file FILE`, `-f FILE`: Analyze passwords from file (one per line)

### Output Options
- `--verbose`, `-v`: Show detailed analysis including character composition and patterns
- `--json`, `-j`: Output results in JSON format
- `--output FILE`, `-o FILE`: Save results to specified file

### Help
- `--help`, `-h`: Show help message and exit

## Analysis Criteria

The tool evaluates passwords based on the following criteria:

### 1. Length Analysis
- **Minimum**: 8+ characters recommended
- **Optimal**: 12+ characters for strong security
- **Scoring**: Longer passwords receive higher scores

### 2. Character Variety
- **Lowercase letters** (a-z)
- **Uppercase letters** (A-Z)
- **Numbers** (0-9)
- **Special characters** (!@#$%^&*()_+-=[]{}|;:,.<>?~`)
- **Scoring**: More character types = higher security

### 3. Entropy Calculation
- Measures password randomness in bits
- Higher entropy = harder to crack
- Considers character space and password length

### 4. Pattern Detection
- Sequential characters (abc, 123, qwerty)
- Repeated character sequences (aaa, 111)
- Keyboard patterns (asdf, qwerty)
- Common character substitutions (@, 3, !)

### 5. Common Password Check
- Checks against database of common weak passwords
- Flags commonly used passwords

## Strength Levels

- **Very Strong** (80-100): Excellent security, meets all criteria
- **Strong** (60-79): Good security with minor improvements possible
- **Moderate** (40-59): Adequate but needs strengthening
- **Weak** (20-39): Poor security, significant improvements needed
- **Very Weak** (0-19): Extremely vulnerable, complete overhaul required

## Example Output

### Standard Output
```
==================================================
PASSWORD STRENGTH ANALYSIS
==================================================
Strength Level: Moderate
Strength Score: 45/100
Estimated Crack Time: Days to weeks

RECOMMENDATIONS:
1. Increase password length to at least 12 characters
2. Add special characters (!@#$%^&*)
3. Avoid sequential characters (abc, 123)
```

### Verbose Output
```
==================================================
PASSWORD STRENGTH ANALYSIS
==================================================
Strength Level: Strong
Strength Score: 72/100
Estimated Crack Time: Months to years

DETAILED ANALYSIS:
Password Length: 14 characters
Entropy: 52.68 bits
Unique Characters: 12
Common Password: No

CHARACTER COMPOSITION:
Lowercase Letters: ✓
Uppercase Letters: ✓
Numbers: ✓
Special Characters: ✓

RECOMMENDATIONS:
No specific recommendations - password meets security criteria!
```

## File Format for Batch Analysis

Create a text file with one password per line:
```
password123
MySecureP@ssw0rd!
weakpass
AnotherPassword2023!
```

## Security Notes

- **Ethical Use Only**: This tool is intended for legitimate password security assessment
- **No Data Storage**: Passwords are not stored or transmitted anywhere
- **Local Analysis**: All analysis is performed locally on your machine
- **Interactive Mode**: Use interactive mode for sensitive passwords to avoid command history

## Limitations

- **Pattern Database**: Limited to common patterns; may not detect all weak patterns
- **Common Passwords**: Contains a subset of common passwords, not exhaustive
- **Crack Time Estimates**: Based on theoretical calculations; actual times may vary
- **Context Unaware**: Cannot assess password reuse or account-specific requirements

## Integration

The tool can be easily integrated into other systems:

### JSON Output Example
```json
{
  "password_length": 12,
  "character_analysis": {
    "has_lowercase": true,
    "has_uppercase": true,
    "has_digits": true,
    "has_special": true,
    "unique_chars": 10,
    "char_variety_score": 4
  },
  "entropy": 47.63,
  "strength_score": 68,
  "strength_level": "Strong",
  "is_common": false,
  "estimated_crack_time": "Months to years",
  "recommendations": []
}
```

## Contributing

Contributions are welcome! Please consider:
- Adding more sophisticated pattern detection
- Expanding the common password database
- Improving entropy calculations
- Adding support for additional languages/character sets

## License

MIT License

Copyright (c) 2024 Password Strength Analyzer

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

## Changelog

### Version 1.0.0
- Initial release
- Basic password strength analysis
- Multiple input methods
- JSON output support
- Batch processing capabilities
- Comprehensive documentation

## Support

For issues, questions, or contributions, please refer to the script's documentation or create an issue in the project repository.
