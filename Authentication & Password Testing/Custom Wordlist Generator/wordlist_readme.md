# CustomWordlistGenerator

A comprehensive Python script for generating custom wordlists with various transformation rules and patterns. This tool is designed for security professionals, penetration testers, and researchers who need to create targeted wordlists for legitimate security testing purposes.

## Features

- **Multiple Input Sources**: Load words from files or specify them directly via command line
- **Transformation Rules**: Apply various transformations including:
  - Case variations (lowercase, uppercase, capitalize, title case)
  - Leet speak substitutions
  - Number appending and prepending
  - Word combinations with separators
- **Pattern-Based Generation**: Generate words based on patterns using wildcards
- **Filtering Options**: Set minimum/maximum word lengths and output limits
- **Duplicate Removal**: Automatically removes duplicate entries
- **Memory Efficient**: Uses iterators to handle large wordlists efficiently
- **Comprehensive Logging**: Detailed logging with verbose mode

## Installation

### Prerequisites

- Python 3.6 or higher
- No external dependencies required (uses only standard library)

### Setup

1. Download the script:
```bash
curl -O https://raw.githubusercontent.com/yourusername/CustomWordlistGenerator/main/CustomWordlistGenerator.py
```

2. Make it executable:
```bash
chmod +x CustomWordlistGenerator.py
```

3. Run the script:
```bash
python3 CustomWordlistGenerator.py --help
```

## Usage

### Basic Usage

```bash
# Generate wordlist from base words with transformations
python3 CustomWordlistGenerator.py -p "admin,user,test" -t case,append_numbers -o wordlist.txt

# Generate from a wordlist file
python3 CustomWordlistGenerator.py -w base_words.txt -t case,leet -o output.txt

# Generate with word combinations
python3 CustomWordlistGenerator.py -p "admin,panel,login" -c -t case -o combined.txt
```

### Advanced Usage

```bash
# Generate with pattern templates
python3 CustomWordlistGenerator.py -pt "admin???,user###,pass@@@" -o patterns.txt

# Apply multiple transformations with length filtering
python3 CustomWordlistGenerator.py -w wordlist.txt -t case,leet,append_numbers,prepend_numbers --min-length 8 --max-length 16 -o filtered.txt

# Generate comprehensive wordlist with all options
python3 CustomWordlistGenerator.py -w base.txt -p "admin,user" -pt "pass###" -t case,leet,append_numbers -c --max-words 500000 -o comprehensive.txt
```

## Command Line Arguments

### Input Options
- `-w, --wordlist`: Path to input wordlist file
- `-p, --patterns`: Comma-separated base words/patterns
- `-pt, --pattern-templates`: Comma-separated pattern templates

### Transformation Options
- `-t, --transformations`: Apply transformations (case, leet, append_numbers, prepend_numbers)
- `-c, --combinations`: Generate word combinations

### Output Options
- `-o, --output`: Output wordlist file (required)

### Filtering Options
- `--min-length`: Minimum word length (default: 1)
- `--max-length`: Maximum word length (default: 50)
- `--max-words`: Maximum number of words to generate (default: 1,000,000)

### Other Options
- `-v, --verbose`: Enable verbose output
- `-h, --help`: Show help message

## Transformation Types

### Case Variations
- **lowercase**: converts to all lowercase
- **UPPERCASE**: converts to all uppercase
- **Capitalize**: capitalizes first letter only
- **Title Case**: capitalizes first letter of each word
- **Mixed Case**: first letter uppercase, rest lowercase

### Leet Speak
Common character substitutions:
- `a/A` → `@`, `4`
- `e/E` → `3`
- `i/I` → `1`, `!`
- `o/O` → `0`
- `s/S` → `$`, `5`
- `t/T` → `7`
- `l/L` → `1`
- `g/G` → `9`

### Number Patterns
**Append Numbers**: Common suffixes like:
- `1`, `12`, `123`, `1234`, `12345`
- `01`, `02`, `03`, `04`, `05`
- `2020`, `2021`, `2022`, `2023`, `2024`, `2025`
- `!`, `!!`, `!!!`, `@`, `#`, `$`

**Prepend Numbers**: Common prefixes like:
- `1`, `12`, `123`
- `the`, `my`, `new`, `old`

## Pattern Templates

Pattern templates use special characters:
- `?` = Any character (letters + numbers)
- `#` = Any digit (0-9)
- `@` = Any letter (a-z)

Examples:
- `admin???` generates `admin` + 3 random characters
- `user###` generates `user` + 3 digits
- `pass@@@` generates `pass` + 3 letters

**Note**: Patterns with more than 4 wildcards are limited to prevent excessive generation.

## Examples

### Example 1: Basic Company Wordlist
```bash
python3 CustomWordlistGenerator.py \
  -p "company,corp,admin,user,login,password" \
  -t case,append_numbers \
  -o company_wordlist.txt
```

### Example 2: Advanced Targeted Wordlist
```bash
python3 CustomWordlistGenerator.py \
  -w common_passwords.txt \
  -p "target,company,admin" \
  -pt "admin###,user###" \
  -t case,leet,append_numbers \
  -c \
  --min-length 6 \
  --max-length 20 \
  -o targeted_wordlist.txt
```

### Example 3: Pattern-Based Generation
```bash
python3 CustomWordlistGenerator.py \
  -pt "admin???,user???,pass###,test@@@" \
  --min-length 7 \
  --max-length 10 \
  -o pattern_wordlist.txt
```

## Performance Considerations

- **Memory Usage**: The script uses iterators and sets to manage memory efficiently
- **Output Limits**: Default limit of 1,000,000 words to prevent excessive file sizes
- **Pattern Complexity**: Patterns with many wildcards are automatically limited
- **Duplicate Handling**: Automatic deduplication using hash sets

## Ethical Use and Legal Considerations

⚠️ **IMPORTANT DISCLAIMER**: This tool is intended for legitimate security testing purposes only.

### Authorized Use Only
- Only use this tool on systems you own or have explicit written permission to test
- Ensure you have proper authorization before conducting any security assessments
- Follow your organization's security testing policies and procedures

### Responsible Disclosure
- If you discover vulnerabilities during testing, follow responsible disclosure practices
- Report findings to the appropriate parties through proper channels
- Do not exploit vulnerabilities for personal gain or malicious purposes

### Legal Compliance
- Ensure your use of this tool complies with local, state, and federal laws
- Be aware that unauthorized access to computer systems is illegal in most jurisdictions
- Consider the ethical implications of your security testing activities

## Limitations

- **Pattern Complexity**: Patterns with more than 4 wildcards are limited to prevent excessive generation
- **Memory Constraints**: Very large wordlists may require significant memory
- **Character Sets**: Pattern generation uses basic character sets (can be extended if needed)
- **Performance**: Complex transformations on large wordlists may take considerable time

## Troubleshooting

### Common Issues

**"File not found" error**:
```bash
# Check file path and permissions
ls -la your_wordlist.txt
```

**"Too many words generated" warning**:
```bash
# Increase the limit or add more filtering
python3 CustomWordlistGenerator.py ... --max-words 2000000 --min-length 8
```

**Memory issues with large wordlists**:
```bash
# Process in smaller chunks or add more restrictive filtering
python3 CustomWordlistGenerator.py ... --max-length 12 --max-words 500000
```

### Verbose Output
Use the `-v` flag for detailed logging:
```bash
python3 CustomWordlistGenerator.py -v -p "test" -t case -o debug.txt
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:
- Bug fixes
- New transformation types
- Performance improvements
- Additional pattern features
- Documentation improvements

## License

MIT License

Copyright (c) 2025 CustomWordlistGenerator

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
- Basic word transformations (case, leet, numbers)
- Pattern-based generation
- Word combinations
- File input/output
- Command-line interface
- Comprehensive documentation

## Support

For questions, issues, or feature requests:
1. Check the existing issues on GitHub
2. Create a new issue with detailed information
3. Include example commands and error messages when reporting bugs

---

**Remember**: Use this tool responsibly and only for legitimate security testing purposes with proper authorization.
