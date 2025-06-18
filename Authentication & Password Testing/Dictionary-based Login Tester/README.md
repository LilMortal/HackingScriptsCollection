# Dictionary-based Login Tester

A Python-based educational tool for testing password strength against common password dictionaries. This tool is designed for security awareness training, authorized penetration testing, and educational purposes.

## ⚠️ IMPORTANT DISCLAIMER

**This tool is for educational and authorized testing purposes ONLY.** 

- ✅ **Authorized uses**: Testing your own accounts, authorized penetration testing, security education, password strength assessment
- ❌ **Prohibited uses**: Unauthorized access attempts, illegal activities, attacking systems you don't own

The authors are not responsible for any misuse of this tool. Always ensure you have proper authorization before testing any systems.

## Description

The Dictionary-based Login Tester simulates password attacks using wordlists to help understand password security vulnerabilities. It includes features like:

- Dictionary-based password testing
- Rate limiting to prevent system overload
- Password variation generation
- Comprehensive logging and statistics
- Configurable attempt limits and delays
- Sample dictionary generation

## Features

- 📖 **Dictionary Loading**: Load passwords from text files
- 🔄 **Password Variations**: Generate common password variations (capitalization, numbers, symbols)
- ⏱️ **Rate Limiting**: Configurable delays between attempts
- 📊 **Statistics**: Detailed reporting of testing results
- 🛡️ **Safety Features**: Built-in attempt limits and responsible testing practices
- 🎯 **Flexible Targeting**: Test against different usernames
- 📝 **Verbose Logging**: Optional detailed output for analysis

## Requirements

- Python 3.6 or higher
- No external dependencies (uses only standard library)

## Installation

1. **Clone or download the script**:
   ```bash
   curl -O https://raw.githubusercontent.com/yourusername/login-tester/main/login_tester.py
   # or download manually
   ```

2. **Make the script executable** (Linux/macOS):
   ```bash
   chmod +x login_tester.py
   ```

3. **Verify installation**:
   ```bash
   python login_tester.py --help
   ```

## Usage

### Basic Usage

```bash
python login_tester.py -u <username> -d <dictionary_file>
```

### Command Line Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--username` | `-u` | Username to test | Required |
| `--dictionary` | `-d` | Path to password dictionary file | Required |
| `--delay` | | Delay between attempts (seconds) | 1.0 |
| `--max-attempts` | | Maximum number of attempts | 1000 |
| `--verbose` | | Enable verbose output | False |
| `--variations` | | Generate password variations | False |
| `--create-sample-dict` | | Create sample dictionary file | N/A |
| `--help` | `-h` | Show help message | N/A |

### Examples

1. **Basic dictionary attack**:
   ```bash
   python login_tester.py -u admin -d common_passwords.txt
   ```

2. **Fast testing with verbose output**:
   ```bash
   python login_tester.py -u root -d wordlist.txt --delay 0.1 --verbose
   ```

3. **Limited attempts with variations**:
   ```bash
   python login_tester.py -u guest -d small_dict.txt --max-attempts 50 --variations
   ```

4. **Create a sample dictionary**:
   ```bash
   python login_tester.py --create-sample-dict sample_passwords.txt
   ```

5. **Professional penetration testing setup**:
   ```bash
   python login_tester.py -u admin -d rockyou.txt --delay 0.5 --max-attempts 10000 --variations
   ```

## Dictionary File Format

Dictionary files should be plain text files with one password per line:

```
password
123456
admin
root
# Comments start with #
qwerty
letmein
```

### Popular Password Dictionaries

- **rockyou.txt**: Most common password dictionary
- **SecLists**: Comprehensive password lists
- **10-million-password-list**: Extensive collection
- **Custom dictionaries**: Industry-specific or target-specific wordlists

## Sample Output

```
Loading dictionary from: common_passwords.txt
Loaded 50 passwords from dictionary
Starting dictionary attack on username: admin
Total passwords to test: 50
Delay between attempts: 1.0 seconds
Maximum attempts: 1000
--------------------------------------------------
Tested 10 passwords...
Tested 20 passwords...

[SUCCESS] Password found: 'password123'
Found after 23 attempts

Statistics:
Total attempts: 23
Time elapsed: 0:00:25.123456
Average attempts per second: 0.92
Password found: password123
```

## Password Variations

When using the `--variations` flag, the tool generates common password modifications:

- **Case variations**: `Password`, `PASSWORD`, `password`
- **Number suffixes**: `password1`, `password123`, `password2024`
- **Symbol suffixes**: `password!`, `password@`
- **Number prefixes**: `123password`
- **Year suffixes**: `password2023`, `password2024`, `password2025`

## Security Considerations

### Rate Limiting
- Default 1-second delay between attempts
- Configurable delays to prevent system overload
- Maximum attempt limits to prevent excessive testing

### Responsible Testing
- Always obtain proper authorization
- Use appropriate delays for production systems
- Monitor system resources during testing
- Document all testing activities

### Detection Avoidance
- Randomize testing patterns
- Use distributed testing when appropriate
- Monitor for account lockout mechanisms
- Implement proper logging and cleanup

## Educational Use Cases

1. **Password Policy Training**: Demonstrate weak password vulnerabilities
2. **Security Awareness**: Show real-world attack scenarios
3. **Penetration Testing Education**: Teach authorized testing methodologies
4. **System Administration**: Test password strength policies

## Troubleshooting

### Common Issues

1. **"Dictionary file not found"**:
   - Verify the file path is correct
   - Check file permissions
   - Use absolute paths if necessary

2. **"Permission denied"**:
   - Check script execution permissions
   - Verify file access rights

3. **Slow performance**:
   - Reduce delay with `--delay 0.1`
   - Limit attempts with `--max-attempts`
   - Use smaller dictionary files

4. **No passwords found**:
   - Try enabling `--variations`
   - Use larger dictionary files
   - Check if target system has lockout mechanisms

### Performance Tips

- Use SSD storage for large dictionaries
- Optimize dictionary files (remove duplicates)
- Consider parallel processing for large-scale testing
- Monitor system resources during testing

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Update documentation
5. Submit a pull request

## Legal and Ethical Guidelines

### Legal Use Only
- Only test systems you own or have explicit written permission to test
- Comply with all applicable laws and regulations
- Respect terms of service and acceptable use policies

### Ethical Considerations
- Use for constructive security improvement
- Report vulnerabilities responsibly
- Protect sensitive information discovered during testing
- Educate rather than exploit

## License

```
MIT License

Copyright (c) 2025 Dictionary-based Login Tester

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

### Version 1.0
- Initial release
- Basic dictionary attack functionality
- Password variation generation
- Rate limiting and safety features
- Comprehensive documentation
- Sample dictionary creation

## Support

For questions, issues, or contributions:

- Create an issue on GitHub
- Review the documentation
- Check existing issues and solutions
- Follow responsible disclosure for security issues

## Related Tools

- **Hydra**: Network login cracker
- **John the Ripper**: Password cracking tool
- **Hashcat**: Advanced password recovery
- **Medusa**: Parallel login brute-forcer
- **Ncrack**: Network authentication cracking tool

---

**Remember**: This tool is for educational and authorized testing purposes only. Always ensure you have proper authorization before testing any systems, and use this knowledge to improve security rather than cause harm.
