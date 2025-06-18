# Hash Cracking Educational Tool

An educational Python script that demonstrates how password hashing works and illustrates the importance of using strong passwords. This tool is designed for cybersecurity education and awareness purposes.

## ⚠️ **IMPORTANT: Educational Use Only**

This tool is created strictly for educational purposes to:
- Demonstrate password hashing concepts
- Show why strong passwords are important
- Illustrate different attack methods used by malicious actors
- Help security professionals understand vulnerabilities

**DO NOT use this tool for:**
- Unauthorized access to systems or accounts
- Cracking passwords you don't own
- Any illegal or unethical activities

## Features

- **Hash Generation**: Create hashes using various algorithms (MD5, SHA1, SHA256, etc.)
- **Dictionary Attacks**: Test passwords against common wordlists
- **Limited Brute Force**: Educational brute force with safety limits
- **Password Analysis**: Comprehensive password strength assessment
- **Multiple Hash Algorithms**: Support for MD5, SHA1, SHA224, SHA256, SHA384, SHA512
- **Performance Metrics**: Track attempts, time, and cracking rates
- **Sample Wordlist**: Built-in creation of test wordlists

## Installation

### Prerequisites
- Python 3.6 or higher
- No external dependencies required (uses only standard library)

### Setup
1. Clone or download the script:
```bash
git clone <repository-url>
# OR download hash_cracker.py directly
```

2. Make the script executable (Linux/Mac):
```bash
chmod +x hash_cracker.py
```

3. Run the script:
```bash
python hash_cracker.py --help
```

## Usage

### Basic Commands

#### 1. Generate a Hash
Create a hash for a password using different algorithms:
```bash
# Generate MD5 hash
python hash_cracker.py --generate "mypassword" --algorithm md5

# Generate SHA256 hash
python hash_cracker.py --generate "mypassword" --algorithm sha256
```

#### 2. Create Sample Wordlist
Generate a test wordlist with common passwords:
```bash
python hash_cracker.py --create-wordlist
```

#### 3. Dictionary Attack
Attempt to crack a hash using a wordlist:
```bash
# Using sample wordlist
python hash_cracker.py --hash "5d41402abc4b2a76b9719d911017c592" --algorithm md5 --wordlist sample_wordlist.txt

# Using custom wordlist
python hash_cracker.py --hash "your_hash_here" --algorithm sha1 --wordlist /path/to/wordlist.txt
```

#### 4. Brute Force Attack (Limited)
Perform educational brute force with length restrictions:
```bash
# Basic brute force (max 4 characters)
python hash_cracker.py --hash "098f6bcd4621d373cade4e832627b4f6" --algorithm md5 --brute

# Custom length and character set
python hash_cracker.py --hash "your_hash" --algorithm md5 --brute --max-length 5 --charset "abc123"
```

#### 5. Password Strength Analysis
Analyze password security:
```bash
python hash_cracker.py --analyze "mypassword123"
```

### Command Line Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `--generate PASSWORD` | Generate hash for password | `--generate "test123"` |
| `--hash HASH` | Hash to crack | `--hash "5d41402a..."` |
| `--analyze PASSWORD` | Analyze password strength | `--analyze "mypass"` |
| `--create-wordlist` | Create sample wordlist | |
| `--algorithm ALG` | Hash algorithm to use | `--algorithm sha256` |
| `--wordlist FILE` | Wordlist for dictionary attack | `--wordlist words.txt` |
| `--brute` | Enable brute force mode | |
| `--max-length N` | Max length for brute force (≤6) | `--max-length 4` |
| `--charset CHARS` | Characters for brute force | `--charset "abc123"` |

### Supported Hash Algorithms

- `md5` - MD5 (128-bit)
- `sha1` - SHA-1 (160-bit)
- `sha224` - SHA-224 (224-bit)
- `sha256` - SHA-256 (256-bit)
- `sha384` - SHA-384 (384-bit)
- `sha512` - SHA-512 (512-bit)

## Examples

### Complete Workflow Example

1. **Create a sample wordlist:**
```bash
python hash_cracker.py --create-wordlist
```

2. **Generate a hash to test:**
```bash
python hash_cracker.py --generate "password123" --algorithm md5
# Output: 482c811da5d5b4bc6d497ffa98491e38
```

3. **Attempt to crack it:**
```bash
python hash_cracker.py --hash "482c811da5d5b4bc6d497ffa98491e38" --algorithm md5 --wordlist sample_wordlist.txt
```

4. **Analyze the cracked password:**
```bash
python hash_cracker.py --analyze "password123"
```

### Security Demonstration

Show the difference between weak and strong passwords:

```bash
# Weak password - easily cracked
python hash_cracker.py --generate "123456" --algorithm md5
python hash_cracker.py --hash "e10adc3949ba59abbe56e057f20f883e" --algorithm md5 --wordlist sample_wordlist.txt

# Strong password - much harder to crack
python hash_cracker.py --generate "Tr0ub4dor&3" --algorithm sha256
python hash_cracker.py --analyze "Tr0ub4dor&3"
```

## Educational Value

This tool demonstrates several important cybersecurity concepts:

### 1. **Hash Function Properties**
- One-way functions (easy to compute, hard to reverse)
- Deterministic output
- Fixed output size
- Avalanche effect

### 2. **Attack Methods**
- **Dictionary Attacks**: Using common passwords
- **Brute Force**: Trying all combinations
- **Hybrid Attacks**: Combining approaches

### 3. **Password Security**
- Importance of length and complexity
- Common password patterns to avoid
- Impact of character set diversity

### 4. **Defense Strategies**
- Use of strong, unique passwords
- Benefits of password managers
- Implementation of account lockouts
- Rate limiting and monitoring

## Safety Limitations

The tool includes several safety measures for educational use:

- **Brute force limited to 6 characters maximum**
- **Progress reporting to show computational cost**
- **Clear educational warnings and lessons**
- **Focus on demonstrating vulnerabilities, not exploiting them**

## Performance Notes

- MD5 and SHA1 are fast but cryptographically broken
- SHA256+ are more secure but slower to crack
- Dictionary attacks are much faster than brute force
- Character set size dramatically affects brute force time

## Contributing

Contributions are welcome! Please ensure any additions:
- Maintain educational focus
- Include appropriate safety limitations
- Add clear documentation
- Follow existing code style

## License

MIT License

Copyright (c) 2024 Hash Cracking Educational Tool

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

This software is provided for educational purposes only. Users are responsible
for ensuring their use complies with applicable laws and regulations. The
authors assume no liability for misuse of this educational tool.

## Resources for Further Learning

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Cryptographic Hash Functions](https://en.wikipedia.org/wiki/Cryptographic_hash_function)
- [Dictionary Attack](https://en.wikipedia.org/wiki/Dictionary_attack)
- [Brute Force Attack](https://en.wikipedia.org/wiki/Brute-force_attack)
