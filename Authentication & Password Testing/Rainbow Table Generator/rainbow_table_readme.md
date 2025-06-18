# Rainbow Table Generator

An educational implementation of a rainbow table generator for cryptographic research and security testing.

## ⚠️ Important Disclaimer

**This tool is for educational purposes and authorized security testing only.** Rainbow tables can be used to crack passwords, and their use must comply with applicable laws, regulations, and organizational policies. Only use this tool on systems you own or have explicit written permission to test.

## What is a Rainbow Table?

Rainbow tables are precomputed tables used to reverse cryptographic hash functions, particularly for password cracking. They implement a time-memory tradeoff by storing hash chains instead of all possible hash-plaintext pairs, making them more space-efficient than simple lookup tables.

## Features

- **Multiple Hash Algorithms**: Supports MD5, SHA1, and SHA256
- **Customizable Character Sets**: Define your own character sets for password generation
- **Configurable Parameters**: Adjust chain length, table size, and password length
- **JSON Storage**: Save and load rainbow tables in JSON format
- **Hash Lookup**: Search for plaintexts corresponding to given hashes
- **Progress Tracking**: Real-time progress updates during generation
- **Command Line Interface**: Easy-to-use CLI with comprehensive options

## Installation

### Requirements

- Python 3.7 or higher
- Standard library modules only (no external dependencies)

### Setup

1. Clone or download the script:
```bash
# Download the script
curl -O https://example.com/rainbow_table_generator.py
```

2. Make the script executable (Unix/Linux/macOS):
```bash
chmod +x rainbow_table_generator.py
```

## Usage

### Basic Usage

Generate a basic rainbow table:
```bash
python rainbow_table_generator.py -a md5 -c abcdefghijklmnopqrstuvwxyz -l 4 -t 1000
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-a, --algorithm` | Hash algorithm (md5, sha1, sha256) | md5 |
| `-c, --charset` | Character set for passwords | abcdefghijklmnopqrstuvwxyz |
| `-l, --max-length` | Maximum password length | 4 |
| `-t, --table-count` | Number of chains to generate | 1000 |
| `--chain-length` | Length of each hash chain | 1000 |
| `-o, --output` | Output filename | rainbow_table.json |
| `--load` | Load existing rainbow table | None |
| `--lookup` | Hash to lookup | None |

### Examples

#### 1. Generate MD5 Rainbow Table for Lowercase Letters
```bash
python rainbow_table_generator.py \
  --algorithm md5 \
  --charset abcdefghijklmnopqrstuvwxyz \
  --max-length 4 \
  --table-count 10000 \
  --output md5_lowercase.json
```

#### 2. Generate SHA256 Rainbow Table with Numbers and Letters
```bash
python rainbow_table_generator.py \
  --algorithm sha256 \
  --charset abcdefghijklmnopqrstuvwxyz0123456789 \
  --max-length 6 \
  --table-count 50000 \
  --chain-length 2000 \
  --output sha256_alphanumeric.json
```

#### 3. Generate Table for Numeric Passwords Only
```bash
python rainbow_table_generator.py \
  --algorithm md5 \
  --charset 0123456789 \
  --max-length 8 \
  --table-count 5000 \
  --output numeric_passwords.json
```

#### 4. Load Table and Lookup Hash
```bash
# Lookup a specific hash
python rainbow_table_generator.py \
  --load rainbow_table.json \
  --lookup 5d41402abc4b2a76b9719d911017c592

# Example output:
# Looking up hash: 5d41402abc4b2a76b9719d911017c592
# Found: hello
# Verification: 5d41402abc4b2a76b9719d911017c592
# ✓ Hash verified successfully!
```

### Understanding the Output

When generating a rainbow table, you'll see output like:
```
Generating rainbow table with 1000 chains...
Algorithm: MD5
Charset: abcdefghijklmnopqrstuvwxyz
Max length: 4
Chain length: 1000
--------------------------------------------------
Progress: 10.0% (100/1000)
Progress: 20.0% (200/1000)
...
Table generation complete!
Generated chains: 1000
Duplicate endpoints avoided: 23
Time elapsed: 12.34 seconds
Coverage estimate: 1000 unique endpoints
```

## How It Works

### Rainbow Table Algorithm

1. **Chain Generation**: 
   - Start with a random password
   - Hash it using the specified algorithm
   - Apply a reduction function to convert the hash back to a password
   - Repeat for the specified chain length
   - Store only the start and end passwords

2. **Reduction Function**:
   - Converts hash values back to password space
   - Uses position-dependent reduction to avoid cycles
   - Ensures deterministic but varied mapping

3. **Lookup Process**:
   - For a given hash, try each possible position in a chain
   - Apply reduction functions to reach chain endpoints
   - Check if endpoint exists in the table
   - If found, regenerate the chain to find the exact password

### Time-Memory Tradeoff

Rainbow tables trade computation time for storage space:
- **Traditional approach**: Store all hash-password pairs (high memory)
- **Rainbow table approach**: Store fewer chain endpoints, compute on lookup (lower memory, more time)

## Performance Considerations

### Memory Usage
- Each chain stores 2 strings (start and end passwords)
- JSON storage adds overhead
- Approximate memory: `table_count * (avg_password_length * 2 + JSON_overhead)`

### Generation Time
- Depends on hash algorithm speed, chain length, and table size
- MD5 is fastest, SHA256 is slowest
- Longer chains = more computation per chain
- More chains = better coverage but longer generation time

### Lookup Success Rate
- Depends on table coverage of the password space
- Larger tables have better success rates
- Success rate ≈ `table_count * chain_length / total_password_space`

## Limitations

1. **Limited Character Sets**: Only works with predefined character sets
2. **Hash Algorithm Support**: Limited to MD5, SHA1, and SHA256
3. **Memory Constraints**: Large tables require significant memory
4. **Success Rate**: Not guaranteed to find all passwords
5. **Salt Handling**: Does not handle salted hashes

## Security Implications

### Defensive Measures Against Rainbow Tables
- **Use Salt**: Add random salt to passwords before hashing
- **Use Slow Hash Functions**: bcrypt, scrypt, Argon2 instead of fast hashes
- **Increase Password Complexity**: Longer passwords with varied character sets
- **Multi-Factor Authentication**: Reduce reliance on passwords alone

### Responsible Use
- Only use on systems you own or have permission to test
- Respect privacy and legal boundaries
- Use for educational purposes and authorized penetration testing
- Follow responsible disclosure practices

## File Format

Rainbow tables are saved in JSON format:
```json
{
  "metadata": {
    "hash_algorithm": "md5",
    "charset": "abcdefghijklmnopqrstuvwxyz",
    "max_length": 4,
    "table_count": 1000,
    "chain_length": 1000,
    "actual_chains": 977
  },
  "table": {
    "endpoint1": "startword1",
    "endpoint2": "startword2",
    ...
  }
}
```

## Troubleshooting

### Common Issues

1. **Memory Errors**: Reduce table size or chain length
2. **Slow Generation**: Use faster hash algorithm (MD5 vs SHA256)
3. **Low Success Rate**: Increase table size or chain length
4. **File Size Too Large**: Use smaller tables or compress output

### Performance Tips

1. **For faster generation**: Use MD5, shorter chains, smaller tables
2. **For better coverage**: Use longer chains, larger tables
3. **For memory efficiency**: Use shorter passwords, smaller character sets

## Contributing

This is an educational implementation. Improvements welcome:
- Additional hash algorithms
- Better reduction functions  
- Memory optimization
- GUI interface
- Salt handling

## License

MIT License

Copyright (c) 2025 Educational Implementation

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

## Educational Resources

- [Cryptographic Hash Functions](https://en.wikipedia.org/wiki/Cryptographic_hash_function)
- [Rainbow Table Research Paper](https://lasec.epfl.ch/pub/lasec/doc/Oech03.pdf)
- [Password Security Best Practices](https://owasp.org/www-project-cheat-sheets/cheatsheets/Password_Storage_Cheat_Sheet.html)

## Changelog

### Version 1.0.0
- Initial implementation
- Support for MD5, SHA1, SHA256
- JSON storage format
- Command line interface
- Hash lookup functionality