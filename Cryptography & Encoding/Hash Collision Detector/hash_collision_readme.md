# Hash Collision Detector

A Python script to detect hash collisions by comparing hash values of multiple inputs using various hashing algorithms. This tool is useful for security research, data integrity verification, duplicate file detection, and educational purposes.

## Features

- **Multi-Algorithm Support**: Supports 12 different hashing algorithms including MD5, SHA family, BLAKE2, and SHA-3
- **Multiple Input Sources**: Process strings, individual files, or entire directories
- **Recursive Directory Processing**: Scan directories and subdirectories recursively
- **Collision Detection**: Automatically identifies and reports hash collisions
- **Performance Optimized**: Handles large files efficiently using chunked reading
- **Detailed Statistics**: Provides comprehensive statistics about processed data
- **Flexible Output**: Option to show all hashes or just collisions
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Supported Hash Algorithms

- **MD5**: `md5` (legacy, not cryptographically secure)
- **SHA-1**: `sha1` (legacy, not cryptographically secure)
- **SHA-2 Family**: `sha224`, `sha256`, `sha384`, `sha512`
- **BLAKE2**: `blake2b`, `blake2s`
- **SHA-3 Family**: `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`

## Installation

### Prerequisites

- Python 3.6 or higher
- No external dependencies required (uses Python standard library only)

### Installation Steps

1. **Download the script:**
   ```bash
   # Option 1: Download directly
   wget https://raw.githubusercontent.com/example/hash-collision-detector/main/hash_collision_detector.py
   
   # Option 2: Clone repository
   git clone https://github.com/example/hash-collision-detector.git
   cd hash-collision-detector
   ```

2. **Make the script executable (Unix/Linux/macOS):**
   ```bash
   chmod +x hash_collision_detector.py
   ```

3. **Verify installation:**
   ```bash
   python hash_collision_detector.py --help
   ```

## Usage

### Basic Syntax

```bash
python hash_collision_detector.py [OPTIONS] [INPUT_SOURCES]
```

### Command Line Arguments

#### Required Arguments (at least one):
- `-f, --files FILE [FILE ...]`: Files to hash and check for collisions
- `-s, --strings STRING [STRING ...]`: Strings to hash and check for collisions  
- `-d, --directory DIR`: Directory containing files to hash

#### Optional Arguments:
- `-a, --algorithm ALGORITHM`: Hashing algorithm to use (default: sha256)
- `--recursive`: Process directories recursively
- `--show-all`: Show all hash values, not just collisions
- `-v, --verbose`: Enable verbose output
- `-h, --help`: Show help message

### Usage Examples

#### 1. Compare Multiple Files
```bash
# Check for collisions among specific files using SHA-256
python hash_collision_detector.py -a sha256 -f file1.txt file2.txt file3.txt

# Use glob patterns to process multiple files
python hash_collision_detector.py -a md5 -f *.txt --show-all
```

#### 2. Compare Text Strings
```bash
# Check for collisions among strings
python hash_collision_detector.py -a sha1 -s "hello" "world" "hello" "test"

# Compare different variations of text
python hash_collision_detector.py -a md5 -s "password" "Password" "PASSWORD"
```

#### 3. Process Directory
```bash
# Hash all files in a directory
python hash_collision_detector.py -a sha256 -d /path/to/directory

# Process directory recursively with verbose output
python hash_collision_detector.py -a blake2b -d /path/to/directory --recursive --verbose
```

#### 4. Test All Algorithms
```bash
# Run collision detection using all supported algorithms
python hash_collision_detector.py -a all -f file1.txt file2.txt
```

#### 5. Advanced Usage
```bash
# Comprehensive analysis with multiple input sources
python hash_collision_detector.py -a sha3_256 \
    -f important_file.pdf backup_file.pdf \
    -s "secret_password" "secret_password" \
    -d /home/user/documents \
    --recursive --verbose --show-all
```

## Output Format

### Basic Output
```
============================================================
HASH COLLISION DETECTION RESULTS (SHA256)
============================================================
Total items processed: 5
Unique hash values: 4
Collision groups found: 1
Collision rate: 25.00%

============================================================
COLLISIONS DETECTED:
============================================================

Collision Group #1
Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Items with identical hash (2):
  1. Type: file
     Identifier: /path/to/empty1.txt
     Content: empty1.txt
     Size: 0 bytes
  2. Type: file
     Identifier: /path/to/empty2.txt
     Content: empty2.txt
     Size: 0 bytes
```

### Statistics Explanation
- **Total items processed**: Number of files/strings analyzed
- **Unique hash values**: Number of distinct hash values found
- **Collision groups found**: Number of hash values with multiple items
- **Collision rate**: Percentage of hash values that have collisions

## Use Cases

### 1. Duplicate File Detection
Identify duplicate files in your system:
```bash
python hash_collision_detector.py -a sha256 -d ~/Downloads --recursive
```

### 2. Data Integrity Verification
Verify that files haven't been corrupted:
```bash
python hash_collision_detector.py -a sha512 -f original.zip backup.zip
```

### 3. Security Research
Test for hash collisions in cryptographic algorithms:
```bash
python hash_collision_detector.py -a md5 -f collision1.bin collision2.bin
```

### 4. Educational Purposes
Demonstrate hash properties and collision resistance:
```bash
python hash_collision_detector.py -a all -s "abc" "def" "abc"
```

## Performance Considerations

- **Large Files**: The script processes files in 8KB chunks to handle large files efficiently
- **Memory Usage**: Hash values and metadata are stored in memory; very large datasets may require significant RAM
- **Processing Speed**: Processing speed depends on the chosen algorithm and file sizes
- **Directory Scanning**: Recursive directory processing shows progress for every 100 files processed

## Security Notes

### Cryptographic Security Warnings
- **MD5 and SHA-1**: These algorithms are cryptographically broken and should not be used for security purposes
- **For Security Applications**: Use SHA-256, SHA-512, or SHA-3 family algorithms
- **Collision Attacks**: Some algorithms are vulnerable to collision attacks where different inputs produce the same hash

### Ethical Use Guidelines
- Only scan files and directories you own or have explicit permission to access
- Respect privacy and confidentiality when processing files
- Do not use this tool for malicious purposes such as finding hash collisions for forgery
- Be aware of legal implications when analyzing files in corporate or regulated environments

## Troubleshooting

### Common Issues

1. **Permission Denied Error**
   ```
   Solution: Ensure you have read permissions for all files and directories being processed
   ```

2. **File Not Found**
   ```
   Solution: Verify file paths are correct and files exist
   ```

3. **Memory Issues with Large Datasets**
   ```
   Solution: Process smaller batches of files or use more specific file filters
   ```

4. **Slow Performance**
   ```
   Solution: Use faster algorithms like BLAKE2 for large datasets, or process files in smaller batches
   ```

### Debugging Tips

- Use the `--verbose` flag to see detailed processing information
- Use `--show-all` to see all hash values, not just collisions
- Test with a small dataset first before processing large directories

## Algorithm Recommendations

### For Different Use Cases:
- **General Purpose**: SHA-256 (good balance of security and performance)
- **High Security**: SHA-512 or SHA3-256
- **Performance Critical**: BLAKE2b or BLAKE2s
- **Legacy Compatibility**: MD5 or SHA-1 (not recommended for security)
- **Research/Educational**: All algorithms for comparison

## License

MIT License

Copyright (c) 2025 Hash Collision Detector

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

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup
```bash
git clone https://github.com/example/hash-collision-detector.git
cd hash-collision-detector
python -m pytest tests/  # Run tests (if available)
```

## Changelog

### Version 1.0.0
- Initial release
- Support for 12 hashing algorithms
- File, string, and directory processing
- Collision detection and reporting
- Cross-platform compatibility

## Support

If you encounter any issues or have questions:

1. Check the troubleshooting section above
2. Search existing issues on GitHub
3. Create a new issue with detailed information about your problem
4. Include your Python version, operating system, and the exact command you ran

## Acknowledgments

- Built using Python's built-in `hashlib` library
- Inspired by various hash collision research and duplicate file detection tools
- Thanks to the Python community for excellent documentation and examples
