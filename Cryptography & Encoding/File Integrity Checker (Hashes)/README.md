# File Integrity Checker (Hashes)

A comprehensive Python tool for computing and verifying file hashes to ensure file integrity. This script helps detect file corruption, unauthorized modifications, and verify file authenticity using various cryptographic hash algorithms.

## Features

- **Multiple Hash Algorithms**: Supports MD5, SHA1, SHA256, SHA512, Blake2b, and Blake2s
- **Single File or Directory Processing**: Hash individual files or entire directory trees
- **Hash Verification**: Verify files against previously computed hashes
- **File Comparison**: Compare two files for identical content
- **Batch Processing**: Process multiple files efficiently with progress feedback
- **Flexible Output**: Display results to console or save to files
- **Error Handling**: Robust error handling for missing files, permission issues, etc.
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Installation

### Prerequisites

- Python 3.6 or higher
- No external dependencies required (uses only Python standard library)

### Download and Setup

1. Download the `file_integrity_checker.py` script
2. Make it executable (on Unix-like systems):
   ```bash
   chmod +x file_integrity_checker.py
   ```

## Usage

The script provides three main operations: `compute`, `verify`, and `compare`.

### Basic Usage

```bash
python file_integrity_checker.py <operation> [options]
```

### 1. Computing Hashes

#### Single File
```bash
# Compute SHA256 hash of a single file
python file_integrity_checker.py compute --file document.pdf

# Use different algorithm
python file_integrity_checker.py compute --file image.jpg --algorithm md5
```

#### Directory (All Files)
```bash
# Hash all files in a directory (recursive by default)
python file_integrity_checker.py compute --directory /path/to/files

# Hash only files in the current directory (non-recursive)
python file_integrity_checker.py compute --directory . --no-recursive

# Save hashes to a file
python file_integrity_checker.py compute --directory /important/files --output checksums.txt
```

### 2. Verifying File Integrity

```bash
# Verify files against saved hashes
python file_integrity_checker.py verify --hashfile checksums.txt

# Verify files in a different directory
python file_integrity_checker.py verify --hashfile checksums.txt --directory /backup/location
```

### 3. Comparing Files

```bash
# Compare two files for identical content
python file_integrity_checker.py compare --file1 original.txt --file2 backup.txt

# Compare using different hash algorithm
python file_integrity_checker.py compare --file1 file1.bin --file2 file2.bin --algorithm sha512
```

## Command Line Options

### Global Options

- `--algorithm`, `-a`: Hash algorithm to use
  - Choices: `md5`, `sha1`, `sha256`, `sha512`, `blake2b`, `blake2s`
  - Default: `sha256`

### Compute Operation

- `--file`, `-f`: Single file to hash
- `--directory`, `-d`: Directory to hash (mutually exclusive with `--file`)
- `--output`, `-o`: Output file to save hashes
- `--recursive`, `-r`: Include subdirectories (default: True)
- `--no-recursive`: Process only the specified directory, not subdirectories

### Verify Operation

- `--hashfile`, `-H`: File containing stored hashes (required)
- `--directory`, `-d`: Base directory for relative paths (default: current directory)

### Compare Operation

- `--file1`: First file to compare (required)
- `--file2`: Second file to compare (required)

## Hash File Format

The script uses a simple, readable format for hash files:

```
# File Integrity Hashes
# Algorithm: SHA256
# Generated: 2025-06-18 14:30:45
# Format: hash_value filename

e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  empty.txt
2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae  hello.txt
```

## Examples

### Example 1: Backup Verification Workflow

```bash
# 1. Create hashes for important files before backup
python file_integrity_checker.py compute --directory /important/documents --output before_backup.txt

# 2. After backup, verify integrity
python file_integrity_checker.py verify --hashfile before_backup.txt --directory /backup/documents
```

### Example 2: File Download Verification

```bash
# 1. Compute hash of downloaded file
python file_integrity_checker.py compute --file downloaded_file.zip --algorithm sha256

# 2. Compare with provided checksum
python file_integrity_checker.py compare --file1 downloaded_file.zip --file2 reference_file.zip
```

### Example 3: System File Monitoring

```bash
# 1. Create baseline hashes
python file_integrity_checker.py compute --directory /etc --output system_baseline.txt

# 2. Later, check for changes
python file_integrity_checker.py verify --hashfile system_baseline.txt --directory /etc
```

## Exit Codes

- `0`: Success (files verified successfully, files are identical)
- `1`: Error or files differ (verification failed, files are different, file not found, etc.)

## Performance Notes

- **Large Files**: The script processes files in chunks (64KB by default) to handle large files efficiently without consuming excessive memory
- **Directory Processing**: Files are processed sequentially with progress feedback
- **Hash Algorithms**: SHA256 provides a good balance of security and performance for most use cases

## Security Considerations

### Hash Algorithm Selection

- **MD5**: Fast but cryptographically broken; suitable only for detecting accidental corruption
- **SHA1**: Deprecated for security purposes; faster than SHA256 but less secure
- **SHA256**: Recommended for most security applications; good balance of security and performance
- **SHA512**: Higher security margin but slower; recommended for highly sensitive data
- **Blake2b/Blake2s**: Modern, fast, and secure; excellent alternatives to SHA family

### Best Practices

1. **Use SHA256 or stronger** for security-critical applications
2. **Store hash files securely** to prevent tampering
3. **Verify hash file integrity** if received from external sources
4. **Use multiple algorithms** for critical verification when possible

## Limitations

- **Large Directories**: Processing very large directory trees may take considerable time
- **File Access**: Requires read permissions for all files being processed
- **Memory Usage**: While efficient, very large files still require processing time
- **Concurrent Access**: Files being modified during hashing may produce inconsistent results

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure you have read permissions for all files
2. **File Not Found**: Check file paths and ensure files exist
3. **Invalid Algorithm**: Use one of the supported algorithms listed above
4. **Hash File Format**: Ensure hash files follow the expected format

### Error Messages

- `File not found`: The specified file or directory doesn't exist
- `Permission denied`: Insufficient permissions to read the file
- `Unsupported algorithm`: The specified hash algorithm is not supported
- `Invalid format`: The hash file format is incorrect

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve this tool.

## License

MIT License

Copyright (c) 2025 File Integrity Checker Script

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
- Support for multiple hash algorithms
- Single file and directory processing
- Hash verification functionality
- File comparison capabilities
- Comprehensive error handling and validation
