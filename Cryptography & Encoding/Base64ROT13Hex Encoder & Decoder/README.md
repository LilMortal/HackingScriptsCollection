# Base64ROT13Hex Encoder & Decoder

A comprehensive command-line utility for encoding and decoding text using Base64, ROT13, and Hexadecimal transformations. The script supports chaining multiple encoding operations and provides both command-line and interactive modes.

## Features

- **Multiple Encoding Methods**: Supports Base64, ROT13, and Hexadecimal encoding/decoding
- **Method Chaining**: Apply multiple encoding methods in sequence
- **File Processing**: Read input from files and write output to files
- **Interactive Mode**: User-friendly interactive interface for multiple operations
- **Error Handling**: Comprehensive error handling with descriptive messages
- **Command-line Interface**: Full argparse integration with help documentation
- **UTF-8 Support**: Proper handling of Unicode text

## Installation

### Prerequisites

- Python 3.6 or higher
- No external dependencies required (uses only Python standard library)

### Setup

1. Download the `base64rot13hex.py` script
2. Make it executable (optional, on Unix-like systems):
   ```bash
   chmod +x base64rot13hex.py
   ```

No additional installation is required as the script uses only Python's standard library.

## Usage

The script provides three main modes of operation:

### 1. Command-line Encoding

```bash
# Basic encoding with single method
python base64rot13hex.py encode --input "Hello World" --method base64

# Chain multiple encoding methods
python base64rot13hex.py encode --input "Secret Message" --method base64 --method rot13 --method hex

# Encode from file and save to file
python base64rot13hex.py encode --file input.txt --method base64 --output encoded.txt
```

### 2. Command-line Decoding

```bash
# Basic decoding with single method
python base64rot13hex.py decode --input "SGVsbG8gV29ybGQ=" --method base64

# Chain multiple decoding methods (methods should be in original encoding order)
python base64rot13hex.py decode --input "encoded_text" --method base64 --method rot13 --method hex

# Decode from file and save to file
python base64rot13hex.py decode --file encoded.txt --method base64 --output decoded.txt
```

### 3. Interactive Mode

```bash
python base64rot13hex.py interactive
```

In interactive mode, you'll be prompted to:
- Choose operation (encode/decode)
- Enter text to process
- Select encoding methods (comma-separated)

## Command-line Options

### Global Options

- `--help`, `-h`: Show help message and exit

### Encode Command

- `--input`, `-i`: Input text to encode
- `--file`, `-f`: Input file to read text from
- `--method`, `-m`: Encoding method to apply (can be used multiple times)
- `--output`, `-o`: Output file to write result

### Decode Command

- `--input`, `-i`: Input text to decode
- `--file`, `-f`: Input file to read text from
- `--method`, `-m`: Decoding method to reverse (can be used multiple times)
- `--output`, `-o`: Output file to write result

### Available Methods

- `base64`: Base64 encoding/decoding
- `rot13`: ROT13 cipher (symmetric - encoding and decoding are identical)
- `hex`: Hexadecimal encoding/decoding

## Examples

### Basic Operations

```bash
# Encode text with Base64
python base64rot13hex.py encode --input "Hello World" --method base64
# Output: SGVsbG8gV29ybGQ=

# Decode Base64 text
python base64rot13hex.py decode --input "SGVsbG8gV29ybGQ=" --method base64
# Output: Hello World

# Apply ROT13 encoding
python base64rot13hex.py encode --input "Hello World" --method rot13
# Output: Uryyb Jbeyq

# Convert to hexadecimal
python base64rot13hex.py encode --input "Hello" --method hex
# Output: 48656c6c6f
```

### Advanced Chaining

```bash
# Triple encoding: Base64 → ROT13 → Hex
python base64rot13hex.py encode --input "Secret" --method base64 --method rot13 --method hex
# Output: (complex encoded string)

# Triple decoding: Hex → ROT13 → Base64 (reverse order automatically applied)
python base64rot13hex.py decode --input "encoded_string" --method base64 --method rot13 --method hex
```

### File Processing

```bash
# Create input file
echo "This is a secret message" > message.txt

# Encode file content
python base64rot13hex.py encode --file message.txt --method base64 --method rot13 --output encoded.txt

# Decode file content
python base64rot13hex.py decode --file encoded.txt --method base64 --method rot13 --output decoded.txt
```

### Interactive Mode Example

```
$ python base64rot13hex.py interactive
=== Base64ROT13Hex Encoder & Decoder - Interactive Mode ===
Available methods: base64, rot13, hex
Type 'quit' or 'exit' to leave interactive mode.

Choose operation (encode/decode): encode
Enter text: Hello World
Enter methods (comma-separated, e.g., base64,rot13,hex): base64,rot13

Result: FryyB JbeyQ=
```

## Understanding Method Chaining

When chaining multiple encoding methods, they are applied in the order specified:

1. **Encoding**: Methods are applied left-to-right
   - `--method base64 --method rot13 --method hex`
   - Text → Base64 → ROT13 → Hex

2. **Decoding**: Methods are automatically reversed
   - `--method base64 --method rot13 --method hex`
   - Text ← Base64 ← ROT13 ← Hex (applied as Hex → ROT13 → Base64)

## Error Handling

The script includes comprehensive error handling for:

- Invalid encoding/decoding operations
- File I/O errors
- Invalid method names
- Malformed input data
- UTF-8 encoding/decoding issues

Error messages are descriptive and help identify the specific issue.

## Notes and Limitations

### Security Notes

- **ROT13** is not a secure encryption method - it's a simple letter substitution cipher
- **Base64** is encoding, not encryption - it provides no security
- **Hexadecimal** is a representation format, not encryption
- This tool is intended for data transformation, not security purposes

### Limitations

- Input text must be valid UTF-8
- Very large files may consume significant memory
- ROT13 only affects alphabetic characters (A-Z, a-z)
- Binary data should be handled carefully with Base64/Hex methods

### Best Practices

- Use file processing for large amounts of data
- Always test decode operations with known encoded data
- Be aware of the order when chaining multiple methods
- Use interactive mode for experimentation and learning

## Troubleshooting

### Common Issues

1. **"Base64 decoding failed"**: Input may not be valid Base64
2. **"Hex decoding failed"**: Input may contain non-hexadecimal characters
3. **"File not found"**: Check file path and permissions
4. **"Invalid method"**: Ensure method names are lowercase and correctly spelled

### Getting Help

```bash
# General help
python base64rot13hex.py --help

# Command-specific help
python base64rot13hex.py encode --help
python base64rot13hex.py decode --help
```

## Contributing

This script is designed to be educational and practical. Contributions for improvements are welcome:

- Additional encoding methods
- Performance optimizations
- Enhanced error handling
- Documentation improvements

## License

MIT License

Copyright (c) 2024

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

## Version History

- **v1.0.0**: Initial release with Base64, ROT13, and Hex support, method chaining, and interactive mode
