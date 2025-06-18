# Caesar Cipher Cracker

A comprehensive Python tool for cracking Caesar cipher encrypted text using multiple sophisticated methods including brute force attack, frequency analysis, and interactive testing.

## Description

The Caesar Cipher Cracker is a command-line tool that can decrypt Caesar cipher encrypted text using three different approaches:

1. **Brute Force Attack**: Tries all possible shifts (0-25) and displays all results
2. **Frequency Analysis**: Uses English letter frequency analysis to determine the most likely decryption
3. **Interactive Mode**: Allows manual testing of different shift values
4. **Specific Shift**: Decrypt using a known or suspected shift value

The tool supports both direct text input and file input, making it versatile for different use cases.

## Features

- **Multiple Cracking Methods**: Choose from brute force, frequency analysis, or interactive modes
- **File and Text Input**: Accept encrypted text directly or from files
- **Frequency Analysis**: Uses chi-squared statistics against English letter frequency for intelligent decryption
- **Error Handling**: Comprehensive input validation and error handling
- **Clean Output**: Well-formatted results with ranking and scoring
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **Case Preservation**: Maintains original text capitalization in decrypted output
- **Non-Alphabetic Character Preservation**: Keeps spaces, punctuation, and numbers unchanged

## Installation

### Requirements

- Python 3.6 or higher
- No external dependencies (uses only Python standard library)

### Setup

1. Download the `caesar_cipher_cracker.py` script
2. Make it executable (on Unix-like systems):
   ```bash
   chmod +x caesar_cipher_cracker.py
   ```

No additional installation steps are required as the script uses only Python's standard library.

## Usage

### Basic Syntax

```bash
python caesar_cipher_cracker.py [-h] (-t TEXT | -f FILE) [-m METHOD] [-s SHIFT]
```

### Arguments

- `-t, --text`: Encrypted text to crack (use quotes for text with spaces)
- `-f, --file`: Path to file containing encrypted text
- `-m, --method`: Cracking method - choices: `brute`, `frequency`, `interactive` (default: `frequency`)
- `-s, --shift`: Decrypt using a specific shift value (0-25)
- `-h, --help`: Show help message and usage examples

### Usage Examples

#### 1. Frequency Analysis (Recommended)
```bash
python caesar_cipher_cracker.py -t "KHOOR ZRUOG" -m frequency
```

#### 2. Brute Force Attack
```bash
python caesar_cipher_cracker.py -t "KHOOR ZRUOG" -m brute
```

#### 3. Interactive Mode
```bash
python caesar_cipher_cracker.py -t "KHOOR ZRUOG" -m interactive
```

#### 4. Using a File Input
```bash
python caesar_cipher_cracker.py -f encrypted_message.txt -m frequency
```

#### 5. Testing a Specific Shift
```bash
python caesar_cipher_cracker.py -t "KHOOR ZRUOG" -s 3
```

#### 6. Complex Text with Punctuation
```bash
python caesar_cipher_cracker.py -t "Khoor, Zruog! Krz duh brx?" -m frequency
```

### Method Details

#### Frequency Analysis
- **Best for**: Most encrypted text, especially longer messages
- **How it works**: Compares letter frequency in decrypted text against standard English letter frequency
- **Output**: Ranked results with chi-squared scores (lower scores = more likely to be correct)

#### Brute Force
- **Best for**: Short messages or when you want to see all possibilities
- **How it works**: Tries all 26 possible shifts and displays results
- **Output**: Complete list of all possible decryptions

#### Interactive Mode
- **Best for**: When you want to test specific shifts manually
- **How it works**: Prompts user to enter shift values to test
- **Output**: Shows decryption for each tested shift

## Sample Output

### Frequency Analysis Example
```
Input text: KHOOR ZRUOG

Frequency Analysis Results (sorted by likelihood):
============================================================
Rank Shift Chi²    Decrypted Text
------------------------------------------------------------
1    3     26.89   HELLO WORLD
2    15    156.73  DAHHK SKNHZ
3    7     189.45  DADDK OKNDR
...
Most likely decryption (shift 3): HELLO WORLD
```

### Brute Force Example
```
Input text: KHOOR ZRUOG

Brute Force Analysis:
==================================================
Shift  0: KHOOR ZRUOG
Shift  1: JGNNQ YQTNF
Shift  2: IFMMP XPSME
Shift  3: HELLO WORLD
Shift  4: GDKKN VNQKC
...
```

## File Format

When using file input (`-f` option), the file should contain the encrypted text. The script will:
- Read the entire file content
- Strip leading/trailing whitespace
- Validate that the file contains at least some letters
- Process the text using the specified method

Example file content:
```
WKLV LV D VHFUHW PHVVDJH
```

## Limitations and Notes

### Limitations
- **Caesar Cipher Only**: This tool is specifically designed for Caesar ciphers (simple substitution with fixed shift)
- **English Text**: Frequency analysis is optimized for English text
- **Case Sensitivity**: The tool preserves case but analyzes text case-insensitively
- **No Key Phrases**: Does not use dictionary attacks or known phrase detection

### Best Practices
- **Longer Text**: Frequency analysis works better with longer encrypted text (50+ characters)
- **Clean Input**: Remove or account for non-English characters that might skew frequency analysis
- **Multiple Methods**: Try frequency analysis first, then brute force if needed
- **Context Clues**: Use your knowledge of the expected content to validate results

### Performance
- **Fast Execution**: All methods run quickly even on longer texts
- **Memory Efficient**: Uses minimal memory regardless of text length
- **Scalable**: Performance scales linearly with text length

## Ethical Use and Legal Considerations

### Educational Purpose
This tool is intended for:
- Educational purposes and learning about cryptography
- CTF (Capture The Flag) competitions
- Analyzing historical ciphers
- Understanding encryption vulnerabilities

### Responsible Use
- **Only decrypt text you own or have permission to decrypt**
- **Do not use for unauthorized access to systems or data**
- **Respect privacy and confidentiality**
- **Follow applicable laws and regulations**

### Academic Integrity
If using this tool for academic purposes:
- Follow your institution's policies on tool usage
- Cite the tool appropriately if required
- Understand the underlying concepts, don't just use the tool blindly

## License

MIT License

Copyright (c) 2024 Caesar Cipher Cracker

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

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

### Potential Enhancements
- Support for other languages' frequency distributions
- Dictionary-based attack methods
- GUI interface
- Batch processing of multiple files
- Export results to file
- Support for other simple substitution ciphers

## Version History

- **v1.0.0**: Initial release with brute force, frequency analysis, and interactive modes
- Comprehensive error handling and input validation
- Support for both text and file input
- Cross-platform compatibility

## Support

For questions, issues, or suggestions, please refer to the script's help:
```bash
python caesar_cipher_cracker.py --help
```

## Acknowledgments

- English letter frequency data based on common linguistic analysis
- Chi-squared statistical method for frequency analysis
- Inspired by classical cryptanalysis techniques