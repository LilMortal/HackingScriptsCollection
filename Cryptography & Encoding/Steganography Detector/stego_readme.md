# Steganography Detector

A Python script that analyzes images to detect potential steganographic content using various statistical and visual analysis techniques.

## Description

This tool implements multiple detection methods to identify hidden data in images:

- **Chi-Square Test**: Analyzes pixel value distributions to detect statistical anomalies
- **LSB Analysis**: Examines least significant bit patterns for hidden data
- **Visual Attack**: Enhances LSB planes to reveal visual patterns
- **File Structure Analysis**: Checks for unusual file size patterns

The detector provides a comprehensive analysis with suspicion scores and detailed reports to help identify potentially modified images.

## Features

- Multiple detection algorithms for comprehensive analysis
- Command-line interface with flexible options
- Detailed reporting with suspicion scores
- JSON output for programmatic use
- Support for common image formats (PNG, JPEG, BMP, etc.)
- Verbose logging for detailed analysis
- Error handling and input validation

## Installation

### Prerequisites

- Python 3.6 or higher
- pip package manager

### Install Dependencies

```bash
pip install Pillow numpy scipy matplotlib
```

Or install all dependencies at once:

```bash
pip install -r requirements.txt
```

Create a `requirements.txt` file with:
```
Pillow>=8.0.0
numpy>=1.19.0
scipy>=1.5.0
matplotlib>=3.3.0
```

### Download the Script

1. Save the script as `steganography_detector.py`
2. Make it executable (Unix/Linux/macOS):
   ```bash
   chmod +x steganography_detector.py
   ```

## Usage

### Basic Usage

Analyze an image with all detection methods:
```bash
python steganography_detector.py image.png
```

### Advanced Usage

#### Save results to a file:
```bash
python steganography_detector.py image.jpg --output results.json
```

#### Enable verbose output:
```bash
python steganography_detector.py image.png --verbose
```

#### Run specific detection methods:
```bash
# Chi-square test only
python steganography_detector.py image.png --chi-square

# LSB analysis only
python steganography_detector.py image.png --lsb-analysis

# Multiple specific methods
python steganography_detector.py image.png --chi-square --visual-attack
```

#### Comprehensive analysis with output:
```bash
python steganography_detector.py suspicious_image.png --all-methods --output analysis.json --verbose
```

## Command Line Arguments

| Argument | Description |
|----------|-------------|
| `image` | Path to the image file to analyze (required) |
| `--output`, `-o` | Output file path for results (JSON format) |
| `--verbose`, `-v` | Enable verbose output and logging |
| `--all-methods` | Run all detection methods (default behavior) |
| `--chi-square` | Run chi-square test only |
| `--lsb-analysis` | Run LSB analysis only |
| `--visual-attack` | Run visual attack only |
| `--file-structure` | Run file structure analysis only |

## Detection Methods Explained

### 1. Chi-Square Test
- Analyzes the distribution of pixel values
- Compares observed vs. expected frequency distributions
- Low p-values (< 0.05) may indicate hidden data

### 2. LSB Analysis
- Examines patterns in the least significant bits
- Calculates entropy and distribution ratios
- Detects deviations from natural randomness

### 3. Visual Attack
- Enhances LSB planes for visual inspection
- Analyzes variance patterns in bit planes
- Identifies structured patterns that may indicate hidden data

### 4. File Structure Analysis
- Compares actual vs. expected file sizes
- Accounts for compression ratios
- Detects unusual size anomalies

## Output Format

### Console Output
The script provides a detailed human-readable report including:
- Image information (size, format, mode)
- Individual test results with interpretations
- Overall suspicion score and assessment

### JSON Output (--output option)
Structured data including:
- All test results with numerical values
- Suspicion flags for each method
- Summary statistics and overall assessment

Example JSON structure:
```json
{
  "image_info": {
    "path": "image.png",
    "size": [800, 600],
    "mode": "RGB",
    "format": "PNG"
  },
  "chi_square_test": {
    "chi2_statistic": 12345.67,
    "p_value": 0.001234,
    "suspicious": true,
    "interpretation": "Suspicious"
  },
  "summary": {
    "suspicious_tests": 2,
    "total_tests": 4,
    "suspicion_score": 0.5,
    "overall_assessment": "Moderately Suspicious"
  }
}
```

## Interpretation Guide

### Suspicion Scores
- **0.75 - 1.0**: Highly Suspicious
- **0.5 - 0.74**: Moderately Suspicious  
- **0.25 - 0.49**: Slightly Suspicious
- **0.0 - 0.24**: Likely Clean

### What to Look For
- Multiple tests showing suspicious results
- Very low p-values in statistical tests
- High entropy in LSB planes
- Unusual file size ratios
- Visual patterns in enhanced bit planes

## Limitations

1. **False Positives**: Natural images may sometimes trigger suspicion
2. **Advanced Steganography**: May not detect sophisticated hiding techniques
3. **File Formats**: Some analysis methods work better with lossless formats (PNG) than compressed formats (JPEG)
4. **Detection vs. Extraction**: This tool detects potential steganography but does not extract hidden data

## Ethical Use and Legal Notice

⚠️ **IMPORTANT**: This tool is intended for:
- Educational purposes
- Security research
- Digital forensics investigations
- Testing your own images

**Do NOT use this tool to**:
- Analyze images without proper authorization
- Violate privacy rights
- Circumvent security measures
- Engage in illegal activities

Users are responsible for ensuring their use complies with applicable laws and regulations.

## Troubleshooting

### Common Issues

1. **Import Error**: Install missing dependencies
   ```bash
   pip install Pillow numpy scipy matplotlib
   ```

2. **File Not Found**: Check image path and file permissions

3. **Unsupported Format**: Convert image to a supported format (PNG, JPEG, BMP)

4. **Memory Issues**: Large images may require more RAM; try resizing the image

### Getting Help

- Run with `--verbose` for detailed logging
- Check that all dependencies are properly installed
- Ensure the image file is not corrupted

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

MIT License

Copyright (c) 2024 Steganography Detector

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
- Chi-square test implementation
- LSB analysis functionality
- Visual attack method
- File structure analysis
- Command-line interface
- JSON output support
- Comprehensive reporting

## References

- [Steganography Detection Techniques](https://en.wikipedia.org/wiki/Steganalysis)
- [Chi-Square Test in Steganography](https://link.springer.com/chapter/10.1007/3-540-61996-8_48)
- [LSB Steganography Detection](https://ieeexplore.ieee.org/document/1335547)

---

For more information or support, please open an issue in the project repository.
