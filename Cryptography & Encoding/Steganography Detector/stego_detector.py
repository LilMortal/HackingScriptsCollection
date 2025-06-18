#!/usr/bin/env python3
"""
Steganography Detector

A Python script to detect potential steganographic content in images using various
statistical and visual analysis techniques.

Author: Assistant
License: MIT
Version: 1.0.0

Usage Example:
    python steganography_detector.py input_image.png --output results.txt --all-methods

Dependencies:
    - PIL (Pillow): pip install Pillow
    - NumPy: pip install numpy
    - SciPy: pip install scipy
    - Matplotlib: pip install matplotlib
"""

import argparse
import sys
import os
from pathlib import Path
import logging
from typing import Dict, List, Tuple, Optional
import json

try:
    import numpy as np
    from PIL import Image
    from scipy import stats
    import matplotlib.pyplot as plt
    from collections import Counter
except ImportError as e:
    print(f"Error: Missing required dependency: {e}")
    print("Please install required packages:")
    print("pip install Pillow numpy scipy matplotlib")
    sys.exit(1)


class SteganographyDetector:
    """
    A class to detect potential steganographic content in images using various
    statistical and visual analysis techniques.
    """
    
    def __init__(self, image_path: str, verbose: bool = False):
        """
        Initialize the steganography detector.
        
        Args:
            image_path (str): Path to the image file to analyze
            verbose (bool): Enable verbose logging output
        """
        self.image_path = Path(image_path)
        self.verbose = verbose
        self.image = None
        self.image_array = None
        self.results = {}
        
        # Set up logging
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Load and validate image
        self._load_image()
    
    def _load_image(self) -> None:
        """Load and validate the input image."""
        try:
            if not self.image_path.exists():
                raise FileNotFoundError(f"Image file not found: {self.image_path}")
            
            self.image = Image.open(self.image_path)
            self.image_array = np.array(self.image)
            
            self.logger.info(f"Loaded image: {self.image_path}")
            self.logger.info(f"Image size: {self.image.size}")
            self.logger.info(f"Image mode: {self.image.mode}")
            
        except Exception as e:
            self.logger.error(f"Failed to load image: {e}")
            raise
    
    def chi_square_test(self) -> Dict[str, float]:
        """
        Perform chi-square test to detect LSB steganography.
        
        This test analyzes the distribution of pixel values to detect
        anomalies that might indicate hidden data.
        
        Returns:
            Dict containing chi-square statistics and p-value
        """
        self.logger.info("Performing chi-square test...")
        
        try:
            # Convert to grayscale if needed
            if len(self.image_array.shape) == 3:
                gray = np.mean(self.image_array, axis=2).astype(np.uint8)
            else:
                gray = self.image_array
            
            # Calculate frequency distribution
            hist, _ = np.histogram(gray.flatten(), bins=256, range=(0, 256))
            
            # Expected uniform distribution
            expected = np.full(256, len(gray.flatten()) / 256)
            
            # Perform chi-square test
            chi2_stat, p_value = stats.chisquare(hist, expected)
            
            # Interpretation
            suspicious = p_value < 0.05
            
            result = {
                'chi2_statistic': float(chi2_stat),
                'p_value': float(p_value),
                'suspicious': suspicious,
                'interpretation': 'Suspicious' if suspicious else 'Normal'
            }
            
            self.logger.info(f"Chi-square test completed: {result['interpretation']}")
            return result
            
        except Exception as e:
            self.logger.error(f"Chi-square test failed: {e}")
            return {'error': str(e)}
    
    def lsb_analysis(self) -> Dict[str, any]:
        """
        Analyze the least significant bits for patterns indicating steganography.
        
        Returns:
            Dict containing LSB analysis results
        """
        self.logger.info("Performing LSB analysis...")
        
        try:
            # Convert to grayscale if needed
            if len(self.image_array.shape) == 3:
                gray = np.mean(self.image_array, axis=2).astype(np.uint8)
            else:
                gray = self.image_array
            
            # Extract LSBs
            lsb_plane = gray & 1
            
            # Calculate statistics
            lsb_ratio = np.mean(lsb_plane)
            lsb_entropy = self._calculate_entropy(lsb_plane.flatten())
            
            # Check for patterns
            total_pixels = lsb_plane.size
            ones_count = np.sum(lsb_plane)
            zeros_count = total_pixels - ones_count
            
            # Chi-square test on LSB distribution
            observed = [zeros_count, ones_count]
            expected = [total_pixels / 2, total_pixels / 2]
            lsb_chi2, lsb_p = stats.chisquare(observed, expected)
            
            # Determine suspicion level
            suspicious = (abs(lsb_ratio - 0.5) > 0.1) or (lsb_p < 0.05) or (lsb_entropy > 0.9)
            
            result = {
                'lsb_ratio': float(lsb_ratio),
                'lsb_entropy': float(lsb_entropy),
                'chi2_statistic': float(lsb_chi2),
                'p_value': float(lsb_p),
                'suspicious': suspicious,
                'interpretation': 'Suspicious' if suspicious else 'Normal'
            }
            
            self.logger.info(f"LSB analysis completed: {result['interpretation']}")
            return result
            
        except Exception as e:
            self.logger.error(f"LSB analysis failed: {e}")
            return {'error': str(e)}
    
    def _calculate_entropy(self, data: np.ndarray) -> float:
        """Calculate Shannon entropy of data."""
        _, counts = np.unique(data, return_counts=True)
        probabilities = counts / len(data)
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
        return entropy
    
    def visual_attack(self) -> Dict[str, any]:
        """
        Perform visual attack by enhancing LSB plane visibility.
        
        Returns:
            Dict containing visual attack results
        """
        self.logger.info("Performing visual attack...")
        
        try:
            # Convert to grayscale if needed
            if len(self.image_array.shape) == 3:
                gray = np.mean(self.image_array, axis=2).astype(np.uint8)
            else:
                gray = self.image_array
            
            # Extract and enhance LSB plane
            lsb_plane = (gray & 1) * 255
            
            # Calculate variance in LSB plane
            lsb_variance = np.var(lsb_plane)
            
            # Check for structured patterns
            # Calculate local variance to detect regions with patterns
            kernel_size = 8
            h, w = lsb_plane.shape
            local_variances = []
            
            for i in range(0, h - kernel_size, kernel_size):
                for j in range(0, w - kernel_size, kernel_size):
                    block = lsb_plane[i:i+kernel_size, j:j+kernel_size]
                    local_variances.append(np.var(block))
            
            avg_local_variance = np.mean(local_variances)
            variance_ratio = lsb_variance / (avg_local_variance + 1e-10)
            
            # Suspicion criteria
            suspicious = lsb_variance > 10000 or variance_ratio > 2.0
            
            result = {
                'lsb_variance': float(lsb_variance),
                'avg_local_variance': float(avg_local_variance),
                'variance_ratio': float(variance_ratio),
                'suspicious': suspicious,
                'interpretation': 'Suspicious' if suspicious else 'Normal'
            }
            
            self.logger.info(f"Visual attack completed: {result['interpretation']}")
            return result
            
        except Exception as e:
            self.logger.error(f"Visual attack failed: {e}")
            return {'error': str(e)}
    
    def file_structure_analysis(self) -> Dict[str, any]:
        """
        Analyze file structure for anomalies that might indicate steganography.
        
        Returns:
            Dict containing file structure analysis results
        """
        self.logger.info("Performing file structure analysis...")
        
        try:
            file_size = self.image_path.stat().st_size
            
            # Calculate expected file size based on image dimensions
            if self.image.mode == 'RGB':
                expected_size = self.image.size[0] * self.image.size[1] * 3
            elif self.image.mode == 'RGBA':
                expected_size = self.image.size[0] * self.image.size[1] * 4
            else:
                expected_size = self.image.size[0] * self.image.size[1]
            
            # Account for compression (rough estimate)
            compression_ratio = 0.1 if self.image_path.suffix.lower() == '.jpg' else 0.8
            expected_size *= compression_ratio
            
            size_ratio = file_size / expected_size
            
            # Check for unusual file size
            suspicious = size_ratio > 1.5 or size_ratio < 0.5
            
            # Get image format info
            format_info = {
                'format': self.image.format,
                'mode': self.image.mode,
                'size': self.image.size
            }
            
            result = {
                'file_size': file_size,
                'expected_size': int(expected_size),
                'size_ratio': float(size_ratio),
                'format_info': format_info,
                'suspicious': suspicious,
                'interpretation': 'Suspicious' if suspicious else 'Normal'
            }
            
            self.logger.info(f"File structure analysis completed: {result['interpretation']}")
            return result
            
        except Exception as e:
            self.logger.error(f"File structure analysis failed: {e}")
            return {'error': str(e)}
    
    def detect_all(self) -> Dict[str, any]:
        """
        Run all detection methods and compile results.
        
        Returns:
            Dict containing all analysis results
        """
        self.logger.info("Running all detection methods...")
        
        results = {
            'image_info': {
                'path': str(self.image_path),
                'size': self.image.size,
                'mode': self.image.mode,
                'format': self.image.format
            },
            'chi_square_test': self.chi_square_test(),
            'lsb_analysis': self.lsb_analysis(),
            'visual_attack': self.visual_attack(),
            'file_structure_analysis': self.file_structure_analysis()
        }
        
        # Calculate overall suspicion score
        suspicious_tests = 0
        total_tests = 0
        
        for test_name, test_result in results.items():
            if test_name != 'image_info' and isinstance(test_result, dict):
                if 'suspicious' in test_result:
                    total_tests += 1
                    if test_result['suspicious']:
                        suspicious_tests += 1
        
        suspicion_score = suspicious_tests / total_tests if total_tests > 0 else 0
        
        results['summary'] = {
            'suspicious_tests': suspicious_tests,
            'total_tests': total_tests,
            'suspicion_score': suspicion_score,
            'overall_assessment': self._get_assessment(suspicion_score)
        }
        
        self.results = results
        return results
    
    def _get_assessment(self, score: float) -> str:
        """Get overall assessment based on suspicion score."""
        if score >= 0.75:
            return "Highly Suspicious"
        elif score >= 0.5:
            return "Moderately Suspicious"
        elif score >= 0.25:
            return "Slightly Suspicious"
        else:
            return "Likely Clean"
    
    def save_results(self, output_path: str) -> None:
        """Save results to a JSON file."""
        try:
            with open(output_path, 'w') as f:
                json.dump(self.results, f, indent=2)
            self.logger.info(f"Results saved to: {output_path}")
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
            raise
    
    def generate_report(self) -> str:
        """Generate a human-readable report."""
        if not self.results:
            return "No analysis results available."
        
        report = []
        report.append("="*60)
        report.append("STEGANOGRAPHY DETECTION REPORT")
        report.append("="*60)
        report.append("")
        
        # Image info
        info = self.results['image_info']
        report.append(f"Image: {info['path']}")
        report.append(f"Size: {info['size'][0]} x {info['size'][1]}")
        report.append(f"Mode: {info['mode']}")
        report.append(f"Format: {info['format']}")
        report.append("")
        
        # Test results
        report.append("ANALYSIS RESULTS:")
        report.append("-" * 40)
        
        for test_name, result in self.results.items():
            if test_name in ['image_info', 'summary']:
                continue
            
            if isinstance(result, dict) and 'error' not in result:
                test_title = test_name.replace('_', ' ').title()
                report.append(f"\n{test_title}:")
                report.append(f"  Status: {result.get('interpretation', 'Unknown')}")
                
                if 'p_value' in result:
                    report.append(f"  P-value: {result['p_value']:.6f}")
                if 'chi2_statistic' in result:
                    report.append(f"  Chi-square: {result['chi2_statistic']:.2f}")
                if 'suspicion_score' in result:
                    report.append(f"  Suspicion Score: {result['suspicion_score']:.2f}")
        
        # Summary
        summary = self.results['summary']
        report.append("")
        report.append("SUMMARY:")
        report.append("-" * 40)
        report.append(f"Tests Run: {summary['total_tests']}")
        report.append(f"Suspicious Tests: {summary['suspicious_tests']}")
        report.append(f"Suspicion Score: {summary['suspicion_score']:.2f}")
        report.append(f"Overall Assessment: {summary['overall_assessment']}")
        report.append("")
        report.append("="*60)
        
        return "\n".join(report)


def main():
    """Main function to handle command line arguments and run the detector."""
    parser = argparse.ArgumentParser(
        description="Detect potential steganographic content in images",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python steganography_detector.py image.png
  python steganography_detector.py image.jpg --output results.json --verbose
  python steganography_detector.py image.png --chi-square --lsb-analysis
        """
    )
    
    parser.add_argument(
        'image',
        help='Path to the image file to analyze'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output file path for results (JSON format)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    # Analysis method selection
    parser.add_argument(
        '--all-methods',
        action='store_true',
        help='Run all detection methods (default)'
    )
    
    parser.add_argument(
        '--chi-square',
        action='store_true',
        help='Run chi-square test only'
    )
    
    parser.add_argument(
        '--lsb-analysis',
        action='store_true',
        help='Run LSB analysis only'
    )
    
    parser.add_argument(
        '--visual-attack',
        action='store_true',
        help='Run visual attack only'
    )
    
    parser.add_argument(
        '--file-structure',
        action='store_true',
        help='Run file structure analysis only'
    )
    
    args = parser.parse_args()
    
    # Validate input file
    if not os.path.exists(args.image):
        print(f"Error: Image file not found: {args.image}")
        sys.exit(1)
    
    try:
        # Initialize detector
        detector = SteganographyDetector(args.image, verbose=args.verbose)
        
        # Determine which methods to run
        run_all = (args.all_methods or 
                  not any([args.chi_square, args.lsb_analysis, 
                          args.visual_attack, args.file_structure]))
        
        if run_all:
            results = detector.detect_all()
        else:
            results = {'image_info': detector.results.get('image_info', {})}
            
            if args.chi_square:
                results['chi_square_test'] = detector.chi_square_test()
            if args.lsb_analysis:
                results['lsb_analysis'] = detector.lsb_analysis()
            if args.visual_attack:
                results['visual_attack'] = detector.visual_attack()
            if args.file_structure:
                results['file_structure_analysis'] = detector.file_structure_analysis()
            
            detector.results = results
        
        # Output results
        if args.output:
            detector.save_results(args.output)
            print(f"Results saved to: {args.output}")
        
        # Print report
        print(detector.generate_report())
        
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
