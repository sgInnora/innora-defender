#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Error Pattern Detection Demo

This script demonstrates how to use the enhanced error pattern detection features
of the Innora-Defender framework to analyze and troubleshoot batch decryption operations.
"""

import os
import sys
import time
import binascii
import argparse
import logging
from typing import List, Dict, Any
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import Innora-Defender modules
from decryption_tools.streaming_engine import StreamingDecryptor
from decryption_tools.enhanced_error_pattern_detector import EnhancedErrorPatternDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("EnhancedErrorDetectionDemo")

# ANSI color codes for terminal output
SUCCESS_COLOR = '\033[92m'  # Green
ERROR_COLOR = '\033[91m'    # Red
WARNING_COLOR = '\033[93m'  # Yellow
INFO_COLOR = '\033[96m'     # Cyan
HEADER_COLOR = '\033[1;97m' # Bold white
RESET_COLOR = '\033[0m'     # Reset

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Enhanced Error Pattern Detection Demo"
    )
    
    parser.add_argument(
        "--input-dir", 
        help="Directory containing encrypted files"
    )
    
    parser.add_argument(
        "--output-dir", 
        help="Directory to save decrypted files"
    )
    
    parser.add_argument(
        "--algorithm", 
        default="aes-cbc",
        help="Encryption algorithm (default: aes-cbc)"
    )
    
    parser.add_argument(
        "--key", 
        help="Encryption key in hex format"
    )
    
    parser.add_argument(
        "--key-file", 
        help="File containing encryption key"
    )
    
    parser.add_argument(
        "--error-file", 
        help="File to inject errors for demonstration purposes"
    )
    
    parser.add_argument(
        "--summary-file",
        default="error_analysis_summary.json",
        help="File to save batch summary with error analysis"
    )
    
    parser.add_argument(
        "--use-standalone",
        action="store_true",
        help="Use standalone error detector instead of integrated analysis"
    )
    
    return parser.parse_args()

def read_key_file(file_path: str) -> bytes:
    """Read key from file"""
    try:
        with open(file_path, 'rb') as f:
            key_data = f.read().strip()
        
        # If it looks like hex, convert it
        if all(c in b'0123456789abcdefABCDEF' for c in key_data):
            return binascii.unhexlify(key_data)
        
        # Otherwise return raw bytes
        return key_data
    except Exception as e:
        logger.error(f"Error reading key file: {e}")
        sys.exit(1)

def parse_key(key_str: str) -> bytes:
    """Parse hex key string to bytes"""
    try:
        # Remove any spaces or colons
        key_str = key_str.replace(" ", "").replace(":", "")
        return binascii.unhexlify(key_str)
    except Exception as e:
        logger.error(f"Error parsing key: {e}")
        sys.exit(1)

def create_file_mappings(input_dir: str, output_dir: str, inject_error_file: str = None) -> List[Dict[str, str]]:
    """Create file mappings with optional error injection"""
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Create file mappings
    mappings = []
    for file_path in Path(input_dir).glob("**/*"):
        if file_path.is_file():
            # Create output path
            rel_path = file_path.relative_to(input_dir)
            output_path = Path(output_dir) / rel_path
            
            # Ensure output directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Add to mappings
            mappings.append({
                "input": str(file_path),
                "output": str(output_path)
            })
    
    # Inject errors for demonstration if requested
    if inject_error_file:
        for mapping in mappings:
            if inject_error_file in mapping["input"]:
                # Change the extension to cause an error
                mapping["input"] = mapping["input"] + ".error_injected"
                logger.info(f"Injected error for file: {mapping['input']}")
    
    return mappings

def print_recommendations(recommendations: List[Dict[str, Any]]):
    """Print formatted recommendations"""
    if not recommendations:
        print(f"\n{INFO_COLOR}No specific recommendations available.{RESET_COLOR}")
        return
    
    print(f"\n{HEADER_COLOR}RECOMMENDATIONS:{RESET_COLOR}")
    for i, rec in enumerate(recommendations, 1):
        priority = rec.get("priority", "medium")
        if priority == "critical":
            priority_color = ERROR_COLOR
        elif priority == "high":
            priority_color = ERROR_COLOR
        elif priority == "medium":
            priority_color = WARNING_COLOR
        else:
            priority_color = INFO_COLOR
            
        print(f"{i}. {rec.get('message', '')} {priority_color}[{priority}]{RESET_COLOR}")
        
        # Print details if available
        if "details" in rec and isinstance(rec["details"], dict):
            for key, value in rec["details"].items():
                print(f"   - {key}: {value}")

def main():
    """Main function"""
    args = parse_args()
    
    # Validate inputs
    if not args.input_dir:
        logger.error("Input directory is required")
        sys.exit(1)
        
    if not args.output_dir:
        logger.error("Output directory is required")
        sys.exit(1)
        
    if not args.key and not args.key_file:
        logger.error("Either --key or --key-file is required")
        sys.exit(1)
    
    # Get key
    if args.key_file:
        key = read_key_file(args.key_file)
    else:
        key = parse_key(args.key)
    
    # Create file mappings
    logger.info("Creating file mappings...")
    file_mappings = create_file_mappings(args.input_dir, args.output_dir, args.error_file)
    
    if not file_mappings:
        logger.error("No files found in input directory")
        sys.exit(1)
        
    logger.info(f"Found {len(file_mappings)} files to process")
    
    # Initialize decryptor
    logger.info("Initializing decryptor...")
    decryptor = StreamingDecryptor()
    
    # Process files with batch decryption
    logger.info("Starting batch decryption...")
    
    batch_params = {
        "parallel_execution": True,
        "auto_detect_algorithm": True,
        "max_workers": 4,
        "continue_on_error": True,
        "error_pattern_analysis": not args.use_standalone,  # Use integrated analysis by default
        "save_summary": True,
        "summary_file": args.summary_file
    }
    
    # Start timing
    start_time = time.time()
    
    # Run batch decryption
    result = decryptor.batch_decrypt(
        file_mappings=file_mappings,
        algorithm=args.algorithm,
        key=key,
        batch_params=batch_params
    )
    
    # Calculate duration
    duration = time.time() - start_time
    
    # Print basic results
    print(f"\n{HEADER_COLOR}BATCH DECRYPTION COMPLETED{RESET_COLOR}")
    print(f"Total files: {result['files']['total']}")
    print(f"Successful: {SUCCESS_COLOR}{result['files']['successful']}{RESET_COLOR}")
    print(f"Failed: {ERROR_COLOR if result['files']['failed'] > 0 else ''}{result['files']['failed']}{RESET_COLOR}")
    print(f"Duration: {duration:.2f} seconds")
    
    # If using standalone error detection, run it now
    if args.use_standalone and result['files']['failed'] > 0:
        logger.info("Running standalone error pattern analysis...")
        
        # Get file results from the batch processor
        file_results = decryptor.batch_processor.result.file_results
        
        # Initialize error detector
        error_detector = EnhancedErrorPatternDetector()
        
        # Analyze error patterns
        analysis = error_detector.analyze_error_patterns(file_results)
        
        # Print patterns
        if "patterns" in analysis and analysis["patterns"]:
            print(f"\n{HEADER_COLOR}DETECTED ERROR PATTERNS:{RESET_COLOR}")
            for pattern_name, pattern_data in analysis["patterns"].items():
                if isinstance(pattern_data, dict) and "count" in pattern_data:
                    print(f"- {pattern_name}: {pattern_data['count']} instances")
                    if "details" in pattern_data:
                        print(f"  Details: {pattern_data['details']}")
        
        # Print recommendations
        if "recommendations" in analysis:
            print_recommendations(analysis["recommendations"])
    
    # If using integrated analysis, print recommendations from there
    elif not args.use_standalone and result['files']['failed'] > 0:
        if "enhanced_recommendations" in result:
            print_recommendations(result["enhanced_recommendations"])
    
    logger.info(f"Analysis summary saved to {args.summary_file}")

if __name__ == "__main__":
    main()