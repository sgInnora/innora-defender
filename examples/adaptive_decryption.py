#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Adaptive Decryption Demo Script

This script demonstrates the enhanced adaptive algorithm selection capabilities
of the Universal Streaming Engine. It provides a convenient way to test and
evaluate the automatic detection features with various ransomware samples.

Examples:
    # Decrypt a single file with automatic algorithm detection
    python adaptive_decryption.py --file encrypted.locked --key 5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A --auto-detect
    
    # Batch process multiple files with adaptive learning
    python adaptive_decryption.py --batch "samples/*.locked" --key-file key.bin --output-dir decrypted/ --parallel
    
    # Process files with a known ransomware family
    python adaptive_decryption.py --batch "samples/*.ryuk" --key 5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A --family ryuk
"""

import os
import sys
import glob
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add parent directory to path to allow importing from decryption_tools
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import our streaming engine
from decryption_tools.streaming_engine import (
    StreamingDecryptionEngine, 
    AlgorithmDetector,
    ValidationLevel
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("AdaptiveDecryptionDemo")

def main():
    parser = argparse.ArgumentParser(description="Adaptive Decryption Demo")
    # Input/output options
    parser.add_argument("--file", help="Encrypted file to decrypt")
    parser.add_argument("--output", help="Output file for decrypted data")
    parser.add_argument("--batch", help="Process multiple files matching a glob pattern")
    parser.add_argument("--output-dir", help="Output directory for batch processing")
    
    # Encryption info
    parser.add_argument("--family", help="Ransomware family (optional)")
    parser.add_argument("--algorithm", help="Specific encryption algorithm to use")
    parser.add_argument("--key", help="Hex-encoded decryption key")
    parser.add_argument("--iv", help="Hex-encoded IV")
    parser.add_argument("--key-file", help="File containing key data")
    parser.add_argument("--header-size", type=int, help="Header size to skip")
    
    # Advanced options
    parser.add_argument("--auto-detect", action="store_true", help="Automatically detect encryption algorithm")
    parser.add_argument("--retry-algorithms", action="store_true", help="Try multiple algorithms if first attempt fails")
    parser.add_argument("--threaded", action="store_true", help="Use multi-threading")
    parser.add_argument("--validation", choices=["none", "basic", "standard", "strict"], 
                      default="standard", help="Validation level")
    parser.add_argument("--parallel", action="store_true", help="Use parallel processing for batch operations")
    parser.add_argument("--no-adaptive", action="store_true", help="Disable adaptive parameter learning for batch")
    parser.add_argument("--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--extract-params", action="store_true", help="Only extract parameters without decrypting")
    parser.add_argument("--analyze-algorithm", action="store_true", help="Analyze file to detect algorithm without decrypting")
    
    args = parser.parse_args()
    
    # Set logging level based on verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        # Set library logging level as well
        logging.getLogger("StreamingDecryptor").setLevel(logging.DEBUG)
    
    # Special analysis mode
    if args.analyze_algorithm:
        analyze_algorithm_only(args)
        return
    
    # Validate arguments
    if args.batch and args.output_dir:
        # Batch mode
        pass
    elif args.file and args.output:
        # Single file mode
        pass
    elif args.extract_params and args.file:
        # Parameter extraction mode
        extract_params_only(args)
        return
    else:
        print("Error: You must specify either --file and --output OR --batch and --output-dir")
        parser.print_help()
        sys.exit(1)
    
    # Get decryption key
    key = get_key_from_args(args)
    
    # Get IV if provided
    iv = None
    if args.iv:
        try:
            iv = bytes.fromhex(args.iv)
        except ValueError:
            logger.error("Invalid IV format. Must be hex-encoded.")
            sys.exit(1)
    
    # Map validation level
    validation_map = {
        "none": ValidationLevel.NONE,
        "basic": ValidationLevel.BASIC,
        "standard": ValidationLevel.STANDARD,
        "strict": ValidationLevel.STRICT
    }
    validation_level = validation_map[args.validation]
    
    # Create parameters
    params = {
        "iv": iv,
        "validation_level": validation_level,
        "use_threading": args.threaded,
        "auto_detect": args.auto_detect or (not args.family and not args.algorithm),
        "retry_algorithms": args.retry_algorithms
    }
    
    if args.header_size is not None:
        params["header_size"] = args.header_size
    
    # Create decryption engine
    engine = StreamingDecryptionEngine()
    
    # Execute in batch or single file mode
    if args.batch:
        process_batch(engine, args, key, params)
    else:
        process_single_file(engine, args, key, params)

def analyze_algorithm_only(args):
    """Analyze file(s) to detect algorithm without actually decrypting"""
    
    if not args.file and not args.batch:
        print("Error: You must specify either --file or --batch for analysis")
        sys.exit(1)
        
    # Create algorithm detector
    detector = AlgorithmDetector()
    
    # Get files to analyze
    files_to_analyze = []
    if args.file:
        files_to_analyze.append(args.file)
    elif args.batch:
        files_to_analyze = glob.glob(args.batch, recursive=True)
        
    if not files_to_analyze:
        print(f"No files found matching pattern: {args.batch}")
        sys.exit(1)
    
    print(f"\nAnalyzing {len(files_to_analyze)} file(s)...\n")
    
    # Analyze each file
    for file_path in files_to_analyze:
        print(f"File: {os.path.basename(file_path)}")
        print(f"Path: {file_path}")
        
        try:
            # Detect algorithm
            result = detector.detect_algorithm(file_path, args.family)
            
            # Print results
            print(f"  Detected Algorithm: {result['algorithm']}")
            print(f"  Confidence: {result['confidence']:.2f}")
            
            if "family" in result:
                print(f"  Detected Family: {result['family']}")
                
            print("  Parameters:")
            for key, value in result.get("params", {}).items():
                print(f"    {key}: {value}")
                
            # Show detection method
            methods = []
            if result.get("params", {}).get("family_match"):
                methods.append("Explicit family match")
            if result.get("params", {}).get("extension_match"):
                methods.append("File extension match")
            if result.get("params", {}).get("signature_match"):
                methods.append("File signature match")
                
            if methods:
                print(f"  Detection Method: {', '.join(methods)}")
                
            print("")
        except Exception as e:
            print(f"  Error analyzing {file_path}: {e}")
            print("")

def extract_params_only(args):
    """Extract decryption parameters from a file without decrypting"""
    if not args.file:
        print("Error: You must specify --file for parameter extraction")
        sys.exit(1)
    
    # Create algorithm detector
    detector = AlgorithmDetector()
    
    print(f"\nExtracting parameters from {args.file}...\n")
    
    try:
        # Detect algorithm and parameters
        result = detector.detect_algorithm(args.file, args.family)
        
        # Print the full results including all parameters
        print(f"File: {os.path.basename(args.file)}")
        print(f"Path: {args.file}")
        print(f"Detected Algorithm: {result['algorithm']}")
        print(f"Confidence: {result['confidence']:.2f}")
        
        if "family" in result:
            print(f"Detected Family: {result['family']}")
        
        print("\nExtracted Parameters:")
        for key, value in result.get("params", {}).items():
            print(f"  {key}: {value}")
        
        # Generate a command line example for decryption
        print("\nCommand Line Example:")
        cmd = f"python {__file__} --file {args.file} --output {args.file}.decrypted"
        
        # Add algorithm
        cmd += f" --algorithm {result['algorithm']}"
        
        # Add key placeholder
        cmd += " --key YOUR_KEY_HERE"
        
        # Add parameters
        for param_name, param_value in result.get("params", {}).items():
            if param_name == "header_size":
                cmd += f" --header-size {param_value}"
        
        print(cmd)
        
    except Exception as e:
        print(f"Error extracting parameters: {e}")

def process_single_file(engine, args, key, params):
    """Process a single file for decryption"""
    logger.info(f"Decrypting file: {args.file}")
    
    if args.family:
        # Use family-specific configuration
        result = engine.decrypt_file(args.file, args.output, args.family, key, **params)
    else:
        # Use algorithm or auto-detect
        if args.algorithm:
            # Use specified algorithm
            params.pop("auto_detect", None)  # Remove auto_detect if present
            result = engine.decrypt_file(args.file, args.output, None, key, algorithm=args.algorithm, **params)
        else:
            # Force auto-detect since no family or algorithm specified
            params["auto_detect"] = True
            result = engine.decrypt_file(args.file, args.output, None, key, **params)
    
    # Print result
    if result.get("success", False):
        print(f"\nSuccessfully decrypted {args.file} to {args.output}")
        
        # Print additional info
        print(f"Algorithm: {result.get('algorithm', 'unknown')}")
        
        if "validation" in result:
            print(f"Validation method: {result['validation'].get('method')}")
            if "entropy" in result["validation"]:
                print(f"Data entropy: {result['validation']['entropy']:.2f}")
        
        if params.get("auto_detect"):
            if result.get("algorithm_retry", False):
                print("Auto-detection: Used algorithm retry")
            if "confidence" in result:
                print(f"Detection confidence: {result['confidence']:.2f}")
        
        if "throughput_bps" in result:
            mbps = result["throughput_bps"] / (1024 * 1024)
            print(f"Throughput: {mbps:.2f} MB/s")
        
        if args.verbose:
            # Print all parameters used
            print("\nDecryption Parameters:")
            for k, v in result.items():
                if k not in ["success", "validation", "throughput_bps", "error"]:
                    print(f"  {k}: {v}")
    else:
        print(f"\nDecryption failed: {result.get('error', 'Unknown error')}")
        
        if result.get("partial_success", False):
            print("Partial success: output file created but validation failed")
            
        if "validation" in result and "error" in result["validation"]:
            print(f"Validation error: {result['validation']['error']}")
            
        if args.verbose and "algorithm" in result:
            print(f"Attempted algorithm: {result['algorithm']}")
            
        sys.exit(1)

def process_batch(engine, args, key, params):
    """Process multiple files in batch mode"""
    # Get files matching the pattern
    matched_files = glob.glob(args.batch, recursive=True)
    
    if not matched_files:
        logger.error(f"No files found matching pattern: {args.batch}")
        sys.exit(1)
    
    logger.info(f"Found {len(matched_files)} files to process")
    
    # Add batch-specific parameters
    batch_params = params.copy()
    batch_params["parallel"] = args.parallel
    batch_params["adaptive_params"] = not args.no_adaptive
    
    # Run batch processing
    results = engine.batch_decrypt(
        matched_files,
        args.output_dir,
        args.family,
        key,
        **batch_params
    )
    
    # Print summary
    print(f"\nBatch Processing Summary:")
    print(f"Total files: {results['total']}")
    print(f"Successfully decrypted: {results['successful']}")
    print(f"Partially successful: {results['partial']}")
    print(f"Failed: {results['failed']}")
    
    # Print algorithm stats
    print("\nAlgorithm Statistics:")
    for algo, stats in results["algorithm_success_rate"].items():
        success_rate = stats["rate"] * 100
        print(f"  {algo}: {stats['successes']}/{stats['attempts']} successful ({success_rate:.1f}%)")
    
    # Print best algorithm
    if results["summary"]["best_algorithm"]:
        print(f"\nBest performing algorithm: {results['summary']['best_algorithm']}")
    
    # Print adaptive info
    if results["summary"]["adapted_parameters"]:
        print("Used adaptive parameters: Yes")
    
    # Detailed file list if verbose
    if args.verbose:
        print("\nDetailed Results:")
        for i, file_result in enumerate(results["files"]):
            status = "SUCCESS" if file_result["success"] else "FAILED"
            print(f"  [{i+1}] {os.path.basename(file_result['input'])}: {status}")
            print(f"      Algorithm: {file_result.get('algorithm', 'unknown')}")
            if file_result.get("used_adaptive_params", False):
                print(f"      Used adaptive parameters")
            if file_result.get("algorithm_retry", False):
                print(f"      Used algorithm retry")
            if not file_result["success"] and "error" in file_result:
                print(f"      Error: {file_result['error']}")
            print()
    
    # Exit with status based on success rate
    if results["successful"] == 0:
        print("No files were successfully decrypted.")
        sys.exit(1)
    elif results["failed"] > 0:
        print(f"Warning: {results['failed']} files failed to decrypt.")
        sys.exit(0)
    else:
        print("All files successfully decrypted.")
        sys.exit(0)

def get_key_from_args(args) -> bytes:
    """Extract and normalize key from command line arguments"""
    key = None
    
    # Skip key requirement if only analyzing
    if args.analyze_algorithm or args.extract_params:
        return b'\x00' * 32  # Dummy key
    
    if args.key:
        try:
            key = bytes.fromhex(args.key)
        except ValueError:
            logger.error("Invalid key format. Must be hex-encoded.")
            sys.exit(1)
    elif args.key_file:
        try:
            with open(args.key_file, 'rb') as f:
                key_data = f.read().strip()
                
            # Try to parse as hex
            if all(c in b'0123456789ABCDEFabcdef' for c in key_data):
                try:
                    key = bytes.fromhex(key_data.decode())
                except:
                    key = key_data
            else:
                key = key_data
        except Exception as e:
            logger.error(f"Error reading key file: {e}")
            sys.exit(1)
    
    if not key and not (args.analyze_algorithm or args.extract_params):
        logger.error("No key provided. Use --key or --key-file.")
        sys.exit(1)
    
    return key

if __name__ == "__main__":
    main()