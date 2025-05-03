#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced YARA Rule Generator CLI

This script provides a user-friendly command-line interface for using the enhanced
YARA rule generator for ransomware detection.
"""

import os
import sys
import json
import argparse
import logging
from typing import Dict, List, Optional, Any

# Add parent directory to path to allow importing relative modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(current_dir))
sys.path.insert(0, parent_dir)

from utils.yara_enhanced.enhanced_yara_generator import EnhancedYaraGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('yara_cli')

def analyze_sample(args):
    """
    Analyze a single ransomware sample
    
    Args:
        args: Command-line arguments
    """
    # Create generator
    generator = EnhancedYaraGenerator(
        output_dir=args.output,
        legacy_mode=args.legacy,
        benign_samples_dir=args.benign
    )
    
    # Analyze sample
    result = generator.analyze_sample(
        file_path=args.file,
        family=args.family,
        generate_rule=True
    )
    
    # Print results
    print(f"\nSample: {args.file}")
    print(f"Family: {args.family}")
    print(f"SHA256: {result['file_info']['sha256']}")
    print(f"Entropy: {result['file_info']['entropy']:.2f}")
    
    # Print feature counts
    print("\nExtracted Features:")
    for extractor_name, feature_count in result['features'].items():
        print(f"  {extractor_name}: {feature_count}")
    
    # Print rule information
    if 'rule' in result:
        print(f"\nGenerated Rule: {result['rule']}")
        print(f"Rule Path: {result['rule_path']}")
        
        # Print rule content
        print("\nRule Preview:")
        try:
            with open(result['rule_path'], 'r') as f:
                rule_content = f.read()
                # Print first 10 lines and last 5 lines
                lines = rule_content.splitlines()
                if len(lines) > 15:
                    preview_lines = lines[:10] + ["..."] + lines[-5:]
                else:
                    preview_lines = lines
                
                for line in preview_lines:
                    print(f"  {line}")
        except Exception as e:
            print(f"Error reading rule: {e}")

def analyze_directory(args):
    """
    Analyze a directory of ransomware samples
    
    Args:
        args: Command-line arguments
    """
    # Create generator
    generator = EnhancedYaraGenerator(
        output_dir=args.output,
        legacy_mode=args.legacy,
        benign_samples_dir=args.benign
    )
    
    # Find samples
    samples = []
    if args.recursive:
        for root, _, files in os.walk(args.directory):
            for filename in files:
                if not filename.startswith('.'):  # Skip hidden files
                    file_path = os.path.join(root, filename)
                    if os.path.isfile(file_path):
                        samples.append(file_path)
    else:
        for item in os.listdir(args.directory):
            if not item.startswith('.'):  # Skip hidden files
                file_path = os.path.join(args.directory, item)
                if os.path.isfile(file_path):
                    samples.append(file_path)
    
    if not samples:
        print(f"No samples found in {args.directory}")
        return
    
    print(f"Found {len(samples)} samples in {args.directory}")
    
    # Process each sample
    for i, sample in enumerate(samples):
        print(f"\nProcessing sample {i+1}/{len(samples)}: {sample}")
        
        try:
            # Analyze sample
            generator.analyze_sample(
                file_path=sample,
                family=args.family,
                generate_rule=False
            )
        except Exception as e:
            logger.error(f"Error processing {sample}: {e}")
    
    # Generate family rule
    print("\nGenerating family rule...")
    rule = generator.generate_rule_for_family(args.family)
    
    if rule:
        rule_path = os.path.join(generator.output_dir, f"{rule.name}.yar")
        print(f"Generated Rule: {rule.name}")
        print(f"Rule Path: {rule_path}")
        
        # Print rule content
        print("\nRule Preview:")
        try:
            with open(rule_path, 'r') as f:
                rule_content = f.read()
                # Print first 10 lines and last 5 lines
                lines = rule_content.splitlines()
                if len(lines) > 15:
                    preview_lines = lines[:10] + ["..."] + lines[-5:]
                else:
                    preview_lines = lines
                
                for line in preview_lines:
                    print(f"  {line}")
        except Exception as e:
            print(f"Error reading rule: {e}")
    else:
        print("Failed to generate family rule")

def test_rule(args):
    """
    Test a YARA rule against samples
    
    Args:
        args: Command-line arguments
    """
    # Import yara module
    try:
        import yara
    except ImportError:
        print("Error: YARA Python module not installed. Install with 'pip install yara-python'")
        return
    
    # Compile YARA ruleset
    try:
        rules = yara.compile(args.rule)
        print(f"Successfully compiled YARA rule: {args.rule}")
    except Exception as e:
        print(f"Error compiling YARA rule: {e}")
        return
    
    # Find samples
    samples = []
    if args.recursive:
        for root, _, files in os.walk(args.directory):
            for filename in files:
                if not filename.startswith('.'):  # Skip hidden files
                    file_path = os.path.join(root, filename)
                    if os.path.isfile(file_path):
                        samples.append(file_path)
    else:
        for item in os.listdir(args.directory):
            if not item.startswith('.'):  # Skip hidden files
                file_path = os.path.join(args.directory, item)
                if os.path.isfile(file_path):
                    samples.append(file_path)
    
    if not samples:
        print(f"No samples found in {args.directory}")
        return
    
    print(f"Found {len(samples)} samples in {args.directory}")
    
    # Initialize results
    test_results = {
        "total_samples": len(samples),
        "matched_samples": 0,
        "rules_matched": {}
    }
    
    # Test each sample
    matched_files = []
    
    for i, sample in enumerate(samples):
        try:
            print(f"Testing sample {i+1}/{len(samples)}: {os.path.basename(sample)}", end="")
            sys.stdout.flush()
            
            # Skip very large files
            if os.path.getsize(sample) > 100 * 1024 * 1024:  # 100 MB
                print(" [SKIPPED - too large]")
                continue
            
            # Test sample
            matches = rules.match(sample)
            
            if matches:
                print(" [MATCHED]")
                test_results["matched_samples"] += 1
                matched_files.append(sample)
                
                # Count matches per rule
                for match in matches:
                    rule_name = match.rule
                    if rule_name not in test_results["rules_matched"]:
                        test_results["rules_matched"][rule_name] = 0
                    test_results["rules_matched"][rule_name] += 1
            else:
                print(" [NO MATCH]")
            
        except Exception as e:
            print(f" [ERROR: {e}]")
    
    # Print summary
    print("\nTest Results:")
    print(f"Total samples: {test_results['total_samples']}")
    print(f"Matched samples: {test_results['matched_samples']}")
    print(f"Match rate: {test_results['matched_samples'] / test_results['total_samples'] * 100:.2f}%")
    
    # Print matched files
    if matched_files:
        print("\nMatched Files:")
        for file_path in matched_files[:10]:  # Limit to first 10
            print(f"  {os.path.basename(file_path)}")
        
        if len(matched_files) > 10:
            print(f"  ... and {len(matched_files) - 10} more")
    
    # Print matched rules
    if test_results["rules_matched"]:
        print("\nRules Matched:")
        for rule_name, count in sorted(test_results["rules_matched"].items(), 
                                    key=lambda x: x[1], reverse=True):
            print(f"  {rule_name}: {count} matches")
    
    # Save results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(test_results, f, indent=2)
        print(f"\nTest results saved to: {args.output}")

def main():
    """Command-line entry point"""
    parser = argparse.ArgumentParser(
        description="Enhanced YARA Rule Generator for Ransomware Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a single sample
  python yara_cli.py analyze --file /path/to/sample.exe --family Locky
  
  # Analyze a directory of samples
  python yara_cli.py analyze-dir --directory /path/to/samples --family Locky
  
  # Test a rule against samples
  python yara_cli.py test --rule /path/to/rule.yar --directory /path/to/samples
"""
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a single ransomware sample')
    analyze_parser.add_argument('--file', '-f', required=True, help='Path to sample file')
    analyze_parser.add_argument('--family', '-F', required=True, help='Ransomware family name')
    analyze_parser.add_argument('--output', '-o', help='Output directory for YARA rules')
    analyze_parser.add_argument('--benign', '-b', help='Directory containing benign samples for testing')
    analyze_parser.add_argument('--legacy', '-l', action='store_true', help='Use legacy YARA generators if available')
    analyze_parser.set_defaults(func=analyze_sample)
    
    # Analyze directory command
    analyze_dir_parser = subparsers.add_parser('analyze-dir', help='Analyze a directory of ransomware samples')
    analyze_dir_parser.add_argument('--directory', '-d', required=True, help='Directory containing samples')
    analyze_dir_parser.add_argument('--family', '-F', required=True, help='Ransomware family name')
    analyze_dir_parser.add_argument('--recursive', '-r', action='store_true', help='Recursively search for samples')
    analyze_dir_parser.add_argument('--output', '-o', help='Output directory for YARA rules')
    analyze_dir_parser.add_argument('--benign', '-b', help='Directory containing benign samples for testing')
    analyze_dir_parser.add_argument('--legacy', '-l', action='store_true', help='Use legacy YARA generators if available')
    analyze_dir_parser.set_defaults(func=analyze_directory)
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Test a YARA rule against samples')
    test_parser.add_argument('--rule', '-r', required=True, help='Path to YARA rule file')
    test_parser.add_argument('--directory', '-d', required=True, help='Directory containing samples')
    test_parser.add_argument('--recursive', '-R', action='store_true', help='Recursively search for samples')
    test_parser.add_argument('--output', '-o', help='Output file for test results')
    test_parser.set_defaults(func=test_rule)
    
    args = parser.parse_args()
    
    if args.command:
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()