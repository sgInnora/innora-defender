#!/usr/bin/env python3
"""
Simple script to analyze all samples in a directory
and generate reports in English
"""

import os
import sys
import json
import logging
import subprocess
import datetime
from pathlib import Path
import hashlib
import shutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SampleAnalysis')

def analyze_sample(sample_path, output_dir=None):
    """
    Analyze a malware sample
    
    Args:
        sample_path: Path to the sample
        output_dir: Output directory for results
    """
    sample_name = os.path.basename(sample_path)
    logger.info(f"Analyzing sample: {sample_path}")
    
    # Create output directory
    if output_dir is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = f"output/{os.path.splitext(sample_name)[0]}_{timestamp}"
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Analyze the sample
    results = {
        'sample': {
            'path': sample_path,
            'name': sample_name,
            'size': os.path.getsize(sample_path),
            'hashes': compute_hashes(sample_path)
        },
        'timestamp': datetime.datetime.now().isoformat(),
        'analysis': perform_analysis(sample_path)
    }
    
    # Save results
    report_path = os.path.join(output_dir, 'analysis_report.json')
    with open(report_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Generate markdown report
    markdown_report = generate_markdown_report(results)
    markdown_path = os.path.join(output_dir, 'analysis_report.md')
    with open(markdown_path, 'w') as f:
        f.write(markdown_report)
    
    logger.info(f"Analysis report saved to: {markdown_path}")
    return results

def compute_hashes(file_path):
    """Compute cryptographic hashes for a file"""
    with open(file_path, 'rb') as f:
        data = f.read()
    
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    
    return {
        'md5': md5,
        'sha1': sha1,
        'sha256': sha256
    }

def perform_analysis(sample_path):
    """Perform basic analysis on a sample"""
    # Get file type
    try:
        output = subprocess.check_output(['file', sample_path]).decode('utf-8', errors='ignore')
        file_type = output.strip()
    except:
        file_type = "Unknown file type"
    
    # Get strings
    try:
        strings_output = subprocess.check_output(['strings', '-a', '-n', '8', sample_path]).decode('utf-8', errors='ignore')
        strings = strings_output.split('\n')
    except:
        strings = []
    
    # Extract indicators
    indicators = extract_indicators(strings)
    
    return {
        'file_type': file_type,
        'strings_count': len(strings),
        'indicators': indicators
    }

def extract_indicators(strings):
    """Extract indicators from strings"""
    indicators = {}
    
    # Keywords by category
    keywords = {
        'ransomware': [
            'ransom', 'encrypt', 'decrypt', 'bitcoin', 'btc', 'wallet', 'payment', 
            'victim', 'restore', 'recovery', '.onion', 'tor', 'readme', 'locker'
        ],
        'encryption': [
            'aes', 'rsa', 'chacha', 'salsa', 'blowfish', 'twofish', 'rijndael', 
            'key', 'encrypt', 'decrypt', 'cipher'
        ],
        'network': [
            'http://', 'https://', '.onion', 'url', 'server', 'connect', 'ip', 
            'socket', 'dns', 'domain'
        ]
    }
    
    # Check each category
    for category, category_keywords in keywords.items():
        category_matches = {}
        for keyword in category_keywords:
            matches = [s for s in strings if keyword.lower() in s.lower()]
            if matches:
                category_matches[keyword] = len(matches)
        
        if category_matches:
            indicators[category] = category_matches
    
    return indicators

def generate_markdown_report(results):
    """Generate a markdown report from analysis results"""
    sample = results['sample']
    analysis = results['analysis']
    
    # Build markdown
    markdown = []
    markdown.append(f"# Malware Analysis Report\n")
    markdown.append(f"*Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
    
    # Sample information
    markdown.append("## Sample Information\n\n")
    markdown.append(f"- **Filename**: {sample['name']}\n")
    markdown.append(f"- **File Size**: {sample['size']} bytes\n")
    markdown.append(f"- **File Type**: {analysis['file_type']}\n")
    markdown.append(f"- **MD5**: `{sample['hashes']['md5']}`\n")
    markdown.append(f"- **SHA1**: `{sample['hashes']['sha1']}`\n")
    markdown.append(f"- **SHA256**: `{sample['hashes']['sha256']}`\n\n")
    
    # Analysis results
    markdown.append("## Analysis Results\n\n")
    markdown.append(f"- **Strings Count**: {analysis['strings_count']}\n\n")
    
    # Indicators
    markdown.append("### Detected Indicators\n\n")
    
    if not analysis['indicators']:
        markdown.append("No significant indicators detected\n\n")
    else:
        for category, matches in analysis['indicators'].items():
            markdown.append(f"#### {category} Indicators\n\n")
            markdown.append("| Indicator | Occurrences |\n")
            markdown.append("|-----------|-------------|\n")
            for indicator, count in matches.items():
                markdown.append(f"| {indicator} | {count} |\n")
            markdown.append("\n")
    
    # Conclusion
    markdown.append("## Conclusion\n\n")
    
    # Determine if likely ransomware
    ransomware_score = 0
    if 'ransomware' in analysis['indicators']:
        num_ransom_indicators = len(analysis['indicators']['ransomware'])
        if num_ransom_indicators >= 3:
            ransomware_score = 2  # High
        elif num_ransom_indicators >= 1:
            ransomware_score = 1  # Medium
    
    if 'encryption' in analysis['indicators']:
        num_encryption_indicators = len(analysis['indicators']['encryption'])
        if num_encryption_indicators >= 3:
            ransomware_score += 1
    
    if ransomware_score >= 2:
        markdown.append("This sample shows **strong indicators of being ransomware**.\n\n")
    elif ransomware_score == 1:
        markdown.append("This sample shows **some indicators of being ransomware**, but more analysis is needed.\n\n")
    else:
        markdown.append("This sample does not show clear ransomware characteristics.\n\n")
    
    # Recommendations
    markdown.append("### Recommendations\n\n")
    markdown.append("- Analyze the sample in a secure sandbox environment\n")
    markdown.append("- Perform deeper analysis with specialized tools\n")
    markdown.append("- Check for known decryption tools if ransomware identified\n")
    
    return "\n".join(markdown)

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <sample_dir> [output_dir]")
        return 1
    
    sample_dir = sys.argv[1]
    output_base_dir = sys.argv[2] if len(sys.argv) > 2 else "output"
    
    if not os.path.isdir(sample_dir):
        logger.error(f"Sample directory not found: {sample_dir}")
        return 1
    
    # Create output directory
    os.makedirs(output_base_dir, exist_ok=True)
    
    # Get all samples
    samples = [os.path.join(sample_dir, f) for f in os.listdir(sample_dir) if os.path.isfile(os.path.join(sample_dir, f))]
    
    if not samples:
        logger.error(f"No samples found in {sample_dir}")
        return 1
    
    logger.info(f"Found {len(samples)} samples to analyze")
    
    # Analyze each sample
    for sample_path in samples:
        sample_name = os.path.basename(sample_path)
        output_dir = os.path.join(output_base_dir, os.path.splitext(sample_name)[0])
        try:
            analyze_sample(sample_path, output_dir)
        except Exception as e:
            logger.error(f"Error analyzing {sample_path}: {e}")
    
    logger.info("Analysis complete")
    return 0

if __name__ == "__main__":
    sys.exit(main())