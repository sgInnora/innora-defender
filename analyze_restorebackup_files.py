#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Restorebackup File Analysis Script

This script analyzes .restorebackup files in the specified directory using the
RestoreBackupAnalyzer module. It generates detailed analysis reports of each file
and outputs a comprehensive summary.
"""

import os
import sys
import argparse
import datetime
import logging
from pathlib import Path

# Import the RestoreBackupAnalyzer module
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from decryption_tools.file_format.restorebackup_analyzer import RestoreBackupAnalyzer, RestoreBackupFormat

def main():
    """Main function to analyze restorebackup files"""
    parser = argparse.ArgumentParser(description="Analyze .restorebackup files for ransomware characteristics")
    parser.add_argument("--input_dir", 
                        default="/Users/anwu/Documents/code/company/Innora_dev/1211/samples/any", 
                        help="Directory containing .restorebackup files")
    parser.add_argument("--output_dir", 
                        default=f"./output/restorebackup_analysis_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}", 
                        help="Output directory for analysis results")
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(os.path.join(args.output_dir, "analysis.log"))
        ]
    )
    logger = logging.getLogger("restorebackup_analysis")
    
    logger.info(f"Starting analysis of .restorebackup files in {args.input_dir}")
    logger.info(f"Results will be saved to {args.output_dir}")
    
    # Create analyzer
    analyzer = RestoreBackupAnalyzer(args.output_dir)
    
    # Count files to analyze
    restorebackup_files = [f for f in os.listdir(args.input_dir) if f.endswith('.restorebackup')]
    logger.info(f"Found {len(restorebackup_files)} .restorebackup files")
    
    # Analyze all restorebackup files
    analyzed_files = analyzer.analyze_directory(args.input_dir)
    
    # Generate comprehensive report
    generate_comprehensive_report(analyzed_files, args.output_dir)
    
    logger.info(f"Analysis complete. Analyzed {len(analyzed_files)} files.")
    logger.info(f"Comprehensive report generated at {os.path.join(args.output_dir, 'comprehensive_report.md')}")


def generate_comprehensive_report(analyzed_files, output_dir):
    """
    Generate a comprehensive report with all findings and analysis
    
    Args:
        analyzed_files: List of analyzed RestoreBackupFormat objects
        output_dir: Directory to save the report
    """
    report_path = os.path.join(output_dir, "comprehensive_report.md")
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("# Comprehensive Ransomware Restorebackup Analysis Report\n\n")
        f.write(f"*Report generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
        
        # Executive summary
        f.write("## Executive Summary\n\n")
        
        lockbit_files = [file for file in analyzed_files if file.lockbit_version]
        
        if lockbit_files:
            f.write(f"🔴 **ALERT: LockBit Ransomware Detected**\n\n")
            f.write(f"Analysis has identified {len(lockbit_files)} files encrypted by LockBit ransomware.\n")
            versions = set(file.lockbit_version for file in lockbit_files)
            f.write(f"Detected LockBit version(s): {', '.join(versions)}\n\n")
        else:
            f.write("⚠️ **No confirmed LockBit ransomware detected in the analyzed files.**\n\n")
        
        # Overall statistics
        f.write("## Analysis Statistics\n\n")
        f.write(f"- Total files analyzed: {len(analyzed_files)}\n")
        f.write(f"- Files confirmed as LockBit: {len(lockbit_files)}\n")
        
        if analyzed_files:
            # Calculate average entropy
            avg_entropy = sum(file.entropy for file in analyzed_files) / len(analyzed_files)
            f.write(f"- Average file entropy: {avg_entropy:.4f} (high entropy indicates encryption)\n")
            
            # Count files with encryption indicators
            with_iv = sum(1 for file in analyzed_files if file.iv)
            with_keys = sum(1 for file in analyzed_files if file.encrypted_key)
            
            f.write(f"- Files with IV detected: {with_iv} ({with_iv/len(analyzed_files)*100:.1f}%)\n")
            f.write(f"- Files with encrypted keys: {with_keys} ({with_keys/len(analyzed_files)*100:.1f}%)\n")
        
        # Encryption details
        f.write("\n## Encryption Analysis\n\n")
        
        algorithms = {}
        for file in analyzed_files:
            algorithm = file.encryption_algorithm or "Unknown"
            algorithms[algorithm] = algorithms.get(algorithm, 0) + 1
        
        f.write("### Encryption Algorithms\n\n")
        for algorithm, count in algorithms.items():
            f.write(f"- {algorithm}: {count} files ({count/len(analyzed_files)*100:.1f}%)\n")
        
        # LockBit specific information
        if lockbit_files:
            f.write("\n## LockBit Ransomware Details\n\n")
            f.write("LockBit is a sophisticated ransomware-as-a-service (RaaS) operation that first appeared in 2019. ")
            f.write("It has evolved through multiple versions and is known for targeting organizations worldwide.\n\n")
            
            f.write("### LockBit Characteristics Identified\n\n")
            
            # Check for the UUID pattern
            uuids = set(file.uuid for file in lockbit_files if file.uuid)
            if uuids:
                f.write(f"- **Unique Identifier**: Found LockBit UUID pattern(s): {', '.join(uuids)}\n")
            
            # Check for encryption details
            if any(file.encryption_algorithm for file in lockbit_files):
                algos = set(file.encryption_algorithm for file in lockbit_files if file.encryption_algorithm)
                modes = set(file.encryption_mode for file in lockbit_files if file.encryption_mode)
                
                f.write(f"- **Encryption**: Uses {', '.join(algos)} in {', '.join(modes)} mode\n")
            
            f.write("- **File Naming Pattern**: Appends `.{UUID}.restorebackup` to original filenames\n")
            
            f.write("\n### Technical Details\n\n")
            f.write("LockBit typically uses the following technical approach:\n\n")
            f.write("1. Encrypts files using AES-256 with CBC mode\n")
            f.write("2. Each file gets a unique IV (initialization vector)\n")
            f.write("3. The file encryption keys are themselves encrypted with an RSA public key\n")
            f.write("4. Original files are replaced with encrypted versions\n")
            f.write("5. Encrypted files are renamed to include a UUID and .restorebackup extension\n")
        
        # File details table
        f.write("\n## Analyzed Files Details\n\n")
        f.write("| Filename | Size (bytes) | Entropy | Original Type | Encryption Algorithm | LockBit Version |\n")
        f.write("|----------|-------------|---------|---------------|--------------------|----------------|\n")
        
        for file in analyzed_files:
            f.write(f"| {file.file_name} | {file.file_size} | {file.entropy:.4f} | ")
            f.write(f"{file.original_file_type or 'Unknown'} | ")
            f.write(f"{file.encryption_algorithm or 'Unknown'} | ")
            f.write(f"{file.lockbit_version or 'Unconfirmed'} |\n")
        
        # Recovery considerations
        f.write("\n## Recovery Considerations\n\n")
        
        if lockbit_files:
            f.write("Recovery options for LockBit encrypted files:\n\n")
            f.write("1. **File Backups**: Restore from secure backups if available\n")
            f.write("2. **Decryption Tools**: Check for publicly available decryptors at No More Ransom project\n")
            f.write("3. **Key Recovery**: In some cases, it may be possible to extract encryption keys from memory if the system hasn't been restarted\n")
            f.write("4. **Technical Analysis**: Further technical analysis may reveal weaknesses in the encryption implementation\n\n")
            
            f.write("⚠️ **Important Note**: Do not pay the ransom unless absolutely necessary, as it funds criminal activities and doesn't guarantee recovery\n")
        else:
            f.write("While no confirmed LockBit ransomware was detected, it's still recommended to:\n\n")
            f.write("1. Scan the entire system with updated security tools\n")
            f.write("2. Check for any additional indicators of compromise\n")
            f.write("3. Restore from secure backups if files are corrupted or encrypted\n")
        
        # Conclusion
        f.write("\n## Conclusion\n\n")
        
        if lockbit_files:
            f.write("The analysis confirms the presence of LockBit ransomware encryption in the examined files. ")
            f.write("LockBit is a sophisticated threat that requires comprehensive security measures for prevention ")
            f.write("and a thorough incident response plan for recovery.\n\n")
            
            f.write("For additional recovery assistance, consider consulting specialized cybersecurity professionals ")
            f.write("with experience in ransomware response and recovery.\n")
        else:
            f.write("The analysis did not conclusively identify LockBit ransomware in the examined files. ")
            f.write("However, encrypted files were detected and could be the result of other ransomware variants ")
            f.write("or encryption methods. Further analysis may be required for definitive identification.\n")


if __name__ == "__main__":
    main()