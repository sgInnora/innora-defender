#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Specialized Analyzer for LockBit .restorebackup Files

This module provides specialized analysis for .restorebackup files created by LockBit ransomware.
It includes detailed format parsing, structure identification, metadata extraction, and recovery attempts.

Key features:
- Format detection and validation for .restorebackup files
- Metadata extraction from encrypted files
- Header and footer analysis
- Encryption information extraction
- Original file type detection
"""

import os
import re
import json
import math
import struct
import base64
import hashlib
import logging
import binascii
import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union, BinaryIO

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("RestoreBackupAnalyzer")


class RestoreBackupFormat:
    """
    Represents the format of a .restorebackup file created by LockBit
    """
    
    # Known LockBit UUIDs
    KNOWN_UUIDS = ["1765FE8E-2103-66E3-7DCB-72284ABD03AA"]
    
    def __init__(self, file_path: str):
        """
        Initialize with file path
        
        Args:
            file_path: Path to the .restorebackup file
        """
        self.file_path = os.path.abspath(file_path)
        self.file_name = os.path.basename(file_path)
        self.file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        
        # LockBit-specific information
        self.lockbit_version = None
        self.uuid = None
        self.original_extension = None
        self.original_filename = None
        
        # Technical details
        self.entropy = 0.0
        self.header_size = 0
        self.footer_size = 0
        self.iv = None
        self.encrypted_key = None
        self.key_marker_position = None
        self.encryption_algorithm = None
        self.encryption_mode = None
        
        # Original file info (if detectable)
        self.original_file_type = None
        self.original_signature = None
        
        # Perform initial analysis
        self._analyze()
    
    def _analyze(self):
        """Analyze the .restorebackup file"""
        # Check if this is a valid .restorebackup file
        if not self._is_valid_restorebackup():
            logger.warning(f"File doesn't appear to be a valid .restorebackup file: {self.file_path}")
            return False
        
        # Extract UUID from filename if present
        for uuid in self.KNOWN_UUIDS:
            if f".{{{uuid}}}" in self.file_name:
                self.uuid = uuid
                self.lockbit_version = "2.0"  # UUID is specific to LockBit 2.0
                
                # Extract original filename and extension
                parts = self.file_name.split(f".{{{uuid}}}")
                self.original_filename = parts[0]
                self.original_extension = os.path.splitext(self.original_filename)[1]
                
                logger.info(f"Detected LockBit {self.lockbit_version} extension with UUID {uuid}")
                break
        
        # Read and analyze file content
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            # Calculate overall entropy
            self.entropy = self._calculate_entropy(data)
            
            # Look for different sections based on entropy variations
            # (Headers and footers often have different entropy than the encrypted content)
            sections = self._find_entropy_sections(data)
            
            # Process the detected sections
            if sections:
                # Files are typically [header][encrypted data][footer]
                if len(sections) >= 2:
                    # First section is likely header
                    header_section = sections[0]
                    self.header_size = header_section[1]  # End of header
                    
                    # Extract IV from header
                    if self.header_size >= 16:
                        self.iv = data[:16]
                    
                    # Last section is likely footer
                    footer_section = sections[-1]
                    self.footer_size = len(data) - footer_section[0]  # Size from start of footer to end
                    
                    # Check footer for encrypted key
                    footer_data = data[footer_section[0]:]
                    self._analyze_footer(footer_data)
                
                # Determine encryption details based on identified patterns
                self._determine_encryption_details()
                
                # Try to detect original file type
                self._detect_original_file_type(data)
        
        except Exception as e:
            logger.error(f"Error analyzing file: {e}")
            return False
        
        return True
    
    def _is_valid_restorebackup(self) -> bool:
        """Check if this appears to be a valid .restorebackup file"""
        # Basic checks
        if not os.path.exists(self.file_path):
            return False
        
        # Check extension
        if not self.file_name.endswith('.restorebackup'):
            return False
        
        # Check for LockBit UUID pattern in filename
        if not any(f".{{{uuid}}}" in self.file_name for uuid in self.KNOWN_UUIDS):
            # It's .restorebackup but doesn't have the UUID pattern
            # Could still be valid, but less certain
            return True
        
        return True
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        # Calculate byte frequency
        counter = {}
        for byte in data:
            if byte not in counter:
                counter[byte] = 0
            counter[byte] += 1
        
        # Calculate entropy
        entropy = 0
        for count in counter.values():
            probability = count / len(data)
            entropy -= probability * (math.log2(probability))
        
        return entropy
    
    def _find_entropy_sections(self, data: bytes, window_size: int = 256) -> List[Tuple[int, int, float]]:
        """
        Find sections of differing entropy in the data
        
        Args:
            data: Byte data to analyze
            window_size: Size of sliding window for entropy calculation
            
        Returns:
            List of tuples (start_position, end_position, entropy)
        """
        if len(data) < window_size * 2:
            # Too small to analyze with windows
            return [(0, len(data), self.entropy)]
        
        # Calculate entropy in sliding windows
        entropies = []
        for i in range(0, len(data) - window_size, window_size // 2):
            window = data[i:i+window_size]
            entropies.append((i, i+window_size, self._calculate_entropy(window)))
        
        # Find significant changes in entropy
        sections = []
        current_section_start = 0
        current_entropy = entropies[0][2]
        
        for i in range(1, len(entropies)):
            pos, end_pos, entropy = entropies[i]
            
            # Check if there's a significant change in entropy
            if abs(entropy - current_entropy) > 0.5:
                # End the current section
                sections.append((current_section_start, pos, current_entropy))
                
                # Start a new section
                current_section_start = pos
                current_entropy = entropy
        
        # Add the last section
        if current_section_start < len(data):
            sections.append((current_section_start, len(data), current_entropy))
        
        return sections
    
    def _analyze_footer(self, footer_data: bytes):
        """
        Analyze footer for encryption metadata
        
        Args:
            footer_data: Footer bytes
        """
        # Look for key markers in the footer
        key_markers = [b'KEY', b'key', b'ENCRYPTED', b'ENC_KEY']
        
        for marker in key_markers:
            marker_pos = footer_data.find(marker)
            if marker_pos != -1:
                self.key_marker_position = marker_pos
                
                # Extract potential encrypted key
                # Typically, the key would be after the marker
                # We extract a reasonably sized chunk that might contain the key
                # For RSA-encrypted AES keys, this is typically 256 bytes
                potential_key_start = marker_pos + len(marker)
                potential_key = footer_data[potential_key_start:potential_key_start+256]
                
                # Only store if it has high entropy (likely encrypted)
                if self._calculate_entropy(potential_key) > 6.5:
                    self.encrypted_key = potential_key
                    logger.info(f"Potential encrypted key found at offset {marker_pos} in footer")
                    break
    
    def _determine_encryption_details(self):
        """Determine the encryption algorithm and mode based on analysis"""
        # LockBit 2.0 typically uses AES-256-CBC
        if self.lockbit_version == "2.0":
            self.encryption_algorithm = "AES-256"
            self.encryption_mode = "CBC"
            
            # Check if we found a potential IV
            if self.iv:
                iv_entropy = self._calculate_entropy(self.iv)
                if 3.5 < iv_entropy < 6.5:  # Typical entropy range for IVs
                    logger.info(f"Identified IV with entropy {iv_entropy:.2f}")
                else:
                    logger.warning(f"Unusual entropy for potential IV: {iv_entropy:.2f}")
    
    def _detect_original_file_type(self, data: bytes):
        """
        Attempt to detect the original file type
        
        Args:
            data: Full file data
        """
        # This is challenging with encrypted data, but we can look for partial signatures
        
        # Check if we already have extension information
        if self.original_extension:
            # Known extensions to common file types
            extension_map = {
                '.txt': 'Text file',
                '.jpg': 'JPEG image',
                '.jpeg': 'JPEG image',
                '.png': 'PNG image',
                '.pdf': 'PDF document',
                '.doc': 'Microsoft Word document',
                '.docx': 'Microsoft Word document (OOXML)',
                '.xls': 'Microsoft Excel spreadsheet',
                '.xlsx': 'Microsoft Excel spreadsheet (OOXML)',
                '.ppt': 'Microsoft PowerPoint presentation',
                '.pptx': 'Microsoft PowerPoint presentation (OOXML)',
                '.zip': 'ZIP archive',
                '.rar': 'RAR archive',
                '.exe': 'Windows executable',
                '.dll': 'Windows dynamic link library',
                '.html': 'HTML document',
                '.xml': 'XML document',
                '.json': 'JSON data',
                '.csv': 'CSV data',
                '.db': 'Database file',
                '.sql': 'SQL script',
                '.py': 'Python script',
                '.js': 'JavaScript file',
                '.c': 'C source code',
                '.cpp': 'C++ source code',
                '.h': 'C/C++ header file',
                '.java': 'Java source code',
                '.php': 'PHP script',
                '.mp3': 'MP3 audio',
                '.mp4': 'MP4 video',
                '.avi': 'AVI video',
                '.mov': 'QuickTime video',
                '.wav': 'WAV audio'
            }
            
            ext = self.original_extension.lower()
            if ext in extension_map:
                self.original_file_type = extension_map[ext]
                logger.info(f"Determined file type from extension: {self.original_file_type}")
        
        # Try to detect from header bytes (difficult with encryption)
        # Some file formats might still have recognizable patterns even after encryption
        # Especially if only the file content is encrypted, not the headers
        
        # Check for some common patterns that might survive encryption
        header_patterns = [
            (b'PK\x03\x04', 'ZIP-based file (could be Office document, APK, etc.)'),
            (b'%PDF', 'PDF document'),
            (b'\xFF\xD8\xFF', 'JPEG image'),
            (b'\x89PNG', 'PNG image'),
            (b'GIF8', 'GIF image'),
            (b'II*\x00', 'TIFF image (little-endian)'),
            (b'MM\x00*', 'TIFF image (big-endian)'),
            (b'<!DOCTYPE HTML', 'HTML document'),
            (b'<!DOCTYPE html', 'HTML document'),
            (b'<html', 'HTML document'),
            (b'<?xml', 'XML document'),
            (b'SQLite', 'SQLite database'),
            (b'MZ', 'Windows executable'),
            (b'\x7FELF', 'ELF executable (Linux/Unix)'),
            (b'\xCA\xFE\xBA\xBE', 'Java class file or Mach-O Fat Binary')
        ]
        
        for pattern, file_type in header_patterns:
            if data.startswith(pattern):
                self.original_file_type = file_type
                self.original_signature = pattern
                logger.info(f"Determined file type from signature: {self.original_file_type}")
                break
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis to dictionary"""
        return {
            'file_path': self.file_path,
            'file_name': self.file_name,
            'file_size': self.file_size,
            'entropy': self.entropy,
            'lockbit_version': self.lockbit_version,
            'uuid': self.uuid,
            'original_filename': self.original_filename,
            'original_extension': self.original_extension,
            'original_file_type': self.original_file_type,
            'header_size': self.header_size,
            'footer_size': self.footer_size,
            'encryption_algorithm': self.encryption_algorithm,
            'encryption_mode': self.encryption_mode,
            'has_iv': bool(self.iv),
            'has_encrypted_key': bool(self.encrypted_key),
            'analysis_timestamp': datetime.datetime.now().isoformat()
        }


class RestoreBackupAnalyzer:
    """
    Analyzer for .restorebackup files
    """
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize the analyzer
        
        Args:
            output_dir: Optional output directory for results
        """
        # Set up output directory
        if output_dir:
            self.output_dir = os.path.abspath(output_dir)
        else:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_dir = os.path.join(os.getcwd(), f"restorebackup_analysis_{timestamp}")
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Configure logging to file
        log_file = os.path.join(self.output_dir, 'restorebackup_analysis.log')
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(file_handler)
        
        # Store analyzed files
        self.analyzed_files = {}
    
    def analyze_file(self, file_path: str) -> RestoreBackupFormat:
        """
        Analyze a .restorebackup file
        
        Args:
            file_path: Path to the file
            
        Returns:
            RestoreBackupFormat object with analysis
        """
        logger.info(f"Analyzing .restorebackup file: {file_path}")
        
        # Create format analyzer
        format_analyzer = RestoreBackupFormat(file_path)
        
        # Store in our collection
        self.analyzed_files[file_path] = format_analyzer
        
        # Generate detailed report
        self._generate_report(format_analyzer)
        
        return format_analyzer
    
    def analyze_directory(self, directory_path: str) -> List[RestoreBackupFormat]:
        """
        Analyze all .restorebackup files in a directory
        
        Args:
            directory_path: Path to directory
            
        Returns:
            List of RestoreBackupFormat objects
        """
        logger.info(f"Analyzing .restorebackup files in directory: {directory_path}")
        analyzed_files = []
        
        for filename in os.listdir(directory_path):
            if filename.endswith('.restorebackup'):
                file_path = os.path.join(directory_path, filename)
                format_analyzer = self.analyze_file(file_path)
                analyzed_files.append(format_analyzer)
        
        # Generate summary report
        self._generate_summary_report()
        
        return analyzed_files
    
    def _generate_report(self, format_analyzer: RestoreBackupFormat):
        """
        Generate a detailed report for a single file
        
        Args:
            format_analyzer: RestoreBackupFormat object
        """
        file_name = format_analyzer.file_name
        report_path = os.path.join(self.output_dir, f"{file_name}_analysis.json")
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(format_analyzer.to_dict(), f, indent=2)
        
        logger.info(f"Detailed report saved to: {report_path}")
        
        # Also generate a human-readable markdown report
        md_report_path = os.path.join(self.output_dir, f"{file_name}_analysis.md")
        
        with open(md_report_path, 'w', encoding='utf-8') as f:
            f.write(f"# .restorebackup File Analysis: {file_name}\n\n")
            
            f.write("## Basic Information\n\n")
            f.write(f"- **File**: {format_analyzer.file_path}\n")
            f.write(f"- **Size**: {format_analyzer.file_size} bytes\n")
            f.write(f"- **Entropy**: {format_analyzer.entropy:.4f}\n")
            
            f.write("\n## LockBit Information\n\n")
            if format_analyzer.lockbit_version:
                f.write(f"- **Version**: LockBit {format_analyzer.lockbit_version}\n")
            else:
                f.write("- **Version**: Unknown\n")
            
            if format_analyzer.uuid:
                f.write(f"- **UUID**: {format_analyzer.uuid}\n")
            
            f.write("\n## Original File Information\n\n")
            if format_analyzer.original_filename:
                f.write(f"- **Original Filename**: {format_analyzer.original_filename}\n")
            
            if format_analyzer.original_extension:
                f.write(f"- **Original Extension**: {format_analyzer.original_extension}\n")
            
            if format_analyzer.original_file_type:
                f.write(f"- **Detected File Type**: {format_analyzer.original_file_type}\n")
            
            f.write("\n## Encryption Details\n\n")
            if format_analyzer.encryption_algorithm:
                f.write(f"- **Algorithm**: {format_analyzer.encryption_algorithm}\n")
            
            if format_analyzer.encryption_mode:
                f.write(f"- **Mode**: {format_analyzer.encryption_mode}\n")
            
            f.write(f"- **Has IV**: {'Yes' if format_analyzer.iv else 'No'}\n")
            f.write(f"- **Has Encrypted Key**: {'Yes' if format_analyzer.encrypted_key else 'No'}\n")
            
            f.write("\n## Structure Information\n\n")
            f.write(f"- **Header Size**: {format_analyzer.header_size} bytes\n")
            f.write(f"- **Footer Size**: {format_analyzer.footer_size} bytes\n")
            f.write(f"- **Encrypted Data Size**: {format_analyzer.file_size - format_analyzer.header_size - format_analyzer.footer_size} bytes\n")
        
        logger.info(f"Markdown report saved to: {md_report_path}")
    
    def _generate_summary_report(self):
        """Generate a summary report for all analyzed files"""
        summary_path = os.path.join(self.output_dir, "summary_report.md")
        
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write("# .restorebackup Files Analysis Summary\n\n")
            
            f.write(f"*Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
            
            f.write(f"## Overview\n\n")
            f.write(f"Total files analyzed: {len(self.analyzed_files)}\n\n")
            
            # Count by version
            version_count = {}
            for file in self.analyzed_files.values():
                version = file.lockbit_version or "Unknown"
                version_count[version] = version_count.get(version, 0) + 1
            
            f.write("### Versions Detected\n\n")
            for version, count in version_count.items():
                f.write(f"- {version}: {count} files\n")
            
            # Count by file type
            file_types = {}
            for file in self.analyzed_files.values():
                file_type = file.original_file_type or "Unknown"
                file_types[file_type] = file_types.get(file_type, 0) + 1
            
            f.write("\n### Original File Types\n\n")
            for file_type, count in file_types.items():
                f.write(f"- {file_type}: {count} files\n")
            
            # Summary of encryption details
            f.write("\n## Encryption Details\n\n")
            
            encryption_algorithms = {}
            for file in self.analyzed_files.values():
                algorithm = file.encryption_algorithm or "Unknown"
                encryption_algorithms[algorithm] = encryption_algorithms.get(algorithm, 0) + 1
            
            f.write("### Encryption Algorithms\n\n")
            for algorithm, count in encryption_algorithms.items():
                f.write(f"- {algorithm}: {count} files\n")
            
            # Count files with IV and encrypted keys
            with_iv = sum(1 for file in self.analyzed_files.values() if file.iv)
            with_keys = sum(1 for file in self.analyzed_files.values() if file.encrypted_key)
            
            f.write(f"\n- Files with IV: {with_iv} ({with_iv/len(self.analyzed_files)*100:.1f}%)\n")
            f.write(f"- Files with encrypted keys: {with_keys} ({with_keys/len(self.analyzed_files)*100:.1f}%)\n")
            
            # File list
            f.write("\n## Analyzed Files\n\n")
            f.write("| Filename | Size (bytes) | Entropy | Version | Original Type | Algorithm |\n")
            f.write("|----------|-------------|---------|---------|---------------|----------|\n")
            
            for file in self.analyzed_files.values():
                f.write(f"| {file.file_name} | {file.file_size} | {file.entropy:.4f} | ")
                f.write(f"{file.lockbit_version or 'Unknown'} | {file.original_file_type or 'Unknown'} | ")
                f.write(f"{file.encryption_algorithm or 'Unknown'} |\n")
            
            f.write(f"\n*Full analysis reports for each file are available in individual files in this directory.*\n")
        
        logger.info(f"Summary report saved to: {summary_path}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description=".restorebackup File Analyzer")
    parser.add_argument("path", help="File or directory to analyze")
    parser.add_argument("-o", "--output", help="Output directory for analysis results")
    args = parser.parse_args()
    
    analyzer = RestoreBackupAnalyzer(args.output)
    
    if os.path.isdir(args.path):
        analyzed_files = analyzer.analyze_directory(args.path)
        print(f"Analyzed {len(analyzed_files)} .restorebackup files in {args.path}")
    elif os.path.isfile(args.path):
        if args.path.endswith('.restorebackup'):
            result = analyzer.analyze_file(args.path)
            print(f"Analysis complete for {args.path}")
        else:
            print(f"Error: Not a .restorebackup file: {args.path}")
    else:
        print(f"Error: Path not found: {args.path}")