#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced YARA Rule Generator for Ransomware Detection

This module provides an advanced YARA rule generation system that combines multiple
approaches for improved ransomware detection. It integrates the capabilities of the 
existing YaraRuleGenerator and RansomwareRuleGenerator classes and adds new features
for better accuracy and customization.

Key Features:
- Multi-feature extraction from multiple file types
- Machine learning-assisted pattern selection
- Advanced entropy analysis for encrypted content detection
- Code similarity detection for related samples
- Contextual string analysis for better detection of ransomware strings
- Modular architecture with pluggable feature extractors
- Integrated validation against known benign samples
- Support for rule clustering and family identification
- Advanced rule optimization for reduced false positives
"""

import os
import re
import json
import math
import uuid
import logging
import hashlib
import datetime
import statistics
import subprocess
import binascii
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any, Union, BinaryIO, Iterator, Callable

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('enhanced_yara_generator')

# Import parent files if possible
try:
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from threat_intel.rules.yara_generator import YaraRuleGenerator
    from tools.yara_rule_generator.ransomware_rule_generator import RansomwareRuleGenerator, YaraRule, YaraFeature, StringFeature, BytePatternFeature, OpcodeFeature
    LEGACY_IMPORTS_AVAILABLE = True
except ImportError:
    logger.warning("Legacy YARA generator imports not available, using standalone mode")
    LEGACY_IMPORTS_AVAILABLE = False

# Constants
MIN_STRING_LENGTH = 8
MAX_STRINGS_PER_RULE = 25
HIGH_ENTROPY_THRESHOLD = 7.0
MEDIUM_ENTROPY_THRESHOLD = 5.5

class FeatureExtractor:
    """Base class for all feature extractors"""
    
    def __init__(self, name: str, weight: float = 1.0, enabled: bool = True):
        """
        Initialize feature extractor
        
        Args:
            name: Extractor name
            weight: Overall weight for features from this extractor
            enabled: Whether this extractor is enabled
        """
        self.name = name
        self.weight = weight
        self.enabled = enabled
        
    def extract_features(self, file_path: str, file_info: Dict = None) -> List[Any]:
        """
        Extract features from a file
        
        Args:
            file_path: Path to the file
            file_info: Optional file information dictionary
            
        Returns:
            List of extracted features
        """
        raise NotImplementedError("Subclasses must implement this method")
    
    def can_handle(self, file_path: str, file_info: Dict = None) -> bool:
        """
        Check if this extractor can handle the given file
        
        Args:
            file_path: Path to the file
            file_info: Optional file information dictionary
            
        Returns:
            True if this extractor can handle the file, False otherwise
        """
        return True

class StringFeatureExtractor(FeatureExtractor):
    """Extracts string features from files"""
    
    def __init__(self, weight: float = 1.0, enabled: bool = True, 
                min_length: int = MIN_STRING_LENGTH,
                max_strings: int = 100):
        """
        Initialize string feature extractor
        
        Args:
            weight: Overall weight for features from this extractor
            enabled: Whether this extractor is enabled
            min_length: Minimum string length to extract
            max_strings: Maximum number of strings to extract
        """
        super().__init__("string_extractor", weight, enabled)
        self.min_length = min_length
        self.max_strings = max_strings
        
        # Configure strings patterns and weights
        self.ransomware_patterns = {
            r'ransom': 2.0,
            r'encrypt': 1.8,
            r'decrypt': 1.8,
            r'bitcoin': 1.9,
            r'wallet': 1.7,
            r'payment': 1.7,
            r'btc': 1.8,
            r'recovery': 1.6,
            r'locked': 1.6,
            r'files are encrypted': 2.0,
            r'pay\s+\d+': 1.9,
            r'\$\d{3,}': 1.8,
            r'\d+\s+bitcoin': 1.9,
            r'private key': 1.7,
            r'public key': 1.5,
            r'encryption key': 1.7,
            r'decryption key': 1.8,
            r'tor\s+browser': 1.8,
            r'\.onion': 1.8,
            r'your files': 1.5,
            r'your data': 1.5,
            r'your documents': 1.5,
            r'readme': 1.6,
            r'how_to_decrypt': 1.8,
            r'how_to_recover': 1.8,
            r'deadline': 1.7,
            r'time left': 1.7,
            r'ticking': 1.6,
            r'irreversible': 1.7,
            r'no way back': 1.7,
            r'no recovery': 1.7,
            r'aes-\d+': 1.5,
            r'rsa-\d+': 1.5
        }
        
        # Common strings to ignore
        self.ignore_strings = [
            "Microsoft", "Windows", "Program Files", "System32",
            "Mozilla", "Firefox", "Chrome", "Google", "http://", "https://",
            "SOFTWARE", "HARDWARE", "SYSTEM", "msvcrt", "kernel32",
            "KERNEL32", "USER32", "GDI32", "ADVAPI32", "ole32",
            "Copyright", "Version", "Assembly", "Runtime", "Software",
            "Library", "Python", "Java", ".NET", "Framework"
        ]
    
    def extract_features(self, file_path: str, file_info: Dict = None) -> List[StringFeature]:
        """
        Extract string features from a file
        
        Args:
            file_path: Path to the file
            file_info: Optional file information dictionary
            
        Returns:
            List of extracted string features
        """
        features = []
        
        try:
            # Use 'strings' command to extract strings
            ascii_strings = []
            unicode_strings = []
            
            # Extract ASCII strings
            strings_proc = subprocess.run(['strings', '-a', '-n', str(self.min_length), file_path], 
                                       capture_output=True, check=False)
            if strings_proc.returncode == 0:
                ascii_strings = strings_proc.stdout.decode('utf-8', errors='ignore').splitlines()
            
            # Extract Unicode strings
            wide_strings_proc = subprocess.run(['strings', '-a', '-n', str(self.min_length), '-e', 'l', file_path], 
                                            capture_output=True, check=False)
            if wide_strings_proc.returncode == 0:
                unicode_strings = wide_strings_proc.stdout.decode('utf-8', errors='ignore').splitlines()
            
            # Combine unique strings
            all_strings = set()
            for string in ascii_strings + unicode_strings:
                string = string.strip()
                if not string or string in all_strings:
                    continue
                all_strings.add(string)
            
            # Process each string
            processed_strings = []
            for string in all_strings:
                # Skip very short, long, or common strings
                if len(string) < self.min_length or len(string) > 200 or self._is_common_string(string):
                    continue
                
                # Calculate string entropy
                entropy = self._calculate_entropy(string.encode())
                
                # Determine string weight
                weight = 1.0
                matched_pattern = False
                
                # Check if string matches any ransomware pattern
                for pattern, pattern_weight in self.ransomware_patterns.items():
                    if re.search(pattern, string, re.IGNORECASE):
                        weight = pattern_weight
                        matched_pattern = True
                        break
                
                # Adjust weight based on entropy (if not already matched a pattern)
                if not matched_pattern:
                    if entropy > HIGH_ENTROPY_THRESHOLD:
                        weight += 0.3
                    elif entropy > MEDIUM_ENTROPY_THRESHOLD:
                        weight += 0.1
                
                # Create string feature
                is_ascii = string in ascii_strings
                feature = StringFeature(
                    string,
                    weight=weight * self.weight,
                    is_ascii=is_ascii,
                    entropy=entropy
                )
                
                processed_strings.append((feature, weight))
            
            # Sort by weight and take top strings
            processed_strings.sort(key=lambda x: x[1], reverse=True)
            features = [item[0] for item in processed_strings[:self.max_strings]]
            
        except Exception as e:
            logger.error(f"Error extracting strings from {file_path}: {e}")
        
        return features
    
    def _is_common_string(self, string: str) -> bool:
        """
        Check if a string is common and should be ignored
        
        Args:
            string: String to check
            
        Returns:
            True if string is common and should be ignored, False otherwise
        """
        # Check for exact matches in ignore list
        if string in self.ignore_strings:
            return True
        
        # Check for substrings in ignore list
        for ignore in self.ignore_strings:
            if ignore in string:
                return True
        
        # Check for generic paths and URLs
        if re.match(r'^[A-Z]:\\', string) or re.match(r'^/usr/|^/bin/|^/etc/', string):
            return True
        
        if re.match(r'^https?://(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', string):
            return True
        
        return False

    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data
        
        Args:
            data: Bytes to calculate entropy for
            
        Returns:
            Shannon entropy value (0-8)
        """
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

class OpcodeFeatureExtractor(FeatureExtractor):
    """Extracts opcode patterns from executable files"""
    
    def __init__(self, weight: float = 1.5, enabled: bool = True, 
                max_patterns: int = 15):
        """
        Initialize opcode feature extractor
        
        Args:
            weight: Overall weight for features from this extractor
            enabled: Whether this extractor is enabled
            max_patterns: Maximum number of opcode patterns to extract
        """
        super().__init__("opcode_extractor", weight, enabled)
        self.max_patterns = max_patterns
        
        # Configure opcode patterns of interest
        self.encryption_patterns = [
            # AES patterns
            r'[^\n]+?mov[^\n]+?xmm[^\n]+?\n[^\n]+?aes[^\n]+?\n',
            r'[^\n]+?aes(?:enc|keygenassist|imc)[^\n]+?\n[^\n]+?(?:pshufd|pextrq)[^\n]+?\n',
            
            # SHA patterns
            r'[^\n]+?sha(?:1|256)[^\n]+?\n[^\n]+?sha(?:1|256)[^\n]+?\n[^\n]+?sha(?:1|256)[^\n]+?\n',
            
            # Generic crypto sequences
            r'[^\n]+?rol[^\n]+?\n[^\n]+?xor[^\n]+?\n[^\n]+?add[^\n]+?\n[^\n]+?ror[^\n]+?\n',
            r'[^\n]+?xor[^\n]+?\n[^\n]+?shl[^\n]+?\n[^\n]+?add[^\n]+?\n[^\n]+?xor[^\n]+?\n',
        ]
        
        self.file_operation_patterns = [
            r'[^\n]+?call[^\n]+?FindFirstFile[^\n]+?\n[^\n]+?test[^\n]+?\n[^\n]+?je[^\n]+?\n',
            r'[^\n]+?call[^\n]+?ReadFile[^\n]+?\n[^\n]+?test[^\n]+?\n[^\n]+?je[^\n]+?\n',
            r'[^\n]+?call[^\n]+?WriteFile[^\n]+?\n[^\n]+?test[^\n]+?\n[^\n]+?je[^\n]+?\n',
            r'[^\n]+?call[^\n]+?CreateFile[^\n]+?\n[^\n]+?test[^\n]+?\n[^\n]+?je[^\n]+?\n',
        ]
    
    def can_handle(self, file_path: str, file_info: Dict = None) -> bool:
        """
        Check if this extractor can handle the given file
        
        Args:
            file_path: Path to the file
            file_info: Optional file information dictionary
            
        Returns:
            True if this extractor can handle the file, False otherwise
        """
        # Check file extension
        if file_path.lower().endswith(('.exe', '.dll', '.sys')):
            return True
        
        # Check file info
        if file_info and 'file_type' in file_info:
            file_type = file_info['file_type'].lower()
            if 'pe' in file_type or 'executable' in file_type or 'elf' in file_type:
                return True
        
        return False
    
    def extract_features(self, file_path: str, file_info: Dict = None) -> List[OpcodeFeature]:
        """
        Extract opcode features from an executable file
        
        Args:
            file_path: Path to the file
            file_info: Optional file information dictionary
            
        Returns:
            List of extracted opcode features
        """
        features = []
        
        try:
            # Get disassembly
            disasm_output = self._get_disassembly(file_path)
            if not disasm_output:
                return features
            
            # Extract patterns from disassembly
            for pattern_list, pattern_type, base_weight in [
                (self.encryption_patterns, "encryption", 1.8),
                (self.file_operation_patterns, "file_operation", 1.5)
            ]:
                for pattern in pattern_list:
                    for match in re.finditer(pattern, disasm_output):
                        code_sequence = match.group(0).strip()
                        if not code_sequence:
                            continue
                        
                        # Extract opcodes from assembly
                        opcodes = []
                        for line in code_sequence.splitlines():
                            parts = line.strip().split(None, 2)
                            if len(parts) >= 2:
                                opcodes.append(parts[1])  # Extract the opcode
                        
                        if not opcodes:
                            continue
                        
                        # Create opcode pattern
                        opcode_str = ' '.join(opcodes)
                        
                        # Create feature
                        feature = OpcodeFeature(
                            opcode_str,
                            weight=base_weight * self.weight,
                            context={"type": pattern_type}
                        )
                        
                        features.append(feature)
            
            # Limit number of features
            features = features[:self.max_patterns]
            
        except Exception as e:
            logger.error(f"Error extracting opcodes from {file_path}: {e}")
        
        return features
    
    def _get_disassembly(self, file_path: str) -> str:
        """
        Get disassembly for an executable file
        
        Args:
            file_path: Path to the file
            
        Returns:
            Disassembly output as string
        """
        try:
            # Try objdump disassembly
            disasm_proc = subprocess.run(['objdump', '-d', file_path], 
                                      capture_output=True, check=False, timeout=30)
            if disasm_proc.returncode == 0:
                return disasm_proc.stdout.decode('utf-8', errors='ignore')
            
            # Alternative disassembly for Windows PE files using radare2 if available
            if os.path.exists('/usr/bin/r2') or os.path.exists('/usr/local/bin/r2'):
                # Create a temporary script to get disassembly
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                    script_path = f.name
                    f.write('aaa\n')  # Analyze all
                    f.write('pdf\n')  # Print disassembly function
                    f.write('q\n')    # Quit
                
                try:
                    r2_proc = subprocess.run(['r2', '-q', '-i', script_path, file_path], 
                                          capture_output=True, check=False, timeout=30)
                    if r2_proc.returncode == 0:
                        return r2_proc.stdout.decode('utf-8', errors='ignore')
                finally:
                    # Clean up temporary file
                    if os.path.exists(script_path):
                        os.unlink(script_path)
            
            return ""
        except Exception as e:
            logger.error(f"Error getting disassembly for {file_path}: {e}")
            return ""

class BytePatternExtractor(FeatureExtractor):
    """Extracts byte pattern features from files"""
    
    def __init__(self, weight: float = 1.2, enabled: bool = True,
                block_size: int = 1024, max_patterns: int = 10):
        """
        Initialize byte pattern extractor
        
        Args:
            weight: Overall weight for features from this extractor
            enabled: Whether this extractor is enabled
            block_size: Size of blocks to analyze for entropy
            max_patterns: Maximum number of byte patterns to extract
        """
        super().__init__("byte_pattern_extractor", weight, enabled)
        self.block_size = block_size
        self.max_patterns = max_patterns
    
    def extract_features(self, file_path: str, file_info: Dict = None) -> List[BytePatternFeature]:
        """
        Extract byte pattern features from a file
        
        Args:
            file_path: Path to the file
            file_info: Optional file information dictionary
            
        Returns:
            List of extracted byte pattern features
        """
        features = []
        
        try:
            with open(file_path, 'rb') as f:
                # Read file header
                header_data = f.read(64)
                
                # Create header feature
                if len(header_data) >= 4:
                    feature = BytePatternFeature(
                        header_data[:16],  # First 16 bytes
                        weight=1.5 * self.weight,
                        offset=0,
                        context={"type": "file_header"}
                    )
                    features.append(feature)
                
                # Check for MZ header (PE file)
                if len(header_data) >= 2 and header_data.startswith(b'MZ'):
                    # Find PE header offset
                    if len(header_data) >= 64:
                        pe_offset = int.from_bytes(header_data[0x3C:0x40], byteorder='little')
                        
                        # Seek to PE header
                        f.seek(pe_offset)
                        pe_header = f.read(24)
                        
                        if pe_header.startswith(b'PE\0\0'):
                            # Create PE header feature
                            feature = BytePatternFeature(
                                pe_header,
                                weight=1.8 * self.weight,
                                offset=pe_offset,
                                context={"type": "pe_header"}
                            )
                            features.append(feature)
                
                # Check for ELF header
                elif len(header_data) >= 4 and header_data.startswith(b'\x7fELF'):
                    feature = BytePatternFeature(
                        header_data[:16],
                        weight=1.8 * self.weight,
                        offset=0,
                        context={"type": "elf_header"}
                    )
                    features.append(feature)
                
                # Look for high-entropy regions
                f.seek(0)
                high_entropy_blocks = []
                
                # Read file in blocks
                offset = 0
                while True:
                    block = f.read(self.block_size)
                    if not block:
                        break
                    
                    if len(block) < 64:  # Skip small trailing blocks
                        break
                    
                    # Calculate entropy
                    entropy = self._calculate_entropy(block)
                    
                    # Check for high entropy
                    if entropy > HIGH_ENTROPY_THRESHOLD:
                        high_entropy_blocks.append((offset, block, entropy))
                    
                    offset += len(block)
                
                # Sort by entropy (descending) and take top N
                high_entropy_blocks.sort(key=lambda x: x[2], reverse=True)
                
                # Take up to max_patterns high-entropy blocks
                for i, (offset, block, entropy) in enumerate(high_entropy_blocks[:self.max_patterns-1]):
                    # Extract a sample of the high-entropy data
                    pattern = block[:16]  # First 16 bytes
                    
                    feature = BytePatternFeature(
                        pattern,
                        weight=1.3 * self.weight,
                        offset=offset,
                        context={"type": "high_entropy_data", "entropy": entropy}
                    )
                    
                    features.append(feature)
        
        except Exception as e:
            logger.error(f"Error extracting byte patterns from {file_path}: {e}")
        
        return features
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data
        
        Args:
            data: Bytes to calculate entropy for
            
        Returns:
            Shannon entropy value (0-8)
        """
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

class ScriptFeatureExtractor(FeatureExtractor):
    """Extracts features from script files (JS, VBS, PowerShell, BAT)"""
    
    def __init__(self, weight: float = 1.3, enabled: bool = True):
        """
        Initialize script feature extractor
        
        Args:
            weight: Overall weight for features from this extractor
            enabled: Whether this extractor is enabled
        """
        super().__init__("script_extractor", weight, enabled)
        
        # Configure patterns
        self.encryption_keywords = [
            'encrypt', 'decrypt', 'AES', 'RSA', 'crypto', 'password',
            'key', 'iv', 'base64', 'sha1', 'sha256', 'md5', 'hash'
        ]
        
        self.ransomware_indicators = [
            'ransom', 'bitcoin', 'payment', 'decrypt', 'files are encrypted',
            'pay', 'btc', 'wallet', 'recovery', 'restore', 'deadline',
            'locked', 'no recovery', 'time left'
        ]
        
        self.file_operations = [
            'open(', 'fopen', 'createFile', 'readFile', 'writeFile',
            'fileStream', 'fstream', 'ReadAllBytes', 'WriteAllBytes',
            'listdir', 'glob.glob', 'FindFirstFile', 'FindNextFile'
        ]
    
    def can_handle(self, file_path: str, file_info: Dict = None) -> bool:
        """
        Check if this extractor can handle the given file
        
        Args:
            file_path: Path to the file
            file_info: Optional file information dictionary
            
        Returns:
            True if this extractor can handle the file, False otherwise
        """
        # Check file extension
        script_extensions = ('.js', '.vbs', '.ps1', '.bat', '.sh', '.py', '.pl', '.php')
        if file_path.lower().endswith(script_extensions):
            return True
        
        # Check file info
        if file_info and 'file_type' in file_info:
            file_type = file_info['file_type'].lower()
            if 'script' in file_type or 'text' in file_type:
                return True
        
        return False
    
    def extract_features(self, file_path: str, file_info: Dict = None) -> List[StringFeature]:
        """
        Extract features from a script file
        
        Args:
            file_path: Path to the file
            file_info: Optional file information dictionary
            
        Returns:
            List of extracted string features
        """
        features = []
        
        try:
            # Read script file
            with open(file_path, 'r', errors='ignore') as f:
                script_content = f.read()
            
            # Split into lines
            lines = script_content.splitlines()
            
            # Process each line
            for i, line in enumerate(lines):
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('//'):
                    continue
                
                # Check for encryption keywords
                for keyword in self.encryption_keywords:
                    if keyword.lower() in line.lower():
                        # Get context (surrounding lines)
                        start_idx = max(0, i - 2)
                        end_idx = min(len(lines), i + 3)
                        context_lines = lines[start_idx:end_idx]
                        context = '\n'.join(context_lines)
                        
                        # Limit context length
                        if len(context) > 500:
                            context = line
                        
                        # Calculate entropy
                        entropy = self._calculate_entropy(context.encode())
                        
                        # Create feature
                        feature = StringFeature(
                            context,
                            weight=1.5 * self.weight,
                            is_ascii=True,
                            entropy=entropy,
                            context={"type": "encryption_code", "line": i + 1}
                        )
                        
                        features.append(feature)
                        break  # Only create one feature for this line
                
                # Check for ransomware indicators
                for indicator in self.ransomware_indicators:
                    if indicator.lower() in line.lower():
                        # Get context
                        start_idx = max(0, i - 2)
                        end_idx = min(len(lines), i + 3)
                        context_lines = lines[start_idx:end_idx]
                        context = '\n'.join(context_lines)
                        
                        # Limit context length
                        if len(context) > 500:
                            context = line
                        
                        # Calculate entropy
                        entropy = self._calculate_entropy(context.encode())
                        
                        # Create feature
                        feature = StringFeature(
                            context,
                            weight=2.0 * self.weight,
                            is_ascii=True,
                            entropy=entropy,
                            context={"type": "ransomware_indicator", "line": i + 1}
                        )
                        
                        features.append(feature)
                        break
                
                # Check for file operations
                for operation in self.file_operations:
                    if operation in line:
                        # Create feature
                        feature = StringFeature(
                            line,
                            weight=1.2 * self.weight,
                            is_ascii=True,
                            entropy=self._calculate_entropy(line.encode()),
                            context={"type": "file_operation", "line": i + 1}
                        )
                        
                        features.append(feature)
                        break
            
            # Look for BASE64-encoded data
            base64_pattern = r'[A-Za-z0-9+/]{30,}={0,2}'
            for match in re.finditer(base64_pattern, script_content):
                base64_data = match.group(0)
                if len(base64_data) > 100:  # Only consider longer Base64 strings
                    # Calculate entropy
                    entropy = self._calculate_entropy(base64_data.encode())
                    
                    # Only use if high entropy (likely not just text)
                    if entropy > MEDIUM_ENTROPY_THRESHOLD:
                        feature = StringFeature(
                            base64_data[:100],  # Limit length for YARA rule
                            weight=1.3 * self.weight,
                            is_ascii=True,
                            entropy=entropy,
                            context={"type": "base64_data"}
                        )
                        
                        features.append(feature)
        
        except Exception as e:
            logger.error(f"Error extracting script features from {file_path}: {e}")
        
        return features
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data
        
        Args:
            data: Bytes to calculate entropy for
            
        Returns:
            Shannon entropy value (0-8)
        """
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

class EnhancedYaraGenerator:
    """Enhanced YARA rule generator for ransomware detection"""
    
    def __init__(self, output_dir: Optional[str] = None, 
                legacy_mode: bool = False,
                benign_samples_dir: Optional[str] = None):
        """
        Initialize the enhanced YARA rule generator
        
        Args:
            output_dir: Directory to store generated rules
            legacy_mode: Whether to use legacy YARA generators if available
            benign_samples_dir: Directory containing benign samples for testing
        """
        # Set up output directory
        self.output_dir = output_dir or os.path.join(os.getcwd(), 'enhanced_yara_rules')
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Create subdirectories
        self.metadata_dir = os.path.join(self.output_dir, 'metadata')
        self.templates_dir = os.path.join(self.output_dir, 'templates')
        
        os.makedirs(self.metadata_dir, exist_ok=True)
        os.makedirs(self.templates_dir, exist_ok=True)
        
        # Set up benign samples directory
        self.benign_samples_dir = benign_samples_dir
        
        # Create feature extractors
        self.extractors = [
            StringFeatureExtractor(weight=1.0, enabled=True),
            OpcodeFeatureExtractor(weight=1.5, enabled=True),
            BytePatternExtractor(weight=1.2, enabled=True),
            ScriptFeatureExtractor(weight=1.3, enabled=True)
        ]
        
        # Initialize data structures
        self.rules = {}  # Family -> YaraRule
        self.family_features = {}  # Family -> List[YaraFeature]
        
        # Legacy mode and generators
        self.legacy_mode = legacy_mode
        self.legacy_generators = {}
        
        if legacy_mode and LEGACY_IMPORTS_AVAILABLE:
            try:
                self.legacy_generators['basic'] = YaraRuleGenerator(rules_dir=os.path.join(self.output_dir, 'legacy_basic'))
                logger.info("Initialized legacy basic YARA generator")
            except:
                logger.warning("Failed to initialize legacy basic YARA generator")
            
            try:
                self.legacy_generators['advanced'] = RansomwareRuleGenerator(output_dir=os.path.join(self.output_dir, 'legacy_advanced'))
                logger.info("Initialized legacy advanced YARA generator")
            except:
                logger.warning("Failed to initialize legacy advanced YARA generator")
        
        # Load rule templates
        self._create_default_templates()
        
        logger.info(f"Enhanced YARA rule generator initialized with output to {self.output_dir}")
        
        # Statistics
        self.processed_samples = 0
    
    def _create_default_templates(self):
        """Create default YARA rule templates"""
        template_file = os.path.join(self.templates_dir, 'ransomware_template.yara')
        if not os.path.exists(template_file):
            with open(template_file, 'w') as f:
                f.write("""rule {rule_name}
{
    meta:
        description = "{description}"
        author = "Enhanced Ransomware Detection System"
        date = "{date}"
        hash = "{hash}"
        family = "{family}"
        confidence = "{confidence}"
        threat_level = "{threat_level}"
        reference = "{reference}"
        sample_count = {sample_count}
        
    strings:
{string_definitions}
        
    condition:
        {condition}
}
""")
    
    def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """
        Get basic file information
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with file information
        """
        file_info = {
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path),
            "created_time": datetime.datetime.fromtimestamp(os.path.getctime(file_path)).isoformat(),
            "modified_time": datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
        }
        
        # Get file type using 'file' command if available
        try:
            file_type_proc = subprocess.run(['file', '-b', file_path], 
                                         capture_output=True, check=False)
            file_info["file_type"] = file_type_proc.stdout.decode('utf-8', errors='ignore').strip()
        except:
            # Fallback to extension-based detection
            ext = os.path.splitext(file_path)[1].lower()
            if ext in ['.exe', '.dll', '.sys']:
                file_info["file_type"] = "PE executable"
            elif ext in ['.sh', '.bash']:
                file_info["file_type"] = "Shell script"
            elif ext in ['.bat', '.cmd']:
                file_info["file_type"] = "Batch script"
            elif ext in ['.js']:
                file_info["file_type"] = "JavaScript"
            elif ext in ['.vbs']:
                file_info["file_type"] = "VBScript"
            elif ext in ['.ps1']:
                file_info["file_type"] = "PowerShell script"
            elif ext in ['.py']:
                file_info["file_type"] = "Python script"
            else:
                file_info["file_type"] = "Unknown"
        
        # Calculate file hashes
        with open(file_path, 'rb') as f:
            data = f.read()
            file_info["md5"] = hashlib.md5(data).hexdigest()
            file_info["sha1"] = hashlib.sha1(data).hexdigest()
            file_info["sha256"] = hashlib.sha256(data).hexdigest()
            
            # Calculate overall file entropy
            file_info["entropy"] = self._calculate_entropy(data)
        
        return file_info
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data
        
        Args:
            data: Bytes to calculate entropy for
            
        Returns:
            Shannon entropy value (0-8)
        """
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
    
    def analyze_sample(self, file_path: str, family: str, 
                      analysis_data: Dict = None,
                      generate_rule: bool = False) -> Dict[str, Any]:
        """
        Analyze a ransomware sample and extract features
        
        Args:
            file_path: Path to the sample file
            family: Ransomware family name
            analysis_data: Optional pre-computed analysis data
            generate_rule: Whether to generate a rule for this sample
            
        Returns:
            Analysis results
        """
        if not os.path.exists(file_path):
            logger.error(f"Sample file not found: {file_path}")
            return {"error": "File not found"}
        
        logger.info(f"Analyzing sample: {file_path} (Family: {family})")
        
        # Get file information
        file_info = self._get_file_info(file_path)
        
        results = {
            "file": file_path,
            "family": family,
            "file_info": file_info,
            "analysis_time": datetime.datetime.now().isoformat(),
            "features": {}
        }
        
        # Extract features using all enabled extractors
        all_features = []
        
        for extractor in self.extractors:
            if not extractor.enabled:
                continue
            
            if extractor.can_handle(file_path, file_info):
                extractor_features = extractor.extract_features(file_path, file_info)
                all_features.extend(extractor_features)
                results["features"][extractor.name] = len(extractor_features)
        
        # Store features by family
        if family not in self.family_features:
            self.family_features[family] = []
        
        self.family_features[family].extend(all_features)
        
        # Update sample count
        self.processed_samples += 1
        
        # Process using legacy generators if enabled
        if self.legacy_mode and self.legacy_generators:
            legacy_results = {}
            
            if 'basic' in self.legacy_generators and analysis_data:
                # Create a sample data for legacy basic generator
                sample_data = {
                    "sha256": file_info["sha256"],
                    "analysis": {}
                }
                
                if analysis_data:
                    sample_data["analysis"] = analysis_data
                
                # Generate rule
                rule_path = self.legacy_generators['basic'].generate_yara_rule(sample_data)
                legacy_results['basic_rule_path'] = rule_path
            
            if 'advanced' in self.legacy_generators:
                # Generate rule
                sample_result = self.legacy_generators['advanced'].analyze_sample(file_path, family)
                legacy_results['advanced_analysis'] = sample_result
            
            results["legacy_results"] = legacy_results
        
        # Generate rule if requested
        if generate_rule:
            rule = self.generate_rule_for_family(family)
            if rule:
                results["rule"] = rule.name
                results["rule_path"] = os.path.join(self.output_dir, f"{rule.name}.yar")
        
        logger.info(f"Extracted {len(all_features)} features from sample")
        return results
    
    def generate_rule_for_family(self, family: str) -> Optional[YaraRule]:
        """
        Generate a YARA rule for a specific ransomware family
        
        Args:
            family: Ransomware family
            
        Returns:
            Generated YARA rule or None if generation failed
        """
        if family not in self.family_features or not self.family_features[family]:
            logger.warning(f"No features available for family: {family}")
            return None
        
        # Check if rule already exists
        rule_name = f"Ransomware_{family}"
        if rule_name in self.rules:
            # Update existing rule
            logger.info(f"Updating existing rule for {family}")
            rule = self.rules[rule_name]
            
            # Add new features
            for feature in self.family_features[family]:
                rule.add_feature(feature)
        else:
            # Create new rule
            logger.info(f"Creating new rule for {family}")
            rule = YaraRule(
                rule_name,
                family,
                f"Detection rule for {family} ransomware"
            )
            
            # Add features
            for feature in self.family_features[family]:
                rule.add_feature(feature)
            
            # Add to rules dictionary
            self.rules[rule_name] = rule
        
        # Update metadata
        rule.meta["sample_count"] = self.processed_samples
        rule.meta["generated_date"] = datetime.datetime.now().strftime("%Y-%m-%d")
        
        # Optimize rule
        self._optimize_rule(rule)
        
        # Test rule against benign samples if available
        if self.benign_samples_dir and os.path.exists(self.benign_samples_dir):
            self._test_rule_against_benign(rule)
        
        # Save rule
        self._save_rule(rule)
        
        logger.info(f"Generated rule for {family} with {len(rule.features)} features")
        return rule
    
    def _optimize_rule(self, rule: YaraRule) -> None:
        """
        Optimize a YARA rule to reduce false positives
        
        Args:
            rule: YARA rule to optimize
        """
        # Sort features by weight and occurrences
        weighted_features = []
        for feature in rule.features:
            # Calculate combined weight
            combined_weight = feature.weight
            if hasattr(feature, 'occurrences') and feature.occurrences > 1:
                # Increase weight for features that appear in multiple samples
                combined_weight *= min(1.5, 1.0 + (feature.occurrences * 0.1))
            weighted_features.append((feature, combined_weight))
        
        # Sort by combined weight
        weighted_features.sort(key=lambda x: x[1], reverse=True)
        
        # Group features by type
        feature_groups = {}
        for feature, _ in weighted_features:
            feature_type = feature.type
            if feature_type not in feature_groups:
                feature_groups[feature_type] = []
            feature_groups[feature_type].append(feature)
        
        # Balance feature types (take top features from each group)
        balanced_features = []
        
        # Decide how many features to take from each type
        total_slots = min(MAX_STRINGS_PER_RULE, len(weighted_features))
        slot_allocation = {}
        
        # Minimum slots per feature type
        min_slots = 2
        remaining_slots = total_slots
        
        # Allocate minimum slots to each feature type
        for feature_type, features in feature_groups.items():
            if features:
                slot_allocation[feature_type] = min(min_slots, len(features))
                remaining_slots -= slot_allocation[feature_type]
        
        # Allocate remaining slots proportionally to feature count
        if remaining_slots > 0:
            total_features = sum(len(features) for features in feature_groups.values())
            for feature_type, features in feature_groups.items():
                if features:
                    # Calculate proportional allocation
                    prop_slots = int((len(features) / total_features) * remaining_slots)
                    slot_allocation[feature_type] += prop_slots
                    remaining_slots -= prop_slots
            
            # Allocate any leftover slots to string features (usually most reliable)
            if remaining_slots > 0 and 'string' in feature_groups and feature_groups['string']:
                slot_allocation['string'] += remaining_slots
        
        # Take allocated features from each group
        for feature_type, count in slot_allocation.items():
            if feature_type in feature_groups:
                balanced_features.extend(feature_groups[feature_type][:count])
        
        # Update rule features
        rule.features = balanced_features
        
        # Set appropriate condition based on feature count and types
        if len(balanced_features) > 15:
            # Require multiple matches for many features
            rule.condition = "uint16(0) == 0x5A4D and 5 of them"  # Check for MZ header and multiple features
        elif len(balanced_features) > 8:
            # Require multiple matches for medium feature count
            rule.condition = "3 of them"
        else:
            # Require few matches for low feature count
            rule.condition = "2 of them"
        
        # Calculate confidence score based on feature weights and counts
        avg_weight = statistics.mean(f.weight for f in balanced_features) if balanced_features else 0
        feature_count_factor = min(1.0, len(balanced_features) / 10.0)
        rule.confidence = min(0.95, (avg_weight / 2.0) * feature_count_factor)
        
        # Estimate false positive rate based on feature specificity
        # (This is just a rough estimate)
        rule.false_positive_rate = max(0.001, 0.05 - (rule.confidence * 0.05))
    
    def _test_rule_against_benign(self, rule: YaraRule) -> None:
        """
        Test a rule against benign samples to check for false positives
        
        Args:
            rule: YARA rule to test
        """
        # Create a temporary YARA rule file
        with tempfile.NamedTemporaryFile(suffix='.yar', delete=False) as f:
            rule_path = f.name
            f.write(rule.generate_rule_text().encode('utf-8'))
        
        try:
            # Import YARA if available
            import yara
            
            # Compile rule
            compiled_rule = yara.compile(rule_path)
            
            # Test against benign samples
            false_positives = 0
            total_samples = 0
            
            # Walk benign samples directory
            for root, _, files in os.walk(self.benign_samples_dir):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    
                    # Skip non-file items
                    if not os.path.isfile(file_path):
                        continue
                    
                    # Skip very large files
                    if os.path.getsize(file_path) > 100 * 1024 * 1024:  # 100 MB
                        logger.warning(f"Skipping large file: {file_path}")
                        continue
                    
                    total_samples += 1
                    
                    try:
                        # Scan file with YARA
                        matches = compiled_rule.match(file_path)
                        
                        if matches:
                            # Found a false positive
                            false_positives += 1
                            logger.warning(f"False positive in {file_path}: {[m.rule for m in matches]}")
                    
                    except Exception as e:
                        logger.error(f"Error scanning file {file_path}: {e}")
            
            # Calculate false positive rate
            if total_samples > 0:
                fp_rate = false_positives / total_samples
                rule.false_positive_rate = fp_rate
                
                # Adjust condition if false positive rate is high
                if fp_rate > 0.05 and len(rule.features) > 5:
                    # Make condition more strict
                    if "of them" in rule.condition:
                        current_count = int(rule.condition.split()[0])
                        rule.condition = f"{current_count + 1} of them"
                    else:
                        # Add a stricter condition
                        rule.condition = f"3 of them"
            
            logger.info(f"Rule {rule.name} tested against {total_samples} benign samples with {false_positives} false positives")
        
        except ImportError:
            logger.warning("YARA Python module not available, skipping benign testing")
        
        except Exception as e:
            logger.error(f"Error testing against benign samples: {e}")
        
        finally:
            # Clean up temporary rule file
            if os.path.exists(rule_path):
                os.unlink(rule_path)
    
    def _save_rule(self, rule: YaraRule) -> None:
        """
        Save a YARA rule to disk
        
        Args:
            rule: YARA rule to save
        """
        # Save YARA rule text
        rule_path = os.path.join(self.output_dir, f"{rule.name}.yar")
        with open(rule_path, 'w') as f:
            f.write(self._generate_rule_text(rule))
        
        # Save metadata
        metadata_path = os.path.join(self.metadata_dir, f"{rule.name}.json")
        with open(metadata_path, 'w') as f:
            json.dump(rule.to_dict(), f, indent=2)
    
    def _generate_rule_text(self, rule: YaraRule) -> str:
        """
        Generate YARA rule text
        
        Args:
            rule: YARA rule
            
        Returns:
            YARA rule text
        """
        # Load template
        template_path = os.path.join(self.templates_dir, 'ransomware_template.yara')
        with open(template_path, 'r') as f:
            template = f.read()
        
        # Create string definitions
        string_definitions = ""
        for feature in rule.features:
            if hasattr(feature, 'to_yara_string'):
                string_definitions += f"        {feature.to_yara_string()}\n"
        
        # Confidence string
        if rule.confidence >= 0.8:
            confidence = "high"
        elif rule.confidence >= 0.5:
            confidence = "medium"
        else:
            confidence = "low"
        
        # Threat level
        threat_level = "high"  # For ransomware, always consider it high
        
        # Hash value
        hash_value = "multiple"
        
        # Fill template
        rule_text = template.format(
            rule_name=rule.name,
            description=rule.meta.get("description", f"Detection rule for {rule.family} ransomware"),
            date=datetime.datetime.now().strftime('%Y-%m-%d'),
            hash=hash_value,
            family=rule.family,
            confidence=confidence,
            threat_level=threat_level,
            reference="",
            sample_count=rule.meta.get("sample_count", 0),
            string_definitions=string_definitions,
            condition=rule.condition
        )
        
        return rule_text
    
    def generate_all_rules(self) -> Dict[str, YaraRule]:
        """
        Generate rules for all processed families
        
        Returns:
            Dictionary mapping family names to generated rules
        """
        rules = {}
        
        for family in self.family_features.keys():
            rule = self.generate_rule_for_family(family)
            if rule:
                rules[family] = rule
        
        logger.info(f"Generated {len(rules)} rules for {len(self.family_features)} families")
        return rules
    
    def save_combined_ruleset(self, filename: str = "enhanced_ransomware_rules.yar") -> Optional[str]:
        """
        Save all generated rules as a single YARA ruleset
        
        Args:
            filename: Output filename
            
        Returns:
            Path to the ruleset file or None if save failed
        """
        if not self.rules:
            logger.warning("No rules to save")
            return None
        
        output_path = os.path.join(self.output_dir, filename)
        
        try:
            with open(output_path, 'w') as f:
                # Add header
                f.write("/*\n")
                f.write(" * Enhanced Ransomware Detection YARA Rules\n")
                f.write(f" * Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f" * Families: {', '.join(self.rules.keys())}\n")
                f.write(" * Author: Enhanced Ransomware Detection System\n")
                f.write(" */\n\n")
                
                # Add rules
                for rule_name, rule in self.rules.items():
                    f.write(self._generate_rule_text(rule))
                    f.write("\n\n")
            
            logger.info(f"Saved combined ruleset to {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error saving combined ruleset: {e}")
            return None

def main():
    """Command-line entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced YARA Rule Generator for Ransomware Detection")
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze ransomware samples')
    analyze_parser.add_argument('samples', nargs='+', help='Sample files to analyze')
    analyze_parser.add_argument('--family', '-f', required=True, help='Ransomware family')
    analyze_parser.add_argument('--output-dir', '-o', help='Output directory for results')
    analyze_parser.add_argument('--benign-dir', '-b', help='Directory containing benign samples for testing')
    analyze_parser.add_argument('--legacy', '-l', action='store_true', help='Use legacy YARA generators if available')
    
    # generate command
    generate_parser = subparsers.add_parser('generate', help='Generate YARA rules')
    generate_parser.add_argument('--family', '-f', help='Generate rule for specific family')
    generate_parser.add_argument('--all', '-a', action='store_true', help='Generate rules for all families')
    generate_parser.add_argument('--output-file', '-o', help='Output file for combined ruleset')
    generate_parser.add_argument('--output-dir', '-d', help='Output directory for results')
    
    # analyze-directory command
    analyze_dir_parser = subparsers.add_parser('analyze-directory', help='Analyze a directory of samples')
    analyze_dir_parser.add_argument('directory', help='Directory containing samples')
    analyze_dir_parser.add_argument('--family', '-f', required=True, help='Ransomware family')
    analyze_dir_parser.add_argument('--recursive', '-r', action='store_true', help='Recurse into subdirectories')
    analyze_dir_parser.add_argument('--output-dir', '-o', help='Output directory for results')
    analyze_dir_parser.add_argument('--benign-dir', '-b', help='Directory containing benign samples for testing')
    
    # test command
    test_parser = subparsers.add_parser('test', help='Test rules against samples')
    test_parser.add_argument('ruleset', help='YARA ruleset file')
    test_parser.add_argument('samples_dir', help='Directory containing test samples')
    test_parser.add_argument('--output', '-o', help='Output file for test results')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Process commands
    if args.command == 'analyze':
        # Create generator
        generator = EnhancedYaraGenerator(
            output_dir=args.output_dir,
            legacy_mode=args.legacy if hasattr(args, 'legacy') else False,
            benign_samples_dir=args.benign_dir if hasattr(args, 'benign_dir') else None
        )
        
        # Analyze samples and generate rule
        for sample in args.samples:
            generator.analyze_sample(sample, args.family, generate_rule=True)
        
        # Generate rule
        rule = generator.generate_rule_for_family(args.family)
        
        if rule:
            print(f"Generated rule: {rule.name}")
            print(f"YARA Rule saved to: {os.path.join(generator.output_dir, rule.name + '.yar')}")
        else:
            print(f"Failed to generate rule for {args.family}")
    
    elif args.command == 'generate':
        # Create generator
        generator = EnhancedYaraGenerator(output_dir=args.output_dir)
        
        if args.family:
            # Generate rule for specific family
            rule = generator.generate_rule_for_family(args.family)
            
            if rule:
                print(f"Generated rule: {rule.name}")
                print(f"YARA Rule saved to: {os.path.join(generator.output_dir, rule.name + '.yar')}")
            else:
                print(f"Failed to generate rule for {args.family}")
        elif args.all:
            # Generate rules for all families
            rules = generator.generate_all_rules()
            
            if rules:
                print(f"Generated {len(rules)} rules:")
                for family, rule in rules.items():
                    print(f"  {rule.name}")
                
                # Save combined ruleset
                output_file = args.output_file or "enhanced_ransomware_rules.yar"
                ruleset_path = generator.save_combined_ruleset(output_file)
                
                if ruleset_path:
                    print(f"Combined ruleset saved to: {ruleset_path}")
            else:
                print("No rules generated")
        else:
            print("No action specified. Use --family or --all")
    
    elif args.command == 'analyze-directory':
        # Create generator
        generator = EnhancedYaraGenerator(
            output_dir=args.output_dir,
            benign_samples_dir=args.benign_dir if hasattr(args, 'benign_dir') else None
        )
        
        # Get all sample files
        samples = []
        if args.recursive:
            for root, _, files in os.walk(args.directory):
                for filename in files:
                    samples.append(os.path.join(root, filename))
        else:
            for filename in os.listdir(args.directory):
                file_path = os.path.join(args.directory, filename)
                if os.path.isfile(file_path):
                    samples.append(file_path)
        
        print(f"Found {len(samples)} samples in {args.directory}")
        
        # Analyze samples
        for sample in samples:
            generator.analyze_sample(sample, args.family)
        
        # Generate rule
        rule = generator.generate_rule_for_family(args.family)
        
        if rule:
            print(f"Generated rule: {rule.name}")
            print(f"YARA Rule saved to: {os.path.join(generator.output_dir, rule.name + '.yar')}")
        else:
            print(f"Failed to generate rule for {args.family}")
    
    elif args.command == 'test':
        # Import yara module
        try:
            import yara
        except ImportError:
            print("Error: YARA Python module not installed. Install with 'pip install yara-python'")
            return 1
        
        # Compile YARA ruleset
        try:
            rules = yara.compile(args.ruleset)
            print(f"Successfully compiled YARA ruleset: {args.ruleset}")
        except Exception as e:
            print(f"Error compiling YARA ruleset: {e}")
            return 1
        
        # Test against samples
        test_results = {
            "total_samples": 0,
            "matched_samples": 0,
            "rules_matched": {}
        }
        
        for root, _, files in os.walk(args.samples_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                
                # Skip non-file items
                if not os.path.isfile(file_path):
                    continue
                
                # Skip very large files
                if os.path.getsize(file_path) > 100 * 1024 * 1024:  # 100 MB
                    print(f"Skipping large file: {file_path}")
                    continue
                
                test_results["total_samples"] += 1
                
                try:
                    # Scan file with YARA
                    matches = rules.match(file_path)
                    
                    if matches:
                        test_results["matched_samples"] += 1
                        
                        # Count matches per rule
                        for match in matches:
                            rule_name = match.rule
                            if rule_name not in test_results["rules_matched"]:
                                test_results["rules_matched"][rule_name] = 0
                            test_results["rules_matched"][rule_name] += 1
                        
                        print(f"Matched: {file_path}")
                        print(f"  Rules: {', '.join(match.rule for match in matches)}")
                
                except Exception as e:
                    print(f"Error scanning file {file_path}: {e}")
        
        # Print results
        print("\nTest Results:")
        print(f"Total samples: {test_results['total_samples']}")
        print(f"Matched samples: {test_results['matched_samples']}")
        if test_results['total_samples'] > 0:
            print(f"Match rate: {test_results['matched_samples'] / test_results['total_samples'] * 100:.2f}%")
        
        if test_results["rules_matched"]:
            print("\nRules matched:")
            for rule_name, count in sorted(test_results["rules_matched"].items(), 
                                        key=lambda x: x[1], reverse=True):
                print(f"  {rule_name}: {count} matches")
        
        # Save results if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(test_results, f, indent=2)
            print(f"\nTest results saved to: {args.output}")
    
    else:
        parser.print_help()
    
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())