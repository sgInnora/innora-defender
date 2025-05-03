#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Ransomware YARA Rule Generator

This module provides automated YARA rule generation for ransomware detection
with sophisticated pattern extraction, statistical analysis, and rule optimization.
Generated rules can be used for improved ransomware detection and classification.

Key features:
- Automatic feature extraction from ransomware samples
- Context-aware string extraction with entropy analysis
- Opcode pattern identification for binary files
- Rule optimization for lowest false positive rates
- Support for multiple file formats and encryption methods
- Integration with existing ransomware databases
"""

import os
import re
import json
import math
import logging
import argparse
import hashlib
import datetime
import statistics
import binascii
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any, Union, BinaryIO, Iterator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('RansomwareRuleGenerator')

# Minimum string length to consider for YARA rules
MIN_STRING_LENGTH = 8

# Entropy thresholds
HIGH_ENTROPY_THRESHOLD = 7.0
MEDIUM_ENTROPY_THRESHOLD = 5.0

# Maximum number of strings per rule
MAX_STRINGS_PER_RULE = 20

class YaraFeature:
    """Base class for YARA rule features."""
    
    def __init__(self, feature_type: str, value: Any, weight: float = 1.0):
        """
        Initialize feature.
        
        Args:
            feature_type: Type of feature
            value: Feature value
            weight: Feature weight for rule significance
        """
        self.type = feature_type
        self.value = value
        self.weight = weight
        self.description = ""
        self.occurrences = 1  # How many times we've seen this feature
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert feature to dictionary representation."""
        return {
            'type': self.type,
            'value': self.value,
            'weight': self.weight,
            'description': self.description,
            'occurrences': self.occurrences
        }
    
    def __str__(self) -> str:
        """String representation of feature."""
        return f"{self.type}: {self.value}"


class StringFeature(YaraFeature):
    """String feature for YARA rules."""
    
    def __init__(self, value: str, weight: float = 1.0, 
                is_ascii: bool = True, entropy: float = 0.0,
                offset: Optional[int] = None, context: Optional[str] = None):
        """
        Initialize string feature.
        
        Args:
            value: String value
            weight: Feature weight
            is_ascii: Whether string is ASCII or binary
            entropy: String entropy value
            offset: File offset where string was found
            context: Additional context about the string
        """
        super().__init__('string', value, weight)
        self.is_ascii = is_ascii
        self.entropy = entropy
        self.offset = offset
        self.context = context or {}
        
        # Generate a unique ID for this string
        self.id = f"s{hashlib.md5(value.encode()).hexdigest()[:8]}"
    
    def to_yara_string(self) -> str:
        """Convert to YARA rule string definition."""
        if self.is_ascii:
            # Escape special characters
            escaped_value = self.value.replace('\\', '\\\\').replace('"', '\\"')
            return f'${self.id} = "{escaped_value}"'
        else:
            # Convert to hex format
            hex_value = ' '.join([f"{ord(c):02x}" for c in self.value])
            return f'${self.id} = {{ {hex_value} }}'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        data = super().to_dict()
        data.update({
            'is_ascii': self.is_ascii,
            'entropy': self.entropy,
            'offset': self.offset,
            'id': self.id,
            'context': self.context
        })
        return data


class BytePatternFeature(YaraFeature):
    """Byte pattern feature for YARA rules."""
    
    def __init__(self, value: bytes, weight: float = 1.0, 
                offset: Optional[int] = None, context: Optional[str] = None):
        """
        Initialize byte pattern feature.
        
        Args:
            value: Byte pattern
            weight: Feature weight
            offset: File offset where pattern was found
            context: Additional context about the pattern
        """
        super().__init__('byte_pattern', value, weight)
        self.offset = offset
        self.context = context or {}
        
        # Generate a unique ID for this pattern
        self.id = f"b{hashlib.md5(value).hexdigest()[:8]}"
    
    def to_yara_string(self) -> str:
        """Convert to YARA rule string definition."""
        # Convert to hex format with wildcards
        hex_bytes = []
        for b in self.value:
            if isinstance(b, int):
                hex_bytes.append(f"{b:02x}")
            else:
                hex_bytes.append("??")  # Wildcard for variable bytes
                
        hex_pattern = ' '.join(hex_bytes)
        return f'${self.id} = {{ {hex_pattern} }}'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        data = super().to_dict()
        data.update({
            'offset': self.offset,
            'id': self.id,
            'context': self.context,
            'value': self.value.hex() if isinstance(self.value, bytes) else str(self.value)
        })
        return data


class OpcodeFeature(YaraFeature):
    """CPU opcode pattern feature for YARA rules."""
    
    def __init__(self, value: str, weight: float = 1.0, 
                offset: Optional[int] = None, context: Optional[str] = None):
        """
        Initialize opcode feature.
        
        Args:
            value: Opcode pattern (e.g., "push ebp; mov ebp, esp")
            weight: Feature weight
            offset: File offset where opcode was found
            context: Additional context about the opcode
        """
        super().__init__('opcode', value, weight)
        self.offset = offset
        self.context = context or {}
        
        # Generate a unique ID for this opcode
        self.id = f"o{hashlib.md5(value.encode()).hexdigest()[:8]}"
    
    def to_yara_string(self) -> str:
        """Convert to YARA rule string definition."""
        return f'${self.id} = {{ {self.value} }}'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        data = super().to_dict()
        data.update({
            'offset': self.offset,
            'id': self.id,
            'context': self.context
        })
        return data


class YaraRule:
    """Represents a YARA rule for ransomware detection."""
    
    def __init__(self, name: str, family: str, description: str = ""):
        """
        Initialize YARA rule.
        
        Args:
            name: Rule name
            family: Ransomware family
            description: Rule description
        """
        self.name = name
        self.family = family
        self.description = description
        self.tags = [family.lower(), "ransomware"]
        self.features: List[YaraFeature] = []
        self.meta = {
            "author": "Innora Ransomware Detection System",
            "date": datetime.datetime.now().strftime("%Y-%m-%d"),
            "description": description or f"Detection rule for {family} ransomware",
            "family": family,
            "sample_count": 0
        }
        self.condition = "any of them"
        self.confidence = 0.0
        self.false_positive_rate = 0.0
    
    def add_feature(self, feature: YaraFeature) -> None:
        """
        Add a feature to the rule.
        
        Args:
            feature: Feature to add
        """
        # Check if a similar feature already exists
        for existing in self.features:
            if (existing.type == feature.type and 
                existing.value == feature.value):
                # Increment occurrence count
                existing.occurrences += 1
                # Increase weight slightly for duplicate occurrences
                existing.weight = min(existing.weight + 0.05, 2.0)
                return
        
        # Add new feature
        self.features.append(feature)
    
    def generate_rule_text(self) -> str:
        """
        Generate YARA rule text.
        
        Returns:
            YARA rule as text
        """
        # Choose top features based on weight
        top_features = sorted(self.features, key=lambda f: f.weight, reverse=True)
        features_to_use = top_features[:MAX_STRINGS_PER_RULE]
        
        # Generate rule text
        rule_text = []
        
        # Add rule header
        rule_text.append(f"rule {self.name} {{")
        
        # Add meta section
        rule_text.append("  meta:")
        for key, value in self.meta.items():
            if isinstance(value, str):
                rule_text.append(f'    {key} = "{value}"')
            else:
                rule_text.append(f"    {key} = {value}")
        
        # Add tags
        rule_text.append("  tags:")
        rule_text.append(f'    {" ".join(self.tags)}')
        
        # Add strings section
        rule_text.append("  strings:")
        for feature in features_to_use:
            if hasattr(feature, 'to_yara_string'):
                rule_text.append(f"    {feature.to_yara_string()}")
        
        # Add condition
        rule_text.append("  condition:")
        rule_text.append(f"    {self.condition}")
        
        # Close rule
        rule_text.append("}")
        
        return "\n".join(rule_text)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'name': self.name,
            'family': self.family,
            'description': self.description,
            'tags': self.tags,
            'meta': self.meta,
            'features': [f.to_dict() for f in self.features],
            'condition': self.condition,
            'confidence': self.confidence,
            'false_positive_rate': self.false_positive_rate
        }


class RansomwareRuleGenerator:
    """Generator for ransomware YARA detection rules."""
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize the rule generator.
        
        Args:
            output_dir: Directory for generated rules
        """
        # Set up output directory
        self.output_dir = output_dir or os.path.join(os.getcwd(), 'yara_rules')
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialize data structures
        self.processed_samples = 0
        self.family_features = {}  # Family -> List[Feature]
        self.generated_rules = {}  # Family -> Rule
        
        # Load existing rules if available
        self.existing_rules = self._load_existing_rules()
        
        logger.info(f"Ransomware Rule Generator initialized with output to {self.output_dir}")
    
    def _load_existing_rules(self) -> Dict[str, YaraRule]:
        """
        Load existing YARA rules from the output directory.
        
        Returns:
            Dictionary mapping rule names to YaraRule objects
        """
        existing_rules = {}
        
        # Look for JSON metadata files
        metadata_dir = os.path.join(self.output_dir, 'metadata')
        if os.path.exists(metadata_dir):
            for filename in os.listdir(metadata_dir):
                if filename.endswith('.json'):
                    try:
                        filepath = os.path.join(metadata_dir, filename)
                        with open(filepath, 'r') as f:
                            rule_data = json.load(f)
                        
                        # Recreate rule from metadata
                        rule = YaraRule(
                            rule_data['name'],
                            rule_data['family'],
                            rule_data['description']
                        )
                        rule.tags = rule_data['tags']
                        rule.meta = rule_data['meta']
                        rule.condition = rule_data['condition']
                        rule.confidence = rule_data.get('confidence', 0.0)
                        rule.false_positive_rate = rule_data.get('false_positive_rate', 0.0)
                        
                        # Add features
                        for feature_data in rule_data.get('features', []):
                            feature_type = feature_data['type']
                            if feature_type == 'string':
                                feature = StringFeature(
                                    feature_data['value'],
                                    feature_data['weight'],
                                    feature_data.get('is_ascii', True),
                                    feature_data.get('entropy', 0.0),
                                    feature_data.get('offset'),
                                    feature_data.get('context')
                                )
                                feature.id = feature_data.get('id', feature.id)
                                rule.add_feature(feature)
                            elif feature_type == 'byte_pattern':
                                # Convert hex string back to bytes
                                if isinstance(feature_data['value'], str):
                                    try:
                                        value = bytes.fromhex(feature_data['value'])
                                    except:
                                        value = feature_data['value'].encode()
                                else:
                                    value = feature_data['value']
                                
                                feature = BytePatternFeature(
                                    value,
                                    feature_data['weight'],
                                    feature_data.get('offset'),
                                    feature_data.get('context')
                                )
                                feature.id = feature_data.get('id', feature.id)
                                rule.add_feature(feature)
                            elif feature_type == 'opcode':
                                feature = OpcodeFeature(
                                    feature_data['value'],
                                    feature_data['weight'],
                                    feature_data.get('offset'),
                                    feature_data.get('context')
                                )
                                feature.id = feature_data.get('id', feature.id)
                                rule.add_feature(feature)
                        
                        existing_rules[rule.name] = rule
                    except Exception as e:
                        logger.error(f"Error loading rule from {filename}: {e}")
        
        logger.info(f"Loaded {len(existing_rules)} existing rules")
        return existing_rules
    
    def analyze_sample(self, file_path: str, family: str) -> Dict[str, Any]:
        """
        Analyze a ransomware sample and extract features.
        
        Args:
            file_path: Path to ransomware sample
            family: Ransomware family
            
        Returns:
            Analysis results
        """
        if not os.path.exists(file_path):
            logger.error(f"Sample file not found: {file_path}")
            return {"error": "File not found"}
        
        logger.info(f"Analyzing sample: {file_path} (Family: {family})")
        
        results = {
            "file": file_path,
            "family": family,
            "features": [],
            "file_info": self._get_file_info(file_path),
            "analysis_time": datetime.datetime.now().isoformat()
        }
        
        # Extract features based on file type
        file_info = results["file_info"]
        file_type = file_info.get("file_type", "").lower()
        
        if "pe" in file_type or file_path.endswith('.exe') or file_path.endswith('.dll'):
            # Windows executable
            features = self._extract_pe_features(file_path)
        elif "elf" in file_type or "executable" in file_type:
            # Linux executable
            features = self._extract_elf_features(file_path)
        elif "script" in file_type or file_path.endswith(('.js', '.vbs', '.ps1', '.bat', '.sh')):
            # Script file
            features = self._extract_script_features(file_path)
        else:
            # Generic binary file
            features = self._extract_binary_features(file_path)
        
        # Add features to family collection
        if family not in self.family_features:
            self.family_features[family] = []
        
        self.family_features[family].extend(features)
        results["features"] = [f.to_dict() for f in features]
        
        # Update processed samples count
        self.processed_samples += 1
        
        logger.info(f"Extracted {len(features)} features from sample")
        return results
    
    def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """
        Get basic file information.
        
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
            else:
                file_info["file_type"] = "Unknown"
        
        # Calculate file hashes
        with open(file_path, 'rb') as f:
            data = f.read()
            file_info["md5"] = hashlib.md5(data).hexdigest()
            file_info["sha1"] = hashlib.sha1(data).hexdigest()
            file_info["sha256"] = hashlib.sha256(data).hexdigest()
        
        return file_info
    
    def _extract_pe_features(self, file_path: str) -> List[YaraFeature]:
        """
        Extract features from a PE executable.
        
        Args:
            file_path: Path to PE file
            
        Returns:
            List of extracted features
        """
        features = []
        
        # Use 'strings' command to extract strings
        try:
            # Extract ASCII strings
            strings_proc = subprocess.run(['strings', '-a', '-n', str(MIN_STRING_LENGTH), file_path], 
                                        capture_output=True, check=False)
            ascii_strings = strings_proc.stdout.decode('utf-8', errors='ignore').splitlines()
            
            # Extract wide (Unicode) strings
            wide_strings_proc = subprocess.run(['strings', '-a', '-n', str(MIN_STRING_LENGTH), '-e', 'l', file_path],
                                             capture_output=True, check=False)
            wide_strings = wide_strings_proc.stdout.decode('utf-8', errors='ignore').splitlines()
            
            # Process strings
            all_strings = set(ascii_strings + wide_strings)
            for string in all_strings:
                # Filter out common strings and very long strings
                if len(string) > 200 or self._is_common_string(string):
                    continue
                
                # Calculate string entropy
                entropy = self._calculate_entropy(string.encode())
                
                # Adjust weight based on entropy and ransomware indicators
                weight = 1.0
                if self._is_ransomware_indicator(string):
                    weight += 0.5
                if entropy > HIGH_ENTROPY_THRESHOLD:
                    weight += 0.3
                elif entropy > MEDIUM_ENTROPY_THRESHOLD:
                    weight += 0.1
                
                # Create string feature
                feature = StringFeature(
                    string,
                    weight=weight,
                    is_ascii=string in ascii_strings,
                    entropy=entropy
                )
                
                features.append(feature)
            
            # Extract functions and imports using objdump if available
            try:
                import_proc = subprocess.run(['objdump', '-x', file_path], 
                                           capture_output=True, check=False)
                import_output = import_proc.stdout.decode('utf-8', errors='ignore')
                
                # Extract imported functions
                import_pattern = r'^\s*([A-Za-z0-9_]+) .* ((?:Crypto|Crypt|AES|Encrypt|Decrypt|RSA|EVP|OpenSSL|Hash|SHA|MD5|Base64).*?)$'
                for match in re.finditer(import_pattern, import_output, re.MULTILINE):
                    function = match.group(2)
                    if function and len(function) >= MIN_STRING_LENGTH:
                        feature = StringFeature(
                            function,
                            weight=1.5,  # Higher weight for cryptographic functions
                            is_ascii=True,
                            entropy=self._calculate_entropy(function.encode()),
                            context={"type": "imported_function"}
                        )
                        features.append(feature)
            except:
                pass
            
        except Exception as e:
            logger.error(f"Error extracting PE strings: {e}")
        
        # Use a more targeted approach to find opcode patterns
        try:
            # Run objdump to get disassembly
            disasm_proc = subprocess.run(['objdump', '-d', file_path], 
                                       capture_output=True, check=False)
            disasm_output = disasm_proc.stdout.decode('utf-8', errors='ignore')
            
            # Look for interesting code patterns
            patterns = self._extract_code_patterns(disasm_output)
            features.extend(patterns)
            
        except Exception as e:
            logger.error(f"Error extracting PE opcodes: {e}")
        
        # Add byte patterns from file headers and specific sections
        try:
            with open(file_path, 'rb') as f:
                data = f.read(4096)  # Read first 4KB for headers
                
                # Extract MZ and PE header
                if data.startswith(b'MZ'):
                    # Find PE header offset
                    pe_offset = int.from_bytes(data[0x3C:0x40], byteorder='little')
                    if pe_offset < len(data) - 4 and data[pe_offset:pe_offset+4] == b'PE\0\0':
                        # Extract byte pattern from PE header
                        pe_bytes = data[pe_offset:pe_offset+24]  # PE header bytes
                        feature = BytePatternFeature(
                            pe_bytes,
                            weight=1.2,
                            offset=pe_offset,
                            context={"type": "pe_header"}
                        )
                        features.append(feature)
        except Exception as e:
            logger.error(f"Error extracting PE headers: {e}")
        
        return features
    
    def _extract_elf_features(self, file_path: str) -> List[YaraFeature]:
        """
        Extract features from an ELF executable.
        
        Args:
            file_path: Path to ELF file
            
        Returns:
            List of extracted features
        """
        features = []
        
        # Use 'strings' command to extract strings
        try:
            strings_proc = subprocess.run(['strings', '-a', '-n', str(MIN_STRING_LENGTH), file_path], 
                                        capture_output=True, check=False)
            all_strings = strings_proc.stdout.decode('utf-8', errors='ignore').splitlines()
            
            # Process strings
            for string in all_strings:
                # Filter out common strings and very long strings
                if len(string) > 200 or self._is_common_string(string):
                    continue
                
                # Calculate string entropy
                entropy = self._calculate_entropy(string.encode())
                
                # Adjust weight based on entropy and ransomware indicators
                weight = 1.0
                if self._is_ransomware_indicator(string):
                    weight += 0.5
                if entropy > HIGH_ENTROPY_THRESHOLD:
                    weight += 0.3
                elif entropy > MEDIUM_ENTROPY_THRESHOLD:
                    weight += 0.1
                
                # Create string feature
                feature = StringFeature(
                    string,
                    weight=weight,
                    is_ascii=True,
                    entropy=entropy
                )
                
                features.append(feature)
            
            # Extract functions and imports using readelf
            try:
                import_proc = subprocess.run(['readelf', '-s', file_path], 
                                           capture_output=True, check=False)
                import_output = import_proc.stdout.decode('utf-8', errors='ignore')
                
                # Extract imported functions
                import_pattern = r'\d+:\s+[0-9a-f]+\s+\d+\s+\w+\s+\w+\s+\w+\s+\w+\s+((?:Crypto|Crypt|AES|Encrypt|Decrypt|RSA|EVP|OpenSSL|Hash|SHA|MD5|Base64).*?)$'
                for match in re.finditer(import_pattern, import_output, re.MULTILINE):
                    function = match.group(1)
                    if function and len(function) >= MIN_STRING_LENGTH:
                        feature = StringFeature(
                            function,
                            weight=1.5,  # Higher weight for cryptographic functions
                            is_ascii=True,
                            entropy=self._calculate_entropy(function.encode()),
                            context={"type": "imported_function"}
                        )
                        features.append(feature)
            except:
                pass
            
        except Exception as e:
            logger.error(f"Error extracting ELF strings: {e}")
        
        # Extract opcode patterns
        try:
            # Run objdump to get disassembly
            disasm_proc = subprocess.run(['objdump', '-d', file_path], 
                                       capture_output=True, check=False)
            disasm_output = disasm_proc.stdout.decode('utf-8', errors='ignore')
            
            # Look for interesting code patterns
            patterns = self._extract_code_patterns(disasm_output)
            features.extend(patterns)
            
        except Exception as e:
            logger.error(f"Error extracting ELF opcodes: {e}")
        
        # Add byte patterns from ELF header
        try:
            with open(file_path, 'rb') as f:
                data = f.read(64)  # Read first 64 bytes for ELF header
                
                if data.startswith(b'\x7fELF'):
                    feature = BytePatternFeature(
                        data[:16],  # ELF header bytes
                        weight=1.2,
                        offset=0,
                        context={"type": "elf_header"}
                    )
                    features.append(feature)
        except Exception as e:
            logger.error(f"Error extracting ELF headers: {e}")
        
        return features
    
    def _extract_script_features(self, file_path: str) -> List[YaraFeature]:
        """
        Extract features from a script file.
        
        Args:
            file_path: Path to script file
            
        Returns:
            List of extracted features
        """
        features = []
        
        try:
            # Read script file
            with open(file_path, 'r', errors='ignore') as f:
                script_content = f.read()
            
            # Split into lines
            lines = script_content.splitlines()
            
            # Extract interesting strings and patterns
            for i, line in enumerate(lines):
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('//'):
                    continue
                
                # Look for encryption-related keywords
                encryption_keywords = [
                    'encrypt', 'decrypt', 'AES', 'RSA', 'crypto', 'password',
                    'key', 'iv', 'base64', 'sha1', 'sha256', 'md5', 'hash'
                ]
                
                for keyword in encryption_keywords:
                    if keyword.lower() in line.lower():
                        # Get more context by including adjacent lines
                        start_idx = max(0, i - 2)
                        end_idx = min(len(lines), i + 3)
                        context_lines = lines[start_idx:end_idx]
                        context = '\n'.join(context_lines)
                        
                        # Only use if context is reasonable length
                        if len(context) > 500:
                            context = line
                        
                        # Calculate entropy
                        entropy = self._calculate_entropy(context.encode())
                        
                        # Create feature
                        feature = StringFeature(
                            context,
                            weight=1.5,  # Higher weight for encryption-related code
                            is_ascii=True,
                            entropy=entropy,
                            context={"type": "encryption_code", "line": i + 1}
                        )
                        
                        features.append(feature)
                        break  # Only create one feature for this line
                
                # Look for ransomware-specific indicators
                ransomware_indicators = [
                    'ransom', 'bitcoin', 'payment', 'decrypt', 'files are encrypted',
                    'pay', 'btc', 'wallet', 'recovery', 'restore'
                ]
                
                for indicator in ransomware_indicators:
                    if indicator.lower() in line.lower():
                        # Get more context
                        start_idx = max(0, i - 2)
                        end_idx = min(len(lines), i + 3)
                        context_lines = lines[start_idx:end_idx]
                        context = '\n'.join(context_lines)
                        
                        # Only use if context is reasonable length
                        if len(context) > 500:
                            context = line
                        
                        # Calculate entropy
                        entropy = self._calculate_entropy(context.encode())
                        
                        # Create feature
                        feature = StringFeature(
                            context,
                            weight=2.0,  # Higher weight for ransomware indicators
                            is_ascii=True,
                            entropy=entropy,
                            context={"type": "ransomware_indicator", "line": i + 1}
                        )
                        
                        features.append(feature)
                        break  # Only create one feature for this line
                
                # Look for file operations
                file_operations = [
                    'open(', 'fopen', 'createFile', 'readFile', 'writeFile',
                    'fileStream', 'fstream', 'ReadAllBytes', 'WriteAllBytes',
                    'listdir', 'glob.glob', 'FindFirstFile', 'FindNextFile'
                ]
                
                for operation in file_operations:
                    if operation in line:
                        # Create feature
                        feature = StringFeature(
                            line,
                            weight=1.2,  # Medium weight for file operations
                            is_ascii=True,
                            entropy=self._calculate_entropy(line.encode()),
                            context={"type": "file_operation", "line": i + 1}
                        )
                        
                        features.append(feature)
                        break  # Only create one feature for this line
            
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
                            weight=1.3,  # Medium-high weight for encoded data
                            is_ascii=True,
                            entropy=entropy,
                            context={"type": "base64_data"}
                        )
                        
                        features.append(feature)
            
            # Look for hexadecimal data
            hex_pattern = r'(?:0x)?[A-Fa-f0-9]{16,}'
            for match in re.finditer(hex_pattern, script_content):
                hex_data = match.group(0)
                if len(hex_data) > 32:  # Only consider longer hex strings
                    # Calculate entropy
                    entropy = self._calculate_entropy(hex_data.encode())
                    
                    feature = StringFeature(
                        hex_data[:64],  # Limit length for YARA rule
                        weight=1.2,  # Medium weight for hex data
                        is_ascii=True,
                        entropy=entropy,
                        context={"type": "hex_data"}
                    )
                    
                    features.append(feature)
            
        except Exception as e:
            logger.error(f"Error extracting script features: {e}")
        
        return features
    
    def _extract_binary_features(self, file_path: str) -> List[YaraFeature]:
        """
        Extract features from a generic binary file.
        
        Args:
            file_path: Path to binary file
            
        Returns:
            List of extracted features
        """
        features = []
        
        try:
            # Read binary file
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Look for string patterns
            strings_proc = subprocess.run(['strings', '-a', '-n', str(MIN_STRING_LENGTH), file_path], 
                                        capture_output=True, check=False)
            all_strings = strings_proc.stdout.decode('utf-8', errors='ignore').splitlines()
            
            # Filter and process strings
            for string in all_strings:
                # Filter out common strings and very long strings
                if len(string) > 200 or self._is_common_string(string):
                    continue
                
                # Calculate string entropy
                entropy = self._calculate_entropy(string.encode())
                
                # Adjust weight based on entropy and ransomware indicators
                weight = 1.0
                if self._is_ransomware_indicator(string):
                    weight += 0.5
                if entropy > HIGH_ENTROPY_THRESHOLD:
                    weight += 0.3
                elif entropy > MEDIUM_ENTROPY_THRESHOLD:
                    weight += 0.1
                
                # Create string feature
                feature = StringFeature(
                    string,
                    weight=weight,
                    is_ascii=True,
                    entropy=entropy
                )
                
                features.append(feature)
            
            # Look for high-entropy regions (potential encrypted data)
            for i in range(0, len(data), 1024):
                block = data[i:i+1024]
                if len(block) < 64:  # Skip small trailing blocks
                    continue
                
                entropy = self._calculate_entropy(block)
                if entropy > HIGH_ENTROPY_THRESHOLD:
                    # Extract a sample of the high-entropy data
                    pattern = block[:16]  # First 16 bytes
                    
                    feature = BytePatternFeature(
                        pattern,
                        weight=1.4,  # Medium-high weight for high-entropy data
                        offset=i,
                        context={"type": "high_entropy_data", "entropy": entropy}
                    )
                    
                    features.append(feature)
            
            # Check for file headers
            if len(data) >= 16:
                header = data[:16]
                feature = BytePatternFeature(
                    header,
                    weight=1.5,  # Higher weight for file header
                    offset=0,
                    context={"type": "file_header"}
                )
                
                features.append(feature)
            
        except Exception as e:
            logger.error(f"Error extracting binary features: {e}")
        
        return features
    
    def _extract_code_patterns(self, disassembly: str) -> List[YaraFeature]:
        """
        Extract code patterns from disassembly.
        
        Args:
            disassembly: Disassembly text
            
        Returns:
            List of opcode features
        """
        features = []
        
        # Look for cryptographic code patterns
        crypto_patterns = [
            # AES patterns
            r'[^\n]+?mov[^\n]+?xmm[^\n]+?\n[^\n]+?aes[^\n]+?\n',
            r'[^\n]+?aes(?:enc|keygenassist|imc)[^\n]+?\n[^\n]+?(?:pshufd|pextrq)[^\n]+?\n',
            
            # SHA patterns
            r'[^\n]+?sha(?:1|256)[^\n]+?\n[^\n]+?sha(?:1|256)[^\n]+?\n[^\n]+?sha(?:1|256)[^\n]+?\n',
            
            # Generic crypto sequences
            r'[^\n]+?rol[^\n]+?\n[^\n]+?xor[^\n]+?\n[^\n]+?add[^\n]+?\n[^\n]+?ror[^\n]+?\n',
            r'[^\n]+?xor[^\n]+?\n[^\n]+?shl[^\n]+?\n[^\n]+?add[^\n]+?\n[^\n]+?xor[^\n]+?\n',
        ]
        
        for pattern in crypto_patterns:
            for match in re.finditer(pattern, disassembly):
                code_sequence = match.group(0).strip()
                if not code_sequence:
                    continue
                
                # Extract assembly opcodes
                opcodes = []
                for line in code_sequence.splitlines():
                    parts = line.strip().split(None, 2)
                    if len(parts) >= 2:
                        opcodes.append(parts[1])  # Extract the opcode
                
                if not opcodes:
                    continue
                
                # Create opcode string
                opcode_str = ' '.join(opcodes)
                
                feature = OpcodeFeature(
                    opcode_str,
                    weight=1.8,  # High weight for crypto code
                    context={"type": "crypto_code"}
                )
                
                features.append(feature)
        
        # Look for file enumeration patterns
        file_patterns = [
            r'[^\n]+?call[^\n]+?FindFirstFile[^\n]+?\n[^\n]+?test[^\n]+?\n[^\n]+?je[^\n]+?\n',
            r'[^\n]+?call[^\n]+?ReadFile[^\n]+?\n[^\n]+?test[^\n]+?\n[^\n]+?je[^\n]+?\n',
            r'[^\n]+?call[^\n]+?WriteFile[^\n]+?\n[^\n]+?test[^\n]+?\n[^\n]+?je[^\n]+?\n',
        ]
        
        for pattern in file_patterns:
            for match in re.finditer(pattern, disassembly):
                code_sequence = match.group(0).strip()
                if not code_sequence:
                    continue
                
                # Extract assembly opcodes
                opcodes = []
                for line in code_sequence.splitlines():
                    parts = line.strip().split(None, 2)
                    if len(parts) >= 2:
                        opcodes.append(parts[1])  # Extract the opcode
                
                if not opcodes:
                    continue
                
                # Create opcode string
                opcode_str = ' '.join(opcodes)
                
                feature = OpcodeFeature(
                    opcode_str,
                    weight=1.5,  # Medium-high weight for file operations
                    context={"type": "file_operation"}
                )
                
                features.append(feature)
        
        return features
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data.
        
        Args:
            data: Byte data
            
        Returns:
            Entropy value between 0 and 8
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
    
    def _is_common_string(self, string: str) -> bool:
        """
        Check if a string is a common, uninteresting string.
        
        Args:
            string: String to check
            
        Returns:
            True if string is common, False otherwise
        """
        # List of common strings to ignore
        common_strings = [
            'Microsoft', 'Windows', 'Program Files', 'System32',
            'Mozilla', 'Firefox', 'Chrome', 'Google', 'http://', 'https://',
            'SOFTWARE', 'HARDWARE', 'SYSTEM', 'msvcrt', 'kernel32',
            'KERNEL32', 'USER32', 'GDI32', 'ADVAPI32', 'ole32',
            'Copyright', 'Version', 'Assembly', 'Runtime', 'Software',
            'Library', 'Python', 'Java', '.NET', 'Framework'
        ]
        
        # Check for exact matches
        if string in common_strings:
            return True
        
        # Check for substrings
        for common in common_strings:
            if common in string:
                return True
        
        # Check for generic paths and URLs
        if re.match(r'^[A-Z]:\\', string) or re.match(r'^/usr/|^/bin/|^/etc/', string):
            return True
        
        if re.match(r'^https?://(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', string):
            return True
        
        return False
    
    def _is_ransomware_indicator(self, string: str) -> bool:
        """
        Check if a string is a potential ransomware indicator.
        
        Args:
            string: String to check
            
        Returns:
            True if string is a ransomware indicator, False otherwise
        """
        # List of ransomware-related keywords
        ransomware_keywords = [
            'ransom', 'encrypt', 'decrypt', 'bitcoin', 'recovery', 'payment',
            'pay', 'restore', 'files', 'locked', 'unlock', 'btc', 'wallet',
            'cryptocurrency', 'aes-256', 'rsa-2048', 'your files',
            'your documents', 'your data', 'your computer', 'your pc',
            'warning', 'attention', 'important', 'readme.txt', 'read.me',
            'how to decrypt', 'how to recover', 'contact us', 'contact me',
            'deadline', 'time left', 'timer', 'clock', 'countdown',
            'private key', 'public key', 'decryption key', 'encryption key',
            'all files', 'all data', 'all documents', 'permanent', 'irreversible',
            'no way back', 'no return', 'no recovery', 'no restore',
            'onion', '.onion', 'tor browser', 'tor network', 'anonymous',
            'anonymity', 'untraceable', 'untracable', 'hidden', 'secret',
            'password', 'file recovery', 'data recovery', 'document recovery',
            'recover files', 'recover data', 'recover documents',
            'locked files', 'locked data', 'locked documents',
            'encrypted files', 'encrypted data', 'encrypted documents',
            'decryption service', 'decryption tool', 'decryption software',
            'decryption program', 'decryption utility'
        ]
        
        # Check for ransom note patterns
        if re.search(r'your files (?:are|have been) encrypted', string, re.IGNORECASE):
            return True
        
        if re.search(r'pay.*bitcoin|bitcoin.*pay', string, re.IGNORECASE):
            return True
        
        if re.search(r'decrypt.*key|key.*decrypt', string, re.IGNORECASE):
            return True
        
        # Check for ransom amounts
        if re.search(r'\$\d{3,}|\d{1,2}\s*BTC|\d{1,3}\s*ETH', string):
            return True
        
        # Check for keywords
        for keyword in ransomware_keywords:
            if keyword.lower() in string.lower():
                return True
        
        return False
    
    def generate_rules_for_family(self, family: str) -> Optional[YaraRule]:
        """
        Generate a YARA rule for a specific ransomware family.
        
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
        if rule_name in self.existing_rules:
            # Update existing rule
            logger.info(f"Updating existing rule for {family}")
            rule = self.existing_rules[rule_name]
            
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
        
        # Update metadata
        rule.meta["sample_count"] = self.processed_samples
        rule.meta["generated_date"] = datetime.datetime.now().strftime("%Y-%m-%d")
        
        # Optimize rule
        self._optimize_rule(rule)
        
        # Save rule
        self._save_rule(rule)
        
        # Store in generated rules
        self.generated_rules[family] = rule
        
        logger.info(f"Generated rule for {family} with {len(rule.features)} features")
        return rule
    
    def _optimize_rule(self, rule: YaraRule) -> None:
        """
        Optimize a YARA rule to reduce false positives.
        
        Args:
            rule: YARA rule to optimize
        """
        # Sort features by weight
        sorted_features = sorted(rule.features, key=lambda f: f.weight, reverse=True)
        
        # Choose top features based on weight
        top_features = sorted_features[:MAX_STRINGS_PER_RULE]
        
        # Filter out features with very low weight
        filtered_features = [f for f in top_features if f.weight >= 1.0]
        
        # Keep at least 5 features
        if len(filtered_features) < 5 and len(top_features) >= 5:
            filtered_features = top_features[:5]
        
        # Update rule features
        rule.features = filtered_features
        
        # Set appropriate condition based on feature count
        if len(filtered_features) > 10:
            # Require multiple matches for many features
            rule.condition = "6 of them"
        elif len(filtered_features) > 5:
            # Require multiple matches for medium feature count
            rule.condition = "3 of them"
        else:
            # Require few matches for low feature count
            rule.condition = "2 of them"
        
        # Update confidence score based on feature weights and counts
        avg_weight = statistics.mean(f.weight for f in filtered_features) if filtered_features else 0
        rule.confidence = min(0.95, avg_weight / 2.0)
        
        # Estimate false positive rate based on feature specificity
        # (This is just a rough estimate)
        rule.false_positive_rate = max(0.001, 0.05 - (rule.confidence * 0.05))
    
    def _save_rule(self, rule: YaraRule) -> None:
        """
        Save a YARA rule to disk.
        
        Args:
            rule: YARA rule to save
        """
        # Save YARA rule text
        rule_path = os.path.join(self.output_dir, f"{rule.name}.yar")
        with open(rule_path, 'w') as f:
            f.write(rule.generate_rule_text())
        
        # Save metadata
        metadata_dir = os.path.join(self.output_dir, 'metadata')
        os.makedirs(metadata_dir, exist_ok=True)
        
        metadata_path = os.path.join(metadata_dir, f"{rule.name}.json")
        with open(metadata_path, 'w') as f:
            json.dump(rule.to_dict(), f, indent=2)
    
    def generate_all_rules(self) -> Dict[str, YaraRule]:
        """
        Generate rules for all processed families.
        
        Returns:
            Dictionary mapping family names to generated rules
        """
        rules = {}
        
        for family in self.family_features.keys():
            rule = self.generate_rules_for_family(family)
            if rule:
                rules[family] = rule
        
        logger.info(f"Generated {len(rules)} rules for {len(self.family_features)} families")
        return rules
    
    def save_combined_ruleset(self, filename: str = "ransomware_rules.yar") -> Optional[str]:
        """
        Save all generated rules as a single YARA ruleset.
        
        Args:
            filename: Output filename
            
        Returns:
            Path to the ruleset file or None if save failed
        """
        if not self.generated_rules:
            logger.warning("No rules to save")
            return None
        
        output_path = os.path.join(self.output_dir, filename)
        
        try:
            with open(output_path, 'w') as f:
                # Add header
                f.write("/*\n")
                f.write(" * Ransomware Detection YARA Rules\n")
                f.write(f" * Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f" * Families: {', '.join(self.generated_rules.keys())}\n")
                f.write(" * Author: Innora Ransomware Detection System\n")
                f.write(" */\n\n")
                
                # Add rules
                for family, rule in self.generated_rules.items():
                    f.write(rule.generate_rule_text())
                    f.write("\n\n")
            
            logger.info(f"Saved combined ruleset to {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error saving combined ruleset: {e}")
            return None
    
    def analyze_ruleset_quality(self) -> Dict[str, Any]:
        """
        Analyze the quality of generated rules.
        
        Returns:
            Quality metrics
        """
        if not self.generated_rules:
            logger.warning("No rules to analyze")
            return {"error": "No rules available"}
        
        metrics = {
            "rule_count": len(self.generated_rules),
            "average_features_per_rule": 0,
            "average_rule_confidence": 0,
            "estimated_false_positive_rate": 0,
            "rules": {}
        }
        
        total_features = 0
        total_confidence = 0
        total_fp_rate = 0
        
        for family, rule in self.generated_rules.items():
            # Calculate rule metrics
            feature_count = len(rule.features)
            total_features += feature_count
            
            confidence = rule.confidence
            total_confidence += confidence
            
            fp_rate = rule.false_positive_rate
            total_fp_rate += fp_rate
            
            # Add rule metrics
            metrics["rules"][family] = {
                "name": rule.name,
                "feature_count": feature_count,
                "confidence": confidence,
                "false_positive_rate": fp_rate,
                "condition": rule.condition
            }
        
        # Calculate averages
        rule_count = len(self.generated_rules)
        metrics["average_features_per_rule"] = total_features / rule_count
        metrics["average_rule_confidence"] = total_confidence / rule_count
        metrics["estimated_false_positive_rate"] = total_fp_rate / rule_count
        
        return metrics
    
    def test_rules_against_samples(self, samples_dir: str) -> Dict[str, Any]:
        """
        Test generated rules against sample files.
        
        Args:
            samples_dir: Directory containing test samples
            
        Returns:
            Test results
        """
        if not self.generated_rules:
            logger.warning("No rules to test")
            return {"error": "No rules available"}
        
        if not os.path.isdir(samples_dir):
            logger.error(f"Samples directory not found: {samples_dir}")
            return {"error": "Samples directory not found"}
        
        # Combine rules into a temporary file
        temp_ruleset = os.path.join(self.output_dir, "temp_ruleset.yar")
        self.save_combined_ruleset(temp_ruleset)
        
        results = {
            "total_samples": 0,
            "total_matches": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "families": {}
        }
        
        try:
            # Initialize results for each family
            for family in self.generated_rules.keys():
                results["families"][family] = {
                    "total": 0,
                    "matched": 0,
                    "false_positives": 0,
                    "false_negatives": 0
                }
            
            # Run YARA against samples
            import yara
            rules = yara.compile(temp_ruleset)
            
            # Scan each file
            for root, _, files in os.walk(samples_dir):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    
                    # Get expected family from directory name
                    path_parts = os.path.normpath(root).split(os.sep)
                    expected_family = path_parts[-1].lower() if path_parts else "unknown"
                    
                    # Skip non-file items
                    if not os.path.isfile(file_path):
                        continue
                    
                    # Skip very large files
                    if os.path.getsize(file_path) > 100 * 1024 * 1024:  # 100 MB
                        logger.warning(f"Skipping large file: {file_path}")
                        continue
                    
                    # Count total samples
                    results["total_samples"] += 1
                    
                    # Count samples per family
                    if expected_family in results["families"]:
                        results["families"][expected_family]["total"] += 1
                    
                    try:
                        # Scan file with YARA
                        matches = rules.match(file_path)
                        
                        if matches:
                            # Count total matches
                            results["total_matches"] += 1
                            
                            # Check if rule matched expected family
                            matched_families = [match.rule.split('_')[1].lower() 
                                              for match in matches 
                                              if match.rule.startswith('Ransomware_')]
                            
                            if expected_family in matched_families:
                                # Correct match
                                if expected_family in results["families"]:
                                    results["families"][expected_family]["matched"] += 1
                            else:
                                # False positive
                                results["false_positives"] += 1
                                
                                # Count false positives per detected family
                                for matched_family in matched_families:
                                    if matched_family in results["families"]:
                                        results["families"][matched_family]["false_positives"] += 1
                        else:
                            # No matches
                            if expected_family in results["families"]:
                                # False negative
                                results["false_negatives"] += 1
                                results["families"][expected_family]["false_negatives"] += 1
                    
                    except Exception as e:
                        logger.error(f"Error scanning file {file_path}: {e}")
            
            # Calculate metrics
            if results["total_samples"] > 0:
                results["match_rate"] = results["total_matches"] / results["total_samples"]
                results["accuracy"] = (results["total_matches"] - results["false_positives"]) / results["total_samples"]
            
            for family, family_results in results["families"].items():
                if family_results["total"] > 0:
                    family_results["match_rate"] = family_results["matched"] / family_results["total"]
                    family_results["false_positive_rate"] = family_results["false_positives"] / family_results["total"] if family_results["total"] > 0 else 0
            
            logger.info(f"Tested rules against {results['total_samples']} samples with {results['total_matches']} matches")
            
            # Clean up temporary ruleset
            if os.path.exists(temp_ruleset):
                os.remove(temp_ruleset)
            
            return results
            
        except Exception as e:
            logger.error(f"Error testing rules: {e}")
            return {"error": str(e)}
        finally:
            # Clean up temporary ruleset
            if os.path.exists(temp_ruleset):
                os.remove(temp_ruleset)


def main():
    """Command-line interface for the Ransomware YARA Rule Generator."""
    parser = argparse.ArgumentParser(description="Ransomware YARA Rule Generator")
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze ransomware samples')
    analyze_parser.add_argument('samples', nargs='+', help='Sample files to analyze')
    analyze_parser.add_argument('--family', '-f', required=True, help='Ransomware family')
    analyze_parser.add_argument('--output-dir', '-o', help='Output directory for results')
    
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
    
    # test command
    test_parser = subparsers.add_parser('test', help='Test rules against samples')
    test_parser.add_argument('ruleset', help='YARA ruleset file')
    test_parser.add_argument('samples_dir', help='Directory containing test samples')
    test_parser.add_argument('--output', '-o', help='Output file for test results')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Process commands
    if args.command == 'analyze':
        # Create rule generator
        generator = RansomwareRuleGenerator(args.output_dir)
        
        # Analyze samples
        for sample in args.samples:
            generator.analyze_sample(sample, args.family)
        
        # Generate rule
        rule = generator.generate_rules_for_family(args.family)
        
        if rule:
            print(f"Generated rule: {rule.name}")
            print(f"YARA Rule saved to: {os.path.join(generator.output_dir, rule.name + '.yar')}")
        else:
            print(f"Failed to generate rule for {args.family}")
    
    elif args.command == 'generate':
        # Create rule generator
        generator = RansomwareRuleGenerator(args.output_dir)
        
        if args.family:
            # Generate rule for specific family
            rule = generator.generate_rules_for_family(args.family)
            
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
                output_file = args.output_file or "ransomware_rules.yar"
                ruleset_path = generator.save_combined_ruleset(output_file)
                
                if ruleset_path:
                    print(f"Combined ruleset saved to: {ruleset_path}")
            else:
                print("No rules generated")
        else:
            print("No action specified. Use --family or --all")
    
    elif args.command == 'analyze-directory':
        # Create rule generator
        generator = RansomwareRuleGenerator(args.output_dir)
        
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
        rule = generator.generate_rules_for_family(args.family)
        
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