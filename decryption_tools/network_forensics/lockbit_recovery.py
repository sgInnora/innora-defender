#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LockBit Specialized Network-Based Recovery Module

This module extends the network-based recovery capabilities with specialized techniques
for detecting and extracting encryption keys from LockBit ransomware samples and network
traffic. It includes LockBit-specific patterns, structures, and decryption methods.

Key features:
- Specialized LockBit encryption key detection
- LockBit-specific file structure parsing
- Targeted decryption for LockBit encrypted files
"""

import os
import re
import json
import struct
import base64
import logging
import hashlib
import datetime
import binascii
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any, Union, BinaryIO

# Import base recovery components
try:
    from decryption_tools.network_forensics.network_based_recovery import NetworkKeyExtractor, NetworkBasedRecovery, ExtractedKey, DecryptionAttempt
    NETWORK_RECOVERY_AVAILABLE = True
except ImportError:
    NETWORK_RECOVERY_AVAILABLE = False
    print("Warning: NetworkBasedRecovery module could not be imported")

# Import cryptography modules if available
try:
    import cryptography
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("LockBitRecovery")


class LockBitFileFormat:
    """Parser for LockBit encrypted file formats"""
    
    def __init__(self, file_path: str):
        """
        Initialize with file path
        
        Args:
            file_path: Path to the encrypted file
        """
        self.file_path = os.path.abspath(file_path)
        self.file_name = os.path.basename(file_path)
        
        # File information
        self.file_size = 0
        self.header_data = b''
        self.encrypted_data = b''
        self.footer_data = b''
        
        # LockBit specific markers
        self.version = None
        self.has_uuid_extension = False
        self.uuid = None
        self.original_extension = None
        self.iv = None
        self.encrypted_key = None
        self.key_position = None
        
        # Parse the file if exists
        if os.path.exists(file_path):
            self.file_size = os.path.getsize(file_path)
            self._parse_file()
    
    def _parse_file(self):
        """Parse the LockBit encrypted file"""
        
        # Check for LockBit UUID extension
        if '.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}' in self.file_name:
            self.has_uuid_extension = True
            self.uuid = '1765FE8E-2103-66E3-7DCB-72284ABD03AA'
            
            # Extract original extension
            original_name = self.file_name.split('.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}')[0]
            self.original_extension = os.path.splitext(original_name)[1]
            
            # This is most likely LockBit 2.0
            self.version = "2.0"
        
        try:
            with open(self.file_path, 'rb') as f:
                # Read the entire file
                file_data = f.read()
                
                # LockBit 2.0 typically uses the first 16 bytes as IV
                if self.version == "2.0" and len(file_data) >= 16:
                    self.header_data = file_data[:16]
                    self.iv = self.header_data
                    
                    # The rest is the encrypted data, except potentially the encrypted key at the end
                    if len(file_data) > 256:
                        # Check if the last 256 bytes might contain the encrypted key
                        footer = file_data[-256:]
                        
                        # Calculate entropy of the footer
                        footer_entropy = self._calculate_entropy(footer)
                        
                        # Look for potential encrypted key markers
                        if b'KEY' in footer or footer_entropy < 7.0:
                            # This might be metadata including the encrypted key
                            self.footer_data = footer
                            self.encrypted_data = file_data[16:-256]
                            
                            # Try to extract the encrypted key
                            key_marker = footer.find(b'KEY')
                            if key_marker != -1:
                                # Key might be after the marker
                                potential_key = footer[key_marker+4:key_marker+260]
                                # Check if it looks like an encrypted key (high entropy)
                                if self._calculate_entropy(potential_key) > 6.5:
                                    self.encrypted_key = potential_key
                                    self.key_position = len(file_data) - 256 + key_marker + 4
                        else:
                            # No key in footer, all data after header is encrypted content
                            self.encrypted_data = file_data[16:]
                    else:
                        # Small file, all data after header is encrypted content
                        self.encrypted_data = file_data[16:]
                
                # If no version detected, try to infer from the data
                elif len(file_data) >= 16:
                    # Check first 16 bytes for LockBit 2.0 pattern (usually random IV)
                    potential_iv = file_data[:16]
                    iv_entropy = self._calculate_entropy(potential_iv)
                    
                    if 3.5 < iv_entropy < 6.0:  # IVs typically have medium-high entropy
                        # Likely LockBit 2.0 with IV at the start
                        self.version = "2.0"
                        self.header_data = potential_iv
                        self.iv = potential_iv
                        self.encrypted_data = file_data[16:]
                    else:
                        # Unknown format, treat everything as encrypted data
                        self.encrypted_data = file_data
        
        except Exception as e:
            logger.error(f"Error parsing LockBit file: {e}")
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        import math
        
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


class LockBitKeyExtractor(NetworkKeyExtractor):
    """Specialized key extractor for LockBit ransomware"""
    
    def __init__(self, pcap_file: Optional[str] = None):
        """
        Initialize the LockBit key extractor
        
        Args:
            pcap_file: Optional path to PCAP file to analyze
        """
        super().__init__(pcap_file)
        
        # Add LockBit-specific patterns to the existing patterns
        self.key_patterns['lockbit_aes'] = [
            # LockBit specific AES key patterns
            rb'\x00{4}[\x10\x18\x20][\x00-\xFF]{16,32}\x00{4}',  # AES key with size indicator
            rb'AES[_-]KEY[_=:]\s*([A-Za-z0-9+/=]{24,88})',  # AES key in base64
            rb'1765FE8E-2103-66E3-7DCB-72284ABD03AA.*?([A-Fa-f0-9]{32,64})',  # AES key near UUID
        ]
        
        # Add LockBit-specific C2 patterns
        if 'LockBit' not in self.c2_patterns:
            self.c2_patterns['LockBit'] = {
                b'1765FE8E-2103-66E3-7DCB-72284ABD03AA': 0.8,  # LockBit 2.0 UUID
                b'LockBit': 0.7,
                b'lock[A-Za-z0-9]+.bit': 0.7,
                b'lock[A-Za-z0-9]+.onion': 0.7,
                b'LOCKBIT': 0.7
            }
    
    def analyze_binary(self, binary_path: str) -> List[ExtractedKey]:
        """
        Analyze a binary file for LockBit encryption keys
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            List of extracted keys
        """
        extracted_keys = []
        
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
            
            # Look for the UUID pattern (strong indicator of LockBit 2.0)
            uuid_match = re.search(rb'1765FE8E-2103-66E3-7DCB-72284ABD03AA', data)
            if uuid_match:
                logger.info(f"Found LockBit 2.0 UUID marker in {binary_path}")
                
                # Search for AES keys around the UUID pattern
                uuid_pos = uuid_match.start()
                
                # Look 1KB before and after the UUID
                search_start = max(0, uuid_pos - 1024)
                search_end = min(len(data), uuid_pos + 1024)
                search_data = data[search_start:search_end]
                
                # Look for potential AES keys (high entropy, specific sizes)
                blocks = self._find_high_entropy_blocks(search_data, min_length=16, max_length=32)
                for block, entropy in blocks:
                    if 16 <= len(block) <= 32 and entropy > 6.5:
                        # This could be an AES key
                        # We need to create mock network parameters since this is from binary analysis
                        src_ip = "127.0.0.1"  # Local source
                        dst_ip = "127.0.0.1"  # Local destination
                        timestamp = datetime.datetime.now()
                        key_type = "aes-256" if len(block) == 32 else "aes-128"
                        
                        key = ExtractedKey(
                            key_data=block,
                            key_type=key_type,
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            timestamp=timestamp,
                            confidence=0.8,  # Higher confidence due to UUID proximity
                            context={
                                "source": "binary_analysis", 
                                "binary": os.path.basename(binary_path),
                                "uuid_proximity": abs(uuid_pos - (search_start + search_data.find(block)))
                            }
                        )
                        extracted_keys.append(key)
            
            # General analysis for all files
            if "PE32" in self._get_file_type(binary_path):
                # This is a PE file, look for encryption keys in typical locations
                
                # 1. Check for keys in .data section (common for ransomware)
                # This is a simplified approach; a real implementation would parse the PE structure
                
                # Look for high-entropy blocks of key sizes (16, 24, 32 bytes)
                blocks = self._find_high_entropy_blocks(data, min_length=16, max_length=32)
                for block, entropy in blocks:
                    if 16 <= len(block) <= 32 and entropy > 7.0:
                        key_type = "aes-256" if len(block) == 32 else ("aes-192" if len(block) == 24 else "aes-128")
                        src_ip = "127.0.0.1"
                        dst_ip = "127.0.0.1"
                        timestamp = datetime.datetime.now()
                        
                        confidence = 0.6  # Base confidence
                        
                        # Adjust confidence based on entropy
                        if entropy > 7.5:
                            confidence += 0.1
                        
                        # Adjust confidence if the block is aligned at 16-byte boundaries
                        # (common for cryptographic keys)
                        block_pos = data.find(block)
                        if block_pos % 16 == 0:
                            confidence += 0.1
                        
                        key = ExtractedKey(
                            key_data=block,
                            key_type=key_type,
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            timestamp=timestamp,
                            confidence=confidence,
                            context={
                                "source": "binary_analysis", 
                                "binary": os.path.basename(binary_path),
                                "position": block_pos
                            }
                        )
                        extracted_keys.append(key)
        
        except Exception as e:
            logger.error(f"Error analyzing binary for LockBit keys: {e}")
        
        return extracted_keys
    
    def _get_file_type(self, file_path: str) -> str:
        """Get the file type of a file"""
        try:
            import subprocess
            proc = subprocess.run(['file', '-b', file_path], 
                                  capture_output=True, check=False)
            return proc.stdout.decode('utf-8', errors='ignore').strip()
        except:
            # Fallback to extension-based type detection
            ext = os.path.splitext(file_path)[1].lower()
            if ext == '.exe':
                return "PE32 executable"
            elif ext == '.dll':
                return "PE32 DLL"
            else:
                return "Unknown"


class LockBitRecovery(NetworkBasedRecovery):
    """Specialized recovery for LockBit encrypted files"""
    
    def __init__(self, keys: Optional[List[ExtractedKey]] = None):
        """
        Initialize the recovery module
        
        Args:
            keys: Optional list of ExtractedKey objects
        """
        super().__init__(keys)
        self.logger = logger
    
    def analyze_sample(self, sample_path: str) -> List[ExtractedKey]:
        """
        Analyze a LockBit sample to extract encryption keys
        
        Args:
            sample_path: Path to the ransomware sample
            
        Returns:
            List of extracted keys
        """
        if not NETWORK_RECOVERY_AVAILABLE:
            logger.error("NetworkBasedRecovery module not available")
            return []
        
        # Create LockBit key extractor
        extractor = LockBitKeyExtractor()
        
        # Analyze the binary
        keys = extractor.analyze_binary(sample_path)
        
        # Add the keys to our collection
        self.add_keys(keys)
        
        logger.info(f"Extracted {len(keys)} potential encryption keys from {sample_path}")
        return keys
    
    def decrypt_file(self, encrypted_file: str, output_file: Optional[str] = None) -> bool:
        """
        Attempt to decrypt a LockBit encrypted file
        
        Args:
            encrypted_file: Path to the encrypted file
            output_file: Optional path to save decrypted file
            
        Returns:
            True if decryption was successful, False otherwise
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            logger.error("Cryptography library not available, decryption not possible")
            return False
        
        if not os.path.exists(encrypted_file):
            logger.error(f"Encrypted file not found: {encrypted_file}")
            return False
        
        # Set default output path if not provided
        if not output_file:
            output_dir = os.path.dirname(encrypted_file)
            file_name = os.path.basename(encrypted_file)
            
            # Remove LockBit extension if present
            if '.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}' in file_name:
                file_name = file_name.split('.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}')[0]
            
            output_file = os.path.join(output_dir, f"decrypted_{file_name}")
        
        # Parse the encrypted file
        parser = LockBitFileFormat(encrypted_file)
        
        # Check if we detected a LockBit format
        if parser.version:
            logger.info(f"Detected LockBit {parser.version} encrypted file")
            
            # Try to decrypt using the detected format
            if parser.version == "2.0":
                return self._decrypt_lockbit_2_file(parser, output_file)
            else:
                logger.warning(f"Unsupported LockBit version: {parser.version}")
                return False
        else:
            logger.warning("Could not determine LockBit version, trying generic decryption")
            
            # Fall back to the parent class method for generic approach
            attempts = super().attempt_decryption(encrypted_file, output_file)
            
            # Check if any of the attempts were successful
            for attempt in attempts:
                if attempt.success:
                    return True
            
            return False
    
    def _decrypt_lockbit_2_file(self, parser: LockBitFileFormat, output_file: str) -> bool:
        """
        Decrypt a LockBit 2.0 encrypted file
        
        Args:
            parser: LockBitFileFormat parser with file details
            output_file: Path to save decrypted file
            
        Returns:
            True if decryption was successful, False otherwise
        """
        # We need to try each potential key
        for key in sorted(self.keys, key=lambda k: k.confidence, reverse=True):
            try:
                # Use AES-CBC with the file's IV if available
                iv = parser.iv if parser.iv else b'\0' * 16
                
                # Ensure the key is the right length
                key_data = key.key_data
                if len(key_data) not in [16, 24, 32]:
                    # Adjust key length
                    if len(key_data) < 16:
                        key_data = key_data.ljust(16, b'\0')
                    elif 16 < len(key_data) < 24:
                        key_data = key_data[:16]
                    elif 24 < len(key_data) < 32:
                        key_data = key_data[:24]
                    elif len(key_data) > 32:
                        key_data = key_data[:32]
                
                # Create AES cipher
                algorithm = algorithms.AES(key_data)
                cipher = Cipher(algorithm, modes.CBC(iv))
                decryptor = cipher.decryptor()
                
                # Decrypt
                decrypted = decryptor.update(parser.encrypted_data) + decryptor.finalize()
                
                # Handle padding
                try:
                    # Try to remove PKCS7 padding
                    padding_size = decrypted[-1]
                    if 1 <= padding_size <= 16:
                        # Check if valid PKCS7 padding
                        if all(b == padding_size for b in decrypted[-padding_size:]):
                            decrypted = decrypted[:-padding_size]
                except:
                    pass  # Use unpadded data
                
                # Check if decryption looks valid
                if self._is_valid_decryption(decrypted):
                    logger.info(f"Successfully decrypted with key {key.key_id}")
                    
                    # Save the decrypted file
                    with open(output_file, 'wb') as f:
                        f.write(decrypted)
                    
                    return True
                
            except Exception as e:
                logger.debug(f"Error decrypting with key {key.key_id}: {e}")
        
        logger.info("All decryption attempts failed")
        return False
    
    def _is_valid_decryption(self, decrypted_data: bytes) -> bool:
        """
        Check if decrypted data looks valid
        
        Args:
            decrypted_data: Decrypted data
            
        Returns:
            True if decryption appears valid, False otherwise
        """
        # Implement more sophisticated checks for decrypted data
        
        # Check for common file signatures
        signatures = {
            b'PK\x03\x04': ['zip', 'docx', 'xlsx', 'pptx'],
            b'%PDF': ['pdf'],
            b'\xFF\xD8\xFF': ['jpg', 'jpeg'],
            b'\x89PNG': ['png'],
            b'GIF8': ['gif'],
            b'II*\x00': ['tif', 'tiff'],
            b'MM\x00*': ['tif', 'tiff'],
            b'\x50\x4B\x03\x04': ['zip', 'jar'],
            b'<!DOC': ['html', 'xml'],
            b'<html': ['html'],
            b'{\r\n': ['json'],
            b'{\n': ['json'],
            b'#!': ['sh', 'bash'],
            b'using': ['cs'],
            b'import': ['py', 'java'],
            b'public': ['java', 'cs'],
            b'package': ['java', 'go'],
            b'function': ['js', 'php'],
            b'class': ['py', 'php', 'java'],
            b'<?xml': ['xml'],
            b'<!DOCTYPE': ['html', 'xml'],
            b'SQLite': ['db', 'sqlite'],
            b'MZ': ['exe', 'dll']
        }
        
        if len(decrypted_data) < 4:
            return False
        
        for sig, extensions in signatures.items():
            if decrypted_data.startswith(sig):
                return True
        
        # Check for text files (ASCII/UTF-8)
        try:
            # Try to decode as UTF-8
            text = decrypted_data[:1000].decode('utf-8', errors='strict')
            
            # Check if it looks like text (high ratio of printable characters)
            printable_count = sum(1 for c in text if c.isprintable())
            if printable_count / len(text) > 0.9:
                return True
        except:
            pass
        
        # Check entropy - decrypted data should have lower entropy than encrypted data
        entropy = self._calculate_entropy(decrypted_data[:1000])
        if entropy < 6.5:  # Most encrypted data has entropy > 7.0
            return True
        
        # Check for common binary file types by checking for NUL bytes distribution
        nul_count = decrypted_data.count(b'\x00')
        if 0.05 < nul_count / len(decrypted_data) < 0.3:
            # This is a typical range for many binary formats
            return True
        
        # Default to false if no validations passed
        return False
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        import math
        
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


# Main execution
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="LockBit Ransomware Recovery Tool")
    parser.add_argument("--sample", help="LockBit sample to analyze for keys")
    parser.add_argument("--encrypted", help="Encrypted file to decrypt")
    parser.add_argument("--output", help="Output file for decrypted data")
    args = parser.parse_args()
    
    # Check if the required modules are available
    if not NETWORK_RECOVERY_AVAILABLE:
        print("ERROR: Required modules not available")
        exit(1)
    
    # Initialize recovery module
    recovery = LockBitRecovery()
    
    # Analyze sample if provided
    if args.sample:
        print(f"Analyzing LockBit sample: {args.sample}")
        keys = recovery.analyze_sample(args.sample)
        print(f"Extracted {len(keys)} potential encryption keys")
    
    # Decrypt file if provided
    if args.encrypted:
        if not args.sample:
            print("WARNING: No sample provided for key extraction")
        
        print(f"Attempting to decrypt: {args.encrypted}")
        success = recovery.decrypt_file(args.encrypted, args.output)
        
        if success:
            output = args.output if args.output else f"decrypted_{os.path.basename(args.encrypted)}"
            print(f"Successfully decrypted to: {output}")
        else:
            print("Decryption failed")