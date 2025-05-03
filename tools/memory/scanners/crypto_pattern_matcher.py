#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cryptographic Pattern Matcher for Ransomware Analysis

This module focuses on detecting cryptographic function artifacts and
ransomware-specific patterns in memory dumps. It is specialized in
identifying in-memory structures used by ransomware families during
the encryption process.
"""

import os
import sys
import logging
import json
import struct
import argparse
import binascii
import re
import math
import hashlib
from typing import List, Dict, Tuple, Optional, BinaryIO, Generator, Any, Union
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('CryptoPatternMatcher')

# Constants
CHUNK_SIZE = 10 * 1024 * 1024  # 10 MB default chunk size

class RansomwareSignature:
    """
    Container class for a ransomware signature pattern.
    Includes information about the pattern, related family, and validation functions.
    """
    def __init__(self, name: str, family: str, pattern: Union[bytes, re.Pattern],
                 description: str, confidence: float, validator: Optional[callable] = None):
        """
        Initialize a ransomware signature.
        
        Args:
            name: Name of the signature
            family: Ransomware family
            pattern: Byte pattern or regex pattern to match
            description: Description of what this signature detects
            confidence: Base confidence level when matched (0.0-1.0)
            validator: Optional function to validate matches
        """
        self.name = name
        self.family = family
        self.pattern = pattern
        self.description = description
        self.confidence = confidence
        self.validator = validator
    
    def __str__(self) -> str:
        return f"{self.name} ({self.family}): {self.description}"

class CryptoPatternMatcher:
    """
    Specialized matcher for cryptographic patterns in memory, with focus
    on ransomware encryption routines and in-memory structures.
    """
    
    def __init__(self, chunk_size: int = CHUNK_SIZE):
        """
        Initialize the matcher with configurable parameters.
        
        Args:
            chunk_size: Size of chunks to process for large files
        """
        self.chunk_size = chunk_size
        self.results = []
        self.signatures = self._load_signatures()
        self.crypto_constants = self._load_crypto_constants()
        
    def _load_signatures(self) -> List[RansomwareSignature]:
        """
        Load ransomware signatures.
        
        Returns:
            List of RansomwareSignature objects
        """
        signatures = []
        
        # === WannaCry signatures ===
        # WannaCry process name pattern
        signatures.append(RansomwareSignature(
            name="WannaCry_Process",
            family="WannaCry",
            pattern=re.compile(b"tasksche\\.exe|wcry\\.exe|wana.*cry", re.IGNORECASE),
            description="WannaCry ransomware process name",
            confidence=0.75
        ))
        
        # WannaCry RSA encryption pattern
        signatures.append(RansomwareSignature(
            name="WannaCry_RSA",
            family="WannaCry",
            pattern=b"WanaCrypt0r",
            description="WannaCry ransomware RSA-related string",
            confidence=0.85
        ))
        
        # WannaCry file marker
        signatures.append(RansomwareSignature(
            name="WannaCry_Marker",
            family="WannaCry",
            pattern=b"WANACRY!",
            description="WannaCry file marker",
            confidence=0.9
        ))
        
        # === REvil/Sodinokibi signatures ===
        # REvil config pattern
        signatures.append(RansomwareSignature(
            name="REvil_Config",
            family="REvil",
            pattern=b"{\"pk\":\"",
            description="REvil ransomware configuration pattern",
            confidence=0.8,
            validator=self._validate_revil_config
        ))
        
        # REvil ransom note marker
        signatures.append(RansomwareSignature(
            name="REvil_Note",
            family="REvil",
            pattern=re.compile(b"!!!.+readme.+!!!", re.IGNORECASE),
            description="REvil ransom note marker",
            confidence=0.75
        ))
        
        # === Ryuk signatures ===
        # Ryuk marker
        signatures.append(RansomwareSignature(
            name="Ryuk_Marker",
            family="Ryuk",
            pattern=b"RyukReadMe",
            description="Ryuk ransomware marker",
            confidence=0.9
        ))
        
        # Ryuk key blob marker
        signatures.append(RansomwareSignature(
            name="Ryuk_KeyBlob",
            family="Ryuk",
            pattern=b"HERMES",
            description="Ryuk/Hermes key blob marker",
            confidence=0.85
        ))
        
        # === LockBit signatures ===
        # LockBit 2.0 marker
        signatures.append(RansomwareSignature(
            name="LockBit_2.0_Marker",
            family="LockBit",
            pattern=re.compile(b"LockBit 2\\.0", re.IGNORECASE),
            description="LockBit 2.0 ransomware marker",
            confidence=0.9
        ))
        
        # LockBit 3.0 marker (Black)
        signatures.append(RansomwareSignature(
            name="LockBit_3.0_Marker",
            family="LockBit",
            pattern=re.compile(b"LockBit 3\\.0|LockBit Black", re.IGNORECASE),
            description="LockBit 3.0 ransomware marker",
            confidence=0.9
        ))
        
        # === BlackCat/ALPHV signatures ===
        # BlackCat config pattern
        signatures.append(RansomwareSignature(
            name="BlackCat_Config",
            family="BlackCat",
            pattern=b"BlackCat",
            description="BlackCat ransomware marker",
            confidence=0.75
        ))
        
        # BlackCat note marker
        signatures.append(RansomwareSignature(
            name="BlackCat_Note",
            family="BlackCat",
            pattern=re.compile(b"RECOVER-[A-Za-z0-9]{5}-FILES\\.txt", re.IGNORECASE),
            description="BlackCat ransom note pattern",
            confidence=0.85
        ))
        
        # === Conti signatures ===
        # Conti marker
        signatures.append(RansomwareSignature(
            name="Conti_Marker",
            family="Conti",
            pattern=b"CONTI",
            description="Conti ransomware marker",
            confidence=0.8
        ))
        
        # Conti config pattern
        signatures.append(RansomwareSignature(
            name="Conti_Config",
            family="Conti",
            pattern=re.compile(b"pubkey\\s*:\\s*[A-Za-z0-9+/=]{20,}", re.IGNORECASE),
            description="Conti ransomware config pattern",
            confidence=0.85
        ))
        
        # === Black Basta signatures ===
        # Black Basta marker
        signatures.append(RansomwareSignature(
            name="BlackBasta_Marker",
            family="BlackBasta",
            pattern=b"BLACK BASTA",
            description="Black Basta ransomware marker",
            confidence=0.9
        ))
        
        # === Hive signatures ===
        # Hive marker
        signatures.append(RansomwareSignature(
            name="Hive_Marker",
            family="Hive",
            pattern=re.compile(b"YouR nETwOrk iS eNcrYPteD bY HIVE", re.IGNORECASE),
            description="Hive ransomware marker",
            confidence=0.9
        ))
        
        # Hive key pattern
        signatures.append(RansomwareSignature(
            name="Hive_Key",
            family="Hive",
            pattern=re.compile(b"encr_(rsa|aes)_key", re.IGNORECASE),
            description="Hive ransomware key pattern",
            confidence=0.85
        ))
        
        # === AvosLocker signatures ===
        # AvosLocker marker
        signatures.append(RansomwareSignature(
            name="AvosLocker_Marker",
            family="AvosLocker",
            pattern=b"AvosLocker",
            description="AvosLocker ransomware marker",
            confidence=0.9
        ))
        
        # === Vice Society signatures ===
        # Vice Society marker
        signatures.append(RansomwareSignature(
            name="ViceSociety_Marker",
            family="ViceSociety",
            pattern=re.compile(b"vice\\s+society", re.IGNORECASE),
            description="Vice Society ransomware marker",
            confidence=0.8
        ))
        
        # === Cl0p signatures ===
        # Cl0p marker
        signatures.append(RansomwareSignature(
            name="Cl0p_Marker",
            family="Clop",
            pattern=re.compile(b"Cl0p", re.IGNORECASE),
            description="Cl0p ransomware marker",
            confidence=0.85
        ))
        
        # === Generic ransomware detection ===
        # Encrypted file headers
        signatures.append(RansomwareSignature(
            name="Encrypted_File_Header",
            family="Generic",
            pattern=re.compile(b"ENCRYPTED_FILE|BEGIN_ENCRYPTION", re.IGNORECASE),
            description="Generic encrypted file header marker",
            confidence=0.7
        ))
        
        # Common ransom note patterns
        signatures.append(RansomwareSignature(
            name="Ransom_Note",
            family="Generic",
            pattern=re.compile(b"your files (have been|are) encrypted|how to decrypt|bitcoin|decryption key|payment", re.IGNORECASE),
            description="Generic ransom note text",
            confidence=0.6
        ))
        
        return signatures
    
    def _load_crypto_constants(self) -> List[Dict[str, Any]]:
        """
        Load cryptographic constants to detect.
        
        Returns:
            List of crypto constant definitions
        """
        constants = []
        
        # AES S-Box
        constants.append({
            "name": "AES_SBOX",
            "description": "AES S-Box lookup table",
            "type": "table",
            "pattern": bytes([
                0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                # Partial match is fine - first 48 bytes are distinctive enough
            ]),
            "confidence": 0.85,
            "algorithm": "AES"
        })
        
        # AES round constants
        constants.append({
            "name": "AES_RCON",
            "description": "AES round constants",
            "type": "table",
            "pattern": bytes([
                0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
            ]),
            "confidence": 0.75,
            "algorithm": "AES"
        })
        
        # ChaCha20 constants
        constants.append({
            "name": "CHACHA20_CONSTANTS",
            "description": "ChaCha20 'expand 32-byte k' constant",
            "type": "constant",
            "pattern": b"expand 32-byte k",
            "confidence": 0.9,
            "algorithm": "ChaCha20"
        })
        
        # Salsa20 constants
        constants.append({
            "name": "SALSA20_CONSTANTS",
            "description": "Salsa20 'expand 32-byte k' constant",
            "type": "constant",
            "pattern": b"expand 32-byte k",
            "confidence": 0.9,
            "algorithm": "Salsa20"
        })
        
        # RC4 PRGA pattern (256-byte state table patterns)
        constants.append({
            "name": "RC4_STATE",
            "description": "RC4 encryption state array pattern",
            "type": "function",
            "pattern": re.compile(
                b"(?:[\x00-\xFF]{16}[\x00-\xFF]{16}[\x00-\xFF]{16}[\x00-\xFF]{16}){16}", 
                re.DOTALL
            ),
            "validator": self._validate_rc4_state,
            "confidence": 0.7,
            "algorithm": "RC4"
        })
        
        # DES S-Box pattern (partial)
        constants.append({
            "name": "DES_SBOX",
            "description": "DES S-Box constants",
            "type": "table",
            "pattern": bytes([
                0x0e, 0x04, 0x0d, 0x01, 0x02, 0x0f, 0x0b, 0x08, 0x03, 0x0a, 0x06, 0x0c, 0x05, 0x09, 0x00, 0x07,
                0x00, 0x0f, 0x07, 0x04, 0x0e, 0x02, 0x0d, 0x01, 0x0a, 0x06, 0x0c, 0x0b, 0x09, 0x05, 0x03, 0x08
            ]),
            "confidence": 0.7,
            "algorithm": "DES"
        })
        
        # RSA public exponent (65537 / 0x010001)
        constants.append({
            "name": "RSA_PUBLIC_EXPONENT",
            "description": "Common RSA public exponent (65537)",
            "type": "constant",
            "pattern": b"\x01\x00\x01",
            "confidence": 0.5,  # Low confidence as it's a common value
            "algorithm": "RSA"
        })
        
        # SHA-256 initial hash values
        constants.append({
            "name": "SHA256_INIT",
            "description": "SHA-256 initial hash values",
            "type": "table",
            "pattern": bytes([
                0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
                0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19
            ]),
            "confidence": 0.85,
            "algorithm": "SHA256"
        })
        
        return constants
        
    def _validate_revil_config(self, data: bytes, offset: int) -> bool:
        """
        Validate a potential REvil configuration structure.
        
        Args:
            data: Data containing potential REvil config
            offset: Offset of the pattern match
            
        Returns:
            True if valid, False otherwise
        """
        try:
            # Start from the match and look for a valid JSON structure
            max_config_size = 2048  # Maximum expected config size
            end_offset = min(offset + max_config_size, len(data))
            config_data = data[offset:end_offset]
            
            # Find the closing brace for the JSON object
            for i in range(20, len(config_data)):
                if config_data[i] == ord('}'):
                    try:
                        potential_config = config_data[:i+1].decode('utf-8')
                        # Try to parse as JSON
                        config = json.loads(potential_config)
                        # Check for REvil specific keys
                        if 'pk' in config and ('pid' in config or 'sub' in config):
                            return True
                    except:
                        pass
            
            return False
        except Exception:
            return False
    
    def _validate_rc4_state(self, data: bytes, offset: int) -> float:
        """
        Validate a potential RC4 state table (256-byte array).
        Check if it contains a permutation of 0-255.
        
        Args:
            data: Data containing potential RC4 state
            offset: Offset of the pattern match
            
        Returns:
            Confidence score between 0 and 1
        """
        try:
            state_data = data[offset:offset+256]
            if len(state_data) != 256:
                return 0.0
                
            # Check if all values 0-255 are present
            value_set = set(state_data)
            if len(value_set) < 200:  # We expect close to 256 unique values
                return 0.0
                
            # RC4 state should be a permutation of 0-255
            # During operation, it might be in any state, but we can check
            # certain statistical properties
            
            # Correlation with a pristine RC4 state (0...255)
            pristine_state = bytes(range(256))
            correlation = sum(1 for a, b in zip(state_data, pristine_state) if abs(a - b) < 20)
            
            if correlation > 50:
                return 0.8  # High confidence if there's some correlation
            elif len(value_set) > 250:
                return 0.6  # Medium confidence if almost all values 0-255 present
            else:
                return 0.3  # Low confidence otherwise
        except Exception:
            return 0.0
    
    def _find_crypto_constants(self, data: bytes, offset: int) -> List[Dict[str, Any]]:
        """
        Find cryptographic constants in memory.
        
        Args:
            data: Memory data to scan
            offset: Base offset of this data chunk
            
        Returns:
            List of findings
        """
        findings = []
        
        for constant in self.crypto_constants:
            pattern = constant["pattern"]
            
            # Different handling for regex vs. byte patterns
            if isinstance(pattern, re.Pattern):
                for match in pattern.finditer(data):
                    match_offset = offset + match.start()
                    
                    # Check if there's a validator function
                    confidence = constant["confidence"]
                    if "validator" in constant and callable(constant["validator"]):
                        validation_result = constant["validator"](data, match.start())
                        if isinstance(validation_result, bool):
                            if not validation_result:
                                continue  # Skip this match if validation failed
                        elif isinstance(validation_result, float):
                            confidence = validation_result
                    
                    finding = {
                        "type": "crypto_constant",
                        "name": constant["name"],
                        "description": constant["description"],
                        "algorithm": constant.get("algorithm", "unknown"),
                        "offset": match_offset,
                        "size": match.end() - match.start(),
                        "constant_type": constant["type"],
                        "confidence": confidence
                    }
                    findings.append(finding)
            else:
                # Byte pattern
                pos = 0
                while True:
                    pos = data.find(pattern, pos)
                    if pos == -1:
                        break
                        
                    match_offset = offset + pos
                    
                    # Check if there's a validator function
                    confidence = constant["confidence"]
                    if "validator" in constant and callable(constant["validator"]):
                        validation_result = constant["validator"](data, pos)
                        if isinstance(validation_result, bool):
                            if not validation_result:
                                continue  # Skip this match if validation failed
                        elif isinstance(validation_result, float):
                            confidence = validation_result
                    
                    finding = {
                        "type": "crypto_constant",
                        "name": constant["name"],
                        "description": constant["description"],
                        "algorithm": constant.get("algorithm", "unknown"),
                        "offset": match_offset,
                        "size": len(pattern),
                        "constant_type": constant["type"],
                        "confidence": confidence
                    }
                    findings.append(finding)
                    
                    pos += len(pattern)  # Move past this match
        
        return findings
    
    def _find_ransomware_patterns(self, data: bytes, offset: int) -> List[Dict[str, Any]]:
        """
        Find ransomware-specific patterns in memory.
        
        Args:
            data: Memory data to scan
            offset: Base offset of this data chunk
            
        Returns:
            List of findings
        """
        findings = []
        
        for signature in self.signatures:
            pattern = signature.pattern
            
            # Different handling for regex vs. byte patterns
            if isinstance(pattern, re.Pattern):
                for match in pattern.finditer(data):
                    match_offset = offset + match.start()
                    
                    # Check if there's a validator function
                    if signature.validator and not signature.validator(data, match.start()):
                        continue  # Skip this match if validation failed
                    
                    finding = {
                        "type": "ransomware_pattern",
                        "name": signature.name,
                        "family": signature.family,
                        "description": signature.description,
                        "offset": match_offset,
                        "size": match.end() - match.start(),
                        "sample": binascii.hexlify(data[match.start():match.end()]).decode('utf-8'),
                        "confidence": signature.confidence
                    }
                    findings.append(finding)
            else:
                # Byte pattern
                pos = 0
                while True:
                    pos = data.find(pattern, pos)
                    if pos == -1:
                        break
                        
                    match_offset = offset + pos
                    
                    # Check if there's a validator function
                    if signature.validator and not signature.validator(data, pos):
                        pos += 1
                        continue  # Skip this match if validation failed
                    
                    # Extract some context around the match
                    context_start = max(0, pos - 20)
                    context_end = min(len(data), pos + len(pattern) + 20)
                    context = data[context_start:context_end]
                    
                    finding = {
                        "type": "ransomware_pattern",
                        "name": signature.name,
                        "family": signature.family,
                        "description": signature.description,
                        "offset": match_offset,
                        "size": len(pattern),
                        "sample": binascii.hexlify(pattern).decode('utf-8'),
                        "context": binascii.hexlify(context).decode('utf-8'),
                        "confidence": signature.confidence
                    }
                    findings.append(finding)
                    
                    pos += len(pattern)  # Move past this match
        
        return findings
    
    def _find_file_format_markers(self, data: bytes, offset: int) -> List[Dict[str, Any]]:
        """
        Find encrypted file format markers in memory.
        These can indicate ransomware has encrypted files with specific headers.
        
        Args:
            data: Memory data to scan
            offset: Base offset of this data chunk
            
        Returns:
            List of findings
        """
        findings = []
        
        # Common ransomware encrypted file headers
        # Many ransomware variants add custom headers to encrypted files
        encrypted_file_headers = [
            (b"WNCRY", "WannaCry"),
            (b"LOCK", "LockBit"),
            (b"HERMES", "Ryuk"),
            (b"CONTI", "Conti"),
            (b"DPCS", "DarkSide"),
            (b"RYK", "Ryuk"),
            (b"REVIL", "REvil"),
            (b"CLOP", "Clop"),
            (b"KRAB", "GandCrab"),
            (b"NEPHILIM", "Nephilim"),
            (b"HELLO", "Hello"),
        ]
        
        for header, family in encrypted_file_headers:
            pos = 0
            while True:
                pos = data.find(header, pos)
                if pos == -1:
                    break
                    
                match_offset = offset + pos
                
                # Extract context around the match
                context_start = max(0, pos - 16)
                context_end = min(len(data), pos + len(header) + 48)
                context = data[context_start:context_end]
                
                finding = {
                    "type": "encrypted_file_header",
                    "family": family,
                    "description": f"{family} encrypted file header marker",
                    "offset": match_offset,
                    "size": len(header),
                    "marker": binascii.hexlify(header).decode('utf-8'),
                    "context": binascii.hexlify(context).decode('utf-8'),
                    "confidence": 0.85
                }
                findings.append(finding)
                
                pos += len(header)  # Move past this match
                
        return findings
        
    def _find_potential_filenames(self, data: bytes, offset: int) -> List[Dict[str, Any]]:
        """
        Find potential encrypted filenames in memory that may indicate
        ransomware operation.
        
        Args:
            data: Memory data to scan
            offset: Base offset of this data chunk
            
        Returns:
            List of findings
        """
        findings = []
        
        # Common ransomware filename patterns
        patterns = [
            (re.compile(b"[A-Za-z0-9_-]+\\.(encrypted|enc|locked|crypted|crypt|cry|lock|WNCRY)", re.IGNORECASE),
             "Encrypted file extension"),
            (re.compile(b"READ[ _]?ME.*\\.(txt|html|hta)", re.IGNORECASE),
             "Ransom note filename"),
            (re.compile(b"RECOVER[ _]?FILES.*\\.(txt|html|hta)", re.IGNORECASE),
             "Ransom recovery instructions"),
            (re.compile(b"HOW[ _]?TO[ _]?(DECRYPT|RECOVERY).*\\.(txt|html|hta)", re.IGNORECASE),
             "Ransom recovery instructions"),
            (re.compile(b"YOUR[ _]?FILES[ _]?ARE[ _]?ENCRYPTED.*\\.(txt|html|hta)", re.IGNORECASE),
             "Ransom note filename"),
        ]
        
        for pattern, description in patterns:
            for match in pattern.finditer(data):
                match_offset = offset + match.start()
                filename = data[match.start():match.end()].decode('utf-8', errors='replace')
                
                finding = {
                    "type": "suspicious_filename",
                    "description": description,
                    "filename": filename,
                    "offset": match_offset,
                    "size": match.end() - match.start(),
                    "confidence": 0.7
                }
                findings.append(finding)
        
        return findings
        
    def _find_api_calls(self, data: bytes, offset: int) -> List[Dict[str, Any]]:
        """
        Find potential cryptographic API calls in memory.
        
        Args:
            data: Memory data to scan
            offset: Base offset of this data chunk
            
        Returns:
            List of findings
        """
        findings = []
        
        # Common crypto API function names
        api_patterns = [
            (re.compile(b"CryptEncrypt", re.IGNORECASE), "Windows CryptoAPI", 0.7),
            (re.compile(b"CryptDecrypt", re.IGNORECASE), "Windows CryptoAPI", 0.7),
            (re.compile(b"CryptCreateHash", re.IGNORECASE), "Windows CryptoAPI", 0.6),
            (re.compile(b"CryptDeriveKey", re.IGNORECASE), "Windows CryptoAPI", 0.7),
            (re.compile(b"BCryptEncrypt", re.IGNORECASE), "Windows CNG API", 0.75),
            (re.compile(b"BCryptDecrypt", re.IGNORECASE), "Windows CNG API", 0.75),
            (re.compile(b"EncryptFile", re.IGNORECASE), "Windows API", 0.8),
            (re.compile(b"EVP_EncryptInit", re.IGNORECASE), "OpenSSL", 0.75),
            (re.compile(b"EVP_DecryptInit", re.IGNORECASE), "OpenSSL", 0.75),
            (re.compile(b"RSA_public_encrypt", re.IGNORECASE), "OpenSSL", 0.8),
            (re.compile(b"AES_encrypt", re.IGNORECASE), "OpenSSL", 0.7),
            (re.compile(b"CC_AES_encrypt", re.IGNORECASE), "CommonCrypto", 0.7),
            (re.compile(b"CCCrypt", re.IGNORECASE), "CommonCrypto", 0.6),
            (re.compile(b"mbedtls_aes_crypt", re.IGNORECASE), "MbedTLS", 0.7),
            (re.compile(b"mbedtls_rsa_pkcs1_encrypt", re.IGNORECASE), "MbedTLS", 0.8),
            (re.compile(b"RAND_bytes", re.IGNORECASE), "OpenSSL", 0.5),
        ]
        
        for pattern, library, confidence in api_patterns:
            for match in pattern.finditer(data):
                match_offset = offset + match.start()
                api_name = data[match.start():match.end()].decode('utf-8', errors='replace')
                
                finding = {
                    "type": "crypto_api",
                    "description": f"Cryptographic API function: {api_name}",
                    "api_name": api_name,
                    "library": library,
                    "offset": match_offset,
                    "size": match.end() - match.start(),
                    "confidence": confidence
                }
                findings.append(finding)
        
        return findings
    
    def scan_chunk(self, data: bytes, offset: int) -> List[Dict[str, Any]]:
        """
        Scan a chunk of memory for all pattern types.
        
        Args:
            data: Memory chunk to scan
            offset: Base offset of this data chunk
            
        Returns:
            List of findings
        """
        findings = []
        
        # Find cryptographic constants
        crypto_findings = self._find_crypto_constants(data, offset)
        findings.extend(crypto_findings)
        
        # Find ransomware-specific patterns
        ransomware_findings = self._find_ransomware_patterns(data, offset)
        findings.extend(ransomware_findings)
        
        # Find encrypted file format markers
        file_format_findings = self._find_file_format_markers(data, offset)
        findings.extend(file_format_findings)
        
        # Find potential filenames
        filename_findings = self._find_potential_filenames(data, offset)
        findings.extend(filename_findings)
        
        # Find API calls
        api_findings = self._find_api_calls(data, offset)
        findings.extend(api_findings)
        
        return findings
    
    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Scan a memory dump file for cryptographic and ransomware patterns.
        
        Args:
            file_path: Path to the memory dump file
            
        Returns:
            List of findings
        """
        self.results = []
        
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return self.results
            
        file_size = os.path.getsize(file_path)
        logger.info(f"Scanning file: {file_path} ({file_size/1024/1024:.2f} MB)")
        
        try:
            with open(file_path, 'rb') as f:
                offset = 0
                while offset < file_size:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                        
                    # Process this chunk
                    chunk_findings = self.scan_chunk(chunk, offset)
                    
                    # Add findings to global results
                    self.results.extend(chunk_findings)
                    
                    offset += len(chunk)
                    logger.info(f"Progress: {offset/file_size*100:.1f}% ({offset/1024/1024:.2f} MB)")
        
        except Exception as e:
            logger.error(f"Error scanning file: {e}")
            
        # Sort results by confidence
        self.results.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        
        # Group similar findings
        self._group_similar_findings()
        
        return self.results
    
    def _group_similar_findings(self, distance_threshold: int = 64) -> None:
        """
        Group similar findings that are close to each other in memory.
        Updates self.results in place.
        
        Args:
            distance_threshold: Maximum distance between findings to be considered related
        """
        if not self.results:
            return
            
        # Sort by offset
        self.results.sort(key=lambda x: x.get("offset", 0))
        
        grouped_results = []
        current_group = [self.results[0]]
        current_type = self.results[0].get("type")
        last_offset = self.results[0].get("offset", 0)
        
        for finding in self.results[1:]:
            offset = finding.get("offset", 0)
            finding_type = finding.get("type")
            
            # If this finding is close to the previous one and of the same type, group them
            if (offset - last_offset <= distance_threshold and finding_type == current_type):
                current_group.append(finding)
            else:
                # Process the completed group
                if len(current_group) > 1:
                    # Create a group finding
                    group_finding = {
                        "type": current_group[0].get("type") + "_group",
                        "description": f"Group of {len(current_group)} related findings",
                        "count": len(current_group),
                        "start_offset": current_group[0].get("offset"),
                        "end_offset": current_group[-1].get("offset") + current_group[-1].get("size", 0),
                        "size": (current_group[-1].get("offset") + current_group[-1].get("size", 0)) - current_group[0].get("offset"),
                        "findings": current_group,
                        # Use highest confidence in the group
                        "confidence": max(f.get("confidence", 0) for f in current_group)
                    }
                    grouped_results.append(group_finding)
                else:
                    # Add the single finding
                    grouped_results.append(current_group[0])
                
                # Start a new group
                current_group = [finding]
                current_type = finding_type
            
            last_offset = offset
        
        # Handle the last group
        if len(current_group) > 1:
            group_finding = {
                "type": current_group[0].get("type") + "_group",
                "description": f"Group of {len(current_group)} related findings",
                "count": len(current_group),
                "start_offset": current_group[0].get("offset"),
                "end_offset": current_group[-1].get("offset") + current_group[-1].get("size", 0),
                "size": (current_group[-1].get("offset") + current_group[-1].get("size", 0)) - current_group[0].get("offset"),
                "findings": current_group,
                "confidence": max(f.get("confidence", 0) for f in current_group)
            }
            grouped_results.append(group_finding)
        elif current_group:
            grouped_results.append(current_group[0])
        
        # Replace original results with grouped ones
        self.results = grouped_results
    
    def scan_range_in_file(self, file_path: str, start_offset: int, size: int) -> List[Dict[str, Any]]:
        """
        Scan a specific range in a file.
        
        Args:
            file_path: Path to the memory dump file
            start_offset: Starting offset to scan from
            size: Number of bytes to scan
            
        Returns:
            List of findings
        """
        self.results = []
        
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return self.results
            
        file_size = os.path.getsize(file_path)
        if start_offset >= file_size:
            logger.error(f"Start offset {start_offset} is beyond file size {file_size}")
            return self.results
            
        # Adjust size if it goes beyond file end
        if start_offset + size > file_size:
            size = file_size - start_offset
            
        logger.info(f"Scanning range in file: {file_path} from {start_offset} to {start_offset+size}")
        
        try:
            with open(file_path, 'rb') as f:
                f.seek(start_offset)
                data = f.read(size)
                
                # Process this chunk
                self.results = self.scan_chunk(data, start_offset)
        
        except Exception as e:
            logger.error(f"Error scanning file range: {e}")
            
        # Sort results by confidence
        self.results.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        
        return self.results
    
    def scan_process_memory(self, pid: int) -> List[Dict[str, Any]]:
        """
        Scan memory of a running process.
        
        Args:
            pid: Process ID to scan
            
        Returns:
            List of findings
        """
        self.results = []
        
        # Platform-specific implementation
        if sys.platform == 'win32':
            self._scan_process_memory_windows(pid)
        elif sys.platform == 'linux':
            self._scan_process_memory_linux(pid)
        elif sys.platform == 'darwin':
            self._scan_process_memory_macos(pid)
        else:
            logger.error(f"Unsupported platform: {sys.platform}")
            
        return self.results
    
    def _scan_process_memory_windows(self, pid: int) -> None:
        """
        Scan memory of a Windows process.
        
        Args:
            pid: Process ID to scan
        """
        try:
            # Windows specific imports
            import win32process
            import win32con
            import ctypes
            from ctypes import wintypes
            
            # Get process handle with required access rights
            hProcess = win32process.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                False, pid
            )
            
            # Get process name
            process_name = "Unknown"
            try:
                import win32api
                process_name = win32api.GetModuleFileNameEx(hProcess, 0)
            except Exception:
                pass
                
            logger.info(f"Scanning process: {pid} ({process_name})")
            
            # Get memory regions
            meminfo = ctypes.c_void_p(0)
            mem_info = wintypes.MEMORY_BASIC_INFORMATION()
            
            while ctypes.windll.kernel32.VirtualQueryEx(
                hProcess.handle, 
                meminfo, 
                ctypes.byref(mem_info), 
                ctypes.sizeof(mem_info)
            ):
                # Check if region is readable and committed
                if (mem_info.State & win32con.MEM_COMMIT and 
                    mem_info.Protect & win32con.PAGE_READABLE):
                    try:
                        # Read the memory region
                        data = win32process.ReadProcessMemory(
                            hProcess.handle, mem_info.BaseAddress, mem_info.RegionSize
                        )
                        
                        # Scan this region
                        region_findings = self.scan_chunk(data, mem_info.BaseAddress)
                        
                        # Add region info to findings
                        for finding in region_findings:
                            finding["region_base"] = mem_info.BaseAddress
                            finding["process_id"] = pid
                            finding["process_name"] = process_name
                            
                        self.results.extend(region_findings)
                        
                    except Exception as e:
                        logger.debug(f"Error reading process memory at {mem_info.BaseAddress:#x}: {e}")
                
                # Move to next region
                meminfo = ctypes.c_void_p(mem_info.BaseAddress + mem_info.RegionSize)
            
            # Close process handle
            hProcess.Close()
            
            # Sort results by confidence
            self.results.sort(key=lambda x: x.get("confidence", 0), reverse=True)
            
        except Exception as e:
            logger.error(f"Error scanning Windows process memory: {e}")
            
    def _scan_process_memory_linux(self, pid: int) -> None:
        """
        Scan memory of a Linux process.
        
        Args:
            pid: Process ID to scan
        """
        try:
            # Linux process memory is exposed through /proc/{pid}/maps and /proc/{pid}/mem
            maps_file = f"/proc/{pid}/maps"
            mem_file = f"/proc/{pid}/mem"
            
            if not os.path.exists(maps_file) or not os.path.exists(mem_file):
                logger.error(f"Process {pid} not found or not accessible")
                return
                
            # Get process name
            process_name = "Unknown"
            try:
                with open(f"/proc/{pid}/comm", 'r') as f:
                    process_name = f.read().strip()
            except Exception:
                pass
                
            logger.info(f"Scanning process: {pid} ({process_name})")
            
            # Parse memory maps
            memory_regions = []
            with open(maps_file, 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 6:
                        continue
                        
                    # Parse address range
                    addr_range = parts[0].split('-')
                    start = int(addr_range[0], 16)
                    end = int(addr_range[1], 16)
                    
                    # Check permissions
                    perms = parts[1]
                    if 'r' in perms:  # Readable region
                        region_name = parts[5] if len(parts) > 5 else "anonymous"
                        memory_regions.append((start, end - start, region_name))
            
            # Open process memory
            with open(mem_file, 'rb') as f:
                for start, size, region_name in memory_regions:
                    try:
                        # Seek to the start address
                        f.seek(start)
                        
                        # Try to read the memory region
                        data = f.read(size)
                        
                        # Scan this region
                        region_findings = self.scan_chunk(data, start)
                        
                        # Add region info to findings
                        for finding in region_findings:
                            finding["region_base"] = start
                            finding["region_name"] = region_name
                            finding["process_id"] = pid
                            finding["process_name"] = process_name
                            
                        self.results.extend(region_findings)
                        
                    except Exception as e:
                        logger.debug(f"Error reading process memory at {start:#x}: {e}")
            
            # Sort results by confidence
            self.results.sort(key=lambda x: x.get("confidence", 0), reverse=True)
            
        except Exception as e:
            logger.error(f"Error scanning Linux process memory: {e}")
            
    def _scan_process_memory_macos(self, pid: int) -> None:
        """
        Scan memory of a macOS process.
        This is a placeholder - actual implementation would require more
        sophisticated handling of macOS memory APIs.
        
        Args:
            pid: Process ID to scan
        """
        logger.warning("macOS process memory scanning is not yet fully implemented")
        
        try:
            # Get process name (simplified approach)
            process_name = "Unknown"
            try:
                import subprocess
                ps_output = subprocess.check_output(['ps', '-p', str(pid), '-o', 'comm='])
                process_name = ps_output.decode().strip()
            except Exception:
                pass
                
            logger.info(f"Scanning process: {pid} ({process_name})")
            
            # For macOS, we'd need to use Mach APIs via ctypes
            # This is a significant implementation that's beyond the scope of this example
            
            logger.error("Direct macOS process memory scanning not implemented.")
            logger.info("Consider using a memory dump tool like vmmap or lldb first.")
            
        except Exception as e:
            logger.error(f"Error scanning macOS process memory: {e}")
    
    def save_results(self, output_file: str) -> None:
        """
        Save scan results to a JSON file.
        
        Args:
            output_file: Path to save results to
        """
        if not self.results:
            logger.warning("No results to save")
            return
            
        try:
            with open(output_file, 'w') as f:
                # Create a result summary with metadata
                result_data = {
                    "scan_time": datetime.now().isoformat(),
                    "total_findings": len(self.results),
                    "findings_by_type": {},
                    "findings": self.results
                }
                
                # Count findings by type
                for finding in self.results:
                    finding_type = finding.get("type", "unknown")
                    result_data["findings_by_type"][finding_type] = result_data["findings_by_type"].get(finding_type, 0) + 1
                
                json.dump(result_data, f, indent=2)
                logger.info(f"Results saved to {output_file}")
                
        except Exception as e:
            logger.error(f"Error saving results: {e}")

def main():
    """Command line interface for the crypto pattern matcher."""
    parser = argparse.ArgumentParser(description="Cryptographic Pattern Matcher for Ransomware Analysis")
    parser.add_argument("input", help="Memory dump file or process ID to scan")
    parser.add_argument("--pid", action="store_true", help="Input is a process ID instead of a file")
    parser.add_argument("--output", "-o", help="Output file for results (JSON)")
    parser.add_argument("--offset", type=int, help="Starting offset for file scan")
    parser.add_argument("--size", type=int, help="Size of data to scan from offset")
    parser.add_argument("--chunk-size", type=int, default=CHUNK_SIZE,
                      help=f"Chunk size for processing large files (default: {CHUNK_SIZE/1024/1024:.1f}MB)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Create matcher
    matcher = CryptoPatternMatcher(chunk_size=args.chunk_size)
    
    # Scan based on input type
    if args.pid:
        try:
            pid = int(args.input)
            logger.info(f"Scanning process with PID: {pid}")
            results = matcher.scan_process_memory(pid)
        except ValueError:
            logger.error("Invalid PID. Must be an integer.")
            return 1
    else:
        if args.offset is not None and args.size is not None:
            logger.info(f"Scanning file range: {args.input} from {args.offset} for {args.size} bytes")
            results = matcher.scan_range_in_file(args.input, args.offset, args.size)
        else:
            logger.info(f"Scanning file: {args.input}")
            results = matcher.scan_file(args.input)
    
    # Print summary
    logger.info(f"Scan complete. Found {len(results)} potential ransomware patterns.")
    
    # Group by type
    findings_by_type = {}
    for finding in results:
        finding_type = finding.get("type", "unknown")
        findings_by_type[finding_type] = findings_by_type.get(finding_type, 0) + 1
    
    for finding_type, count in findings_by_type.items():
        logger.info(f"  {finding_type}: {count}")
    
    # Group by ransomware family for ransomware patterns
    families = {}
    for finding in results:
        if finding.get("type") == "ransomware_pattern":
            family = finding.get("family", "unknown")
            families[family] = families.get(family, 0) + 1
    
    if families:
        logger.info("\nRansomware families detected:")
        for family, count in sorted(families.items(), key=lambda x: x[1], reverse=True):
            logger.info(f"  {family}: {count} matches")
    
    # Save results if output file specified
    if args.output:
        matcher.save_results(args.output)
    elif not args.output and results:
        # Print top 5 findings
        logger.info("\nTop findings:")
        for i, finding in enumerate(results[:5]):
            logger.info(f"[{i+1}] Type: {finding.get('type')}, " +
                       f"Family: {finding.get('family', 'N/A')}, " +
                       f"Confidence: {finding.get('confidence', 0):.2f}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())