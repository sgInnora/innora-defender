#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ransomware Memory Key Extractor

Advanced memory analysis module for extracting encryption keys from ransomware processes.
This module implements specialized extractors for various ransomware families with
sophisticated pattern detection, statistical analysis, and heuristics.

Key features:
- Advanced pattern-based key extraction for multiple ransomware families
- Multi-stage validation and confidence scoring for extracted keys
- Specialized extractors for common encryption algorithms (AES, RSA, ChaCha)
- Context-aware memory analysis for increased accuracy
- Integration with ransomware family databases
"""

import os
import re
import struct
import logging
import binascii
import datetime
import hashlib
import math
from typing import Dict, List, Tuple, Set, Optional, Any, Union, BinaryIO

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('RansomwareKeyExtractor')

# Constants for key detection
AES_KEY_SIZES = [16, 24, 32]  # 128, 192, 256 bits
RSA_MIN_KEY_SIZE = 128  # 1024 bits
RSA_MAX_KEY_SIZE = 512  # 4096 bits
CHACHA_KEY_SIZE = 32  # 256 bits
SALSA_KEY_SIZE = 32  # 256 bits

# Minimum entropy for key detection
MIN_KEY_ENTROPY = 3.5

# Minimum byte range for a valid memory block
MIN_BLOCK_SIZE = 16
MAX_SCAN_BLOCK = 10 * 1024 * 1024  # 10 MB at a time

# Key validation thresholds
ENTROPY_THRESHOLD = 5.0
PATTERN_MATCH_THRESHOLD = 0.7

class RansomKeySearchResult:
    """
    Represents a key search result with context and validation information.
    """
    
    def __init__(self, key_data: bytes, key_type: str, offset: int, 
                confidence: float, context: Optional[Dict[str, Any]] = None):
        """
        Initialize a key search result.
        
        Args:
            key_data: The extracted key bytes
            key_type: The type of key (e.g., 'aes-256', 'rsa-private')
            offset: The offset in memory where the key was found
            confidence: Confidence score (0.0 to 1.0)
            context: Additional context about the key
        """
        self.key_data = key_data
        self.key_type = key_type
        self.offset = offset
        self.confidence = confidence
        self.context = context or {}
        self.timestamp = datetime.datetime.now()
        self.key_id = self._generate_key_id()
        
        # Additional validation attributes
        self.validated = False
        self.validation_method = None
        self.entropy = self._calculate_entropy(key_data)
        
    def _generate_key_id(self) -> str:
        """Generate a unique ID for the key."""
        hash_input = self.key_data + str(self.offset).encode() + str(self.timestamp).encode()
        return hashlib.sha256(hash_input).hexdigest()[:16]
    
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
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary representation."""
        return {
            'key_id': self.key_id,
            'key_type': self.key_type,
            'key_hex': self.key_data.hex(),
            'key_size_bits': len(self.key_data) * 8,
            'offset': self.offset,
            'confidence': self.confidence,
            'entropy': self.entropy,
            'validated': self.validated,
            'validation_method': self.validation_method,
            'timestamp': self.timestamp.isoformat(),
            'context': self.context
        }

class RansomwareKeyExtractor:
    """
    Advanced extractor for ransomware encryption keys from memory dumps and processes.
    """
    
    def __init__(self, work_dir: Optional[str] = None):
        """
        Initialize the ransomware key extractor.
        
        Args:
            work_dir: Working directory for temporary files
        """
        self.work_dir = work_dir or os.path.join(os.getcwd(), 'key_extractor_output')
        os.makedirs(self.work_dir, exist_ok=True)
        
        # Load family-specific patterns
        self.family_patterns = self._load_family_patterns()
        
        # Initialize key trackers
        self.found_keys = []
        self.validated_keys = []
        
        logger.info("Ransomware Key Extractor initialized")
    
    def _load_family_patterns(self) -> Dict[str, Dict[str, Any]]:
        """
        Load family-specific key search patterns and contexts.
        
        Returns:
            Dictionary mapping ransomware families to their patterns
        """
        patterns = {
            # LockBit patterns for key detection
            'lockbit': {
                'aes_key_markers': [
                    rb'\x00{4}[\x10\x18\x20][\x00-\xFF]{16,32}\x00{4}',  # AES key with size indicator
                    rb'AES[_-]KEY[_=:]\s*([A-Za-z0-9+/=]{24,88})',  # AES key in base64
                    rb'1765FE8E-2103-66E3-7DCB-72284ABD03AA.*?([A-Fa-f0-9]{32,64})',  # AES key near UUID
                ],
                'key_neighborhood_markers': [
                    b'encrypt', b'KEY', b'Salsa', b'ChaCha', 
                    b'AES', b'RSA', b'CBC', b'ECB', b'1765FE8E',
                    b'.locked', b'README', b'readme.txt'
                ],
                'context_markers': {
                    'version_markers': {
                        'lockbit_2.0': [b'1765FE8E-2103-66E3-7DCB-72284ABD03AA', b'LockBit 2.0'],
                        'lockbit_3.0': [b'lockbit3', b'LockBit 3.0', b'LockBit Black']
                    }
                }
            },
            
            # Ryuk patterns for key detection
            'ryuk': {
                'aes_key_markers': [
                    rb'[\x10\x18\x20]\x00{3}[\x00-\xFF]{16,32}',  # Potential AES key with size marker
                    rb'RyukReadMe.*?([A-Fa-f0-9]{32,64})'  # Key near readme reference
                ],
                'key_neighborhood_markers': [
                    b'encrypt', b'Ryuk', b'AES_set', b'RyukReadMe', 
                    b'UNIQUE_ID', b'CryptEncrypt', b'CryptGenKey'
                ],
                'context_markers': {}
            },
            
            # WannaCry patterns for key detection
            'wannacry': {
                'aes_key_markers': [
                    rb'WanaDecryptor',
                    rb'WANACRY!',
                    rb'\.wncry',
                    rb'00000000\s?[\da-f]{16}\s?0{16}\s?([\da-f]{32})'  # Key pattern in memory
                ],
                'key_neighborhood_markers': [
                    b'TaskStart', b'WanaDecryptor', b'CryptEncrypt', 
                    b'CryptGenKey', b'wcry', b'WANACRY'
                ],
                'context_markers': {}
            },
            
            # Generic ransomware markers
            'generic': {
                'aes_key_markers': [
                    rb'AES_(?:set|encrypt|decrypt).*?(?:\s|=|:)([A-Fa-f0-9]{32,64})',
                    rb'CryptEncrypt.*?([A-Fa-f0-9]{32,64})',
                    rb'Crypt(?:Generate|Import)Key'
                ],
                'key_neighborhood_markers': [
                    b'encrypt', b'decrypt', b'AES_', b'EVP_', b'openssl',
                    b'Crypt', b'ransom', b'bitcoin', b'payment', b'.locked'
                ],
                'context_markers': {}
            }
        }
        
        return patterns
    
    def analyze_memory_dump(self, memory_path: str, 
                           family: Optional[str] = None) -> List[RansomKeySearchResult]:
        """
        Analyze a memory dump file for encryption keys.
        
        Args:
            memory_path: Path to the memory dump file
            family: Optional ransomware family to optimize search
            
        Returns:
            List of key search results
        """
        if not os.path.exists(memory_path):
            logger.error(f"Memory dump file not found: {memory_path}")
            return []
        
        logger.info(f"Analyzing memory dump for encryption keys: {memory_path}")
        
        # Try to determine ransomware family if not specified
        if not family:
            family = self._detect_family_from_memory(memory_path)
            if family:
                logger.info(f"Detected ransomware family: {family}")
        
        # Reset results for new analysis
        self.found_keys = []
        
        # Set up patterns based on family
        patterns = []
        neighborhood_markers = []
        
        if family and family in self.family_patterns:
            # Use family-specific patterns
            patterns = self.family_patterns[family]['aes_key_markers']
            neighborhood_markers = self.family_patterns[family]['key_neighborhood_markers']
            logger.info(f"Using {family}-specific search patterns")
        else:
            # Use generic patterns
            patterns = self.family_patterns['generic']['aes_key_markers']
            neighborhood_markers = self.family_patterns['generic']['key_neighborhood_markers']
            
            # Also include patterns from all families for comprehensive search
            for fam, fam_patterns in self.family_patterns.items():
                if fam != 'generic':
                    patterns.extend(fam_patterns['aes_key_markers'])
                    neighborhood_markers.extend(fam_patterns['key_neighborhood_markers'])
            
            logger.info("Using generic search patterns")
        
        # Remove duplicates
        neighborhood_markers = list(set(neighborhood_markers))
        
        # Perform memory analysis
        keys = self._scan_memory_file(memory_path, patterns, neighborhood_markers, family)
        
        # Additional family-specific postprocessing
        if family:
            keys = self._apply_family_specific_post_processing(keys, family)
        
        # Store the found keys
        self.found_keys = keys
        
        # Perform validation
        self._validate_keys(keys)
        
        logger.info(f"Found {len(keys)} potential encryption keys")
        return keys
    
    def _detect_family_from_memory(self, memory_path: str) -> Optional[str]:
        """
        Try to detect ransomware family from memory dump.
        
        Args:
            memory_path: Path to memory dump file
            
        Returns:
            Detected family name or None
        """
        # Define family-specific markers
        family_markers = {
            'lockbit': [b'LockBit', b'1765FE8E-2103-66E3-7DCB-72284ABD03AA'],
            'ryuk': [b'RyukReadMe', b'RYUK'],
            'wannacry': [b'WanaDecryptor', b'WANACRY', b'.wncry'],
            'revil': [b'REvil', b'Sodinokibi'],
            'conti': [b'conti_news', b'CONTI'],
            'blackcat': [b'BlackCat', b'ALPHV'],
            'hive': [b'HiveLeaks', b'Hive']
        }
        
        # Check for family markers in the dump
        try:
            with open(memory_path, 'rb') as f:
                # Read the first 20MB for quick check
                data = f.read(20 * 1024 * 1024)
                
                # Count matches for each family
                family_matches = {}
                for family, markers in family_markers.items():
                    matches = 0
                    for marker in markers:
                        matches += data.count(marker)
                    
                    if matches > 0:
                        family_matches[family] = matches
                
                # Return family with most matches if any
                if family_matches:
                    return max(family_matches.items(), key=lambda x: x[1])[0]
        
        except Exception as e:
            logger.error(f"Error detecting family from memory: {e}")
        
        return None
    
    def _scan_memory_file(self, memory_path: str, patterns: List[bytes], 
                         neighborhood_markers: List[bytes], 
                         family: Optional[str] = None) -> List[RansomKeySearchResult]:
        """
        Scan memory file for encryption keys.
        
        Args:
            memory_path: Path to memory dump file
            patterns: List of byte patterns to search for
            neighborhood_markers: List of context markers
            family: Optional ransomware family for context
            
        Returns:
            List of key search results
        """
        results = []
        file_size = os.path.getsize(memory_path)
        
        try:
            with open(memory_path, 'rb') as f:
                # Process the file in chunks for memory efficiency
                offset = 0
                while offset < file_size:
                    chunk_size = min(MAX_SCAN_BLOCK, file_size - offset)
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    # Process this chunk
                    chunk_results = self._scan_memory_chunk(chunk, offset, patterns, 
                                                         neighborhood_markers, family)
                    results.extend(chunk_results)
                    
                    # Update offset
                    offset += chunk_size
                    
                    # Progress reporting
                    progress = min(100, int((offset / file_size) * 100))
                    if progress % 10 == 0:
                        logger.info(f"Scanning memory: {progress}% complete")
        
        except Exception as e:
            logger.error(f"Error scanning memory file: {e}")
        
        return results
    
    def _scan_memory_chunk(self, chunk: bytes, base_offset: int, patterns: List[bytes],
                          neighborhood_markers: List[bytes], 
                          family: Optional[str] = None) -> List[RansomKeySearchResult]:
        """
        Scan a chunk of memory for encryption keys.
        
        Args:
            chunk: Memory chunk to scan
            base_offset: Base offset of the chunk in the file
            patterns: List of byte patterns to search for
            neighborhood_markers: List of context markers
            family: Optional ransomware family for context
            
        Returns:
            List of key search results
        """
        results = []
        
        # Apply pattern-based search first
        for pattern in patterns:
            try:
                for match in re.finditer(pattern, chunk):
                    start_pos = match.start()
                    
                    # Extract different possible key lengths
                    for key_size in AES_KEY_SIZES:
                        if start_pos + key_size <= len(chunk):
                            # Extract potential key
                            key_data = chunk[start_pos:start_pos + key_size]
                            
                            # Calculate absolute offset
                            absolute_offset = base_offset + start_pos
                            
                            # Calculate entropy to filter out low-entropy keys
                            entropy = self._calculate_entropy(key_data)
                            if entropy < MIN_KEY_ENTROPY:
                                continue
                            
                            # Initial confidence based on entropy
                            confidence = min(1.0, entropy / 8.0)
                            
                            # Adjust confidence based on neighborhood
                            confidence = self._adjust_confidence_by_neighborhood(
                                chunk, start_pos, neighborhood_markers, confidence)
                            
                            # Create context
                            context = {
                                'pattern': pattern.decode('latin1', errors='replace'),
                                'entropy': entropy,
                                'family_hint': family
                            }
                            
                            # Determine key type
                            key_type = f"aes-{key_size * 8}"
                            
                            # Create result
                            result = RansomKeySearchResult(
                                key_data=key_data,
                                key_type=key_type,
                                offset=absolute_offset,
                                confidence=confidence,
                                context=context
                            )
                            
                            results.append(result)
            except Exception as e:
                logger.debug(f"Error matching pattern: {e}")
        
        # Also perform entropy-based search for high-entropy blocks
        entropy_results = self._scan_for_high_entropy_blocks(chunk, base_offset, family)
        results.extend(entropy_results)
        
        # Deduplicate results
        deduplicated = []
        seen_keys = set()
        for result in results:
            key_hex = result.key_data.hex()
            if key_hex not in seen_keys:
                seen_keys.add(key_hex)
                deduplicated.append(result)
        
        return deduplicated
    
    def _scan_for_high_entropy_blocks(self, chunk: bytes, base_offset: int,
                                    family: Optional[str] = None) -> List[RansomKeySearchResult]:
        """
        Scan for high-entropy blocks that could be encryption keys.
        
        Args:
            chunk: Memory chunk to scan
            base_offset: Base offset of the chunk in the file
            family: Optional ransomware family for context
            
        Returns:
            List of key search results
        """
        results = []
        chunk_len = len(chunk)
        
        # Skip small chunks
        if chunk_len < 64:
            return results
        
        # Scan the chunk with a sliding window
        for key_size in AES_KEY_SIZES:
            for i in range(0, chunk_len - key_size, 16):  # Step by 16 bytes
                # Extract a potential key block
                key_block = chunk[i:i + key_size]
                
                # Calculate entropy
                entropy = self._calculate_entropy(key_block)
                
                # Only consider high-entropy blocks
                if entropy > ENTROPY_THRESHOLD:
                    # Calculate absolute offset
                    absolute_offset = base_offset + i
                    
                    # Initial confidence based purely on entropy
                    confidence = min(0.7, (entropy - ENTROPY_THRESHOLD) / 3.0)
                    
                    # Create context
                    context = {
                        'entropy': entropy,
                        'method': 'entropy_scan',
                        'family_hint': family
                    }
                    
                    # Determine key type
                    key_type = f"aes-{key_size * 8}"
                    
                    # Create result
                    result = RansomKeySearchResult(
                        key_data=key_block,
                        key_type=key_type,
                        offset=absolute_offset,
                        confidence=confidence,
                        context=context
                    )
                    
                    results.append(result)
        
        return results
    
    def _adjust_confidence_by_neighborhood(self, chunk: bytes, position: int,
                                         markers: List[bytes], 
                                         base_confidence: float) -> float:
        """
        Adjust confidence based on neighborhood context.
        
        Args:
            chunk: Memory chunk
            position: Position of the key in the chunk
            markers: List of context markers to look for
            base_confidence: Base confidence to adjust
            
        Returns:
            Adjusted confidence score
        """
        adjusted_confidence = base_confidence
        
        # Define neighborhood size
        neighborhood_size = 1024  # 1KB on each side
        
        # Extract neighborhood
        start = max(0, position - neighborhood_size)
        end = min(len(chunk), position + neighborhood_size)
        neighborhood = chunk[start:end]
        
        # Count marker hits
        hits = 0
        for marker in markers:
            if marker in neighborhood:
                hits += 1
        
        # Adjust confidence based on marker hits
        if hits > 0:
            # Increase confidence with diminishing returns
            marker_bonus = min(0.3, hits * 0.05)
            adjusted_confidence = min(1.0, adjusted_confidence + marker_bonus)
        
        return adjusted_confidence
    
    def _apply_family_specific_post_processing(self, keys: List[RansomKeySearchResult],
                                             family: str) -> List[RansomKeySearchResult]:
        """
        Apply family-specific post-processing to key results.
        
        Args:
            keys: List of key search results
            family: Ransomware family
            
        Returns:
            Processed key results
        """
        if family == 'lockbit':
            # Add LockBit-specific context
            for key in keys:
                key.context['ransomware_family'] = 'LockBit'
                
                # Try to determine LockBit version
                if 'family_hint' in key.context:
                    key.context['family_version'] = key.context['family_hint']
        
        elif family == 'ryuk':
            # Ryuk-specific processing
            for key in keys:
                key.context['ransomware_family'] = 'Ryuk'
                
                # Ryuk uses pure AES keys, so high confidence for high entropy
                if key.entropy > 7.0:
                    key.confidence = min(1.0, key.confidence + 0.1)
        
        elif family == 'wannacry':
            # WannaCry-specific processing
            for key in keys:
                key.context['ransomware_family'] = 'WannaCry'
                
                # WannaCry stores keys in a specific format
                # Increase confidence for keys found near certain markers
                if b'WanaDecryptor' in key.context.get('pattern', b''):
                    key.confidence = min(1.0, key.confidence + 0.2)
        
        return keys
    
    def _validate_keys(self, keys: List[RansomKeySearchResult]) -> None:
        """
        Validate extracted keys for additional confidence.
        
        Args:
            keys: List of key search results
        """
        validated_keys = []
        
        for key in keys:
            # Perform basic validation
            if self._validate_key_structure(key):
                key.validated = True
                key.validation_method = "structure"
                validated_keys.append(key)
                continue
            
            # TODO: Implement additional validation methods
            # - Pattern validation
            # - Cryptographic property validation
            # - Entropy distribution validation
        
        self.validated_keys = validated_keys
        logger.info(f"Validated {len(validated_keys)} of {len(keys)} extracted keys")
    
    def _validate_key_structure(self, key: RansomKeySearchResult) -> bool:
        """
        Validate key structure based on its type.
        
        Args:
            key: Key search result
            
        Returns:
            True if the key has valid structure, False otherwise
        """
        key_type = key.key_type
        key_data = key.key_data
        
        # Validate AES keys
        if key_type.startswith('aes-'):
            # Check key size
            expected_size = int(key_type.split('-')[1]) // 8
            if len(key_data) != expected_size:
                return False
            
            # Check entropy
            if key.entropy < ENTROPY_THRESHOLD:
                return False
            
            return True
        
        # Validate RSA keys
        elif key_type.startswith('rsa-'):
            # RSA validation is more complex
            # TODO: Implement proper RSA key validation
            pass
        
        # Validate ChaCha keys
        elif key_type.startswith('chacha'):
            if len(key_data) != CHACHA_KEY_SIZE:
                return False
            
            if key.entropy < ENTROPY_THRESHOLD:
                return False
            
            return True
        
        return False
    
    def extract_keys_to_file(self, output_file: Optional[str] = None, 
                            min_confidence: float = 0.5) -> Optional[str]:
        """
        Extract validated keys to a file for use with decryption tools.
        
        Args:
            output_file: Optional path to save the keys
            min_confidence: Minimum confidence threshold
            
        Returns:
            Path to the output file or None if extraction failed
        """
        if not self.found_keys:
            logger.error("No keys to extract")
            return None
        
        # Filter keys by confidence
        high_confidence_keys = [key for key in self.found_keys 
                              if key.confidence >= min_confidence]
        
        if not high_confidence_keys:
            logger.error(f"No keys meet the minimum confidence threshold of {min_confidence}")
            return None
        
        # Generate default output filename if not provided
        if not output_file:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.work_dir, f"extracted_keys_{timestamp}.json")
        
        try:
            # Convert keys to dictionary representation
            keys_data = {
                'extraction_time': datetime.datetime.now().isoformat(),
                'total_keys_found': len(self.found_keys),
                'high_confidence_keys': len(high_confidence_keys),
                'confidence_threshold': min_confidence,
                'keys': [key.to_dict() for key in high_confidence_keys]
            }
            
            # Save as JSON
            import json
            with open(output_file, 'w') as f:
                json.dump(keys_data, f, indent=2)
            
            logger.info(f"Extracted {len(high_confidence_keys)} keys to {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Error extracting keys to file: {e}")
            return None
    
    def get_key_data(self, key_id: str) -> Optional[bytes]:
        """
        Get raw key data by key ID.
        
        Args:
            key_id: The ID of the key to retrieve
            
        Returns:
            Raw key bytes or None if key not found
        """
        for key in self.found_keys:
            if key.key_id == key_id:
                return key.key_data
        return None
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data.
        
        Args:
            data: Byte data to calculate entropy for
            
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


class LockBitKeyExtractor(RansomwareKeyExtractor):
    """
    Specialized key extractor for LockBit ransomware.
    """
    
    def __init__(self, work_dir: Optional[str] = None):
        """
        Initialize the LockBit key extractor.
        
        Args:
            work_dir: Working directory for temporary files
        """
        super().__init__(work_dir)
        
        # LockBit-specific patterns
        self.lockbit_uuid = "1765FE8E-2103-66E3-7DCB-72284ABD03AA"
        self.lockbit_markers = [
            b"LockBit",
            b"README.txt",
            b".locked",
            bytes.fromhex("1765FE8E210366E37DCB72284ABD03AA"),
            b"encrypt_files",
            b"decrypt_files",
            b"pay_for_decrypt",
            b"readme.txt"
        ]
        
        # LockBit encryption method identifiers
        self.encryption_methods = {
            'aes-cbc': [b'AES-CBC', b'AES_CBC', b'AES_set_encrypt_key', b'AES_set_decrypt_key'],
            'chacha20': [b'ChaCha20', b'chacha20_encrypt', b'chacha_encrypt'],
            'salsa20': [b'Salsa20', b'salsa20_encrypt', b'salsa_encrypt']
        }
        
        logger.info("LockBit Key Extractor initialized")
    
    def analyze_memory_for_lockbit(self, memory_path: str) -> List[RansomKeySearchResult]:
        """
        Analyze memory specifically for LockBit encryption keys.
        
        Args:
            memory_path: Path to memory dump file
            
        Returns:
            List of key search results
        """
        logger.info(f"Analyzing memory for LockBit keys: {memory_path}")
        
        # Use the base analyze_memory_dump with 'lockbit' family hint
        return self.analyze_memory_dump(memory_path, family='lockbit')
    
    def detect_lockbit_version(self, memory_path: str) -> str:
        """
        Detect the LockBit version from memory.
        
        Args:
            memory_path: Path to memory dump file
            
        Returns:
            LockBit version string
        """
        try:
            with open(memory_path, 'rb') as f:
                # Read the first 20MB for quick check
                data = f.read(20 * 1024 * 1024)
                
                # Check for version-specific markers
                if b'LockBit 3.0' in data or b'lockbit3' in data or b'LockBit Black' in data:
                    return "3.0"
                elif self.lockbit_uuid.encode() in data or b'LockBit 2.0' in data:
                    return "2.0"
                else:
                    return "unknown"
                    
        except Exception as e:
            logger.error(f"Error detecting LockBit version: {e}")
            return "unknown"
    
    def extract_iv_and_keys(self, memory_path: str) -> Dict[str, Any]:
        """
        Extract both initialization vectors (IVs) and keys from memory.
        
        Args:
            memory_path: Path to memory dump file
            
        Returns:
            Dictionary with IVs and keys
        """
        results = {
            'version': self.detect_lockbit_version(memory_path),
            'keys': [],
            'ivs': []
        }
        
        # First get encryption keys
        keys = self.analyze_memory_for_lockbit(memory_path)
        results['keys'] = [key.to_dict() for key in keys]
        
        # Now look for IVs (typically 16 bytes)
        iv_results = self._scan_for_ivs(memory_path)
        results['ivs'] = iv_results
        
        logger.info(f"Extracted {len(keys)} keys and {len(iv_results)} IVs")
        return results
    
    def _scan_for_ivs(self, memory_path: str) -> List[Dict[str, Any]]:
        """
        Scan memory for initialization vectors.
        
        Args:
            memory_path: Path to memory dump file
            
        Returns:
            List of IV data dictionaries
        """
        ivs = []
        file_size = os.path.getsize(memory_path)
        
        # IV patterns for LockBit
        iv_patterns = [
            rb'\x00{4}\x10\x00{3}([\x00-\xFF]{16})',  # AES-CBC IV with marker
            rb'AES_(?:cbc|CBC).*?([\x00-\xFF]{16})',  # IV near AES-CBC reference
            rb'IV[=:]?([\x00-\xFF]{16})'  # Explicit IV marker
        ]
        
        try:
            with open(memory_path, 'rb') as f:
                # Process in chunks
                offset = 0
                while offset < file_size:
                    chunk_size = min(MAX_SCAN_BLOCK, file_size - offset)
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    # Search for IV patterns
                    for pattern in iv_patterns:
                        for match in re.finditer(pattern, chunk):
                            # Extract IV data
                            iv_start = match.start(1) if len(match.groups()) > 0 else match.start()
                            iv_data = chunk[iv_start:iv_start + 16]
                            
                            # Only consider IVs with sufficient entropy
                            entropy = self._calculate_entropy(iv_data)
                            if entropy > 3.0:  # Lower threshold for IVs
                                ivs.append({
                                    'iv_hex': iv_data.hex(),
                                    'offset': offset + iv_start,
                                    'entropy': entropy,
                                    'context': pattern.decode('latin1', errors='replace')
                                })
                    
                    # Update offset
                    offset += chunk_size
        
        except Exception as e:
            logger.error(f"Error scanning for IVs: {e}")
        
        return ivs


def main():
    """Command-line interface for the ransomware key extractor."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Ransomware Encryption Key Extractor")
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze memory dump')
    analyze_parser.add_argument('file', help='Memory dump file to analyze')
    analyze_parser.add_argument('--family', '-f', help='Specify ransomware family')
    analyze_parser.add_argument('--output', '-o', help='Output file for extracted keys')
    analyze_parser.add_argument('--min-confidence', '-c', type=float, default=0.5,
                             help='Minimum confidence threshold (0.0-1.0)')
    analyze_parser.add_argument('--work-dir', '-w', help='Working directory')
    
    # LockBit command
    lockbit_parser = subparsers.add_parser('lockbit', help='LockBit-specific analysis')
    lockbit_parser.add_argument('file', help='Memory dump file to analyze')
    lockbit_parser.add_argument('--output', '-o', help='Output file for extracted keys')
    lockbit_parser.add_argument('--extract-iv', '-i', action='store_true',
                              help='Extract initialization vectors as well')
    lockbit_parser.add_argument('--work-dir', '-w', help='Working directory')
    
    # Parse arguments
    args = parser.parse_args()
    
    if args.command == 'analyze':
        # Create extractor
        extractor = RansomwareKeyExtractor(args.work_dir)
        
        # Analyze memory dump
        keys = extractor.analyze_memory_dump(args.file, args.family)
        
        # Extract keys to file
        output_file = extractor.extract_keys_to_file(args.output, args.min_confidence)
        
        if output_file:
            print(f"Extracted keys saved to: {output_file}")
        
    elif args.command == 'lockbit':
        # Create LockBit extractor
        extractor = LockBitKeyExtractor(args.work_dir)
        
        if args.extract_iv:
            # Extract both keys and IVs
            results = extractor.extract_iv_and_keys(args.file)
            
            # Save results
            if not args.output:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                args.output = f"lockbit_keys_ivs_{timestamp}.json"
            
            import json
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            
            print(f"LockBit version: {results['version']}")
            print(f"Found {len(results['keys'])} keys and {len(results['ivs'])} IVs")
            print(f"Results saved to: {args.output}")
            
        else:
            # Just extract keys
            keys = extractor.analyze_memory_for_lockbit(args.file)
            output_file = extractor.extract_keys_to_file(args.output)
            
            if output_file:
                print(f"Extracted keys saved to: {output_file}")
    
    else:
        parser.print_help()
    
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())