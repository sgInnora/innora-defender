#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ransomware Encryption Analyzer

This module analyzes encrypted files to determine the encryption algorithm,
key length, mode of operation, and other characteristics that help identify
the ransomware family and potential decryption methods.
"""

import os
import re
import math
import struct
import logging
import binascii
import hashlib
from typing import Dict, List, Optional, Any, Tuple, Union, Set
from collections import Counter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('EncryptionAnalyzer')

class EncryptionAnalyzer:
    """
    Analyzer for identifying encryption characteristics in ransomware-encrypted files.
    """
    
    def __init__(self):
        """Initialize the encryption analyzer."""
        # Known ransomware markers and their associated families
        self.known_markers = {
            b'WANACRY!': 'WannaCry',
            b'HERMES': 'Ryuk',
            b'LOCK': 'LockBit',
            b'CONTI': 'Conti',
            b'BLACKCAT': 'BlackCat',
            b'HIVE': 'Hive',
            b'DHARMA': 'Dharma',
            b'CERBER': 'Cerber'
        }
        
        # Known file extensions by ransomware family
        self.known_extensions = {
            '.wncry': 'WannaCry',
            '.wcry': 'WannaCry',
            '.wncryt': 'WannaCry',
            '.ryk': 'Ryuk',
            '.ryuk': 'Ryuk',
            '.RYK': 'Ryuk',
            '.lockbit': 'LockBit',
            '.lock': 'LockBit',
            '.conti': 'Conti',
            '.blackcat': 'BlackCat',
            '.hive': 'Hive',
            '.djvu': 'STOP',
            '.djvus': 'STOP',
            '.djvur': 'STOP',
            '.uudjvu': 'STOP',
            '.revil': 'REvil',
            '.sodinokibi': 'REvil',
            '.xxxx': 'GlobeImposter',
            '.basta': 'BlackBasta',
            '.avos': 'AvosLocker',
            '.phobos': 'Phobos',
            '.lokibot': 'LokiBot',
            '.locked': 'Locky'
        }
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze an encrypted file to determine its characteristics.
        
        Args:
            file_path: Path to the encrypted file
            
        Returns:
            Dictionary with analysis results
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return {"error": "File not found"}
            
        logger.info(f"Analyzing file: {file_path}")
        
        results = {
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path),
            "extension": os.path.splitext(file_path)[1].lower(),
            "entropy": None,
            "potential_family": None,
            "encryption_details": {},
            "encryption_confidence": 0.0,
            "header_analysis": {},
            "file_structure": {},
        }
        
        # Perform basic file analysis
        self._analyze_file_basics(file_path, results)
        
        # Analyze file header
        self._analyze_file_header(file_path, results)
        
        # Calculate entropy
        results["entropy"] = self._calculate_file_entropy(file_path)
        
        # Detect potential encryption algorithm
        self._detect_encryption_algorithm(file_path, results)
        
        # Determine ransomware family
        self._identify_ransomware_family(results)
        
        # Calculate overall confidence
        self._calculate_confidence(results)
        
        return results
    
    def _analyze_file_basics(self, file_path: str, results: Dict[str, Any]) -> None:
        """
        Analyze basic file characteristics.
        
        Args:
            file_path: Path to the file
            results: Results dictionary to update
        """
        # Check file extension against known ransomware extensions
        extension = results["extension"]
        if extension in self.known_extensions:
            results["potential_family"] = self.known_extensions[extension]
            results["encryption_confidence"] = 0.6  # Initial confidence based on extension
            
        # Check if extension looks like a ransomware extension
        if re.match(r'\.[a-zA-Z0-9]{4,8}$', extension) and extension not in ['.jpeg', '.png', '.mp3', '.mp4', '.docx', '.xlsx', '.pptx', '.pdf']:
            results["file_structure"]["suspicious_extension"] = True
            results["encryption_confidence"] = max(results.get("encryption_confidence", 0), 0.4)
            
        # Check for common ransomware patterns in filename
        filename = results["file_name"].lower()
        if any(pattern in filename for pattern in ['encrypt', 'locked', 'ransom', 'decrypt']):
            results["file_structure"]["suspicious_filename"] = True
            results["encryption_confidence"] = max(results.get("encryption_confidence", 0), 0.5)
    
    def _analyze_file_header(self, file_path: str, results: Dict[str, Any]) -> None:
        """
        Analyze the file header for known markers and patterns.
        
        Args:
            file_path: Path to the file
            results: Results dictionary to update
        """
        try:
            # Read first 1KB of the file
            with open(file_path, 'rb') as f:
                header = f.read(1024)
                
            results["header_analysis"]["header_hex"] = header[:64].hex()
            
            # Check for known ransomware markers
            for marker, family in self.known_markers.items():
                if marker in header:
                    results["header_analysis"]["known_marker"] = marker.decode('utf-8', errors='replace')
                    results["potential_family"] = family
                    results["encryption_confidence"] = 0.8
                    break
                    
            # Check if the header starts with a size or other metadata (common in encrypted files)
            if len(header) >= 8:
                potential_size = struct.unpack("<Q", header[:8])[0]
                if 0 < potential_size < 10 * 1024 * 1024:  # Reasonable file size (<10MB)
                    results["header_analysis"]["potential_size_header"] = potential_size
                    results["encryption_confidence"] = max(results.get("encryption_confidence", 0), 0.6)
                    
            # Look for Base64-encoded data in the header (common in some ransomware)
            if re.search(b'[A-Za-z0-9+/]{30,}={0,2}', header):
                results["header_analysis"]["potential_base64_data"] = True
                results["encryption_confidence"] = max(results.get("encryption_confidence", 0), 0.5)
                
            # Check for JSON structure (some ransomware embeds keys or configs)
            if b'{' in header and b'}' in header and (b'"' in header or b"'" in header):
                results["header_analysis"]["potential_json_data"] = True
                
                # Try to extract any embedded keys or IDs
                json_start = header.find(b'{')
                json_end = header.find(b'}', json_start)
                if json_start >= 0 and json_end > json_start:
                    json_data = header[json_start:json_end+1].decode('utf-8', errors='replace')
                    results["header_analysis"]["json_data"] = json_data
                    
                    # Look for key-like patterns
                    if re.search(r'"(key|iv|id|pub|priv)"', json_data):
                        results["header_analysis"]["potential_key_reference"] = True
                        results["encryption_confidence"] = max(results.get("encryption_confidence", 0), 0.7)
            
            # Check for high entropy in the header (typically indicates encryption)
            header_entropy = self._calculate_entropy(header)
            results["header_analysis"]["header_entropy"] = header_entropy
            
            if header_entropy > 7.8:
                results["header_analysis"]["high_entropy_header"] = True
                results["encryption_confidence"] = max(results.get("encryption_confidence", 0), 0.6)
            
        except Exception as e:
            logger.error(f"Error analyzing file header: {e}")
            results["header_analysis"]["error"] = str(e)
    
    def _calculate_file_entropy(self, file_path: str) -> float:
        """
        Calculate Shannon entropy of a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Entropy value between 0 and 8
        """
        try:
            # Read file in chunks to handle large files
            chunk_size = 8192
            byte_counts = Counter()
            total_bytes = 0
            
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                        
                    byte_counts.update(chunk)
                    total_bytes += len(chunk)
            
            if total_bytes == 0:
                return 0.0
                
            # Calculate entropy
            entropy = 0.0
            for count in byte_counts.values():
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)
                
            return entropy
            
        except Exception as e:
            logger.error(f"Error calculating file entropy: {e}")
            return 0.0
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of a byte string.
        
        Args:
            data: Bytes to calculate entropy for
            
        Returns:
            Entropy value between 0 and 8
        """
        if not data:
            return 0.0
            
        entropy = 0.0
        data_len = len(data)
        
        # Count occurrences of each byte value
        byte_counts = Counter(data)
        
        # Calculate Shannon entropy
        for count in byte_counts.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
            
        return entropy
    
    def _detect_encryption_algorithm(self, file_path: str, results: Dict[str, Any]) -> None:
        """
        Attempt to detect the encryption algorithm used.
        
        Args:
            file_path: Path to the file
            results: Results dictionary to update
        """
        try:
            # Read parts of the file for analysis
            with open(file_path, 'rb') as f:
                header = f.read(1024)
                
                # Skip to middle of file for another sample
                f.seek(max(0, results["file_size"] // 2 - 512))
                middle = f.read(1024)
                
                # Read end of file
                f.seek(max(0, results["file_size"] - 1024))
                end = f.read(1024)
            
            encryption_details = {}
            
            # Check for block cipher patterns
            if self._check_block_cipher_patterns(header, middle, end, encryption_details):
                results["encryption_details"].update(encryption_details)
                
            # Check for RSA patterns
            if self._check_rsa_patterns(header, end, encryption_details):
                results["encryption_details"].update(encryption_details)
                
            # Check for stream cipher patterns
            if self._check_stream_cipher_patterns(middle, encryption_details):
                results["encryption_details"].update(encryption_details)
                
            # Set default if nothing detected
            if not results["encryption_details"] and results["entropy"] > 7.5:
                results["encryption_details"]["likely_algorithm"] = "Unknown (high entropy)"
                results["encryption_details"]["confidence"] = 0.4
                
        except Exception as e:
            logger.error(f"Error detecting encryption algorithm: {e}")
            results["encryption_details"]["error"] = str(e)
    
    def _check_block_cipher_patterns(self, header: bytes, middle: bytes, end: bytes,
                                    details: Dict[str, Any]) -> bool:
        """
        Check for patterns that indicate block cipher encryption.
        
        Args:
            header: Start of the file
            middle: Middle part of the file
            end: End of the file
            details: Dictionary to update with findings
            
        Returns:
            True if block cipher patterns detected, False otherwise
        """
        # Block size detection
        block_patterns = {
            16: {"algorithm": "AES", "confidence": 0.7},
            8: {"algorithm": "DES/3DES", "confidence": 0.6}
        }
        
        # Look for repetition at block boundaries
        for block_size, info in block_patterns.items():
            # Check if there are patterns at block boundaries
            if (self._check_block_boundaries(header, block_size) or
                self._check_block_boundaries(middle, block_size)):
                details["likely_algorithm"] = info["algorithm"]
                details["block_size"] = block_size
                details["confidence"] = info["confidence"]
                
                # Try to determine mode of operation
                details["mode"] = self._determine_operation_mode(header, middle, block_size)
                return True
                
        # AES in CBC mode often has high entropy but not perfect
        middle_entropy = self._calculate_entropy(middle)
        if 7.6 <= middle_entropy <= 7.99:
            details["likely_algorithm"] = "AES"
            details["block_size"] = 16
            details["confidence"] = 0.6
            details["mode"] = "CBC (tentative)"
            return True
            
        return False
    
    def _check_block_boundaries(self, data: bytes, block_size: int) -> bool:
        """
        Check if there are patterns at block boundaries.
        
        Args:
            data: Data to analyze
            block_size: Block size to check
            
        Returns:
            True if patterns found, False otherwise
        """
        if len(data) < block_size * 3:
            return False
            
        # Look for similar patterns at block boundaries
        similarities = 0
        total_checks = min(5, len(data) // block_size - 1)
        
        for i in range(total_checks):
            block1 = data[i * block_size:(i + 1) * block_size]
            block2 = data[(i + 1) * block_size:(i + 2) * block_size]
            
            # Calculate Hamming distance between blocks
            distance = sum(b1 != b2 for b1, b2 in zip(block1, block2))
            
            # Blocks should be different but with some similarities
            if distance > 0 and distance < block_size * 0.7:
                similarities += 1
                
        return similarities >= total_checks // 2
    
    def _determine_operation_mode(self, header: bytes, middle: bytes, block_size: int) -> str:
        """
        Attempt to determine block cipher mode of operation.
        
        Args:
            header: Start of the file
            middle: Middle part of the file
            block_size: Block size
            
        Returns:
            Likely mode of operation
        """
        # ECB mode will have repeating patterns for identical plaintext blocks
        # Look for identical ciphertext blocks
        blocks = [middle[i:i+block_size] for i in range(0, len(middle) - block_size, block_size)]
        unique_blocks = len(set(blocks))
        
        if unique_blocks < len(blocks) * 0.9:  # More than 10% repeating blocks
            return "ECB"
            
        # CBC mode often has IV at the beginning
        if len(header) >= block_size * 2:
            first_block_entropy = self._calculate_entropy(header[:block_size])
            if 7.5 <= first_block_entropy <= 8.0:
                return "CBC"
                
        # CTR/GCM modes often have nonce/counter at the beginning
        if len(header) >= block_size + 4:
            if struct.unpack("<I", header[block_size:block_size+4])[0] < 1000:
                return "CTR/GCM"
                
        return "CBC/CFB (tentative)"
    
    def _check_rsa_patterns(self, header: bytes, end: bytes, details: Dict[str, Any]) -> bool:
        """
        Check for patterns that indicate RSA encryption.
        
        Args:
            header: Start of the file
            end: End of the file
            details: Dictionary to update with findings
            
        Returns:
            True if RSA patterns detected, False otherwise
        """
        # Look for ASN.1 DER encoding patterns common in RSA
        asn1_patterns = [
            b'\x30\x82',  # SEQUENCE
            b'\x02\x01\x00',  # INTEGER
            b'\x02\x82'  # INTEGER with 2 bytes length
        ]
        
        for pattern in asn1_patterns:
            if pattern in header or pattern in end:
                details["likely_algorithm"] = "RSA"
                details["confidence"] = 0.7
                details["key_type"] = "public/private key"
                return True
                
        # Look for Base64-encoded key data
        base64_pattern = re.compile(b'[A-Za-z0-9+/]{30,}={0,2}')
        if base64_pattern.search(header) or base64_pattern.search(end):
            # Check if header contains key-like strings
            header_str = header.decode('utf-8', errors='replace').lower()
            if any(key_marker in header_str for key_marker in ['rsa', 'key', 'pub', 'priv', 'mod', 'exp']):
                details["likely_algorithm"] = "RSA"
                details["confidence"] = 0.6
                details["key_format"] = "Base64"
                return True
                
        return False
    
    def _check_stream_cipher_patterns(self, data: bytes, details: Dict[str, Any]) -> bool:
        """
        Check for patterns that indicate stream cipher encryption.
        
        Args:
            data: Data to analyze
            details: Dictionary to update with findings
            
        Returns:
            True if stream cipher patterns detected, False otherwise
        """
        # Stream ciphers typically produce very high entropy data
        entropy = self._calculate_entropy(data)
        
        if entropy > 7.99:
            # ChaCha20 and Salsa20 often have "expand 32-byte k" constant
            if b'expand 32-byte k' in data:
                details["likely_algorithm"] = "ChaCha20/Salsa20"
                details["confidence"] = 0.9
                return True
                
            details["likely_algorithm"] = "RC4 or other stream cipher"
            details["confidence"] = 0.5
            return True
            
        return False
    
    def _identify_ransomware_family(self, results: Dict[str, Any]) -> None:
        """
        Identify the most likely ransomware family based on analysis results.
        
        Args:
            results: Analysis results dictionary to update
        """
        potential_family = results.get("potential_family")
        confidence = results.get("encryption_confidence", 0.0)
        
        if potential_family:
            # Already identified from extension or marker
            return
            
        # Try to identify based on other characteristics
        family_indicators = {
            # WannaCry: AES + RSA, specific markers
            "WannaCry": [
                lambda r: "header_analysis" in r and "known_marker" in r["header_analysis"] and "WANACRY" in r["header_analysis"]["known_marker"],
                lambda r: r["extension"] in ['.wncry', '.wcry', '.wncryt', '.wncrypt'],
                lambda r: "encryption_details" in r and r["encryption_details"].get("likely_algorithm") == "AES" and r["encryption_details"].get("mode") == "CBC"
            ],
            
            # Ryuk: AES + RSA, HERMES marker
            "Ryuk": [
                lambda r: "header_analysis" in r and "known_marker" in r["header_analysis"] and "HERMES" in r["header_analysis"]["known_marker"],
                lambda r: r["extension"] in ['.ryk', '.ryuk', '.RYK'],
                lambda r: "encryption_details" in r and r["encryption_details"].get("likely_algorithm") == "AES" and r["encryption_details"].get("mode") == "CBC"
            ],
            
            # REvil: Salsa20 + RSA, specific extensions
            "REvil": [
                lambda r: r["extension"] in ['.revil', '.sodinokibi', '.sodin'],
                lambda r: "encryption_details" in r and r["encryption_details"].get("likely_algorithm") == "ChaCha20/Salsa20",
                lambda r: "header_analysis" in r and r["header_analysis"].get("potential_json_data", False)
            ],
            
            # LockBit: AES + RSA, LOCK marker
            "LockBit": [
                lambda r: "header_analysis" in r and "known_marker" in r["header_analysis"] and "LOCK" in r["header_analysis"]["known_marker"],
                lambda r: r["extension"] in ['.lockbit', '.lock'],
                lambda r: "encryption_details" in r and r["encryption_details"].get("likely_algorithm") == "AES"
            ],
            
            # STOP/DJVU: RSA + Salsa20, specific extensions
            "STOP": [
                lambda r: r["extension"] in ['.djvu', '.djvus', '.djvur', '.uudjvu'],
                lambda r: "header_analysis" in r and r["header_analysis"].get("potential_base64_data", False),
                lambda r: "encryption_details" in r and (r["encryption_details"].get("likely_algorithm") == "ChaCha20/Salsa20" or 
                                                      r["encryption_details"].get("likely_algorithm") == "RC4 or other stream cipher")
            ]
        }
        
        # Check each family's indicators
        family_scores = {}
        
        for family, indicators in family_indicators.items():
            # Count how many indicators match
            matches = sum(1 for indicator in indicators if indicator(results))
            if matches > 0:
                score = matches / len(indicators)
                family_scores[family] = score
                
        if family_scores:
            # Select the family with the highest score
            best_family, best_score = max(family_scores.items(), key=lambda x: x[1])
            results["potential_family"] = best_family
            results["family_confidence"] = best_score
            results["encryption_confidence"] = max(confidence, best_score * 0.8)
        else:
            # Generic detection based on entropy
            if results["entropy"] > 7.0:
                results["potential_family"] = "Generic Ransomware"
                results["family_confidence"] = 0.4
                results["encryption_confidence"] = max(confidence, 0.4)
    
    def _calculate_confidence(self, results: Dict[str, Any]) -> None:
        """
        Calculate overall confidence in the analysis.
        
        Args:
            results: Analysis results dictionary to update
        """
        # Factors influencing confidence:
        # 1. Entropy (higher = more likely encrypted)
        # 2. Known markers or extensions
        # 3. Encryption algorithm detection confidence
        # 4. File structure abnormalities
        
        confidence = results.get("encryption_confidence", 0.0)
        
        # Adjust based on entropy
        entropy = results.get("entropy", 0.0)
        if entropy > 7.9:
            confidence = max(confidence, 0.8)
        elif entropy > 7.5:
            confidence = max(confidence, 0.6)
        elif entropy > 7.0:
            confidence = max(confidence, 0.4)
        elif entropy < 6.0:
            confidence = min(confidence, 0.3)  # Likely not encrypted
            
        # Adjust based on algorithm detection
        if "encryption_details" in results and "confidence" in results["encryption_details"]:
            algorithm_confidence = results["encryption_details"]["confidence"]
            confidence = max(confidence, algorithm_confidence)
            
        # Final confidence calculation
        results["encryption_confidence"] = round(confidence, 2)
        
        # Add textual assessment
        if confidence > 0.8:
            results["assessment"] = "High confidence - almost certainly encrypted by ransomware"
        elif confidence > 0.6:
            results["assessment"] = "Medium confidence - likely encrypted by ransomware"
        elif confidence > 0.4:
            results["assessment"] = "Low confidence - possibly encrypted by ransomware"
        else:
            results["assessment"] = "Very low confidence - probably not encrypted by ransomware"

def main():
    """Command-line interface for the encryption analyzer."""
    import argparse
    import json
    
    parser = argparse.ArgumentParser(description="Ransomware Encryption Analyzer")
    parser.add_argument('file', help='File to analyze')
    parser.add_argument('--output', '-o', help='Output file for analysis results (JSON)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show verbose output')
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Analyze file
    analyzer = EncryptionAnalyzer()
    results = analyzer.analyze_file(args.file)
    
    # Print summary
    print(f"\nAnalysis of {os.path.basename(args.file)}:")
    print(f"Size: {results['file_size']} bytes")
    print(f"Entropy: {results['entropy']:.2f} / 8.00")
    
    if "potential_family" in results:
        family_confidence = results.get("family_confidence", results.get("encryption_confidence", 0.0))
        print(f"Potential Ransomware Family: {results['potential_family']} (Confidence: {family_confidence:.2f})")
        
    if "encryption_details" in results and "likely_algorithm" in results["encryption_details"]:
        algo = results["encryption_details"]["likely_algorithm"]
        mode = results["encryption_details"].get("mode", "")
        print(f"Likely Encryption: {algo} {mode}")
        
    print(f"Assessment: {results.get('assessment', 'Unknown')}")
    
    # Show detailed results if verbose
    if args.verbose:
        print("\nDetailed Analysis:")
        
        if "header_analysis" in results:
            print("\nHeader Analysis:")
            for key, value in results["header_analysis"].items():
                print(f"  {key}: {value}")
                
        if "encryption_details" in results:
            print("\nEncryption Details:")
            for key, value in results["encryption_details"].items():
                print(f"  {key}: {value}")
                
        if "file_structure" in results:
            print("\nFile Structure:")
            for key, value in results["file_structure"].items():
                print(f"  {key}: {value}")
    
    # Save results if output file specified
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
            print(f"\nDetailed results saved to {args.output}")
    
if __name__ == "__main__":
    main()