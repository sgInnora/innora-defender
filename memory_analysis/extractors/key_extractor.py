#!/usr/bin/env python3
"""
Ransomware Memory Key Extractor
Scans memory dumps for encryption keys and related artifacts to help with ransomware analysis.
"""

import os
import re
import json
import math
import struct
import logging
import datetime
import binascii
from typing import Dict, List, Any, Optional, Set, Tuple, BinaryIO, Union
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('key_extractor')

class MemoryKeyExtractor:
    """Extracts encryption keys and related artifacts from memory dumps"""
    
    def __init__(self, patterns_file=None):
        """
        Initialize the memory key extractor
        
        Args:
            patterns_file: Path to patterns JSON file (optional)
        """
        self.patterns = self._load_patterns(patterns_file)
        self.results_cache = {}
    
    def _load_patterns(self, patterns_file=None) -> Dict:
        """
        Load key patterns from file or use defaults
        
        Args:
            patterns_file: Path to patterns file
            
        Returns:
            Dictionary of patterns
        """
        default_patterns = {
            "aes_keys": {
                "patterns": [
                    # AES key schedule patterns (simplified)
                    rb"(.{16})(.{16})(.{16})(.{16})(.{16})(.{16})(.{16})(.{16})(.{16})(.{16})(.{16})",
                    rb"(.{32})(.{32})(.{32})(.{32})(.{32})",
                ],
                "entropy_threshold": 3.5,
                "min_key_length": 16,
                "max_key_length": 32,
                "validation": "aes_key_check"
            },
            "rsa_keys": {
                "patterns": [
                    # RSA key markers
                    rb"-----BEGIN RSA PRIVATE KEY-----(.{100,3000})-----END RSA PRIVATE KEY-----",
                    rb"-----BEGIN PRIVATE KEY-----(.{100,3000})-----END PRIVATE KEY-----",
                    # RSA key components in binary format
                    rb"(?:\x02\x82.{2})(.{128,1024})(?:\x02\x82.{2})",
                ],
                "entropy_threshold": 4.0,
                "min_key_length": 128,
                "max_key_length": 4096,
                "validation": "rsa_key_check"
            },
            "bitcoin_addresses": {
                "patterns": [
                    # Bitcoin address patterns
                    rb"[13][a-km-zA-HJ-NP-Z1-9]{25,34}",
                    rb"bc1[a-zA-Z0-9]{25,90}"
                ],
                "validation": "bitcoin_address_check"
            },
            "bitcoin_keys": {
                "patterns": [
                    # Bitcoin private key patterns
                    rb"[5KL][1-9A-HJ-NP-Za-km-z]{50,52}",
                    # Bitcoin seed phrases
                    rb"(?:word|seed|mnemonic|phrase)[^\n]{10,200}[a-z]{3,10} [a-z]{3,10}( [a-z]{3,10}){10,22}"
                ],
                "validation": "bitcoin_key_check"
            },
            "ransom_notes": {
                "patterns": [
                    # Common ransom note patterns
                    rb"(YOUR FILES HAVE BEEN ENCRYPTED)[^\n]{10,1000}",
                    rb"(All your files have been encrypted)[^\n]{10,1000}",
                    rb"(WHAT HAPPENED TO MY FILES\?)[^\n]{10,1000}",
                    rb"(HOW TO DECRYPT)[^\n]{10,1000}",
                    rb"(ATTENTION\!)[^\n]{10,100}(FILES ENCRYPTED|ENCRYPTED FILES|RANSOMWARE|CRYPTED)",
                    rb"(HOW TO RECOVER|HOW TO RESTORE|HOW TO DECRYPT)[^\n]{10,1000}",
                    rb"([Bb]itcoin|[Bb]TC|[Mm]onero|XMR|[Dd]ash)[^\n]{10,200}([Pp]ay|[Pp]ayment|[Rr]ansom)[^\n]{10,200}([Aa]ddress|[Ww]allet)"
                ],
                "validation": "ransom_note_check"
            },
            "command_and_control": {
                "patterns": [
                    # C2 server indicators
                    rb"https?://[a-zA-Z0-9\.\-]{5,50}\.(?:com|net|org|biz|info|xyz|onion)[^\s]{0,100}",
                    rb"(?:server|host|gateway|c2)[^\n]{1,30}[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",
                    rb"tor[^\n]{1,20}[a-zA-Z0-9]{16}\.onion"
                ],
                "validation": "url_check"
            },
            "known_family_patterns": {
                "locky": {
                    "patterns": [
                        rb"_Locky_recover_instructions\.txt",
                        rb"Locky_recover_instructions\.bmp",
                        rb"locky_decrypt"
                    ],
                    "validation": None
                },
                "ryuk": {
                    "patterns": [
                        rb"RyukReadMe\.txt",
                        rb"UNIQUE_ID_DO_NOT_REMOVE",
                        rb"RyukReadMe\.html"
                    ],
                    "validation": None
                },
                "wannacry": {
                    "patterns": [
                        rb"@WanaDecryptor@",
                        rb"taskdl\.exe",
                        rb"taskse\.exe",
                        rb"wanacry"
                    ],
                    "validation": None
                },
                "gandcrab": {
                    "patterns": [
                        rb"GANDCRAB",
                        rb"KRAB",
                        rb"-DECRYPT\.txt",
                        rb"\.CRAB"
                    ],
                    "validation": None
                },
                "petya": {
                    "patterns": [
                        rb"petya",
                        rb"perfc\.dat",
                        rb"CHKDSK is repairing",
                        rb"NotPetya"
                    ],
                    "validation": None
                }
            }
        }
        
        if patterns_file and os.path.exists(patterns_file):
            try:
                with open(patterns_file, 'r') as f:
                    patterns = json.load(f)
                
                # Precompile regexes for loaded patterns
                self._precompile_patterns(patterns)
                
                return patterns
            except Exception as e:
                logger.error(f"Error loading patterns: {e}")
                # Continue with default patterns
        
        # Precompile regexes for default patterns
        self._precompile_patterns(default_patterns)
        
        return default_patterns
    
    def _precompile_patterns(self, patterns: Dict) -> None:
        """
        Precompile regex patterns for efficiency
        
        Args:
            patterns: Patterns dictionary to compile
        """
        for category, config in patterns.items():
            if category == "known_family_patterns":
                # Compile family patterns
                for family, family_config in config.items():
                    if "patterns" in family_config:
                        family_config["compiled"] = [re.compile(p) for p in family_config["patterns"]]
            else:
                # Compile regular patterns
                if "patterns" in config:
                    config["compiled"] = [re.compile(p) for p in config["patterns"]]
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data
        
        Args:
            data: Bytes to calculate entropy for
            
        Returns:
            Entropy value (0-8)
        """
        if not data:
            return 0.0
            
        entropy = 0.0
        for byte_value in range(256):
            p_x = data.count(bytes([byte_value])) / len(data)
            if p_x > 0:
                entropy -= p_x * math.log(p_x, 2)
        return entropy
    
    def _aes_key_check(self, data: bytes) -> bool:
        """
        Basic validation for AES key candidates
        
        Args:
            data: Potential AES key data
            
        Returns:
            True if data passes validation, False otherwise
        """
        # Check length
        if len(data) not in [16, 24, 32]:  # AES-128, AES-192, AES-256
            return False
            
        # Check entropy
        entropy = self._calculate_entropy(data)
        if entropy < 3.5:  # Low entropy keys are unlikely
            return False
            
        return True
    
    def _rsa_key_check(self, data: bytes) -> bool:
        """
        Basic validation for RSA key candidates
        
        Args:
            data: Potential RSA key data
            
        Returns:
            True if data passes validation, False otherwise
        """
        # Look for PEM format indicators
        if b"RSA PRIVATE KEY" in data or b"PRIVATE KEY" in data:
            return True
            
        # If not PEM, check for ASN.1 structure indicators
        if data.startswith(b'\x30'):  # ASN.1 SEQUENCE
            return True
            
        # Check for common OpenSSL key export format
        if b"OpenSSL" in data and (b"Private" in data or b"PRIVATE" in data):
            return True
            
        return False
    
    def _bitcoin_address_check(self, data: bytes) -> bool:
        """
        Basic validation for Bitcoin address candidates
        
        Args:
            data: Potential Bitcoin address data
            
        Returns:
            True if data passes validation, False otherwise
        """
        try:
            # Convert to string for validation
            address = data.decode('ascii').strip()
            
            # Basic format check
            if len(address) < 26 or len(address) > 35:
                return False
                
            # Check for valid characters
            if not all(c in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" for c in address):
                return False
                
            # Note: A real implementation would include base58 checksum validation
                
            return True
        except:
            return False
    
    def _bitcoin_key_check(self, data: bytes) -> bool:
        """
        Basic validation for Bitcoin key candidates
        
        Args:
            data: Potential Bitcoin key data
            
        Returns:
            True if data passes validation, False otherwise
        """
        try:
            # Convert to string for validation
            key_data = data.decode('ascii').strip()
            
            # Check for WIF format
            if len(key_data) >= 50 and len(key_data) <= 52 and key_data[0] in "5KL":
                return all(c in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" for c in key_data)
                
            # Check for BIP39 mnemonic (seed phrase)
            if "word" in key_data.lower() or "seed" in key_data.lower() or "mnemonic" in key_data.lower():
                # Count potential words in a seed phrase (12, 15, 18, 21, 24 words)
                words = [w for w in re.findall(r'[a-z]{3,10}', key_data.lower()) if len(w) >= 3]
                return len(words) in [12, 15, 18, 21, 24]
                
            return False
        except:
            return False
    
    def _ransom_note_check(self, data: bytes) -> bool:
        """
        Basic validation for ransomware note candidates
        
        Args:
            data: Potential ransom note data
            
        Returns:
            True if data passes validation, False otherwise
        """
        try:
            # Convert to string for validation
            note_data = data.decode('ascii', errors='ignore').strip()
            
            # Check for common ransomware terms
            ransom_terms = [
                "encrypt", "decrypt", "bitcoin", "payment", "ransom", "files", "locked",
                "key", "pay", "btc", "restore", "recover", "monero", "xmr", "wallet",
                "deadline", "hours", "unlock", "instruction", "private key"
            ]
            
            # Count how many terms are found
            terms_found = sum(1 for term in ransom_terms if term.lower() in note_data.lower())
            
            # If at least 3 terms are found, it's likely a ransom note
            return terms_found >= 3
        except:
            return False
    
    def _url_check(self, data: bytes) -> bool:
        """
        Basic validation for URL/C2 candidates
        
        Args:
            data: Potential URL/C2 data
            
        Returns:
            True if data passes validation, False otherwise
        """
        try:
            # Convert to string for validation
            url_data = data.decode('ascii', errors='ignore').strip()
            
            # Check for URL format
            if url_data.startswith(("http://", "https://")):
                # Basic URL format validation
                url_pattern = r'^https?://[a-zA-Z0-9\.\-]{5,}(?:\.[a-zA-Z]{2,})+(?:[/\?][^\s]*)?$'
                return re.match(url_pattern, url_data) is not None
                
            # Check for IP address format
            ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?$'
            if re.match(ip_pattern, url_data):
                # Basic validation of IP address components
                parts = url_data.split(':')[0].split('.')
                return all(0 <= int(p) <= 255 for p in parts)
                
            # Check for .onion address format
            if ".onion" in url_data:
                onion_pattern = r'^[a-zA-Z0-9]{16}\.onion(?::[0-9]{1,5})?$'
                return re.match(onion_pattern, url_data) is not None
                
            return False
        except:
            return False
    
    def _validate_match(self, match: bytes, validation_method: str) -> bool:
        """
        Validate a pattern match using the specified validation method
        
        Args:
            match: Matched data
            validation_method: Name of validation method to use
            
        Returns:
            True if match passes validation, False otherwise
        """
        if validation_method is None:
            return True
            
        if validation_method == "aes_key_check":
            return self._aes_key_check(match)
        elif validation_method == "rsa_key_check":
            return self._rsa_key_check(match)
        elif validation_method == "bitcoin_address_check":
            return self._bitcoin_address_check(match)
        elif validation_method == "bitcoin_key_check":
            return self._bitcoin_key_check(match)
        elif validation_method == "ransom_note_check":
            return self._ransom_note_check(match)
        elif validation_method == "url_check":
            return self._url_check(match)
            
        return True  # If unknown validation method, assume valid
    
    def search_memory_dump(self, dump_file: str, offset: int = 0, 
                         max_size: int = None) -> Dict:
        """
        Search a memory dump file for encryption keys and artifacts
        
        Args:
            dump_file: Path to memory dump file
            offset: Byte offset to start search from
            max_size: Maximum bytes to search (None for entire file)
            
        Returns:
            Dictionary containing all found artifacts
        """
        # Check if we've already processed this dump file
        cache_key = f"{dump_file}_{offset}_{max_size}"
        if cache_key in self.results_cache:
            return self.results_cache[cache_key]
        
        results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "dump_file": dump_file,
            "file_size": os.path.getsize(dump_file),
            "search_offset": offset,
            "search_size": max_size,
            "findings": {}
        }
        
        try:
            with open(dump_file, 'rb') as f:
                # Seek to offset
                f.seek(offset)
                
                # Determine how much to read
                if max_size is None:
                    data = f.read()
                else:
                    data = f.read(max_size)
                
                # Search for patterns
                for category, config in self.patterns.items():
                    if category == "known_family_patterns":
                        # Search for family-specific patterns
                        family_findings = {}
                        
                        for family, family_config in config.items():
                            family_matches = []
                            
                            for i, pattern in enumerate(family_config.get("compiled", [])):
                                for match in pattern.finditer(data):
                                    match_data = match.group(0)
                                    
                                    # Validate if needed
                                    validation_method = family_config.get("validation")
                                    if validation_method and not self._validate_match(match_data, validation_method):
                                        continue
                                    
                                    # Add to findings
                                    family_matches.append({
                                        "offset": offset + match.start(),
                                        "length": len(match_data),
                                        "pattern_index": i,
                                        "hex": match_data.hex()[:100] + "..." if len(match_data) > 50 else match_data.hex(),
                                        "ascii": match_data.decode('ascii', errors='replace')[:100] + "..." if len(match_data) > 50 else match_data.decode('ascii', errors='replace')
                                    })
                            
                            if family_matches:
                                family_findings[family] = family_matches
                        
                        if family_findings:
                            results["findings"]["ransomware_families"] = family_findings
                    else:
                        # Search for regular patterns
                        matches = []
                        
                        for i, pattern in enumerate(config.get("compiled", [])):
                            for match in pattern.finditer(data):
                                # Extract the match or the first capture group if there is one
                                if len(match.groups()) > 0:
                                    match_data = match.group(1)
                                else:
                                    match_data = match.group(0)
                                
                                # Validate match if needed
                                validation_method = config.get("validation")
                                if validation_method and not self._validate_match(match_data, validation_method):
                                    continue
                                
                                # For keys, check entropy and size constraints
                                if category in ["aes_keys", "rsa_keys"]:
                                    entropy = self._calculate_entropy(match_data)
                                    min_key_length = config.get("min_key_length", 0)
                                    max_key_length = config.get("max_key_length", float('inf'))
                                    entropy_threshold = config.get("entropy_threshold", 0)
                                    
                                    if (len(match_data) < min_key_length or 
                                        len(match_data) > max_key_length or
                                        entropy < entropy_threshold):
                                        continue
                                
                                # Add to findings
                                matches.append({
                                    "offset": offset + match.start(),
                                    "length": len(match_data),
                                    "pattern_index": i,
                                    "entropy": self._calculate_entropy(match_data) if category in ["aes_keys", "rsa_keys"] else None,
                                    "hex": match_data.hex()[:100] + "..." if len(match_data) > 50 else match_data.hex(),
                                    "ascii": match_data.decode('ascii', errors='replace')[:100] + "..." if len(match_data) > 50 else match_data.decode('ascii', errors='replace')
                                })
                        
                        if matches:
                            results["findings"][category] = matches
        
        except Exception as e:
            logger.error(f"Error searching memory dump: {e}")
            results["error"] = str(e)
        
        # Cache results
        self.results_cache[cache_key] = results
        
        return results
    
    def search_process_memory(self, pid: int, output_dir: str = None) -> Dict:
        """
        Search memory of a running process
        
        Args:
            pid: Process ID to search
            output_dir: Directory to save memory regions (optional)
            
        Returns:
            Dictionary containing all found artifacts
        """
        results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "pid": pid,
            "memory_regions": [],
            "findings": {}
        }
        
        # This is a placeholder implementation
        # In a real implementation, this would:
        # 1. Use platform-specific methods to access process memory
        # 2. Iterate through memory regions
        # 3. Dump each region to a file if output_dir is specified
        # 4. Search each region for patterns
        
        logger.warning("Process memory search is not implemented for this platform")
        results["error"] = "Process memory search not implemented for this platform"
        
        return results
    
    def extract_key_from_offset(self, dump_file: str, offset: int, 
                              key_type: str, key_size: int = None) -> Dict:
        """
        Extract a key from specific offset in a memory dump
        
        Args:
            dump_file: Path to memory dump file
            offset: Byte offset to extract from
            key_type: Type of key ('aes', 'rsa', etc.)
            key_size: Size of key in bytes (optional)
            
        Returns:
            Dictionary containing extracted key
        """
        key_sizes = {
            'aes': [16, 24, 32],  # AES-128, AES-192, AES-256
            'rsa': [128, 256, 512, 1024, 2048, 4096]  # Common RSA key sizes in bytes
        }
        
        result = {
            "timestamp": datetime.datetime.now().isoformat(),
            "dump_file": dump_file,
            "offset": offset,
            "key_type": key_type,
            "key_size": key_size
        }
        
        try:
            with open(dump_file, 'rb') as f:
                f.seek(offset)
                
                # Determine how much to read
                if key_size is not None:
                    data = f.read(key_size)
                elif key_type.lower() in key_sizes:
                    # Try to auto-detect key size
                    sizes = key_sizes[key_type.lower()]
                    data = f.read(max(sizes))
                else:
                    # Default to reading a larger chunk
                    data = f.read(4096)
                
                result["key_data"] = {
                    "hex": data.hex(),
                    "base64": binascii.b2a_base64(data).decode('ascii').strip(),
                    "length": len(data),
                    "entropy": self._calculate_entropy(data)
                }
                
                # Try to format key in a standard way
                if key_type.lower() == 'aes':
                    # Format AES key for tool usage
                    result["key_formatted"] = ':'.join(format(x, '02x') for x in data)
                elif key_type.lower() == 'rsa':
                    # For RSA, check if it's in PEM format
                    if b"-----BEGIN RSA PRIVATE KEY-----" in data:
                        result["key_formatted"] = data.decode('ascii', errors='ignore')
                    else:
                        # Otherwise, provide raw hex
                        result["key_formatted"] = data.hex()
        
        except Exception as e:
            logger.error(f"Error extracting key: {e}")
            result["error"] = str(e)
        
        return result
    
    def identify_ransomware_family(self, dump_file: str) -> Dict:
        """
        Attempt to identify the ransomware family from a memory dump
        
        Args:
            dump_file: Path to memory dump file
            
        Returns:
            Dictionary containing identified family and confidence score
        """
        # Search for family-specific patterns
        search_results = self.search_memory_dump(dump_file)
        
        result = {
            "timestamp": datetime.datetime.now().isoformat(),
            "dump_file": dump_file,
            "identified_families": []
        }
        
        # Check if any family-specific patterns were found
        family_findings = search_results.get("findings", {}).get("ransomware_families", {})
        
        for family, matches in family_findings.items():
            # Calculate confidence based on number of matches
            confidence = min(0.95, 0.5 + 0.1 * len(matches))  # Max confidence 95%
            
            result["identified_families"].append({
                "name": family,
                "confidence": confidence,
                "match_count": len(matches),
                "first_match": matches[0] if matches else None
            })
        
        # Sort by confidence
        result["identified_families"].sort(key=lambda x: x["confidence"], reverse=True)
        
        return result
    
    def analyze_memory_dump(self, dump_file: str) -> Dict:
        """
        Perform complete analysis of a memory dump
        
        Args:
            dump_file: Path to memory dump file
            
        Returns:
            Dictionary containing analysis results
        """
        result = {
            "timestamp": datetime.datetime.now().isoformat(),
            "dump_file": dump_file,
            "file_size": os.path.getsize(dump_file),
            "analysis": {}
        }
        
        # Step 1: Search for all patterns
        search_results = self.search_memory_dump(dump_file)
        result["artifacts"] = search_results.get("findings", {})
        
        # Step 2: Try to identify the ransomware family
        family_identification = self.identify_ransomware_family(dump_file)
        result["analysis"]["identified_families"] = family_identification.get("identified_families", [])
        
        # Step 3: Summarize findings
        summary = {
            "key_candidates": {
                "aes": len(result["artifacts"].get("aes_keys", [])),
                "rsa": len(result["artifacts"].get("rsa_keys", []))
            },
            "bitcoin_addresses": len(result["artifacts"].get("bitcoin_addresses", [])),
            "bitcoin_keys": len(result["artifacts"].get("bitcoin_keys", [])),
            "ransom_notes": len(result["artifacts"].get("ransom_notes", [])),
            "command_and_control": len(result["artifacts"].get("command_and_control", [])),
            "ransomware_families": {}
        }
        
        # Summarize family findings
        family_findings = result["artifacts"].get("ransomware_families", {})
        for family, matches in family_findings.items():
            summary["ransomware_families"][family] = len(matches)
        
        result["analysis"]["summary"] = summary
        
        # Step 4: Extract the most promising encryption keys
        promising_keys = []
        
        # Add AES keys
        aes_keys = result["artifacts"].get("aes_keys", [])
        sorted_aes = sorted(aes_keys, key=lambda k: k.get("entropy", 0), reverse=True)
        promising_keys.extend([
            {
                "type": "aes",
                "length": k["length"],
                "offset": k["offset"],
                "entropy": k["entropy"],
                "hex": k["hex"],
                "ascii": k["ascii"]
            } for k in sorted_aes[:5]  # Top 5 AES candidates
        ])
        
        # Add RSA keys
        rsa_keys = result["artifacts"].get("rsa_keys", [])
        sorted_rsa = sorted(rsa_keys, key=lambda k: k.get("entropy", 0), reverse=True)
        promising_keys.extend([
            {
                "type": "rsa",
                "length": k["length"],
                "offset": k["offset"],
                "entropy": k["entropy"],
                "hex": k["hex"],
                "ascii": k["ascii"]
            } for k in sorted_rsa[:3]  # Top 3 RSA candidates
        ])
        
        result["analysis"]["promising_keys"] = promising_keys
        
        # Step 5: Add basic recommendations
        recommendations = []
        
        if promising_keys:
            recommendations.append({
                "type": "key_extraction",
                "priority": "high",
                "description": f"Extract and test the {len(promising_keys)} identified key candidates using decrypt_test.py",
                "details": "Use the extract_key_from_offset() method with the offsets listed in promising_keys"
            })
        
        if result["analysis"]["identified_families"]:
            top_family = result["analysis"]["identified_families"][0]
            recommendations.append({
                "type": "family_specific",
                "priority": "high",
                "description": f"Search for known decryptors for {top_family['name']} ransomware",
                "details": f"Family identified with {top_family['confidence']:.0%} confidence"
            })
        
        if summary["ransom_notes"] > 0:
            recommendations.append({
                "type": "ransom_note_analysis",
                "priority": "medium",
                "description": "Extract and analyze the complete ransom notes to identify payment information",
                "details": f"Found {summary['ransom_notes']} potential ransom notes in memory"
            })
        
        result["analysis"]["recommendations"] = recommendations
        
        return result


def main():
    """Main function for command-line usage"""
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description="Ransomware Memory Key Extractor")
    parser.add_argument('--dump', '-d', required=True, help='Path to memory dump file')
    parser.add_argument('--patterns', '-p', help='Path to patterns JSON file')
    parser.add_argument('--output', '-o', help='Output JSON file for results')
    parser.add_argument('--extract-key', '-e', help='Extract key from specific offset')
    parser.add_argument('--key-type', '-t', help='Type of key to extract (aes, rsa)')
    parser.add_argument('--key-size', '-s', type=int, help='Size of key to extract in bytes')
    parser.add_argument('--full-analysis', '-f', action='store_true', help='Perform full analysis of memory dump')
    
    args = parser.parse_args()
    
    extractor = MemoryKeyExtractor(args.patterns)
    
    try:
        if args.extract_key:
            # Extract key from specific offset
            offset = int(args.extract_key, 0)  # Parse as int, supporting hex with 0x prefix
            if not args.key_type:
                logger.error("Key type must be specified with --key-type")
                sys.exit(1)
                
            result = extractor.extract_key_from_offset(
                args.dump, offset, args.key_type, args.key_size
            )
        elif args.full_analysis:
            # Perform full analysis
            result = extractor.analyze_memory_dump(args.dump)
        else:
            # Default: search for patterns
            result = extractor.search_memory_dump(args.dump)
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2)
        else:
            print(json.dumps(result, indent=2))
        
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
    
    sys.exit(0)


if __name__ == "__main__":
    main()