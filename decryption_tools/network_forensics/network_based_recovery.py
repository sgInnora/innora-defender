#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network-Based Ransomware Recovery Module

This module provides specialized capabilities for extracting encryption keys and parameters
from network traffic to assist with ransomware decryption. It integrates with the existing
decryption tools and ransomware family database to enhance recovery options.

Key features:
- Analysis of network captures (PCAP files) for encryption key material
- Extraction of ransomware configuration from C2 communications
- Identification of key exchange patterns in network traffic
- Memory correlation with network communications
- Integration with encryption_analyzer.py for enhanced decryption capabilities

Usage:
    extractor = NetworkKeyExtractor('capture.pcap')
    keys = extractor.extract_potential_keys()
    recovery = NetworkBasedRecovery(keys)
    recovery.attempt_decryption('encrypted_file.txt')
"""

import os
import re
import json
import struct
import base64
import binascii
import logging
import ipaddress
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional, Union, Any, BinaryIO
from dataclasses import dataclass, field
import threading
from pathlib import Path
import tempfile
import hashlib

# Optional dependencies
try:
    import dpkt
    from dpkt.ethernet import Ethernet
    from dpkt.ip import IP
    from dpkt.tcp import TCP
    from dpkt.udp import UDP
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False

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
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("NetworkBasedRecovery")


@dataclass
class ExtractedKey:
    """Data class for keys extracted from network traffic"""
    key_data: bytes
    key_type: str  # 'aes', 'rsa', 'chacha20', etc.
    source_ip: str
    destination_ip: str
    timestamp: datetime
    confidence: float
    context: Dict[str, Any]
    format: str = "raw"  # 'raw', 'base64', 'hex'
    key_id: str = field(init=False)
    
    def __post_init__(self):
        """Generate a unique key ID after initialization"""
        source = f"{self.source_ip}-{self.destination_ip}"
        key_hash = hashlib.sha256(self.key_data).hexdigest()[:16]
        timestamp = self.timestamp.strftime("%Y%m%d%H%M%S")
        self.key_id = f"{self.key_type}-{key_hash}-{timestamp}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert key to dictionary for serialization"""
        return {
            "key_id": self.key_id,
            "key_type": self.key_type,
            "key_data_hex": self.key_data.hex(),
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "timestamp": self.timestamp.isoformat(),
            "confidence": self.confidence,
            "context": self.context,
            "format": self.format
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ExtractedKey':
        """Create ExtractedKey instance from dictionary"""
        key_data = bytes.fromhex(data["key_data_hex"])
        timestamp = datetime.fromisoformat(data["timestamp"])
        
        key = cls(
            key_data=key_data,
            key_type=data["key_type"],
            source_ip=data["source_ip"],
            destination_ip=data["destination_ip"],
            timestamp=timestamp,
            confidence=data["confidence"],
            context=data["context"],
            format=data.get("format", "raw")
        )
        key.key_id = data["key_id"]
        return key


class NetworkKeyExtractor:
    """Extracts potential encryption keys from network traffic"""
    
    def __init__(self, pcap_file: Optional[str] = None):
        """
        Initialize the key extractor
        
        Args:
            pcap_file: Optional path to PCAP file to analyze
        """
        self.pcap_file = pcap_file
        self.families_db_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "external", "data", "families"
        )
        self.families_data = self._load_families_data()
        self.network_patterns = self._load_network_patterns()
        
        # Patterns for key identification
        self.key_patterns = {
            'aes': [
                # Common patterns for AES keys in memory and network
                rb'\x00{4}[\x10\x18\x20][\x00-\xFF]{16,32}\x00{4}',  # AES key with size indicator
                rb'AES[_-]KEY[_=:]\s*([A-Za-z0-9+/=]{24,88})',  # AES key in base64
                rb'key[_=:]\s*([A-Fa-f0-9]{32,64})',  # Hex-encoded key
            ],
            'rsa': [
                # RSA key identification patterns
                rb'-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----',
                rb'-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----',
                rb'MII[A-Za-z0-9+/=]{10,}',  # PEM-encoded RSA key (base64)
            ],
            'chacha20': [
                # ChaCha20 key patterns (32 bytes)
                rb'ChaCha20.*?key[_=:]\s*([A-Za-z0-9+/=]{42,46})', 
                rb'ChaCha20.*?([A-Fa-f0-9]{64})',  # Hex-encoded key
            ],
            'salsa20': [
                # Salsa20 key patterns
                rb'Salsa20.*?key[_=:]\s*([A-Za-z0-9+/=]{42,46})',
                rb'Salsa20.*?([A-Fa-f0-9]{64})',  # Hex-encoded key
            ]
        }
        
        # C2 communication patterns
        self.c2_patterns = {}
        for family, data in self.families_data.items():
            family_patterns = {}
            
            # Extract patterns from detection signatures
            sig_data = data.get("detection_signatures", {})
            for rule_type, rules in sig_data.items():
                for rule in rules:
                    # Look for content patterns in rules
                    matches = re.findall(r'content:\"(.*?)\"', rule)
                    for match in matches:
                        # Filter out very short or common patterns
                        if len(match) > 4 and match not in [".onion", "POST", "GET", "HTTP"]:
                            pattern = match.encode('utf-8', errors='ignore')
                            family_patterns[pattern] = 0.6  # Medium confidence
            
            # Traffic pattern descriptions
            traffic_patterns = data.get("traffic_patterns", [])
            for pattern_data in traffic_patterns:
                if isinstance(pattern_data, dict) and "pattern" in pattern_data:
                    pattern_desc = pattern_data["pattern"]
                    # Extract key terms from pattern descriptions
                    key_terms = re.findall(r'([A-Za-z0-9-_]{4,})', pattern_desc)
                    for term in key_terms:
                        if len(term) > 4 and not term.lower() in ['http', 'https', 'traffic', 'with']:
                            pattern = term.encode('utf-8', errors='ignore')
                            family_patterns[pattern] = 0.4  # Lower confidence
            
            if family_patterns:
                self.c2_patterns[family] = family_patterns
    
    def _load_families_data(self) -> Dict[str, Any]:
        """Load ransomware family data from JSON files"""
        families_data = {}
        
        if not os.path.exists(self.families_db_path):
            logger.warning(f"Families database path not found: {self.families_db_path}")
            return families_data
        
        for filename in os.listdir(self.families_db_path):
            if filename.endswith('.json') and filename != 'index.json':
                try:
                    file_path = os.path.join(self.families_db_path, filename)
                    with open(file_path, 'r') as f:
                        family_data = json.load(f)
                        name = family_data.get('name')
                        if name:
                            families_data[name] = family_data
                except (json.JSONDecodeError, PermissionError) as e:
                    logger.error(f"Error loading family data from {filename}: {e}")
        
        return families_data
    
    def _load_network_patterns(self) -> Dict[str, Any]:
        """Load network patterns database"""
        pattern_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "threat_intel", "data", "ransomware_network_patterns.json"
        )
        
        try:
            with open(pattern_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning(f"Could not load network patterns: {e}")
            return {"families": {}, "version": "1.0"}
    
    def analyze_pcap(self, pcap_file: Optional[str] = None) -> List[ExtractedKey]:
        """
        Analyze a PCAP file to extract potential encryption keys
        
        Args:
            pcap_file: Optional PCAP file path (uses self.pcap_file if None)
            
        Returns:
            List of ExtractedKey objects found in the PCAP
        """
        file_to_analyze = pcap_file or self.pcap_file
        if not file_to_analyze:
            logger.error("No PCAP file specified")
            return []
        
        if not os.path.exists(file_to_analyze):
            logger.error(f"PCAP file not found: {file_to_analyze}")
            return []
        
        if not DPKT_AVAILABLE:
            logger.error("DPKT library not available, cannot parse PCAP")
            return []
        
        extracted_keys = []
        
        try:
            with open(file_to_analyze, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                for timestamp, buf in pcap:
                    try:
                        eth = Ethernet(buf)
                        if not isinstance(eth.data, IP):
                            continue
                            
                        ip = eth.data
                        src_ip = self._ip_to_str(ip.src)
                        dst_ip = self._ip_to_str(ip.dst)
                        
                        # Process TCP packets
                        if isinstance(ip.data, TCP):
                            tcp = ip.data
                            src_port = tcp.sport
                            dst_port = tcp.dport
                            
                            # Extract payload for analysis
                            payload = tcp.data
                            if payload:
                                # Check for HTTP (basic detection)
                                if payload.startswith(b'HTTP/') or payload.startswith(b'GET ') or payload.startswith(b'POST '):
                                    # Process HTTP payload
                                    keys = self._extract_keys_from_http(payload, src_ip, dst_ip, timestamp)
                                    extracted_keys.extend(keys)
                                else:
                                    # Process generic TCP payload
                                    keys = self._extract_keys_from_payload(payload, src_ip, dst_ip, timestamp)
                                    extracted_keys.extend(keys)
                                    
                                # Check for C2 patterns
                                c2_matches = self._match_c2_patterns(payload, src_ip, dst_ip, timestamp)
                                if c2_matches:
                                    # Extract keys from C2 communication
                                    keys = self._extract_keys_from_c2(payload, c2_matches, src_ip, dst_ip, timestamp)
                                    extracted_keys.extend(keys)
                        
                        # Process UDP packets
                        elif isinstance(ip.data, UDP):
                            udp = ip.data
                            src_port = udp.sport
                            dst_port = udp.dport
                            payload = udp.data
                            
                            if payload:
                                # Check for DNS tunneling
                                if dst_port == 53:  # DNS port
                                    # Process potential DNS tunneling
                                    keys = self._extract_keys_from_dns(payload, src_ip, dst_ip, timestamp)
                                    extracted_keys.extend(keys)
                                else:
                                    # Generic UDP payload analysis
                                    keys = self._extract_keys_from_payload(payload, src_ip, dst_ip, timestamp)
                                    extracted_keys.extend(keys)
                    
                    except Exception as e:
                        logger.debug(f"Error processing packet: {e}")
        
        except Exception as e:
            logger.error(f"Error analyzing PCAP file: {e}")
        
        # Deduplicate keys
        unique_keys = {}
        for key in extracted_keys:
            if key.key_id not in unique_keys:
                unique_keys[key.key_id] = key
            elif key.confidence > unique_keys[key.key_id].confidence:
                unique_keys[key.key_id] = key
        
        return list(unique_keys.values())
    
    def _ip_to_str(self, ip_bytes: bytes) -> str:
        """Convert bytes IP address to string"""
        return '.'.join(str(b) for b in ip_bytes)
    
    def _extract_keys_from_http(self, http_data: bytes, src_ip: str, dst_ip: str, timestamp: datetime) -> List[ExtractedKey]:
        """Extract potential keys from HTTP traffic"""
        extracted_keys = []
        
        # Search for key patterns in HTTP data
        for key_type, patterns in self.key_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, http_data, re.DOTALL)
                for match in matches:
                    # The entire match or the first group if there is one
                    key_data = match.group(1) if match.lastindex else match.group(0)
                    
                    # Handle different key formats
                    if re.match(rb'^[A-Za-z0-9+/=]+$', key_data):
                        # Looks like base64
                        try:
                            # Try to decode base64
                            decoded = base64.b64decode(key_data)
                            if len(decoded) >= 16:  # At least 128 bits
                                extracted_keys.append(ExtractedKey(
                                    key_data=decoded,
                                    key_type=key_type,
                                    source_ip=src_ip,
                                    destination_ip=dst_ip,
                                    timestamp=datetime.fromtimestamp(timestamp),
                                    confidence=0.7,
                                    context={"source": "http", "original_format": "base64"},
                                    format="raw"
                                ))
                        except:
                            # Not valid base64, treat as raw
                            extracted_keys.append(ExtractedKey(
                                key_data=key_data,
                                key_type=key_type,
                                source_ip=src_ip,
                                destination_ip=dst_ip,
                                timestamp=datetime.fromtimestamp(timestamp),
                                confidence=0.5,
                                context={"source": "http", "original_format": "raw"},
                                format="raw"
                            ))
                    elif re.match(rb'^[A-Fa-f0-9]+$', key_data) and len(key_data) >= 32:
                        # Hex encoded
                        try:
                            decoded = bytes.fromhex(key_data.decode('ascii'))
                            extracted_keys.append(ExtractedKey(
                                key_data=decoded,
                                key_type=key_type,
                                source_ip=src_ip,
                                destination_ip=dst_ip,
                                timestamp=datetime.fromtimestamp(timestamp),
                                confidence=0.7,
                                context={"source": "http", "original_format": "hex"},
                                format="raw"
                            ))
                        except:
                            # Not valid hex, treat as raw
                            extracted_keys.append(ExtractedKey(
                                key_data=key_data,
                                key_type=key_type,
                                source_ip=src_ip,
                                destination_ip=dst_ip,
                                timestamp=datetime.fromtimestamp(timestamp),
                                confidence=0.5,
                                context={"source": "http", "original_format": "raw"},
                                format="raw"
                            ))
                    else:
                        # Raw format
                        extracted_keys.append(ExtractedKey(
                            key_data=key_data,
                            key_type=key_type,
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            timestamp=datetime.fromtimestamp(timestamp),
                            confidence=0.6,
                            context={"source": "http", "original_format": "raw"},
                            format="raw"
                        ))
        
        return extracted_keys
    
    def _extract_keys_from_payload(self, payload: bytes, src_ip: str, dst_ip: str, timestamp: datetime) -> List[ExtractedKey]:
        """Extract potential keys from generic network payload"""
        extracted_keys = []
        
        # This is a more general approach - just looking for key-like patterns
        for key_type, patterns in self.key_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, payload, re.DOTALL)
                for match in matches:
                    # The entire match or the first group if there is one
                    key_data = match.group(1) if match.lastindex else match.group(0)
                    
                    # Skip if key is too short or too long
                    if len(key_data) < 16 or len(key_data) > 512:
                        continue
                    
                    # Add to extracted keys
                    extracted_keys.append(ExtractedKey(
                        key_data=key_data,
                        key_type=key_type,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        timestamp=datetime.fromtimestamp(timestamp),
                        confidence=0.5,  # Lower confidence for generic payload
                        context={"source": "generic_payload", "offset": match.start()},
                        format="raw"
                    ))
        
        # Look for high-entropy data blocks (potential encrypted keys)
        blocks = self._find_high_entropy_blocks(payload)
        for block, entropy in blocks:
            if 16 <= len(block) <= 64:  # Typical key sizes
                key_type = self._guess_key_type(block, entropy)
                if key_type:
                    confidence = min(0.4 + (entropy - 6.5) * 0.1, 0.7)  # Scale by entropy
                    extracted_keys.append(ExtractedKey(
                        key_data=block,
                        key_type=key_type,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        timestamp=datetime.fromtimestamp(timestamp),
                        confidence=confidence,
                        context={"source": "entropy_analysis", "entropy": entropy},
                        format="raw"
                    ))
        
        return extracted_keys
    
    def _match_c2_patterns(self, payload: bytes, src_ip: str, dst_ip: str, timestamp: datetime) -> List[Tuple[str, float]]:
        """Match payload against known C2 patterns"""
        matches = []
        
        for family, patterns in self.c2_patterns.items():
            for pattern, base_confidence in patterns.items():
                if pattern in payload:
                    matches.append((family, base_confidence))
        
        return matches
    
    def _extract_keys_from_c2(self, payload: bytes, c2_matches: List[Tuple[str, float]], 
                              src_ip: str, dst_ip: str, timestamp: datetime) -> List[ExtractedKey]:
        """Extract keys from identified C2 communication"""
        extracted_keys = []
        
        # Get information about the matching families
        for family, confidence in c2_matches:
            family_data = self.families_data.get(family, {})
            encryption_info = family_data.get("technical_details", {}).get("encryption", {})
            
            # Determine key sizes to look for based on family
            key_lengths = []
            if isinstance(encryption_info, dict):
                alg = encryption_info.get("algorithm", "")
                key_length = encryption_info.get("key_length", 0)
                
                if isinstance(alg, str) and alg.lower() in ["aes-256", "aes256", "aes"]:
                    key_lengths.append(32)  # AES-256 key size in bytes
                elif isinstance(alg, str) and alg.lower() in ["aes-128", "aes128"]:
                    key_lengths.append(16)  # AES-128 key size in bytes
                elif isinstance(alg, str) and alg.lower() in ["chacha20", "salsa20"]:
                    key_lengths.append(32)  # ChaCha20/Salsa20 key size in bytes
                
                if isinstance(key_length, int) and key_length > 0:
                    key_lengths.append(key_length // 8)  # Convert bits to bytes
            
            # If we don't have specific sizes, use defaults
            if not key_lengths:
                key_lengths = [16, 24, 32]  # Common key sizes in bytes
            
            # Look for data blocks that match key sizes with high entropy
            blocks = self._find_high_entropy_blocks(payload, min_length=min(key_lengths), max_length=max(key_lengths))
            for block, entropy in blocks:
                if len(block) in key_lengths and entropy > 6.8:
                    # Get key type based on family info and block characteristics
                    key_type = self._get_key_type_for_family(family, block)
                    
                    # Scale confidence by entropy and family match
                    adjusted_confidence = min(confidence + (entropy - 6.8) * 0.15, 0.85)
                    
                    extracted_keys.append(ExtractedKey(
                        key_data=block,
                        key_type=key_type,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        timestamp=datetime.fromtimestamp(timestamp),
                        confidence=adjusted_confidence,
                        context={
                            "source": "c2_communication", 
                            "family": family, 
                            "entropy": entropy
                        },
                        format="raw"
                    ))
        
        return extracted_keys
    
    def _extract_keys_from_dns(self, dns_data: bytes, src_ip: str, dst_ip: str, timestamp: datetime) -> List[ExtractedKey]:
        """Extract potential keys from DNS traffic (often used for tunneling)"""
        extracted_keys = []
        
        try:
            # Try to parse as DNS packet
            dns = dpkt.dns.DNS(dns_data)
            
            # Check DNS queries
            if dns.qd:
                for question in dns.qd:
                    if hasattr(question, 'name'):
                        # Check for long domain names (potential data exfiltration/tunneling)
                        domain = question.name.decode('utf-8', errors='ignore')
                        
                        # Split into parts
                        parts = domain.split('.')
                        for part in parts:
                            # Look for high-entropy subdomains
                            if len(part) > 16 and self._calculate_entropy(part.encode()) > 3.8:
                                # This could be encoded data
                                try:
                                    # Try to decode as base32/base64
                                    data = None
                                    
                                    # Check if it looks like base64
                                    if re.match(r'^[A-Za-z0-9+/=]+$', part):
                                        try:
                                            # Add padding if needed
                                            padded = part + '=' * ((4 - len(part) % 4) % 4)
                                            data = base64.b64decode(padded)
                                        except:
                                            pass
                                    
                                    # Check if it looks like base32
                                    if not data and re.match(r'^[A-Z2-7=]+$', part.upper()):
                                        try:
                                            # Add padding if needed
                                            padded = part.upper() + '=' * ((8 - len(part) % 8) % 8)
                                            data = base64.b32decode(padded)
                                        except:
                                            pass
                                    
                                    # Check if it looks like hex
                                    if not data and re.match(r'^[A-Fa-f0-9]+$', part) and len(part) % 2 == 0:
                                        try:
                                            data = bytes.fromhex(part)
                                        except:
                                            pass
                                    
                                    # If we've decoded something, check if it could be a key
                                    if data and 16 <= len(data) <= 64:
                                        # Calculate entropy of the decoded data
                                        entropy = self._calculate_entropy(data)
                                        if entropy > 6.5:  # High entropy suggests encrypted/random data
                                            key_type = self._guess_key_type(data, entropy)
                                            extracted_keys.append(ExtractedKey(
                                                key_data=data,
                                                key_type=key_type,
                                                source_ip=src_ip,
                                                destination_ip=dst_ip,
                                                timestamp=datetime.fromtimestamp(timestamp),
                                                confidence=0.6,
                                                context={
                                                    "source": "dns_tunneling", 
                                                    "domain": domain,
                                                    "entropy": entropy
                                                },
                                                format="raw"
                                            ))
                                except Exception as e:
                                    logger.debug(f"Error decoding DNS data: {e}")
        except Exception as e:
            logger.debug(f"Error parsing DNS packet: {e}")
        
        return extracted_keys
    
    def _find_high_entropy_blocks(self, data: bytes, min_length: int = 16, 
                                 max_length: int = 64, step: int = 8) -> List[Tuple[bytes, float]]:
        """Find blocks of high entropy data that might be encryption keys"""
        high_entropy_blocks = []
        
        # Scan the data with sliding windows of different sizes
        for size in range(min_length, min(max_length + 1, len(data) + 1), step):
            for i in range(0, len(data) - size + 1, 4):  # Step by 4 for efficiency
                block = data[i:i+size]
                entropy = self._calculate_entropy(block)
                
                # High entropy suggests random/encrypted data, potential keys
                if entropy > 6.5:  # Threshold for high entropy
                    high_entropy_blocks.append((block, entropy))
        
        # Sort by entropy (highest first)
        high_entropy_blocks.sort(key=lambda x: x[1], reverse=True)
        
        # Return top results (limit to 5 to avoid too many false positives)
        return high_entropy_blocks[:5]
    
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
            entropy -= probability * (math.log(probability) / math.log(2))
        
        return entropy
    
    def _guess_key_type(self, data: bytes, entropy: float) -> str:
        """Guess the key type based on its characteristics"""
        length = len(data)
        
        if length == 16:
            return "aes-128"
        elif length == 24:
            return "aes-192"
        elif length == 32:
            if entropy > 7.5:
                # ChaCha20 and Salsa20 keys tend to have very high entropy
                return "chacha20_or_salsa20"
            else:
                return "aes-256"
        elif length > 100:
            # Longer keys are likely RSA or other asymmetric keys
            return "rsa"
        else:
            return "unknown"
    
    def _get_key_type_for_family(self, family: str, data: bytes) -> str:
        """Get the key type based on the ransomware family and data characteristics"""
        family_data = self.families_data.get(family, {})
        encryption_info = family_data.get("technical_details", {}).get("encryption", {})
        
        if isinstance(encryption_info, dict):
            alg = encryption_info.get("algorithm", "")
            
            if isinstance(alg, str):
                alg_lower = alg.lower()
                
                if "aes" in alg_lower:
                    if "256" in alg_lower and len(data) == 32:
                        return "aes-256"
                    elif "192" in alg_lower and len(data) == 24:
                        return "aes-192"
                    elif "128" in alg_lower and len(data) == 16:
                        return "aes-128"
                    else:
                        # Just AES without specific size
                        if len(data) == 32:
                            return "aes-256"
                        elif len(data) == 24:
                            return "aes-192"
                        elif len(data) == 16:
                            return "aes-128"
                
                if "chacha" in alg_lower and len(data) == 32:
                    return "chacha20"
                
                if "salsa" in alg_lower and len(data) == 32:
                    return "salsa20"
        
        # Fall back to guessing based on data characteristics
        return self._guess_key_type(data, self._calculate_entropy(data))
    
    def extract_potential_keys(self, pcap_file: Optional[str] = None) -> List[ExtractedKey]:
        """
        Extract potential encryption keys from a PCAP file
        
        Args:
            pcap_file: Optional PCAP file path (uses self.pcap_file if None)
            
        Returns:
            List of ExtractedKey objects
        """
        return self.analyze_pcap(pcap_file)
    
    def save_keys_to_file(self, keys: List[ExtractedKey], output_file: str) -> bool:
        """
        Save extracted keys to a JSON file
        
        Args:
            keys: List of ExtractedKey objects
            output_file: Path to output file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            data = {
                "timestamp": datetime.now().isoformat(),
                "key_count": len(keys),
                "keys": [key.to_dict() for key in keys]
            }
            
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            return True
        except Exception as e:
            logger.error(f"Error saving keys to file: {e}")
            return False
    
    def load_keys_from_file(self, input_file: str) -> List[ExtractedKey]:
        """
        Load keys from a JSON file
        
        Args:
            input_file: Path to input file
            
        Returns:
            List of ExtractedKey objects
        """
        keys = []
        
        try:
            with open(input_file, 'r') as f:
                data = json.load(f)
            
            for key_data in data.get("keys", []):
                try:
                    key = ExtractedKey.from_dict(key_data)
                    keys.append(key)
                except Exception as e:
                    logger.error(f"Error parsing key data: {e}")
        except Exception as e:
            logger.error(f"Error loading keys from file: {e}")
        
        return keys


# Named constants for encryption modes
MODE_AES_CBC = "CBC"
MODE_AES_ECB = "ECB"
MODE_AES_CTR = "CTR"
MODE_AES_GCM = "GCM"
MODE_AES_CFB = "CFB"
MODE_AES_OFB = "OFB"
MODE_CHACHA20 = "CHACHA20"
MODE_SALSA20 = "SALSA20"
MODE_RSA = "RSA"


class DecryptionAttempt:
    """Results of a decryption attempt"""
    
    def __init__(self, success: bool, key_used: Optional[ExtractedKey] = None,
                 decrypted_data: Optional[bytes] = None, error: Optional[str] = None):
        """
        Initialize a decryption attempt result
        
        Args:
            success: Whether decryption was successful
            key_used: The key used for decryption
            decrypted_data: The decrypted data (if successful)
            error: Error message (if unsuccessful)
        """
        self.success = success
        self.key_used = key_used
        self.decrypted_data = decrypted_data
        self.error = error
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = {
            "success": self.success,
            "timestamp": self.timestamp.isoformat(),
        }
        
        if self.key_used:
            result["key_used"] = self.key_used.to_dict()
        
        if self.decrypted_data:
            # Only include first 100 bytes of decrypted data in the report
            if len(self.decrypted_data) > 100:
                preview = self.decrypted_data[:100]
                result["decrypted_data_preview"] = preview.hex()
                result["decrypted_data_size"] = len(self.decrypted_data)
            else:
                result["decrypted_data"] = self.decrypted_data.hex()
        
        if self.error:
            result["error"] = self.error
            
        return result


class NetworkBasedRecovery:
    """
    Uses network-extracted keys to attempt decryption of ransomware-encrypted files
    """
    
    def __init__(self, keys: Optional[List[ExtractedKey]] = None):
        """
        Initialize the recovery module
        
        Args:
            keys: Optional list of ExtractedKey objects
        """
        self.keys = keys or []
        self.results = []
        self.logger = logger
        
        # Ensure cryptography library is available
        if not CRYPTOGRAPHY_AVAILABLE:
            self.logger.warning("Cryptography library not available, decryption will not be possible")
    
    def add_key(self, key: ExtractedKey):
        """Add a key to the list of keys"""
        self.keys.append(key)
    
    def add_keys(self, keys: List[ExtractedKey]):
        """Add multiple keys to the list of keys"""
        self.keys.extend(keys)
    
    def load_keys_from_file(self, file_path: str):
        """Load keys from a JSON file"""
        extractor = NetworkKeyExtractor()
        keys = extractor.load_keys_from_file(file_path)
        self.add_keys(keys)
        return len(keys)
    
    def attempt_decryption(self, encrypted_file: str, output_file: Optional[str] = None,
                          original_file: Optional[str] = None, key_file: Optional[str] = None) -> List[DecryptionAttempt]:
        """
        Attempt to decrypt a file using extracted keys
        
        Args:
            encrypted_file: Path to the encrypted file
            output_file: Optional path to save decrypted file
            original_file: Optional path to the original file (for validation)
            key_file: Optional path to a key file
            
        Returns:
            List of DecryptionAttempt objects
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            self.logger.error("Cryptography library not available, decryption not possible")
            return [DecryptionAttempt(False, error="Cryptography library not available")]
        
        if not os.path.exists(encrypted_file):
            self.logger.error(f"Encrypted file not found: {encrypted_file}")
            return [DecryptionAttempt(False, error=f"Encrypted file not found: {encrypted_file}")]
        
        # Load additional keys if provided
        if key_file and os.path.exists(key_file):
            self.load_keys_from_file(key_file)
        
        # Read the encrypted file
        try:
            with open(encrypted_file, 'rb') as f:
                encrypted_data = f.read()
        except Exception as e:
            self.logger.error(f"Error reading encrypted file: {e}")
            return [DecryptionAttempt(False, error=f"Error reading encrypted file: {e}")]
        
        # Read the original file if provided (for validation)
        original_data = None
        if original_file and os.path.exists(original_file):
            try:
                with open(original_file, 'rb') as f:
                    original_data = f.read()
            except Exception as e:
                self.logger.warning(f"Error reading original file: {e}")
        
        results = []
        
        # Try to identify the file encryption structure
        structure = self._detect_encryption_structure(encrypted_data)
        
        # Try each key and each possible encryption mode
        for key in sorted(self.keys, key=lambda k: k.confidence, reverse=True):
            # Try with different modes based on structure
            if structure:
                # Use detected structure
                result = self._decrypt_with_structure(encrypted_data, key, structure)
                if result.success:
                    results.append(result)
                    # Check if we should save the decrypted file
                    if output_file and result.decrypted_data:
                        self._save_decrypted_file(output_file, result.decrypted_data)
                    break
            else:
                # Try common decryption methods
                result = self._try_common_decryption_methods(encrypted_data, key, original_data)
                if result.success:
                    results.append(result)
                    # Check if we should save the decrypted file
                    if output_file and result.decrypted_data:
                        self._save_decrypted_file(output_file, result.decrypted_data)
                    break
        
        # If no successful results, add a failure result
        if not results:
            results.append(DecryptionAttempt(False, error="No keys were able to decrypt the file"))
        
        # Add results to the instance
        self.results.extend(results)
        
        return results
    
    def _detect_encryption_structure(self, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Attempt to detect the encryption structure of a file
        
        Args:
            data: Encrypted file data
            
        Returns:
            Dictionary with encryption structure information or None
        """
        # Check for known encryption markers or headers
        structure = {}
        
        # Try to detect WannaCry structure
        if data.startswith(b'WANACRY!'):
            structure = {
                "family": "WannaCry",
                "algorithm": "AES",
                "mode": MODE_AES_CBC,
                "key_location": "network",
                "key_size": 16,
                "iv_included": True,
                "iv_location": "header",
                "iv_offset": 0x20,
                "iv_size": 16,
                "data_offset": 0x200,
                "key_in_file": False,
                "header_size": 0x200
            }
            return structure
        
        # Try to detect STOP/Djvu structure
        if len(data) > 20 and data[0:4] in [b'\x00\x00\x00\x00', b'\x02\x00\x00\x00', b'\x03\x00\x00\x00']:
            # Try to find STOP marker
            marker_pos = data.find(b'STOP')
            if marker_pos != -1 and marker_pos < 0x100:
                structure = {
                    "family": "STOP/Djvu",
                    "algorithm": "Salsa20",
                    "mode": MODE_SALSA20,
                    "key_location": "file",
                    "key_size": 32,
                    "key_offset": None,  # Varies by version
                    "key_encrypted": True,
                    "online_id": True,
                    "key_in_file": False,
                    "header_size": 0x258
                }
                return structure
        
        # More generic structure detection
        if len(data) > 64:
            # Check for potential encryption marker patterns
            
            # Many ransomware families include the encrypted file key at the end
            if len(data) > 256:
                # Check last 256 bytes for key-like data
                tail = data[-256:]
                
                # Look for RSA-encrypted blocks (they have high entropy)
                blocks = self._find_high_entropy_blocks(tail, min_length=128, max_length=256)
                if blocks:
                    structure = {
                        "algorithm": "AES",
                        "mode": MODE_AES_CBC,
                        "key_location": "file_end",
                        "key_size": 32,
                        "key_encrypted": True,
                        "key_encryption": "RSA",
                        "data_end": len(data) - len(blocks[0][0]),
                        "encrypted_key": blocks[0][0],
                        "key_in_file": True
                    }
                    return structure
            
            # Many families include the IV at the beginning of the file
            potential_iv = data[0:16]
            entropy = self._calculate_entropy(potential_iv)
            if 3.5 < entropy < 5.5:  # IVs are random but not as random as encrypted data
                structure = {
                    "algorithm": "AES",
                    "mode": MODE_AES_CBC,
                    "iv_included": True,
                    "iv_location": "start",
                    "iv_size": 16,
                    "data_offset": 16,
                    "key_in_file": False
                }
                return structure
        
        return None
    
    def _try_common_decryption_methods(self, encrypted_data: bytes, key: ExtractedKey, 
                                      original_data: Optional[bytes] = None) -> DecryptionAttempt:
        """
        Try common decryption methods with a given key
        
        Args:
            encrypted_data: Encrypted data
            key: Key to try
            original_data: Optional original data for validation
            
        Returns:
            DecryptionAttempt object
        """
        methods = []
        
        # First check key type
        if key.key_type.startswith("aes"):
            # For AES keys, try CBC, ECB, and CTR modes
            methods = [
                (self._decrypt_aes_cbc, {"key": key.key_data}),
                (self._decrypt_aes_ecb, {"key": key.key_data}),
                (self._decrypt_aes_ctr, {"key": key.key_data}),
                (self._decrypt_aes_cbc, {"key": key.key_data, "iv_in_file": True})
            ]
        elif key.key_type in ["chacha20", "chacha20_or_salsa20", "salsa20"]:
            # For ChaCha20/Salsa20 keys
            methods = [
                (self._decrypt_chacha20, {"key": key.key_data}),
                (self._decrypt_salsa20, {"key": key.key_data})
            ]
        else:
            # For unknown types, try everything
            methods = [
                (self._decrypt_aes_cbc, {"key": key.key_data}),
                (self._decrypt_aes_ecb, {"key": key.key_data}),
                (self._decrypt_aes_ctr, {"key": key.key_data}),
                (self._decrypt_chacha20, {"key": key.key_data}),
                (self._decrypt_salsa20, {"key": key.key_data})
            ]
        
        for decrypt_func, params in methods:
            try:
                decrypted_data = decrypt_func(encrypted_data, **params)
                
                if decrypted_data:
                    # Validate decrypted data
                    if self._is_valid_decryption(decrypted_data, original_data):
                        return DecryptionAttempt(True, key, decrypted_data)
            except Exception as e:
                self.logger.debug(f"Decryption failed with method {decrypt_func.__name__}: {e}")
        
        return DecryptionAttempt(False, key, error="All decryption methods failed")
    
    def _decrypt_with_structure(self, encrypted_data: bytes, key: ExtractedKey, 
                               structure: Dict[str, Any]) -> DecryptionAttempt:
        """
        Decrypt data using detected structure
        
        Args:
            encrypted_data: Encrypted data
            key: Key to use
            structure: Detected encryption structure
            
        Returns:
            DecryptionAttempt object
        """
        algorithm = structure.get("algorithm", "").lower()
        mode = structure.get("mode", "")
        
        if algorithm == "aes":
            if mode == MODE_AES_CBC:
                # Get IV if included
                iv = None
                if structure.get("iv_included", False):
                    iv_location = structure.get("iv_location", "")
                    iv_offset = structure.get("iv_offset", 0)
                    iv_size = structure.get("iv_size", 16)
                    
                    if iv_location == "header":
                        iv = encrypted_data[iv_offset:iv_offset+iv_size]
                    elif iv_location == "start":
                        iv = encrypted_data[0:iv_size]
                
                # Get data offset
                data_offset = structure.get("data_offset", 0)
                data_end = structure.get("data_end", len(encrypted_data))
                
                # Extract the actual encrypted data
                actual_data = encrypted_data[data_offset:data_end]
                
                # Decrypt
                try:
                    if iv:
                        decrypted = self._decrypt_aes_cbc(actual_data, key.key_data, iv)
                    else:
                        decrypted = self._decrypt_aes_cbc(actual_data, key.key_data)
                    
                    if decrypted and self._is_valid_decryption(decrypted):
                        return DecryptionAttempt(True, key, decrypted)
                except Exception as e:
                    self.logger.debug(f"Structured AES-CBC decryption failed: {e}")
            
            elif mode == MODE_AES_ECB:
                # Get data offset
                data_offset = structure.get("data_offset", 0)
                data_end = structure.get("data_end", len(encrypted_data))
                
                # Extract the actual encrypted data
                actual_data = encrypted_data[data_offset:data_end]
                
                # Decrypt
                try:
                    decrypted = self._decrypt_aes_ecb(actual_data, key.key_data)
                    
                    if decrypted and self._is_valid_decryption(decrypted):
                        return DecryptionAttempt(True, key, decrypted)
                except Exception as e:
                    self.logger.debug(f"Structured AES-ECB decryption failed: {e}")
        
        elif algorithm in ["chacha20", "salsa20"]:
            # Get data offset
            data_offset = structure.get("data_offset", 0)
            data_end = structure.get("data_end", len(encrypted_data))
            
            # Extract the actual encrypted data
            actual_data = encrypted_data[data_offset:data_end]
            
            # Get nonce/counter if included
            nonce = None
            if structure.get("nonce_included", False):
                nonce_location = structure.get("nonce_location", "")
                nonce_offset = structure.get("nonce_offset", 0)
                nonce_size = structure.get("nonce_size", 8)
                
                if nonce_location == "header":
                    nonce = encrypted_data[nonce_offset:nonce_offset+nonce_size]
            
            # Decrypt
            try:
                if algorithm == "chacha20":
                    if nonce:
                        decrypted = self._decrypt_chacha20(actual_data, key.key_data, nonce)
                    else:
                        decrypted = self._decrypt_chacha20(actual_data, key.key_data)
                else:  # salsa20
                    if nonce:
                        decrypted = self._decrypt_salsa20(actual_data, key.key_data, nonce)
                    else:
                        decrypted = self._decrypt_salsa20(actual_data, key.key_data)
                
                if decrypted and self._is_valid_decryption(decrypted):
                    return DecryptionAttempt(True, key, decrypted)
            except Exception as e:
                self.logger.debug(f"Structured {algorithm} decryption failed: {e}")
        
        return DecryptionAttempt(False, key, error=f"Structured decryption failed for {algorithm}/{mode}")
    
    def _decrypt_aes_cbc(self, data: bytes, key: bytes, iv: Optional[bytes] = None, 
                        iv_in_file: bool = False) -> Optional[bytes]:
        """
        Decrypt data using AES in CBC mode
        
        Args:
            data: Encrypted data
            key: AES key
            iv: Optional IV
            iv_in_file: Whether the IV is included in the data
            
        Returns:
            Decrypted data or None
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            return None
        
        # Ensure the key is the right length
        if len(key) not in [16, 24, 32]:
            # Adjust key length
            if len(key) < 16:
                key = key.ljust(16, b'\0')
            elif 16 < len(key) < 24:
                key = key[:16]
            elif 24 < len(key) < 32:
                key = key[:24]
            elif len(key) > 32:
                key = key[:32]
        
        # Handle IV
        if iv_in_file:
            # Assume IV is at the beginning (common scenario)
            iv = data[:16]
            data = data[16:]
        elif not iv:
            # Use zeros if IV not provided
            iv = b'\0' * 16
        
        try:
            # Create AES cipher
            algorithm = algorithms.AES(key)
            cipher = Cipher(algorithm, modes.CBC(iv))
            decryptor = cipher.decryptor()
            
            # Decrypt
            decrypted = decryptor.update(data) + decryptor.finalize()
            
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
            
            return decrypted
        except Exception as e:
            self.logger.debug(f"AES-CBC decryption failed: {e}")
            return None
    
    def _decrypt_aes_ecb(self, data: bytes, key: bytes) -> Optional[bytes]:
        """
        Decrypt data using AES in ECB mode
        
        Args:
            data: Encrypted data
            key: AES key
            
        Returns:
            Decrypted data or None
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            return None
        
        # Ensure the key is the right length
        if len(key) not in [16, 24, 32]:
            # Adjust key length
            if len(key) < 16:
                key = key.ljust(16, b'\0')
            elif 16 < len(key) < 24:
                key = key[:16]
            elif 24 < len(key) < 32:
                key = key[:24]
            elif len(key) > 32:
                key = key[:32]
        
        try:
            # Create AES cipher
            algorithm = algorithms.AES(key)
            cipher = Cipher(algorithm, modes.ECB())
            decryptor = cipher.decryptor()
            
            # Decrypt
            decrypted = decryptor.update(data) + decryptor.finalize()
            
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
            
            return decrypted
        except Exception as e:
            self.logger.debug(f"AES-ECB decryption failed: {e}")
            return None
    
    def _decrypt_aes_ctr(self, data: bytes, key: bytes, nonce: Optional[bytes] = None) -> Optional[bytes]:
        """
        Decrypt data using AES in CTR mode
        
        Args:
            data: Encrypted data
            key: AES key
            nonce: Optional nonce/counter
            
        Returns:
            Decrypted data or None
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            return None
        
        # Ensure the key is the right length
        if len(key) not in [16, 24, 32]:
            # Adjust key length
            if len(key) < 16:
                key = key.ljust(16, b'\0')
            elif 16 < len(key) < 24:
                key = key[:16]
            elif 24 < len(key) < 32:
                key = key[:24]
            elif len(key) > 32:
                key = key[:32]
        
        # Handle nonce
        if not nonce:
            # Use zeros if nonce not provided
            nonce = b'\0' * 16
        elif len(nonce) < 16:
            # Adjust nonce length
            nonce = nonce.ljust(16, b'\0')
        
        try:
            # Create AES cipher
            algorithm = algorithms.AES(key)
            cipher = Cipher(algorithm, modes.CTR(nonce))
            decryptor = cipher.decryptor()
            
            # Decrypt (CTR mode doesn't need padding)
            decrypted = decryptor.update(data) + decryptor.finalize()
            
            return decrypted
        except Exception as e:
            self.logger.debug(f"AES-CTR decryption failed: {e}")
            return None
    
    def _decrypt_chacha20(self, data: bytes, key: bytes, nonce: Optional[bytes] = None) -> Optional[bytes]:
        """
        Decrypt data using ChaCha20
        
        Args:
            data: Encrypted data
            key: ChaCha20 key
            nonce: Optional nonce
            
        Returns:
            Decrypted data or None
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            return None
        
        # Ensure the key is 32 bytes (ChaCha20 requirement)
        if len(key) != 32:
            if len(key) < 32:
                key = key.ljust(32, b'\0')
            else:
                key = key[:32]
        
        # Handle nonce
        if not nonce:
            # Use zeros if nonce not provided
            nonce = b'\0' * 16
        elif len(nonce) < 16:
            # Adjust nonce length
            nonce = nonce.ljust(16, b'\0')
        
        try:
            # Create ChaCha20 cipher
            algorithm = algorithms.ChaCha20(key, nonce)
            cipher = Cipher(algorithm, mode=None)
            decryptor = cipher.decryptor()
            
            # Decrypt
            decrypted = decryptor.update(data) + decryptor.finalize()
            
            return decrypted
        except Exception as e:
            self.logger.debug(f"ChaCha20 decryption failed: {e}")
            return None
    
    def _decrypt_salsa20(self, data: bytes, key: bytes, nonce: Optional[bytes] = None) -> Optional[bytes]:
        """
        Decrypt data using Salsa20
        
        Args:
            data: Encrypted data
            key: Salsa20 key
            nonce: Optional nonce
            
        Returns:
            Decrypted data or None
        """
        # Note: Native cryptography library doesn't support Salsa20
        # This is a placeholder - in a real implementation, you'd use a library that supports Salsa20
        # or implement it directly
        self.logger.warning("Salsa20 decryption not implemented in this version")
        return None
    
    def _is_valid_decryption(self, decrypted_data: bytes, original_data: Optional[bytes] = None) -> bool:
        """
        Check if decrypted data looks valid
        
        Args:
            decrypted_data: Decrypted data
            original_data: Optional original data for validation
            
        Returns:
            True if decryption appears valid, False otherwise
        """
        # If we have the original file, compare with it
        if original_data:
            # Check if the decrypted data matches the original
            if decrypted_data == original_data:
                return True
            
            # Check if the beginning matches (partial decryption)
            if len(decrypted_data) >= 100 and len(original_data) >= 100:
                if decrypted_data[:100] == original_data[:100]:
                    return True
        
        # No original data, check for common file signatures
        if len(decrypted_data) < 4:
            return False
        
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
            b'<!DOCTYPE': ['html', 'xml']
        }
        
        for sig, extensions in signatures.items():
            if decrypted_data.startswith(sig):
                return True
        
        # Check for text files (ASCII/UTF-8)
        try:
            # Try to decode as UTF-8
            text = decrypted_data[:1000].decode('utf-8')
            
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
            entropy -= probability * (math.log(probability) / math.log(2))
        
        return entropy
    
    def _find_high_entropy_blocks(self, data: bytes, min_length: int = 16, 
                                 max_length: int = 64, step: int = 8) -> List[Tuple[bytes, float]]:
        """Find blocks of high entropy data that might be encrypted"""
        high_entropy_blocks = []
        
        # Scan the data with sliding windows of different sizes
        for size in range(min_length, min(max_length + 1, len(data) + 1), step):
            for i in range(0, len(data) - size + 1, 4):  # Step by 4 for efficiency
                block = data[i:i+size]
                entropy = self._calculate_entropy(block)
                
                # High entropy suggests random/encrypted data
                if entropy > 6.5:  # Threshold for high entropy
                    high_entropy_blocks.append((block, entropy))
        
        # Sort by entropy (highest first)
        high_entropy_blocks.sort(key=lambda x: x[1], reverse=True)
        
        # Return top results (limit to 5 to avoid too many false positives)
        return high_entropy_blocks[:5]
    
    def _save_decrypted_file(self, output_file: str, decrypted_data: bytes) -> bool:
        """
        Save decrypted data to a file
        
        Args:
            output_file: Path to save decrypted data
            decrypted_data: Decrypted data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
            return True
        except Exception as e:
            self.logger.error(f"Error saving decrypted file: {e}")
            return False
    
    def generate_report(self, include_keys: bool = True) -> Dict[str, Any]:
        """
        Generate a report of decryption attempts
        
        Args:
            include_keys: Whether to include key data in the report
            
        Returns:
            Report dictionary
        """
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_keys": len(self.keys),
            "total_attempts": len(self.results),
            "successful_attempts": sum(1 for r in self.results if r.success),
            "results": [r.to_dict() for r in self.results]
        }
        
        if include_keys:
            report["keys"] = [k.to_dict() for k in self.keys]
        
        return report


# Import mathematical functions for entropy calculations
import math


if __name__ == "__main__":
    # Example usage
    logger.info("Network-Based Ransomware Recovery Tool")
    
    # Parse arguments
    import argparse
    parser = argparse.ArgumentParser(description="Network-Based Ransomware Recovery Tool")
    parser.add_argument("--pcap", help="PCAP file to analyze")
    parser.add_argument("--encrypted", help="Encrypted file to decrypt")
    parser.add_argument("--original", help="Original file for validation")
    parser.add_argument("--output", help="Output file for decrypted data")
    parser.add_argument("--keys", help="Key file (JSON)")
    parser.add_argument("--save-keys", help="Save extracted keys to this file")
    args = parser.parse_args()
    
    # Extract keys from PCAP
    if args.pcap:
        logger.info(f"Analyzing PCAP file: {args.pcap}")
        extractor = NetworkKeyExtractor(args.pcap)
        keys = extractor.extract_potential_keys()
        logger.info(f"Extracted {len(keys)} potential keys")
        
        # Save keys if requested
        if args.save_keys:
            success = extractor.save_keys_to_file(keys, args.save_keys)
            if success:
                logger.info(f"Saved keys to {args.save_keys}")
            else:
                logger.error(f"Failed to save keys to {args.save_keys}")
        
        # Try decryption if requested
        if args.encrypted:
            recovery = NetworkBasedRecovery(keys)
            results = recovery.attempt_decryption(args.encrypted, args.output, args.original)
            
            for result in results:
                if result.success:
                    logger.info(f"Successfully decrypted file")
                    if args.output:
                        logger.info(f"Decrypted file saved to {args.output}")
                else:
                    logger.info(f"Decryption failed: {result.error}")
    
    # Just decrypt a file with provided keys
    elif args.encrypted and args.keys:
        logger.info(f"Attempting to decrypt {args.encrypted} using keys from {args.keys}")
        recovery = NetworkBasedRecovery()
        recovery.load_keys_from_file(args.keys)
        results = recovery.attempt_decryption(args.encrypted, args.output, args.original)
        
        for result in results:
            if result.success:
                logger.info(f"Successfully decrypted file")
                if args.output:
                    logger.info(f"Decrypted file saved to {args.output}")
            else:
                logger.info(f"Decryption failed: {result.error}")
    
    else:
        logger.error("Missing required arguments. Use --help for usage information.")