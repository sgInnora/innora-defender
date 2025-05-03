#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Pattern-based Memory Key Scanner for Ransomware Analysis
This module scans memory dumps for patterns that indicate encryption keys
using multiple detection methods beyond YARA rules.
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
from typing import List, Dict, Tuple, Optional, BinaryIO, Generator, Any, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('PatternKeyScanner')

# Constants for key detection
AES_KEY_SIZES = [16, 24, 32]  # 128, 192, 256 bits in bytes
RSA_MIN_KEY_SIZE = 128  # 1024 bits in bytes
RSA_MARKER = b'\x30\x82'  # ASN.1 marker often seen in RSA keys

# Entropy calculation window size
WINDOW_SIZE = 512
# Minimum entropy threshold (0-8, 8 being completely random)
MIN_ENTROPY = 7.0
# Maximum key size to extract
MAX_KEY_SIZE = 4096

class PatternKeyScanner:
    """
    Scanner that uses pattern matching, entropy analysis, and structure recognition
    to identify potential encryption keys in memory dumps.
    """
    
    def __init__(self, min_entropy: float = MIN_ENTROPY, 
                 max_key_size: int = MAX_KEY_SIZE,
                 chunk_size: int = 10*1024*1024):
        """
        Initialize the scanner with configurable parameters.
        
        Args:
            min_entropy: Minimum Shannon entropy threshold (0-8)
            max_key_size: Maximum size of key to extract
            chunk_size: Size of chunks to process for large files
        """
        self.min_entropy = min_entropy
        self.max_key_size = max_key_size
        self.chunk_size = chunk_size
        self.results = []
        
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
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Calculate Shannon entropy
        for count in byte_counts.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
            
        return entropy
        
    def _scan_chunk_for_entropy(self, data: bytes, offset: int) -> List[Dict[str, Any]]:
        """
        Scan a chunk of data for high-entropy regions that might be encryption keys.
        
        Args:
            data: Chunk of data to scan
            offset: File offset of this chunk
            
        Returns:
            List of potential key findings
        """
        findings = []
        data_len = len(data)
        
        # Sliding window entropy calculation
        for i in range(0, data_len - WINDOW_SIZE, 64):  # Step by 64 bytes for performance
            window = data[i:i+WINDOW_SIZE]
            entropy = self._calculate_entropy(window)
            
            if entropy >= self.min_entropy:
                # Extract a larger context around high entropy region
                context_start = max(0, i - 128)
                context_end = min(data_len, i + WINDOW_SIZE + 128)
                context = data[context_start:context_end]
                
                finding = {
                    "type": "high_entropy",
                    "offset": offset + i,
                    "size": WINDOW_SIZE,
                    "entropy": entropy,
                    "data_hex": binascii.hexlify(window).decode('utf-8'),
                    "confidence": self._calculate_key_confidence(window, entropy),
                    "context_hex": binascii.hexlify(context).decode('utf-8')
                }
                findings.append(finding)
                
                # Skip ahead past this high-entropy region to avoid duplicate findings
                i += WINDOW_SIZE
        
        return findings
    
    def _scan_chunk_for_patterns(self, data: bytes, offset: int) -> List[Dict[str, Any]]:
        """
        Scan a chunk of data for known key patterns and structures.
        
        Args:
            data: Chunk of data to scan
            offset: File offset of this chunk
            
        Returns:
            List of potential key findings
        """
        findings = []
        
        # Scan for AES key schedules
        aes_key_findings = self._find_aes_key_schedules(data, offset)
        findings.extend(aes_key_findings)
        
        # Scan for RSA key structures
        rsa_key_findings = self._find_rsa_keys(data, offset)
        findings.extend(rsa_key_findings)
        
        # Scan for ChaCha20/Salsa20 key patterns
        chacha_key_findings = self._find_chacha_keys(data, offset)
        findings.extend(chacha_key_findings)
        
        return findings
    
    def _find_aes_key_schedules(self, data: bytes, offset: int) -> List[Dict[str, Any]]:
        """
        Find potential AES key schedules in memory.
        
        Args:
            data: Chunk of data to scan
            offset: File offset of this chunk
            
        Returns:
            List of potential AES key findings
        """
        findings = []
        
        # AES key schedule has specific patterns of repeating and transformed bytes
        # Look for potential round keys with specific spacing and relationships
        
        # Simple check for AES-128 key schedules (44 words = 176 bytes)
        for i in range(len(data) - 176):
            potential_key_schedule = data[i:i+176]
            
            # Check entropy first as a quick filter
            if self._calculate_entropy(potential_key_schedule) < 7.0:
                continue
                
            # Check for patterns typical in AES key schedules
            # This is a simplified check - production code would have more sophisticated detection
            if self._check_aes_key_schedule_pattern(potential_key_schedule):
                finding = {
                    "type": "aes_key_schedule",
                    "algorithm": "AES-128",
                    "offset": offset + i,
                    "size": 176,
                    "key_hex": binascii.hexlify(potential_key_schedule[0:16]).decode('utf-8'),
                    "schedule_hex": binascii.hexlify(potential_key_schedule).decode('utf-8'),
                    "confidence": self._calculate_key_confidence(potential_key_schedule[0:16], 7.8)
                }
                findings.append(finding)
        
        # Similar checks would be implemented for AES-192 and AES-256
        
        return findings
    
    def _check_aes_key_schedule_pattern(self, data: bytes) -> bool:
        """
        Check if the data matches patterns expected in an AES key schedule.
        
        Args:
            data: Potential key schedule data
            
        Returns:
            True if matches pattern, False otherwise
        """
        # This is a simplified implementation for demonstration
        # A full implementation would validate the key schedule structure according to AES spec
        
        # Check for word relationships in a key schedule
        try:
            words = [data[i:i+4] for i in range(0, len(data), 4)]
            
            # In AES-128, W[i] = W[i-4] ⊕ (either W[i-1] or a transformed W[i-1])
            for i in range(4, len(words)):
                # Every 4th word has special treatment, others are simple XOR
                if i % 4 == 0:
                    # Should have some relationship to rotated and substituted previous word
                    pass
                else:
                    # Should be XOR of previous and 4 words back
                    w_prev_xor = bytes(a ^ b for a, b in zip(words[i-4], words[i-1]))
                    if w_prev_xor == words[i]:
                        return True
        except Exception:
            return False
            
        return False
    
    def _find_rsa_keys(self, data: bytes, offset: int) -> List[Dict[str, Any]]:
        """
        Find potential RSA keys in memory.
        
        Args:
            data: Chunk of data to scan
            offset: File offset of this chunk
            
        Returns:
            List of potential RSA key findings
        """
        findings = []
        
        # Look for ASN.1 markers commonly found in RSA keys
        for marker in [RSA_MARKER, b'\x30\x81']:
            pos = 0
            while True:
                pos = data.find(marker, pos)
                if pos == -1:
                    break
                    
                # Check if this looks like a valid RSA key (PKCS#1, X.509, etc.)
                if pos + 2 < len(data):
                    # Get the length from ASN.1 structure
                    try:
                        if marker == RSA_MARKER:  # 2-byte length field
                            length = struct.unpack('>H', data[pos+2:pos+4])[0]
                            if length > 50 and pos + length + 4 <= len(data):
                                key_data = data[pos:pos+length+4]
                                if self._is_valid_asn1(key_data):
                                    finding = {
                                        "type": "rsa_key",
                                        "format": "asn1_der",
                                        "offset": offset + pos,
                                        "size": length + 4,
                                        "entropy": self._calculate_entropy(key_data),
                                        "data_hex": binascii.hexlify(key_data[:100]).decode('utf-8') + "...",
                                        "confidence": 0.8
                                    }
                                    findings.append(finding)
                        elif marker == b'\x30\x81':  # 1-byte length field
                            length = data[pos+2]
                            if length > 50 and pos + length + 3 <= len(data):
                                key_data = data[pos:pos+length+3]
                                if self._is_valid_asn1(key_data):
                                    finding = {
                                        "type": "rsa_key",
                                        "format": "asn1_der",
                                        "offset": offset + pos,
                                        "size": length + 3,
                                        "entropy": self._calculate_entropy(key_data),
                                        "data_hex": binascii.hexlify(key_data[:100]).decode('utf-8') + "...",
                                        "confidence": 0.8
                                    }
                                    findings.append(finding)
                    except Exception as e:
                        logger.debug(f"Error parsing potential RSA key: {e}")
                
                pos += 1  # Move to next position
        
        # Also check for PEM formatted keys
        pem_start = b'-----BEGIN'
        pos = 0
        while True:
            pos = data.find(pem_start, pos)
            if pos == -1:
                break
                
            # Try to find the end marker
            end_pos = data.find(b'-----END', pos)
            if end_pos != -1 and end_pos - pos < 10000:  # Reasonable key size
                key_data = data[pos:end_pos+30]  # Include the end marker and some padding
                
                if b'PRIVATE KEY' in key_data:
                    finding = {
                        "type": "rsa_key",
                        "format": "pem",
                        "offset": offset + pos,
                        "size": len(key_data),
                        "entropy": self._calculate_entropy(key_data),
                        "data_text": key_data.decode('utf-8', errors='replace'),
                        "confidence": 0.9
                    }
                    findings.append(finding)
            
            pos += 10  # Move ahead
        
        return findings
    
    def _is_valid_asn1(self, data: bytes) -> bool:
        """
        Simple check to validate if data could be a valid ASN.1 structure.
        
        Args:
            data: Potential ASN.1 data
            
        Returns:
            True if potentially valid ASN.1, False otherwise
        """
        # This is a very basic check - a real implementation would be more thorough
        # Just checking for basic ASN.1 structure patterns
        
        # Must start with SEQUENCE (0x30)
        if not data.startswith(b'\x30'):
            return False
        
        # Check for INTEGER (0x02) tags which are common in RSA keys
        int_count = data.count(b'\x02')
        if int_count < 2:  # RSA keys have multiple INTEGER fields
            return False
            
        # Check for OID for RSA (1.2.840.113549.1.1.1)
        if b'\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01' not in data:
            return False
            
        return True
    
    def _find_chacha_keys(self, data: bytes, offset: int) -> List[Dict[str, Any]]:
        """
        Find potential ChaCha20/Salsa20 keys in memory.
        
        Args:
            data: Chunk of data to scan
            offset: File offset of this chunk
            
        Returns:
            List of potential ChaCha20/Salsa20 key findings
        """
        findings = []
        
        # ChaCha20 and Salsa20 use 256-bit (32 byte) keys with specific constants
        # Look for the ChaCha20 constants "expand 32-byte k"
        constants = b'expand 32-byte k'
        
        pos = 0
        while True:
            pos = data.find(constants, pos)
            if pos == -1:
                break
                
            # Check surrounding data
            key_start = pos - 32
            if key_start >= 0:
                # Extract the potential key
                key_data = data[key_start:pos]
                nonce_data = data[pos+16:pos+16+12]  # 96-bit nonce
                
                # Calculate entropy to validate this looks like a real key
                key_entropy = self._calculate_entropy(key_data)
                if key_entropy > 7.5:
                    finding = {
                        "type": "chacha20_key",
                        "offset": offset + key_start,
                        "key_size": 32,
                        "nonce_size": 12,
                        "key_hex": binascii.hexlify(key_data).decode('utf-8'),
                        "nonce_hex": binascii.hexlify(nonce_data).decode('utf-8'),
                        "entropy": key_entropy,
                        "confidence": self._calculate_key_confidence(key_data, key_entropy)
                    }
                    findings.append(finding)
            
            pos += 16  # Move ahead
        
        return findings
    
    def _calculate_key_confidence(self, key_data: bytes, entropy: float) -> float:
        """
        Calculate a confidence score for a potential key.
        
        Args:
            key_data: The potential key data
            entropy: Entropy value already calculated
            
        Returns:
            Confidence score between 0 and 1
        """
        confidence = 0.0
        
        # Entropy-based confidence
        if entropy > 7.9:
            confidence += 0.7
        elif entropy > 7.5:
            confidence += 0.5
        elif entropy > 7.0:
            confidence += 0.3
        
        # Key size based confidence
        key_size = len(key_data)
        if key_size in AES_KEY_SIZES:
            confidence += 0.2
        elif key_size in [32, 64]:  # Common for ChaCha20, Salsa20
            confidence += 0.2
        elif key_size >= RSA_MIN_KEY_SIZE:
            confidence += 0.1
            
        # Limit to max of 1.0
        return min(0.95, confidence)
    
    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Scan a memory dump file for potential encryption keys.
        
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
                    entropy_findings = self._scan_chunk_for_entropy(chunk, offset)
                    pattern_findings = self._scan_chunk_for_patterns(chunk, offset)
                    
                    # Combine findings, ensuring we don't have duplicate offsets
                    findings = entropy_findings + pattern_findings
                    
                    # Sort by offset and remove duplicates
                    all_offsets = set()
                    unique_findings = []
                    for finding in findings:
                        if finding["offset"] not in all_offsets:
                            all_offsets.add(finding["offset"])
                            unique_findings.append(finding)
                            
                    self.results.extend(unique_findings)
                    
                    offset += len(chunk)
                    logger.info(f"Progress: {offset/file_size*100:.1f}% ({offset/1024/1024:.2f} MB)")
        
        except Exception as e:
            logger.error(f"Error scanning file: {e}")
            
        # Sort results by confidence
        self.results.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        
        return self.results
        
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
                entropy_findings = self._scan_chunk_for_entropy(data, start_offset)
                pattern_findings = self._scan_chunk_for_patterns(data, start_offset)
                
                # Combine findings, ensuring we don't have duplicate offsets
                findings = entropy_findings + pattern_findings
                
                # Sort by offset and remove duplicates
                all_offsets = set()
                unique_findings = []
                for finding in findings:
                    if finding["offset"] not in all_offsets:
                        all_offsets.add(finding["offset"])
                        unique_findings.append(finding)
                        
                self.results.extend(unique_findings)
        
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
            self.results = self._scan_process_memory_windows(pid)
        elif sys.platform == 'linux':
            self.results = self._scan_process_memory_linux(pid)
        elif sys.platform == 'darwin':
            self.results = self._scan_process_memory_macos(pid)
        else:
            logger.error(f"Unsupported platform: {sys.platform}")
            
        return self.results
    
    def _scan_process_memory_windows(self, pid: int) -> List[Dict[str, Any]]:
        """
        Scan memory of a Windows process.
        
        Args:
            pid: Process ID to scan
            
        Returns:
            List of findings
        """
        try:
            # Windows specific imports
            import win32process
            import win32con
            import win32security
            import ctypes
            from ctypes import wintypes
            
            # Results list
            results = []
            
            # Get process handle with required access rights
            hProcess = win32process.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                False, pid
            )
            
            # Get memory regions
            meminfo = ctypes.c_void_p(0)
            mem_size = ctypes.c_size_t(0)
            
            while ctypes.windll.kernel32.VirtualQueryEx(
                hProcess.handle, meminfo, ctypes.byref(mem_size), 
                ctypes.sizeof(mem_size)
            ):
                # Check if region is readable and committed
                if mem_size.value > 0:
                    try:
                        # Read the memory region
                        data = win32process.ReadProcessMemory(
                            hProcess.handle, meminfo.value, mem_size.value
                        )
                        
                        # Scan this region
                        offset = meminfo.value
                        entropy_findings = self._scan_chunk_for_entropy(data, offset)
                        pattern_findings = self._scan_chunk_for_patterns(data, offset)
                        
                        # Combine findings
                        findings = entropy_findings + pattern_findings
                        results.extend(findings)
                        
                    except Exception as e:
                        logger.debug(f"Error reading process memory at {meminfo.value:#x}: {e}")
                
                # Move to next region
                meminfo = ctypes.c_void_p(meminfo.value + mem_size.value)
            
            # Close process handle
            hProcess.Close()
            
            return results
            
        except Exception as e:
            logger.error(f"Error scanning Windows process memory: {e}")
            return []
            
    def _scan_process_memory_linux(self, pid: int) -> List[Dict[str, Any]]:
        """
        Scan memory of a Linux process.
        
        Args:
            pid: Process ID to scan
            
        Returns:
            List of findings
        """
        results = []
        
        try:
            # Linux process memory is exposed through /proc/{pid}/maps and /proc/{pid}/mem
            maps_file = f"/proc/{pid}/maps"
            mem_file = f"/proc/{pid}/mem"
            
            if not os.path.exists(maps_file) or not os.path.exists(mem_file):
                logger.error(f"Process {pid} not found or not accessible")
                return results
                
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
                        memory_regions.append((start, end - start))
            
            # Open process memory
            with open(mem_file, 'rb') as f:
                for start, size in memory_regions:
                    try:
                        # Seek to the start address
                        f.seek(start)
                        
                        # Try to read the memory region
                        data = f.read(size)
                        
                        # Scan this region
                        entropy_findings = self._scan_chunk_for_entropy(data, start)
                        pattern_findings = self._scan_chunk_for_patterns(data, start)
                        
                        # Combine findings
                        findings = entropy_findings + pattern_findings
                        results.extend(findings)
                        
                    except Exception as e:
                        logger.debug(f"Error reading process memory at {start:#x}: {e}")
            
            return results
            
        except Exception as e:
            logger.error(f"Error scanning Linux process memory: {e}")
            return []
            
    def _scan_process_memory_macos(self, pid: int) -> List[Dict[str, Any]]:
        """
        Scan memory of a macOS process.
        
        Args:
            pid: Process ID to scan
            
        Returns:
            List of findings
        """
        results = []
        
        try:
            # For macOS, we use the vmmap command to get memory regions
            import subprocess
            
            # Use vmmap to get memory regions
            cmd = ['vmmap', str(pid)]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Error getting memory map for process {pid}: {stderr.decode()}")
                return results
                
            # Parse vmmap output to find readable regions
            import re
            
            memory_regions = []
            lines = stdout.decode().split('\n')
            
            region_pattern = re.compile(r'([0-9a-f]+)-([0-9a-f]+)\s+\[\s*(\d+)K\]')
            for line in lines:
                match = region_pattern.search(line)
                if match and 'r' in line:  # Readable region
                    start = int(match.group(1), 16)
                    end = int(match.group(2), 16)
                    memory_regions.append((start, end - start))
            
            # Now we need to use mach APIs to read process memory
            # This part is more complex and would require ctypes bindings to Mach APIs
            # This is a simplified implementation
            
            logger.warning("MacOS process memory scanning is not fully implemented")
            logger.info(f"Found {len(memory_regions)} readable memory regions")
            
            # Placeholder for actual implementation
            # Would need to use vm_read, mach_vm_read or similar Mach APIs
            
            return results
            
        except Exception as e:
            logger.error(f"Error scanning macOS process memory: {e}")
            return []
    
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
    """Command line interface for the pattern scanner."""
    parser = argparse.ArgumentParser(description="Pattern-based Memory Key Scanner")
    parser.add_argument("input", help="Memory dump file or process ID to scan")
    parser.add_argument("--pid", action="store_true", help="Input is a process ID instead of a file")
    parser.add_argument("--output", "-o", help="Output file for results (JSON)")
    parser.add_argument("--entropy", "-e", type=float, default=MIN_ENTROPY, 
                      help=f"Minimum entropy threshold (0-8, default: {MIN_ENTROPY})")
    parser.add_argument("--offset", type=int, help="Starting offset for file scan")
    parser.add_argument("--size", type=int, help="Size of data to scan from offset")
    parser.add_argument("--chunk-size", type=int, default=10*1024*1024,
                      help="Chunk size for processing large files (default: 10MB)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Create scanner
    scanner = PatternKeyScanner(min_entropy=args.entropy, chunk_size=args.chunk_size)
    
    # Scan based on input type
    if args.pid:
        try:
            pid = int(args.input)
            logger.info(f"Scanning process with PID: {pid}")
            results = scanner.scan_process_memory(pid)
        except ValueError:
            logger.error("Invalid PID. Must be an integer.")
            return 1
    else:
        if args.offset is not None and args.size is not None:
            logger.info(f"Scanning file range: {args.input} from {args.offset} for {args.size} bytes")
            results = scanner.scan_range_in_file(args.input, args.offset, args.size)
        else:
            logger.info(f"Scanning file: {args.input}")
            results = scanner.scan_file(args.input)
    
    # Print summary
    logger.info(f"Scan complete. Found {len(results)} potential encryption keys.")
    
    # Group by type
    findings_by_type = {}
    for finding in results:
        finding_type = finding.get("type", "unknown")
        findings_by_type[finding_type] = findings_by_type.get(finding_type, 0) + 1
    
    for finding_type, count in findings_by_type.items():
        logger.info(f"  {finding_type}: {count}")
    
    # Save results if output file specified
    if args.output:
        scanner.save_results(args.output)
    elif not args.output and results:
        # Print top 5 findings
        logger.info("\nTop findings:")
        for i, finding in enumerate(results[:5]):
            logger.info(f"[{i+1}] Type: {finding.get('type')}, " +
                       f"Confidence: {finding.get('confidence', 0):.2f}, " +
                       f"Offset: {finding.get('offset', 0):#x}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())