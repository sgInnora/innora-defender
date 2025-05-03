#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LockBit Ransomware Specialized Analyzer

This module provides specialized analysis capabilities for LockBit ransomware samples.
It includes detailed static and dynamic analysis, encryption detection, and decryption attempts
specifically tailored to the LockBit ransomware family patterns.

Key features:
- Specialized static analysis for LockBit indicators
- Decryption pattern detection for LockBit
- Specialized format analysis for .restorebackup files
- Integration with network-based key extraction
- Comprehensive reporting in both Chinese and English
"""

import os
import sys
import re
import json
import logging
import hashlib
import struct
import base64
import binascii
import datetime
import argparse
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any, Union, BinaryIO

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import project components
try:
    from decryption_tools.ransomware_recovery import RansomwareRecovery
    from decryption_tools.external.encryption_analyzer import EncryptionAnalyzer
    from decryption_tools.network_forensics.network_based_recovery import NetworkKeyExtractor, NetworkBasedRecovery
    MODULES_AVAILABLE = True
except ImportError:
    MODULES_AVAILABLE = False
    print("Warning: Some project modules could not be imported, functionality will be limited")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("LockBitAnalyzer")


class LockBitFile:
    """Represents an analyzed LockBit ransomware file"""
    
    def __init__(self, file_path: str):
        """
        Initialize with file path
        
        Args:
            file_path: Path to the file
        """
        self.file_path = os.path.abspath(file_path)
        self.file_name = os.path.basename(file_path)
        self.file_size = os.path.getsize(file_path)
        self.file_type = self._get_file_type()
        self.hashes = self._compute_hashes()
        self.is_encrypted = False
        self.is_encryptor = False
        self.is_decryptor = False
        self.is_countermeasure = False
        self.encryption_markers = {}
        self.network_indicators = {}
        self.analysis_results = {}
        
    def _get_file_type(self) -> str:
        """Determine file type"""
        try:
            # Use file command
            proc = subprocess.run(['file', '-b', self.file_path], 
                                capture_output=True, check=False)
            return proc.stdout.decode('utf-8', errors='ignore').strip()
        except Exception:
            # Fallback to extension-based detection
            ext = os.path.splitext(self.file_path)[1].lower()
            if ext == '.exe':
                return "PE32 executable"
            elif ext == '.bat':
                return "Batch file"
            elif ext == '.dll':
                return "PE32 DLL"
            elif '.restorebackup' in self.file_name:
                return "LockBit encrypted file"
            else:
                return "Unknown"
    
    def _compute_hashes(self) -> Dict[str, str]:
        """Compute file hashes"""
        hashes = {}
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
                hashes['md5'] = hashlib.md5(data).hexdigest()
                hashes['sha1'] = hashlib.sha1(data).hexdigest()
                hashes['sha256'] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            logger.error(f"Error computing hashes: {e}")
        return hashes
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "file_path": self.file_path,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "file_type": self.file_type,
            "hashes": self.hashes,
            "is_encrypted": self.is_encrypted,
            "is_encryptor": self.is_encryptor,
            "is_decryptor": self.is_decryptor,
            "is_countermeasure": self.is_countermeasure,
            "encryption_markers": self.encryption_markers,
            "network_indicators": self.network_indicators,
            "analysis_results": self.analysis_results
        }


class LockBitAnalyzer:
    """
    Specialized analyzer for LockBit ransomware samples
    """
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize the LockBit analyzer
        
        Args:
            output_dir: Optional output directory for results
        """
        # Set up output directory
        if output_dir:
            self.output_dir = os.path.abspath(output_dir)
        else:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_dir = os.path.join(os.getcwd(), f"lockbit_analysis_{timestamp}")
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Set up log file
        log_file = os.path.join(self.output_dir, 'lockbit_analysis.log')
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(file_handler)
        
        # Initialize decryption tools if available
        self.recovery = None
        self.encryption_analyzer = None
        if MODULES_AVAILABLE:
            try:
                self.recovery = RansomwareRecovery()
                self.encryption_analyzer = EncryptionAnalyzer()
            except Exception as e:
                logger.error(f"Error initializing decryption tools: {e}")
        
        # LockBit specific patterns
        self.lockbit_patterns = {
            'file_markers': [
                rb'.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}',
                rb'LockBit',
                rb'LOCKBIT DECRYPTOR',
                rb'PAY\s+[A-Z0-9]{20,}',
                rb'lock[A-Za-z0-9]{4,}\.bit',
                rb'lock[A-Za-z0-9]{4,}\.onion'
            ],
            'encryption_artifacts': [
                rb'AES-NI',
                rb'ChaCha\d+',
                rb'Salsa\d+',
                rb'\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}'
            ],
            'network_indicators': [
                rb'http://lockbit[a-z0-9-]{0,20}\.onion',
                rb'https?://[a-z0-9]{10,}\.onion',
                rb'TOR[a-zA-Z0-9\s-]{1,20}Browser'
            ],
            'antivirus_evasion': [
                rb'taskkill',
                rb'process\s*hacker',
                rb'\/tn\s+"',
                rb'reg\s*delete',
                rb'wmic\s+process\s+delete',
                rb'bcdedit\s+\/set',
                rb'vssadmin\s+delete'
            ]
        }
        
        # Sample collection
        self.samples = {}
        
        # Analysis results
        self.analysis_results = {
            'timestamp': datetime.datetime.now().isoformat(),
            'sample_count': 0,
            'identified_components': [],
            'decryption_attempts': [],
            'is_lockbit_confirmed': False,
            'confidence': 0.0,
            'detected_version': '',
            'recommendations': []
        }
    
    def analyze_file(self, file_path: str) -> LockBitFile:
        """
        Perform specialized LockBit analysis on a file
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            LockBitFile object with analysis results
        """
        logger.info(f"Analyzing file: {file_path}")
        lb_file = LockBitFile(file_path)
        
        # 1. Perform basic LockBit pattern analysis
        self._analyze_lockbit_patterns(lb_file)
        
        # 2. Perform executable-specific analysis for PE files
        if "PE32" in lb_file.file_type:
            self._analyze_pe_file(lb_file)
        
        # 3. Perform BAT script analysis if it's a batch file
        elif "Batch" in lb_file.file_type:
            self._analyze_batch_file(lb_file)
        
        # 4. Analyze encrypted files
        elif ".restorebackup" in lb_file.file_name:
            self._analyze_encrypted_file(lb_file)
        
        # 5. Save file to collection
        self.samples[lb_file.file_path] = lb_file
        self.analysis_results['sample_count'] += 1
        
        return lb_file
    
    def analyze_directory(self, directory_path: str) -> List[LockBitFile]:
        """
        Analyze all files in a directory
        
        Args:
            directory_path: Path to directory containing files
            
        Returns:
            List of analyzed LockBitFile objects
        """
        analyzed_files = []
        
        logger.info(f"Analyzing all files in: {directory_path}")
        for filename in os.listdir(directory_path):
            file_path = os.path.join(directory_path, filename)
            if os.path.isfile(file_path):
                lb_file = self.analyze_file(file_path)
                analyzed_files.append(lb_file)
        
        # Perform correlation analysis
        if len(analyzed_files) > 1:
            self._correlate_samples()
        
        return analyzed_files
    
    def _analyze_lockbit_patterns(self, lb_file: LockBitFile):
        """Analyze file for LockBit-specific patterns"""
        logger.info(f"Analyzing for LockBit patterns: {lb_file.file_name}")
        
        # Read file content
        try:
            with open(lb_file.file_path, 'rb') as f:
                data = f.read()
                
            # Check for file markers
            marker_matches = {}
            for pattern in self.lockbit_patterns['file_markers']:
                if re.search(pattern, data):
                    marker_matches[pattern.decode('utf-8', errors='ignore')] = True
            
            if marker_matches:
                lb_file.analysis_results['lockbit_markers'] = marker_matches
                self.analysis_results['is_lockbit_confirmed'] = True
                # Update confidence based on number of matches
                new_confidence = min(0.5 + (len(marker_matches) * 0.1), 0.95)
                self.analysis_results['confidence'] = max(self.analysis_results['confidence'], new_confidence)
            
            # Check for encryption artifacts
            encryption_matches = {}
            for pattern in self.lockbit_patterns['encryption_artifacts']:
                if re.search(pattern, data):
                    encryption_matches[pattern.decode('utf-8', errors='ignore')] = True
            
            if encryption_matches:
                lb_file.encryption_markers = encryption_matches
                # If file has encryption markers, it's likely the encryptor
                if "PE32" in lb_file.file_type and not lb_file.is_decryptor:
                    lb_file.is_encryptor = True
                    if "LockBit Encryptor" not in self.analysis_results['identified_components']:
                        self.analysis_results['identified_components'].append("LockBit Encryptor")
            
            # Check for network indicators
            network_matches = {}
            for pattern in self.lockbit_patterns['network_indicators']:
                matches = re.findall(pattern, data)
                for match in matches:
                    match_str = match.decode('utf-8', errors='ignore')
                    network_matches[match_str] = True
            
            if network_matches:
                lb_file.network_indicators = network_matches
            
            # Check for anti-AV patterns
            av_evasion_matches = {}
            for pattern in self.lockbit_patterns['antivirus_evasion']:
                if re.search(pattern, data):
                    av_evasion_matches[pattern.decode('utf-8', errors='ignore')] = True
            
            if av_evasion_matches:
                lb_file.analysis_results['av_evasion'] = av_evasion_matches
                # If file has many AV evasion techniques and is a batch file, it's likely the countermeasure script
                if "Batch" in lb_file.file_type and len(av_evasion_matches) > 2:
                    lb_file.is_countermeasure = True
                    if "LockBit Countermeasure Script" not in self.analysis_results['identified_components']:
                        self.analysis_results['identified_components'].append("LockBit Countermeasure Script")
            
            # Check for decryptor UI markers
            if "LOCKBIT DECRYPTOR" in data.decode('utf-8', errors='ignore'):
                lb_file.is_decryptor = True
                if "LockBit Decryptor UI" not in self.analysis_results['identified_components']:
                    self.analysis_results['identified_components'].append("LockBit Decryptor UI")
            
            # Additional LockBit version detection
            content = data.decode('utf-8', errors='ignore')
            if "LockBit 3.0" in content or "LockBit Black" in content:
                lb_file.analysis_results['version'] = "LockBit 3.0 (Black)"
                self.analysis_results['detected_version'] = "LockBit 3.0 (Black)"
            elif "LockBit 2.0" in content:
                lb_file.analysis_results['version'] = "LockBit 2.0"
                self.analysis_results['detected_version'] = "LockBit 2.0"
            elif "1765FE8E-2103-66E3-7DCB-72284ABD03AA" in content:
                lb_file.analysis_results['version'] = "LockBit 2.0"
                self.analysis_results['detected_version'] = "LockBit 2.0"
            
            # Check for file encryption extension pattern (LockBit specific)
            if ".{1765FE8E-2103-66E3-7DCB-72284ABD03AA}" in content:
                lb_file.analysis_results['encryption_extension'] = ".{1765FE8E-2103-66E3-7DCB-72284ABD03AA}"
                # If file has the extension pattern and is an EXE, it's very likely the encryptor
                if "PE32" in lb_file.file_type and not lb_file.is_decryptor:
                    lb_file.is_encryptor = True
                    if "LockBit Encryptor" not in self.analysis_results['identified_components']:
                        self.analysis_results['identified_components'].append("LockBit Encryptor")
        
        except Exception as e:
            logger.error(f"Error analyzing LockBit patterns: {e}")
    
    def _analyze_pe_file(self, lb_file: LockBitFile):
        """Analyze PE file for LockBit characteristics"""
        logger.info(f"Analyzing PE file: {lb_file.file_name}")
        
        # Run strings on the file
        try:
            strings_proc = subprocess.run(['strings', '-a', lb_file.file_path], 
                                        capture_output=True, check=False)
            strings_output = strings_proc.stdout.decode('utf-8', errors='ignore')
            
            # Look for encryption functions
            encryption_functions = []
            encryption_keywords = ['AES_set_encrypt_key', 'AES_encrypt', 'EVP_EncryptInit',
                                'CryptEncrypt', 'RC4_set_key', 'ChaCha20_ctr32', 'Salsa20']
            
            for func in encryption_functions:
                if func in strings_output:
                    encryption_functions.append(func)
            
            if encryption_functions:
                lb_file.analysis_results['encryption_functions'] = encryption_functions
                lb_file.is_encryptor = True
                if "LockBit Encryptor" not in self.analysis_results['identified_components']:
                    self.analysis_results['identified_components'].append("LockBit Encryptor")
            
            # Look for decryption functions
            decryption_functions = []
            decryption_keywords = ['AES_set_decrypt_key', 'AES_decrypt', 'EVP_DecryptInit',
                                'CryptDecrypt', 'RC4_set_key', 'ChaCha20_ctr32', 'Salsa20']
            
            for func in decryption_keywords:
                if func in strings_output:
                    decryption_functions.append(func)
            
            if decryption_functions and "DECRYPTOR" in strings_output:
                lb_file.analysis_results['decryption_functions'] = decryption_functions
                lb_file.is_decryptor = True
                if "LockBit Decryptor" not in self.analysis_results['identified_components']:
                    self.analysis_results['identified_components'].append("LockBit Decryptor UI")
            
            # Look for anti-analysis features
            anti_analysis = []
            anti_analysis_keywords = ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 
                                    'OutputDebugString', 'NtQueryInformationProcess',
                                    'GetTickCount', 'Sleep', 'QueryPerformanceCounter']
            
            for keyword in anti_analysis_keywords:
                if keyword in strings_output:
                    anti_analysis.append(keyword)
            
            if anti_analysis:
                lb_file.analysis_results['anti_analysis'] = anti_analysis
            
            # Look for persistence mechanisms
            persistence = []
            persistence_keywords = ['HKEY_LOCAL_MACHINE\\SOFTWARE', 'HKEY_CURRENT_USER\\SOFTWARE',
                                  'HKLM\\SOFTWARE', 'HKCU\\SOFTWARE', 'CurrentVersion\\Run',
                                  'Shell\\Open\\Command', 'ScheduledTask', 'schtasks',
                                  'WinLogon']
            
            for keyword in persistence_keywords:
                if keyword in strings_output:
                    persistence.append(keyword)
            
            if persistence:
                lb_file.analysis_results['persistence'] = persistence
            
            # If this is likely the encryptor component, extract more details
            if lb_file.is_encryptor:
                # Get ransom message
                ransom_snippets = []
                ransom_message_patterns = [
                    r'Your files are encrypted',
                    r'All of your files have been encrypted',
                    r'To decrypt your files, you need to buy the decryption key',
                    r'lockbit',
                    r'your personal id',
                    r'recovery key',
                    r'bitcoin address',
                    r'payment'
                ]
                
                for pattern in ransom_message_patterns:
                    match = re.search(pattern, strings_output, re.IGNORECASE)
                    if match:
                        context_start = max(0, match.start() - 100)
                        context_end = min(len(strings_output), match.end() + 100)
                        snippet = strings_output[context_start:context_end].strip()
                        ransom_snippets.append(snippet)
                
                if ransom_snippets:
                    lb_file.analysis_results['ransom_message_snippets'] = ransom_snippets
            
            # Extract .onion URLs
            onion_urls = re.findall(r'https?://[a-z0-9]{10,}\.onion', strings_output)
            if onion_urls:
                lb_file.network_indicators['onion_urls'] = onion_urls
            
            # Extract potential C2 IP addresses
            ip_addresses = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', strings_output)
            if ip_addresses:
                # Filter out common false positives
                filtered_ips = [ip for ip in ip_addresses if not (
                    ip.startswith('127.') or ip.startswith('0.') or 
                    ip.startswith('255.') or ip.startswith('224.')
                )]
                if filtered_ips:
                    lb_file.network_indicators['ip_addresses'] = filtered_ips
            
            # Extract encryption file extension
            extension_pattern = re.search(r'\.\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}', 
                                        strings_output)
            if extension_pattern:
                lb_file.analysis_results['encryption_extension'] = extension_pattern.group(0)
        
        except Exception as e:
            logger.error(f"Error analyzing PE file: {e}")
    
    def _analyze_batch_file(self, lb_file: LockBitFile):
        """Analyze batch file for LockBit characteristics"""
        logger.info(f"Analyzing batch file: {lb_file.file_name}")
        
        try:
            with open(lb_file.file_path, 'r', errors='ignore') as f:
                content = f.read()
            
            # Check for security software termination
            security_termination = []
            security_software = [
                'taskkill.*defender', 'taskkill.*msmpeng', 'taskkill.*mcafee',
                'taskkill.*norton', 'taskkill.*kaspersky', 'taskkill.*avast',
                'taskkill.*avira', 'taskkill.*mbae', 'taskkill.*sophos',
                'taskkill.*trend', 'taskkill.*eset', 'taskkill.*cylance'
            ]
            
            for software in security_software:
                if re.search(software, content, re.IGNORECASE):
                    security_termination.append(software.replace('taskkill.*', ''))
            
            if security_termination:
                lb_file.analysis_results['security_termination'] = security_termination
                lb_file.is_countermeasure = True
                if "LockBit Countermeasure Script" not in self.analysis_results['identified_components']:
                    self.analysis_results['identified_components'].append("LockBit Countermeasure Script")
            
            # Check for backup/recovery prevention
            backup_prevention = []
            backup_keywords = [
                'vssadmin.*delete', 'bcdedit.*set', 'wbadmin.*delete',
                'wmic.*shadowcopy.*delete', 'powershell.*win32_shadowcopy',
                'reg.*system\\\\currentcontrolset\\\\services\\\\vss'
            ]
            
            for keyword in backup_keywords:
                if re.search(keyword, content, re.IGNORECASE):
                    backup_prevention.append(keyword.split('.*')[0])
            
            if backup_prevention:
                lb_file.analysis_results['backup_prevention'] = backup_prevention
            
            # Check for service manipulation
            service_manipulation = []
            service_keywords = [
                'sc.*stop', 'net.*stop', 'sc.*config', 'sc.*delete'
            ]
            
            for keyword in service_keywords:
                matches = re.findall(f'{keyword}\\s+([\\w-]+)', content, re.IGNORECASE)
                for match in matches:
                    if match not in ['winrm', 'ws']:  # Filter common false positives
                        service_manipulation.append(match)
            
            if service_manipulation:
                lb_file.analysis_results['service_manipulation'] = service_manipulation
        
        except Exception as e:
            logger.error(f"Error analyzing batch file: {e}")
    
    def _analyze_encrypted_file(self, lb_file: LockBitFile):
        """Analyze LockBit encrypted file"""
        logger.info(f"Analyzing encrypted file: {lb_file.file_name}")
        
        lb_file.is_encrypted = True
        if "LockBit Encrypted Files" not in self.analysis_results['identified_components']:
            self.analysis_results['identified_components'].append("LockBit Encrypted Files")
        
        try:
            with open(lb_file.file_path, 'rb') as f:
                data = f.read()
            
            # Calculate entropy to confirm encryption
            entropy = self._calculate_entropy(data)
            lb_file.analysis_results['entropy'] = entropy
            
            # LockBit typically uses high entropy for encrypted files
            if entropy > 7.0:
                lb_file.analysis_results['high_entropy'] = True
            
            # Check for LockBit file structure
            # LockBit 2.0 adds the extension with UUID and usually preserves original extension
            if '.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}' in lb_file.file_name:
                lb_file.analysis_results['lockbit_extension'] = True
                
                # Extract original extension
                original_name = lb_file.file_name.split('.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}')[0]
                original_ext = os.path.splitext(original_name)[1]
                if original_ext:
                    lb_file.analysis_results['original_extension'] = original_ext
            
            # LockBit 2.0 usually stores encryption info in the first 16 bytes (IV or marker)
            if len(data) >= 16:
                header = data[:16]
                header_hex = header.hex()
                lb_file.analysis_results['file_header'] = header_hex
                
                # Try to detect encryption method
                if all(0 <= b <= 255 for b in header) and entropy > 3.5:
                    lb_file.analysis_results['possible_iv'] = True
            
            # Attempt limited format detection on encrypted data
            # Some known file types might be partially recognizable even when encrypted
            try:
                # Check for encrypted PNG
                if len(data) > 50 and data[0] == 137 and data[1] in range(80, 90):
                    lb_file.analysis_results['possible_original_type'] = 'PNG image'
                
                # Check for encrypted JPEG
                elif len(data) > 50 and data[0] == 255 and data[1] in range(213, 219):
                    lb_file.analysis_results['possible_original_type'] = 'JPEG image'
                
                # Check for encrypted PDF
                elif len(data) > 50 and data[0] in range(35, 40) and data[1] in range(80, 85):
                    lb_file.analysis_results['possible_original_type'] = 'PDF document'
                
                # Check for encrypted Office document (DOCX, XLSX)
                elif len(data) > 50 and data[0] == 80 and data[1] in range(75, 90):
                    lb_file.analysis_results['possible_original_type'] = 'Microsoft Office document'
            except:
                pass
            
            # Check for encryption key inside file (rare but possible)
            # LockBit sometimes includes metadata at the end of encrypted files
            if len(data) > 256:
                tail = data[-256:]
                
                # Look for non-random data in the tail
                tail_entropy = self._calculate_entropy(tail)
                if tail_entropy < 7.0 and tail_entropy > 3.0:
                    lb_file.analysis_results['possible_metadata_tail'] = True
                    
                    # Check for key markers
                    if b'KEY' in tail or b'key' in tail:
                        lb_file.analysis_results['possible_key_reference'] = True
                    
                    # Check for ID markers
                    if b'ID:' in tail or b'id:' in tail:
                        lb_file.analysis_results['possible_id_reference'] = True
        
        except Exception as e:
            logger.error(f"Error analyzing encrypted file: {e}")
    
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
    
    def _correlate_samples(self):
        """Correlate all samples to identify LockBit components"""
        logger.info("Correlating all samples")
        
        # Count identified components
        encryptor_count = sum(1 for file in self.samples.values() if file.is_encryptor)
        decryptor_count = sum(1 for file in self.samples.values() if file.is_decryptor)
        countermeasure_count = sum(1 for file in self.samples.values() if file.is_countermeasure)
        encrypted_count = sum(1 for file in self.samples.values() if file.is_encrypted)
        
        # Confirm LockBit based on component presence
        if encryptor_count > 0 and encrypted_count > 0:
            self.analysis_results['is_lockbit_confirmed'] = True
            self.analysis_results['confidence'] = max(self.analysis_results['confidence'], 0.85)
            logger.info("LockBit ransomware confirmed with high confidence")
        
        # Get common extension
        extensions = []
        for file in self.samples.values():
            if 'encryption_extension' in file.analysis_results:
                extensions.append(file.analysis_results['encryption_extension'])
        
        if extensions:
            # Use most common extension
            from collections import Counter
            common_ext = Counter(extensions).most_common(1)[0][0]
            self.analysis_results['encryption_extension'] = common_ext
            logger.info(f"Identified common encryption extension: {common_ext}")
        
        # Get common .onion URLs
        onion_urls = []
        for file in self.samples.values():
            if 'onion_urls' in file.network_indicators:
                onion_urls.extend(file.network_indicators['onion_urls'])
        
        if onion_urls:
            # Use unique URLs
            unique_urls = list(set(onion_urls))
            self.analysis_results['onion_urls'] = unique_urls
            logger.info(f"Identified {len(unique_urls)} unique .onion URLs")
        
        # Generate recommendations based on analysis
        self._generate_recommendations()
    
    def _generate_recommendations(self):
        """Generate recommendations based on analysis results"""
        recommendations = []
        
        # Basic recommendations for any ransomware
        recommendations.append("Àsîª◊”˚ﬂ≠ Q‹ﬁ•Â2bˆ")
        recommendations.append("(Ô·ÑÕ≈“oˆkœ*◊”Ñ˚ﬂ")
        recommendations.append("¿Â˝Ñåt'vn›ÉÏ*´†∆")
        
        # Specific recommendations for LockBit
        if self.analysis_results['is_lockbit_confirmed']:
            if any(file.is_countermeasure for file in self.samples.values()):
                recommendations.append("ÿüqPwo,° (VSS)ÓÔ˝´;˚Å(ÑWindows˝ü˝")
            
            recommendations.append("(Ô˝ÑM9„∆ÂwÇ'LockBit Decryptor'’báˆ")
            recommendations.append("¿Â´;˚Ñ˚ﬂÂ∑÷†∆∆•LockBit	ˆ∆•X®(,0")
            
            # Add version-specific recommendations
            if "3.0" in self.analysis_results.get('detected_version', ''):
                recommendations.append("(€—∆ÂwkœÖX-Ô˝X(Ñ„∆∆•")
                recommendations.append("LockBit 3.0(˜†∆πHËáˆÔ˝«(1†∆ó’")
            else:
                recommendations.append("Â~yÅ :'.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}'Ñáˆ")
        
        self.analysis_results['recommendations'] = recommendations
    
    def attempt_decryption(self, encrypted_file_path: str, output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Attempt to decrypt a LockBit encrypted file
        
        Args:
            encrypted_file_path: Path to encrypted file
            output_path: Optional path for decrypted output
            
        Returns:
            Dictionary with decryption results
        """
        if not MODULES_AVAILABLE:
            logger.error("Decryption modules not available")
            return {"success": False, "error": "Decryption modules not available"}
        
        if not self.recovery:
            logger.error("Recovery module not initialized")
            return {"success": False, "error": "Recovery module not initialized"}
        
        logger.info(f"Attempting decryption of: {encrypted_file_path}")
        
        # Create network-based recovery for LockBit
        try:
            # First check if we have the file in our analyzed samples
            lb_file = None
            if encrypted_file_path in self.samples:
                lb_file = self.samples[encrypted_file_path]
            else:
                # If not, quickly analyze it
                lb_file = LockBitFile(encrypted_file_path)
                self._analyze_encrypted_file(lb_file)
            
            # Prepare output path
            if not output_path:
                output_dir = os.path.join(self.output_dir, 'decrypted')
                os.makedirs(output_dir, exist_ok=True)
                
                # Get original filename without LockBit extension
                original_name = os.path.basename(encrypted_file_path)
                if '.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}' in original_name:
                    original_name = original_name.split('.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}')[0]
                
                output_path = os.path.join(output_dir, f"decrypted_{original_name}")
            
            # Create test PCAP for network key extractor
            dummy_pcap = os.path.join(self.output_dir, 'dummy.pcap')
            with open(dummy_pcap, 'wb') as f:
                f.write(b'\x00' * 24)  # Minimal PCAP header
            
            # Initialize network-based recovery with LockBit-specific adaptations
            network_key_extractor = NetworkKeyExtractor(dummy_pcap)
            
            # Add LockBit specific key patterns
            network_key_extractor.key_patterns['aes'].append(rb'1765FE8E-2103-66E3-7DCB-72284ABD03AA')
            
            # Look for keys in all analyzed samples
            found_keys = []
            for sample_path, sample in self.samples.items():
                if sample.is_encryptor or sample.is_decryptor:
                    logger.info(f"Searching for keys in sample: {sample.file_name}")
                    try:
                        with open(sample_path, 'rb') as f:
                            sample_data = f.read()
                        
                        # Try to find keys in the sample
                        blocks = network_key_extractor._find_high_entropy_blocks(sample_data, min_length=16, max_length=32)
                        for block, entropy in blocks:
                            if 16 <= len(block) <= 32 and entropy > 6.5:
                                key_type = network_key_extractor._guess_key_type(block, entropy)
                                src_ip = "127.0.0.1"  # Local source
                                dst_ip = "127.0.0.1"  # Local destination
                                timestamp = datetime.datetime.now()
                                from decryption_tools.network_forensics.network_based_recovery import ExtractedKey
                                
                                key = ExtractedKey(
                                    key_data=block,
                                    key_type=key_type,
                                    source_ip=src_ip,
                                    destination_ip=dst_ip,
                                    timestamp=timestamp,
                                    confidence=0.7,
                                    context={"source": "ransomware_sample", "sample": sample.file_name}
                                )
                                found_keys.append(key)
                    except Exception as e:
                        logger.error(f"Error searching for keys in sample: {e}")
            
            # Try decryption with found keys
            if found_keys:
                logger.info(f"Found {len(found_keys)} potential keys")
                recovery = NetworkBasedRecovery(found_keys)
                
                # Attempt decryption
                results = recovery.attempt_decryption(encrypted_file_path, output_path)
                
                for result in results:
                    if result.success:
                        logger.info(f"Successfully decrypted file to: {output_path}")
                        # Record successful attempt
                        self.analysis_results['decryption_attempts'].append({
                            "file": os.path.basename(encrypted_file_path),
                            "success": True,
                            "output": output_path,
                            "method": "network_based_recovery"
                        })
                        return {"success": True, "output_path": output_path}
            
            # If network-based approach failed, try ransomware-specific approaches
            logger.info("Network-based decryption failed, trying ransomware recovery tools")
            
            # Prepare family info
            family_info = {
                "family": "LockBit",
                "variant": self.analysis_results.get('detected_version', 'unknown'),
                "extension": self.analysis_results.get('encryption_extension', '.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}')
            }
            
            # Use the RansomwareRecovery module
            success = self.recovery.decrypt_file(
                encrypted_file_path,
                tool_id="auto",
                output_file=output_path,
                options=family_info
            )
            
            if success:
                logger.info(f"Successfully decrypted file to: {output_path}")
                # Record successful attempt
                self.analysis_results['decryption_attempts'].append({
                    "file": os.path.basename(encrypted_file_path),
                    "success": True,
                    "output": output_path,
                    "method": "ransomware_recovery"
                })
                return {"success": True, "output_path": output_path}
            else:
                logger.info("Decryption failed")
                # Record failed attempt
                self.analysis_results['decryption_attempts'].append({
                    "file": os.path.basename(encrypted_file_path),
                    "success": False,
                    "method": "combined"
                })
                return {"success": False, "error": "Decryption failed with all methods"}
        
        except Exception as e:
            logger.error(f"Error during decryption attempt: {e}")
            # Record failed attempt
            self.analysis_results['decryption_attempts'].append({
                "file": os.path.basename(encrypted_file_path),
                "success": False,
                "error": str(e),
                "method": "combined"
            })
            return {"success": False, "error": str(e)}
    
    def generate_report(self, lang: str = 'cn') -> str:
        """
        Generate a comprehensive analysis report
        
        Args:
            lang: Language for the report ('cn' for Chinese, 'en' for English)
            
        Returns:
            Path to the generated report file
        """
        if lang == 'en':
            return self._generate_english_report()
        else:
            return self._generate_chinese_report()
    
    def _generate_chinese_report(self) -> str:
        """Generate a comprehensive Chinese analysis report"""
        logger.info("-áê•J")
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(self.output_dir, f'LockBitê•J_{timestamp}.md')
        
        with open(report_path, 'w', encoding='utf-8') as f:
            # Title
            f.write("# LockBit“"oˆê•J\n\n")
            f.write(f"*êˆÙ: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
            
            # Summary
            f.write("## êXÅ\n\n")
            
            if self.analysis_results['is_lockbit_confirmed']:
                confidence = int(self.analysis_results['confidence'] * 100)
                f.write(f"**¿K0Ñ“"oˆ∂œ**: LockBit (n·¶: {confidence}%)\n\n")
                
                if self.analysis_results.get('detected_version'):
                    f.write(f"**¿K0ÑH,**: {self.analysis_results['detected_version']}\n\n")
            else:
                f.write("***˝nö“"oˆ∂œ**\n\n")
            
            # Analyzed components
            f.write("## êÑƒˆ\n\n")
            f.write(f"qêÜ {self.analysis_results['sample_count']} *áˆ\n\n")
            
            if self.analysis_results['identified_components']:
                f.write("### Ú∆+ƒˆ\n\n")
                for component in self.analysis_results['identified_components']:
                    if component == "LockBit Encryptor":
                        f.write("- **†∆hƒˆ** - #†∆◊≥áˆ\n")
                    elif component == "LockBit Decryptor UI":
                        f.write("- **„∆hLb** - (é„∆áˆÑLbƒˆ\n")
                    elif component == "LockBit Countermeasure Script":
                        f.write("- **Õâh™Ω,** - (éÅ(âhoˆå˝Ñy,\n")
                    elif component == "LockBit Encrypted Files":
                        f.write("- **´†∆áˆ7,** - LockBit†∆Ñáˆ:ã\n")
            
            # Sample details
            f.write("### 7,Ê≈\n\n")
            f.write("| áˆ | ' | {ã | ƒˆ | MD5 |\n")
            f.write("|-------|------|------|------|-----|\n")
            
            for sample in self.samples.values():
                component_type = ""
                if sample.is_encryptor:
                    component_type = "†∆h"
                elif sample.is_decryptor:
                    component_type = "„∆h"
                elif sample.is_countermeasure:
                    component_type = "Õâh™Ω,"
                elif sample.is_encrypted:
                    component_type = "´†∆áˆ"
                else:
                    component_type = "*Â"
                
                f.write(f"| {sample.file_name} | {sample.file_size} WÇ | {sample.file_type} | {component_type} | {sample.hashes.get('md5', 'N/A')} |\n")
            
            # Technical details
            f.write("\n## Ä/∆Ç\n\n")
            
            # Encryption details
            f.write("### †∆∆Ç\n\n")
            
            if self.analysis_results.get('encryption_extension'):
                f.write(f"- **†∆áˆiU**: `{self.analysis_results['encryption_extension']}`\n")
            
            f.write("- **†∆π’**: LockBit(˜†∆πH\n")
            f.write("  - áˆ†∆(AES-256∆•\n")
            f.write("  - AES∆•(RSA-2048l•†∆\n")
            f.write("  - œ*áˆ(/ ÑAES∆•\n")
            
            # Network indicators
            f.write("\n### Q‹\n\n")
            
            if self.analysis_results.get('onion_urls'):
                f.write("#### TorqQ‹0@\n\n")
                for url in self.analysis_results['onion_urls']:
                    f.write(f"- `{url}`\n")
                
                f.write("\nŸõ0@(é;˚Ñ/ÿË7·\n")
            
            # Behavioral analysis
            f.write("\n### L:ê\n\n")
            
            encryptor_behaviors = []
            countermeasure_behaviors = []
            
            for sample in self.samples.values():
                if sample.is_encryptor:
                    encryptor_behaviors.append(f"- áˆ `{sample.file_name}` +†∆ü˝")
                    if 'encryption_functions' in sample.analysis_results:
                        functions = sample.analysis_results['encryption_functions']
                        encryptor_behaviors.append(f"  - (Ñ†∆˝p: {', '.join(functions)}")
                    
                    if 'anti_analysis' in sample.analysis_results:
                        techniques = sample.analysis_results['anti_analysis']
                        encryptor_behaviors.append(f"  - (ÑÕêÄ/: {', '.join(techniques)}")
                
                if sample.is_countermeasure:
                    countermeasure_behaviors.append(f"- áˆ `{sample.file_name}` +Õâh™Ω")
                    if 'security_termination' in sample.analysis_results:
                        software = sample.analysis_results['security_termination']
                        countermeasure_behaviors.append(f"  - ’»bÑâhoˆ: {', '.join(software)}")
                    
                    if 'backup_prevention' in sample.analysis_results:
                        techniques = sample.analysis_results['backup_prevention']
                        countermeasure_behaviors.append(f"  - (ÑÕ˝Ä/: {', '.join(techniques)}")
            
            if encryptor_behaviors:
                f.write("#### †∆hL:\n\n")
                for behavior in encryptor_behaviors:
                    f.write(f"{behavior}\n")
            
            if countermeasure_behaviors:
                f.write("\n#### Õâh™ΩL:\n\n")
                for behavior in countermeasure_behaviors:
                    f.write(f"{behavior}\n")
            
            # Decryption attempts
            f.write("\n### „∆’\n\n")
            
            if self.analysis_results['decryption_attempts']:
                successful = sum(1 for a in self.analysis_results['decryption_attempts'] if a['success'])
                failed = len(self.analysis_results['decryption_attempts']) - successful
                
                f.write(f";q€LÜ {len(self.analysis_results['decryption_attempts'])} !„∆’v- {successful} !ü{failed} !1%\n\n")
                
                if successful > 0:
                    f.write("#### üÑ„∆’\n\n")
                    f.write("| áˆ | π’ | ì˙ÔÑ |\n")
                    f.write("|------|------|----------|\n")
                    
                    for attempt in self.analysis_results['decryption_attempts']:
                        if attempt['success']:
                            f.write(f"| {attempt['file']} | {attempt['method']} | {attempt.get('output', 'N/A')} |\n")
                else:
                    f.write("@	„∆’GJ1%ŸhÂ“"oˆ(Ü:†∆πH‡’«Í®Âw€L„∆\n")
            else:
                f.write("*€L„∆’\n")
            
            # Recommendations
            f.write("\n## ˙Æ\n\n")
            
            if self.analysis_results['recommendations']:
                for recommendation in self.analysis_results['recommendations']:
                    f.write(f"- {recommendation}\n")
            else:
                f.write("- Àsîª◊”˚ﬂ≠ Q‹ﬁ•Â2bˆ\n")
                f.write("- (Ô·ÑÕ≈“oˆkœ*◊”Ñ˚ﬂ\n")
                f.write("- ¿Â˝Ñåt'vn›ÉÏ*´†∆\n")
            
            # IOCs
            f.write("\n## ¡ (IOCs)\n\n")
            
            # File hashes
            f.write("### áˆ»\n\n")
            f.write("| áˆ | MD5 | SHA256 |\n")
            f.write("|-------|-----|--------|\n")
            
            for sample in self.samples.values():
                md5 = sample.hashes.get('md5', 'N/A')
                sha256 = sample.hashes.get('sha256', 'N/A')
                f.write(f"| {sample.file_name} | {md5} | {sha256} |\n")
            
            # File markers
            f.write("\n### áˆ∞\n\n")
            f.write(f"- †∆áˆiU: `{self.analysis_results.get('encryption_extension', '.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}')}`\n")
            
            # Network IOCs
            if self.analysis_results.get('onion_urls'):
                f.write("\n### Q‹\n\n")
                for url in self.analysis_results['onion_urls']:
                    f.write(f"- `{url}`\n")
            
            # Conclusion
            f.write("\n## ”∫\n\n")
            
            if self.analysis_results['is_lockbit_confirmed']:
                f.write("ên§Ÿ/**LockBit“"oˆ**ÑƒˆLockBit/ ÕqiÑ“"oˆ(:†∆ó’åBÑÕâh™Ω")
                
                if "LockBit Encryptor" in self.analysis_results['identified_components']:
                    f.write(" 7,-+†∆ƒˆÔÂ˘˚ﬂ-Ñáˆ€L†∆")
                
                if "LockBit Countermeasure Script" in self.analysis_results['identified_components']:
                    f.write(" d7,-+Õâh™Ω,ÔÂÅ(âhoˆå˝ü˝")
                
                f.write(" ˙ÆÀs«÷„™Ωîª◊”˚ﬂv«Ô·˝bpn\n")
            else:
                f.write("}67,>:˙“"oˆÑyÅF‡’növwS∂œ˙Æ(Nv	g˙Æ«÷„™Ω\n")
        
        logger.info(f"-áê•JÚ: {report_path}")
        return report_path
    
    def _generate_english_report(self) -> str:
        """Generate a comprehensive English analysis report"""
        logger.info("Generating English analysis report")
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(self.output_dir, f'LockBit_Analysis_Report_{timestamp}.md')
        
        with open(report_path, 'w', encoding='utf-8') as f:
            # Title
            f.write("# LockBit Ransomware Analysis Report\n\n")
            f.write(f"*Analysis Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
            
            # Summary
            f.write("## Analysis Summary\n\n")
            
            if self.analysis_results['is_lockbit_confirmed']:
                confidence = int(self.analysis_results['confidence'] * 100)
                f.write(f"**Detected Ransomware Family**: LockBit (Confidence: {confidence}%)\n\n")
                
                if self.analysis_results.get('detected_version'):
                    f.write(f"**Detected Version**: {self.analysis_results['detected_version']}\n\n")
            else:
                f.write("**Unable to determine ransomware family**\n\n")
            
            # Analyzed components
            f.write("## Analyzed Components\n\n")
            f.write(f"A total of {self.analysis_results['sample_count']} files were analyzed\n\n")
            
            if self.analysis_results['identified_components']:
                f.write("### Identified Components\n\n")
                for component in self.analysis_results['identified_components']:
                    if component == "LockBit Encryptor":
                        f.write("- **Encryptor Component** - Responsible for encrypting victim files\n")
                    elif component == "LockBit Decryptor UI":
                        f.write("- **Decryptor UI** - Interface component for decrypting files\n")
                    elif component == "LockBit Countermeasure Script":
                        f.write("- **Countermeasure Script** - Batch script for disabling security software and backups\n")
                    elif component == "LockBit Encrypted Files":
                        f.write("- **Encrypted File Samples** - Examples of LockBit encrypted files\n")
            
            # Sample details
            f.write("### Sample Details\n\n")
            f.write("| Filename | Size | Type | Component | MD5 |\n")
            f.write("|----------|------|------|-----------|-----|\n")
            
            for sample in self.samples.values():
                component_type = ""
                if sample.is_encryptor:
                    component_type = "Encryptor"
                elif sample.is_decryptor:
                    component_type = "Decryptor"
                elif sample.is_countermeasure:
                    component_type = "Countermeasure Script"
                elif sample.is_encrypted:
                    component_type = "Encrypted File"
                else:
                    component_type = "Unknown"
                
                f.write(f"| {sample.file_name} | {sample.file_size} bytes | {sample.file_type} | {component_type} | {sample.hashes.get('md5', 'N/A')} |\n")
            
            # Technical details
            f.write("\n## Technical Details\n\n")
            
            # Encryption details
            f.write("### Encryption Details\n\n")
            
            if self.analysis_results.get('encryption_extension'):
                f.write(f"- **Encrypted File Extension**: `{self.analysis_results['encryption_extension']}`\n")
            
            f.write("- **Encryption Method**: LockBit uses a hybrid encryption scheme\n")
            f.write("  - Files are encrypted using AES-256 keys\n")
            f.write("  - AES keys are encrypted using an RSA-2048 public key\n")
            f.write("  - Each file uses a unique AES key\n")
            
            # Network indicators
            f.write("\n### Network Indicators\n\n")
            
            if self.analysis_results.get('onion_urls'):
                f.write("#### Tor Onion Addresses\n\n")
                for url in self.analysis_results['onion_urls']:
                    f.write(f"- `{url}`\n")
                
                f.write("\nThese addresses are used for communication with the attacker's payment portal.\n")
            
            # Behavioral analysis
            f.write("\n### Behavioral Analysis\n\n")
            
            encryptor_behaviors = []
            countermeasure_behaviors = []
            
            for sample in self.samples.values():
                if sample.is_encryptor:
                    encryptor_behaviors.append(f"- File `{sample.file_name}` contains encryption capabilities")
                    if 'encryption_functions' in sample.analysis_results:
                        functions = sample.analysis_results['encryption_functions']
                        encryptor_behaviors.append(f"  - Encryption functions used: {', '.join(functions)}")
                    
                    if 'anti_analysis' in sample.analysis_results:
                        techniques = sample.analysis_results['anti_analysis']
                        encryptor_behaviors.append(f"  - Anti-analysis techniques used: {', '.join(techniques)}")
                
                if sample.is_countermeasure:
                    countermeasure_behaviors.append(f"- File `{sample.file_name}` contains security countermeasures")
                    if 'security_termination' in sample.analysis_results:
                        software = sample.analysis_results['security_termination']
                        countermeasure_behaviors.append(f"  - Security software targeted for termination: {', '.join(software)}")
                    
                    if 'backup_prevention' in sample.analysis_results:
                        techniques = sample.analysis_results['backup_prevention']
                        countermeasure_behaviors.append(f"  - Backup prevention techniques used: {', '.join(techniques)}")
            
            if encryptor_behaviors:
                f.write("#### Encryptor Behavior\n\n")
                for behavior in encryptor_behaviors:
                    f.write(f"{behavior}\n")
            
            if countermeasure_behaviors:
                f.write("\n#### Countermeasure Behavior\n\n")
                for behavior in countermeasure_behaviors:
                    f.write(f"{behavior}\n")
            
            # Decryption attempts
            f.write("\n### Decryption Attempts\n\n")
            
            if self.analysis_results['decryption_attempts']:
                successful = sum(1 for a in self.analysis_results['decryption_attempts'] if a['success'])
                failed = len(self.analysis_results['decryption_attempts']) - successful
                
                f.write(f"A total of {len(self.analysis_results['decryption_attempts'])} decryption attempts were made, with {successful} successes and {failed} failures.\n\n")
                
                if successful > 0:
                    f.write("#### Successful Decryption Attempts\n\n")
                    f.write("| File | Method | Output Path |\n")
                    f.write("|------|--------|-------------|\n")
                    
                    for attempt in self.analysis_results['decryption_attempts']:
                        if attempt['success']:
                            f.write(f"| {attempt['file']} | {attempt['method']} | {attempt.get('output', 'N/A')} |\n")
                else:
                    f.write("All decryption attempts failed. This indicates that the ransomware uses a strong encryption scheme that cannot be decrypted through automated tools.\n")
            else:
                f.write("No decryption attempts were made.\n")
            
            # Recommendations
            f.write("\n## Recommendations\n\n")
            
            if self.analysis_results['recommendations']:
                for recommendation in self.analysis_results['recommendations']:
                    # Translate Chinese recommendations to English
                    if recommendation == "Àsîª◊”˚ﬂ≠ Q‹ﬁ•Â2bˆ":
                        f.write("- Immediately isolate infected systems and disconnect from the network to prevent spread\n")
                    elif recommendation == "(Ô·ÑÕ≈“oˆkœ*◊”Ñ˚ﬂ":
                        f.write("- Scan uninfected systems with trusted antivirus software\n")
                    elif recommendation == "¿Â˝Ñåt'vn›ÉÏ*´†∆":
                        f.write("- Check the integrity of backups and ensure they are not encrypted\n")
                    elif recommendation == "ÿüqPwo,° (VSS)ÓÔ˝´;˚Å(ÑWindows˝ü˝":
                        f.write("- Restore Volume Shadow Copy Service (VSS), repair Windows backup functionality that may have been disabled by the attacker\n")
                    elif recommendation == "(Ô˝ÑM9„∆ÂwÇ'LockBit Decryptor'’báˆ":
                        f.write("- Use potentially available free decryption tools like 'LockBit Decryptor' to attempt file recovery\n")
                    elif recommendation == "¿Â´;˚Ñ˚ﬂÂ∑÷†∆∆•LockBit	ˆ∆•X®(,0":
                        f.write("- Check compromised systems for encryption keys, as LockBit sometimes stores keys locally\n")
                    elif recommendation == "(€—∆ÂwkœÖX-Ô˝X(Ñ„∆∆•":
                        f.write("- Use process monitoring tools to scan for decryption keys potentially present in memory\n")
                    elif recommendation == "LockBit 3.0(˜†∆πHËáˆÔ˝«(1†∆ó’":
                        f.write("- LockBit 3.0 uses a hybrid encryption scheme; some files may use weaker encryption algorithms\n")
                    elif recommendation == "Â~yÅ :'.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}'Ñáˆ":
                        f.write("- Look for files with the characteristic suffix '.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}'\n")
                    else:
                        f.write(f"- {recommendation}\n")
            else:
                f.write("- Immediately isolate infected systems and disconnect from the network to prevent spread\n")
                f.write("- Scan uninfected systems with trusted antivirus software\n")
                f.write("- Check the integrity of backups and ensure they are not encrypted\n")
            
            # IOCs
            f.write("\n## Indicators of Compromise (IOCs)\n\n")
            
            # File hashes
            f.write("### File Hashes\n\n")
            f.write("| Filename | MD5 | SHA256 |\n")
            f.write("|----------|-----|--------|\n")
            
            for sample in self.samples.values():
                md5 = sample.hashes.get('md5', 'N/A')
                sha256 = sample.hashes.get('sha256', 'N/A')
                f.write(f"| {sample.file_name} | {md5} | {sha256} |\n")
            
            # File markers
            f.write("\n### File Markers\n\n")
            f.write(f"- Encrypted file extension: `{self.analysis_results.get('encryption_extension', '.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}')}`\n")
            
            # Network IOCs
            if self.analysis_results.get('onion_urls'):
                f.write("\n### Network Indicators\n\n")
                for url in self.analysis_results['onion_urls']:
                    f.write(f"- `{url}`\n")
            
            # Conclusion
            f.write("\n## Conclusion\n\n")
            
            if self.analysis_results['is_lockbit_confirmed']:
                f.write("Analysis confirms these are components of the **LockBit ransomware**. LockBit is a dangerous ransomware that employs strong encryption algorithms and sophisticated anti-security measures.")
                
                if "LockBit Encryptor" in self.analysis_results['identified_components']:
                    f.write(" The samples include an encryption component that can encrypt files on the system.")
                
                if "LockBit Countermeasure Script" in self.analysis_results['identified_components']:
                    f.write(" Additionally, the samples include a countermeasure script that can disable security software and backup functionality.")
                
                f.write(" It is recommended to take immediate mitigation measures, isolate infected systems, and restore data from trusted backups.\n")
            else:
                f.write("While the samples exhibit characteristics of ransomware, their specific family could not be determined. It is recommended to handle with caution and follow the mitigation recommendations.\n")
        
        logger.info(f"English analysis report generated: {report_path}")
        return report_path


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="LockBit Ransomware Analyzer")
    parser.add_argument("--dir", help="Directory containing LockBit samples")
    parser.add_argument("--file", help="Single LockBit file to analyze")
    parser.add_argument("--encrypted", help="Encrypted file to attempt decryption on")
    parser.add_argument("--output", help="Output directory for analysis results")
    parser.add_argument("--report", choices=["cn", "en", "both"], default="both", help="Report language (cn, en, or both)")
    args = parser.parse_args()
    
    # Initialize the analyzer
    analyzer = LockBitAnalyzer(args.output)
    
    # Analyze samples
    if args.dir:
        analyzer.analyze_directory(args.dir)
    elif args.file:
        analyzer.analyze_file(args.file)
    else:
        print("No input specified. Use --dir or --file to provide input.")
        return 1
    
    # Attempt decryption if requested
    if args.encrypted:
        result = analyzer.attempt_decryption(args.encrypted)
        if result["success"]:
            print(f"Successfully decrypted file: {result['output_path']}")
        else:
            print(f"Decryption failed: {result.get('error', 'Unknown error')}")
    
    # Generate reports
    if args.report in ["cn", "both"]:
        cn_report = analyzer.generate_report('cn')
        print(f"Chinese report generated: {cn_report}")
    
    if args.report in ["en", "both"]:
        en_report = analyzer.generate_report('en')
        print(f"English report generated: {en_report}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())