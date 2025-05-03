#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Ransomware Analysis Workflow

This module integrates various specialized ransomware analysis components into a unified
automated workflow. It coordinates sample analysis, network key extraction, file format
analysis, decryption attempts, and comprehensive reporting in a streamlined process.

Key features:
- End-to-end automation of the ransomware analysis process
- Integration of specialized LockBit analysis components
- Coordination of static, dynamic, and network-based analysis
- Automated decryption attempts with multiple strategies
- Generation of detailed technical reports in multiple languages
- Classification and validation of ransomware families
"""

import os
import sys
import re
import json
import time
import logging
import hashlib
import argparse
import datetime
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any, Union

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import specialized analysis components
from lockbit_analyzer import LockBitAnalyzer, LockBitFile
from decryption_tools.file_format.restorebackup_analyzer import RestoreBackupAnalyzer, RestoreBackupFormat
from decryption_tools.network_forensics.lockbit_recovery import LockBitKeyExtractor, LockBitRecovery
from decryption_tools.ransomware_recovery import RansomwareRecovery
from memory_analysis_integration import MemoryAnalysisIntegrator, WorkflowMemoryAnalysisAdapter

# Try importing advanced malware analysis components
try:
    from advanced_malware_analysis import MalwareAnalyzer
    ADVANCED_ANALYSIS_AVAILABLE = True
except ImportError:
    ADVANCED_ANALYSIS_AVAILABLE = False
    print("Warning: Advanced malware analysis module not available")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("AutomatedRansomwareWorkflow")


class RansomwareAnalysisCoordinator:
    """
    Coordinates the automated ransomware analysis workflow
    """
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize the coordinator
        
        Args:
            output_dir: Optional output directory for results
        """
        # Set up output directory
        if output_dir:
            self.output_dir = os.path.abspath(output_dir)
        else:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_dir = os.path.join(os.getcwd(), f"ransomware_analysis_{timestamp}")
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Set up log file
        log_file = os.path.join(self.output_dir, 'ransomware_analysis.log')
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(file_handler)
        
        # Initialize component directories
        self.components_dirs = {
            'samples': os.path.join(self.output_dir, 'samples'),
            'static_analysis': os.path.join(self.output_dir, 'static_analysis'),
            'network_analysis': os.path.join(self.output_dir, 'network_analysis'),
            'memory_analysis': os.path.join(self.output_dir, 'memory_analysis'),
            'decryption_attempts': os.path.join(self.output_dir, 'decryption_attempts'),
            'reports': os.path.join(self.output_dir, 'reports'),
            'temp': os.path.join(self.output_dir, 'temp')
        }
        
        # Create component directories
        for dir_path in self.components_dirs.values():
            os.makedirs(dir_path, exist_ok=True)
        
        # Initialize components
        self.lockbit_analyzer = None
        self.restorebackup_analyzer = None
        self.network_recovery = None
        self.general_analyzer = None
        self.memory_analyzer = None
        
        # Analysis results
        self.analyzed_samples = {}
        self.identified_family = None
        self.confidence_score = 0.0
        self.family_version = None
        self.decryption_results = []
        self.memory_analysis_results = {}
        
        # Workflow metadata
        self.workflow_start_time = datetime.datetime.now()
        self.workflow_complete = False
        self.workflow_duration = 0
        self.workflow_steps_completed = set()
        self.workflow_steps_failed = set()
    
    def analyze_directory(self, directory_path: str, pcap_file: Optional[str] = None, 
                        memory_dumps: List[str] = None) -> Dict[str, Any]:
        """
        Analyze all files in a directory
        
        Args:
            directory_path: Path to directory containing files
            pcap_file: Optional PCAP file for network analysis
            memory_dumps: Optional list of memory dump files
            
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Starting automated ransomware analysis of directory: {directory_path}")
        self.workflow_start_time = datetime.datetime.now()
        
        # Step 1: Collect and categorize samples
        logger.info("Step 1: Collecting and categorizing samples")
        samples = self._collect_samples(directory_path)
        
        if not samples:
            logger.error("No samples found in the directory")
            return {"error": "No samples found"}
        
        # Step 2: Perform initial triage and ransomware family detection
        logger.info("Step 2: Performing initial triage and family detection")
        family_detection = self._detect_ransomware_family(samples)
        
        # Step 3: Initialize specialized analyzers based on detected family
        logger.info(f"Step 3: Initializing specialized analyzers for {self.identified_family}")
        self._initialize_specialized_analyzers()
        
        # Step 4: Perform specialized ransomware analysis
        logger.info("Step 4: Performing specialized ransomware analysis")
        self._perform_specialized_analysis(samples, pcap_file, memory_dumps)
        
        # Step 5: Attempt decryption if encrypted files present
        logger.info("Step 5: Attempting decryption of encrypted files")
        self._attempt_decryption(samples)
        
        # Step 6: Generate comprehensive reports
        logger.info("Step 6: Generating comprehensive reports")
        reports = self._generate_reports()
        
        # Complete workflow
        self.workflow_complete = True
        workflow_end_time = datetime.datetime.now()
        self.workflow_duration = (workflow_end_time - self.workflow_start_time).total_seconds()
        
        logger.info(f"Ransomware analysis workflow completed in {self.workflow_duration:.2f} seconds")
        
        # Return summary of results
        return {
            "identified_family": self.identified_family,
            "confidence": self.confidence_score,
            "version": self.family_version,
            "analyzed_samples": len(samples),
            "decryption_attempts": len(self.decryption_results),
            "successful_decryptions": sum(1 for r in self.decryption_results if r.get("success", False)),
            "memory_analysis_performed": "memory_analysis" in self.workflow_steps_completed,
            "memory_keys_extracted": len(self.memory_analysis_results.get("decryption_keys", [])) if self.memory_analysis_results else 0,
            "output_directory": self.output_dir,
            "reports": reports,
            "duration_seconds": self.workflow_duration,
            "completed": self.workflow_complete
        }
    
    def analyze_file(self, file_path: str, pcap_file: Optional[str] = None, 
                    memory_dumps: List[str] = None) -> Dict[str, Any]:
        """
        Analyze a single file
        
        Args:
            file_path: Path to the file
            pcap_file: Optional PCAP file for network analysis
            memory_dumps: Optional list of memory dump files
            
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Starting automated ransomware analysis of file: {file_path}")
        self.workflow_start_time = datetime.datetime.now()
        
        # Prepare samples list with single file
        samples = [file_path]
        
        # Perform the same workflow as directory analysis
        logger.info("Step 1: Categorizing sample")
        self._collect_samples(os.path.dirname(file_path))
        
        logger.info("Step 2: Performing initial triage and family detection")
        family_detection = self._detect_ransomware_family([file_path])
        
        logger.info(f"Step 3: Initializing specialized analyzers for {self.identified_family}")
        self._initialize_specialized_analyzers()
        
        logger.info("Step 4: Performing specialized ransomware analysis")
        self._perform_specialized_analysis([file_path], pcap_file, memory_dumps)
        
        logger.info("Step 5: Attempting decryption if it's an encrypted file")
        self._attempt_decryption([file_path])
        
        logger.info("Step 6: Generating comprehensive reports")
        reports = self._generate_reports()
        
        # Complete workflow
        self.workflow_complete = True
        workflow_end_time = datetime.datetime.now()
        self.workflow_duration = (workflow_end_time - self.workflow_start_time).total_seconds()
        
        logger.info(f"Ransomware analysis workflow completed in {self.workflow_duration:.2f} seconds")
        
        # Return summary of results
        return {
            "identified_family": self.identified_family,
            "confidence": self.confidence_score,
            "version": self.family_version,
            "analyzed_samples": len(samples),
            "decryption_attempts": len(self.decryption_results),
            "successful_decryptions": sum(1 for r in self.decryption_results if r.get("success", False)),
            "memory_analysis_performed": "memory_analysis" in self.workflow_steps_completed,
            "memory_keys_extracted": len(self.memory_analysis_results.get("decryption_keys", [])) if self.memory_analysis_results else 0,
            "output_directory": self.output_dir,
            "reports": reports,
            "duration_seconds": self.workflow_duration,
            "completed": self.workflow_complete
        }
    
    def _collect_samples(self, directory_path: str) -> List[str]:
        """
        Collect and categorize samples from a directory
        
        Args:
            directory_path: Path to directory containing samples
            
        Returns:
            List of sample paths
        """
        if not os.path.exists(directory_path):
            logger.error(f"Directory not found: {directory_path}")
            return []
        
        collected_samples = []
        
        for filename in os.listdir(directory_path):
            file_path = os.path.join(directory_path, filename)
            if os.path.isfile(file_path):
                # Copy the file to our samples directory
                sample_path = os.path.join(self.components_dirs['samples'], filename)
                try:
                    with open(file_path, 'rb') as src, open(sample_path, 'wb') as dst:
                        dst.write(src.read())
                    collected_samples.append(sample_path)
                    logger.info(f"Collected sample: {filename}")
                except Exception as e:
                    logger.error(f"Error collecting sample {filename}: {e}")
        
        logger.info(f"Collected {len(collected_samples)} samples")
        self.workflow_steps_completed.add("collect_samples")
        return collected_samples
    
    def _detect_ransomware_family(self, samples: List[str]) -> Dict[str, Any]:
        """
        Detect ransomware family from samples
        
        Args:
            samples: List of sample file paths
            
        Returns:
            Dictionary with detection results
        """
        # Define detection patterns for common ransomware families
        family_patterns = {
            "LockBit": [
                rb'1765FE8E-2103-66E3-7DCB-72284ABD03AA',  # LockBit 2.0 UUID
                rb'LockBit',
                rb'LOCKBIT',
                rb'lock[A-Za-z0-9]{4,}\.bit',
                rb'lock[A-Za-z0-9]{4,}\.onion',
                rb'\.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}',
                rb'restorebackup'
            ],
            "Ryuk": [
                rb'RyukReadMe',
                rb'RYUK',
                rb'ryuk',
                rb'RyukReadMe\.html',
                rb'\.ryk',
                rb'\.RYK'
            ],
            "WannaCry": [
                rb'WannaCry',
                rb'WANACRY',
                rb'\.wncry',
                rb'\.WNCRY',
                rb'@WanaDecryptor@',
                rb'msg/m_english\.wnry'
            ],
            "Conti": [
                rb'CONTI',
                rb'conti',
                rb'\.conti',
                rb'CONTI_README',
                rb'recovery-conti\.txt'
            ]
        }
        
        # Count matches for each family
        family_matches = {family: 0 for family in family_patterns}
        
        for sample_path in samples:
            try:
                with open(sample_path, 'rb') as f:
                    data = f.read()
                
                # For each ransomware family
                for family, patterns in family_patterns.items():
                    # For each pattern in the family
                    for pattern in patterns:
                        # Check if pattern matches
                        if re.search(pattern, data) or re.search(pattern, sample_path.encode('utf-8')):
                            family_matches[family] += 1
                            logger.debug(f"Found {family} pattern match in {os.path.basename(sample_path)}")
            except Exception as e:
                logger.error(f"Error analyzing {sample_path} for family detection: {e}")
        
        # Find family with most matches
        if any(count > 0 for count in family_matches.values()):
            # Sort families by match count (descending)
            sorted_families = sorted(family_matches.items(), key=lambda x: x[1], reverse=True)
            top_family, top_count = sorted_families[0]
            
            # If we have matches, identify the family
            if top_count > 0:
                self.identified_family = top_family
                
                # Calculate confidence based on number of matches and samples
                matches_ratio = top_count / (len(samples) * len(family_patterns[top_family]))
                self.confidence_score = min(0.5 + (matches_ratio * 0.5), 0.95)
                
                logger.info(f"Detected ransomware family: {top_family} (confidence: {self.confidence_score:.2f})")
                
                # Try to determine version
                if top_family == "LockBit":
                    # Check for LockBit version indicators
                    version_patterns = {
                        "2.0": [rb'1765FE8E-2103-66E3-7DCB-72284ABD03AA', rb'restorebackup'],
                        "3.0": [rb'lockbit3', rb'LockBit3', rb'LockBit Black']
                    }
                    
                    for version, patterns in version_patterns.items():
                        for sample_path in samples:
                            try:
                                with open(sample_path, 'rb') as f:
                                    data = f.read()
                                
                                for pattern in patterns:
                                    if re.search(pattern, data):
                                        self.family_version = version
                                        logger.info(f"Detected LockBit version: {version}")
                                        break
                                
                                if self.family_version:
                                    break
                            except Exception:
                                pass
                        
                        if self.family_version:
                            break
                
                # If no specific version detected, set to "unknown"
                if not self.family_version:
                    self.family_version = "unknown"
            else:
                self.identified_family = "Unknown"
                self.confidence_score = 0.0
                logger.warning("Could not identify ransomware family")
        else:
            self.identified_family = "Unknown"
            self.confidence_score = 0.0
            logger.warning("Could not identify ransomware family")
        
        self.workflow_steps_completed.add("detect_family")
        
        return {
            "identified_family": self.identified_family,
            "confidence": self.confidence_score,
            "version": self.family_version
        }
    
    def _initialize_specialized_analyzers(self):
        """Initialize specialized analyzers based on detected family"""
        try:
            # Initialize LockBit analyzer if LockBit detected
            if self.identified_family == "LockBit":
                lockbit_output_dir = os.path.join(self.components_dirs['static_analysis'], 'lockbit')
                self.lockbit_analyzer = LockBitAnalyzer(lockbit_output_dir)
                logger.info("Initialized LockBit analyzer")
                
                # Initialize RestoreBackup analyzer for LockBit
                restorebackup_output_dir = os.path.join(self.components_dirs['static_analysis'], 'restorebackup')
                self.restorebackup_analyzer = RestoreBackupAnalyzer(restorebackup_output_dir)
                logger.info("Initialized RestoreBackup analyzer")
                
                # Initialize LockBit recovery
                self.network_recovery = LockBitRecovery()
                logger.info("Initialized LockBit network recovery")
            
            # Initialize general malware analyzer if available
            if ADVANCED_ANALYSIS_AVAILABLE:
                general_output_dir = os.path.join(self.components_dirs['static_analysis'], 'general')
                self.general_analyzer = MalwareAnalyzer(general_output_dir)
                logger.info("Initialized general malware analyzer")
            
            # Initialize memory analysis adapter
            memory_output_dir = self.components_dirs['memory_analysis']
            self.memory_analyzer = WorkflowMemoryAnalysisAdapter(self.output_dir)
            logger.info("Initialized memory analysis adapter")
            
            self.workflow_steps_completed.add("initialize_analyzers")
            
        except Exception as e:
            logger.error(f"Error initializing specialized analyzers: {e}")
            self.workflow_steps_failed.add("initialize_analyzers")
    
    def _perform_specialized_analysis(self, samples: List[str], pcap_file: Optional[str] = None, memory_dumps: List[str] = None):
        """
        Perform specialized analysis based on detected family
        
        Args:
            samples: List of sample file paths
            pcap_file: Optional PCAP file for network analysis
            memory_dumps: Optional list of memory dump files
        """
        # LockBit specific analysis
        if self.identified_family == "LockBit" and self.lockbit_analyzer:
            logger.info("Performing specialized LockBit analysis")
            
            for sample_path in samples:
                try:
                    # Analyze with LockBit analyzer
                    lb_file = self.lockbit_analyzer.analyze_file(sample_path)
                    self.analyzed_samples[sample_path] = lb_file
                    logger.info(f"Analyzed {os.path.basename(sample_path)} with LockBit analyzer")
                    
                    # If it's a .restorebackup file, analyze with RestoreBackup analyzer
                    if ".restorebackup" in sample_path and self.restorebackup_analyzer:
                        rb_format = self.restorebackup_analyzer.analyze_file(sample_path)
                        logger.info(f"Analyzed {os.path.basename(sample_path)} with RestoreBackup analyzer")
                except Exception as e:
                    logger.error(f"Error analyzing {os.path.basename(sample_path)}: {e}")
                    self.workflow_steps_failed.add(f"analyze_{os.path.basename(sample_path)}")
            
            # Analyze PCAP file if provided
            if pcap_file and self.network_recovery:
                try:
                    # Create LockBit key extractor
                    key_extractor = LockBitKeyExtractor(pcap_file)
                    
                    # Extract keys from PCAP
                    extracted_keys = key_extractor.extract_keys()
                    
                    # Add keys to recovery
                    self.network_recovery.add_keys(extracted_keys)
                    
                    logger.info(f"Analyzed PCAP file and extracted {len(extracted_keys)} potential keys")
                    
                    # Also analyze all PE samples for keys
                    for sample_path in samples:
                        if "PE32" in self._get_file_type(sample_path):
                            binary_keys = self.network_recovery.analyze_sample(sample_path)
                            logger.info(f"Extracted {len(binary_keys)} potential keys from {os.path.basename(sample_path)}")
                    
                    self.workflow_steps_completed.add("network_analysis")
                except Exception as e:
                    logger.error(f"Error analyzing PCAP file: {e}")
                    self.workflow_steps_failed.add("network_analysis")
        
        # General malware analysis for all samples
        if self.general_analyzer:
            logger.info("Performing general malware analysis")
            
            for sample_path in samples:
                try:
                    result = self.general_analyzer.analyze_file(sample_path)
                    logger.info(f"Completed general analysis of {os.path.basename(sample_path)}")
                except Exception as e:
                    logger.error(f"Error in general analysis of {os.path.basename(sample_path)}: {e}")
        
        # Perform memory analysis if memory dumps are provided or if we should generate memory dumps
        if self.memory_analyzer:
            self._perform_memory_analysis(samples, memory_dumps)
        
        # Perform correlation analysis if we have multiple samples
        if self.identified_family == "LockBit" and self.lockbit_analyzer and len(samples) > 1:
            self.lockbit_analyzer._correlate_samples()
            logger.info("Performed correlation analysis across samples")
        
        self.workflow_steps_completed.add("specialized_analysis")
        
    def _perform_memory_analysis(self, samples: List[str], memory_dumps: List[str] = None):
        """
        Perform memory analysis using the memory analysis adapter.
        
        Args:
            samples: List of sample file paths
            memory_dumps: Optional list of memory dump files
        """
        if not self.memory_analyzer:
            logger.warning("Memory analyzer not initialized, skipping memory analysis")
            return
        
        logger.info("Starting memory analysis")
        
        try:
            # Analyze samples along with memory dumps
            memory_results = self.memory_analyzer.analyze_samples(
                ransomware_samples=samples,
                memory_dumps=memory_dumps,
                family=self.identified_family
            )
            
            # Store memory analysis results
            self.memory_analysis_results = memory_results
            
            # Get extracted keys for decryption
            if "decryption_keys" in memory_results and memory_results["decryption_keys"]:
                decryption_keys = memory_results["decryption_keys"]
                logger.info(f"Extracted {len(decryption_keys)} potential decryption keys from memory")
                
                # If we have LockBit recovery, add the keys
                if self.network_recovery and self.identified_family == "LockBit":
                    # Convert keys to the format expected by LockBitRecovery
                    for key_info in decryption_keys:
                        if "key_hex" in key_info:
                            key_bytes = bytes.fromhex(key_info["key_hex"])
                            self.network_recovery.add_key(key_bytes)
                    
                    logger.info(f"Added {len(decryption_keys)} keys from memory analysis to LockBit recovery")
            
            self.workflow_steps_completed.add("memory_analysis")
            logger.info("Memory analysis completed successfully")
            
        except Exception as e:
            logger.error(f"Error during memory analysis: {e}")
            self.workflow_steps_failed.add("memory_analysis")
    
    def _attempt_decryption(self, samples: List[str]):
        """
        Attempt decryption of encrypted files
        
        Args:
            samples: List of sample file paths
        """
        # Find encrypted files
        encrypted_files = []
        for sample_path in samples:
            if self.identified_family == "LockBit":
                # Check for LockBit encrypted files
                if ".restorebackup" in sample_path or ".{1765FE8E-2103-66E3-7DCB-72284ABD03AA}" in sample_path:
                    encrypted_files.append(sample_path)
                elif sample_path in self.analyzed_samples and self.analyzed_samples[sample_path].is_encrypted:
                    encrypted_files.append(sample_path)
            else:
                # For other ransomware, use entropy to detect encrypted files
                try:
                    with open(sample_path, 'rb') as f:
                        data = f.read(4096)  # Read first 4KB
                        entropy = self._calculate_entropy(data)
                        if entropy > 7.0:  # High entropy indicates encryption
                            encrypted_files.append(sample_path)
                except Exception:
                    pass
        
        if not encrypted_files:
            logger.info("No encrypted files found for decryption")
            return
        
        logger.info(f"Found {len(encrypted_files)} encrypted files")
        
        # Create decryption directory
        decryption_dir = self.components_dirs['decryption_attempts']
        
        # For LockBit, use specialized LockBit recovery
        if self.identified_family == "LockBit" and self.lockbit_analyzer:
            logger.info("Attempting LockBit decryption")
            
            for encrypted_file in encrypted_files:
                try:
                    # Generate output path
                    file_name = os.path.basename(encrypted_file)
                    output_path = os.path.join(decryption_dir, f"decrypted_{file_name}")
                    
                    # Attempt decryption
                    result = self.lockbit_analyzer.attempt_decryption(encrypted_file, output_path)
                    
                    # Record result
                    self.decryption_results.append({
                        "file": file_name,
                        "success": result.get("success", False),
                        "output": output_path if result.get("success", False) else None,
                        "error": result.get("error", None)
                    })
                    
                    if result.get("success", False):
                        logger.info(f"Successfully decrypted {file_name}")
                    else:
                        logger.info(f"Failed to decrypt {file_name}: {result.get('error', 'Unknown error')}")
                except Exception as e:
                    logger.error(f"Error attempting decryption of {file_name}: {e}")
                    self.decryption_results.append({
                        "file": file_name,
                        "success": False,
                        "error": str(e)
                    })
        else:
            # For other ransomware, use RansomwareRecovery
            logger.info("Attempting generic ransomware decryption")
            
            try:
                recovery = RansomwareRecovery()
                
                for encrypted_file in encrypted_files:
                    file_name = os.path.basename(encrypted_file)
                    output_path = os.path.join(decryption_dir, f"decrypted_{file_name}")
                    
                    # Try with "auto" tool
                    success = recovery.decrypt_file(
                        encrypted_file, 
                        tool_id="auto",
                        output_file=output_path,
                        options={
                            "family": self.identified_family,
                            "variant": self.family_version
                        }
                    )
                    
                    # Record result
                    self.decryption_results.append({
                        "file": file_name,
                        "success": success,
                        "output": output_path if success else None,
                        "error": None if success else "Generic decryption failed"
                    })
                    
                    if success:
                        logger.info(f"Successfully decrypted {file_name}")
                    else:
                        logger.info(f"Failed to decrypt {file_name}")
            except Exception as e:
                logger.error(f"Error in generic decryption: {e}")
                self.workflow_steps_failed.add("generic_decryption")
        
        self.workflow_steps_completed.add("decryption_attempts")
    
    def _generate_reports(self) -> Dict[str, str]:
        """
        Generate comprehensive reports
        
        Returns:
            Dictionary with report file paths
        """
        reports = {}
        
        # For LockBit, generate specialized reports
        if self.identified_family == "LockBit" and self.lockbit_analyzer:
            # Generate Chinese report
            cn_report = self.lockbit_analyzer.generate_report('cn')
            reports['chinese_report'] = cn_report
            logger.info(f"Generated Chinese LockBit analysis report: {os.path.basename(cn_report)}")
            
            # Generate English report
            en_report = self.lockbit_analyzer.generate_report('en')
            reports['english_report'] = en_report
            logger.info(f"Generated English LockBit analysis report: {os.path.basename(en_report)}")
        
        # Generate workflow summary report
        summary_report = self._generate_workflow_summary()
        reports['workflow_summary'] = summary_report
        logger.info(f"Generated workflow summary report: {os.path.basename(summary_report)}")
        
        # Generate technical details report for any ransomware
        technical_report = self._generate_technical_report()
        reports['technical_report'] = technical_report
        logger.info(f"Generated technical details report: {os.path.basename(technical_report)}")
        
        self.workflow_steps_completed.add("generate_reports")
        return reports
    
    def _generate_workflow_summary(self) -> str:
        """
        Generate workflow summary report
        
        Returns:
            Path to the generated report
        """
        report_path = os.path.join(self.components_dirs['reports'], "workflow_summary.md")
        
        with open(report_path, 'w', encoding='utf-8') as f:
            # Title
            f.write("# Automated Ransomware Analysis Workflow Summary\n\n")
            f.write(f"*Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
            
            # Overview
            f.write("## Analysis Overview\n\n")
            f.write(f"- **Ransomware Family**: {self.identified_family}\n")
            f.write(f"- **Detection Confidence**: {self.confidence_score:.2f}\n")
            if self.family_version:
                f.write(f"- **Detected Version**: {self.family_version}\n")
            f.write(f"- **Samples Analyzed**: {len(self.analyzed_samples)}\n")
            f.write(f"- **Workflow Duration**: {self.workflow_duration:.2f} seconds\n")
            f.write(f"- **Completed**: {'Yes' if self.workflow_complete else 'No'}\n\n")
            
            # Workflow steps
            f.write("## Workflow Steps\n\n")
            f.write("| Step | Status | Notes |\n")
            f.write("|------|--------|-------|\n")
            
            # Define workflow steps in order
            workflow_steps = [
                ("collect_samples", "Sample Collection"),
                ("detect_family", "Ransomware Family Detection"),
                ("initialize_analyzers", "Initialize Specialized Analyzers"),
                ("specialized_analysis", "Specialized Analysis"),
                ("network_analysis", "Network Analysis"),
                ("memory_analysis", "Memory Analysis"),
                ("decryption_attempts", "Decryption Attempts"),
                ("generate_reports", "Report Generation")
            ]
            
            for step_id, step_name in workflow_steps:
                if step_id in self.workflow_steps_completed:
                    status = "✅ Completed"
                elif step_id in self.workflow_steps_failed:
                    status = "❌ Failed"
                else:
                    status = "⚠️ Not executed"
                
                # Add notes for certain steps
                notes = ""
                if step_id == "decryption_attempts":
                    successful = sum(1 for r in self.decryption_results if r.get("success", False))
                    total = len(self.decryption_results)
                    if total > 0:
                        notes = f"{successful}/{total} successful"
                
                f.write(f"| {step_name} | {status} | {notes} |\n")
            
            # Decryption results
            if self.decryption_results:
                f.write("\n## Decryption Results\n\n")
                f.write("| File | Success | Output | Error |\n")
                f.write("|------|---------|--------|-------|\n")
                
                for result in self.decryption_results:
                    file_name = result.get("file", "Unknown")
                    success = "Yes" if result.get("success", False) else "No"
                    output = os.path.basename(result.get("output", "")) if result.get("output") else "N/A"
                    error = result.get("error", "N/A")
                    
                    f.write(f"| {file_name} | {success} | {output} | {error} |\n")
            
            # Output locations
            f.write("\n## Output Locations\n\n")
            f.write("The analysis results are available in the following locations:\n\n")
            
            for name, path in self.components_dirs.items():
                f.write(f"- **{name.replace('_', ' ').title()}**: `{path}`\n")
        
        return report_path
    
    def _generate_technical_report(self) -> str:
        """
        Generate technical details report
        
        Returns:
            Path to the generated report
        """
        report_path = os.path.join(self.components_dirs['reports'], "technical_details.md")
        
        with open(report_path, 'w', encoding='utf-8') as f:
            # Title
            f.write("# Ransomware Technical Analysis Report\n\n")
            f.write(f"*Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
            
            # Summary
            f.write("## Analysis Summary\n\n")
            
            f.write(f"**Ransomware Family**: {self.identified_family}\n\n")
            
            if self.confidence_score > 0:
                confidence = int(self.confidence_score * 100)
                f.write(f"**Detection Confidence**: {confidence}%\n\n")
                
                if self.family_version:
                    f.write(f"**Detected Version**: {self.family_version}\n\n")
            
            # Sample details
            f.write("## Analyzed Samples\n\n")
            f.write("| Filename | Size (bytes) | Type | MD5 Hash |\n")
            f.write("|----------|--------------|------|----------|\n")
            
            for sample_path, lb_file in self.analyzed_samples.items():
                file_name = os.path.basename(sample_path)
                
                # For LockBit files, we can get details directly
                if isinstance(lb_file, LockBitFile):
                    file_size = lb_file.file_size
                    file_type = lb_file.file_type
                    md5_hash = lb_file.hashes.get('md5', 'N/A')
                else:
                    # For other files, compute details
                    file_size = os.path.getsize(sample_path)
                    file_type = self._get_file_type(sample_path)
                    md5_hash = self._compute_md5(sample_path)
                
                f.write(f"| {file_name} | {file_size} | {file_type} | {md5_hash} |\n")
            
            # For LockBit, include specialized analysis details
            if self.identified_family == "LockBit" and self.lockbit_analyzer:
                # Component details
                if self.lockbit_analyzer.analysis_results.get('identified_components'):
                    f.write("\n## Identified Components\n\n")
                    for component in self.lockbit_analyzer.analysis_results['identified_components']:
                        if component == "LockBit Encryptor":
                            f.write("- **Encryption Component** - Responsible for encrypting victim files\n")
                        elif component == "LockBit Decryptor UI":
                            f.write("- **Decryptor UI** - Interface component for decrypting files\n")
                        elif component == "LockBit Countermeasure Script":
                            f.write("- **Countermeasure Script** - Batch script for disabling security software and backups\n")
                        elif component == "LockBit Encrypted Files":
                            f.write("- **Encrypted File Samples** - Examples of LockBit encrypted files\n")
                
                # Encryption details
                f.write("\n## Encryption Details\n\n")
                
                if self.lockbit_analyzer.analysis_results.get('encryption_extension'):
                    f.write(f"- **Encrypted File Extension**: `{self.lockbit_analyzer.analysis_results['encryption_extension']}`\n")
                
                f.write("- **Encryption Method**: LockBit uses a hybrid encryption scheme\n")
                f.write("  - Files are encrypted using AES-256 keys\n")
                f.write("  - AES keys are encrypted using an RSA-2048 public key\n")
                f.write("  - Each file uses a unique AES key\n")
                
                # Network indicators
                if self.lockbit_analyzer.analysis_results.get('onion_urls'):
                    f.write("\n## Network Indicators\n\n")
                    f.write("### Tor Onion Addresses\n\n")
                    for url in self.lockbit_analyzer.analysis_results['onion_urls']:
                        f.write(f"- `{url}`\n")
                
                # Behavioral analysis
                f.write("\n## Behavioral Analysis\n\n")
                
                encryptor_behaviors = []
                countermeasure_behaviors = []
                
                for sample_path, lb_file in self.analyzed_samples.items():
                    if not isinstance(lb_file, LockBitFile):
                        continue
                    
                    if lb_file.is_encryptor:
                        encryptor_behaviors.append(f"- File `{lb_file.file_name}` contains encryption capabilities")
                        if 'encryption_functions' in lb_file.analysis_results:
                            functions = lb_file.analysis_results['encryption_functions']
                            encryptor_behaviors.append(f"  - Encryption functions used: {', '.join(functions)}")
                        
                        if 'anti_analysis' in lb_file.analysis_results:
                            techniques = lb_file.analysis_results['anti_analysis']
                            encryptor_behaviors.append(f"  - Anti-analysis techniques used: {', '.join(techniques)}")
                    
                    if lb_file.is_countermeasure:
                        countermeasure_behaviors.append(f"- File `{lb_file.file_name}` contains security countermeasures")
                        if 'security_termination' in lb_file.analysis_results:
                            software = lb_file.analysis_results['security_termination']
                            countermeasure_behaviors.append(f"  - Security software targeted for termination: {', '.join(software)}")
                        
                        if 'backup_prevention' in lb_file.analysis_results:
                            techniques = lb_file.analysis_results['backup_prevention']
                            countermeasure_behaviors.append(f"  - Backup prevention techniques used: {', '.join(techniques)}")
                
                if encryptor_behaviors:
                    f.write("### Encryptor Behavior\n\n")
                    for behavior in encryptor_behaviors:
                        f.write(f"{behavior}\n")
                
                if countermeasure_behaviors:
                    f.write("\n### Countermeasure Behavior\n\n")
                    for behavior in countermeasure_behaviors:
                        f.write(f"{behavior}\n")
            
            # Memory Analysis
            f.write("\n## Memory Analysis\n\n")
            
            if "memory_analysis" in self.workflow_steps_completed:
                f.write("Memory analysis was performed to extract potential encryption keys.\n\n")
                
                if self.memory_analysis_results and "decryption_keys" in self.memory_analysis_results:
                    keys = self.memory_analysis_results["decryption_keys"]
                    f.write(f"- **Extracted Keys**: {len(keys)}\n")
                    
                    # Show high confidence keys
                    high_conf_keys = [k for k in keys if k.get("confidence", 0) >= 0.7]
                    if high_conf_keys:
                        f.write(f"- **High Confidence Keys**: {len(high_conf_keys)}\n\n")
                        
                        f.write("### High Confidence Keys\n\n")
                        f.write("| Key Type | Confidence | Key (First 16 bytes) |\n")
                        f.write("|----------|------------|----------------------|\n")
                        
                        for key in high_conf_keys[:5]:  # Show up to 5 keys
                            key_type = key.get("key_type", "unknown")
                            confidence = f"{key.get('confidence', 0):.2f}"
                            key_hex = key.get("key_hex", "")
                            display_key = key_hex[:32] + "..." if len(key_hex) > 32 else key_hex
                            
                            f.write(f"| {key_type} | {confidence} | `{display_key}` |\n")
                        
                        if len(high_conf_keys) > 5:
                            f.write(f"\n*Note: {len(high_conf_keys) - 5} additional high-confidence keys were found.*\n")
                else:
                    f.write("No encryption keys were extracted from memory analysis.\n")
            else:
                f.write("No memory analysis was performed during this workflow run.\n")
            
            # Decryption attempts
            f.write("\n## Decryption Attempts\n\n")
            
            if self.decryption_results:
                successful = sum(1 for r in self.decryption_results if r.get("success", False))
                failed = len(self.decryption_results) - successful
                
                f.write(f"A total of {len(self.decryption_results)} decryption attempts were made, with {successful} successes and {failed} failures.\n\n")
                
                if successful > 0:
                    f.write("### Successful Decryption Attempts\n\n")
                    f.write("| File | Method | Output Path |\n")
                    f.write("|------|--------|-------------|\n")
                    
                    for result in self.decryption_results:
                        if result.get("success", False):
                            file_name = result.get("file", "Unknown")
                            method = "Specialized recovery" if self.identified_family == "LockBit" else "Generic recovery"
                            output = os.path.basename(result.get("output", "")) if result.get("output") else "N/A"
                            
                            f.write(f"| {file_name} | {method} | {output} |\n")
                else:
                    f.write("All decryption attempts failed. This suggests that the ransomware uses a strong encryption scheme that cannot be decrypted through automated tools.\n")
            else:
                f.write("No decryption attempts were made.\n")
            
            # Recommendations
            f.write("\n## Recommendations\n\n")
            
            # LockBit specific recommendations
            if self.identified_family == "LockBit":
                f.write("- Immediately isolate infected systems and disconnect from the network to prevent spread\n")
                f.write("- Scan uninfected systems with trusted antivirus software\n")
                f.write("- Check the integrity of backups and ensure they are not encrypted\n")
                f.write("- Restore Volume Shadow Copy Service (VSS), repair Windows backup functionality that may have been disabled\n")
                
                if self.family_version == "2.0":
                    f.write("- Look for files with the characteristic suffix '.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}'\n")
                elif self.family_version == "3.0":
                    f.write("- LockBit 3.0 uses a hybrid encryption scheme; some files may use weaker encryption algorithms\n")
            else:
                # Generic recommendations
                f.write("- Immediately isolate infected systems and disconnect from the network\n")
                f.write("- Document the ransom note and any specific instructions to aid identification\n")
                f.write("- Contact cybersecurity professionals specialized in ransomware recovery\n")
                f.write("- Check for available decryption tools for the specific ransomware variant\n")
                f.write("- Restore from clean backups if available\n")
            
            # Always add these recommendations
            f.write("- Report the incident to law enforcement\n")
            f.write("- Review security policies to prevent future infections\n")
            f.write("- Implement regular offline backups\n")
        
        return report_path
    
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
            elif ext == '.bat':
                return "Batch file"
            elif ext == '.ps1':
                return "PowerShell script"
            elif ext == '.sh':
                return "Shell script"
            elif ext == '.py':
                return "Python script"
            elif ext == '.txt':
                return "Text file"
            elif ext == '.html' or ext == '.htm':
                return "HTML document"
            elif ext == '.pdf':
                return "PDF document"
            elif ext == '.jpg' or ext == '.jpeg':
                return "JPEG image"
            elif ext == '.png':
                return "PNG image"
            elif ext == '.zip':
                return "ZIP archive"
            elif ext == '.iso':
                return "ISO image"
            else:
                return f"Unknown ({ext})"
    
    def _compute_md5(self, file_path: str) -> str:
        """Compute MD5 hash of a file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                return hashlib.md5(data).hexdigest()
        except Exception as e:
            logger.error(f"Error computing MD5 hash: {e}")
            return "N/A"
    
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


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Automated Ransomware Analysis Workflow")
    parser.add_argument("--dir", help="Directory containing ransomware samples")
    parser.add_argument("--file", help="Single file to analyze")
    parser.add_argument("--pcap", help="PCAP file for network-based recovery")
    parser.add_argument("--memdump", "--memory", action="append", help="Memory dump file(s) for memory analysis (can be specified multiple times)")
    parser.add_argument("--process", type=int, help="Process ID to create memory dump from")
    parser.add_argument("--output", help="Output directory for analysis results")
    args = parser.parse_args()
    
    # Initialize coordinator
    coordinator = RansomwareAnalysisCoordinator(args.output)
    
    # Handle process memory dump
    memory_dumps = args.memdump or []
    if args.process:
        try:
            if coordinator.memory_analyzer:
                dump_file = coordinator.memory_analyzer.memory_dump_from_process(args.process)
                if dump_file:
                    memory_dumps.append(dump_file)
                    print(f"Created memory dump from process {args.process}: {dump_file}")
        except Exception as e:
            print(f"Error creating memory dump from process {args.process}: {e}")
    
    # Analyze samples
    if args.dir:
        results = coordinator.analyze_directory(args.dir, args.pcap, memory_dumps)
    elif args.file:
        results = coordinator.analyze_file(args.file, args.pcap, memory_dumps)
    else:
        print("No input specified. Use --dir or --file to provide input.")
        return 1
    
    # Print summary of results
    print("\nRansomware Analysis Complete")
    print(f"Identified family: {results['identified_family']} (confidence: {results['confidence']:.2f})")
    if results.get('version'):
        print(f"Detected version: {results['version']}")
    
    print(f"\nAnalyzed {results['analyzed_samples']} samples")
    print(f"Decryption attempts: {results['decryption_attempts']} (successful: {results['successful_decryptions']})")
    
    # Print memory analysis results if performed
    if results.get('memory_analysis_performed', False):
        print(f"Memory analysis: Completed (extracted keys: {results.get('memory_keys_extracted', 0)})")
    
    print(f"\nResults available in: {results['output_directory']}")
    
    # Print report locations
    if 'reports' in results:
        print("\nGenerated Reports:")
        for report_type, report_path in results['reports'].items():
            print(f"- {report_type.replace('_', ' ').title()}: {report_path}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())