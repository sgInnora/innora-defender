#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ransomware Network Analyzer

This script integrates network traffic analysis with ransomware detection and recovery.
It combines the capabilities of network-based recovery, ransomware detection, and
encryption analysis to provide a comprehensive solution for ransomware analysis.

Key features:
- Analyze network traffic for ransomware communication patterns
- Extract potential encryption keys from network traffic
- Correlate file encryption with network activity
- Identify ransomware families based on network and file patterns
- Attempt decryption using network-extracted keys
- Generate comprehensive reports of findings

Usage:
    python ransomware_network_analyzer.py --pcap capture.pcap --samples /path/to/samples --output report.json
"""

import os
import sys
import json
import time
import logging
import argparse
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional, Union, Any
from pathlib import Path
import tempfile
import hashlib
import shutil
import concurrent.futures

# Add parent directory to path to import modules
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(script_dir))
sys.path.append(parent_dir)

# Import modules from the project
try:
    from decryption_tools.network_forensics.network_based_recovery import (
        NetworkKeyExtractor, NetworkBasedRecovery, ExtractedKey
    )
except ImportError:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from network_based_recovery import NetworkKeyExtractor, NetworkBasedRecovery, ExtractedKey

# Try to import other project modules if available
try:
    from decryption_tools.external.encryption_analyzer import EncryptionAnalyzer
    ENCRYPTION_ANALYZER_AVAILABLE = True
except ImportError:
    ENCRYPTION_ANALYZER_AVAILABLE = False
    print("Warning: EncryptionAnalyzer module not found. Limited functionality available.")

try:
    from behavior_analysis.detectors.ransomware_network_detector import RansomwareNetworkDetector
    NETWORK_DETECTOR_AVAILABLE = True
except ImportError:
    NETWORK_DETECTOR_AVAILABLE = False
    print("Warning: RansomwareNetworkDetector module not found. Limited functionality available.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("RansomwareNetworkAnalyzer")


class RansomwareNetworkAnalyzer:
    """
    Integrates network traffic analysis with ransomware detection and recovery
    """
    
    def __init__(self, pcap_file: Optional[str] = None, interface: str = "any"):
        """
        Initialize the analyzer
        
        Args:
            pcap_file: Optional path to PCAP file for analysis
            interface: Network interface to monitor (if live monitoring)
        """
        self.pcap_file = pcap_file
        self.interface = interface
        self.network_keys = []
        self.memory_keys = []
        self.identified_families = set()
        self.results = {}
        
        # Initialize components
        self.key_extractor = NetworkKeyExtractor(pcap_file)
        self.recovery = NetworkBasedRecovery()
        
        if NETWORK_DETECTOR_AVAILABLE:
            self.network_detector = RansomwareNetworkDetector(interface)
        else:
            self.network_detector = None
        
        if ENCRYPTION_ANALYZER_AVAILABLE:
            self.encryption_analyzer = EncryptionAnalyzer()
        else:
            self.encryption_analyzer = None
    
    def analyze_pcap(self) -> Dict[str, Any]:
        """
        Analyze PCAP file to extract keys and identify ransomware families
        
        Returns:
            Dictionary of analysis results
        """
        if not self.pcap_file:
            logger.error("No PCAP file specified")
            return {
                "status": "error",
                "message": "No PCAP file specified",
                "timestamp": datetime.now().isoformat()
            }
        
        if not os.path.exists(self.pcap_file):
            logger.error(f"PCAP file not found: {self.pcap_file}")
            return {
                "status": "error",
                "message": f"PCAP file not found: {self.pcap_file}",
                "timestamp": datetime.now().isoformat()
            }
        
        logger.info(f"Analyzing PCAP file: {self.pcap_file}")
        
        # Extract keys from PCAP
        keys = self.key_extractor.extract_potential_keys()
        self.network_keys = keys
        
        # Add keys to recovery module
        self.recovery.add_keys(keys)
        
        # Get network alerts if detector is available
        network_alerts = []
        if self.network_detector:
            # Convert PCAP to network alerts
            network_alerts = self._pcap_to_alerts()
            
            # Analyze alerts to identify families
            families = set()
            for alert in network_alerts:
                if alert.get("ransomware_family"):
                    families.add(alert["ransomware_family"])
            
            self.identified_families.update(families)
        
        # Prepare results
        results = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "pcap_file": self.pcap_file,
            "extracted_keys": {
                "count": len(keys),
                "keys": [key.to_dict() for key in keys]
            },
            "network_alerts": {
                "count": len(network_alerts),
                "alerts": network_alerts
            },
            "identified_families": list(self.identified_families)
        }
        
        self.results["pcap_analysis"] = results
        return results
    
    def _pcap_to_alerts(self) -> List[Dict[str, Any]]:
        """
        Convert PCAP analysis to network alerts format
        
        Returns:
            List of network alert dictionaries
        """
        # This is a placeholder for actual conversion
        # In a full implementation, this would use a library to convert PCAP to alerts
        
        # For now, just extract some basic info from extracted keys
        alerts = []
        for key in self.network_keys:
            context = key.context or {}
            family = context.get("family")
            
            if family:
                alerts.append({
                    "timestamp": key.timestamp.isoformat(),
                    "alert_type": "potential_encryption_key",
                    "source_ip": key.source_ip,
                    "destination_ip": key.destination_ip,
                    "protocol": context.get("source", "unknown"),
                    "confidence": key.confidence,
                    "description": f"Potential {key.key_type} encryption key for {family}",
                    "ransomware_family": family
                })
        
        return alerts
    
    def analyze_samples(self, samples_dir: str) -> Dict[str, Any]:
        """
        Analyze sample files to identify encryption and ransomware families
        
        Args:
            samples_dir: Directory containing sample files
            
        Returns:
            Dictionary of analysis results
        """
        if not os.path.exists(samples_dir) or not os.path.isdir(samples_dir):
            logger.error(f"Samples directory not found: {samples_dir}")
            return {
                "status": "error",
                "message": f"Samples directory not found: {samples_dir}",
                "timestamp": datetime.now().isoformat()
            }
        
        logger.info(f"Analyzing samples in: {samples_dir}")
        
        results = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "samples_dir": samples_dir,
            "analyzed_files": [],
            "identified_families": [],
            "decryption_attempts": []
        }
        
        # Get all files in the directory
        sample_files = []
        for root, _, files in os.walk(samples_dir):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.isfile(file_path):
                    sample_files.append(file_path)
        
        if not sample_files:
            logger.warning(f"No files found in: {samples_dir}")
            return {
                "status": "warning",
                "message": f"No files found in: {samples_dir}",
                "timestamp": datetime.now().isoformat()
            }
        
        # Analyze each file
        file_results = []
        families = set()
        
        for file_path in sample_files:
            # Skip very large files
            if os.path.getsize(file_path) > 100 * 1024 * 1024:  # 100 MB
                logger.warning(f"Skipping large file: {file_path}")
                continue
                
            logger.info(f"Analyzing file: {file_path}")
            
            file_result = {
                "file_path": file_path,
                "file_size": os.path.getsize(file_path),
                "timestamp": datetime.now().isoformat()
            }
            
            # Analyze encryption if available
            if self.encryption_analyzer:
                try:
                    encryption_result = self.encryption_analyzer.analyze_file(file_path)
                    file_result["encryption_analysis"] = encryption_result
                    
                    # Add family to identified families
                    if encryption_result.get("identified_family"):
                        families.add(encryption_result["identified_family"])
                except Exception as e:
                    logger.error(f"Error analyzing encryption: {e}")
                    file_result["encryption_analysis"] = {
                        "status": "error",
                        "message": str(e)
                    }
            
            # Try decryption with extracted keys
            try:
                decryption_results = self.attempt_file_decryption(file_path)
                file_result["decryption_attempts"] = {
                    "count": len(decryption_results),
                    "successful": any(r.get("success", False) for r in decryption_results),
                    "results": decryption_results
                }
            except Exception as e:
                logger.error(f"Error attempting decryption: {e}")
                file_result["decryption_attempts"] = {
                    "status": "error",
                    "message": str(e)
                }
            
            file_results.append(file_result)
        
        # Update identified families
        self.identified_families.update(families)
        
        # Update results
        results["analyzed_files"] = file_results
        results["identified_families"] = list(self.identified_families)
        
        self.results["sample_analysis"] = results
        return results
    
    def analyze_memory_dumps(self, memory_dir: str) -> Dict[str, Any]:
        """
        Analyze memory dumps for encryption keys
        
        Args:
            memory_dir: Directory containing memory dumps
            
        Returns:
            Dictionary of analysis results
        """
        if not os.path.exists(memory_dir) or not os.path.isdir(memory_dir):
            logger.error(f"Memory dumps directory not found: {memory_dir}")
            return {
                "status": "error",
                "message": f"Memory dumps directory not found: {memory_dir}",
                "timestamp": datetime.now().isoformat()
            }
        
        logger.info(f"Analyzing memory dumps in: {memory_dir}")
        
        # This is a placeholder - in a full implementation, this would:
        # 1. Scan memory dumps for encryption keys
        # 2. Correlate with network traffic
        # 3. Extract and add keys to the recovery module
        
        # For now, just return a placeholder result
        results = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "memory_dir": memory_dir,
            "message": "Memory dump analysis not fully implemented in this version",
            "extracted_keys": {
                "count": 0,
                "keys": []
            }
        }
        
        self.results["memory_analysis"] = results
        return results
    
    def attempt_file_decryption(self, file_path: str, output_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Attempt to decrypt a file using extracted keys
        
        Args:
            file_path: Path to encrypted file
            output_dir: Optional directory to save decrypted files
            
        Returns:
            List of decryption attempt results
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return [{
                "status": "error",
                "message": f"File not found: {file_path}",
                "timestamp": datetime.now().isoformat()
            }]
        
        # Create output file path if output directory is specified
        output_file = None
        if output_dir:
            if not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)
            
            filename = os.path.basename(file_path)
            output_file = os.path.join(output_dir, f"decrypted_{filename}")
        
        # Attempt decryption
        logger.info(f"Attempting to decrypt: {file_path}")
        results = self.recovery.attempt_decryption(file_path, output_file)
        
        # Convert results to dictionaries
        return [result.to_dict() for result in results]
    
    def analyze_all(self, samples_dir: Optional[str] = None, 
                   memory_dir: Optional[str] = None,
                   output_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of PCAP, samples, and memory dumps
        
        Args:
            samples_dir: Optional directory containing sample files
            memory_dir: Optional directory containing memory dumps
            output_dir: Optional directory to save output files
            
        Returns:
            Dictionary of all analysis results
        """
        # Analyze PCAP file
        pcap_results = self.analyze_pcap()
        
        # Analyze samples if directory provided
        sample_results = None
        if samples_dir:
            sample_results = self.analyze_samples(samples_dir)
        
        # Analyze memory dumps if directory provided
        memory_results = None
        if memory_dir:
            memory_results = self.analyze_memory_dumps(memory_dir)
        
        # Generate final report
        report = self.generate_report()
        
        # Save report if output directory provided
        if output_dir:
            if not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)
            
            report_file = os.path.join(output_dir, "ransomware_network_analysis_report.json")
            try:
                with open(report_file, 'w') as f:
                    json.dump(report, f, indent=2)
                logger.info(f"Report saved to: {report_file}")
            except Exception as e:
                logger.error(f"Error saving report: {e}")
        
        return report
    
    def monitor_network(self, duration: int = 300) -> Dict[str, Any]:
        """
        Monitor network for ransomware activity
        
        Args:
            duration: Monitoring duration in seconds
            
        Returns:
            Dictionary of monitoring results
        """
        if not self.network_detector:
            logger.error("Network detector not available")
            return {
                "status": "error",
                "message": "Network detector not available. Install required packages.",
                "timestamp": datetime.now().isoformat()
            }
        
        logger.info(f"Starting network monitoring for {duration} seconds on interface {self.interface}")
        
        # Start network monitoring
        self.network_detector.start_monitoring()
        
        try:
            # Monitor for specified duration
            for i in range(duration):
                if i % 10 == 0:  # Log every 10 seconds
                    alerts = self.network_detector.get_alerts(min_confidence=0.5)
                    logger.info(f"Monitoring... {i}/{duration}s, {len(alerts)} alerts")
                time.sleep(1)
        finally:
            # Stop monitoring
            self.network_detector.stop_monitoring()
        
        # Get all alerts
        alerts = self.network_detector.get_alerts()
        
        # Identify families from alerts
        families = set()
        for alert in alerts:
            if alert.get("ransomware_family"):
                families.add(alert["ransomware_family"])
        
        self.identified_families.update(families)
        
        # Prepare results
        results = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "interface": self.interface,
            "duration": duration,
            "alerts": {
                "count": len(alerts),
                "alerts": alerts
            },
            "identified_families": list(self.identified_families)
        }
        
        self.results["network_monitoring"] = results
        return results
    
    def generate_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive report of all analysis results
        
        Returns:
            Report dictionary
        """
        # Combine all results
        report = {
            "timestamp": datetime.now().isoformat(),
            "identified_ransomware_families": list(self.identified_families),
            "extracted_keys": {
                "network": [key.to_dict() for key in self.network_keys],
                "memory": [key.to_dict() for key in self.memory_keys]
            },
            "results": self.results
        }
        
        # Add summary
        report["summary"] = {
            "ransomware_detected": len(self.identified_families) > 0,
            "family_count": len(self.identified_families),
            "network_key_count": len(self.network_keys),
            "memory_key_count": len(self.memory_keys),
            "timestamp": datetime.now().isoformat()
        }
        
        return report


def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description="Ransomware Network Analyzer")
    parser.add_argument("--pcap", help="PCAP file to analyze")
    parser.add_argument("--samples", help="Directory containing sample files")
    parser.add_argument("--memory", help="Directory containing memory dumps")
    parser.add_argument("--output", help="Directory to save output files")
    parser.add_argument("--interface", default="any", help="Network interface to monitor")
    parser.add_argument("--monitor", type=int, help="Monitor network for specified duration (seconds)")
    parser.add_argument("--report", help="Save report to this file")
    args = parser.parse_args()
    
    # Check if at least one of the required options is specified
    if not (args.pcap or args.samples or args.memory or args.monitor):
        parser.error("At least one of --pcap, --samples, --memory, or --monitor must be specified")
    
    # Create analyzer
    analyzer = RansomwareNetworkAnalyzer(args.pcap, args.interface)
    
    # Perform analysis based on provided options
    if args.pcap:
        analyzer.analyze_pcap()
    
    if args.samples:
        analyzer.analyze_samples(args.samples)
    
    if args.memory:
        analyzer.analyze_memory_dumps(args.memory)
    
    if args.monitor:
        analyzer.monitor_network(args.monitor)
    
    # Generate report
    report = analyzer.generate_report()
    
    # Save report if specified
    if args.report:
        try:
            with open(args.report, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report saved to: {args.report}")
        except Exception as e:
            logger.error(f"Error saving report: {e}")
    
    # Save decrypted files to output directory if specified
    if args.output and args.samples:
        # This would decrypt and save files
        pass
    
    logger.info("Analysis complete")
    
    # Print summary
    summary = report.get("summary", {})
    print("\nAnalysis Summary:")
    print(f"Timestamp: {summary.get('timestamp')}")
    print(f"Ransomware detected: {summary.get('ransomware_detected')}")
    print(f"Families identified: {summary.get('family_count')}")
    print(f"Network keys extracted: {summary.get('network_key_count')}")
    print(f"Memory keys extracted: {summary.get('memory_key_count')}")
    
    if report.get("identified_ransomware_families"):
        print("\nIdentified Ransomware Families:")
        for family in report["identified_ransomware_families"]:
            print(f" - {family}")


if __name__ == "__main__":
    main()