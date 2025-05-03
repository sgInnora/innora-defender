#!/usr/bin/env python3
"""
Advanced Ransomware Analysis Integration
Combines memory analysis, behavior detection, and threat intelligence
for comprehensive ransomware analysis.
"""

import os
import sys
import json
import time
import logging
import argparse
import datetime
import threading
from typing import Dict, List, Any, Optional
from pathlib import Path

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import our modules
from memory_analysis.extractors.key_extractor import MemoryKeyExtractor
from behavior_analysis.detectors.ransomware_detector import RansomwareBehaviorDetector
from threat_intel.threat_intel_analyzer import ThreatIntelAnalyzer
from threat_intel.integration import ThreatIntelIntegration

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(__file__), 'logs', 'advanced_analysis.log'), mode='a'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('advanced_analysis')

# Create logs directory if it doesn't exist
os.makedirs(os.path.join(os.path.dirname(__file__), 'logs'), exist_ok=True)

class AdvancedAnalysisIntegration:
    """
    Integrates memory analysis, behavior detection, and threat intelligence
    """
    
    def __init__(self, config_file=None, api_keys=None, output_dir=None):
        """
        Initialize the advanced analysis integration
        
        Args:
            config_file: Path to configuration file (optional)
            api_keys: Dictionary of API keys (optional)
            output_dir: Base directory for outputs (optional)
        """
        self.config = self._load_config(config_file)
        
        # Set API keys in environment if provided
        if api_keys:
            for key_name, key_value in api_keys.items():
                os.environ[key_name] = key_value
        
        # Set output directory
        self.output_dir = output_dir or os.path.join(
            os.path.dirname(__file__), 'output', 'advanced_analysis'
        )
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Create subdirectories
        self.memory_dir = os.path.join(self.output_dir, 'memory_analysis')
        self.behavior_dir = os.path.join(self.output_dir, 'behavior_analysis')
        self.integrated_dir = os.path.join(self.output_dir, 'integrated_reports')
        
        os.makedirs(self.memory_dir, exist_ok=True)
        os.makedirs(self.behavior_dir, exist_ok=True)
        os.makedirs(self.integrated_dir, exist_ok=True)
        
        # Initialize components
        self.memory_extractor = MemoryKeyExtractor()
        self.behavior_detector = RansomwareBehaviorDetector()
        self.threat_intel_analyzer = ThreatIntelAnalyzer(api_keys=api_keys)
        self.threat_intel_integration = ThreatIntelIntegration(api_keys=api_keys)
    
    def _load_config(self, config_file=None) -> Dict:
        """
        Load configuration from file or use defaults
        
        Args:
            config_file: Path to configuration file
            
        Returns:
            Configuration dictionary
        """
        default_config = {
            "enable_live_monitoring": False,
            "monitor_timeout": 300,  # 5 minutes
            "memory_analysis": {
                "enabled": True,
                "full_analysis": True,
                "extract_promising_keys": True
            },
            "behavior_analysis": {
                "enabled": True,
                "alert_on_detection": True
            },
            "threat_intel": {
                "enabled": True,
                "generate_reports": True,
                "generate_iocs": True,
                "generate_yara": True,
                "ioc_formats": ["json", "csv", "stix"]
            },
            "integration": {
                "correlate_across_components": True,
                "integrated_report": True
            }
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                
                # Merge with defaults to ensure all keys exist
                merged_config = default_config.copy()
                for section, settings in config.items():
                    if section in merged_config and isinstance(merged_config[section], dict):
                        merged_config[section].update(settings)
                    else:
                        merged_config[section] = settings
                
                return merged_config
            except Exception as e:
                logger.error(f"Error loading configuration: {e}")
                return default_config
        else:
            return default_config
    
    def analyze_memory_dump(self, dump_file: str) -> Dict:
        """
        Analyze a memory dump file
        
        Args:
            dump_file: Path to memory dump file
            
        Returns:
            Analysis results dictionary
        """
        logger.info(f"Analyzing memory dump: {dump_file}")
        
        if not self.config["memory_analysis"]["enabled"]:
            logger.info("Memory analysis is disabled in configuration")
            return {"status": "skipped", "reason": "Memory analysis disabled in configuration"}
        
        try:
            # Perform full analysis
            if self.config["memory_analysis"]["full_analysis"]:
                results = self.memory_extractor.analyze_memory_dump(dump_file)
            else:
                # Otherwise just search for patterns
                results = self.memory_extractor.search_memory_dump(dump_file)
            
            # Save results to file
            output_file = os.path.join(
                self.memory_dir,
                f"memory_analysis_{Path(dump_file).stem}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.json"
            )
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            # Extract promising keys if configured
            if (self.config["memory_analysis"]["extract_promising_keys"] and 
                "analysis" in results and 
                "promising_keys" in results["analysis"]):
                
                promising_keys = results["analysis"]["promising_keys"]
                extracted_keys = []
                
                for key_info in promising_keys:
                    try:
                        key_result = self.memory_extractor.extract_key_from_offset(
                            dump_file,
                            key_info["offset"],
                            key_info["type"],
                            key_info["length"]
                        )
                        extracted_keys.append(key_result)
                    except Exception as e:
                        logger.error(f"Error extracting key at offset {key_info['offset']}: {e}")
                
                # Save extracted keys
                keys_file = os.path.join(
                    self.memory_dir,
                    f"extracted_keys_{Path(dump_file).stem}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.json"
                )
                with open(keys_file, 'w') as f:
                    json.dump(extracted_keys, f, indent=2)
                
                results["extracted_keys_file"] = keys_file
            
            results["output_file"] = output_file
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing memory dump: {e}")
            return {"status": "error", "error": str(e)}
    
    def analyze_sample_behavior(self, sample_data: Dict) -> Dict:
        """
        Analyze sample behavior
        
        Args:
            sample_data: Sample data dictionary
            
        Returns:
            Analysis results dictionary
        """
        logger.info(f"Analyzing sample behavior for {sample_data.get('sha256', 'unknown')}")
        
        if not self.config["behavior_analysis"]["enabled"]:
            logger.info("Behavior analysis is disabled in configuration")
            return {"status": "skipped", "reason": "Behavior analysis disabled in configuration"}
        
        try:
            results = self.behavior_detector.analyze_sample(sample_data)
            
            # Save results to file
            output_file = os.path.join(
                self.behavior_dir,
                f"behavior_analysis_{sample_data.get('sha256', 'unknown')}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.json"
            )
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            results["output_file"] = output_file
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing sample behavior: {e}")
            return {"status": "error", "error": str(e)}
    
    def analyze_threat_intelligence(self, sample_data: Dict) -> Dict:
        """
        Analyze sample with threat intelligence
        
        Args:
            sample_data: Sample data dictionary
            
        Returns:
            Analysis results dictionary
        """
        logger.info(f"Analyzing threat intelligence for {sample_data.get('sha256', 'unknown')}")
        
        if not self.config["threat_intel"]["enabled"]:
            logger.info("Threat intelligence analysis is disabled in configuration")
            return {"status": "skipped", "reason": "Threat intelligence disabled in configuration"}
        
        try:
            results = self.threat_intel_integration.process_sample(
                sample_data,
                generate_report=self.config["threat_intel"]["generate_reports"],
                generate_iocs=self.config["threat_intel"]["generate_iocs"],
                generate_yara=self.config["threat_intel"]["generate_yara"],
                ioc_formats=self.config["threat_intel"]["ioc_formats"],
                view_report=False
            )
            
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing threat intelligence: {e}")
            return {"status": "error", "error": str(e)}
    
    def integrate_analysis_results(self, memory_results: Dict, behavior_results: Dict, 
                                threat_intel_results: Dict, 
                                sample_data: Dict) -> Dict:
        """
        Integrate results from different analysis components
        
        Args:
            memory_results: Memory analysis results
            behavior_results: Behavior analysis results
            threat_intel_results: Threat intelligence results
            sample_data: Original sample data
            
        Returns:
            Integrated analysis results
        """
        logger.info("Integrating analysis results")
        
        results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "sample_id": sample_data.get("sha256", "unknown"),
            "sample_name": sample_data.get("name", "unknown"),
            "analysis_components": {},
            "integrated_analysis": {
                "ransomware_classification": {
                    "is_ransomware": False,
                    "confidence": 0.0,
                    "identified_families": []
                },
                "encryption_artifacts": {
                    "encryption_keys": [],
                    "ransom_notes": [],
                    "bitcoin_addresses": []
                },
                "behavior_indicators": [],
                "network_indicators": [],
                "recommendations": []
            }
        }
        
        # Add component results
        if memory_results:
            if "status" in memory_results and memory_results["status"] in ["skipped", "error"]:
                results["analysis_components"]["memory_analysis"] = memory_results
            else:
                results["analysis_components"]["memory_analysis"] = {
                    "status": "completed",
                    "output_file": memory_results.get("output_file")
                }
                if "extracted_keys_file" in memory_results:
                    results["analysis_components"]["memory_analysis"]["extracted_keys_file"] = memory_results["extracted_keys_file"]
        
        if behavior_results:
            if "status" in behavior_results and behavior_results["status"] in ["skipped", "error"]:
                results["analysis_components"]["behavior_analysis"] = behavior_results
            else:
                results["analysis_components"]["behavior_analysis"] = {
                    "status": "completed",
                    "output_file": behavior_results.get("output_file"),
                    "severity": behavior_results.get("severity", "low"),
                    "conclusion": behavior_results.get("conclusion", "Unknown")
                }
        
        if threat_intel_results:
            if "status" in threat_intel_results and threat_intel_results["status"] in ["skipped", "error"]:
                results["analysis_components"]["threat_intel"] = threat_intel_results
            else:
                results["analysis_components"]["threat_intel"] = {
                    "status": "completed",
                    "correlation_file": threat_intel_results.get("correlation_file"),
                    "report_path": threat_intel_results.get("report_path"),
                    "ioc_files": threat_intel_results.get("ioc_files", {}),
                    "yara_rule": threat_intel_results.get("yara_rule")
                }
        
        # Integrate ransomware classification
        # Combine evidence from multiple sources
        ransomware_confidence_scores = []
        identified_families = []
        
        # Check threat intel classification
        if (threat_intel_results and 
            "correlation" in threat_intel_results and 
            "is_ransomware" in threat_intel_results["correlation"]):
            ti_is_ransomware = threat_intel_results["correlation"]["is_ransomware"]
            ti_confidence = threat_intel_results["correlation"].get("ransomware_probability", 0.5)
            ransomware_confidence_scores.append(ti_confidence if ti_is_ransomware else 1.0 - ti_confidence)
            
            # Add identified families
            if "identified_families" in threat_intel_results["correlation"]:
                for family in threat_intel_results["correlation"]["identified_families"]:
                    if family not in identified_families:
                        identified_families.append(family)
        
        # Check behavior classification
        if behavior_results and "conclusion" in behavior_results:
            conclusion = behavior_results["conclusion"]
            if "high confidence" in conclusion.lower():
                ransomware_confidence_scores.append(0.9)
            elif "medium confidence" in conclusion.lower():
                ransomware_confidence_scores.append(0.6)
            elif "no clear" in conclusion.lower():
                ransomware_confidence_scores.append(0.1)
        
        # Check memory analysis classification
        if (memory_results and 
            "analysis" in memory_results and 
            "identified_families" in memory_results["analysis"]):
            memory_families = memory_results["analysis"]["identified_families"]
            if memory_families:
                # Add confidence based on top family
                ransomware_confidence_scores.append(memory_families[0].get("confidence", 0.5))
                
                # Add identified families
                for family in memory_families:
                    family_info = {
                        "name": family["name"],
                        "confidence": family["confidence"]
                    }
                    if family_info not in identified_families:
                        identified_families.append(family_info)
        
        # Calculate overall confidence
        if ransomware_confidence_scores:
            avg_confidence = sum(ransomware_confidence_scores) / len(ransomware_confidence_scores)
            results["integrated_analysis"]["ransomware_classification"]["confidence"] = avg_confidence
            results["integrated_analysis"]["ransomware_classification"]["is_ransomware"] = avg_confidence > 0.5
        
        # Add identified families
        results["integrated_analysis"]["ransomware_classification"]["identified_families"] = identified_families
        
        # Integrate encryption artifacts
        # Add encryption keys from memory analysis
        if (memory_results and 
            "analysis" in memory_results and 
            "promising_keys" in memory_results["analysis"]):
            for key in memory_results["analysis"]["promising_keys"]:
                results["integrated_analysis"]["encryption_artifacts"]["encryption_keys"].append({
                    "type": key["type"],
                    "length": key["length"],
                    "offset": key["offset"],
                    "source": "memory_analysis"
                })
        
        # Add ransom notes
        if (memory_results and 
            "artifacts" in memory_results and 
            "ransom_notes" in memory_results["artifacts"]):
            for note in memory_results["artifacts"]["ransom_notes"]:
                results["integrated_analysis"]["encryption_artifacts"]["ransom_notes"].append({
                    "excerpt": note["ascii"],
                    "offset": note["offset"],
                    "source": "memory_analysis"
                })
        
        if behavior_results and "found_behaviors" in behavior_results:
            for behavior in behavior_results["found_behaviors"]:
                if behavior["type"] == "ransom_note":
                    results["integrated_analysis"]["encryption_artifacts"]["ransom_notes"].append({
                        "path": behavior.get("path", "unknown"),
                        "severity": behavior.get("severity", "unknown"),
                        "source": "behavior_analysis"
                    })
        
        # Add Bitcoin addresses
        if (memory_results and 
            "artifacts" in memory_results and 
            "bitcoin_addresses" in memory_results["artifacts"]):
            for addr in memory_results["artifacts"]["bitcoin_addresses"]:
                results["integrated_analysis"]["encryption_artifacts"]["bitcoin_addresses"].append({
                    "address": addr["ascii"],
                    "source": "memory_analysis"
                })
        
        # Integrate behavior indicators
        if behavior_results and "found_behaviors" in behavior_results:
            for behavior in behavior_results["found_behaviors"]:
                results["integrated_analysis"]["behavior_indicators"].append({
                    "type": behavior["type"],
                    "severity": behavior.get("severity", "unknown"),
                    "details": behavior
                })
        
        # Integrate network indicators
        # From memory analysis
        if (memory_results and 
            "artifacts" in memory_results and 
            "command_and_control" in memory_results["artifacts"]):
            for c2 in memory_results["artifacts"]["command_and_control"]:
                results["integrated_analysis"]["network_indicators"].append({
                    "type": "command_and_control",
                    "value": c2["ascii"],
                    "source": "memory_analysis"
                })
        
        # From threat intel
        if (threat_intel_results and 
            "correlation" in threat_intel_results and 
            "iocs" in threat_intel_results["correlation"]):
            iocs = threat_intel_results["correlation"]["iocs"]
            
            if "domains" in iocs:
                for domain in iocs["domains"]:
                    results["integrated_analysis"]["network_indicators"].append({
                        "type": "domain",
                        "value": domain.get("value", domain),
                        "source": "threat_intel"
                    })
            
            if "ips" in iocs:
                for ip in iocs["ips"]:
                    results["integrated_analysis"]["network_indicators"].append({
                        "type": "ip",
                        "value": ip.get("value", ip),
                        "source": "threat_intel"
                    })
            
            if "urls" in iocs:
                for url in iocs["urls"]:
                    results["integrated_analysis"]["network_indicators"].append({
                        "type": "url",
                        "value": url.get("value", url),
                        "source": "threat_intel"
                    })
        
        # Integrate recommendations
        # From memory analysis
        if (memory_results and 
            "analysis" in memory_results and 
            "recommendations" in memory_results["analysis"]):
            for rec in memory_results["analysis"]["recommendations"]:
                results["integrated_analysis"]["recommendations"].append({
                    "type": rec["type"],
                    "priority": rec["priority"],
                    "description": rec["description"],
                    "source": "memory_analysis"
                })
        
        # From threat intel
        if (threat_intel_results and 
            "correlation" in threat_intel_results and 
            "recommendations" in threat_intel_results["correlation"]):
            for rec in threat_intel_results["correlation"]["recommendations"]:
                results["integrated_analysis"]["recommendations"].append({
                    "type": rec.get("type", "unknown"),
                    "priority": rec.get("priority", "medium"),
                    "description": rec.get("description", "Unknown"),
                    "source": "threat_intel"
                })
        
        # Sort recommendations by priority
        priority_order = {"high": 0, "medium": 1, "low": 2}
        results["integrated_analysis"]["recommendations"].sort(
            key=lambda x: priority_order.get(x["priority"], 3)
        )
        
        # Generate integrated report
        if self.config["integration"]["integrated_report"]:
            output_file = os.path.join(
                self.integrated_dir,
                f"integrated_analysis_{sample_data.get('sha256', 'unknown')}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.json"
            )
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            results["output_file"] = output_file
        
        return results
    
    def analyze_sample(self, sample_data: Dict, memory_dump_file: str = None) -> Dict:
        """
        Perform complete analysis of a sample
        
        Args:
            sample_data: Sample data dictionary
            memory_dump_file: Path to memory dump file (optional)
            
        Returns:
            Integrated analysis results
        """
        logger.info(f"Analyzing sample {sample_data.get('sha256', 'unknown')}")
        
        # Step 1: Analyze behavior
        behavior_results = self.analyze_sample_behavior(sample_data)
        
        # Step 2: Analyze memory dump if provided
        memory_results = None
        if memory_dump_file:
            memory_results = self.analyze_memory_dump(memory_dump_file)
        
        # Step 3: Analyze threat intelligence
        threat_intel_results = self.analyze_threat_intelligence(sample_data)
        
        # Step 4: Integrate results
        integrated_results = self.integrate_analysis_results(
            memory_results, behavior_results, threat_intel_results, sample_data
        )
        
        return integrated_results
    
    def monitor_live_system(self, timeout: int = None, alert_handler=None) -> Dict:
        """
        Monitor a live system for ransomware activity
        
        Args:
            timeout: Monitoring timeout in seconds (None for indefinite)
            alert_handler: Function to handle alerts (optional)
            
        Returns:
            Monitoring results
        """
        logger.info("Starting live system monitoring")
        
        if not self.config["behavior_analysis"]["enabled"]:
            logger.info("Behavior analysis is disabled in configuration")
            return {"status": "skipped", "reason": "Behavior analysis disabled in configuration"}
        
        if timeout is None:
            timeout = self.config["monitor_timeout"]
        
        try:
            # Register alert handler if provided
            if alert_handler:
                self.behavior_detector.register_alert_handler(alert_handler)
            
            # Register console alerts if configured
            if self.config["behavior_analysis"]["alert_on_detection"]:
                self.behavior_detector.register_alert_handler(
                    lambda alert: logger.warning(f"ALERT: {json.dumps(alert)}")
                )
            
            # Start monitoring
            self.behavior_detector.start()
            
            # Monitor for specified time
            logger.info(f"Monitoring for {timeout} seconds...")
            time.sleep(timeout)
            
            # Stop monitoring
            self.behavior_detector.stop()
            
            # Get all alerts
            alerts = self.behavior_detector.get_alerts()
            
            # Save alerts to file
            output_file = os.path.join(
                self.behavior_dir,
                f"live_monitoring_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.json"
            )
            with open(output_file, 'w') as f:
                json.dump({"alerts": alerts}, f, indent=2)
            
            return {
                "status": "completed",
                "duration": timeout,
                "alert_count": len(alerts),
                "output_file": output_file
            }
            
        except Exception as e:
            logger.error(f"Error in live monitoring: {e}")
            # Make sure to stop monitoring
            try:
                self.behavior_detector.stop()
            except:
                pass
            
            return {"status": "error", "error": str(e)}
    
    def create_memory_dump(self, pid: int, output_file: str = None) -> str:
        """
        Create a memory dump of a process
        
        Args:
            pid: Process ID
            output_file: Output file path (optional)
            
        Returns:
            Path to the memory dump file
        """
        logger.info(f"Creating memory dump for process {pid}")
        
        if not output_file:
            output_file = os.path.join(
                self.memory_dir,
                f"process_dump_{pid}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.dmp"
            )
        
        # This is a placeholder implementation
        # In a real implementation, this would:
        # 1. Use platform-specific methods to dump process memory
        # 2. Save the dump to the specified file
        
        logger.warning("Memory dump creation is not implemented for this platform")
        raise NotImplementedError("Memory dump creation not implemented for this platform")


def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description="Advanced Ransomware Analysis Integration")
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--sample', '-s', help='Path to sample JSON file')
    input_group.add_argument('--memory-dump', '-m', help='Path to memory dump file')
    input_group.add_argument('--monitor', action='store_true', help='Monitor live system')
    
    # Configuration options
    parser.add_argument('--config', '-c', help='Path to configuration file')
    parser.add_argument('--output-dir', '-o', help='Output directory for all results')
    
    # API keys
    parser.add_argument('--vt-key', help='VirusTotal API key')
    parser.add_argument('--otx-key', help='AlienVault OTX API key')
    
    # Monitoring options
    parser.add_argument('--timeout', '-t', type=int, default=300, help='Monitoring timeout in seconds (default: 300)')
    
    # Analysis options
    parser.add_argument('--full-analysis', '-f', action='store_true', help='Perform full analysis (memory + behavior + threat intel)')
    
    args = parser.parse_args()
    
    # Configure API keys
    api_keys = {}
    if args.vt_key:
        api_keys['VIRUSTOTAL_API_KEY'] = args.vt_key
    if args.otx_key:
        api_keys['ALIENVAULT_OTX_API_KEY'] = args.otx_key
    
    # Create integration
    integration = AdvancedAnalysisIntegration(
        config_file=args.config,
        api_keys=api_keys,
        output_dir=args.output_dir
    )
    
    try:
        if args.monitor:
            # Monitor live system
            print("Starting live system monitoring...")
            
            # Define alert handler
            def alert_handler(alert):
                print(f"\nALERT: {alert['type']} - Severity: {alert.get('severity', 'unknown')}")
                if "process_name" in alert:
                    print(f"Process: {alert['process_name']}")
                if "command_line" in alert:
                    print(f"Command: {alert['command_line']}")
                if "path" in alert:
                    print(f"File: {alert['path']}")
                print(f"Time: {alert['timestamp_iso']}")
                print("-" * 60)
            
            results = integration.monitor_live_system(
                timeout=args.timeout,
                alert_handler=alert_handler
            )
            
            print(f"\nMonitoring completed with {results['alert_count']} alerts")
            print(f"Results saved to: {results.get('output_file')}")
            
        elif args.memory_dump:
            # Analyze memory dump
            print(f"Analyzing memory dump: {args.memory_dump}")
            
            if args.full_analysis:
                # Create a minimal sample data structure
                sample_data = {
                    "sha256": Path(args.memory_dump).stem,
                    "name": Path(args.memory_dump).name
                }
                
                # Perform full analysis
                results = integration.analyze_sample(sample_data, args.memory_dump)
                
                print("\nAnalysis completed:")
                for component, info in results["analysis_components"].items():
                    print(f"- {component}: {info['status']}")
                
                classification = results["integrated_analysis"]["ransomware_classification"]
                print(f"\nRansomware Classification:")
                print(f"- Is Ransomware: {classification['is_ransomware']}")
                print(f"- Confidence: {classification['confidence']:.1%}")
                
                if classification["identified_families"]:
                    print(f"- Families: {', '.join(f.get('name', 'unknown') for f in classification['identified_families'])}")
                
                print(f"\nIntegrated analysis saved to: {results.get('output_file')}")
                
            else:
                # Just analyze memory dump
                results = integration.analyze_memory_dump(args.memory_dump)
                
                print("\nMemory analysis completed")
                
                if "analysis" in results:
                    analysis = results["analysis"]
                    
                    print("\nSummary:")
                    if "summary" in analysis:
                        summary = analysis["summary"]
                        print(f"- AES Keys: {summary['key_candidates']['aes']}")
                        print(f"- RSA Keys: {summary['key_candidates']['rsa']}")
                        print(f"- Bitcoin Addresses: {summary['bitcoin_addresses']}")
                        print(f"- Ransom Notes: {summary['ransom_notes']}")
                        print(f"- C2 Indicators: {summary['command_and_control']}")
                    
                    if "identified_families" in analysis and analysis["identified_families"]:
                        families = analysis["identified_families"]
                        print("\nIdentified Families:")
                        for family in families:
                            print(f"- {family['name']} ({family['confidence']:.1%})")
                
                print(f"\nResults saved to: {results.get('output_file')}")
                
        elif args.sample:
            # Analyze sample
            print(f"Analyzing sample: {args.sample}")
            
            try:
                with open(args.sample, 'r') as f:
                    sample_data = json.load(f)
            except Exception as e:
                print(f"Error reading sample file: {e}")
                return 1
            
            # Check if a memory dump is available alongside the sample
            memory_dump_file = None
            sample_dir = Path(args.sample).parent
            sample_name = Path(args.sample).stem
            
            potential_dump_files = [
                sample_dir / f"{sample_name}.dmp",
                sample_dir / f"{sample_name}_memory.dmp",
                sample_dir / f"{sample_name}.mem",
                sample_dir / "memory" / f"{sample_name}.dmp"
            ]
            
            for dump_file in potential_dump_files:
                if dump_file.exists():
                    memory_dump_file = str(dump_file)
                    print(f"Found memory dump file: {memory_dump_file}")
                    break
            
            # Perform analysis
            results = integration.analyze_sample(sample_data, memory_dump_file)
            
            print("\nAnalysis completed:")
            for component, info in results["analysis_components"].items():
                print(f"- {component}: {info['status']}")
            
            classification = results["integrated_analysis"]["ransomware_classification"]
            print(f"\nRansomware Classification:")
            print(f"- Is Ransomware: {classification['is_ransomware']}")
            print(f"- Confidence: {classification['confidence']:.1%}")
            
            if classification["identified_families"]:
                print(f"- Families: {', '.join(f.get('name', 'unknown') for f in classification['identified_families'])}")
            
            print(f"\nIntegrated analysis saved to: {results.get('output_file')}")
        
    except Exception as e:
        logger.error(f"Error in main: {e}")
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())