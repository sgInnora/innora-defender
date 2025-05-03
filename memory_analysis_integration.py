#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Memory Analysis Integration Module

This module integrates advanced memory analysis capabilities into the ransomware analysis workflow.
It provides a bridge between memory dump analysis and the automated workflow system, enhancing
the ability to extract encryption keys and other artifacts from memory dumps.

Key features:
- Integration with specialized ransomware memory key extractors
- Memory dump acquisition from running processes
- Automated extraction and validation of encryption keys
- Support for multiple ransomware families
- Enhanced LockBit-specific memory analysis
"""

import os
import sys
import logging
import tempfile
import datetime
import subprocess
from typing import Dict, List, Optional, Any, Union, Tuple

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import memory key extractor components
from tools.memory.key_extractors.ransomware_key_extractor import (
    RansomwareKeyExtractor, LockBitKeyExtractor, RansomKeySearchResult
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("MemoryAnalysisIntegration")


class MemoryAnalysisIntegrator:
    """
    Integrates memory analysis capabilities into the ransomware analysis workflow.
    """
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize the memory analysis integrator.
        
        Args:
            output_dir: Optional output directory for results
        """
        # Set up output directory
        if output_dir:
            self.output_dir = os.path.abspath(output_dir)
        else:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_dir = os.path.join(os.getcwd(), f"memory_analysis_{timestamp}")
        
        os.makedirs(self.output_dir, exist_ok=True)
        logger.info(f"Memory Analysis Integrator initialized with output directory: {self.output_dir}")
        
        # Initialize components
        self.generic_extractor = RansomwareKeyExtractor(self.output_dir)
        self.lockbit_extractor = LockBitKeyExtractor(self.output_dir)
        
        # Analysis results
        self.memory_dumps = []
        self.extracted_keys = {}
        self.analysis_reports = {}
    
    def acquire_memory_dump(self, process_id: Optional[int] = None, 
                           dump_path: Optional[str] = None) -> str:
        """
        Acquire a memory dump from a running process or use an existing dump.
        
        Args:
            process_id: Optional process ID to dump memory from
            dump_path: Optional path to an existing memory dump
            
        Returns:
            Path to the memory dump file
        """
        if dump_path and os.path.exists(dump_path):
            logger.info(f"Using existing memory dump: {dump_path}")
            self.memory_dumps.append(dump_path)
            return dump_path
        
        if not process_id:
            logger.error("Neither process ID nor dump path provided")
            raise ValueError("Must provide either process_id or dump_path")
        
        # Generate a filename for the dump
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        dump_file = os.path.join(self.output_dir, f"memdump_pid{process_id}_{timestamp}.dmp")
        
        try:
            # Create memory dump using platform-specific methods
            if sys.platform == 'win32':
                # Windows - use procdump or similar tool
                logger.info(f"Creating memory dump for process {process_id} on Windows")
                subprocess.run([
                    "procdump", "-ma", str(process_id), dump_file
                ], check=True, capture_output=True)
            elif sys.platform in ('linux', 'linux2'):
                # Linux - use process memory maps
                logger.info(f"Creating memory dump for process {process_id} on Linux")
                with open(dump_file, 'wb') as f:
                    # Use /proc/[pid]/mem to dump memory
                    maps_path = f"/proc/{process_id}/maps"
                    mem_path = f"/proc/{process_id}/mem"
                    
                    with open(maps_path, 'r') as maps:
                        for line in maps:
                            fields = line.split()
                            if len(fields) < 6:
                                continue
                                
                            # Parse address range
                            addr_range = fields[0].split('-')
                            start = int(addr_range[0], 16)
                            end = int(addr_range[1], 16)
                            
                            # Check if readable
                            if 'r' in fields[1]:
                                try:
                                    with open(mem_path, 'rb') as mem:
                                        mem.seek(start)
                                        f.write(mem.read(end - start))
                                except Exception as e:
                                    # Skip regions that can't be read
                                    logger.debug(f"Couldn't read memory region {fields[0]}: {e}")
            else:
                # MacOS - use pmmap or similar tool
                logger.info(f"Creating memory dump for process {process_id} on MacOS")
                subprocess.run([
                    "sudo", "gcore", str(process_id)
                ], check=True, capture_output=True)
                
                # gcore creates a file in current directory named "core.[pid]"
                core_file = f"core.{process_id}"
                if os.path.exists(core_file):
                    # Move to our dump file path
                    os.rename(core_file, dump_file)
            
            logger.info(f"Memory dump created at {dump_file}")
            self.memory_dumps.append(dump_file)
            return dump_file
            
        except Exception as e:
            logger.error(f"Failed to create memory dump: {e}")
            raise
    
    def analyze_memory_dump(self, memory_dump: str, 
                           family: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze a memory dump for encryption keys.
        
        Args:
            memory_dump: Path to memory dump file
            family: Optional ransomware family name
            
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Analyzing memory dump: {memory_dump}")
        
        # Determine family if not specified
        if not family:
            family = self.detect_family(memory_dump)
            logger.info(f"Detected ransomware family: {family}")
        
        results = {}
        
        # Use family-specific extractor if available
        if family and family.lower() == 'lockbit':
            logger.info("Using specialized LockBit extractor")
            # Extract both keys and IVs for LockBit
            lockbit_results = self.lockbit_extractor.extract_iv_and_keys(memory_dump)
            
            # Capture keys
            keys = []
            for key_dict in lockbit_results.get('keys', []):
                keys.append(key_dict)
            
            # Add to results
            results = {
                'family': 'LockBit',
                'version': lockbit_results.get('version', 'unknown'),
                'keys': keys,
                'ivs': lockbit_results.get('ivs', []),
                'timestamp': datetime.datetime.now().isoformat()
            }
        else:
            # Use generic extractor for unknown or other families
            logger.info(f"Using generic extractor for {family if family else 'unknown'} family")
            generic_keys = self.generic_extractor.analyze_memory_dump(memory_dump, family)
            
            # Convert to dictionary format
            keys = [key.to_dict() for key in generic_keys]
            
            # Add to results
            results = {
                'family': family if family else 'Unknown',
                'keys': keys,
                'timestamp': datetime.datetime.now().isoformat()
            }
        
        # Save results to file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        family_name = family.lower() if family else 'unknown'
        results_file = os.path.join(self.output_dir, f"memory_analysis_{family_name}_{timestamp}.json")
        
        import json
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Memory analysis results saved to {results_file}")
        
        # Store in our results tracking
        file_key = os.path.basename(memory_dump)
        self.extracted_keys[file_key] = results
        self.analysis_reports[file_key] = results_file
        
        return results
    
    def detect_family(self, memory_dump: str) -> Optional[str]:
        """
        Detect ransomware family from memory dump.
        
        Args:
            memory_dump: Path to memory dump file
            
        Returns:
            Detected family name or None if unknown
        """
        try:
            # Use the detector from RansomwareKeyExtractor
            return self.generic_extractor._detect_family_from_memory(memory_dump)
        except Exception as e:
            logger.error(f"Error detecting family: {e}")
            return None
    
    def extract_key_data(self, memory_analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract usable key data from memory analysis results.
        
        Args:
            memory_analysis_results: Results from memory analysis
            
        Returns:
            Dictionary with key data for decryption tools
        """
        key_data = {
            'family': memory_analysis_results.get('family', 'Unknown'),
            'keys': []
        }
        
        # Process keys
        for key_info in memory_analysis_results.get('keys', []):
            # Extract key hex data
            key_hex = key_info.get('key_hex', '')
            
            # Only include high-confidence keys
            confidence = key_info.get('confidence', 0.0)
            if confidence >= 0.7 and key_hex:
                key_entry = {
                    'key_type': key_info.get('key_type', 'unknown'),
                    'key_hex': key_hex,
                    'confidence': confidence
                }
                
                # Add additional context if available
                if 'context' in key_info:
                    key_entry['context'] = key_info.get('context')
                
                key_data['keys'].append(key_entry)
        
        # Add IVs if available (LockBit specific)
        if 'ivs' in memory_analysis_results:
            key_data['ivs'] = memory_analysis_results['ivs']
        
        # Add version if available
        if 'version' in memory_analysis_results:
            key_data['version'] = memory_analysis_results['version']
        
        return key_data
    
    def get_decryption_keys(self, memory_dump: str = None, 
                           family: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get decryption keys from memory dump in a format suitable for decryption tools.
        
        Args:
            memory_dump: Optional path to memory dump file
            family: Optional ransomware family name
            
        Returns:
            List of extraction key dictionaries for decryption
        """
        # If memory dump specified, analyze it first
        if memory_dump:
            results = self.analyze_memory_dump(memory_dump, family)
        else:
            # Otherwise, use all previously analyzed dumps
            if not self.extracted_keys:
                logger.warning("No memory analysis results available")
                return []
            
            # Merge results from all dumps
            results = {
                'family': next(iter(self.extracted_keys.values())).get('family', 'Unknown'),
                'keys': []
            }
            
            for dump_results in self.extracted_keys.values():
                results['keys'].extend(dump_results.get('keys', []))
                
                # Add IVs if available
                if 'ivs' in dump_results and 'ivs' not in results:
                    results['ivs'] = dump_results['ivs']
                elif 'ivs' in dump_results and 'ivs' in results:
                    results['ivs'].extend(dump_results['ivs'])
                
                # Add version if available
                if 'version' in dump_results and 'version' not in results:
                    results['version'] = dump_results['version']
        
        # Extract usable key data
        key_data = self.extract_key_data(results)
        
        # Return as list of keys
        return key_data['keys']
    
    def get_summary_report(self) -> Dict[str, Any]:
        """
        Get a summary report of all memory analysis results.
        
        Returns:
            Dictionary with summary information
        """
        if not self.extracted_keys:
            return {"status": "No memory analysis performed"}
        
        # Count extracted keys
        total_keys = 0
        high_confidence_keys = 0
        family_counts = {}
        
        for dump_file, results in self.extracted_keys.items():
            family = results.get('family', 'Unknown')
            keys = results.get('keys', [])
            
            # Update family count
            if family not in family_counts:
                family_counts[family] = 0
            family_counts[family] += len(keys)
            
            # Update key counts
            total_keys += len(keys)
            high_confidence_keys += sum(1 for k in keys if k.get('confidence', 0) >= 0.7)
        
        # Create summary
        summary = {
            "memory_dumps_analyzed": len(self.memory_dumps),
            "total_keys_found": total_keys,
            "high_confidence_keys": high_confidence_keys,
            "family_breakdown": family_counts,
            "report_files": list(self.analysis_reports.values())
        }
        
        return summary


class WorkflowMemoryAnalysisAdapter:
    """
    Adapter class to integrate memory analysis into the automated ransomware workflow.
    This class bridges the memory analysis capabilities with the main workflow engine.
    """
    
    def __init__(self, workflow_output_dir: str):
        """
        Initialize the adapter.
        
        Args:
            workflow_output_dir: Output directory from the main workflow
        """
        self.workflow_dir = workflow_output_dir
        self.memory_dir = os.path.join(workflow_output_dir, 'memory_analysis')
        os.makedirs(self.memory_dir, exist_ok=True)
        
        # Initialize memory analysis integrator
        self.memory_analyzer = MemoryAnalysisIntegrator(self.memory_dir)
        logger.info(f"Memory Analysis Adapter initialized with directory: {self.memory_dir}")
    
    def analyze_samples(self, ransomware_samples: List[str], 
                       memory_dumps: List[str] = None, 
                       family: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze ransomware samples along with memory dumps.
        
        Args:
            ransomware_samples: List of ransomware sample files
            memory_dumps: Optional list of memory dump files
            family: Optional ransomware family name
            
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Starting memory analysis for {len(ransomware_samples)} samples")
        
        results = {
            "analyzed_samples": len(ransomware_samples),
            "memory_dumps": memory_dumps or [],
            "extracted_keys": [],
            "status": "success"
        }
        
        # Analyze memory dumps if provided
        if memory_dumps:
            for dump_file in memory_dumps:
                try:
                    dump_results = self.memory_analyzer.analyze_memory_dump(dump_file, family)
                    key_data = self.memory_analyzer.extract_key_data(dump_results)
                    results["extracted_keys"].extend(key_data.get('keys', []))
                except Exception as e:
                    logger.error(f"Error analyzing memory dump {dump_file}: {e}")
        
        # Extract decryption keys from memory
        decryption_keys = self.memory_analyzer.get_decryption_keys()
        if decryption_keys:
            logger.info(f"Found {len(decryption_keys)} potential decryption keys")
            results["decryption_keys"] = decryption_keys
        
        # Generate a summary report file
        summary = self.memory_analyzer.get_summary_report()
        results["summary"] = summary
        
        # Save combined results to a file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(self.memory_dir, f"memory_analysis_report_{timestamp}.json")
        
        import json
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Memory analysis report saved to {report_file}")
        results["report_file"] = report_file
        
        return results
    
    def integrate_keys_with_workflow(self, workflow_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Integrate extracted keys with main workflow state.
        
        Args:
            workflow_state: Current state of the workflow
            
        Returns:
            Updated workflow state with memory analysis data
        """
        # Get decryption keys from memory analysis
        decryption_keys = self.memory_analyzer.get_decryption_keys()
        
        if not decryption_keys:
            logger.info("No decryption keys from memory analysis to integrate")
            return workflow_state
        
        logger.info(f"Integrating {len(decryption_keys)} keys with workflow")
        
        # Add memory analysis information to workflow state
        if "memory_analysis" not in workflow_state:
            workflow_state["memory_analysis"] = {
                "status": "completed",
                "keys_extracted": len(decryption_keys),
                "timestamp": datetime.datetime.now().isoformat()
            }
        
        # Add decryption keys to workflow state
        if "decryption_keys" not in workflow_state:
            workflow_state["decryption_keys"] = []
        
        workflow_state["decryption_keys"].extend(decryption_keys)
        
        return workflow_state
    
    def memory_dump_from_process(self, process_id: int) -> Optional[str]:
        """
        Create a memory dump from a running process.
        
        Args:
            process_id: Process ID to dump
            
        Returns:
            Path to memory dump or None if failed
        """
        try:
            dump_path = self.memory_analyzer.acquire_memory_dump(process_id=process_id)
            logger.info(f"Created memory dump from process {process_id}: {dump_path}")
            return dump_path
        except Exception as e:
            logger.error(f"Failed to create memory dump from process {process_id}: {e}")
            return None


# Direct execution
def main():
    """Command-line interface for memory analysis integration."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Memory Analysis Integration Module")
    parser.add_argument("--dump", "-d", help="Memory dump file to analyze")
    parser.add_argument("--process", "-p", type=int, help="Process ID to dump and analyze")
    parser.add_argument("--family", "-f", help="Ransomware family name")
    parser.add_argument("--output", "-o", help="Output directory")
    args = parser.parse_args()
    
    # Initialize integrator
    integrator = MemoryAnalysisIntegrator(args.output)
    
    # Process arguments
    if args.process:
        # Dump and analyze process memory
        dump_file = integrator.acquire_memory_dump(process_id=args.process)
        results = integrator.analyze_memory_dump(dump_file, args.family)
        
        # Print summary
        print(f"\nAnalysis Results:")
        print(f"  Family: {results.get('family', 'Unknown')}")
        print(f"  Keys found: {len(results.get('keys', []))}")
        if 'ivs' in results:
            print(f"  IVs found: {len(results.get('ivs', []))}")
        
        # Print high confidence keys
        high_conf_keys = [k for k in results.get('keys', []) if k.get('confidence', 0) >= 0.7]
        if high_conf_keys:
            print(f"\nHigh Confidence Keys ({len(high_conf_keys)}):")
            for i, key in enumerate(high_conf_keys[:3]):  # Show up to 3 keys
                print(f"  {i+1}. Type: {key.get('key_type', 'unknown')}")
                print(f"     Confidence: {key.get('confidence', 0):.2f}")
                key_hex = key.get('key_hex', '')
                if len(key_hex) > 32:
                    key_display = f"{key_hex[:16]}...{key_hex[-16:]}"
                else:
                    key_display = key_hex
                print(f"     Key: {key_display}")
            
            if len(high_conf_keys) > 3:
                print(f"     ... and {len(high_conf_keys) - 3} more keys")
    
    elif args.dump:
        # Analyze existing memory dump
        results = integrator.analyze_memory_dump(args.dump, args.family)
        
        # Print summary
        print(f"\nAnalysis Results:")
        print(f"  Family: {results.get('family', 'Unknown')}")
        print(f"  Keys found: {len(results.get('keys', []))}")
        if 'ivs' in results:
            print(f"  IVs found: {len(results.get('ivs', []))}")
        
        # Print high confidence keys
        high_conf_keys = [k for k in results.get('keys', []) if k.get('confidence', 0) >= 0.7]
        if high_conf_keys:
            print(f"\nHigh Confidence Keys ({len(high_conf_keys)}):")
            for i, key in enumerate(high_conf_keys[:3]):  # Show up to 3 keys
                print(f"  {i+1}. Type: {key.get('key_type', 'unknown')}")
                print(f"     Confidence: {key.get('confidence', 0):.2f}")
                key_hex = key.get('key_hex', '')
                if len(key_hex) > 32:
                    key_display = f"{key_hex[:16]}...{key_hex[-16:]}"
                else:
                    key_display = key_hex
                print(f"     Key: {key_display}")
            
            if len(high_conf_keys) > 3:
                print(f"     ... and {len(high_conf_keys) - 3} more keys")
    
    else:
        parser.print_help()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())