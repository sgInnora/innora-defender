#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Memory Analysis Engine for Ransomware

This script provides a unified interface for analyzing memory dumps and
processes for ransomware artifacts. It coordinates multiple scanners and
integrates results with threat intelligence.
"""

import os
import sys
import logging
import json
import argparse
import tempfile
import shutil
from datetime import datetime
from typing import Dict, Any, List, Optional, Union
import importlib.util

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('MemoryAnalysisEngine')

# Define scanners directory
SCANNERS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scanners')

def import_module_from_path(module_name: str, module_path: str) -> Optional[object]:
    """
    Import a module from a file path.
    
    Args:
        module_name: Name to assign to the module
        module_path: Path to the module file
        
    Returns:
        Imported module or None if import failed
    """
    try:
        if not os.path.exists(module_path):
            logger.error(f"Module not found: {module_path}")
            return None
            
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        logger.error(f"Error importing module {module_name} from {module_path}: {e}")
        return None

def validate_files() -> bool:
    """
    Validate that all required scanner files exist.
    
    Returns:
        True if all required files exist, False otherwise
    """
    required_files = [
        os.path.join(SCANNERS_DIR, 'memory_scanner_orchestrator.py'),
        os.path.join(SCANNERS_DIR, 'memory_threat_intel_integrator.py')
    ]
    
    optional_files = [
        os.path.join(SCANNERS_DIR, 'yara_mem_scanner.py'),
        os.path.join(SCANNERS_DIR, 'pattern_key_scanner.py'),
        os.path.join(SCANNERS_DIR, 'crypto_pattern_matcher.py')
    ]
    
    # Check required files
    missing_required = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_required.append(file_path)
    
    if missing_required:
        logger.error(f"Missing required files: {', '.join(missing_required)}")
        return False
    
    # Check optional files
    missing_optional = []
    for file_path in optional_files:
        if not os.path.exists(file_path):
            missing_optional.append(file_path)
    
    if missing_optional:
        logger.warning(f"Missing optional scanner modules: {', '.join(missing_optional)}")
        logger.warning("Some scanning capabilities may be limited")
    
    return True

def validate_dependencies() -> bool:
    """
    Validate that all required dependencies are installed.
    
    Returns:
        True if all dependencies are available, False otherwise
    """
    required_modules = [
        'json', 'datetime', 'tempfile', 'shutil', 'importlib'
    ]
    
    optional_modules = [
        'yara'  # For YARA scanning
    ]
    
    # Check required modules
    missing_required = []
    for module_name in required_modules:
        try:
            __import__(module_name)
        except ImportError:
            missing_required.append(module_name)
    
    if missing_required:
        logger.error(f"Missing required modules: {', '.join(missing_required)}")
        return False
    
    # Check optional modules
    missing_optional = []
    for module_name in optional_modules:
        try:
            __import__(module_name)
        except ImportError:
            missing_optional.append(module_name)
    
    if missing_optional:
        logger.warning(f"Missing optional modules: {', '.join(missing_optional)}")
        logger.warning("Some scanning capabilities may be limited")
    
    return True

def analyze_memory_dump(dump_file: str, output_dir: str, 
                       options: Dict[str, Any]) -> Optional[str]:
    """
    Analyze a memory dump file using all available scanners.
    
    Args:
        dump_file: Path to the memory dump file
        output_dir: Directory to save results
        options: Analysis options
        
    Returns:
        Path to the final results file, or None if analysis failed
    """
    if not os.path.exists(dump_file):
        logger.error(f"Memory dump file not found: {dump_file}")
        return None
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate output filenames
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_results_file = os.path.join(output_dir, f"mem_scan_{timestamp}.json")
    ti_results_file = os.path.join(output_dir, f"mem_analysis_{timestamp}.json")
    
    # Step 1: Import the scanner orchestrator
    orchestrator_path = os.path.join(SCANNERS_DIR, 'memory_scanner_orchestrator.py')
    orchestrator_module = import_module_from_path('memory_scanner_orchestrator', orchestrator_path)
    
    if not orchestrator_module:
        logger.error("Failed to import scanner orchestrator")
        return None
    
    # Create orchestrator instance
    try:
        orchestrator = orchestrator_module.MemoryScannerOrchestrator()
    except Exception as e:
        logger.error(f"Error creating scanner orchestrator: {e}")
        return None
    
    # Step 2: Scan the memory dump
    logger.info(f"Starting memory dump scan: {dump_file}")
    
    try:
        # Set scanner weights if specified
        if options.get('scanner_weights'):
            for scanner_id, weight in options['scanner_weights'].items():
                orchestrator.set_scanner_weight(scanner_id, weight)
        
        # Perform scan
        scan_results = orchestrator.scan_file(dump_file)
        
        # Save scan results
        with open(scan_results_file, 'w') as f:
            json.dump(scan_results, f, indent=2)
            
        logger.info(f"Memory scan completed and results saved to {scan_results_file}")
        
        # Generate YARA rules if requested
        if options.get('generate_yara'):
            yara_dir = os.path.join(output_dir, 'yara_rules')
            os.makedirs(yara_dir, exist_ok=True)
            
            yara_file = orchestrator.export_yara_rules(yara_dir)
            if yara_file:
                logger.info(f"Generated YARA rules saved to: {yara_file}")
        
        # Check for specific family if requested
        if options.get('check_family'):
            family_result = orchestrator.check_ransomware_family(options['check_family'])
            logger.info(f"\nChecking for {options['check_family']} ransomware:")
            logger.info(f"  {family_result.get('message')}")
            logger.info(f"  Findings: {family_result.get('findings_count', 0)}")
        
        # Extract keys if requested
        if options.get('extract_keys'):
            keys = orchestrator.extract_potential_keys()
            if keys:
                keys_file = os.path.join(output_dir, f"potential_keys_{timestamp}.json")
                with open(keys_file, 'w') as f:
                    json.dump(keys, f, indent=2)
                logger.info(f"Extracted {len(keys)} potential encryption keys to {keys_file}")
    
    except Exception as e:
        logger.error(f"Error during memory scan: {e}")
        return scan_results_file  # Return partial results if available
    
    # Step 3: Perform threat intelligence integration
    if options.get('threat_intel', True):
        # Import the threat intelligence integrator
        ti_integrator_path = os.path.join(SCANNERS_DIR, 'memory_threat_intel_integrator.py')
        ti_integrator_module = import_module_from_path('memory_threat_intel_integrator', ti_integrator_path)
        
        if not ti_integrator_module:
            logger.error("Failed to import threat intelligence integrator")
            return scan_results_file
        
        try:
            # Create integrator instance
            ti_integrator = ti_integrator_module.MemoryThreatIntelIntegrator()
            
            # Load scan results
            if not ti_integrator.load_memory_scan_results(scan_results_file):
                logger.error("Failed to load scan results for threat intelligence integration")
                return scan_results_file
            
            # Perform integration
            logger.info("Enriching results with threat intelligence...")
            enriched_results = ti_integrator.enrich_with_threat_intelligence()
            
            # Perform additional analysis as requested
            if options.get('mitre_mapping', True):
                logger.info("Generating MITRE ATT&CK mapping...")
                mitre_mapping = ti_integrator.generate_mitre_mapping()
                enriched_results["mitre_attack_mapping"] = mitre_mapping
            
            if options.get('family_analysis', True):
                logger.info("Performing detailed family analysis...")
                family_analysis = ti_integrator.analyze_families()
                enriched_results["family_analysis"] = family_analysis
            
            if options.get('recovery_recommendations', True):
                logger.info("Generating recovery recommendations...")
                recovery_recommendations = ti_integrator.generate_recovery_recommendations()
                enriched_results["recovery_recommendations"] = recovery_recommendations
            
            # Save enriched results
            ti_integrator.enriched_results = enriched_results
            ti_integrator.save_results(ti_results_file)
            
            logger.info(f"Enriched analysis results saved to {ti_results_file}")
            
            # Return path to final results
            return ti_results_file
            
        except Exception as e:
            logger.error(f"Error during threat intelligence integration: {e}")
            return scan_results_file
    
    # Return path to scan results if TI integration was not performed
    return scan_results_file

def analyze_process(pid: int, output_dir: str, options: Dict[str, Any]) -> Optional[str]:
    """
    Analyze a running process for ransomware indicators.
    
    Args:
        pid: Process ID to analyze
        output_dir: Directory to save results
        options: Analysis options
        
    Returns:
        Path to the results file, or None if analysis failed
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate output filenames
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_results_file = os.path.join(output_dir, f"process_{pid}_scan_{timestamp}.json")
    ti_results_file = os.path.join(output_dir, f"process_{pid}_analysis_{timestamp}.json")
    
    # Step 1: Import the scanner orchestrator
    orchestrator_path = os.path.join(SCANNERS_DIR, 'memory_scanner_orchestrator.py')
    orchestrator_module = import_module_from_path('memory_scanner_orchestrator', orchestrator_path)
    
    if not orchestrator_module:
        logger.error("Failed to import scanner orchestrator")
        return None
    
    # Create orchestrator instance
    try:
        orchestrator = orchestrator_module.MemoryScannerOrchestrator()
    except Exception as e:
        logger.error(f"Error creating scanner orchestrator: {e}")
        return None
    
    # Step 2: Scan the process
    logger.info(f"Starting process scan: PID {pid}")
    
    try:
        # Set scanner weights if specified
        if options.get('scanner_weights'):
            for scanner_id, weight in options['scanner_weights'].items():
                orchestrator.set_scanner_weight(scanner_id, weight)
        
        # Perform scan
        scan_results = orchestrator.scan_process(pid)
        
        # Save scan results
        with open(scan_results_file, 'w') as f:
            json.dump(scan_results, f, indent=2)
            
        logger.info(f"Process scan completed and results saved to {scan_results_file}")
        
        # Generate YARA rules if requested
        if options.get('generate_yara'):
            yara_dir = os.path.join(output_dir, 'yara_rules')
            os.makedirs(yara_dir, exist_ok=True)
            
            yara_file = orchestrator.export_yara_rules(yara_dir)
            if yara_file:
                logger.info(f"Generated YARA rules saved to: {yara_file}")
        
        # Check for specific family if requested
        if options.get('check_family'):
            family_result = orchestrator.check_ransomware_family(options['check_family'])
            logger.info(f"\nChecking for {options['check_family']} ransomware:")
            logger.info(f"  {family_result.get('message')}")
            logger.info(f"  Findings: {family_result.get('findings_count', 0)}")
        
        # Extract keys if requested
        if options.get('extract_keys'):
            keys = orchestrator.extract_potential_keys()
            if keys:
                keys_file = os.path.join(output_dir, f"process_{pid}_keys_{timestamp}.json")
                with open(keys_file, 'w') as f:
                    json.dump(keys, f, indent=2)
                logger.info(f"Extracted {len(keys)} potential encryption keys to {keys_file}")
    
    except Exception as e:
        logger.error(f"Error during process scan: {e}")
        return scan_results_file  # Return partial results if available
    
    # Step 3: Perform threat intelligence integration
    if options.get('threat_intel', True):
        # Import the threat intelligence integrator
        ti_integrator_path = os.path.join(SCANNERS_DIR, 'memory_threat_intel_integrator.py')
        ti_integrator_module = import_module_from_path('memory_threat_intel_integrator', ti_integrator_path)
        
        if not ti_integrator_module:
            logger.error("Failed to import threat intelligence integrator")
            return scan_results_file
        
        try:
            # Create integrator instance
            ti_integrator = ti_integrator_module.MemoryThreatIntelIntegrator()
            
            # Load scan results
            if not ti_integrator.load_memory_scan_results(scan_results_file):
                logger.error("Failed to load scan results for threat intelligence integration")
                return scan_results_file
            
            # Perform integration
            logger.info("Enriching results with threat intelligence...")
            enriched_results = ti_integrator.enrich_with_threat_intelligence()
            
            # Perform additional analysis as requested
            if options.get('mitre_mapping', True):
                logger.info("Generating MITRE ATT&CK mapping...")
                mitre_mapping = ti_integrator.generate_mitre_mapping()
                enriched_results["mitre_attack_mapping"] = mitre_mapping
            
            if options.get('family_analysis', True):
                logger.info("Performing detailed family analysis...")
                family_analysis = ti_integrator.analyze_families()
                enriched_results["family_analysis"] = family_analysis
            
            if options.get('recovery_recommendations', True):
                logger.info("Generating recovery recommendations...")
                recovery_recommendations = ti_integrator.generate_recovery_recommendations()
                enriched_results["recovery_recommendations"] = recovery_recommendations
            
            # Save enriched results
            ti_integrator.enriched_results = enriched_results
            ti_integrator.save_results(ti_results_file)
            
            logger.info(f"Enriched analysis results saved to {ti_results_file}")
            
            # Return path to final results
            return ti_results_file
            
        except Exception as e:
            logger.error(f"Error during threat intelligence integration: {e}")
            return scan_results_file
    
    # Return path to scan results if TI integration was not performed
    return scan_results_file

def dump_process_memory(pid: int, output_dir: str) -> Optional[str]:
    """
    Dump the memory of a process for analysis.
    
    Args:
        pid: Process ID to dump
        output_dir: Directory to save the dump
        
    Returns:
        Path to the memory dump file, or None if dumping failed
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate output filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dump_file = os.path.join(output_dir, f"process_{pid}_dump_{timestamp}.dmp")
    
    # Platform-specific implementation
    if sys.platform == 'win32':
        return _dump_process_memory_windows(pid, dump_file)
    elif sys.platform == 'linux':
        return _dump_process_memory_linux(pid, dump_file)
    elif sys.platform == 'darwin':
        return _dump_process_memory_macos(pid, dump_file)
    else:
        logger.error(f"Unsupported platform: {sys.platform}")
        return None

def _dump_process_memory_windows(pid: int, dump_file: str) -> Optional[str]:
    """
    Dump the memory of a Windows process.
    
    Args:
        pid: Process ID to dump
        dump_file: Path to save the dump
        
    Returns:
        Path to the memory dump file, or None if dumping failed
    """
    try:
        # Try to use procdump.exe if available
        procdump_path = shutil.which('procdump.exe')
        if procdump_path:
            import subprocess
            
            logger.info(f"Using ProcDump to dump process {pid}")
            command = [procdump_path, '-ma', str(pid), dump_file]
            
            result = subprocess.run(command, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"ProcDump failed: {result.stderr}")
                return None
                
            logger.info(f"Process memory dumped to {dump_file}")
            return dump_file
        
        # Fallback to using Windows API directly
        try:
            import win32process
            import win32con
            import ctypes
            from ctypes import wintypes
            
            logger.info(f"Dumping process {pid} using Windows API")
            
            # Get process handle
            hProcess = win32process.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                False, pid
            )
            
            # MiniDumpWriteDump function
            MiniDumpWriteDump = ctypes.windll.dbghelp.MiniDumpWriteDump
            MiniDumpWithFullMemory = 2  # Full memory dump option
            
            # Create file handle
            hFile = ctypes.windll.kernel32.CreateFileW(
                dump_file, 
                win32con.GENERIC_WRITE, 
                0, 
                None, 
                win32con.CREATE_ALWAYS, 
                win32con.FILE_ATTRIBUTE_NORMAL, 
                None
            )
            
            if hFile == win32con.INVALID_HANDLE_VALUE:
                logger.error("Failed to create dump file")
                hProcess.Close()
                return None
            
            # Write dump
            success = MiniDumpWriteDump(
                hProcess.handle,
                pid,
                hFile,
                MiniDumpWithFullMemory,
                None,
                None,
                None
            )
            
            # Close handles
            ctypes.windll.kernel32.CloseHandle(hFile)
            hProcess.Close()
            
            if not success:
                logger.error("MiniDumpWriteDump failed")
                os.remove(dump_file)  # Clean up partial file
                return None
                
            logger.info(f"Process memory dumped to {dump_file}")
            return dump_file
            
        except ImportError:
            logger.error("Windows-specific modules not available")
            return None
        
    except Exception as e:
        logger.error(f"Error dumping Windows process memory: {e}")
        return None

def _dump_process_memory_linux(pid: int, dump_file: str) -> Optional[str]:
    """
    Dump the memory of a Linux process.
    
    Args:
        pid: Process ID to dump
        dump_file: Path to save the dump
        
    Returns:
        Path to the memory dump file, or None if dumping failed
    """
    try:
        import subprocess
        
        # Check if process exists
        proc_dir = f"/proc/{pid}"
        if not os.path.exists(proc_dir):
            logger.error(f"Process {pid} not found")
            return None
        
        # Try different dumping methods
        
        # Method 1: Use GDB if available
        gdb_path = shutil.which('gdb')
        if gdb_path:
            logger.info(f"Using GDB to dump process {pid}")
            
            # Create GDB command file
            gdb_cmd_file = f"{dump_file}.gdb_cmd"
            with open(gdb_cmd_file, 'w') as f:
                f.write(f"attach {pid}\n")
                f.write(f"generate-core-file {dump_file}\n")
                f.write("detach\n")
                f.write("quit\n")
            
            # Run GDB
            command = [gdb_path, '-batch', '-x', gdb_cmd_file]
            result = subprocess.run(command, capture_output=True, text=True)
            
            # Clean up command file
            os.remove(gdb_cmd_file)
            
            if os.path.exists(dump_file) and os.path.getsize(dump_file) > 0:
                logger.info(f"Process memory dumped to {dump_file}")
                return dump_file
            else:
                logger.warning("GDB dump failed or produced empty file")
        
        # Method 2: Use process_vm_readv to manually dump memory
        logger.info(f"Using manual memory mapping to dump process {pid}")
        
        # Read process maps
        maps_file = f"/proc/{pid}/maps"
        mem_file = f"/proc/{pid}/mem"
        
        if not os.path.exists(maps_file) or not os.path.exists(mem_file):
            logger.error(f"Cannot access memory maps for process {pid}")
            return None
        
        # Parse memory regions from maps file
        with open(maps_file, 'r') as f:
            memory_regions = []
            for line in f:
                parts = line.split()
                if len(parts) < 6:
                    continue
                
                # Parse address range
                addr_range = parts[0].split('-')
                start = int(addr_range[0], 16)
                end = int(addr_range[1], 16)
                
                # Check permissions ('r' means readable)
                perms = parts[1]
                if 'r' in perms:
                    memory_regions.append((start, end - start))
        
        # Dump readable regions to file
        with open(mem_file, 'rb') as mem, open(dump_file, 'wb') as out:
            for start, size in memory_regions:
                try:
                    mem.seek(start)
                    data = mem.read(size)
                    out.write(data)
                except Exception as e:
                    logger.debug(f"Error reading region at {start:#x}: {e}")
                    # Continue with other regions
        
        # Check if we were able to dump anything
        if os.path.exists(dump_file) and os.path.getsize(dump_file) > 0:
            logger.info(f"Process memory dumped to {dump_file}")
            return dump_file
        else:
            logger.error("Failed to dump process memory")
            if os.path.exists(dump_file):
                os.remove(dump_file)
            return None
        
    except Exception as e:
        logger.error(f"Error dumping Linux process memory: {e}")
        return None

def _dump_process_memory_macos(pid: int, dump_file: str) -> Optional[str]:
    """
    Dump the memory of a macOS process.
    
    Args:
        pid: Process ID to dump
        dump_file: Path to save the dump
        
    Returns:
        Path to the memory dump file, or None if dumping failed
    """
    try:
        import subprocess
        
        # Method 1: Try using lldb
        lldb_path = shutil.which('lldb')
        if lldb_path:
            logger.info(f"Using LLDB to dump process {pid}")
            
            # Create LLDB command file
            lldb_cmd_file = f"{dump_file}.lldb_cmd"
            with open(lldb_cmd_file, 'w') as f:
                f.write(f"process attach -p {pid}\n")
                f.write(f"process save-core \"{dump_file}\"\n")
                f.write("process detach\n")
                f.write("quit\n")
            
            # Run LLDB
            command = [lldb_path, '-s', lldb_cmd_file]
            result = subprocess.run(command, capture_output=True, text=True)
            
            # Clean up command file
            os.remove(lldb_cmd_file)
            
            if os.path.exists(dump_file) and os.path.getsize(dump_file) > 0:
                logger.info(f"Process memory dumped to {dump_file}")
                return dump_file
            else:
                logger.warning("LLDB dump failed or produced empty file")
        
        # Method 2: Try using vmmap and directly reading process memory
        logger.warning("Direct process memory dumping on macOS is complex and may require additional tools")
        logger.warning("Consider using a dedicated tool like OSXPmem or mac-memory-reader")
        
        return None
        
    except Exception as e:
        logger.error(f"Error dumping macOS process memory: {e}")
        return None

def generate_report(results_file: str, output_file: str = None) -> Optional[str]:
    """
    Generate a human-readable report from analysis results.
    
    Args:
        results_file: Path to the analysis results JSON file
        output_file: Path to save the report (optional)
        
    Returns:
        Path to the report file, or None if generation failed
    """
    if not os.path.exists(results_file):
        logger.error(f"Results file not found: {results_file}")
        return None
    
    try:
        with open(results_file, 'r') as f:
            results = json.load(f)
        
        # Generate default output filename if not provided
        if not output_file:
            output_dir = os.path.dirname(results_file)
            base_name = os.path.basename(results_file).replace('.json', '')
            output_file = os.path.join(output_dir, f"{base_name}_report.txt")
        
        # Generate report content
        report = []
        
        # Add report header
        report.append("=" * 80)
        report.append("MEMORY ANALYSIS REPORT FOR RANSOMWARE DETECTION")
        report.append("=" * 80)
        
        # Add timestamp
        scan_time = results.get('scan_time', datetime.now().isoformat())
        report.append(f"Report generated: {scan_time}")
        report.append("")
        
        # Add summary section
        report.append("-" * 80)
        report.append("ANALYSIS SUMMARY")
        report.append("-" * 80)
        
        summary = results.get('summary', {})
        total_findings = summary.get('total_findings', 0)
        report.append(f"Total findings: {total_findings}")
        
        # Add findings by type
        findings_by_type = summary.get('findings_by_type', {})
        if findings_by_type:
            report.append("\nFindings by type:")
            for finding_type, count in findings_by_type.items():
                report.append(f"  {finding_type}: {count}")
        
        # Add findings by family
        findings_by_family = summary.get('findings_by_family', {})
        if findings_by_family:
            report.append("\nDetected ransomware families:")
            for family, count in sorted(findings_by_family.items(), key=lambda x: x[1], reverse=True):
                report.append(f"  {family}: {count} matches")
        
        # Add detection verdict if available
        detection_summary = results.get('detection_summary', {})
        if detection_summary:
            report.append("\nDetection verdict:")
            report.append(f"  {detection_summary.get('message', 'No verdict available')}")
        
        # Add threat intelligence section if available
        ti_data = results.get('threat_intelligence', {})
        if ti_data:
            report.append("\n" + "-" * 80)
            report.append("THREAT INTELLIGENCE")
            report.append("-" * 80)
            
            # Add family details
            family_details = ti_data.get('family_details', {})
            if family_details:
                report.append("\nRansomware family details:")
                for family, details in family_details.items():
                    report.append(f"  {family}:")
                    
                    if 'aliases' in details:
                        aliases = ', '.join(details['aliases'])
                        report.append(f"    Aliases: {aliases}")
                        
                    if 'first_seen' in details:
                        report.append(f"    First seen: {details['first_seen']}")
                        
                    if 'encryption' in details:
                        encryption = details['encryption']
                        algorithms = encryption.get('algorithms', [])
                        if algorithms:
                            report.append(f"    Encryption algorithms: {', '.join(algorithms)}")
                            
                    if 'file_extensions' in details:
                        extensions = ', '.join(details['file_extensions'])
                        report.append(f"    File extensions: {extensions}")
                        
                    if 'decryptors_available' in details:
                        decryptors = "Yes" if details['decryptors_available'] else "No"
                        report.append(f"    Decryptors available: {decryptors}")
                        
                        if details.get('decryptor_links'):
                            for link in details['decryptor_links']:
                                report.append(f"      Decryptor: {link}")
            
            # Add key assessment
            key_assessment = ti_data.get('key_assessment', {})
            if key_assessment:
                report.append("\nEncryption key assessment:")
                
                keys_found = key_assessment.get('keys_found', False)
                key_count = key_assessment.get('key_count', 0)
                
                if keys_found:
                    report.append(f"  Found {key_count} potential encryption keys")
                    
                    algorithms = key_assessment.get('algorithms_found', [])
                    if algorithms:
                        report.append(f"  Algorithms: {', '.join(algorithms)}")
                        
                    decryption_potential = key_assessment.get('decryption_potential', 'none')
                    report.append(f"  Decryption potential: {decryption_potential}")
                    
                    # Add per-algorithm details
                    keys_by_algorithm = key_assessment.get('keys_by_algorithm', {})
                    for algorithm, algo_data in keys_by_algorithm.items():
                        report.append(f"\n  {algorithm} keys:")
                        report.append(f"    Count: {algo_data.get('count', 0)}")
                        report.append(f"    Confidence: {algo_data.get('max_confidence', 0):.2f}")
                        
                        # Add recommendations
                        recommendations = algo_data.get('recommendations', [])
                        if recommendations:
                            report.append("    Recommendations:")
                            for rec in recommendations:
                                report.append(f"      - {rec}")
                else:
                    report.append("  No encryption keys identified in memory")
        
        # Add MITRE ATT&CK mapping if available
        mitre_mapping = results.get('mitre_attack_mapping', {})
        if mitre_mapping:
            report.append("\n" + "-" * 80)
            report.append("MITRE ATT&CK TECHNIQUES")
            report.append("-" * 80)
            
            techniques = mitre_mapping.get('techniques', [])
            if techniques:
                report.append("\nDetected techniques:")
                for technique in techniques:
                    technique_id = technique.get('technique_id', '')
                    technique_name = technique.get('technique_name', '')
                    tactic = technique.get('tactic', '')
                    count = technique.get('count', 0)
                    confidence = technique.get('confidence', 'low')
                    
                    report.append(f"  {technique_id} ({tactic}): {technique_name}")
                    report.append(f"    Matches: {count}, Confidence: {confidence}")
        
        # Add recovery recommendations if available
        recovery_recs = results.get('recovery_recommendations', {})
        if recovery_recs:
            report.append("\n" + "-" * 80)
            report.append("RECOVERY RECOMMENDATIONS")
            report.append("-" * 80)
            
            recommendations = recovery_recs.get('recommendations', [])
            if recommendations:
                report.append("\nRecommendations:")
                for i, rec in enumerate(recommendations, 1):
                    report.append(f"  {i}. {rec}")
        
        # Write report to file
        with open(output_file, 'w') as f:
            f.write('\n'.join(report))
            
        logger.info(f"Report generated and saved to {output_file}")
        return output_file
        
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return None

def main():
    """Command line interface for the Memory Analysis Engine."""
    parser = argparse.ArgumentParser(description="Memory Analysis Engine for Ransomware")
    
    # Define subcommands
    subparsers = parser.add_subparsers(dest='command', help='Analysis command')
    
    # Analyze memory dump command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a memory dump file')
    analyze_parser.add_argument("dump_file", help="Memory dump file to analyze")
    analyze_parser.add_argument("--output-dir", "-o", default="results", help="Directory to save results")
    analyze_parser.add_argument("--report", "-r", action="store_true", help="Generate human-readable report")
    analyze_parser.add_argument("--generate-yara", "-y", action="store_true", help="Generate YARA rules")
    analyze_parser.add_argument("--check-family", help="Check for a specific ransomware family")
    analyze_parser.add_argument("--extract-keys", "-k", action="store_true", help="Extract potential encryption keys")
    analyze_parser.add_argument("--no-threat-intel", action="store_true", help="Skip threat intelligence integration")
    analyze_parser.add_argument("--no-mitre", action="store_true", help="Skip MITRE ATT&CK mapping")
    analyze_parser.add_argument("--no-family-analysis", action="store_true", help="Skip detailed family analysis")
    analyze_parser.add_argument("--no-recovery", action="store_true", help="Skip recovery recommendations")
    analyze_parser.add_argument("--scanner-weights", help="Comma-separated list of scanner:weight pairs (e.g., 'yara:1.0,pattern:0.8')")
    
    # Process analysis command
    process_parser = subparsers.add_parser('process', help='Analyze a running process')
    process_parser.add_argument("pid", type=int, help="Process ID to analyze")
    process_parser.add_argument("--output-dir", "-o", default="results", help="Directory to save results")
    process_parser.add_argument("--report", "-r", action="store_true", help="Generate human-readable report")
    process_parser.add_argument("--dump", "-d", action="store_true", help="Dump process memory before analysis")
    process_parser.add_argument("--generate-yara", "-y", action="store_true", help="Generate YARA rules")
    process_parser.add_argument("--check-family", help="Check for a specific ransomware family")
    process_parser.add_argument("--extract-keys", "-k", action="store_true", help="Extract potential encryption keys")
    process_parser.add_argument("--no-threat-intel", action="store_true", help="Skip threat intelligence integration")
    process_parser.add_argument("--no-mitre", action="store_true", help="Skip MITRE ATT&CK mapping")
    process_parser.add_argument("--no-family-analysis", action="store_true", help="Skip detailed family analysis")
    process_parser.add_argument("--no-recovery", action="store_true", help="Skip recovery recommendations")
    process_parser.add_argument("--scanner-weights", help="Comma-separated list of scanner:weight pairs (e.g., 'yara:1.0,pattern:0.8')")
    
    # Report generation command
    report_parser = subparsers.add_parser('report', help='Generate a report from analysis results')
    report_parser.add_argument("results_file", help="Analysis results JSON file")
    report_parser.add_argument("--output", "-o", help="Output report file")
    
    # Help command
    help_parser = subparsers.add_parser('help', help='Display help information')
    
    # Version command
    version_parser = subparsers.add_parser('version', help='Display version information')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Validate files and dependencies
    if not validate_files() or not validate_dependencies():
        return 1
    
    # Process commands
    if args.command == 'analyze':
        # Parse scanner weights if provided
        scanner_weights = {}
        if args.scanner_weights:
            for pair in args.scanner_weights.split(','):
                if ':' in pair:
                    scanner, weight = pair.split(':')
                    try:
                        scanner_weights[scanner] = float(weight)
                    except ValueError:
                        logger.error(f"Invalid weight value: {weight}")
        
        # Set analysis options
        options = {
            'generate_yara': args.generate_yara,
            'check_family': args.check_family,
            'extract_keys': args.extract_keys,
            'threat_intel': not args.no_threat_intel,
            'mitre_mapping': not args.no_mitre,
            'family_analysis': not args.no_family_analysis,
            'recovery_recommendations': not args.no_recovery,
            'scanner_weights': scanner_weights
        }
        
        # Analyze memory dump
        results_file = analyze_memory_dump(args.dump_file, args.output_dir, options)
        
        if results_file:
            logger.info(f"Analysis completed. Results saved to {results_file}")
            
            # Generate report if requested
            if args.report:
                report_file = generate_report(results_file)
                if report_file:
                    logger.info(f"Report saved to {report_file}")
        else:
            logger.error("Analysis failed")
            return 1
            
    elif args.command == 'process':
        # Parse scanner weights if provided
        scanner_weights = {}
        if args.scanner_weights:
            for pair in args.scanner_weights.split(','):
                if ':' in pair:
                    scanner, weight = pair.split(':')
                    try:
                        scanner_weights[scanner] = float(weight)
                    except ValueError:
                        logger.error(f"Invalid weight value: {weight}")
        
        # Set analysis options
        options = {
            'generate_yara': args.generate_yara,
            'check_family': args.check_family,
            'extract_keys': args.extract_keys,
            'threat_intel': not args.no_threat_intel,
            'mitre_mapping': not args.no_mitre,
            'family_analysis': not args.no_family_analysis,
            'recovery_recommendations': not args.no_recovery,
            'scanner_weights': scanner_weights
        }
        
        # Dump process memory if requested
        if args.dump:
            dump_file = dump_process_memory(args.pid, args.output_dir)
            if dump_file:
                logger.info(f"Process memory dumped to {dump_file}")
                
                # Analyze dumped memory
                results_file = analyze_memory_dump(dump_file, args.output_dir, options)
            else:
                logger.error("Process memory dump failed")
                return 1
        else:
            # Directly analyze running process
            results_file = analyze_process(args.pid, args.output_dir, options)
        
        if results_file:
            logger.info(f"Analysis completed. Results saved to {results_file}")
            
            # Generate report if requested
            if args.report:
                report_file = generate_report(results_file)
                if report_file:
                    logger.info(f"Report saved to {report_file}")
        else:
            logger.error("Analysis failed")
            return 1
            
    elif args.command == 'report':
        # Generate report from results file
        report_file = generate_report(args.results_file, args.output)
        if report_file:
            logger.info(f"Report saved to {report_file}")
        else:
            logger.error("Report generation failed")
            return 1
            
    elif args.command == 'help':
        parser.print_help()
        
    elif args.command == 'version':
        print("Memory Analysis Engine for Ransomware v1.0.0")
        print("© 2025 Innora Research")
        
    else:
        parser.print_help()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())