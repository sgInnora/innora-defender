#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ransomware Recovery Tool

A comprehensive ransomware analysis and recovery tool that integrates:
1. Encryption analysis to identify ransomware families
2. Memory analysis to extract encryption keys
3. Enhanced external decryption tool integration (with multiple repository support)
4. File recovery capabilities
"""

import os
import sys
import json
import logging
import argparse
import tempfile
import datetime
from typing import Dict, List, Optional, Any, Tuple, Union, Set

# Ensure the external tools directory is in the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'external'))

# Import components
from external.encryption_analyzer import EncryptionAnalyzer
from enhanced_tool_integration import EnhancedToolIntegration

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('RansomwareRecovery')

class RansomwareRecovery:
    """
    Comprehensive tool for ransomware analysis and file recovery.
    """
    
    def __init__(self, work_dir: Optional[str] = None, 
                use_containers: bool = False, force_no_gui: bool = False):
        """
        Initialize the ransomware recovery tool.
        
        Args:
            work_dir: Working directory for temporary files
            use_containers: Whether to use containerized execution where available
            force_no_gui: Force non-GUI mode for tools that support it
        """
        self.work_dir = work_dir or tempfile.mkdtemp(prefix="ransomware_recovery_")
        
        # Ensure work directory exists
        os.makedirs(self.work_dir, exist_ok=True)
        
        # Initialize components
        self.analyzer = EncryptionAnalyzer()
        self.tools = EnhancedToolIntegration(
            work_dir=self.work_dir,
            use_containers=use_containers,
            force_no_gui=force_no_gui
        )
        
        logger.info(f"Initialized RansomwareRecovery in {self.work_dir}")
        
    def analyze_file(self, file_path: str, output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze an encrypted file to determine ransomware family and encryption details.
        
        Args:
            file_path: Path to the encrypted file
            output_file: Optional path to save analysis results
            
        Returns:
            Analysis results
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return {"error": "File not found"}
            
        logger.info(f"Analyzing file: {file_path}")
        
        # Analyze file
        results = self.analyzer.analyze_file(file_path)
        
        # Find available decryption tools for the detected family
        if "potential_family" in results and results["potential_family"]:
            family = results["potential_family"]
            available_tools = self.tools.find_tools_for_family(family)
            
            if available_tools:
                results["available_tools"] = [
                    {
                        "id": tool["id"],
                        "name": tool.get("name", "Unknown"),
                        "description": tool.get("description", ""),
                        "installed": tool.get("installed", False),
                        "url": tool.get("url", ""),
                        "source": tool.get("source", "unknown")
                    }
                    for tool in available_tools
                ]
            else:
                results["available_tools"] = []
                
            # Report on decryption possibilities
            self._assess_decryption_possibilities(results)
        
        # Save results if output file specified
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    json.dump(results, f, indent=2)
                logger.info(f"Analysis results saved to {output_file}")
            except Exception as e:
                logger.error(f"Error saving analysis results: {e}")
        
        return results
    
    def _assess_decryption_possibilities(self, results: Dict[str, Any]) -> None:
        """
        Assess decryption possibilities based on analysis results.
        
        Args:
            results: Analysis results to update
        """
        family = results.get("potential_family")
        if not family:
            results["decryption_possibilities"] = {
                "assessment": "Unknown ransomware family, decryption options unclear",
                "free_decryptor_available": False,
                "probability": "unknown"
            }
            return
            
        # Check if tools are available
        tools_available = len(results.get("available_tools", [])) > 0
        
        # Known families with free decryptors
        families_with_decryptors = {
            "WannaCry": {
                "assessment": "Decryption possible if the system was not rebooted after infection",
                "method": "Extract keys from memory or use WanaKiwi/WannaKey tools",
                "probability": "high"
            },
            "STOP": {
                "assessment": "Decryption possible for older versions with online keys",
                "method": "Use Emsisoft STOP Decryptor or try online key databases",
                "probability": "medium"
            },
            "TeslaCrypt": {
                "assessment": "Decryption possible with master key released by authors",
                "method": "Use TeslaCrypt Decryptor tools",
                "probability": "high"
            },
            "Shade": {
                "assessment": "Decryption possible with released master keys",
                "method": "Use Kaspersky or ESET Shade Decryptor",
                "probability": "high"
            },
            "GandCrab": {
                "assessment": "Decryption possible for versions 1, 4, and 5 with released keys",
                "method": "Use Bitdefender GandCrab Decryptor",
                "probability": "medium"
            },
            "Dharma": {
                "assessment": "Decryption rarely possible, depends on specific variant",
                "method": "Try Kaspersky RakhniDecryptor for some variants",
                "probability": "low"
            },
            "Crysis": {
                "assessment": "Decryption possible with released master keys",
                "method": "Use ESET Crysis Decryptor",
                "probability": "high"
            }
        }
        
        # Hard-to-decrypt families
        difficult_families = {
            "Ryuk": {
                "assessment": "Decryption generally not possible without paying ransom",
                "method": "Try to find unencrypted copies or backups",
                "probability": "very low"
            },
            "REvil": {
                "assessment": "Decryption generally not possible without paying ransom",
                "method": "Check for specific law enforcement operations with keys",
                "probability": "very low"
            },
            "LockBit": {
                "assessment": "Decryption generally not possible without paying ransom",
                "method": "Try to find unencrypted copies or backups",
                "probability": "very low"
            },
            "Conti": {
                "assessment": "Decryption generally not possible without paying ransom",
                "method": "Try to find unencrypted copies or backups",
                "probability": "very low"
            },
            "BlackCat": {
                "assessment": "Decryption generally not possible without paying ransom",
                "method": "Try to find unencrypted copies or backups",
                "probability": "very low"
            }
        }
        
        # Generic assessment
        generic_assessment = {
            "assessment": "Unknown decryption possibilities for this ransomware family",
            "method": "Search for recent developments and try available tools",
            "probability": "unknown",
            "free_decryptor_available": tools_available
        }
        
        # Determine assessment
        if family in families_with_decryptors:
            assessment = families_with_decryptors[family]
            assessment["free_decryptor_available"] = True
        elif family in difficult_families:
            assessment = difficult_families[family]
            assessment["free_decryptor_available"] = False
        else:
            assessment = generic_assessment
            
        results["decryption_possibilities"] = assessment
    
    def scan_directory(self, directory: str, recursive: bool = True, 
                      output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan a directory for files encrypted by ransomware.
        
        Args:
            directory: Directory to scan
            recursive: Whether to scan recursively
            output_file: Optional path to save scan results
            
        Returns:
            Scan results
        """
        if not os.path.isdir(directory):
            logger.error(f"Directory not found: {directory}")
            return {"error": "Directory not found"}
            
        logger.info(f"Scanning directory: {directory}")
        
        # Use analyzer to scan directory and identify encrypted files
        encrypted_files = {}
        
        # This is a placeholder implementation, in a real scenario we'd need to
        # ensure the EnhancedToolIntegration has a scan_directory method or implement
        # the scanning functionality here
        
        # Walk through directory
        for root, _, files in os.walk(directory) if recursive else [(directory, None, os.listdir(directory))]:
            for filename in files:
                file_path = os.path.join(root, filename)
                
                # Skip very large files and non-regular files
                if not os.path.isfile(file_path) or os.path.getsize(file_path) > 100 * 1024 * 1024:
                    continue
                    
                # Analyze file to detect ransomware family
                try:
                    analysis = self.analyzer.analyze_file(file_path)
                    if "potential_family" in analysis and analysis["potential_family"]:
                        family = analysis["potential_family"]
                        
                        # Add to results
                        if family not in encrypted_files:
                            encrypted_files[family] = []
                            
                        encrypted_files[family].append(file_path)
                except Exception as e:
                    logger.warning(f"Error analyzing file {file_path}: {e}")
        
        results = {
            "scan_time": datetime.datetime.now().isoformat(),
            "directory": directory,
            "recursive": recursive,
            "total_encrypted_files": sum(len(files) for files in encrypted_files.values()),
            "families_detected": list(encrypted_files.keys()),
            "files_by_family": encrypted_files,
            "available_tools": {}
        }
        
        # Find available tools for each family
        for family in encrypted_files:
            available_tools = self.tools.find_tools_for_family(family)
            if available_tools:
                results["available_tools"][family] = [
                    {
                        "id": tool["id"],
                        "name": tool.get("name", "Unknown"),
                        "description": tool.get("description", ""),
                        "installed": tool.get("installed", False),
                        "source": tool.get("source", "unknown"),
                        "url": tool.get("url", "")
                    }
                    for tool in available_tools
                ]
            else:
                results["available_tools"][family] = []
        
        # Save results if output file specified
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    json.dump(results, f, indent=2)
                logger.info(f"Scan results saved to {output_file}")
            except Exception as e:
                logger.error(f"Error saving scan results: {e}")
        
        return results
    
    def decrypt_file(self, file_path: str, tool_id: Optional[str] = None,
                    key_file: Optional[str] = None, output_file: Optional[str] = None,
                    options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Decrypt a file using the specified tool.
        
        Args:
            file_path: Path to the encrypted file
            tool_id: ID of the decryption tool to use
            key_file: Optional path to a key file
            output_file: Optional path for decrypted output
            options: Additional options for the decryption process
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return False
            
        logger.info(f"Decrypting file: {file_path}")
        
        if not options:
            options = {}
            
        # Analyze file first if no family specified
        if "family" not in options:
            analysis = self.analyzer.analyze_file(file_path)
            if "potential_family" in analysis and analysis["potential_family"]:
                options["family"] = analysis["potential_family"]
                logger.info(f"Detected ransomware family: {options['family']}")
                
        # If no tool specified, use auto mode
        if not tool_id:
            return self.tools.attempt_auto_decrypt(file_path, output_file, options.get("family"))
            
        # Otherwise use the specified tool
        if not self.tools.load_tool(tool_id):
            logger.error(f"Failed to load tool: {tool_id}")
            return False
            
        return self.tools.decrypt_file(file_path, key_file, output_file, options)
    
    def list_tools(self, family: Optional[str] = None, 
                  show_installed: bool = False) -> List[Dict[str, Any]]:
        """
        List available decryption tools.
        
        Args:
            family: Optional ransomware family to filter tools
            show_installed: Whether to show only installed tools
            
        Returns:
            List of tools
        """
        if family:
            tools = self.tools.find_tools_for_family(family)
        else:
            if show_installed:
                tools = self.tools.get_installed_tools()
            else:
                all_tools = self.tools.get_all_tools()
                tools = []
                for tool_id, tool_info in all_tools.items():
                    tool_copy = dict(tool_info)
                    tool_copy['id'] = tool_id
                    tools.append(tool_copy)
                
        return tools
        
    def update_tools(self) -> bool:
        """
        Update the tool database and check for tool updates.
        
        Returns:
            True if updates were successful, False otherwise
        """
        logger.info("Updating tool database and checking for updates")
        
        # Use the synchronize_registries method from the enhanced tool integration
        results = self.tools.synchronize_registries()
        
        # Check for updates
        updates = self.tools.check_for_updates()
        
        if updates['enhanced'] or updates['standard']:
            logger.info("Updates available for:")
            
            for tool_id in updates['enhanced']:
                logger.info(f"  {tool_id} (enhanced)")
                
            for tool_id in updates['standard']:
                logger.info(f"  {tool_id} (standard)")
                
        return results['added'] > 0 or results['updated'] > 0
    
    def install_tool(self, tool_id: str, family: Optional[str] = None) -> Optional[str]:
        """
        Install a decryption tool.
        
        Args:
            tool_id: Tool ID to install
            family: Optional ransomware family for specific tool variant
            
        Returns:
            Path to installed tool or None if installation failed
        """
        logger.info(f"Installing tool: {tool_id}")
        
        return self.tools.install_tool(tool_id, family)
    
    def generate_report(self, analysis_results: Dict[str, Any], 
                       output_file: Optional[str] = None) -> Optional[str]:
        """
        Generate a human-readable report from analysis results.
        
        Args:
            analysis_results: Analysis results from analyze_file
            output_file: Optional path to save the report
            
        Returns:
            Path to the report or None if generation failed
        """
        if not analysis_results:
            logger.error("No analysis results provided")
            return None
            
        # Generate default output filename if not provided
        if not output_file:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.work_dir, f"ransomware_report_{timestamp}.txt")
            
        try:
            # Create report content
            report_lines = [
                "=" * 80,
                "RANSOMWARE ANALYSIS REPORT",
                "=" * 80,
                "",
                f"Report generated: {datetime.datetime.now().isoformat()}",
                "",
                "FILE INFORMATION",
                "-" * 80,
                f"File: {analysis_results.get('file_path', 'Unknown')}",
                f"Size: {analysis_results.get('file_size', 0)} bytes",
                f"Entropy: {analysis_results.get('entropy', 0):.2f} / 8.00",
                "",
                "RANSOMWARE IDENTIFICATION",
                "-" * 80
            ]
            
            # Add ransomware identification
            if "potential_family" in analysis_results:
                family = analysis_results["potential_family"]
                confidence = analysis_results.get("family_confidence", 
                                              analysis_results.get("encryption_confidence", 0.0))
                                              
                report_lines.extend([
                    f"Identified Family: {family}",
                    f"Identification Confidence: {confidence:.2f}",
                    f"Assessment: {analysis_results.get('assessment', 'Unknown')}"
                ])
            else:
                report_lines.append("No specific ransomware family identified")
                
            # Add encryption details
            report_lines.extend([
                "",
                "ENCRYPTION DETAILS",
                "-" * 80
            ])
            
            encryption_details = analysis_results.get("encryption_details", {})
            if encryption_details:
                algorithm = encryption_details.get("likely_algorithm", "Unknown")
                mode = encryption_details.get("mode", "")
                
                report_lines.extend([
                    f"Likely Encryption Algorithm: {algorithm}",
                    f"Mode of Operation: {mode}",
                    f"Algorithm Confidence: {encryption_details.get('confidence', 0.0):.2f}"
                ])
                
                # Add any additional details
                for key, value in encryption_details.items():
                    if key not in ["likely_algorithm", "mode", "confidence"]:
                        report_lines.append(f"{key}: {value}")
            else:
                report_lines.append("No specific encryption details identified")
                
            # Add decryption possibilities
            report_lines.extend([
                "",
                "DECRYPTION POSSIBILITIES",
                "-" * 80
            ])
            
            decryption = analysis_results.get("decryption_possibilities", {})
            if decryption:
                report_lines.extend([
                    f"Assessment: {decryption.get('assessment', 'Unknown')}",
                    f"Method: {decryption.get('method', 'Unknown')}",
                    f"Probability: {decryption.get('probability', 'Unknown')}",
                    f"Free Decryptor Available: {'Yes' if decryption.get('free_decryptor_available', False) else 'No'}"
                ])
            else:
                report_lines.append("Decryption possibilities could not be determined")
                
            # Add available tools
            report_lines.extend([
                "",
                "AVAILABLE DECRYPTION TOOLS",
                "-" * 80
            ])
            
            tools = analysis_results.get("available_tools", [])
            if tools:
                for tool in tools:
                    status = "Installed" if tool.get("installed", False) else "Available"
                    report_lines.extend([
                        f"Tool: {tool.get('name', 'Unknown')} ({tool.get('id', 'Unknown')}) - {status}",
                        f"  {tool.get('description', '')}",
                        f"  URL: {tool.get('url', 'N/A')}"
                    ])
            else:
                report_lines.append("No specific decryption tools available")
                
            # Add general recommendations
            report_lines.extend([
                "",
                "GENERAL RECOMMENDATIONS",
                "-" * 80,
                "1. DO NOT pay the ransom unless absolutely necessary",
                "2. Check https://www.nomoreransom.org for free decryption tools",
                "3. Report the incident to local law enforcement and relevant cybersecurity agencies",
                "4. If system is still running, capture memory dumps for potential key extraction",
                "5. Check for backup copies of encrypted files",
                "6. Isolate infected systems to prevent further spread",
                "",
                "DISCLAIMER",
                "-" * 80,
                "This analysis is based on automated pattern recognition and may not be 100% accurate.",
                "Always consult with cybersecurity professionals for critical situations."
            ])
            
            # Write report to file
            with open(output_file, 'w') as f:
                f.write('\n'.join(report_lines))
                
            logger.info(f"Report saved to {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return None
    
    def batch_decrypt(self, files: List[str], tool_id: Optional[str] = None,
                     key_file: Optional[str] = None, output_dir: Optional[str] = None,
                     options: Optional[Dict[str, Any]] = None) -> Dict[str, bool]:
        """
        Decrypt multiple files using the same tool and settings.
        
        Args:
            files: List of files to decrypt
            tool_id: ID of the decryption tool to use
            key_file: Optional path to a key file
            output_dir: Optional directory for decrypted outputs
            options: Additional options for the decryption process
            
        Returns:
            Dictionary mapping file paths to decryption success status
        """
        if not files:
            logger.error("No files provided for batch decryption")
            return {}
            
        logger.info(f"Batch decrypting {len(files)} files")
        
        # Use the enhanced tool integration's batch decrypt capability
        return self.tools.batch_decrypt(files, tool_id, key_file, output_dir, options)

def main():
    """Command-line interface for the ransomware recovery tool."""
    parser = argparse.ArgumentParser(description="Ransomware Recovery Tool")
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze encrypted file')
    analyze_parser.add_argument('file', help='File to analyze')
    analyze_parser.add_argument('--output', '-o', help='Output file for analysis results (JSON)')
    analyze_parser.add_argument('--report', '-r', help='Generate human-readable report')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan for encrypted files')
    scan_parser.add_argument('directory', help='Directory to scan')
    scan_parser.add_argument('--no-recursive', action='store_true', help='Disable recursive scanning')
    scan_parser.add_argument('--output', '-o', help='Output file for scan results (JSON)')
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('file', help='File to decrypt')
    decrypt_parser.add_argument('--tool', help='Tool ID to use')
    decrypt_parser.add_argument('--family', help='Ransomware family')
    decrypt_parser.add_argument('--key', help='Path to key file')
    decrypt_parser.add_argument('--output', '-o', help='Output path')
    decrypt_parser.add_argument('--auto', action='store_true', help='Try automatic decryption')
    decrypt_parser.add_argument('--container', action='store_true', help='Use containerized execution for this operation')
    decrypt_parser.add_argument('--no-gui', action='store_true', help='Force non-GUI mode for this operation')
    decrypt_parser.add_argument('--source', choices=['enhanced', 'standard'], help='Preferred tool source')
    
    # Batch decrypt command
    batch_parser = subparsers.add_parser('batch-decrypt', help='Decrypt multiple files')
    batch_parser.add_argument('files', nargs='+', help='Files to decrypt')
    batch_parser.add_argument('--tool', help='Tool ID to use')
    batch_parser.add_argument('--family', help='Ransomware family')
    batch_parser.add_argument('--key', help='Path to key file')
    batch_parser.add_argument('--output-dir', '-o', help='Output directory')
    batch_parser.add_argument('--auto', action='store_true', help='Try automatic decryption')
    batch_parser.add_argument('--container', action='store_true', help='Use containerized execution for this operation')
    batch_parser.add_argument('--no-gui', action='store_true', help='Force non-GUI mode for this operation')
    batch_parser.add_argument('--source', choices=['enhanced', 'standard'], help='Preferred tool source')
    
    # Tools command
    tools_parser = subparsers.add_parser('tools', help='Manage decryption tools')
    tools_parser.add_argument('--list', action='store_true', help='List available tools')
    tools_parser.add_argument('--family', help='Filter by ransomware family')
    tools_parser.add_argument('--installed', action='store_true', help='Show only installed tools')
    tools_parser.add_argument('--install', help='Install a tool (provide tool ID)')
    tools_parser.add_argument('--update', action='store_true', help='Update tool database')
    tools_parser.add_argument('--search', help='Search for tools by name, family, or description')
    tools_parser.add_argument('--source', choices=['enhanced', 'standard', 'all'], default='all',
                             help='Filter tools by source (enhanced or standard registry)')
    tools_parser.add_argument('--info', help='Get detailed information about a specific tool')
    tools_parser.add_argument('--synchronize', action='store_true', help='Synchronize enhanced and standard registries')
    tools_parser.add_argument('--update-all', action='store_true', help='Update all installed tools')
    
    # Add global options for all commands
    parser.add_argument('--use-containers', action='store_true', help='Use containerized execution where available')
    parser.add_argument('--force-no-gui', action='store_true', help='Force non-GUI mode for tools that support it')
    parser.add_argument('--work-dir', help='Working directory for temporary files')

    # Parse arguments
    args = parser.parse_args()
    
    # Create recovery tool with enhanced options
    recovery = RansomwareRecovery(
        work_dir=args.work_dir,
        use_containers=args.use_containers,
        force_no_gui=args.force_no_gui
    )
    
    if args.command == 'analyze':
        # Analyze file
        results = recovery.analyze_file(args.file, args.output)
        
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
        
        if "decryption_possibilities" in results:
            decr = results["decryption_possibilities"]
            print(f"\nDecryption Assessment: {decr.get('assessment', 'Unknown')}")
            print(f"Decryption Method: {decr.get('method', 'Unknown')}")
            print(f"Probability: {decr.get('probability', 'Unknown')}")
            
        if "available_tools" in results and results["available_tools"]:
            print("\nAvailable Decryption Tools:")
            for tool in results["available_tools"]:
                status = "Installed" if tool.get("installed", False) else "Available"
                print(f"  {tool['id']}: {tool['name']} - {status}")
        
        # Generate report if requested
        if args.report:
            report_path = recovery.generate_report(results, args.report)
            if report_path:
                print(f"\nDetailed report saved to: {report_path}")
                
    elif args.command == 'scan':
        # Scan directory
        results = recovery.scan_directory(args.directory, not args.no_recursive, args.output)
        
        # Print summary
        if "error" in results:
            print(f"Error: {results['error']}")
        else:
            total_files = results.get("total_encrypted_files", 0)
            print(f"\nScan of {args.directory}:")
            print(f"Found {total_files} potentially encrypted files")
            
            for family, files in results.get("files_by_family", {}).items():
                print(f"\n{family} ({len(files)} files):")
                for file in files[:5]:  # Limit to 5 files per family
                    print(f"  {file}")
                if len(files) > 5:
                    print(f"  ...and {len(files) - 5} more files")
                    
            # Show available tools
            for family, tools in results.get("available_tools", {}).items():
                if tools:
                    print(f"\nDecryption tools for {family}:")
                    for tool in tools:
                        status = "Installed" if tool.get("installed", False) else "Available"
                        print(f"  {tool['id']}: {tool['name']} - {status}")
                else:
                    print(f"\nNo known decryption tools for {family}")
                    
    elif args.command == 'decrypt':
        # Prepare options
        options = {}
        if args.family:
            options["family"] = args.family
            
        # Set per-operation container and GUI flags if specified
        if args.container:
            recovery.tools.use_containers = True
        if args.no_gui:
            recovery.tools.force_no_gui = True
            
        # Set source preference if specified
        if args.source:
            options["preferred_source"] = args.source
            
        # Decrypt file
        if args.auto:
            success = recovery.decrypt_file(args.file, None, args.key, args.output, options)
        elif args.tool:
            success = recovery.decrypt_file(args.file, args.tool, args.key, args.output, options)
        else:
            print("Either --tool or --auto must be specified")
            return 1
            
        if success:
            print("Decryption successful")
        else:
            print("Decryption failed")
            
    elif args.command == 'batch-decrypt':
        # Prepare options
        options = {}
        if args.family:
            options["family"] = args.family
            
        # Set per-operation container and GUI flags if specified
        if args.container:
            recovery.tools.use_containers = True
        if args.no_gui:
            recovery.tools.force_no_gui = True
            
        # Set source preference if specified
        if args.source:
            options["preferred_source"] = args.source
            
        # Determine tool ID
        tool_id = args.tool if not args.auto else None
            
        # Batch decrypt files
        results = recovery.batch_decrypt(args.files, tool_id, args.key, args.output_dir, options)
        
        # Print summary
        successful = sum(1 for success in results.values() if success)
        print(f"\nDecryption Results: {successful} of {len(results)} files successfully decrypted")
        
        # List failures
        failures = [path for path, success in results.items() if not success]
        if failures:
            print("\nFailed to decrypt:")
            for path in failures[:10]:  # Show only first 10 for clarity
                print(f"  {path}")
            if len(failures) > 10:
                print(f"  ...and {len(failures) - 10} more files")
                
    elif args.command == 'tools':
        if args.search:
            # Search for tools
            tools = recovery.tools.search_tools(args.search)
            print(f"Found {len(tools)} tools matching '{args.search}':")
            
            for tool in tools:
                source = tool.get('source', 'unknown')
                if args.source != 'all' and source != args.source:
                    continue
                    
                status = "Installed" if tool.get("installed", False) else "Available"
                print(f"\n{tool.get('id')} ({source}):")
                print(f"  Name: {tool.get('name', 'Unknown')}")
                print(f"  Description: {tool.get('description', '')}")
                print(f"  Families: {', '.join(tool.get('families', []))}")
                print(f"  Status: {status}")
                
        elif args.info:
            # Get detailed tool info
            tool = recovery.tools.get_tool_info(args.info)
            if tool:
                print(f"Tool: {args.info}")
                print(f"Source: {tool.get('source', 'unknown')}")
                print(f"Name: {tool.get('name', 'Unknown')}")
                print(f"Description: {tool.get('description', '')}")
                print(f"Families: {', '.join(tool.get('families', []))}")
                print(f"Platforms: {', '.join(tool.get('platforms', []))}")
                print(f"Repository: {tool.get('repository', 'unknown')}")
                print(f"Installed: {'Yes' if tool.get('installed', False) else 'No'}")
                
                if tool.get('installed', False):
                    print(f"Install Path: {tool.get('install_path', 'Unknown')}")
                    print(f"Installed Date: {tool.get('installed_date', 'Unknown')}")
            else:
                print(f"Tool not found: {args.info}")
                
        elif args.synchronize:
            # Synchronize registries
            result = recovery.tools.synchronize_registries()
            print(f"Synchronized registries:")
            print(f"  Added: {result['added']} tools")
            print(f"  Updated: {result['updated']} tools")
            
        elif args.list:
            # List tools
            if args.family:
                tools = recovery.list_tools(args.family, args.installed)
                print(f"Tools for {args.family}:")
            elif args.installed:
                tools = recovery.list_tools(None, True)
                print("Installed tools:")
            else:
                tools = recovery.list_tools()
                print("All available tools:")
                
            # Filter by source if specified
            if args.source != 'all':
                tools = [tool for tool in tools if tool.get('source', 'unknown') == args.source]
                
            for tool in tools:
                source = tool.get('source', 'unknown')
                status = "Installed" if tool.get("installed", False) else "Available"
                print(f"\n{tool.get('id')} ({source}):")
                print(f"  Name: {tool.get('name', 'Unknown')}")
                print(f"  Description: {tool.get('description', '')}")
                print(f"  Families: {', '.join(tool.get('families', []))}")
                print(f"  Platforms: {', '.join(tool.get('platforms', []))}")
                print(f"  Status: {status}")
                
        elif args.install:
            # Install tool
            install_path = recovery.install_tool(args.install, args.family)
            if install_path:
                print(f"Tool installed to: {install_path}")
            else:
                print(f"Failed to install tool: {args.install}")
                
        elif args.update or args.update_all:
            if args.update_all:
                # Update all installed tools
                updates = recovery.tools.check_for_updates()
                
                all_updates = updates['enhanced'] + updates['standard']
                if not all_updates:
                    print("No updates available")
                else:
                    print(f"Updating {len(all_updates)} tools...")
                    
                    success_count = 0
                    for tool_id in all_updates:
                        print(f"Updating {tool_id}...")
                        if recovery.tools.update_tool(tool_id):
                            success_count += 1
                            print(f"  Success!")
                        else:
                            print(f"  Failed!")
                            
                    print(f"\nUpdated {success_count} of {len(all_updates)} tools")
            else:
                # Update tools database and check for updates
                if recovery.update_tools():
                    print("Tool database updated successfully")
                else:
                    print("No updates found")
                    
        else:
            print("No tools action specified (use --list, --search, --info, --install, --update, or --synchronize)")
            
    else:
        parser.print_help()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())