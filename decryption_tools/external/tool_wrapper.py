#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ransomware Decryption Tool Wrapper

This module provides a standardized interface for running and interacting with 
external ransomware decryption tools from various sources.
"""

import os
import re
import sys
import json
import shutil
import logging
import tempfile
import platform
import subprocess
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from datetime import datetime

from tool_registry import DecryptionToolRegistry

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('DecryptionToolWrapper')

class ToolCompatibilityError(Exception):
    """Exception raised when a tool is incompatible with the current system."""
    pass

class ToolNotInstalledError(Exception):
    """Exception raised when trying to use a tool that's not installed."""
    pass

class DecryptionToolWrapper:
    """
    Wrapper for standardizing interaction with external decryption tools.
    """
    
    def __init__(self, registry: Optional[DecryptionToolRegistry] = None):
        """
        Initialize the decryption tool wrapper.
        
        Args:
            registry: Optional DecryptionToolRegistry instance
        """
        self.registry = registry or DecryptionToolRegistry()
        self.platform = platform.system().lower()
        self.current_tool = None
        self.current_tool_id = None
        
    def load_tool(self, tool_id: str) -> bool:
        """
        Load a tool from the registry.
        
        Args:
            tool_id: Tool identifier
            
        Returns:
            True if tool loaded successfully, False otherwise
        """
        tool = self.registry.get_tool(tool_id)
        if not tool:
            logger.error(f"Tool {tool_id} not found in registry")
            return False
            
        # Check platform compatibility
        if self.platform not in tool.get('platforms', []):
            logger.error(f"Tool {tool_id} is not compatible with {self.platform}")
            return False
            
        # Check if installed
        if not tool.get('installed', False):
            logger.warning(f"Tool {tool_id} is not installed. Attempting to download...")
            install_path = self.registry.download_tool(tool_id)
            if not install_path:
                logger.error(f"Failed to download tool {tool_id}")
                return False
                
            # Reload tool info after download
            tool = self.registry.get_tool(tool_id)
            
        self.current_tool = tool
        self.current_tool_id = tool_id
        return True
    
    def decrypt_file(self, encrypted_file: str, key_file: Optional[str] = None,
                    output_file: Optional[str] = None, options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Decrypt a file using the currently loaded tool.
        
        Args:
            encrypted_file: Path to the encrypted file
            key_file: Optional path to a key file
            output_file: Optional path for decrypted output
            options: Additional options for the decryption process
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        if not self.current_tool:
            logger.error("No tool loaded")
            return False
            
        if not os.path.exists(encrypted_file):
            logger.error(f"Encrypted file not found: {encrypted_file}")
            return False
            
        if key_file and not os.path.exists(key_file):
            logger.error(f"Key file not found: {key_file}")
            return False
            
        # Determine tool type and handle appropriately
        tool_type = self.current_tool.get('type', 'standalone')
        
        try:
            if tool_type == 'standalone':
                return self._run_standalone_decryption(encrypted_file, key_file, output_file, options)
            elif tool_type == 'github':
                return self._run_github_decryption(encrypted_file, key_file, output_file, options)
            elif tool_type == 'website':
                logger.error(f"Tool {self.current_tool_id} is a website reference and cannot decrypt files directly")
                return False
            else:
                logger.error(f"Unsupported tool type: {tool_type}")
                return False
        except Exception as e:
            logger.error(f"Error during decryption: {e}")
            return False
    
    def _run_standalone_decryption(self, encrypted_file: str, key_file: Optional[str] = None,
                                  output_file: Optional[str] = None, 
                                  options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Run a standalone decryption tool.
        
        Args:
            encrypted_file: Path to the encrypted file
            key_file: Optional path to a key file
            output_file: Optional path for decrypted output
            options: Additional options for the decryption process
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        if not options:
            options = {}
            
        # Get tool path
        tool_path = self.current_tool.get('install_path')
        if not tool_path or not os.path.exists(tool_path):
            logger.error(f"Tool {self.current_tool_id} is not properly installed")
            return False
            
        # Handle tool-specific parameters based on known tools
        tool_name = self.current_tool.get('name', '').lower()
        
        # Build command line
        cmd = [tool_path]
        
        # Auto-detect tool type and adjust command line
        if 'emsisoft' in tool_name:
            return self._run_emsisoft_decryptor(tool_path, encrypted_file, key_file, output_file, options)
        elif 'kaspersky' in tool_name or 'nomore' in tool_name:
            return self._run_kaspersky_decryptor(tool_path, encrypted_file, key_file, output_file, options)
        elif 'trend micro' in tool_name:
            return self._run_trendmicro_decryptor(tool_path, encrypted_file, key_file, output_file, options)
        elif 'avast' in tool_name:
            return self._run_avast_decryptor(tool_path, encrypted_file, key_file, output_file, options)
        else:
            # Generic approach for unknown tools
            return self._run_generic_decryptor(tool_path, encrypted_file, key_file, output_file, options)
    
    def _run_emsisoft_decryptor(self, tool_path: str, encrypted_file: str, 
                               key_file: Optional[str] = None, output_file: Optional[str] = None,
                               options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Run an Emsisoft decryptor tool.
        
        Args:
            tool_path: Path to the decryptor executable
            encrypted_file: Path to the encrypted file
            key_file: Optional path to a key file
            output_file: Optional path for decrypted output
            options: Additional options for the decryption process
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        logger.info(f"Running Emsisoft decryptor: {tool_path}")
        
        # Emsisoft decryptors typically run interactively
        if self.platform == 'windows':
            # On Windows, just launch the tool and guide the user
            logger.info("Launching Emsisoft decryptor. Please follow the GUI prompts.")
            subprocess.Popen([tool_path])
            return True
        else:
            logger.error("Emsisoft decryptors are Windows-only and cannot be run on this platform")
            return False
    
    def _run_kaspersky_decryptor(self, tool_path: str, encrypted_file: str, 
                                key_file: Optional[str] = None, output_file: Optional[str] = None,
                                options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Run a Kaspersky decryptor tool.
        
        Args:
            tool_path: Path to the decryptor executable
            encrypted_file: Path to the encrypted file
            key_file: Optional path to a key file
            output_file: Optional path for decrypted output
            options: Additional options for the decryption process
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        logger.info(f"Running Kaspersky decryptor: {tool_path}")
        
        # Kaspersky decryptors typically run interactively
        if self.platform == 'windows':
            # On Windows, just launch the tool and guide the user
            logger.info("Launching Kaspersky decryptor. Please follow the GUI prompts.")
            subprocess.Popen([tool_path])
            return True
        else:
            logger.error("Kaspersky decryptors are Windows-only and cannot be run on this platform")
            return False
    
    def _run_trendmicro_decryptor(self, tool_path: str, encrypted_file: str, 
                                 key_file: Optional[str] = None, output_file: Optional[str] = None,
                                 options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Run a Trend Micro decryptor tool.
        
        Args:
            tool_path: Path to the decryptor executable
            encrypted_file: Path to the encrypted file
            key_file: Optional path to a key file
            output_file: Optional path for decrypted output
            options: Additional options for the decryption process
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        logger.info(f"Running Trend Micro decryptor: {tool_path}")
        
        # Trend Micro decryptors typically run interactively
        if self.platform == 'windows':
            # On Windows, just launch the tool and guide the user
            logger.info("Launching Trend Micro decryptor. Please follow the GUI prompts.")
            subprocess.Popen([tool_path])
            return True
        else:
            logger.error("Trend Micro decryptors are Windows-only and cannot be run on this platform")
            return False
    
    def _run_avast_decryptor(self, tool_path: str, encrypted_file: str, 
                            key_file: Optional[str] = None, output_file: Optional[str] = None,
                            options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Run an Avast decryptor tool.
        
        Args:
            tool_path: Path to the decryptor executable
            encrypted_file: Path to the encrypted file
            key_file: Optional path to a key file
            output_file: Optional path for decrypted output
            options: Additional options for the decryption process
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        logger.info(f"Running Avast decryptor: {tool_path}")
        
        # Avast decryptors typically run interactively
        if self.platform == 'windows':
            # On Windows, just launch the tool and guide the user
            logger.info("Launching Avast decryptor. Please follow the GUI prompts.")
            subprocess.Popen([tool_path])
            return True
        else:
            logger.error("Avast decryptors are Windows-only and cannot be run on this platform")
            return False
    
    def _run_generic_decryptor(self, tool_path: str, encrypted_file: str, 
                              key_file: Optional[str] = None, output_file: Optional[str] = None,
                              options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Run a generic decryptor tool with best-effort parameters.
        
        Args:
            tool_path: Path to the decryptor executable
            encrypted_file: Path to the encrypted file
            key_file: Optional path to a key file
            output_file: Optional path for decrypted output
            options: Additional options for the decryption process
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        logger.info(f"Running generic decryptor: {tool_path}")
        
        cmd = [tool_path]
        
        # Add common command-line parameters
        cmd.append(encrypted_file)
        
        if key_file:
            cmd.extend(['-k', key_file])
            
        if output_file:
            cmd.extend(['-o', output_file])
            
        # Add any additional options
        if options:
            for key, value in options.items():
                if len(key) == 1:
                    cmd.append(f"-{key}")
                else:
                    cmd.append(f"--{key}")
                    
                if value is not True:  # Skip value for boolean flags
                    cmd.append(str(value))
        
        # Run the command
        try:
            logger.info(f"Running command: {' '.join(cmd)}")
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if process.returncode != 0:
                logger.error(f"Decryption failed: {process.stderr}")
                return False
                
            logger.info(f"Decryption output: {process.stdout}")
            return True
            
        except Exception as e:
            logger.error(f"Error running decryptor: {e}")
            return False
    
    def _run_github_decryption(self, encrypted_file: str, key_file: Optional[str] = None,
                              output_file: Optional[str] = None, 
                              options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Run a GitHub-based decryption tool.
        
        Args:
            encrypted_file: Path to the encrypted file
            key_file: Optional path to a key file
            output_file: Optional path for decrypted output
            options: Additional options for the decryption process
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        if not options:
            options = {}
            
        # Get tool path
        repo_path = self.current_tool.get('install_path')
        if not repo_path or not os.path.exists(repo_path):
            logger.error(f"Tool {self.current_tool_id} is not properly installed")
            return False
            
        # Look for specific tools based on ID
        tool_id = self.current_tool_id.lower()
        
        if 'mcafee' in tool_id and 'mr2' in tool_id:
            return self._run_mcafee_mr2(repo_path, encrypted_file, key_file, output_file, options)
        else:
            # Try to find common entry points
            entry_points = [
                os.path.join(repo_path, 'decrypt.py'),
                os.path.join(repo_path, 'decryptor.py'),
                os.path.join(repo_path, 'main.py'),
                os.path.join(repo_path, 'run.py')
            ]
            
            for entry_point in entry_points:
                if os.path.exists(entry_point):
                    return self._run_python_script(entry_point, encrypted_file, key_file, output_file, options)
                    
            logger.error(f"Could not find a suitable entry point for {self.current_tool_id}")
            return False
    
    def _run_mcafee_mr2(self, repo_path: str, encrypted_file: str, 
                       key_file: Optional[str] = None, output_file: Optional[str] = None,
                       options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Run McAfee Ransomware Recover (mr2) tool.
        
        Args:
            repo_path: Path to the mr2 repository
            encrypted_file: Path to the encrypted file
            key_file: Optional path to a key file
            output_file: Optional path for decrypted output
            options: Additional options for the decryption process
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        logger.info("Running McAfee Ransomware Recover (mr2) tool")
        
        # Look for the main script
        mr2_script = os.path.join(repo_path, 'mr2.py')
        
        if not os.path.exists(mr2_script):
            logger.error(f"Mr2 script not found at {mr2_script}")
            return False
            
        # Build command
        cmd = [sys.executable, mr2_script, '--decrypt']
        
        # If we know the ransomware family, use the appropriate module
        if options and 'family' in options:
            family = options['family'].lower()
            if 'wannacry' in family:
                cmd.append('--wannacry')
        else:
            # Default to autodiscover
            cmd.append('--autodiscover')
            
        # Add file to decrypt
        cmd.extend(['--file', encrypted_file])
        
        # Add output file if specified
        if output_file:
            cmd.extend(['--output', output_file])
            
        # Add key file if specified
        if key_file:
            cmd.extend(['--key', key_file])
            
        # Add any additional options
        if options:
            for key, value in options.items():
                if key not in ['family']:  # Skip options we've already handled
                    if len(key) == 1:
                        cmd.append(f"-{key}")
                    else:
                        cmd.append(f"--{key}")
                        
                    if value is not True:  # Skip value for boolean flags
                        cmd.append(str(value))
        
        # Run the command
        try:
            logger.info(f"Running command: {' '.join(cmd)}")
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if process.returncode != 0:
                logger.error(f"Decryption failed: {process.stderr}")
                return False
                
            logger.info(f"Decryption output: {process.stdout}")
            
            # Check if decryption was successful based on output
            if "successfully decrypted" in process.stdout.lower():
                return True
            else:
                logger.warning("Decryption may not have been successful. Check the output.")
                return False
                
        except Exception as e:
            logger.error(f"Error running Mr2: {e}")
            return False
    
    def _run_python_script(self, script_path: str, encrypted_file: str, 
                          key_file: Optional[str] = None, output_file: Optional[str] = None,
                          options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Run a Python decryption script.
        
        Args:
            script_path: Path to the Python script
            encrypted_file: Path to the encrypted file
            key_file: Optional path to a key file
            output_file: Optional path for decrypted output
            options: Additional options for the decryption process
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        logger.info(f"Running Python script: {script_path}")
        
        # Build command
        cmd = [sys.executable, script_path]
        
        # Add file to decrypt
        cmd.append(encrypted_file)
        
        # Add output file if specified
        if output_file:
            cmd.extend(['-o', output_file])
            
        # Add key file if specified
        if key_file:
            cmd.extend(['-k', key_file])
            
        # Add any additional options
        if options:
            for key, value in options.items():
                if len(key) == 1:
                    cmd.append(f"-{key}")
                else:
                    cmd.append(f"--{key}")
                    
                if value is not True:  # Skip value for boolean flags
                    cmd.append(str(value))
        
        # Run the command
        try:
            logger.info(f"Running command: {' '.join(cmd)}")
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            if process.returncode != 0:
                logger.error(f"Decryption failed: {process.stderr}")
                return False
                
            logger.info(f"Decryption output: {process.stdout}")
            return True
            
        except Exception as e:
            logger.error(f"Error running Python script: {e}")
            return False
    
    def scan_directory(self, directory: str, recursive: bool = True) -> Dict[str, List[str]]:
        """
        Scan a directory for files encrypted by known ransomware families.
        
        Args:
            directory: Directory to scan
            recursive: Whether to scan recursively
            
        Returns:
            Dictionary mapping ransomware family names to lists of potentially encrypted files
        """
        if not os.path.isdir(directory):
            logger.error(f"Directory not found: {directory}")
            return {}
            
        logger.info(f"Scanning directory: {directory}")
        
        results = {}
        
        # Get file extensions and markers used by known ransomware families
        family_signatures = self._get_ransomware_signatures()
        
        # Walk directory
        for root, _, files in os.walk(directory):
            for filename in files:
                file_path = os.path.join(root, filename)
                
                # Check file extension
                _, ext = os.path.splitext(filename)
                if ext:
                    ext = ext.lower()
                    
                # Check against known extensions
                for family, signatures in family_signatures.items():
                    extensions = signatures.get('extensions', [])
                    if ext in extensions:
                        if family not in results:
                            results[family] = []
                        results[family].append(file_path)
                        continue
                        
                    # Check for known filenames
                    filenames = signatures.get('filenames', [])
                    if any(pattern in filename.lower() for pattern in filenames):
                        if family not in results:
                            results[family] = []
                        results[family].append(file_path)
                        continue
                        
                    # Check file headers for known markers
                    markers = signatures.get('markers', [])
                    if markers and self._check_file_markers(file_path, markers):
                        if family not in results:
                            results[family] = []
                        results[family].append(file_path)
            
            # Stop if not recursive
            if not recursive:
                break
                
        return results
    
    def _check_file_markers(self, file_path: str, markers: List[bytes]) -> bool:
        """
        Check if a file contains any of the given markers in its header.
        
        Args:
            file_path: Path to the file
            markers: List of byte patterns to check for
            
        Returns:
            True if any marker is found, False otherwise
        """
        try:
            with open(file_path, 'rb') as f:
                header = f.read(1024)  # Read first 1KB
                
            return any(marker in header for marker in markers)
            
        except Exception:
            return False
    
    def _get_ransomware_signatures(self) -> Dict[str, Dict[str, Any]]:
        """
        Get signatures for known ransomware families.
        
        Returns:
            Dictionary mapping family names to signature information
        """
        # This data could be loaded from a JSON file or database
        # Here we're defining it inline for simplicity
        return {
            "WannaCry": {
                "extensions": [".wncry", ".wcry", ".wncrypt", ".wncryt"],
                "filenames": ["@please_read_me@", "!please_read_me!"],
                "markers": [b"WANACRY!"]
            },
            "Ryuk": {
                "extensions": [".ryk", ".ryuk", ".RYK"],
                "filenames": ["ryukreadme.txt", "ryuk"],
                "markers": [b"HERMES", b"RyukReadMe"]
            },
            "REvil": {
                "extensions": [".revil", ".sodinokibi", ".sodin", ".random"],
                "filenames": ["readme", "-readme.txt"],
                "markers": []
            },
            "LockBit": {
                "extensions": [".lockbit", ".abcd", ".lock"],
                "filenames": ["restore-my-files.txt"],
                "markers": [b"LOCK", b"LockBit"]
            },
            "BlackCat": {
                "extensions": [".blackcat", ".bc", ".cat"],
                "filenames": ["restore-my-files.txt", "recover-files.txt"],
                "markers": [b"BlackCat"]
            },
            "Conti": {
                "extensions": [".conti", ".crypt", ".encryption"],
                "filenames": ["conti_readme.txt"],
                "markers": [b"CONTI"]
            },
            "BlackBasta": {
                "extensions": [".basta"],
                "filenames": ["readme.txt"],
                "markers": [b"BLACK BASTA"]
            },
            "Hive": {
                "extensions": [".hive", ".key"],
                "filenames": ["how_to_decrypt.txt"],
                "markers": []
            },
            "AvosLocker": {
                "extensions": [".avos", ".avos2"],
                "filenames": ["get_your_files_back.txt"],
                "markers": [b"AvosLocker"]
            },
            "STOP": {
                "extensions": [".djvu", ".djvus", ".djvur", ".uudjvu", ".udjvu", ".djvuq", ".djvuk"],
                "filenames": ["_readme.txt"],
                "markers": []
            }
        }
    
    def find_decryption_tools(self, family: str) -> List[Dict[str, Any]]:
        """
        Find tools that can decrypt a specific ransomware family.
        
        Args:
            family: Ransomware family name
            
        Returns:
            List of suitable tools
        """
        return self.registry.get_tools_for_family(family)
    
    def attempt_auto_decrypt(self, encrypted_file: str, 
                            output_file: Optional[str] = None,
                            family: Optional[str] = None) -> bool:
        """
        Attempt to automatically decrypt a file using available tools.
        
        Args:
            encrypted_file: Path to the encrypted file
            output_file: Optional path for decrypted output
            family: Optional ransomware family hint
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        if not os.path.exists(encrypted_file):
            logger.error(f"Encrypted file not found: {encrypted_file}")
            return False
            
        # Determine ransomware family if not provided
        if not family:
            family = self._detect_ransomware_family(encrypted_file)
            if not family:
                logger.error("Could not detect ransomware family. Please specify manually.")
                return False
                
        logger.info(f"Attempting to decrypt file encrypted by {family}")
        
        # Find suitable tools
        tools = self.find_decryption_tools(family)
        if not tools:
            logger.error(f"No decryption tools found for {family}")
            return False
            
        # Try each tool
        for tool in tools:
            tool_id = tool['id']
            logger.info(f"Trying tool: {tool['name']} ({tool_id})")
            
            # Load tool
            if not self.load_tool(tool_id):
                logger.warning(f"Failed to load tool {tool_id}, trying next tool")
                continue
                
            # Attempt decryption
            if self.decrypt_file(encrypted_file, output_file=output_file, options={'family': family}):
                logger.info(f"Decryption successful with {tool['name']}")
                return True
                
            logger.warning(f"Decryption failed with {tool['name']}, trying next tool")
            
        logger.error("All decryption attempts failed")
        return False
    
    def _detect_ransomware_family(self, file_path: str) -> Optional[str]:
        """
        Attempt to detect ransomware family from file characteristics.
        
        Args:
            file_path: Path to the encrypted file
            
        Returns:
            Detected ransomware family or None if detection failed
        """
        # Get file extension
        _, ext = os.path.splitext(file_path)
        if ext:
            ext = ext.lower()
            
        # Get file signatures
        signatures = self._get_ransomware_signatures()
        
        # Check each family's signatures
        for family, family_sigs in signatures.items():
            # Check extension
            if ext in family_sigs.get('extensions', []):
                return family
                
            # Check filename
            filename = os.path.basename(file_path).lower()
            if any(pattern in filename for pattern in family_sigs.get('filenames', [])):
                return family
                
            # Check markers
            markers = family_sigs.get('markers', [])
            if markers and self._check_file_markers(file_path, markers):
                return family
                
        # Check for common ransom notes in the same directory
        dir_path = os.path.dirname(file_path)
        files = os.listdir(dir_path)
        
        common_note_patterns = [
            (r"readme.*\.txt", ["WannaCry", "REvil", "LockBit"]),
            (r"how.*decrypt.*\.txt", ["Hive", "BlackCat"]),
            (r"recover.*files.*\.txt", ["BlackCat", "AvosLocker"]),
            (r".*ransom.*\.txt", ["REvil", "Ryuk"]),
            (r".*restore.*\.txt", ["LockBit", "BlackBasta"]),
            (r".*decrypt.*\.html", ["Conti", "STOP"]),
            (r"_readme\.txt", ["STOP"])
        ]
        
        for filename in files:
            for pattern, families in common_note_patterns:
                if re.match(pattern, filename.lower()):
                    # Return the first family as the most likely
                    return families[0]
                    
        return None

def main():
    """Command-line interface for the decryption tool wrapper."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Ransomware Decryption Tool Wrapper")
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan for encrypted files')
    scan_parser.add_argument('directory', help='Directory to scan')
    scan_parser.add_argument('--no-recursive', action='store_true', help='Disable recursive scanning')
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('file', help='File to decrypt')
    decrypt_parser.add_argument('--tool', help='Tool ID to use')
    decrypt_parser.add_argument('--family', help='Ransomware family')
    decrypt_parser.add_argument('--key', help='Path to key file')
    decrypt_parser.add_argument('--output', '-o', help='Output path')
    decrypt_parser.add_argument('--auto', action='store_true', help='Try automatic decryption')
    
    # Find tools command
    find_parser = subparsers.add_parser('find-tools', help='Find tools for a ransomware family')
    find_parser.add_argument('family', help='Ransomware family')
    
    args = parser.parse_args()
    
    # Create wrapper and registry
    registry = DecryptionToolRegistry()
    wrapper = DecryptionToolWrapper(registry)
    
    if args.command == 'scan':
        results = wrapper.scan_directory(args.directory, not args.no_recursive)
        if results:
            print("Potentially encrypted files found:")
            for family, files in results.items():
                print(f"\n{family} ({len(files)} files):")
                for file in files[:10]:  # Limit to 10 files per family
                    print(f"  {file}")
                if len(files) > 10:
                    print(f"  ...and {len(files) - 10} more files")
                    
            # Suggest tools
            print("\nAvailable decryption tools:")
            for family in results.keys():
                tools = wrapper.find_decryption_tools(family)
                if tools:
                    print(f"\n{family}:")
                    for tool in tools:
                        status = "Installed" if tool.get('installed', False) else "Available"
                        print(f"  {tool['id']}: {tool['name']} - {status}")
                else:
                    print(f"\n{family}: No decryption tools available")
        else:
            print("No encrypted files found")
            
    elif args.command == 'decrypt':
        if args.auto:
            if wrapper.attempt_auto_decrypt(args.file, args.output, args.family):
                print("Decryption successful")
            else:
                print("Decryption failed")
        elif args.tool:
            if wrapper.load_tool(args.tool):
                if wrapper.decrypt_file(args.file, args.key, args.output, {'family': args.family} if args.family else None):
                    print("Decryption successful")
                else:
                    print("Decryption failed")
            else:
                print(f"Failed to load tool {args.tool}")
        else:
            print("Either --tool or --auto must be specified")
            
    elif args.command == 'find-tools':
        tools = wrapper.find_decryption_tools(args.family)
        if tools:
            print(f"Tools for {args.family}:")
            for tool in tools:
                status = "Installed" if tool.get('installed', False) else "Available"
                print(f"  {tool['id']}: {tool['name']} - {status}")
                print(f"    {tool['description']}")
                print(f"    URL: {tool['url']}")
                platforms = ', '.join(tool.get('platforms', []))
                print(f"    Platforms: {platforms}")
                print()
        else:
            print(f"No decryption tools found for {args.family}")
            
    else:
        parser.print_help()
    
if __name__ == "__main__":
    main()