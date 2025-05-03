#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Decryption Tool Integration

This module provides an integration layer between the enhanced tool registry
and the ransomware recovery system. It extends the capabilities of the
standard tool registry with:

- Support for multiple tool repositories
- Advanced compatibility checking
- Sophisticated version management
- Dynamic tool discovery and installation
- Support for containerized execution
- Enhanced command-line argument handling
- Cross-platform compatibility optimizations
"""

import os
import sys
import json
import logging
import tempfile
import platform
import subprocess
from typing import Dict, List, Tuple, Set, Optional, Any, Union
from pathlib import Path
import shutil
import datetime

# Add external directory to path for imports
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'external'))

# Import components
from external.enhanced_tool_registry import EnhancedToolRegistry
from external.tool_registry import DecryptionToolRegistry
from external.tool_wrapper import DecryptionToolWrapper

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('EnhancedToolIntegration')

class EnhancedToolIntegration:
    """
    Integration layer between enhanced tool registry and ransomware recovery system.
    """
    
    def __init__(self, work_dir: Optional[str] = None, 
                use_containers: bool = False, force_no_gui: bool = False):
        """
        Initialize the enhanced tool integration.
        
        Args:
            work_dir: Working directory for temporary files
            use_containers: Use containerized execution where available
            force_no_gui: Force non-GUI mode for tools that support it
        """
        self.work_dir = work_dir or tempfile.mkdtemp(prefix="enhanced_tool_integration_")
        self.platform = platform.system().lower()
        self.use_containers = use_containers
        self.force_no_gui = force_no_gui
        
        # Create tool output directory
        self.output_dir = os.path.join(self.work_dir, 'outputs')
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Create tool temp directory
        self.temp_dir = os.path.join(self.work_dir, 'temp')
        os.makedirs(self.temp_dir, exist_ok=True)
        
        # Initialize tool registries and wrapper
        self.enhanced_registry = EnhancedToolRegistry()
        self.standard_registry = DecryptionToolRegistry()
        self.tool_wrapper = DecryptionToolWrapper(self.standard_registry)
        
        # Track currently active tool
        self.active_registry = None
        self.active_tool_id = None
        self.active_tool = None
        self.active_container = None
        
        logger.info(f"Enhanced Tool Integration initialized in {self.work_dir}")
        
        # Merge registry tools 
        self._merge_registries()
    
    def _merge_registries(self) -> None:
        """Merge tools from the enhanced registry into the standard registry."""
        enhanced_tools = self.enhanced_registry.get_all_tools()
        for tool_id, tool_data in enhanced_tools.items():
            # If tool doesn't already exist in standard registry, add it
            if tool_id not in self.standard_registry.get_all_tools():
                # Extract the fields needed by the standard registry
                standard_tool = {
                    'name': tool_data.get('name', 'Unknown'),
                    'description': tool_data.get('description', ''),
                    'url': tool_data.get('url', ''),
                    'families': tool_data.get('families', []),
                    'platforms': tool_data.get('platforms', []),
                    'type': 'enhanced',  # Mark as coming from the enhanced registry
                    'download_urls': {},  # Will be populated later
                    'installed': tool_data.get('installed', False),
                    'install_path': tool_data.get('install_path', None),
                    'status': 'available'
                }
                
                # Add tool to standard registry
                self.standard_registry.add_tool(tool_id, standard_tool)
                logger.debug(f"Added enhanced tool {tool_id} to standard registry")
                
        logger.info(f"Merged {len(enhanced_tools)} enhanced tools into standard registry")
    
    def synchronize_registries(self) -> Dict[str, int]:
        """
        Synchronize tool registries to ensure consistent state.
        
        Returns:
            Dictionary with counts of added, updated, and removed tools
        """
        result = {
            'added': 0,
            'updated': 0,
            'removed': 0
        }
        
        # First update both registries from their sources
        self.enhanced_registry.update_tool_database()
        self.standard_registry.update_tool_database()
        
        # Merge enhanced tools into standard registry
        enhanced_tools = self.enhanced_registry.get_all_tools()
        standard_tools = self.standard_registry.get_all_tools()
        
        # Add or update tools from enhanced registry
        for tool_id, tool_data in enhanced_tools.items():
            if tool_id in standard_tools:
                # Update existing tool
                standard_tool = {
                    'name': tool_data.get('name', 'Unknown'),
                    'description': tool_data.get('description', ''),
                    'url': tool_data.get('url', ''),
                    'families': tool_data.get('families', []),
                    'platforms': tool_data.get('platforms', []),
                    'type': 'enhanced',  # Mark as coming from the enhanced registry
                    'status': 'available'
                }
                
                # Preserve installed state if already installed
                if standard_tools[tool_id].get('installed', False):
                    standard_tool['installed'] = True
                    standard_tool['install_path'] = standard_tools[tool_id].get('install_path')
                else:
                    standard_tool['installed'] = tool_data.get('installed', False)
                    standard_tool['install_path'] = tool_data.get('install_path')
                
                self.standard_registry.update_tool(tool_id, standard_tool)
                result['updated'] += 1
            else:
                # Add new tool
                standard_tool = {
                    'name': tool_data.get('name', 'Unknown'),
                    'description': tool_data.get('description', ''),
                    'url': tool_data.get('url', ''),
                    'families': tool_data.get('families', []),
                    'platforms': tool_data.get('platforms', []),
                    'type': 'enhanced',  # Mark as coming from the enhanced registry
                    'download_urls': {},  # Will be populated later
                    'installed': tool_data.get('installed', False),
                    'install_path': tool_data.get('install_path', None),
                    'status': 'available'
                }
                
                self.standard_registry.add_tool(tool_id, standard_tool)
                result['added'] += 1
        
        logger.info(f"Synchronized registries: {result['added']} added, {result['updated']} updated")
        return result
    
    def get_all_tools(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all tools from both registries.
        
        Returns:
            Dictionary of all tools
        """
        # Get tools from both registries
        enhanced_tools = self.enhanced_registry.get_all_tools()
        standard_tools = self.standard_registry.get_all_tools()
        
        # Merge tools, prioritizing enhanced registry versions
        combined_tools = {}
        combined_tools.update(standard_tools)  # Add all standard tools
        combined_tools.update(enhanced_tools)  # Override with enhanced tools
        
        return combined_tools
    
    def search_tools(self, query: str) -> List[Dict[str, Any]]:
        """
        Search for tools matching a query.
        
        Args:
            query: Search query (family name, tool name, etc.)
            
        Returns:
            List of matching tools
        """
        query = query.lower()
        matching_tools = []
        
        # Search in enhanced registry first
        for tool_id, tool in self.enhanced_registry.get_all_tools().items():
            if (query in tool_id.lower() or 
                query in tool.get('name', '').lower() or
                query in tool.get('description', '').lower() or
                any(query in family.lower() for family in tool.get('families', []))):
                
                tool_copy = dict(tool)
                tool_copy['id'] = tool_id
                tool_copy['source'] = 'enhanced'
                matching_tools.append(tool_copy)
        
        # Also search in standard registry
        for tool_id, tool in self.standard_registry.get_all_tools().items():
            # Skip tools that are already included from enhanced registry
            if any(t['id'] == tool_id for t in matching_tools):
                continue
                
            if (query in tool_id.lower() or 
                query in tool.get('name', '').lower() or
                query in tool.get('description', '').lower() or
                any(query in family.lower() for family in tool.get('families', []))):
                
                tool_copy = dict(tool)
                tool_copy['id'] = tool_id
                tool_copy['source'] = 'standard'
                matching_tools.append(tool_copy)
        
        return matching_tools
    
    def find_tools_for_family(self, family: str) -> List[Dict[str, Any]]:
        """
        Find tools for a specific ransomware family.
        
        Args:
            family: Ransomware family name
            
        Returns:
            List of suitable tools
        """
        tools = []
        
        # First search in enhanced registry
        enhanced_tools = self.enhanced_registry.find_tools_for_family(family)
        for tool in enhanced_tools:
            tool['source'] = 'enhanced'
            tools.append(tool)
        
        # Then search in standard registry
        standard_tools = self.standard_registry.get_tools_for_family(family)
        for tool in standard_tools:
            # Skip tools that are already included from enhanced registry
            if any(t['id'] == tool['id'] for t in tools):
                continue
                
            tool['source'] = 'standard'
            tools.append(tool)
        
        # Sort tools by installed status (installed first) and then by source
        return sorted(tools, key=lambda t: (not t.get('installed', False), t['source'] != 'enhanced'))
    
    def get_installed_tools(self) -> List[Dict[str, Any]]:
        """
        Get all installed tools.
        
        Returns:
            List of installed tools
        """
        tools = []
        
        # Get installed tools from enhanced registry
        enhanced_installed = self.enhanced_registry.get_installed_tools()
        for tool in enhanced_installed:
            tool['source'] = 'enhanced'
            tools.append(tool)
        
        # Get installed tools from standard registry
        standard_installed = self.standard_registry.get_installed_tools()
        for tool in standard_installed:
            # Skip tools that are already included from enhanced registry
            if any(t['id'] == tool['id'] for t in tools):
                continue
                
            tool['source'] = 'standard'
            tools.append(tool)
        
        return tools
    
    def install_tool(self, tool_id: str, family: Optional[str] = None) -> Optional[str]:
        """
        Install a tool.
        
        Args:
            tool_id: Tool ID to install
            family: Optional ransomware family for tool variant
            
        Returns:
            Path to installed tool or None if installation failed
        """
        logger.info(f"Installing tool: {tool_id}")
        
        # Try to install from enhanced registry first
        enhanced_tool = self.enhanced_registry.get_tool(tool_id)
        if enhanced_tool:
            install_path = self.enhanced_registry.download_tool(tool_id, family)
            if install_path:
                logger.info(f"Tool {tool_id} installed from enhanced registry: {install_path}")
                
                # Also update standard registry
                self.standard_registry.update_tool(tool_id, {
                    'installed': True,
                    'install_path': install_path
                })
                
                return install_path
        
        # If not found or installation failed, try standard registry
        standard_tool = self.standard_registry.get_tool(tool_id)
        if standard_tool:
            install_path = self.standard_registry.download_tool(tool_id, family)
            if install_path:
                logger.info(f"Tool {tool_id} installed from standard registry: {install_path}")
                
                # Also update enhanced registry if the tool exists there
                if enhanced_tool:
                    self.enhanced_registry.update_tool(tool_id, {
                        'installed': True,
                        'install_path': install_path
                    })
                
                return install_path
        
        logger.error(f"Tool {tool_id} not found or installation failed")
        return None
    
    def load_tool(self, tool_id: str) -> bool:
        """
        Load a tool for use.
        
        Args:
            tool_id: Tool ID to load
            
        Returns:
            True if tool loaded successfully, False otherwise
        """
        logger.info(f"Loading tool: {tool_id}")
        
        # Reset active tool
        self.active_registry = None
        self.active_tool_id = None
        self.active_tool = None
        self.active_container = None
        
        # Try loading from enhanced registry first
        enhanced_tool = self.enhanced_registry.get_tool(tool_id)
        if enhanced_tool:
            if not enhanced_tool.get('installed', False):
                # Try to install
                if not self.install_tool(tool_id):
                    logger.error(f"Tool {tool_id} is not installed and installation failed")
                    return False
                    
                # Reload after installation
                enhanced_tool = self.enhanced_registry.get_tool(tool_id)
            
            # Set active tool
            self.active_registry = 'enhanced'
            self.active_tool_id = tool_id
            self.active_tool = enhanced_tool
            
            logger.info(f"Tool {tool_id} loaded from enhanced registry")
            return True
        
        # If not found or loading failed, try standard registry using the wrapper
        if self.tool_wrapper.load_tool(tool_id):
            # Get tool data from wrapper
            self.active_registry = 'standard'
            self.active_tool_id = tool_id
            self.active_tool = self.standard_registry.get_tool(tool_id)
            
            logger.info(f"Tool {tool_id} loaded from standard registry")
            return True
        
        logger.error(f"Tool {tool_id} not found or loading failed")
        return False
    
    def prepare_container(self, tool_id: str) -> bool:
        """
        Prepare a Docker container for running a tool (if supported).
        
        Args:
            tool_id: Tool ID
            
        Returns:
            True if container prepared successfully, False otherwise
        """
        if not self.use_containers:
            logger.info("Container execution disabled")
            return False
            
        # Check if Docker is available
        if not self._is_command_available('docker'):
            logger.error("Docker command not available, cannot use containerized execution")
            return False
            
        # Get tool data
        tool = None
        if self.enhanced_registry.get_tool(tool_id):
            tool = self.enhanced_registry.get_tool(tool_id)
        elif self.standard_registry.get_tool(tool_id):
            tool = self.standard_registry.get_tool(tool_id)
            
        if not tool:
            logger.error(f"Tool {tool_id} not found")
            return False
            
        # Check if tool supports containerized execution
        if not tool.get('container_image'):
            logger.info(f"Tool {tool_id} does not have a container image defined")
            return False
            
        container_image = tool.get('container_image')
        
        # Pull container image
        logger.info(f"Pulling container image: {container_image}")
        pull_cmd = ['docker', 'pull', container_image]
        pull_result = subprocess.run(pull_cmd, capture_output=True, text=True)
        
        if pull_result.returncode != 0:
            logger.error(f"Failed to pull container image: {pull_result.stderr}")
            return False
            
        # Generate a unique container name
        container_name = f"decryptor_{tool_id.replace('/', '_')}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        self.active_container = container_name
        
        logger.info(f"Container {container_name} prepared for tool {tool_id}")
        return True
    
    def decrypt_file(self, file_path: str, key_file: Optional[str] = None,
                    output_file: Optional[str] = None, options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Decrypt a file using the currently loaded tool.
        
        Args:
            file_path: Path to the encrypted file
            key_file: Optional path to a key file
            output_file: Optional path for decrypted output
            options: Additional options for the decryption process
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        if not self.active_tool_id or not self.active_tool:
            logger.error("No tool loaded")
            return False
            
        logger.info(f"Decrypting file: {file_path}")
        
        # Set default output file if not specified
        if not output_file:
            base_name = os.path.basename(file_path)
            name, ext = os.path.splitext(base_name)
            output_file = os.path.join(self.output_dir, f"{name}_decrypted{ext}")
            
        # If using enhanced registry
        if self.active_registry == 'enhanced':
            return self._run_enhanced_decryption(file_path, key_file, output_file, options)
        # If using standard registry (use tool wrapper)
        elif self.active_registry == 'standard':
            return self.tool_wrapper.decrypt_file(file_path, key_file, output_file, options)
        else:
            logger.error("Invalid active registry")
            return False
    
    def _run_enhanced_decryption(self, file_path: str, key_file: Optional[str] = None,
                               output_file: Optional[str] = None, 
                               options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Run decryption with a tool from the enhanced registry.
        
        Args:
            file_path: Path to the encrypted file
            key_file: Optional path to a key file
            output_file: Optional path for decrypted output
            options: Additional options for the decryption process
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        if not options:
            options = {}
            
        # Use containerized execution if available and enabled
        if self.use_containers and self.active_tool.get('container_image') and self._is_command_available('docker'):
            return self._run_container_decryption(file_path, key_file, output_file, options)
            
        # Get tool properties
        tool_type = self.active_tool.get('type', 'standalone')
        install_path = self.active_tool.get('install_path')
        
        if not install_path or not os.path.exists(install_path):
            logger.error(f"Tool {self.active_tool_id} is not properly installed")
            return False
            
        # Determine tool-specific handling based on tool properties
        if self.active_tool.get('repository') == 'emsisoft':
            return self._run_emsisoft_decryptor(install_path, file_path, key_file, output_file, options)
        elif self.active_tool.get('repository') == 'kaspersky':
            return self._run_kaspersky_decryptor(install_path, file_path, key_file, output_file, options)
        elif 'nomoreransom' in self.active_tool_id.lower():
            return self._run_nomoreransom_decryptor(install_path, file_path, key_file, output_file, options)
        elif tool_type == 'github':
            return self._run_github_decryptor(install_path, file_path, key_file, output_file, options)
        elif tool_type == 'custom':
            command_template = self.active_tool.get('command_template')
            if command_template:
                return self._run_custom_decryptor(install_path, command_template, file_path, key_file, output_file, options)
        
        # If no specialized handler, use generic approach
        return self._run_generic_decryptor(install_path, file_path, key_file, output_file, options)
    
    def _run_container_decryption(self, file_path: str, key_file: Optional[str] = None,
                                output_file: Optional[str] = None, 
                                options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Run decryption in a Docker container.
        
        Args:
            file_path: Path to the encrypted file
            key_file: Optional path to a key file
            output_file: Optional path for decrypted output
            options: Additional options for the decryption process
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        logger.info("Running decryption in container")
        
        if not self.active_container:
            # Prepare container if not already done
            if not self.prepare_container(self.active_tool_id):
                logger.error("Failed to prepare container")
                return False
        
        container_image = self.active_tool.get('container_image')
        container_command = self.active_tool.get('container_command', '/app/decrypt')
        
        # Create volume mounts for input/output files
        input_dir = os.path.dirname(os.path.abspath(file_path))
        output_dir = os.path.dirname(os.path.abspath(output_file))
        
        # Build Docker command
        cmd = [
            'docker', 'run', '--rm',
            '-v', f"{input_dir}:/input",
            '-v', f"{output_dir}:/output"
        ]
        
        # Add key file volume if needed
        if key_file:
            key_dir = os.path.dirname(os.path.abspath(key_file))
            cmd.extend(['-v', f"{key_dir}:/keys"])
            
        # Add environment variables for options
        for key, value in options.items():
            cmd.extend(['-e', f"{key.upper()}={value}"])
            
        # Add container name and image
        cmd.extend(['--name', self.active_container, container_image])
        
        # Add container command
        cmd.append(container_command)
        
        # Add file paths (adjusted for in-container paths)
        cmd.append(f"/input/{os.path.basename(file_path)}")
        cmd.append(f"/output/{os.path.basename(output_file)}")
        
        # Add key file if specified
        if key_file:
            cmd.append(f"/keys/{os.path.basename(key_file)}")
            
        # Run container
        try:
            logger.info(f"Running container command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"Container execution failed: {result.stderr}")
                return False
                
            logger.info(f"Container execution output: {result.stdout}")
            
            # Check if output file was created
            if not os.path.exists(output_file):
                logger.error(f"Output file not created: {output_file}")
                return False
                
            return True
            
        except Exception as e:
            logger.error(f"Error running container: {e}")
            return False
    
    def _run_emsisoft_decryptor(self, install_path: str, file_path: str,
                              key_file: Optional[str] = None, output_file: Optional[str] = None,
                              options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Run an Emsisoft decryptor tool.
        
        Args:
            install_path: Path to the decryptor executable
            file_path: Path to the encrypted file
            key_file: Optional path to a key file
            output_file: Optional path for decrypted output
            options: Additional options for the decryption process
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        logger.info(f"Running Emsisoft decryptor: {install_path}")
        
        # Emsisoft decryptors are GUI-based on Windows
        if self.platform == 'windows' and not self.force_no_gui:
            # Launch GUI and guide the user
            logger.info("Launching Emsisoft decryptor GUI. Please follow the prompts.")
            
            # Prepare and show instructions
            instructions = [
                "1. When the Emsisoft decryptor opens, follow these steps:",
                f"2. Select the file: {file_path}",
                "3. If asked for encryption ID or key file:"
            ]
            
            if key_file:
                instructions.append(f"   - Select the key file: {key_file}")
            else:
                instructions.append("   - Use automatic detection or enter the ID if known")
                
            if output_file:
                instructions.append(f"4. Set the output location to: {output_file}")
                
            instructions.append("5. Start the decryption process and wait for completion")
            
            for line in instructions:
                logger.info(line)
                
            # Launch the decryptor
            subprocess.Popen([install_path])
            
            # Wait for user confirmation
            input("Press Enter when decryption is complete...")
            
            # Check if output file exists
            if output_file and os.path.exists(output_file):
                logger.info(f"Decryption completed successfully: {output_file}")
                return True
            elif not output_file:
                logger.info("Decryption process completed. Check the output location manually.")
                return True
            else:
                logger.warning(f"Output file not found: {output_file}")
                return False
        else:
            # Try command-line mode for Emsisoft decryptors that support it
            cmd = [install_path, '-console']
            
            # Add file to decrypt
            cmd.append(file_path)
            
            # Add output file if specified
            if output_file:
                cmd.extend(['-output', output_file])
                
            # Add key file if specified
            if key_file:
                cmd.extend(['-key', key_file])
                
            # Run command
            try:
                logger.info(f"Running command: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    logger.error(f"Decryption failed: {result.stderr}")
                    return False
                    
                logger.info(f"Decryption output: {result.stdout}")
                
                # Check if output file was created
                if output_file and not os.path.exists(output_file):
                    logger.error(f"Output file not created: {output_file}")
                    return False
                    
                return True
                
            except Exception as e:
                logger.error(f"Error running Emsisoft decryptor: {e}")
                return False
    
    def _run_kaspersky_decryptor(self, install_path: str, file_path: str,
                               key_file: Optional[str] = None, output_file: Optional[str] = None,
                               options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Run a Kaspersky decryptor tool.
        
        Args:
            install_path: Path to the decryptor executable
            file_path: Path to the encrypted file
            key_file: Optional path to a key file
            output_file: Optional path for decrypted output
            options: Additional options for the decryption process
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        logger.info(f"Running Kaspersky decryptor: {install_path}")
        
        # Kaspersky decryptors are GUI-based on Windows
        if self.platform == 'windows' and not self.force_no_gui:
            # Launch GUI and guide the user
            logger.info("Launching Kaspersky decryptor GUI. Please follow the prompts.")
            
            # Prepare and show instructions
            instructions = [
                "1. When the Kaspersky decryptor opens, follow these steps:",
                f"2. Select the file: {file_path}",
                "3. If asked for a key file:"
            ]
            
            if key_file:
                instructions.append(f"   - Select the key file: {key_file}")
            else:
                instructions.append("   - Use automatic detection if available")
                
            if output_file:
                instructions.append(f"4. Set the output location to: {output_file}")
                
            instructions.append("5. Start the decryption process and wait for completion")
            
            for line in instructions:
                logger.info(line)
                
            # Launch the decryptor
            subprocess.Popen([install_path])
            
            # Wait for user confirmation
            input("Press Enter when decryption is complete...")
            
            # Check if output file exists
            if output_file and os.path.exists(output_file):
                logger.info(f"Decryption completed successfully: {output_file}")
                return True
            elif not output_file:
                logger.info("Decryption process completed. Check the output location manually.")
                return True
            else:
                logger.warning(f"Output file not found: {output_file}")
                return False
        else:
            # Try command-line mode for Kaspersky decryptors that support it
            cmd = [install_path, '-silent']
            
            # Add file to decrypt
            cmd.append(file_path)
            
            # Add output file if specified
            if output_file:
                cmd.extend(['-out', output_file])
                
            # Add key file if specified
            if key_file:
                cmd.extend(['-key', key_file])
                
            # Run command
            try:
                logger.info(f"Running command: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode != 0:
                    logger.error(f"Decryption failed: {result.stderr}")
                    return False
                    
                logger.info(f"Decryption output: {result.stdout}")
                
                # Check if output file was created
                if output_file and not os.path.exists(output_file):
                    logger.error(f"Output file not created: {output_file}")
                    return False
                    
                return True
                
            except Exception as e:
                logger.error(f"Error running Kaspersky decryptor: {e}")
                return False
    
    def _run_nomoreransom_decryptor(self, install_path: str, file_path: str,
                                   key_file: Optional[str] = None, output_file: Optional[str] = None,
                                   options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Run a No More Ransom project decryptor.
        
        Args:
            install_path: Path to the decryptor executable
            file_path: Path to the encrypted file
            key_file: Optional path to a key file
            output_file: Optional path for decrypted output
            options: Additional options for the decryption process
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        logger.info(f"Running No More Ransom decryptor: {install_path}")
        
        # No More Ransom tools are mostly GUI-based on Windows
        if self.platform == 'windows' and not self.force_no_gui:
            # Launch GUI and guide the user
            logger.info("Launching No More Ransom decryptor GUI. Please follow the prompts.")
            
            # Prepare and show instructions
            instructions = [
                "1. When the decryptor opens, follow these steps:",
                f"2. Select the file: {file_path}"
            ]
            
            if key_file:
                instructions.append(f"3. If asked for a key file, select: {key_file}")
                
            if output_file:
                instructions.append(f"4. Set the output location to: {output_file}")
                
            for line in instructions:
                logger.info(line)
                
            # Launch the decryptor
            subprocess.Popen([install_path])
            
            # Wait for user confirmation
            input("Press Enter when decryption is complete...")
            
            # Check if output file exists
            if output_file and os.path.exists(output_file):
                logger.info(f"Decryption completed successfully: {output_file}")
                return True
            elif not output_file:
                logger.info("Decryption process completed. Check the output location manually.")
                return True
            else:
                logger.warning(f"Output file not found: {output_file}")
                return False
        else:
            # Try different command-line argument formats
            cmd_variants = [
                [install_path, '-d', file_path, '-o', output_file or os.path.dirname(file_path)],
                [install_path, '--decrypt', file_path, '--output', output_file or os.path.dirname(file_path)],
                [install_path, file_path, output_file or os.path.dirname(file_path)]
            ]
            
            # Add key file if specified
            if key_file:
                cmd_variants[0].extend(['-k', key_file])
                cmd_variants[1].extend(['--key', key_file])
                cmd_variants[2].append(key_file)
                
            # Try each command variant
            for cmd in cmd_variants:
                try:
                    logger.info(f"Trying command: {' '.join(cmd)}")
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        logger.info(f"Decryption output: {result.stdout}")
                        
                        # Check if output file was created
                        if output_file and os.path.exists(output_file):
                            logger.info(f"Decryption completed successfully: {output_file}")
                            return True
                        elif not output_file:
                            # Look for decrypted files in the same directory
                            input_dir = os.path.dirname(file_path)
                            input_name = os.path.basename(file_path)
                            
                            for filename in os.listdir(input_dir):
                                if filename.startswith(input_name) and filename.endswith('_decrypted'):
                                    logger.info(f"Found decrypted file: {os.path.join(input_dir, filename)}")
                                    return True
                            
                            logger.info("Decryption process completed. Check for decrypted files manually.")
                            return True
                except Exception:
                    # Continue to next variant
                    pass
                    
            logger.error("All command variants failed")
            return False
    
    def _run_github_decryptor(self, install_path: str, file_path: str,
                            key_file: Optional[str] = None, output_file: Optional[str] = None,
                            options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Run a GitHub-based decryption tool.
        
        Args:
            install_path: Path to the repository directory
            file_path: Path to the encrypted file
            key_file: Optional path to a key file
            output_file: Optional path for decrypted output
            options: Additional options for the decryption process
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        logger.info(f"Running GitHub decryptor: {install_path}")
        
        # Look for common entry points
        entry_points = [
            os.path.join(install_path, 'decrypt.py'),
            os.path.join(install_path, 'decryptor.py'),
            os.path.join(install_path, 'main.py'),
            os.path.join(install_path, 'run.py')
        ]
        
        # Check if readme contains execution instructions
        readme_paths = [
            os.path.join(install_path, 'README.md'),
            os.path.join(install_path, 'README'),
            os.path.join(install_path, 'README.txt')
        ]
        
        for readme_path in readme_paths:
            if os.path.exists(readme_path):
                try:
                    with open(readme_path, 'r') as f:
                        readme_content = f.read()
                        
                    # Look for execution commands
                    if '```' in readme_content:
                        # Extract code blocks
                        import re
                        code_blocks = re.findall(r'```(?:bash|shell|python)?\n(.*?)\n```', readme_content, re.DOTALL)
                        
                        for block in code_blocks:
                            if ('python ' in block or 'python3 ' in block) and ('.py' in block):
                                # Extract script path
                                match = re.search(r'python[3]?\s+([^\s]+\.py)', block)
                                if match:
                                    script_path = match.group(1)
                                    # Handle relative path
                                    if not os.path.isabs(script_path):
                                        script_path = os.path.join(install_path, script_path)
                                        
                                    if os.path.exists(script_path):
                                        entry_points.insert(0, script_path)
                except Exception:
                    pass
        
        # Try each entry point
        for entry_point in entry_points:
            if os.path.exists(entry_point):
                logger.info(f"Found entry point: {entry_point}")
                
                # Build command
                cmd = [sys.executable, entry_point]
                
                # Add file to decrypt
                cmd.append(file_path)
                
                # Add output file if specified
                if output_file:
                    if entry_point.endswith('main.py') or entry_point.endswith('run.py'):
                        cmd.extend(['--output', output_file])
                    else:
                        cmd.extend(['-o', output_file])
                        
                # Add key file if specified
                if key_file:
                    if entry_point.endswith('main.py') or entry_point.endswith('run.py'):
                        cmd.extend(['--key', key_file])
                    else:
                        cmd.extend(['-k', key_file])
                        
                # Add any additional options
                if options:
                    for key, value in options.items():
                        if key in ['family', 'variant', 'version']:
                            cmd.extend([f"--{key}", str(value)])
                            
                # Run command
                try:
                    logger.info(f"Running command: {' '.join(cmd)}")
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        logger.info(f"Decryption output: {result.stdout}")
                        
                        # Check if output file was created
                        if output_file and os.path.exists(output_file):
                            logger.info(f"Decryption completed successfully: {output_file}")
                            return True
                        elif not output_file:
                            # Look for decrypted files in the same directory
                            input_dir = os.path.dirname(file_path)
                            input_name = os.path.basename(file_path)
                            
                            for filename in os.listdir(input_dir):
                                if filename.startswith(os.path.splitext(input_name)[0]) and "_decrypted" in filename:
                                    logger.info(f"Found decrypted file: {os.path.join(input_dir, filename)}")
                                    return True
                            
                            logger.info("Decryption process completed. Check for decrypted files manually.")
                            return True
                    else:
                        logger.warning(f"Decryption failed with entry point {entry_point}: {result.stderr}")
                except Exception as e:
                    logger.warning(f"Error running entry point {entry_point}: {e}")
                    
        logger.error("All entry points failed")
        return False
    
    def _run_custom_decryptor(self, install_path: str, command_template: str, file_path: str,
                            key_file: Optional[str] = None, output_file: Optional[str] = None,
                            options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Run a custom decryptor with a command template.
        
        Args:
            install_path: Path to the decryptor executable
            command_template: Command template with placeholders
            file_path: Path to the encrypted file
            key_file: Optional path to a key file
            output_file: Optional path for decrypted output
            options: Additional options for the decryption process
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        logger.info(f"Running custom decryptor: {install_path}")
        
        # Replace placeholders in command template
        cmd_str = command_template.replace('{TOOL_PATH}', install_path)
        cmd_str = cmd_str.replace('{INPUT_FILE}', file_path)
        
        if output_file:
            cmd_str = cmd_str.replace('{OUTPUT_FILE}', output_file)
        else:
            # Use default output location
            base_name = os.path.basename(file_path)
            name, ext = os.path.splitext(base_name)
            default_output = os.path.join(os.path.dirname(file_path), f"{name}_decrypted{ext}")
            cmd_str = cmd_str.replace('{OUTPUT_FILE}', default_output)
            
        if key_file:
            cmd_str = cmd_str.replace('{KEY_FILE}', key_file)
        else:
            # Remove key file parameter if not provided
            cmd_str = re.sub(r'\s+\-\-?[kK](?:ey)?\s+\{KEY_FILE\}', '', cmd_str)
            
        # Add options
        if options:
            options_str = ''
            for key, value in options.items():
                if len(key) == 1:
                    options_str += f" -{key} {value}"
                else:
                    options_str += f" --{key} {value}"
                    
            cmd_str = cmd_str.replace('{OPTIONS}', options_str)
        else:
            cmd_str = cmd_str.replace('{OPTIONS}', '')
            
        # Convert to list
        cmd = cmd_str.split()
        
        # Run command
        try:
            logger.info(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Decryption output: {result.stdout}")
                
                # Check if output file was created
                if output_file and os.path.exists(output_file):
                    logger.info(f"Decryption completed successfully: {output_file}")
                    return True
                elif not output_file:
                    logger.info("Decryption process completed. Check for decrypted files manually.")
                    return True
                else:
                    logger.warning(f"Output file not found: {output_file}")
                    return False
            else:
                logger.error(f"Decryption failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error running custom decryptor: {e}")
            return False
    
    def _run_generic_decryptor(self, install_path: str, file_path: str,
                             key_file: Optional[str] = None, output_file: Optional[str] = None,
                             options: Optional[Dict[str, Any]] = None) -> bool:
        """
        Run a generic decryptor with best-effort parameters.
        
        Args:
            install_path: Path to the decryptor executable
            file_path: Path to the encrypted file
            key_file: Optional path to a key file
            output_file: Optional path for decrypted output
            options: Additional options for the decryption process
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        logger.info(f"Running generic decryptor: {install_path}")
        
        # Attempt interactive execution if GUI-based
        if (self.platform == 'windows' and not self.force_no_gui and 
            (install_path.endswith('.exe') or os.path.isdir(install_path))):
            
            try:
                # Try to launch the tool
                if os.path.isdir(install_path):
                    # Look for executable
                    for filename in os.listdir(install_path):
                        if filename.endswith('.exe'):
                            exe_path = os.path.join(install_path, filename)
                            subprocess.Popen([exe_path])
                            break
                else:
                    subprocess.Popen([install_path])
                    
                # Provide guidance
                logger.info("Launched decryption tool. Please follow the tool's interface.")
                logger.info(f"Input file: {file_path}")
                
                if key_file:
                    logger.info(f"Key file: {key_file}")
                    
                if output_file:
                    logger.info(f"Output file: {output_file}")
                    
                # Wait for user confirmation
                input("Press Enter when decryption is complete...")
                
                # Check if output file exists
                if output_file and os.path.exists(output_file):
                    logger.info(f"Decryption completed successfully: {output_file}")
                    return True
                elif not output_file:
                    logger.info("Decryption process completed. Check for decrypted files manually.")
                    return True
                else:
                    # Check for decrypted files in the same directory
                    input_dir = os.path.dirname(file_path)
                    input_name = os.path.basename(file_path)
                    
                    for filename in os.listdir(input_dir):
                        if filename.startswith(os.path.splitext(input_name)[0]) and "_decrypted" in filename:
                            logger.info(f"Found decrypted file: {os.path.join(input_dir, filename)}")
                            return True
                            
                    logger.warning(f"Output file not found: {output_file}")
                    return False
                    
            except Exception as e:
                logger.warning(f"Error launching interactive decryptor: {e}")
        
        # Fall back to command-line execution
        cmd = [install_path]
        
        # Add file to decrypt
        cmd.append(file_path)
        
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
                    
        # Run command
        try:
            logger.info(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Decryption output: {result.stdout}")
                return True
            else:
                logger.error(f"Decryption failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error running generic decryptor: {e}")
            return False
    
    def _is_command_available(self, command: str) -> bool:
        """
        Check if a command is available on the system.
        
        Args:
            command: Command to check
            
        Returns:
            True if command is available, False otherwise
        """
        try:
            if platform.system() == 'Windows':
                subprocess.run(['where', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            else:
                subprocess.run(['which', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return True
        except subprocess.SubprocessError:
            return False
    
    def attempt_auto_decrypt(self, file_path: str, output_file: Optional[str] = None,
                            family: Optional[str] = None) -> bool:
        """
        Attempt to automatically decrypt a file using available tools.
        
        Args:
            file_path: Path to the encrypted file
            output_file: Optional path for decrypted output
            family: Optional ransomware family hint
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return False
            
        logger.info(f"Attempting automatic decryption of {file_path}")
        
        # Try to detect family if not provided
        if not family:
            family = self._detect_family(file_path)
            if family:
                logger.info(f"Detected ransomware family: {family}")
            else:
                logger.warning("Could not detect ransomware family")
                family = "unknown"
                
        # Find suitable tools
        tools = self.find_tools_for_family(family)
        if not tools:
            logger.error(f"No tools found for family: {family}")
            return False
            
        # Try each tool
        for tool in tools:
            tool_id = tool['id']
            logger.info(f"Trying tool: {tool['name']} ({tool_id})")
            
            # Load tool
            if not self.load_tool(tool_id):
                logger.warning(f"Failed to load tool {tool_id}")
                continue
                
            # Try decryption
            success = self.decrypt_file(file_path, output_file=output_file, options={'family': family})
            if success:
                logger.info(f"Decryption successful with tool: {tool_id}")
                return True
                
            logger.warning(f"Decryption failed with tool: {tool_id}")
            
        # If all tools failed, try generic approach with standard wrapper
        logger.info("Trying standard tool wrapper with auto-decrypt mode")
        return self.tool_wrapper.attempt_auto_decrypt(file_path, output_file, family)
    
    def _detect_family(self, file_path: str) -> Optional[str]:
        """
        Detect ransomware family from file characteristics.
        
        Args:
            file_path: Path to the encrypted file
            
        Returns:
            Detected family name or None
        """
        # Use file extension
        _, ext = os.path.splitext(file_path)
        if ext:
            ext = ext.lower()
            
            # Common ransomware extensions
            extension_map = {
                '.locked': 'LockBit',
                '.lockbit': 'LockBit',
                '.lock': 'LockBit',
                '.wncry': 'WannaCry',
                '.wcry': 'WannaCry',
                '.wncryt': 'WannaCry',
                '.crypt': 'Conti',
                '.conti': 'Conti',
                '.ryuk': 'Ryuk',
                '.ryk': 'Ryuk',
                '.revil': 'REvil',
                '.sodinokibi': 'REvil',
                '.sodin': 'REvil',
                '.djvu': 'STOP',
                '.phobos': 'Phobos',
                '.hive': 'Hive',
                '.blackcat': 'BlackCat',
                '.bc': 'BlackCat',
                '.gandcrab': 'GandCrab',
                '.maze': 'Maze'
            }
            
            if ext in extension_map:
                return extension_map[ext]
                
        # Check file content
        try:
            with open(file_path, 'rb') as f:
                content = f.read(4096)  # Read first 4KB
                
                # Look for known markers
                if b'WANACRY!' in content:
                    return 'WannaCry'
                elif b'lockbit' in content.lower() or b'LockBit' in content:
                    return 'LockBit'
                elif b'conti' in content.lower():
                    return 'Conti'
                elif b'gandcrab' in content.lower():
                    return 'GandCrab'
                elif b'ryuk' in content.lower():
                    return 'Ryuk'
                    
        except Exception:
            pass
            
        # Check if there's a ransom note in the same directory
        try:
            directory = os.path.dirname(file_path)
            for filename in os.listdir(directory):
                lower_name = filename.lower()
                
                if 'read' in lower_name and 'me' in lower_name:
                    note_path = os.path.join(directory, filename)
                    with open(note_path, 'rb') as f:
                        note_content = f.read()
                        
                        if b'lockbit' in note_content.lower():
                            return 'LockBit'
                        elif b'ryuk' in note_content.lower():
                            return 'Ryuk'
                        elif b'wannacry' in note_content.lower() or b'wanacry' in note_content.lower():
                            return 'WannaCry'
                        elif b'gandcrab' in note_content.lower():
                            return 'GandCrab'
                        elif b'conti' in note_content.lower():
                            return 'Conti'
                        elif b'revil' in note_content.lower() or b'sodinokibi' in note_content.lower():
                            return 'REvil'
                        
        except Exception:
            pass
            
        # Ask the tool wrapper to detect
        return self.tool_wrapper._detect_ransomware_family(file_path)
    
    def batch_decrypt(self, files: List[str], tool_id: Optional[str] = None,
                    key_file: Optional[str] = None, output_dir: Optional[str] = None,
                    options: Optional[Dict[str, Any]] = None) -> Dict[str, bool]:
        """
        Decrypt multiple files with the same tool and settings.
        
        Args:
            files: List of files to decrypt
            tool_id: Optional tool ID to use
            key_file: Optional path to a key file
            output_dir: Optional directory for output files
            options: Additional options for the decryption process
            
        Returns:
            Dictionary mapping file paths to decryption success status
        """
        if not files:
            logger.error("No files provided for batch decryption")
            return {}
            
        logger.info(f"Batch decrypting {len(files)} files")
        
        # Create or use output directory
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        else:
            output_dir = self.output_dir
            
        # Results tracking
        results = {}
        
        # Load tool if specified
        if tool_id:
            if not self.load_tool(tool_id):
                logger.error(f"Failed to load tool {tool_id}")
                return {file: False for file in files}
                
        # Process each file
        for file_path in files:
            if not os.path.exists(file_path):
                logger.warning(f"File not found: {file_path}")
                results[file_path] = False
                continue
                
            # Generate output filename
            base_name = os.path.basename(file_path)
            name, ext = os.path.splitext(base_name)
            output_file = os.path.join(output_dir, f"{name}_decrypted{ext}")
            
            # Decrypt file
            if tool_id:
                # Use specified tool
                success = self.decrypt_file(file_path, key_file, output_file, options)
            else:
                # Use auto-decrypt
                success = self.attempt_auto_decrypt(file_path, output_file, options.get('family') if options else None)
                
            results[file_path] = success
            
            if success:
                logger.info(f"Successfully decrypted: {file_path} -> {output_file}")
            else:
                logger.warning(f"Failed to decrypt: {file_path}")
                
        return results
    
    def check_for_updates(self) -> Dict[str, List[str]]:
        """
        Check for updates to installed tools.
        
        Returns:
            Dictionary mapping sources to lists of tool IDs with updates
        """
        updates = {
            'enhanced': [],
            'standard': []
        }
        
        # Check enhanced registry
        enhanced_updates = self.enhanced_registry.check_tool_updates()
        for tool_id, has_update in enhanced_updates.items():
            if has_update:
                updates['enhanced'].append(tool_id)
                
        # Check standard registry
        standard_updates = self.standard_registry.check_tool_updates()
        for tool_id, has_update in standard_updates.items():
            if has_update and tool_id not in updates['enhanced']:
                updates['standard'].append(tool_id)
                
        logger.info(f"Found {len(updates['enhanced']) + len(updates['standard'])} tools with updates")
        return updates
    
    def update_tool(self, tool_id: str) -> bool:
        """
        Update a specific tool.
        
        Args:
            tool_id: Tool ID to update
            
        Returns:
            True if update succeeded, False otherwise
        """
        logger.info(f"Updating tool: {tool_id}")
        
        # Check if tool exists in enhanced registry
        if tool_id in self.enhanced_registry.get_all_tools():
            # Uninstall and reinstall
            tool = self.enhanced_registry.get_tool(tool_id)
            if tool.get('installed', False):
                install_path = tool.get('install_path')
                if install_path and os.path.exists(install_path):
                    if os.path.isdir(install_path):
                        shutil.rmtree(install_path)
                    else:
                        os.remove(install_path)
                        
            # Install tool
            install_path = self.install_tool(tool_id)
            return install_path is not None
            
        # If not in enhanced registry, try standard registry
        elif tool_id in self.standard_registry.get_all_tools():
            # Download tool
            install_path = self.standard_registry.download_tool(tool_id)
            return install_path is not None
            
        logger.error(f"Tool {tool_id} not found")
        return False
    
    def get_tool_info(self, tool_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a specific tool.
        
        Args:
            tool_id: Tool ID
            
        Returns:
            Dictionary with tool information or None if not found
        """
        # Check enhanced registry first
        if tool_id in self.enhanced_registry.get_all_tools():
            tool = dict(self.enhanced_registry.get_tool(tool_id))
            tool['id'] = tool_id
            tool['source'] = 'enhanced'
            return tool
            
        # Check standard registry
        if tool_id in self.standard_registry.get_all_tools():
            tool = dict(self.standard_registry.get_tool(tool_id))
            tool['id'] = tool_id
            tool['source'] = 'standard'
            return tool
            
        return None


def main():
    """Command-line interface for the enhanced tool integration."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced Decryption Tool Integration")
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # List tools command
    list_parser = subparsers.add_parser('list', help='List available tools')
    list_parser.add_argument('--family', '-f', help='Filter by ransomware family')
    list_parser.add_argument('--installed', '-i', action='store_true', help='Show only installed tools')
    list_parser.add_argument('--search', '-s', help='Search for tools by name or keyword')
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('file', help='File to decrypt')
    decrypt_parser.add_argument('--tool', '-t', help='Tool ID to use')
    decrypt_parser.add_argument('--family', '-f', help='Ransomware family')
    decrypt_parser.add_argument('--key', '-k', help='Path to key file')
    decrypt_parser.add_argument('--output', '-o', help='Output path')
    decrypt_parser.add_argument('--auto', '-a', action='store_true', help='Try automatic decryption')
    decrypt_parser.add_argument('--container', '-c', action='store_true', help='Use containerized execution')
    decrypt_parser.add_argument('--no-gui', '-ng', action='store_true', help='Force non-GUI mode')
    
    # Batch decrypt command
    batch_parser = subparsers.add_parser('batch', help='Batch decrypt multiple files')
    batch_parser.add_argument('files', nargs='+', help='Files to decrypt')
    batch_parser.add_argument('--tool', '-t', help='Tool ID to use')
    batch_parser.add_argument('--family', '-f', help='Ransomware family')
    batch_parser.add_argument('--key', '-k', help='Path to key file')
    batch_parser.add_argument('--output-dir', '-o', help='Output directory')
    batch_parser.add_argument('--auto', '-a', action='store_true', help='Try automatic decryption')
    
    # Install command
    install_parser = subparsers.add_parser('install', help='Install a tool')
    install_parser.add_argument('tool_id', help='Tool ID to install')
    install_parser.add_argument('--family', '-f', help='Ransomware family variant')
    
    # Update command
    update_parser = subparsers.add_parser('update', help='Update tools')
    update_parser.add_argument('--tool', '-t', help='Tool ID to update')
    update_parser.add_argument('--check', '-c', action='store_true', help='Check for updates only')
    update_parser.add_argument('--all', '-a', action='store_true', help='Update all installed tools')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show tool information')
    info_parser.add_argument('tool_id', help='Tool ID')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Create integration
    integrator = EnhancedToolIntegration()
    
    if args.command == 'list':
        # List tools
        if args.search:
            tools = integrator.search_tools(args.search)
            print(f"Found {len(tools)} tools matching '{args.search}':")
        elif args.family:
            tools = integrator.find_tools_for_family(args.family)
            print(f"Found {len(tools)} tools for {args.family}:")
        elif args.installed:
            tools = integrator.get_installed_tools()
            print(f"Found {len(tools)} installed tools:")
        else:
            all_tools = integrator.get_all_tools()
            tools = []
            for tool_id, tool in all_tools.items():
                tool_copy = dict(tool)
                tool_copy['id'] = tool_id
                tools.append(tool_copy)
            print(f"Found {len(tools)} total tools:")
            
        # Display tools
        for tool in tools:
            status = "Installed" if tool.get('installed', False) else "Available"
            source = tool.get('source', 'unknown')
            print(f"\n{tool['id']} ({source}):")
            print(f"  Name: {tool.get('name', 'Unknown')}")
            print(f"  Description: {tool.get('description', '')}")
            print(f"  Families: {', '.join(tool.get('families', []))}")
            print(f"  Status: {status}")
            
    elif args.command == 'decrypt':
        # Set up options
        options = {}
        if args.family:
            options['family'] = args.family
            
        # Set up container and GUI flags
        integrator.use_containers = args.container
        integrator.force_no_gui = args.no_gui
        
        # Decrypt file
        if args.auto:
            # Use auto mode
            if integrator.attempt_auto_decrypt(args.file, args.output, args.family):
                print(f"File successfully decrypted: {args.file}")
            else:
                print(f"Failed to decrypt file: {args.file}")
        elif args.tool:
            # Use specific tool
            if integrator.load_tool(args.tool):
                if integrator.decrypt_file(args.file, args.key, args.output, options):
                    print(f"File successfully decrypted: {args.file}")
                else:
                    print(f"Failed to decrypt file: {args.file}")
            else:
                print(f"Failed to load tool: {args.tool}")
        else:
            print("Error: Either --tool or --auto must be specified")
            
    elif args.command == 'batch':
        # Set up options
        options = {}
        if args.family:
            options['family'] = args.family
            
        # Batch decrypt
        if args.auto:
            # Use auto mode for each file
            results = integrator.batch_decrypt(args.files, None, args.key, args.output_dir, options)
        elif args.tool:
            # Use specific tool
            results = integrator.batch_decrypt(args.files, args.tool, args.key, args.output_dir, options)
        else:
            print("Error: Either --tool or --auto must be specified")
            return
            
        # Print results
        successful = sum(1 for success in results.values() if success)
        print(f"\nDecryption Results: {successful} of {len(results)} files successfully decrypted")
        
        # List failures
        failures = [path for path, success in results.items() if not success]
        if failures:
            print("\nFailed to decrypt:")
            for path in failures[:10]:
                print(f"  {path}")
            if len(failures) > 10:
                print(f"  ...and {len(failures) - 10} more files")
                
    elif args.command == 'install':
        # Install tool
        install_path = integrator.install_tool(args.tool_id, args.family)
        if install_path:
            print(f"Tool {args.tool_id} installed to: {install_path}")
        else:
            print(f"Failed to install tool: {args.tool_id}")
            
    elif args.command == 'update':
        if args.check:
            # Check for updates
            updates = integrator.check_for_updates()
            
            if not updates['enhanced'] and not updates['standard']:
                print("No updates available")
            else:
                print("Updates available for:")
                
                if updates['enhanced']:
                    print("\nEnhanced Registry:")
                    for tool_id in updates['enhanced']:
                        tool = integrator.enhanced_registry.get_tool(tool_id)
                        print(f"  {tool_id}: {tool.get('name', 'Unknown')}")
                        
                if updates['standard']:
                    print("\nStandard Registry:")
                    for tool_id in updates['standard']:
                        tool = integrator.standard_registry.get_tool(tool_id)
                        print(f"  {tool_id}: {tool.get('name', 'Unknown')}")
        elif args.tool:
            # Update specific tool
            if integrator.update_tool(args.tool):
                print(f"Tool {args.tool} updated successfully")
            else:
                print(f"Failed to update tool: {args.tool}")
        elif args.all:
            # Update all installed tools
            updates = integrator.check_for_updates()
            
            all_updates = updates['enhanced'] + updates['standard']
            if not all_updates:
                print("No updates available")
            else:
                print(f"Updating {len(all_updates)} tools...")
                
                success_count = 0
                for tool_id in all_updates:
                    print(f"Updating {tool_id}...")
                    if integrator.update_tool(tool_id):
                        success_count += 1
                        print(f"  Success!")
                    else:
                        print(f"  Failed!")
                        
                print(f"\nUpdated {success_count} of {len(all_updates)} tools")
        else:
            # Synchronize registries
            result = integrator.synchronize_registries()
            print(f"Synchronized registries:")
            print(f"  Added: {result['added']} tools")
            print(f"  Updated: {result['updated']} tools")
            
    elif args.command == 'info':
        # Show tool info
        tool = integrator.get_tool_info(args.tool_id)
        if tool:
            print(f"Tool: {args.tool_id}")
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
            print(f"Tool not found: {args.tool_id}")
            
    else:
        parser.print_help()
    
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())