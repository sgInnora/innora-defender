#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ransomware Decryption Tool Registry

This module manages a registry of publicly available ransomware decryption tools,
including metadata about each tool, its compatibility, and how to use it.
"""

import os
import json
import logging
import hashlib
import platform
import subprocess
import pkg_resources
import requests
from typing import Dict, List, Optional, Union, Any, Tuple
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('DecryptionToolRegistry')

# Base directory for storing external tools
TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DB_PATH = os.path.join(TOOLS_DIR, 'tools_db.json')
DOWNLOADS_DIR = os.path.join(TOOLS_DIR, 'downloads')
CONFIGS_DIR = os.path.join(TOOLS_DIR, 'configs')

# Ensure directories exist
os.makedirs(DOWNLOADS_DIR, exist_ok=True)
os.makedirs(CONFIGS_DIR, exist_ok=True)

class DecryptionToolRegistry:
    """
    Registry for managing publicly available ransomware decryption tools.
    """
    
    def __init__(self, db_path: str = TOOLS_DB_PATH):
        """
        Initialize the decryption tool registry.
        
        Args:
            db_path: Path to the tools database JSON file
        """
        self.db_path = db_path
        self.tools_db = self._load_database()
        self.platform = platform.system().lower()
        
    def _load_database(self) -> Dict[str, Dict[str, Any]]:
        """
        Load the tools database from JSON file.
        
        Returns:
            Dictionary containing tool data
        """
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading tools database: {e}")
                return {}
        else:
            # Initialize with built-in tool list
            initial_db = self._get_initial_tools_db()
            self._save_database(initial_db)
            return initial_db
            
    def _save_database(self, db: Dict[str, Dict[str, Any]]) -> None:
        """
        Save the tools database to JSON file.
        
        Args:
            db: Tools database to save
        """
        try:
            with open(self.db_path, 'w') as f:
                json.dump(db, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving tools database: {e}")
            
    def _get_initial_tools_db(self) -> Dict[str, Dict[str, Any]]:
        """
        Get initial tools database with built-in tool definitions.
        
        Returns:
            Dictionary with initial tool entries
        """
        return {
            "emsisoft_decryptor": {
                "name": "Emsisoft Decryptor",
                "description": "Collection of free decryptors for various ransomware families",
                "url": "https://www.emsisoft.com/ransomware-decryption-tools/",
                "families": [
                    "STOP (Djvu)", "Amnesia", "Avaddon", "Babuk", "Chaos", 
                    "DeadBolt", "Diavol", "FenixLocker", "Hive", "Maze",
                    "MegaCortex", "Ragnarok", "Atom", "Fonix", "Conti"
                ],
                "platforms": ["windows"],
                "last_updated": "2023-05-15",
                "type": "standalone",
                "download_urls": {
                    "STOP (Djvu)": "https://www.emsisoft.com/ransomware-decryption-tools/download/stop-djvu",
                    "Babuk": "https://www.emsisoft.com/ransomware-decryption-tools/download/babuk"
                },
                "installed": False,
                "status": "available"
            },
            "kaspersky_nomoreransom": {
                "name": "Kaspersky No More Ransom Tools",
                "description": "Ransomware decryptors from the No More Ransom project",
                "url": "https://nomore.kaspersky.com/",
                "families": [
                    "Rannoh", "Rakhni", "Wildfire", "CoinVault", "Rector",
                    "Bart", "Demon", "NoobCrypt", "Xorist"
                ],
                "platforms": ["windows"],
                "last_updated": "2023-02-10",
                "type": "standalone",
                "download_urls": {
                    "Rannoh": "https://nomore.kaspersky.com/static/media/tools/RannohDecryptor.exe"
                },
                "installed": False,
                "status": "available" 
            },
            "trend_micro_tools": {
                "name": "Trend Micro Ransomware Decryptors",
                "description": "Free decryption tools for multiple ransomware families",
                "url": "https://www.trendmicro.com/en_us/consumer/support/free-tools.html",
                "families": ["TeslaCrypt", "Cryptear", "SNSLocker", "Stampado"],
                "platforms": ["windows"],
                "last_updated": "2022-11-05",
                "type": "standalone",
                "download_urls": {
                    "TeslaCrypt": "https://github.com/Trend-Micro-Tools/TeslaCrypt-Decryptor"
                },
                "installed": False,
                "status": "available"
            },
            "europol_nomoreransom": {
                "name": "No More Ransom Project",
                "description": "Collection of decryptors from the No More Ransom coalition",
                "url": "https://www.nomoreransom.org/",
                "families": [
                    "GandCrab", "Shade", "Troldesh", "Teslacrypt", "Rannoh",
                    "LockerGoga", "WannaCry", "SynAck", "Cryakl", "MegaLocker"
                ],
                "platforms": ["windows"],
                "last_updated": "2023-06-20",
                "type": "website",
                "download_urls": {},
                "installed": False,
                "status": "reference"
            },
            "mcafee_tools": {
                "name": "McAfee Ransomware Recover (Mr2)",
                "description": "Tools for WannaCry and other ransomware decryption",
                "url": "https://github.com/advanced-threat-research/mr2",
                "families": ["WannaCry"],
                "platforms": ["windows", "linux"],
                "last_updated": "2020-09-18",
                "type": "github",
                "download_urls": {
                    "WannaCry": "https://github.com/advanced-threat-research/mr2"
                },
                "requirements": ["git", "python3"],
                "installed": False,
                "status": "available"
            },
            "avast_decryptors": {
                "name": "Avast Ransomware Decryptors",
                "description": "Free tools to unlock files encrypted by ransomware",
                "url": "https://www.avast.com/ransomware-decryption-tools",
                "families": [
                    "AtomSilo", "Babuk", "HermeticRansom", "LambdaLocker",
                    "Legion", "NemucodAES", "SZFLocker"
                ],
                "platforms": ["windows"],
                "last_updated": "2023-04-12",
                "type": "standalone",
                "download_urls": {},
                "installed": False,
                "status": "available"
            }
        }
    
    def get_all_tools(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all tools in the registry.
        
        Returns:
            Dictionary of all registered tools
        """
        return self.tools_db
    
    def get_tool(self, tool_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific tool by ID.
        
        Args:
            tool_id: Identifier of the tool
            
        Returns:
            Tool data or None if not found
        """
        return self.tools_db.get(tool_id)
    
    def get_tools_for_family(self, family: str) -> List[Dict[str, Any]]:
        """
        Get tools that can decrypt a specific ransomware family.
        
        Args:
            family: Ransomware family name
            
        Returns:
            List of tools for the specified family
        """
        matching_tools = []
        family_lower = family.lower()
        
        for tool_id, tool_data in self.tools_db.items():
            families = [f.lower() for f in tool_data.get('families', [])]
            if any(family_lower in f or f in family_lower for f in families):
                tool_copy = dict(tool_data)
                tool_copy['id'] = tool_id
                matching_tools.append(tool_copy)
                
        return matching_tools
    
    def add_tool(self, tool_id: str, tool_data: Dict[str, Any]) -> bool:
        """
        Add a new tool to the registry.
        
        Args:
            tool_id: Identifier for the tool
            tool_data: Tool metadata
            
        Returns:
            True if added successfully, False otherwise
        """
        if tool_id in self.tools_db:
            logger.warning(f"Tool {tool_id} already exists in the registry")
            return False
            
        # Validate required fields
        required_fields = ['name', 'description', 'url', 'families', 'platforms']
        for field in required_fields:
            if field not in tool_data:
                logger.error(f"Missing required field: {field}")
                return False
                
        # Add default fields
        tool_data['installed'] = False
        tool_data['status'] = 'available'
        tool_data['last_updated'] = datetime.now().strftime("%Y-%m-%d")
        
        # Add to database and save
        self.tools_db[tool_id] = tool_data
        self._save_database(self.tools_db)
        logger.info(f"Added tool {tool_id} to registry")
        return True
    
    def update_tool(self, tool_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update an existing tool in the registry.
        
        Args:
            tool_id: Identifier for the tool
            updates: Updated fields
            
        Returns:
            True if updated successfully, False otherwise
        """
        if tool_id not in self.tools_db:
            logger.error(f"Tool {tool_id} not found in registry")
            return False
            
        # Update fields
        self.tools_db[tool_id].update(updates)
        self._save_database(self.tools_db)
        logger.info(f"Updated tool {tool_id} in registry")
        return True
    
    def remove_tool(self, tool_id: str) -> bool:
        """
        Remove a tool from the registry.
        
        Args:
            tool_id: Identifier for the tool
            
        Returns:
            True if removed successfully, False otherwise
        """
        if tool_id not in self.tools_db:
            logger.error(f"Tool {tool_id} not found in registry")
            return False
            
        # Remove from database and save
        del self.tools_db[tool_id]
        self._save_database(self.tools_db)
        logger.info(f"Removed tool {tool_id} from registry")
        return True
    
    def download_tool(self, tool_id: str, family: Optional[str] = None) -> Optional[str]:
        """
        Download a tool from its source.
        
        Args:
            tool_id: Identifier for the tool
            family: Specific ransomware family to download tool for
            
        Returns:
            Path to downloaded tool or None if download failed
        """
        if tool_id not in self.tools_db:
            logger.error(f"Tool {tool_id} not found in registry")
            return None
            
        tool = self.tools_db[tool_id]
        
        # Check platform compatibility
        if self.platform not in tool.get('platforms', []):
            logger.error(f"Tool {tool_id} is not compatible with {self.platform}")
            return None
            
        # Handle different tool types
        tool_type = tool.get('type', 'standalone')
        
        if tool_type == 'standalone':
            return self._download_standalone_tool(tool_id, tool, family)
        elif tool_type == 'github':
            return self._download_github_tool(tool_id, tool)
        elif tool_type == 'website':
            logger.info(f"Tool {tool_id} is a website reference: {tool.get('url')}")
            return tool.get('url')
        else:
            logger.error(f"Unsupported tool type: {tool_type}")
            return None
    
    def _download_standalone_tool(self, tool_id: str, tool: Dict[str, Any], 
                                 family: Optional[str] = None) -> Optional[str]:
        """
        Download a standalone decryption tool.
        
        Args:
            tool_id: Tool identifier
            tool: Tool metadata
            family: Specific ransomware family
            
        Returns:
            Path to downloaded tool or None if download failed
        """
        download_urls = tool.get('download_urls', {})
        
        # If family specified, get URL for that family
        if family and family in download_urls:
            url = download_urls[family]
        # Otherwise use first URL if available
        elif download_urls:
            family, url = next(iter(download_urls.items()))
        else:
            logger.error(f"No download URLs found for {tool_id}")
            return None
            
        # Create destination directory
        tool_dir = os.path.join(DOWNLOADS_DIR, tool_id)
        os.makedirs(tool_dir, exist_ok=True)
        
        # Get filename from URL
        filename = os.path.basename(url)
        if not filename:
            filename = f"{family.lower().replace(' ', '_')}_decryptor"
            if self.platform == 'windows':
                filename += '.exe'
                
        output_path = os.path.join(tool_dir, filename)
        
        try:
            logger.info(f"Downloading {tool['name']} for {family} from {url}")
            
            # Download file
            response = requests.get(url, stream=True)
            response.raise_for_status()
            
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    
            # Make executable on Unix platforms
            if self.platform in ['linux', 'darwin']:
                os.chmod(output_path, 0o755)
                
            # Update tool status
            self.tools_db[tool_id]['installed'] = True
            self.tools_db[tool_id]['install_path'] = output_path
            self.tools_db[tool_id]['download_date'] = datetime.now().strftime("%Y-%m-%d")
            self._save_database(self.tools_db)
            
            logger.info(f"Tool downloaded to {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error downloading {tool_id}: {e}")
            return None
    
    def _download_github_tool(self, tool_id: str, tool: Dict[str, Any]) -> Optional[str]:
        """
        Clone a tool from GitHub.
        
        Args:
            tool_id: Tool identifier
            tool: Tool metadata
            
        Returns:
            Path to cloned repository or None if clone failed
        """
        # Get repository URL
        url = next(iter(tool.get('download_urls', {}).values()), tool.get('url'))
        if not url:
            logger.error(f"No GitHub URL found for {tool_id}")
            return None
            
        # Create destination directory
        tool_dir = os.path.join(DOWNLOADS_DIR, tool_id)
        
        try:
            logger.info(f"Cloning {tool['name']} from {url}")
            
            # Check if git is available
            if not self._is_command_available('git'):
                logger.error("Git command not available, cannot clone repository")
                return None
                
            # Clone repository
            if os.path.exists(tool_dir):
                # Pull latest changes if repo exists
                cmd = ['git', '-C', tool_dir, 'pull']
            else:
                # Clone repo if it doesn't exist
                cmd = ['git', 'clone', url, tool_dir]
                
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"Git operation failed: {result.stderr}")
                return None
                
            # Check if repository has requirements
            requirements_file = os.path.join(tool_dir, 'requirements.txt')
            if os.path.exists(requirements_file):
                logger.info(f"Installing requirements for {tool_id}")
                if self._is_command_available('pip') or self._is_command_available('pip3'):
                    pip_cmd = 'pip3' if self._is_command_available('pip3') else 'pip'
                    install_cmd = [pip_cmd, 'install', '-r', requirements_file]
                    
                    result = subprocess.run(install_cmd, capture_output=True, text=True)
                    
                    if result.returncode != 0:
                        logger.warning(f"Failed to install requirements: {result.stderr}")
                else:
                    logger.warning("Pip not available, cannot install requirements")
            
            # Update tool status
            self.tools_db[tool_id]['installed'] = True
            self.tools_db[tool_id]['install_path'] = tool_dir
            self.tools_db[tool_id]['download_date'] = datetime.now().strftime("%Y-%m-%d")
            self._save_database(self.tools_db)
            
            logger.info(f"Tool cloned to {tool_dir}")
            return tool_dir
            
        except Exception as e:
            logger.error(f"Error cloning {tool_id}: {e}")
            return None
    
    def _is_command_available(self, command: str) -> bool:
        """
        Check if a command is available on the system.
        
        Args:
            command: Command to check
            
        Returns:
            True if command is available, False otherwise
        """
        try:
            if self.platform == 'windows':
                result = subprocess.run(['where', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            else:
                result = subprocess.run(['which', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
            return result.returncode == 0
        except Exception:
            return False
    
    def check_tool_updates(self) -> Dict[str, bool]:
        """
        Check for updates to installed tools.
        
        Returns:
            Dictionary mapping tool IDs to update status (True if update available)
        """
        update_status = {}
        
        for tool_id, tool in self.tools_db.items():
            if not tool.get('installed', False):
                continue
                
            # Different update checks based on tool type
            if tool.get('type') == 'github':
                update_status[tool_id] = self._check_github_update(tool_id, tool)
            else:
                # For standalone tools, check the last_updated field
                update_status[tool_id] = self._check_standalone_update(tool_id, tool)
                
        return update_status
    
    def _check_github_update(self, tool_id: str, tool: Dict[str, Any]) -> bool:
        """
        Check if a GitHub tool has updates available.
        
        Args:
            tool_id: Tool identifier
            tool: Tool metadata
            
        Returns:
            True if updates are available, False otherwise
        """
        install_path = tool.get('install_path')
        if not install_path or not os.path.exists(install_path):
            return False
            
        try:
            # Get current commit hash
            cmd = ['git', '-C', install_path, 'rev-parse', 'HEAD']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"Failed to get current commit hash: {result.stderr}")
                return False
                
            current_hash = result.stdout.strip()
            
            # Fetch latest changes
            fetch_cmd = ['git', '-C', install_path, 'fetch']
            subprocess.run(fetch_cmd, capture_output=True, text=True)
            
            # Get remote hash
            cmd = ['git', '-C', install_path, 'rev-parse', 'origin/HEAD']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"Failed to get remote commit hash: {result.stderr}")
                return False
                
            remote_hash = result.stdout.strip()
            
            # Compare hashes
            return current_hash != remote_hash
            
        except Exception as e:
            logger.error(f"Error checking for updates to {tool_id}: {e}")
            return False
    
    def _check_standalone_update(self, tool_id: str, tool: Dict[str, Any]) -> bool:
        """
        Check if a standalone tool has updates available.
        
        Args:
            tool_id: Tool identifier
            tool: Tool metadata
            
        Returns:
            True if updates are available, False otherwise
        """
        try:
            # Parse dates
            last_updated = datetime.strptime(tool.get('last_updated', '2000-01-01'), "%Y-%m-%d")
            download_date = datetime.strptime(tool.get('download_date', '2000-01-01'), "%Y-%m-%d")
            
            # If the tool was updated after it was downloaded, an update is available
            return last_updated > download_date
            
        except Exception as e:
            logger.error(f"Error checking for updates to {tool_id}: {e}")
            return False
    
    def get_installed_tools(self) -> List[Dict[str, Any]]:
        """
        Get all installed tools.
        
        Returns:
            List of installed tools
        """
        installed_tools = []
        
        for tool_id, tool in self.tools_db.items():
            if tool.get('installed', False):
                tool_copy = dict(tool)
                tool_copy['id'] = tool_id
                installed_tools.append(tool_copy)
                
        return installed_tools
    
    def get_compatible_tools(self) -> List[Dict[str, Any]]:
        """
        Get tools compatible with the current platform.
        
        Returns:
            List of compatible tools
        """
        compatible_tools = []
        
        for tool_id, tool in self.tools_db.items():
            if self.platform in tool.get('platforms', []):
                tool_copy = dict(tool)
                tool_copy['id'] = tool_id
                compatible_tools.append(tool_copy)
                
        return compatible_tools

    def update_tool_database(self) -> bool:
        """
        Update the tool database with the latest information from online sources.
        
        Returns:
            True if updated successfully, False otherwise
        """
        try:
            # This is a placeholder for a real implementation
            # In a real implementation, this would fetch updated tool information
            # from a central repository or API
            
            logger.info("Updating tool database from online sources")
            
            # For now, we'll just update the 'last_checked' field
            for tool_id in self.tools_db:
                self.tools_db[tool_id]['last_checked'] = datetime.now().strftime("%Y-%m-%d")
                
            self._save_database(self.tools_db)
            return True
            
        except Exception as e:
            logger.error(f"Error updating tool database: {e}")
            return False

def main():
    """Command-line interface for the decryption tool registry."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Ransomware Decryption Tool Registry")
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # List tools command
    list_parser = subparsers.add_parser('list', help='List available tools')
    list_parser.add_argument('--family', help='Filter by ransomware family')
    list_parser.add_argument('--installed', action='store_true', help='Show only installed tools')
    list_parser.add_argument('--compatible', action='store_true', help='Show only compatible tools')
    
    # Show tool details command
    show_parser = subparsers.add_parser('show', help='Show tool details')
    show_parser.add_argument('tool_id', help='Tool identifier')
    
    # Download tool command
    download_parser = subparsers.add_parser('download', help='Download a tool')
    download_parser.add_argument('tool_id', help='Tool identifier')
    download_parser.add_argument('--family', help='Ransomware family')
    
    # Update database command
    update_parser = subparsers.add_parser('update', help='Update tool database')
    
    # Check for tool updates command
    check_updates_parser = subparsers.add_parser('check-updates', help='Check for tool updates')
    
    args = parser.parse_args()
    
    # Create registry
    registry = DecryptionToolRegistry()
    
    if args.command == 'list':
        if args.family:
            tools = registry.get_tools_for_family(args.family)
            print(f"Tools for {args.family}:")
        elif args.installed:
            tools = registry.get_installed_tools()
            print("Installed tools:")
        elif args.compatible:
            tools = registry.get_compatible_tools()
            print("Compatible tools:")
        else:
            tools = [dict(tool, id=tool_id) for tool_id, tool in registry.get_all_tools().items()]
            print("All tools:")
            
        for tool in tools:
            status = "Installed" if tool.get('installed', False) else "Available"
            print(f"  {tool.get('id')}: {tool.get('name')} - {status}")
            print(f"    Families: {', '.join(tool.get('families', []))}")
            print(f"    Platforms: {', '.join(tool.get('platforms', []))}")
            print()
            
    elif args.command == 'show':
        tool = registry.get_tool(args.tool_id)
        if tool:
            print(f"Tool: {args.tool_id}")
            for key, value in tool.items():
                if key == 'download_urls':
                    print("Download URLs:")
                    for family, url in value.items():
                        print(f"  {family}: {url}")
                else:
                    print(f"{key}: {value}")
        else:
            print(f"Tool {args.tool_id} not found")
            
    elif args.command == 'download':
        path = registry.download_tool(args.tool_id, args.family)
        if path:
            print(f"Tool downloaded to: {path}")
        else:
            print(f"Failed to download {args.tool_id}")
            
    elif args.command == 'update':
        if registry.update_tool_database():
            print("Tool database updated successfully")
        else:
            print("Failed to update tool database")
            
    elif args.command == 'check-updates':
        updates = registry.check_tool_updates()
        if updates:
            print("Updates available for:")
            for tool_id, has_update in updates.items():
                if has_update:
                    print(f"  {tool_id}")
        else:
            print("No updates available")
            
    else:
        parser.print_help()
    
if __name__ == "__main__":
    main()