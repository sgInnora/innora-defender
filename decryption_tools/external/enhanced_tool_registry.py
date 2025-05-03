#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Ransomware Decryption Tool Registry

This module provides an expanded registry for ransomware decryption tools with:
- Support for a wider range of ransomware families
- Integration with multiple tool repositories
- Sophisticated tool version management
- Enhanced compatibility checking
- Dynamic tool discovery and registration
- Automated tool updates
"""

import os
import re
import json
import shutil
import logging
import hashlib
import tempfile
import datetime
import subprocess
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('EnhancedToolRegistry')

class EnhancedToolRegistry:
    """
    Enhanced registry for ransomware decryption tools.
    """
    
    # Tool repository URLs
    REPOSITORY_URLS = {
        'nomoreransom': 'https://www.nomoreransom.org/api/tools.json',
        'emsisoft': 'https://decrypter.emsisoft.com/api/info',
        'kaspersky': 'https://noransom.kaspersky.com/api/decryptors'
    }
    
    # Default tool database location
    DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                                  'data', 'tool_registry.json')
    
    # Default tool installation directory
    DEFAULT_TOOLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                                    'tools')
    
    def __init__(self, db_path: Optional[str] = None, tools_dir: Optional[str] = None):
        """
        Initialize the enhanced tool registry.
        
        Args:
            db_path: Path to the tool database JSON file
            tools_dir: Directory for tool installations
        """
        self.db_path = db_path or self.DEFAULT_DB_PATH
        self.tools_dir = tools_dir or self.DEFAULT_TOOLS_DIR
        
        # Ensure directories exist
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        os.makedirs(self.tools_dir, exist_ok=True)
        
        # Initialize tool database and family mappings
        self.tools = {}
        self.family_mappings = {}
        self._load_database()
        
        # Updated families list with extended aliases
        self.family_aliases = self._initialize_family_aliases()
        
        logger.info(f"Enhanced Tool Registry initialized with {len(self.tools)} tools")
    
    def _initialize_family_aliases(self) -> Dict[str, List[str]]:
        """
        Initialize the mapping of ransomware family aliases.
        
        Returns:
            Dictionary mapping canonical family names to lists of aliases
        """
        aliases = {
            'lockbit': ['lockbit', 'lockbit 2.0', 'lockbit 3.0', 'lockbit black', 'lb'],
            'ryuk': ['ryuk', 'ryuk ransomware'],
            'revil': ['revil', 'sodinokibi', 'sodin', 'ruk', 'gandcrypt', 'sodinokibi revil'],
            'gandcrab': ['gandcrab', 'gcrab', 'gandcrypt', 'crab'],
            'stop': ['stop', 'stop/djvu', 'djvu', 'stopdjvu', 'stop_djvu', '.djvu'],
            'dharma': ['dharma', 'crysis', 'dharma/crysis', 'dharma ransomware'],
            'phobos': ['phobos', 'phobos ransomware'],
            'wannacry': ['wannacry', 'wana decrypt0r', 'wncry', 'wannacryptor', 'wcry'],
            'teslacrypt': ['teslacrypt', 'tesla', 'tesla crypt', 'cryptowall', 'alpha'],
            'shade': ['shade', 'troldesh', 'shade ransomware'],
            'avaddon': ['avaddon', 'avaddon ransomware'],
            'troldesh': ['troldesh', 'shade', 'encoder.858', 'encoder.troldesh'],
            'ragnarok': ['ragnarok', 'ragnarlocker', 'ragnar locker'],
            'maze': ['maze', 'maze ransomware', 'maze crew'],
            'nemty': ['nemty', 'nefilim', 'nemty/nefilim'],
            'zeppelin': ['zeppelin', 'buran', 'vega', 'zeppelin ransomware'],
            'megacortex': ['megacortex', 'mega cortex', 'cortex', 'm-cortex'],
            'blackmatter': ['blackmatter', 'darkside', 'black matter'],
            'conti': ['conti', 'conti ransomware'],
            'hive': ['hive', 'hive ransomware'],
            'blackcat': ['blackcat', 'alphv', 'alpha', 'black cat'],
            'babuk': ['babuk', 'babuk locker', 'babyk'],
            'kaseya': ['kaseya', 'revil kaseya', 'kaseya attack'],
            'snatch': ['snatch', 'snatch ransomware'],
            'lockergoga': ['lockergoga', 'locker goga'],
            'pysa': ['pysa', 'mespinosa', 'mespinoza'],
            'cryakl': ['cryakl', 'cryakip', 'cryaki'],
            'encryptor_raas': ['encryptor_raas', 'encryptor raas', 'encryptor'],
            'ziggy': ['ziggy', 'ziggy ransomware'],
            'darkside': ['darkside', 'dark side', 'darkside ransomware'],
            'fonix': ['fonix', 'phoenix', 'fonix ransomware'],
            'thanos': ['thanos', 'thanos ransomware', 'hakbit'],
            'prometheus': ['prometheus', 'prometheus ransomware'],
            'hello': ['hello', 'hello ransomware', '5ss5c'],
            'iraq': ['iraq', 'iraq ransomware'],
            'esxi': ['esxi', 'esxi ransomware', 'esxi locker'],
            'deadbolt': ['deadbolt', 'dead bolt', 'deadbolt ransomware'],
            'lorenz': ['lorenz', 'lorenz ransomware'],
            'grief': ['grief', 'grief ransomware', 'pay grief'],
            'quantum': ['quantum', 'quantum ransomware', 'quantum locker'],
            'blackbyte': ['blackbyte', 'black byte', 'blackbyte ransomware']
        }
        return aliases
    
    def _load_database(self) -> None:
        """Load the tool database from disk."""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r') as f:
                    data = json.load(f)
                    self.tools = data.get('tools', {})
                    self.family_mappings = data.get('family_mappings', {})
                    
                logger.info(f"Loaded tool database with {len(self.tools)} tools")
            except Exception as e:
                logger.error(f"Error loading tool database: {e}")
                self.tools = {}
                self.family_mappings = {}
        else:
            logger.warning(f"Tool database not found at {self.db_path}, initializing empty database")
            self.tools = {}
            self.family_mappings = {}
            self._save_database()
    
    def _save_database(self) -> None:
        """Save the tool database to disk."""
        try:
            with open(self.db_path, 'w') as f:
                json.dump({
                    'updated': datetime.datetime.now().isoformat(),
                    'tools': self.tools,
                    'family_mappings': self.family_mappings
                }, f, indent=2)
                
            logger.info(f"Saved tool database with {len(self.tools)} tools")
        except Exception as e:
            logger.error(f"Error saving tool database: {e}")
    
    def get_all_tools(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all registered tools.
        
        Returns:
            Dictionary of all tools
        """
        return self.tools
    
    def get_tool(self, tool_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific tool by ID.
        
        Args:
            tool_id: Tool ID
            
        Returns:
            Tool details or None if not found
        """
        return self.tools.get(tool_id)
    
    def get_installed_tools(self) -> List[Dict[str, Any]]:
        """
        Get all installed tools.
        
        Returns:
            List of installed tools
        """
        installed_tools = []
        for tool_id, tool in self.tools.items():
            if tool.get('installed', False):
                installed_tools.append(dict(tool, id=tool_id))
        return installed_tools
    
    def find_tools_for_family(self, family: str) -> List[Dict[str, Any]]:
        """
        Find tools for a specific ransomware family.
        
        Args:
            family: Ransomware family name
            
        Returns:
            List of tools for the family
        """
        # Normalize family name
        normalized_family = self._normalize_family_name(family)
        
        # Get tools directly mapped to this family
        tools = []
        if normalized_family in self.family_mappings:
            tool_ids = self.family_mappings[normalized_family]
            for tool_id in tool_ids:
                if tool_id in self.tools:
                    tools.append(dict(self.tools[tool_id], id=tool_id))
        
        # Also check each tool's explicit families list
        for tool_id, tool in self.tools.items():
            tool_families = [self._normalize_family_name(f) for f in tool.get('families', [])]
            if normalized_family in tool_families and tool_id not in [t['id'] for t in tools]:
                tools.append(dict(tool, id=tool_id))
        
        return tools
    
    def _normalize_family_name(self, family: str) -> str:
        """
        Normalize a ransomware family name.
        
        Args:
            family: Family name to normalize
            
        Returns:
            Normalized family name
        """
        family = family.lower().strip()
        
        # Check all aliases
        for canonical, aliases in self.family_aliases.items():
            if family in aliases:
                return canonical
        
        # Default to the original family name
        return family
    
    def add_tool(self, tool_id: str, name: str, description: str, families: List[str],
                url: str, platforms: List[str], repository: str = 'custom',
                compatibility: Optional[Dict[str, Any]] = None) -> bool:
        """
        Add a new tool to the registry.
        
        Args:
            tool_id: Unique tool ID
            name: Tool name
            description: Tool description
            families: List of supported ransomware families
            url: Tool download URL
            platforms: List of supported platforms
            repository: Tool repository
            compatibility: Compatibility requirements
            
        Returns:
            True if the tool was added, False otherwise
        """
        if tool_id in self.tools:
            logger.warning(f"Tool {tool_id} already exists")
            return False
        
        # Create tool entry
        tool = {
            'name': name,
            'description': description,
            'families': families,
            'url': url,
            'platforms': platforms,
            'repository': repository,
            'compatibility': compatibility or {},
            'added': datetime.datetime.now().isoformat(),
            'installed': False
        }
        
        # Add to registry
        self.tools[tool_id] = tool
        
        # Update family mappings
        for family in families:
            normalized_family = self._normalize_family_name(family)
            if normalized_family not in self.family_mappings:
                self.family_mappings[normalized_family] = []
            if tool_id not in self.family_mappings[normalized_family]:
                self.family_mappings[normalized_family].append(tool_id)
        
        # Save database
        self._save_database()
        
        logger.info(f"Added tool {tool_id} for families: {', '.join(families)}")
        return True
    
    def update_tool(self, tool_id: str, **updates) -> bool:
        """
        Update an existing tool.
        
        Args:
            tool_id: Tool ID to update
            **updates: Key-value pairs to update
            
        Returns:
            True if the tool was updated, False otherwise
        """
        if tool_id not in self.tools:
            logger.warning(f"Tool {tool_id} not found")
            return False
        
        # Update tool properties
        for key, value in updates.items():
            if key in self.tools[tool_id]:
                self.tools[tool_id][key] = value
        
        # If families were updated, update mappings
        if 'families' in updates:
            # Remove tool from old family mappings
            for family, tools in self.family_mappings.items():
                if tool_id in tools:
                    self.family_mappings[family].remove(tool_id)
            
            # Add to new family mappings
            for family in updates['families']:
                normalized_family = self._normalize_family_name(family)
                if normalized_family not in self.family_mappings:
                    self.family_mappings[normalized_family] = []
                if tool_id not in self.family_mappings[normalized_family]:
                    self.family_mappings[normalized_family].append(tool_id)
        
        # Add update timestamp
        self.tools[tool_id]['updated'] = datetime.datetime.now().isoformat()
        
        # Save database
        self._save_database()
        
        logger.info(f"Updated tool {tool_id}")
        return True
    
    def remove_tool(self, tool_id: str) -> bool:
        """
        Remove a tool from the registry.
        
        Args:
            tool_id: Tool ID to remove
            
        Returns:
            True if the tool was removed, False otherwise
        """
        if tool_id not in self.tools:
            logger.warning(f"Tool {tool_id} not found")
            return False
        
        # Check if tool is installed
        if self.tools[tool_id].get('installed', False):
            # Uninstall first
            if not self._uninstall_tool(tool_id):
                logger.warning(f"Failed to uninstall tool {tool_id}")
                # Continue anyway
        
        # Remove tool from family mappings
        for family, tools in self.family_mappings.items():
            if tool_id in tools:
                self.family_mappings[family].remove(tool_id)
        
        # Remove tool from registry
        del self.tools[tool_id]
        
        # Save database
        self._save_database()
        
        logger.info(f"Removed tool {tool_id}")
        return True
    
    def _uninstall_tool(self, tool_id: str) -> bool:
        """
        Uninstall a tool.
        
        Args:
            tool_id: Tool ID to uninstall
            
        Returns:
            True if uninstallation was successful, False otherwise
        """
        if tool_id not in self.tools:
            logger.warning(f"Tool {tool_id} not found")
            return False
        
        tool = self.tools[tool_id]
        
        if not tool.get('installed', False):
            logger.warning(f"Tool {tool_id} is not installed")
            return False
        
        # Get installation path
        install_path = tool.get('install_path')
        if not install_path or not os.path.exists(install_path):
            logger.warning(f"Tool {tool_id} installation path not found")
            return False
        
        # Remove installation
        try:
            if os.path.isdir(install_path):
                shutil.rmtree(install_path)
            else:
                os.remove(install_path)
            
            # Update tool status
            self.tools[tool_id]['installed'] = False
            self.tools[tool_id]['install_path'] = None
            self.tools[tool_id]['uninstalled'] = datetime.datetime.now().isoformat()
            
            # Save database
            self._save_database()
            
            logger.info(f"Uninstalled tool {tool_id} from {install_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error uninstalling tool {tool_id}: {e}")
            return False
    
    def download_tool(self, tool_id: str, family: Optional[str] = None) -> Optional[str]:
        """
        Download and install a tool.
        
        Args:
            tool_id: Tool ID to download
            family: Optional family for specialized versions
            
        Returns:
            Installation path or None if download failed
        """
        if tool_id not in self.tools:
            logger.warning(f"Tool {tool_id} not found")
            return None
        
        tool = self.tools[tool_id]
        
        # Get download URL
        url = tool.get('url')
        if not url:
            logger.error(f"Tool {tool_id} has no download URL")
            return None
        
        # Create installation directory
        install_dir = os.path.join(self.tools_dir, tool_id)
        os.makedirs(install_dir, exist_ok=True)
        
        try:
            # Download file
            logger.info(f"Downloading tool {tool_id} from {url}")
            
            filename = os.path.basename(url) or f"{tool_id}.zip"
            download_path = os.path.join(install_dir, filename)
            
            # Use urllib to download
            urllib.request.urlretrieve(url, download_path)
            
            # Check if download was successful
            if not os.path.exists(download_path) or os.path.getsize(download_path) == 0:
                logger.error(f"Download failed for tool {tool_id}")
                return None
            
            # Extract if it's a ZIP file
            installed_path = download_path
            if download_path.endswith('.zip'):
                try:
                    import zipfile
                    with zipfile.ZipFile(download_path, 'r') as zip_ref:
                        extract_dir = os.path.join(install_dir, 'extracted')
                        zip_ref.extractall(extract_dir)
                    
                    # Find main executable in extracted files
                    for root, _, files in os.walk(extract_dir):
                        for file in files:
                            if file.endswith('.exe') or os.access(os.path.join(root, file), os.X_OK):
                                installed_path = os.path.join(root, file)
                                break
                        
                        if installed_path != download_path:
                            break
                
                except Exception as e:
                    logger.error(f"Error extracting ZIP file for tool {tool_id}: {e}")
                    # Continue with downloaded file
            
            # Update tool status
            self.tools[tool_id]['installed'] = True
            self.tools[tool_id]['install_path'] = installed_path
            self.tools[tool_id]['installed_date'] = datetime.datetime.now().isoformat()
            self.tools[tool_id]['installed_version'] = '1.0'  # Default version
            
            # Calculate hash for verification
            with open(installed_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
                self.tools[tool_id]['installed_hash'] = file_hash
            
            # Save database
            self._save_database()
            
            logger.info(f"Installed tool {tool_id} to {installed_path}")
            return installed_path
            
        except Exception as e:
            logger.error(f"Error downloading tool {tool_id}: {e}")
            return None
    
    def update_tool_database(self) -> bool:
        """
        Update the tool database from online repositories.
        
        Returns:
            True if database was updated, False otherwise
        """
        updated = False
        new_tools = 0
        updated_tools = 0
        
        for repo, url in self.REPOSITORY_URLS.items():
            try:
                logger.info(f"Updating tool database from {repo} repository")
                
                # Download repository information
                with urllib.request.urlopen(url) as response:
                    data = json.loads(response.read().decode('utf-8'))
                
                # Process tools based on repository format
                if repo == 'nomoreransom':
                    self._process_nomoreransom_tools(data, new_tools, updated_tools)
                elif repo == 'emsisoft':
                    self._process_emsisoft_tools(data, new_tools, updated_tools)
                elif repo == 'kaspersky':
                    self._process_kaspersky_tools(data, new_tools, updated_tools)
                
                updated = True
                
            except Exception as e:
                logger.error(f"Error updating tool database from {repo}: {e}")
        
        if updated:
            # Save database
            self._save_database()
            logger.info(f"Tool database updated: {new_tools} new tools, {updated_tools} updated tools")
        
        return updated
    
    def _process_nomoreransom_tools(self, data: Dict[str, Any], 
                                  new_tools: int, updated_tools: int) -> None:
        """
        Process tools from NoMoreRansom repository.
        
        Args:
            data: Repository data
            new_tools: Counter for new tools added
            updated_tools: Counter for tools updated
        """
        tools = data.get('tools', [])
        for tool_data in tools:
            try:
                # Extract tool information
                tool_id = f"nomoreransom_{tool_data.get('id', str(hash(tool_data['title'])))}"
                name = tool_data.get('title', 'Unknown Tool')
                description = tool_data.get('description', '')
                url = tool_data.get('url', '')
                
                # Extract families
                families = []
                for variant in tool_data.get('variants', []):
                    families.append(variant.get('name', '').lower())
                
                # Determine platforms
                platforms = []
                if 'windows' in url.lower() or 'win' in url.lower():
                    platforms.append('windows')
                if 'mac' in url.lower() or 'osx' in url.lower():
                    platforms.append('macos')
                if 'linux' in url.lower():
                    platforms.append('linux')
                
                # Default to all platforms if not determined
                if not platforms:
                    platforms = ['windows', 'macos', 'linux']
                
                # Check if tool already exists
                if tool_id in self.tools:
                    # Update existing tool
                    self.update_tool(tool_id, name=name, description=description, 
                                   families=families, url=url, platforms=platforms, 
                                   repository='nomoreransom')
                    updated_tools += 1
                else:
                    # Add new tool
                    self.add_tool(tool_id, name, description, families, url, platforms, 
                                'nomoreransom')
                    new_tools += 1
                    
            except Exception as e:
                logger.error(f"Error processing NoMoreRansom tool: {e}")
    
    def _process_emsisoft_tools(self, data: Dict[str, Any], 
                              new_tools: int, updated_tools: int) -> None:
        """
        Process tools from Emsisoft repository.
        
        Args:
            data: Repository data
            new_tools: Counter for new tools added
            updated_tools: Counter for tools updated
        """
        tools = data.get('decrypters', [])
        for tool_data in tools:
            try:
                # Extract tool information
                tool_id = f"emsisoft_{tool_data.get('id', str(hash(tool_data['name'])))}"
                name = tool_data.get('name', 'Unknown Tool')
                description = tool_data.get('description', '')
                url = tool_data.get('url', '')
                
                # Extract families
                families = []
                for variant in tool_data.get('variants', []):
                    families.append(variant.lower())
                
                # Emsisoft tools are Windows-only
                platforms = ['windows']
                
                # Check if tool already exists
                if tool_id in self.tools:
                    # Update existing tool
                    self.update_tool(tool_id, name=name, description=description, 
                                   families=families, url=url, platforms=platforms, 
                                   repository='emsisoft')
                    updated_tools += 1
                else:
                    # Add new tool
                    self.add_tool(tool_id, name, description, families, url, platforms, 
                                'emsisoft')
                    new_tools += 1
                    
            except Exception as e:
                logger.error(f"Error processing Emsisoft tool: {e}")
    
    def _process_kaspersky_tools(self, data: Dict[str, Any], 
                               new_tools: int, updated_tools: int) -> None:
        """
        Process tools from Kaspersky repository.
        
        Args:
            data: Repository data
            new_tools: Counter for new tools added
            updated_tools: Counter for tools updated
        """
        tools = data.get('decryptors', [])
        for tool_data in tools:
            try:
                # Extract tool information
                tool_id = f"kaspersky_{tool_data.get('id', str(hash(tool_data['name'])))}"
                name = tool_data.get('name', 'Unknown Tool')
                description = tool_data.get('description', '')
                url = tool_data.get('download_url', '')
                
                # Extract families
                families = []
                for family in tool_data.get('families', []):
                    families.append(family.lower())
                
                # Kaspersky tools are usually Windows-only
                platforms = ['windows']
                
                # Check if tool already exists
                if tool_id in self.tools:
                    # Update existing tool
                    self.update_tool(tool_id, name=name, description=description, 
                                   families=families, url=url, platforms=platforms, 
                                   repository='kaspersky')
                    updated_tools += 1
                else:
                    # Add new tool
                    self.add_tool(tool_id, name, description, families, url, platforms, 
                                'kaspersky')
                    new_tools += 1
                    
            except Exception as e:
                logger.error(f"Error processing Kaspersky tool: {e}")
    
    def check_tool_updates(self) -> Dict[str, bool]:
        """
        Check for updates to installed tools.
        
        Returns:
            Dictionary mapping tool IDs to update availability
        """
        updates = {}
        
        for tool_id, tool in self.tools.items():
            if tool.get('installed', False):
                try:
                    # Get installed path
                    install_path = tool.get('install_path')
                    if not install_path or not os.path.exists(install_path):
                        logger.warning(f"Tool {tool_id} installation path not found")
                        continue
                    
                    # Calculate current hash
                    with open(install_path, 'rb') as f:
                        current_hash = hashlib.sha256(f.read()).hexdigest()
                    
                    # Get stored hash
                    stored_hash = tool.get('installed_hash')
                    
                    # Compare hashes
                    if stored_hash and current_hash != stored_hash:
                        logger.warning(f"Tool {tool_id} has been modified locally")
                        updates[tool_id] = False
                        continue
                    
                    # Check for online updates based on repository
                    repository = tool.get('repository', 'custom')
                    
                    if repository == 'nomoreransom':
                        has_update = self._check_nomoreransom_update(tool_id, tool)
                    elif repository == 'emsisoft':
                        has_update = self._check_emsisoft_update(tool_id, tool)
                    elif repository == 'kaspersky':
                        has_update = self._check_kaspersky_update(tool_id, tool)
                    else:
                        has_update = False
                    
                    updates[tool_id] = has_update
                    
                except Exception as e:
                    logger.error(f"Error checking updates for tool {tool_id}: {e}")
                    updates[tool_id] = False
        
        return updates
    
    def _check_nomoreransom_update(self, tool_id: str, tool: Dict[str, Any]) -> bool:
        """
        Check for updates to a NoMoreRansom tool.
        
        Args:
            tool_id: Tool ID
            tool: Tool data
            
        Returns:
            True if an update is available, False otherwise
        """
        try:
            # Extract original ID from tool_id
            original_id = tool_id.replace('nomoreransom_', '')
            
            # Get repository information
            with urllib.request.urlopen(self.REPOSITORY_URLS['nomoreransom']) as response:
                data = json.loads(response.read().decode('utf-8'))
            
            # Find tool in repository
            for tool_data in data.get('tools', []):
                if tool_data.get('id') == original_id:
                    # Check URL for changes
                    if tool_data.get('url') != tool.get('url'):
                        return True
                    
                    # Check version if available
                    if 'version' in tool_data and 'installed_version' in tool:
                        if tool_data['version'] != tool['installed_version']:
                            return True
                    
                    return False
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking NoMoreRansom update: {e}")
            return False
    
    def _check_emsisoft_update(self, tool_id: str, tool: Dict[str, Any]) -> bool:
        """
        Check for updates to an Emsisoft tool.
        
        Args:
            tool_id: Tool ID
            tool: Tool data
            
        Returns:
            True if an update is available, False otherwise
        """
        try:
            # Extract original ID from tool_id
            original_id = tool_id.replace('emsisoft_', '')
            
            # Get repository information
            with urllib.request.urlopen(self.REPOSITORY_URLS['emsisoft']) as response:
                data = json.loads(response.read().decode('utf-8'))
            
            # Find tool in repository
            for tool_data in data.get('decrypters', []):
                if tool_data.get('id') == original_id:
                    # Check URL for changes
                    if tool_data.get('url') != tool.get('url'):
                        return True
                    
                    # Check version if available
                    if 'version' in tool_data and 'installed_version' in tool:
                        if tool_data['version'] != tool['installed_version']:
                            return True
                    
                    return False
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking Emsisoft update: {e}")
            return False
    
    def _check_kaspersky_update(self, tool_id: str, tool: Dict[str, Any]) -> bool:
        """
        Check for updates to a Kaspersky tool.
        
        Args:
            tool_id: Tool ID
            tool: Tool data
            
        Returns:
            True if an update is available, False otherwise
        """
        try:
            # Extract original ID from tool_id
            original_id = tool_id.replace('kaspersky_', '')
            
            # Get repository information
            with urllib.request.urlopen(self.REPOSITORY_URLS['kaspersky']) as response:
                data = json.loads(response.read().decode('utf-8'))
            
            # Find tool in repository
            for tool_data in data.get('decryptors', []):
                if tool_data.get('id') == original_id:
                    # Check URL for changes
                    if tool_data.get('download_url') != tool.get('url'):
                        return True
                    
                    # Check version if available
                    if 'version' in tool_data and 'installed_version' in tool:
                        if tool_data['version'] != tool['installed_version']:
                            return True
                    
                    return False
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking Kaspersky update: {e}")
            return False
    
    def add_custom_tool(self, tool_id: str, name: str, description: str, families: List[str],
                      executable_path: str, platforms: List[str]) -> bool:
        """
        Add a custom tool from a local executable.
        
        Args:
            tool_id: Unique tool ID
            name: Tool name
            description: Tool description
            families: List of supported ransomware families
            executable_path: Path to the tool executable
            platforms: List of supported platforms
            
        Returns:
            True if the tool was added, False otherwise
        """
        if tool_id in self.tools:
            logger.warning(f"Tool {tool_id} already exists")
            return False
        
        if not os.path.exists(executable_path):
            logger.error(f"Executable file not found: {executable_path}")
            return False
        
        # Create tool directory
        tool_dir = os.path.join(self.tools_dir, tool_id)
        os.makedirs(tool_dir, exist_ok=True)
        
        try:
            # Copy executable to tool directory
            dest_path = os.path.join(tool_dir, os.path.basename(executable_path))
            shutil.copy2(executable_path, dest_path)
            
            # Make it executable on Unix systems
            if os.name == 'posix':
                os.chmod(dest_path, 0o755)
            
            # Calculate file hash
            with open(dest_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Create tool entry
            tool = {
                'name': name,
                'description': description,
                'families': families,
                'url': '',  # No URL for custom tools
                'platforms': platforms,
                'repository': 'custom',
                'compatibility': {},
                'added': datetime.datetime.now().isoformat(),
                'installed': True,
                'install_path': dest_path,
                'installed_date': datetime.datetime.now().isoformat(),
                'installed_version': '1.0',  # Default version
                'installed_hash': file_hash
            }
            
            # Add to registry
            self.tools[tool_id] = tool
            
            # Update family mappings
            for family in families:
                normalized_family = self._normalize_family_name(family)
                if normalized_family not in self.family_mappings:
                    self.family_mappings[normalized_family] = []
                if tool_id not in self.family_mappings[normalized_family]:
                    self.family_mappings[normalized_family].append(tool_id)
            
            # Save database
            self._save_database()
            
            logger.info(f"Added custom tool {tool_id} from {executable_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding custom tool {tool_id}: {e}")
            return False
    
    def update_family_aliases(self, canonical: str, aliases: List[str]) -> bool:
        """
        Update the aliases for a ransomware family.
        
        Args:
            canonical: Canonical family name
            aliases: List of aliases
            
        Returns:
            True if aliases were updated, False otherwise
        """
        canonical = canonical.lower().strip()
        
        # Update aliases
        self.family_aliases[canonical] = [a.lower().strip() for a in aliases]
        
        # Add canonical name to aliases if not present
        if canonical not in self.family_aliases[canonical]:
            self.family_aliases[canonical].append(canonical)
        
        logger.info(f"Updated aliases for {canonical}: {', '.join(aliases)}")
        return True
    
    def get_family_tools_count(self) -> Dict[str, int]:
        """
        Get the count of tools available for each family.
        
        Returns:
            Dictionary mapping family names to tool counts
        """
        counts = {}
        
        for family, tools in self.family_mappings.items():
            counts[family] = len(tools)
        
        return counts


def main():
    """Command-line interface for the enhanced tool registry."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced Ransomware Decryption Tool Registry")
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List tools')
    list_parser.add_argument('--family', '-f', help='Filter by ransomware family')
    list_parser.add_argument('--installed', '-i', action='store_true', help='Show only installed tools')
    list_parser.add_argument('--details', '-d', action='store_true', help='Show detailed information')
    
    # Add command
    add_parser = subparsers.add_parser('add', help='Add a custom tool')
    add_parser.add_argument('--id', required=True, help='Tool ID')
    add_parser.add_argument('--name', required=True, help='Tool name')
    add_parser.add_argument('--description', required=True, help='Tool description')
    add_parser.add_argument('--families', required=True, help='Comma-separated list of families')
    add_parser.add_argument('--executable', required=True, help='Path to executable')
    add_parser.add_argument('--platforms', help='Comma-separated list of platforms')
    
    # Install command
    install_parser = subparsers.add_parser('install', help='Install a tool')
    install_parser.add_argument('tool_id', help='Tool ID to install')
    install_parser.add_argument('--family', '-f', help='Family for specialized versions')
    
    # Uninstall command
    uninstall_parser = subparsers.add_parser('uninstall', help='Uninstall a tool')
    uninstall_parser.add_argument('tool_id', help='Tool ID to uninstall')
    
    # Update command
    update_parser = subparsers.add_parser('update', help='Update the tool database')
    update_parser.add_argument('--check', '-c', action='store_true', help='Check for updates only')
    
    # Families command
    families_parser = subparsers.add_parser('families', help='List supported ransomware families')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Create registry
    registry = EnhancedToolRegistry()
    
    if args.command == 'list':
        # List tools
        tools = []
        
        if args.family:
            tools = registry.find_tools_for_family(args.family)
            print(f"Tools for {args.family}:")
        elif args.installed:
            tools = registry.get_installed_tools()
            print("Installed tools:")
        else:
            tools = [dict(tool, id=tool_id) for tool_id, tool in registry.get_all_tools().items()]
            print("All tools:")
        
        # Display tools
        for tool in tools:
            if args.details:
                print(f"\n{tool['id']}: {tool['name']}")
                print(f"  Description: {tool['description']}")
                print(f"  Families: {', '.join(tool['families'])}")
                print(f"  Platforms: {', '.join(tool['platforms'])}")
                print(f"  Repository: {tool['repository']}")
                print(f"  Installed: {'Yes' if tool.get('installed', False) else 'No'}")
                if tool.get('installed', False):
                    print(f"  Install path: {tool.get('install_path', 'Unknown')}")
            else:
                status = "Installed" if tool.get('installed', False) else "Available"
                print(f"{tool['id']}: {tool['name']} - {status}")
        
        print(f"\nTotal: {len(tools)} tools")
    
    elif args.command == 'add':
        # Add a custom tool
        families = [f.strip() for f in args.families.split(',')]
        platforms = [p.strip() for p in args.platforms.split(',')] if args.platforms else ['windows']
        
        if registry.add_custom_tool(args.id, args.name, args.description, families, args.executable, platforms):
            print(f"Added custom tool: {args.id}")
        else:
            print(f"Failed to add custom tool: {args.id}")
    
    elif args.command == 'install':
        # Install a tool
        install_path = registry.download_tool(args.tool_id, args.family)
        if install_path:
            print(f"Installed tool {args.tool_id} to: {install_path}")
        else:
            print(f"Failed to install tool: {args.tool_id}")
    
    elif args.command == 'uninstall':
        # Uninstall a tool
        if registry._uninstall_tool(args.tool_id):
            print(f"Uninstalled tool: {args.tool_id}")
        else:
            print(f"Failed to uninstall tool: {args.tool_id}")
    
    elif args.command == 'update':
        # Update tool database
        if args.check:
            updates = registry.check_tool_updates()
            
            if updates:
                print("Tools with available updates:")
                for tool_id, has_update in updates.items():
                    if has_update:
                        print(f"  {tool_id}")
                
                print("\nTools without updates:")
                for tool_id, has_update in updates.items():
                    if not has_update:
                        print(f"  {tool_id}")
            else:
                print("No installed tools to check for updates")
        else:
            if registry.update_tool_database():
                print("Tool database updated successfully")
            else:
                print("Failed to update tool database")
    
    elif args.command == 'families':
        # List supported families
        counts = registry.get_family_tools_count()
        
        print("Supported ransomware families:")
        for family, count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            print(f"{family}: {count} tools")
        
        print(f"\nTotal: {len(counts)} families")
    
    else:
        parser.print_help()
    
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())