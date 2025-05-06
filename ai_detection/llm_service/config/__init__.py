"""
LLM Service Configuration

This module handles loading and merging of LLM service configuration from
various sources, including default config, environment variables and user config.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "default_config.json")
USER_CONFIG_PATH = os.path.expanduser("~/.innora/config/llm_config.json")

def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load LLM service configuration.
    
    Args:
        config_path: Optional path to custom config file
        
    Returns:
        Configuration dictionary
    """
    # Load default config
    default_config = {}
    try:
        with open(DEFAULT_CONFIG_PATH, 'r') as f:
            default_config = json.load(f)
    except Exception as e:
        print(f"Warning: Failed to load default config: {e}")
    
    # Load user config if exists
    user_config = {}
    if os.path.exists(USER_CONFIG_PATH):
        try:
            with open(USER_CONFIG_PATH, 'r') as f:
                user_config = json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load user config: {e}")
    
    # Load custom config if specified
    custom_config = {}
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                custom_config = json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load custom config: {e}")
    
    # Merge configs (custom > user > default)
    config = {**default_config, **user_config, **custom_config}
    
    # Resolve paths
    if "cache_directory" in config:
        config["cache_directory"] = os.path.expanduser(config["cache_directory"])
    
    if "usage_log_file" in config:
        config["usage_log_file"] = os.path.expanduser(config["usage_log_file"])
    
    if "stats_file" in config:
        config["stats_file"] = os.path.expanduser(config["stats_file"])
    
    # Ensure directories exist
    if "cache_directory" in config:
        Path(config["cache_directory"]).mkdir(parents=True, exist_ok=True)
    
    return config

def save_user_config(config: Dict[str, Any]) -> None:
    """
    Save user configuration.
    
    Args:
        config: Configuration dictionary to save
    """
    try:
        # Ensure directory exists
        Path(os.path.dirname(USER_CONFIG_PATH)).mkdir(parents=True, exist_ok=True)
        
        with open(USER_CONFIG_PATH, 'w') as f:
            json.dump(config, f, indent=2)
            
        print(f"Configuration saved to {USER_CONFIG_PATH}")
    except Exception as e:
        print(f"Error saving configuration: {e}")

# Default configuration
config = load_config()