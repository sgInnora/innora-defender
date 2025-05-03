"""
AI Detection Module for Ransomware Analysis

This package provides deep learning-enhanced capabilities for ransomware
detection, family classification, and variant identification.
"""

from pathlib import Path
import os
import json

# Define package metadata
__version__ = "1.0.0"
__author__ = "Innora Security Team"

# Define default paths
_package_dir = Path(__file__).parent.absolute()
DEFAULT_CONFIG_PATH = _package_dir / "config" / "default_config.json"
DEFAULT_MODELS_DIR = _package_dir / "models"
DEFAULT_DATA_DIR = _package_dir / "data"

# Load default configuration
def load_default_config():
    """Load default configuration from file"""
    if DEFAULT_CONFIG_PATH.exists():
        try:
            with open(DEFAULT_CONFIG_PATH, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading default config: {e}")
    
    return {}