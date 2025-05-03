"""
Enhanced Ransomware Family Detection Package

This package provides enhanced ransomware family detection capabilities,
including variant identification, multi-feature correlation, and integration
with the existing correlation engine.
"""

from .integration import get_family_detection_integration
from .enhanced_family_detector import EnhancedFamilyDetector

# Define version info
__version__ = "1.0.0"
__author__ = "Innora Security Team"
__description__ = "Enhanced ransomware family detection with variant support"