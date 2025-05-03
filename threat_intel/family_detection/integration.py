#!/usr/bin/env python3
"""
Enhanced Ransomware Family Detection Integration

This module integrates the enhanced family detector with the existing correlation engine,
providing a seamless upgrade path for improved ransomware family identification.
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional

from .enhanced_family_detector import EnhancedFamilyDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('family_detection_integration')

class EnhancedFamilyDetectionIntegration:
    """
    Integration class for enhanced family detection.
    
    This class provides a bridge between the enhanced family detector and the
    existing correlation engine, allowing for a seamless upgrade path.
    """
    
    def __init__(self, 
                 families_dir: Optional[str] = None, 
                 yara_rules_dir: Optional[str] = None,
                 fallback_to_legacy: bool = True,
                 min_confidence_threshold: float = 0.6):
        """
        Initialize the integration.
        
        Args:
            families_dir: Directory containing family definition files
            yara_rules_dir: Directory containing YARA rules
            fallback_to_legacy: Whether to fall back to legacy detection if enhanced fails
            min_confidence_threshold: Minimum confidence threshold for family identification
        """
        self.enhanced_detector = EnhancedFamilyDetector(
            families_dir=families_dir,
            yara_rules_dir=yara_rules_dir
        )
        
        self.fallback_to_legacy = fallback_to_legacy
        self.min_confidence_threshold = min_confidence_threshold
        
        logger.info("Enhanced Family Detection Integration initialized")
    
    def identify_ransomware_family(self, sample_data: Dict[str, Any], 
                                  legacy_results: Optional[List[Dict]] = None) -> List[Dict]:
        """
        Identify ransomware family using enhanced detection.
        
        Args:
            sample_data: Sample analysis data
            legacy_results: Results from legacy detection (if available)
            
        Returns:
            List of identified families with confidence scores
        """
        try:
            # Run enhanced detection
            enhanced_results = self.enhanced_detector.identify_family(
                sample_data, 
                min_score=self.min_confidence_threshold
            )
            
            # If we have results, return them
            if enhanced_results:
                logger.info(f"Enhanced detection identified {len(enhanced_results)} families")
                
                # Format results to match expected output
                formatted_results = []
                for result in enhanced_results:
                    family_entry = {
                        "name": result["family_name"],
                        "confidence": result["confidence"],
                        "detection_method": "enhanced_detection",
                        "aliases": result.get("aliases", []),
                        "active": result.get("active", False),
                        "feature_scores": result.get("feature_scores", {})
                    }
                    
                    # Add variant information if available
                    if "variant" in result:
                        family_entry["variant"] = result["variant"]["name"]
                        family_entry["variant_confidence"] = result["variant"]["confidence"]
                        family_entry["variant_indicator"] = result["variant"]["indicator"]
                    
                    formatted_results.append(family_entry)
                
                return formatted_results
            
            # If no results and fallback is enabled, use legacy results
            if self.fallback_to_legacy and legacy_results:
                logger.info("Enhanced detection found no families, falling back to legacy detection")
                
                # Add detection method to indicate legacy
                for result in legacy_results:
                    result["detection_method"] = "legacy_detection"
                
                return legacy_results
            
            # No results found
            logger.info("No ransomware families identified")
            return []
            
        except Exception as e:
            logger.error(f"Error in enhanced ransomware family detection: {e}")
            
            # Fall back to legacy results if available
            if self.fallback_to_legacy and legacy_results:
                logger.info("Error in enhanced detection, falling back to legacy detection")
                
                # Add detection method to indicate legacy
                for result in legacy_results:
                    result["detection_method"] = "legacy_detection"
                
                return legacy_results
            
            # Return empty list on error
            return []
    
    def refine_family_information(self, family_name: str) -> Dict[str, Any]:
        """
        Get detailed information about a ransomware family.
        
        Args:
            family_name: Name of the ransomware family
            
        Returns:
            Dictionary containing detailed family information
        """
        try:
            # Normalize family name
            normalized_name = self.enhanced_detector.normalize_family_name(family_name)
            
            # Get family data
            family_data = self.enhanced_detector.families.get(normalized_name)
            if not family_data:
                logger.warning(f"Family information not found for {family_name}")
                return {}
            
            # Extract key information
            result = {
                "name": family_data.get("name", normalized_name),
                "aliases": family_data.get("aliases", []),
                "active": family_data.get("active", False),
                "first_seen": family_data.get("first_seen", "unknown"),
                "description": family_data.get("description", ""),
                "technical_details": {}
            }
            
            # Add technical details
            tech_details = family_data.get("technical_details", {})
            if tech_details:
                result["technical_details"] = {
                    "encryption": tech_details.get("encryption", {}),
                    "extensions": tech_details.get("extension", []),
                    "ransom_note": tech_details.get("ransom_note", {})
                }
            
            # Add available decryptors
            if "available_decryptors" in family_data:
                result["decryptors"] = family_data["available_decryptors"]
            
            # Add recovery strategies
            if "recovery_strategies" in family_data:
                result["recovery_strategies"] = family_data["recovery_strategies"]
            
            return result
            
        except Exception as e:
            logger.error(f"Error retrieving family information for {family_name}: {e}")
            return {}
    
    def get_all_family_names(self) -> List[Dict[str, Any]]:
        """
        Get a list of all known ransomware family names and their variants.
        
        Returns:
            List of dictionaries with family names and variants
        """
        try:
            results = []
            
            for family_id, family_data in self.enhanced_detector.families.items():
                family_entry = {
                    "id": family_id,
                    "name": family_data.get("name", family_id),
                    "aliases": family_data.get("aliases", []),
                    "active": family_data.get("active", False)
                }
                
                results.append(family_entry)
            
            return results
            
        except Exception as e:
            logger.error(f"Error retrieving family names: {e}")
            return []
    
    def get_detection_features(self) -> Dict[str, Any]:
        """
        Get information about the detection features used by the enhanced detector.
        
        Returns:
            Dictionary containing detection feature information
        """
        features = {}
        
        for feature in self.enhanced_detector.features:
            features[feature.name] = {
                "weight": feature.weight,
                "description": feature.__class__.__doc__ or "No description available"
            }
        
        return features
    
    def add_family_definition(self, family_data: Dict[str, Any]) -> bool:
        """
        Add a new family definition.
        
        Args:
            family_data: Family definition data
            
        Returns:
            True if the family was added successfully, False otherwise
        """
        try:
            result = self.enhanced_detector.add_family_definition(family_data)
            
            if result:
                # Update index file
                self.enhanced_detector.update_index_file()
            
            return result
            
        except Exception as e:
            logger.error(f"Error adding family definition: {e}")
            return False
    
    def update_family_definition(self, family_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update an existing family definition.
        
        Args:
            family_id: Family ID to update
            updates: Dictionary of fields to update
            
        Returns:
            True if the family was updated successfully, False otherwise
        """
        try:
            result = self.enhanced_detector.update_family_definition(family_id, updates)
            
            if result:
                # Update index file
                self.enhanced_detector.update_index_file()
            
            return result
            
        except Exception as e:
            logger.error(f"Error updating family definition: {e}")
            return False
    
    def extract_sample_features(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract features from a sample for manual analysis.
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            Dictionary of extracted features
        """
        try:
            return self.enhanced_detector.extract_features(sample_data)
        except Exception as e:
            logger.error(f"Error extracting sample features: {e}")
            return {}


# Singleton instance for global access
_instance = None

def get_family_detection_integration(families_dir=None, yara_rules_dir=None):
    """
    Get the singleton instance of the family detection integration.
    
    Args:
        families_dir: Directory containing family definition files
        yara_rules_dir: Directory containing YARA rules
        
    Returns:
        EnhancedFamilyDetectionIntegration instance
    """
    global _instance
    
    if _instance is None:
        _instance = EnhancedFamilyDetectionIntegration(
            families_dir=families_dir,
            yara_rules_dir=yara_rules_dir
        )
    
    return _instance