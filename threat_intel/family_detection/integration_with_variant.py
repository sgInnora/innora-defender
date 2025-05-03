#!/usr/bin/env python3
"""
Enhanced Ransomware Family Detection Integration with Variant Detection

This module extends the enhanced family detection integration with automatic
variant detection capabilities, providing a complete solution for identifying
known families, their variants, and emerging new variants.
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional

from .enhanced_family_detector import EnhancedFamilyDetector
from .auto_variant_detector import AutoVariantDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('family_detection_integration')

class AdvancedFamilyDetectionIntegration:
    """
    Integration class for enhanced family detection with variant detection.
    
    This class provides a bridge between the enhanced family detector, the
    automatic variant detector, and the existing correlation engine.
    """
    
    def __init__(self, 
                 families_dir: Optional[str] = None, 
                 yara_rules_dir: Optional[str] = None,
                 clusters_dir: Optional[str] = None,
                 fallback_to_legacy: bool = True,
                 min_confidence_threshold: float = 0.6,
                 auto_variant_detection: bool = True,
                 similarity_threshold: float = 0.75,
                 cohesion_threshold: float = 0.7,
                 min_variant_samples: int = 2):
        """
        Initialize the integration.
        
        Args:
            families_dir: Directory containing family definition files
            yara_rules_dir: Directory containing YARA rules
            clusters_dir: Directory containing variant clusters
            fallback_to_legacy: Whether to fall back to legacy detection if enhanced fails
            min_confidence_threshold: Minimum confidence threshold for family identification
            auto_variant_detection: Whether to enable automatic variant detection
            similarity_threshold: Threshold for similarity matching in variant detection
            cohesion_threshold: Threshold for cluster cohesion in variant detection
            min_variant_samples: Minimum samples for a valid variant cluster
        """
        # Initialize enhanced detector
        self.enhanced_detector = EnhancedFamilyDetector(
            families_dir=families_dir,
            yara_rules_dir=yara_rules_dir
        )
        
        # Initialize variant detector if enabled
        self.auto_variant_detection = auto_variant_detection
        self.variant_detector = None
        
        if auto_variant_detection:
            self.variant_detector = AutoVariantDetector(
                enhanced_detector=self.enhanced_detector,
                clusters_dir=clusters_dir,
                similarity_threshold=similarity_threshold,
                cohesion_threshold=cohesion_threshold,
                min_samples=min_variant_samples
            )
        
        self.fallback_to_legacy = fallback_to_legacy
        self.min_confidence_threshold = min_confidence_threshold
        
        logger.info("Advanced Family Detection Integration initialized")
        if auto_variant_detection:
            logger.info(f"Automatic variant detection enabled with {len(self.variant_detector.clusters)} clusters")
    
    def identify_ransomware_family(self, sample_data: Dict[str, Any], 
                                  legacy_results: Optional[List[Dict]] = None) -> List[Dict]:
        """
        Identify ransomware family using enhanced detection and variant detection.
        
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
            
            # Add detection method
            for result in enhanced_results:
                result["detection_method"] = "enhanced_detection"
            
            # Run variant detection if enabled and we have a family match
            if self.auto_variant_detection and self.variant_detector and enhanced_results:
                variant_result = self.variant_detector.process_sample(sample_data)
                
                variant_detection = variant_result.get("variant_detection", {})
                if variant_detection.get("is_variant", False):
                    # Add variant information to family results
                    for result in enhanced_results:
                        if result["family_id"] == variant_detection.get("base_family"):
                            result["variant"] = variant_detection.get("variant_name")
                            result["variant_confidence"] = variant_detection.get("confidence")
                            result["variant_cluster_id"] = variant_detection.get("cluster_id")
                            result["is_new_variant"] = variant_detection.get("is_new_variant", False)
                            break
                    
                    # If it's a high-confidence new variant, add it as a separate entry
                    if variant_detection.get("is_new_variant", False) and variant_detection.get("confidence", 0) >= 0.6:
                        cluster_id = variant_detection.get("cluster_id")
                        if cluster_id and cluster_id in self.variant_detector.clusters:
                            cluster = self.variant_detector.clusters[cluster_id]
                            
                            # Add to results
                            variant_entry = {
                                "family_id": f"{variant_detection['base_family']}_variant",
                                "family_name": variant_detection["variant_name"],
                                "confidence": variant_detection["confidence"],
                                "detection_method": "variant_detection",
                                "is_variant": True,
                                "base_family": variant_detection["base_family"],
                                "variant_cluster_id": variant_detection["cluster_id"],
                                "is_new_variant": True,
                                "feature_scores": {}  # We don't have per-feature scores for variants
                            }
                            
                            # Add distinctive features if available
                            if cluster.distinctive_features:
                                variant_entry["distinctive_features"] = cluster.distinctive_features
                            
                            enhanced_results.append(variant_entry)
            
            # If we have results, return them
            if enhanced_results:
                logger.info(f"Advanced detection identified {len(enhanced_results)} families/variants")
                return enhanced_results
            
            # If no results and fallback is enabled, use legacy results
            if self.fallback_to_legacy and legacy_results:
                logger.info("Advanced detection found no families, falling back to legacy detection")
                
                # Add detection method to indicate legacy
                for result in legacy_results:
                    result["detection_method"] = "legacy_detection"
                
                return legacy_results
            
            # No results found
            logger.info("No ransomware families identified")
            return []
            
        except Exception as e:
            logger.error(f"Error in advanced ransomware family detection: {e}")
            
            # Fall back to legacy results if available
            if self.fallback_to_legacy and legacy_results:
                logger.info("Error in advanced detection, falling back to legacy detection")
                
                # Add detection method to indicate legacy
                for result in legacy_results:
                    result["detection_method"] = "legacy_detection"
                
                return legacy_results
            
            # Return empty list on error
            return []
    
    def refine_family_information(self, family_name: str) -> Dict[str, Any]:
        """
        Get detailed information about a ransomware family or variant.
        
        Args:
            family_name: Name of the ransomware family or variant
            
        Returns:
            Dictionary containing detailed family information
        """
        try:
            # Check if this is a variant
            if self.auto_variant_detection and self.variant_detector:
                # Look for matching variant
                for cluster_id, cluster in self.variant_detector.clusters.items():
                    if cluster.variant_name.lower() == family_name.lower():
                        # Generate variant definition
                        definition = self.variant_detector.generate_variant_definition(cluster_id)
                        if definition:
                            # Extract key information
                            result = {
                                "name": definition.get("name", family_name),
                                "aliases": definition.get("aliases", []),
                                "active": definition.get("active", True),
                                "first_seen": definition.get("first_seen", "unknown"),
                                "description": definition.get("description", ""),
                                "technical_details": definition.get("technical_details", {}),
                                "is_variant": True,
                                "base_family": definition.get("base_family", "unknown"),
                                "auto_generated": True,
                                "confidence_score": cluster.confidence_score,
                                "distinctive_features": cluster.distinctive_features
                            }
                            
                            return result
            
            # Not a variant or variant not found, try base family
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
            
            # Check for known variants
            if self.auto_variant_detection and self.variant_detector:
                variants = []
                
                for cluster_id, cluster in self.variant_detector.clusters.items():
                    if cluster.base_family == normalized_name and cluster.confidence_score >= 0.6:
                        variants.append({
                            "name": cluster.variant_name,
                            "confidence": cluster.confidence_score,
                            "samples": len(cluster.samples),
                            "first_seen": cluster.creation_date,
                            "cluster_id": cluster_id
                        })
                
                if variants:
                    result["known_variants"] = variants
            
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
            
            # Get base families
            for family_id, family_data in self.enhanced_detector.families.items():
                family_entry = {
                    "id": family_id,
                    "name": family_data.get("name", family_id),
                    "aliases": family_data.get("aliases", []),
                    "active": family_data.get("active", False),
                    "is_variant": False
                }
                
                results.append(family_entry)
            
            # Add variants if enabled
            if self.auto_variant_detection and self.variant_detector:
                # Get valid variants
                valid_variants = self.variant_detector.evaluate_clusters()
                
                for variant in valid_variants:
                    variant_entry = {
                        "id": variant["cluster_id"],
                        "name": variant["variant_name"],
                        "aliases": [variant["variant_name"]],
                        "active": True,  # Variants are considered active
                        "is_variant": True,
                        "base_family": variant["base_family"],
                        "confidence": variant["confidence"]
                    }
                    
                    results.append(variant_entry)
            
            return results
            
        except Exception as e:
            logger.error(f"Error retrieving family names: {e}")
            return []
    
    def get_detection_features(self) -> Dict[str, Any]:
        """
        Get information about the detection features used by the detectors.
        
        Returns:
            Dictionary containing detection feature information
        """
        features = {}
        
        # Enhanced detector features
        for feature in self.enhanced_detector.features:
            features[feature.name] = {
                "weight": feature.weight,
                "description": feature.__class__.__doc__ or "No description available"
            }
        
        # Variant detector features
        if self.auto_variant_detection and self.variant_detector:
            features["variant_detection"] = {
                "similarity_threshold": self.variant_detector.similarity_threshold,
                "cohesion_threshold": self.variant_detector.cohesion_threshold,
                "min_samples": self.variant_detector.min_samples,
                "feature_weights": self.variant_detector.feature_weights
            }
        
        return features
    
    def get_variant_clusters(self) -> List[Dict[str, Any]]:
        """
        Get information about variant clusters.
        
        Returns:
            List of variant cluster information
        """
        if not self.auto_variant_detection or not self.variant_detector:
            return []
        
        return self.variant_detector.evaluate_clusters()
    
    def generate_variant_definition(self, cluster_id: str) -> Optional[Dict[str, Any]]:
        """
        Generate a family definition for a variant.
        
        Args:
            cluster_id: Cluster identifier
            
        Returns:
            Family definition dictionary or None if cluster not found
        """
        if not self.auto_variant_detection or not self.variant_detector:
            return None
        
        return self.variant_detector.generate_variant_definition(cluster_id)
    
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
    
    def save_variant_definitions(self, output_dir: Optional[str] = None) -> Dict[str, str]:
        """
        Save variant definitions to files.
        
        Args:
            output_dir: Output directory (defaults to families directory)
            
        Returns:
            Dictionary mapping cluster IDs to file paths
        """
        if not self.auto_variant_detection or not self.variant_detector:
            return {}
        
        # Use enhanced detector's families directory if not specified
        if not output_dir:
            output_dir = self.enhanced_detector.families_dir
        
        return self.variant_detector.save_variant_definitions(output_dir)
    
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

def get_advanced_family_detection(families_dir=None, yara_rules_dir=None, clusters_dir=None,
                                auto_variant_detection=True):
    """
    Get the singleton instance of the advanced family detection integration.
    
    Args:
        families_dir: Directory containing family definition files
        yara_rules_dir: Directory containing YARA rules
        clusters_dir: Directory containing variant clusters
        auto_variant_detection: Whether to enable automatic variant detection
        
    Returns:
        AdvancedFamilyDetectionIntegration instance
    """
    global _instance
    
    if _instance is None:
        _instance = AdvancedFamilyDetectionIntegration(
            families_dir=families_dir,
            yara_rules_dir=yara_rules_dir,
            clusters_dir=clusters_dir,
            auto_variant_detection=auto_variant_detection
        )
    
    return _instance