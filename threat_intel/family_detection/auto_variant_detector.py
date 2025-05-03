#!/usr/bin/env python3
"""
Automatic Ransomware Variant Detector

This module provides automatic feature extraction and similarity matching for
newly emerging ransomware variants. It uses machine learning techniques and
similarity analysis to identify new variants of known ransomware families.
"""

import os
import re
import json
import logging
import hashlib
import datetime
import difflib
import numpy as np
from typing import Dict, List, Set, Optional, Any, Tuple, Union
from pathlib import Path
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('auto_variant_detector')

class RansomwareVariantCluster:
    """
    Represents a cluster of similar ransomware samples that may constitute a variant
    """
    
    def __init__(self, base_family: str, variant_name: Optional[str] = None):
        """
        Initialize a ransomware variant cluster
        
        Args:
            base_family: Base family name
            variant_name: Optional variant name (auto-generated if not provided)
        """
        self.base_family = base_family
        self.variant_name = variant_name or f"{base_family}_variant_{datetime.datetime.now().strftime('%Y%m%d')}"
        self.samples = []
        self.feature_vectors = {}
        self.common_features = {}
        self.creation_date = datetime.datetime.now().isoformat()
        self.last_updated = self.creation_date
        self.confidence_score = 0.0
        self.distinctive_features = []
        self.relationship_score = 0.0  # Relationship to base family (0.0 to 1.0)
    
    def add_sample(self, sample_id: str, features: Dict[str, Any], vector: Dict[str, Any]) -> None:
        """
        Add a sample to the cluster
        
        Args:
            sample_id: Sample identifier
            features: Extracted features
            vector: Feature vector
        """
        self.samples.append(sample_id)
        self.feature_vectors[sample_id] = vector
        self.last_updated = datetime.datetime.now().isoformat()
        
        # Update common features
        if not self.common_features:
            self.common_features = features
        else:
            self._update_common_features(features)
    
    def _update_common_features(self, features: Dict[str, Any]) -> None:
        """
        Update common features based on a new sample
        
        Args:
            features: New sample features
        """
        # For each feature category
        for category, values in features.items():
            if category not in self.common_features:
                continue
                
            if isinstance(values, dict):
                # For dictionary features, keep common keys
                common_dict = {}
                for key, value in values.items():
                    if key in self.common_features[category]:
                        common_value = self.common_features[category][key]
                        if value == common_value:
                            common_dict[key] = value
                self.common_features[category] = common_dict
            
            elif isinstance(values, list):
                # For list features, keep intersection
                self.common_features[category] = [
                    item for item in self.common_features[category]
                    if item in values
                ]
    
    def calculate_cohesion(self) -> float:
        """
        Calculate cohesion score for this cluster (how similar samples are to each other)
        
        Returns:
            Cohesion score (0.0 to 1.0)
        """
        if len(self.samples) <= 1:
            return 1.0  # Perfect cohesion for single sample
        
        similarity_sum = 0.0
        comparison_count = 0
        
        # Compare each pair of samples
        for i in range(len(self.samples)):
            for j in range(i + 1, len(self.samples)):
                sample_i = self.samples[i]
                sample_j = self.samples[j]
                
                vector_i = self.feature_vectors[sample_i]
                vector_j = self.feature_vectors[sample_j]
                
                similarity = self._calculate_vector_similarity(vector_i, vector_j)
                similarity_sum += similarity
                comparison_count += 1
        
        # Average similarity
        return similarity_sum / comparison_count if comparison_count > 0 else 0.0
    
    def _calculate_vector_similarity(self, vector1: Dict[str, Any], vector2: Dict[str, Any]) -> float:
        """
        Calculate similarity between two feature vectors
        
        Args:
            vector1: First feature vector
            vector2: Second feature vector
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        # Ensure both vectors have the same keys
        all_keys = set(vector1.keys()).union(set(vector2.keys()))
        
        similarity_sum = 0.0
        key_count = 0
        
        for key in all_keys:
            if key in vector1 and key in vector2:
                # Both vectors have this feature
                if isinstance(vector1[key], (int, float)) and isinstance(vector2[key], (int, float)):
                    # Numeric features - calculate normalized similarity
                    max_val = max(abs(vector1[key]), abs(vector2[key]))
                    if max_val > 0:
                        similarity = 1.0 - (abs(vector1[key] - vector2[key]) / max_val)
                    else:
                        similarity = 1.0  # Both are zero, perfect match
                
                elif isinstance(vector1[key], str) and isinstance(vector2[key], str):
                    # String features - use sequence matcher
                    similarity = difflib.SequenceMatcher(None, vector1[key], vector2[key]).ratio()
                
                elif isinstance(vector1[key], (list, set)) and isinstance(vector2[key], (list, set)):
                    # List features - calculate Jaccard similarity
                    set1 = set(vector1[key])
                    set2 = set(vector2[key])
                    
                    if not set1 and not set2:
                        similarity = 1.0  # Both empty, perfect match
                    else:
                        intersection = len(set1.intersection(set2))
                        union = len(set1.union(set2))
                        similarity = intersection / union if union > 0 else 0.0
                
                elif isinstance(vector1[key], dict) and isinstance(vector2[key], dict):
                    # Dictionary features - recursive calculation
                    similarity = self._calculate_vector_similarity(vector1[key], vector2[key])
                
                else:
                    # Different types, no meaningful comparison
                    similarity = 0.0
                
                similarity_sum += similarity
                key_count += 1
        
        # Return average similarity across all features
        return similarity_sum / key_count if key_count > 0 else 0.0
    
    def extract_distinctive_features(self, base_family_features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract distinctive features that differentiate this variant from the base family
        
        Args:
            base_family_features: Features of the base family
            
        Returns:
            List of distinctive features
        """
        distinctive_features = []
        
        # Compare each feature category
        for category, values in self.common_features.items():
            if category not in base_family_features:
                # Entire category is distinctive
                distinctive_features.append({
                    "category": category,
                    "type": "new_category",
                    "description": f"New feature category '{category}' not present in base family"
                })
                continue
            
            base_values = base_family_features[category]
            
            if isinstance(values, dict) and isinstance(base_values, dict):
                # For dictionary features, find different values
                for key, value in values.items():
                    if key not in base_values:
                        distinctive_features.append({
                            "category": category,
                            "type": "new_property",
                            "property": key,
                            "value": value,
                            "description": f"New property '{key}' in '{category}'"
                        })
                    elif base_values[key] != value:
                        distinctive_features.append({
                            "category": category,
                            "type": "changed_property",
                            "property": key,
                            "old_value": base_values[key],
                            "new_value": value,
                            "description": f"Changed property '{key}' in '{category}'"
                        })
            
            elif isinstance(values, list) and isinstance(base_values, list):
                # For list features, find new items
                new_items = [item for item in values if item not in base_values]
                if new_items:
                    distinctive_features.append({
                        "category": category,
                        "type": "new_items",
                        "items": new_items,
                        "description": f"New items in '{category}'"
                    })
        
        # Store and return
        self.distinctive_features = distinctive_features
        return distinctive_features
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert cluster to dictionary representation
        
        Returns:
            Dictionary representation
        """
        return {
            "base_family": self.base_family,
            "variant_name": self.variant_name,
            "samples": self.samples,
            "creation_date": self.creation_date,
            "last_updated": self.last_updated,
            "confidence_score": self.confidence_score,
            "relationship_score": self.relationship_score,
            "sample_count": len(self.samples),
            "common_features": self.common_features,
            "distinctive_features": self.distinctive_features,
            "cohesion": self.calculate_cohesion()
        }
    
    def to_family_definition(self) -> Dict[str, Any]:
        """
        Convert cluster to a family definition format
        
        Returns:
            Family definition dictionary
        """
        # Extract information from common features
        encryption_info = {}
        extensions = []
        ransom_note = {}
        execution_behavior = {}
        
        # Process string patterns
        string_patterns = self.common_features.get("string_patterns", {})
        
        # Extract encryption references
        encryption_refs = string_patterns.get("encryption_references", [])
        for ref in encryption_refs:
            ref_lower = ref.lower()
            if "aes" in ref_lower:
                encryption_info["algorithm"] = "AES"
                if "256" in ref_lower:
                    encryption_info["key_length"] = 256
            elif "rsa" in ref_lower:
                encryption_info["algorithm"] = "RSA"
                if "2048" in ref_lower:
                    encryption_info["key_length"] = 2048
            elif "chacha" in ref_lower:
                encryption_info["algorithm"] = "ChaCha20"
            elif "salsa" in ref_lower:
                encryption_info["algorithm"] = "Salsa20"
        
        # Process extensions
        ext_features = self.common_features.get("ransomware_extensions", {})
        extensions = ext_features.get("encrypted_extensions", [])
        
        # Process ransom note
        ransom_note["filenames"] = ext_features.get("ransom_note_names", [])
        ransom_note["content_markers"] = string_patterns.get("ransom_note_content", [])
        
        # Process behavior
        behavior = self.common_features.get("behavior_patterns", {})
        command_patterns = behavior.get("command_patterns", [])
        
        execution_behavior["anti_analysis"] = command_patterns
        
        # Build family definition
        first_seen = datetime.datetime.now().strftime("%Y-%m")
        
        # Create definition
        definition = {
            "name": self.variant_name,
            "aliases": [self.variant_name],
            "first_seen": first_seen,
            "active": True,
            "ransomware_as_service": True,
            "group_attribution": f"Related to {self.base_family}",
            "sectors_targeted": ["unknown"],
            "description": f"Newly detected variant of {self.base_family} ransomware with {len(self.distinctive_features)} distinctive features.",
            "technical_details": {
                "programming_language": "Unknown",
                "key_generation": {
                    "method": "Unknown",
                    "description": "Key generation method has not been determined."
                },
                "encryption": encryption_info,
                "extension": extensions,
                "ransom_note": ransom_note,
                "file_markers": {
                    "header": "Unknown",
                    "footer": "Unknown"
                },
                "network_indicators": {
                    "c2_domains": [],
                    "tor_addresses": []
                },
                "execution_behavior": execution_behavior
            },
            "detection_signatures": {
                "yara_rules": [],
                "sigma_rules": []
            },
            "notable_attacks": [],
            "references": [],
            "last_updated": datetime.datetime.now().isoformat(),
            "auto_generated": True,
            "base_family": self.base_family,
            "confidence_score": self.confidence_score,
            "distinctive_features": self.distinctive_features
        }
        
        return definition


class AutoVariantDetector:
    """
    Automatic detector for new ransomware variants
    """
    
    def __init__(self, 
                enhanced_detector=None,
                clusters_dir: Optional[str] = None,
                similarity_threshold: float = 0.75,
                cohesion_threshold: float = 0.7,
                min_samples: int = 2):
        """
        Initialize the auto variant detector
        
        Args:
            enhanced_detector: EnhancedFamilyDetector instance
            clusters_dir: Directory for storing variant clusters
            similarity_threshold: Threshold for similarity matching
            cohesion_threshold: Threshold for cluster cohesion
            min_samples: Minimum samples for a valid cluster
        """
        self.enhanced_detector = enhanced_detector
        self.clusters_dir = clusters_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'data', 'variant_clusters'
        )
        
        # Create clusters directory if it doesn't exist
        os.makedirs(self.clusters_dir, exist_ok=True)
        
        self.similarity_threshold = similarity_threshold
        self.cohesion_threshold = cohesion_threshold
        self.min_samples = min_samples
        
        # Load existing clusters
        self.clusters = {}
        self._load_clusters()
        
        # Feature weight configuration
        self.feature_weights = {
            "string_patterns": 1.2,
            "behavior_patterns": 1.1,
            "file_structure": 0.9,
            "ransomware_extensions": 1.3,
            "network_indicators": 0.8,
            "yara_rules": 1.5
        }
        
        # Sample cache to avoid reprocessing
        self.sample_cache = {}
        
        logger.info(f"Auto Variant Detector initialized with {len(self.clusters)} clusters")
    
    def _load_clusters(self) -> None:
        """Load existing variant clusters"""
        if not os.path.exists(self.clusters_dir):
            return
        
        for filename in os.listdir(self.clusters_dir):
            if filename.endswith('.json'):
                try:
                    filepath = os.path.join(self.clusters_dir, filename)
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                    
                    # Reconstruct cluster
                    cluster_id = os.path.splitext(filename)[0]
                    base_family = data.get('base_family', 'unknown')
                    variant_name = data.get('variant_name', f"{base_family}_variant")
                    
                    cluster = RansomwareVariantCluster(base_family, variant_name)
                    cluster.creation_date = data.get('creation_date', cluster.creation_date)
                    cluster.last_updated = data.get('last_updated', cluster.last_updated)
                    cluster.confidence_score = data.get('confidence_score', 0.0)
                    cluster.relationship_score = data.get('relationship_score', 0.0)
                    cluster.samples = data.get('samples', [])
                    cluster.common_features = data.get('common_features', {})
                    cluster.distinctive_features = data.get('distinctive_features', [])
                    
                    # Note: We don't have feature vectors for existing samples
                    # This is acceptable as they'll be recomputed if needed
                    
                    self.clusters[cluster_id] = cluster
                    
                except Exception as e:
                    logger.error(f"Error loading cluster from {filename}: {e}")
        
        logger.info(f"Loaded {len(self.clusters)} variant clusters")
    
    def _save_cluster(self, cluster_id: str, cluster: RansomwareVariantCluster) -> None:
        """
        Save a cluster to disk
        
        Args:
            cluster_id: Cluster identifier
            cluster: Cluster object
        """
        try:
            filepath = os.path.join(self.clusters_dir, f"{cluster_id}.json")
            
            # Convert cluster to dictionary
            cluster_dict = cluster.to_dict()
            
            # Remove feature vectors to save space
            if "feature_vectors" in cluster_dict:
                del cluster_dict["feature_vectors"]
            
            # Save to file
            with open(filepath, 'w') as f:
                json.dump(cluster_dict, f, indent=2)
                
            logger.info(f"Saved cluster {cluster_id} to {filepath}")
            
        except Exception as e:
            logger.error(f"Error saving cluster {cluster_id}: {e}")
    
    def extract_feature_vector(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract a feature vector from sample features
        
        Args:
            features: Extracted features
            
        Returns:
            Feature vector
        """
        vector = {}
        
        # Process string patterns
        if "string_patterns" in features:
            string_patterns = features["string_patterns"]
            
            # Count pattern types
            vector["ransom_note_content_count"] = len(string_patterns.get("ransom_note_content", []))
            vector["encryption_references_count"] = len(string_patterns.get("encryption_references", []))
            vector["payment_references_count"] = len(string_patterns.get("payment_references", []))
            vector["file_markers_count"] = len(string_patterns.get("file_markers", []))
            vector["command_patterns_count"] = len(string_patterns.get("command_patterns", []))
            vector["url_patterns_count"] = len(string_patterns.get("url_patterns", []))
            
            # Extract encryption algorithms
            enc_refs = string_patterns.get("encryption_references", [])
            enc_algos = []
            for ref in enc_refs:
                ref_lower = ref.lower()
                if "aes" in ref_lower:
                    enc_algos.append("aes")
                if "rsa" in ref_lower:
                    enc_algos.append("rsa")
                if "chacha" in ref_lower:
                    enc_algos.append("chacha")
                if "salsa" in ref_lower:
                    enc_algos.append("salsa")
            
            vector["encryption_algorithms"] = enc_algos
            
            # Extract common ransom note words
            note_content = " ".join(string_patterns.get("ransom_note_content", []))
            common_words = set()
            for word in ["bitcoin", "payment", "decrypt", "key", "files", "restore", "wallet", "tor", "onion", "time"]:
                if word in note_content.lower():
                    common_words.add(word)
            
            vector["ransom_note_keywords"] = list(common_words)
        
        # Process behavior patterns
        if "behavior_patterns" in features:
            behavior = features["behavior_patterns"]
            
            # File operations
            file_ops = behavior.get("file_operations", {})
            vector["file_operations_total"] = file_ops.get("total_operations", 0)
            vector["file_extensions_count"] = len(file_ops.get("extensions_accessed", []))
            
            # Registry and process
            vector["registry_keys_count"] = len(behavior.get("registry_keys", []))
            vector["process_actions_count"] = len(behavior.get("process_actions", []))
            vector["command_patterns_count"] = len(behavior.get("command_patterns", []))
        
        # Process file structure
        if "file_structure" in features:
            file_struct = features["file_structure"]
            
            vector["file_type"] = file_struct.get("file_type", "unknown")
            vector["file_size"] = file_struct.get("file_size", 0)
            vector["pe_sections_count"] = len(file_struct.get("pe_sections", []))
            vector["imports_count"] = len(file_struct.get("imports", []))
            vector["exports_count"] = len(file_struct.get("exports", []))
            vector["resources_count"] = len(file_struct.get("resources", []))
            vector["encryption_markers_count"] = len(file_struct.get("encryption_markers", []))
        
        # Process extensions
        if "ransomware_extensions" in features:
            extensions = features["ransomware_extensions"]
            
            vector["encrypted_extensions_count"] = len(extensions.get("encrypted_extensions", []))
            vector["ransom_note_names_count"] = len(extensions.get("ransom_note_names", []))
            vector["extension_append_mode"] = 1 if extensions.get("extension_append_mode", False) else 0
            vector["email_references_count"] = len(extensions.get("email_references", []))
        
        # Process network indicators
        if "network_indicators" in features:
            network = features["network_indicators"]
            
            vector["domains_count"] = len(network.get("domains", []))
            vector["ips_count"] = len(network.get("ips", []))
            vector["urls_count"] = len(network.get("urls", []))
            vector["protocols_count"] = len(network.get("protocols", []))
            vector["tor_references_count"] = len(network.get("tor_references", []))
            vector["c2_patterns_count"] = len(network.get("c2_patterns", []))
        
        # Process YARA rules
        if "yara_rules" in features:
            yara = features["yara_rules"]
            
            vector["rule_matches_count"] = len(yara.get("rule_matches", []))
            vector["family_matches_count"] = len(yara.get("family_matches", {}))
            
            # Add family matches as a feature
            vector["family_matches"] = list(yara.get("family_matches", {}).keys())
        
        return vector
    
    def process_sample(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a sample for variant detection
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            Processing results
        """
        results = {
            "sample_id": sample_data.get("sha256", "unknown"),
            "timestamp": datetime.datetime.now().isoformat(),
            "enhanced_results": None,
            "variant_detection": {
                "is_variant": False,
                "base_family": None,
                "variant_name": None,
                "confidence": 0.0,
                "cluster_id": None,
                "is_new_variant": False
            }
        }
        
        try:
            # Check cache first
            sample_id = results["sample_id"]
            if sample_id in self.sample_cache:
                cached_result = self.sample_cache[sample_id]
                logger.info(f"Using cached result for sample {sample_id}")
                return cached_result
            
            # Use enhanced detector to identify family
            if self.enhanced_detector:
                family_results = self.enhanced_detector.identify_family(
                    sample_data, 
                    min_score=0.5
                )
                
                if family_results:
                    # Get top family match
                    top_family = family_results[0]
                    results["enhanced_results"] = {
                        "family_name": top_family["family_name"],
                        "confidence": top_family["confidence"],
                        "has_variant": "variant" in top_family
                    }
                    
                    # If high confidence match and no variant, look for variant match
                    if top_family["confidence"] >= 0.6 and "variant" not in top_family:
                        base_family = top_family["family_id"]
                        
                        # Extract features and vector
                        features = self.enhanced_detector.extract_features(sample_data)
                        vector = self.extract_feature_vector(features)
                        
                        # Check for variant match
                        variant_result = self._check_variant_match(
                            sample_id, base_family, features, vector
                        )
                        
                        # Update results
                        results["variant_detection"] = variant_result
            
            # Add to cache
            self.sample_cache[sample_id] = results
            
            return results
            
        except Exception as e:
            logger.error(f"Error processing sample for variant detection: {e}")
            return results
    
    def _check_variant_match(self, sample_id: str, base_family: str, 
                           features: Dict[str, Any], vector: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if a sample matches an existing variant or forms a new variant
        
        Args:
            sample_id: Sample identifier
            base_family: Base family identifier
            features: Extracted features
            vector: Feature vector
            
        Returns:
            Variant detection results
        """
        result = {
            "is_variant": False,
            "base_family": base_family,
            "variant_name": None,
            "confidence": 0.0,
            "cluster_id": None,
            "is_new_variant": False
        }
        
        # Find relevant clusters for this base family
        relevant_clusters = [
            (cluster_id, cluster) for cluster_id, cluster in self.clusters.items()
            if cluster.base_family == base_family
        ]
        
        # Match with existing clusters
        best_match = None
        best_score = 0.0
        
        for cluster_id, cluster in relevant_clusters:
            # Skip clusters with no feature vectors
            if not cluster.feature_vectors:
                continue
            
            # Calculate average similarity to all samples in the cluster
            similarity_sum = 0.0
            for other_id, other_vector in cluster.feature_vectors.items():
                similarity = self._calculate_weighted_similarity(vector, other_vector)
                similarity_sum += similarity
            
            avg_similarity = similarity_sum / len(cluster.feature_vectors)
            
            # Check if this is better than current best
            if avg_similarity > best_score and avg_similarity >= self.similarity_threshold:
                best_score = avg_similarity
                best_match = (cluster_id, cluster)
        
        # If match found, add to existing cluster
        if best_match:
            cluster_id, cluster = best_match
            
            # Add sample to cluster
            cluster.add_sample(sample_id, features, vector)
            
            # Update cohesion and confidence
            cohesion = cluster.calculate_cohesion()
            if cohesion >= self.cohesion_threshold:
                # Good cohesion, update confidence
                cluster.confidence_score = min(cluster.confidence_score + 0.05, 1.0)
            else:
                # Poor cohesion, reduce confidence
                cluster.confidence_score = max(cluster.confidence_score - 0.05, 0.0)
            
            # Save updated cluster
            self._save_cluster(cluster_id, cluster)
            
            # Update result
            result["is_variant"] = True
            result["variant_name"] = cluster.variant_name
            result["confidence"] = best_score
            result["cluster_id"] = cluster_id
            result["is_new_variant"] = False
            
            logger.info(f"Sample {sample_id} matched existing variant cluster {cluster_id} with score {best_score:.2f}")
            
        else:
            # No good match found, create a new cluster candidate
            cluster_id = f"{base_family}_variant_{hashlib.md5(sample_id.encode()).hexdigest()[:8]}"
            new_cluster = RansomwareVariantCluster(base_family)
            
            # Add sample
            new_cluster.add_sample(sample_id, features, vector)
            
            # Set initial confidence
            new_cluster.confidence_score = 0.3  # Start with low confidence
            
            # Save cluster candidate
            self.clusters[cluster_id] = new_cluster
            self._save_cluster(cluster_id, new_cluster)
            
            # Update result
            result["is_variant"] = True
            result["variant_name"] = new_cluster.variant_name
            result["confidence"] = 0.3  # Low initial confidence
            result["cluster_id"] = cluster_id
            result["is_new_variant"] = True
            
            logger.info(f"Created new variant cluster candidate {cluster_id} for sample {sample_id}")
        
        return result
    
    def _calculate_weighted_similarity(self, vector1: Dict[str, Any], vector2: Dict[str, Any]) -> float:
        """
        Calculate weighted similarity between two feature vectors
        
        Args:
            vector1: First feature vector
            vector2: Second feature vector
            
        Returns:
            Weighted similarity score (0.0 to 1.0)
        """
        # Get common numeric features
        numeric_features = {}
        for key in vector1:
            if key in vector2 and isinstance(vector1[key], (int, float)) and isinstance(vector2[key], (int, float)):
                numeric_features[key] = (vector1[key], vector2[key])
        
        # Get common list features
        list_features = {}
        for key in vector1:
            if key in vector2 and isinstance(vector1[key], list) and isinstance(vector2[key], list):
                list_features[key] = (vector1[key], vector2[key])
        
        # Calculate similarity for numeric features
        numeric_similarity = 0.0
        numeric_weight_sum = 0.0
        
        for key, (val1, val2) in numeric_features.items():
            # Determine feature category
            category = self._get_feature_category(key)
            weight = self.feature_weights.get(category, 1.0)
            
            # Calculate normalized similarity
            max_val = max(abs(val1), abs(val2))
            if max_val > 0:
                similarity = 1.0 - (abs(val1 - val2) / max_val)
            else:
                similarity = 1.0  # Both are zero, perfect match
            
            numeric_similarity += similarity * weight
            numeric_weight_sum += weight
        
        # Calculate similarity for list features
        list_similarity = 0.0
        list_weight_sum = 0.0
        
        for key, (list1, list2) in list_features.items():
            # Determine feature category
            category = self._get_feature_category(key)
            weight = self.feature_weights.get(category, 1.0)
            
            # Calculate Jaccard similarity
            set1 = set(list1)
            set2 = set(list2)
            
            if not set1 and not set2:
                similarity = 1.0  # Both empty, perfect match
            else:
                intersection = len(set1.intersection(set2))
                union = len(set1.union(set2))
                similarity = intersection / union if union > 0 else 0.0
            
            list_similarity += similarity * weight
            list_weight_sum += weight
        
        # Combine similarities
        total_weight_sum = numeric_weight_sum + list_weight_sum
        if total_weight_sum > 0:
            combined_similarity = (numeric_similarity + list_similarity) / total_weight_sum
        else:
            combined_similarity = 0.0
        
        return combined_similarity
    
    def _get_feature_category(self, feature_name: str) -> str:
        """
        Determine the category of a feature based on its name
        
        Args:
            feature_name: Feature name
            
        Returns:
            Category name
        """
        if any(x in feature_name for x in ["note", "encryption", "payment", "marker", "command", "url"]):
            return "string_patterns"
        elif any(x in feature_name for x in ["file_operations", "registry", "process", "api"]):
            return "behavior_patterns"
        elif any(x in feature_name for x in ["file_type", "section", "import", "export", "resource"]):
            return "file_structure"
        elif any(x in feature_name for x in ["extension", "append", "email"]):
            return "ransomware_extensions"
        elif any(x in feature_name for x in ["domain", "ip", "url", "protocol", "tor", "c2"]):
            return "network_indicators"
        elif any(x in feature_name for x in ["rule", "yara", "match"]):
            return "yara_rules"
        else:
            return "other"
    
    def evaluate_clusters(self) -> List[Dict[str, Any]]:
        """
        Evaluate all clusters to identify valid new variants
        
        Returns:
            List of valid variant clusters
        """
        valid_variants = []
        
        for cluster_id, cluster in self.clusters.items():
            # Skip clusters with too few samples
            if len(cluster.samples) < self.min_samples:
                continue
            
            # Calculate cohesion
            cohesion = cluster.calculate_cohesion()
            
            # Check if this is a valid variant
            is_valid = (
                cohesion >= self.cohesion_threshold and
                cluster.confidence_score >= 0.6 and
                len(cluster.samples) >= self.min_samples
            )
            
            if is_valid:
                # Get base family features
                base_family_features = {}
                if self.enhanced_detector:
                    base_family_features = self.enhanced_detector.extract_family_features(cluster.base_family)
                
                # Extract distinctive features
                distinctive_features = cluster.extract_distinctive_features(base_family_features)
                
                # Calculate relationship to base family
                relationship_score = 0.0
                if self.enhanced_detector and base_family_features:
                    # Compare a random sample's features with base family
                    if cluster.samples:
                        sample_id = cluster.samples[0]
                        if sample_id in cluster.feature_vectors:
                            sample_vector = cluster.feature_vectors[sample_id]
                            
                            # Extract base family vector
                            base_vector = self.extract_feature_vector(base_family_features)
                            
                            # Calculate similarity
                            relationship_score = self._calculate_weighted_similarity(sample_vector, base_vector)
                
                # Update cluster
                cluster.relationship_score = relationship_score
                self._save_cluster(cluster_id, cluster)
                
                # Add to valid variants
                valid_variants.append({
                    "cluster_id": cluster_id,
                    "base_family": cluster.base_family,
                    "variant_name": cluster.variant_name,
                    "samples": len(cluster.samples),
                    "confidence": cluster.confidence_score,
                    "cohesion": cohesion,
                    "relationship_score": relationship_score,
                    "distinctive_features_count": len(distinctive_features)
                })
        
        # Sort by confidence
        valid_variants.sort(key=lambda x: x["confidence"], reverse=True)
        
        return valid_variants
    
    def generate_variant_definition(self, cluster_id: str) -> Optional[Dict[str, Any]]:
        """
        Generate a family definition for a variant
        
        Args:
            cluster_id: Cluster identifier
            
        Returns:
            Family definition dictionary or None if cluster not found
        """
        if cluster_id not in self.clusters:
            logger.error(f"Cluster {cluster_id} not found")
            return None
        
        try:
            cluster = self.clusters[cluster_id]
            
            # Check if this is a valid variant
            if len(cluster.samples) < self.min_samples or cluster.confidence_score < 0.6:
                logger.warning(f"Cluster {cluster_id} is not a valid variant")
                return None
            
            # Generate variant definition
            definition = cluster.to_family_definition()
            
            # Enhance with YARA rule if possible
            if self.enhanced_detector:
                # Get base family YARA rule
                base_family_features = self.enhanced_detector.extract_family_features(cluster.base_family)
                if "yara_rules" in base_family_features:
                    yara_rules = base_family_features["yara_rules"].get("rule_matches", [])
                    if yara_rules:
                        for rule in yara_rules:
                            if "rule" in rule and rule["rule"].startswith(f"{cluster.base_family}_ransomware"):
                                # Create variant rule based on base rule
                                variant_rule = rule.copy()
                                variant_rule["rule"] = f"{cluster.variant_name}_variant"
                                variant_rule["namespace"] = "variant_detections"
                                
                                if "meta" in variant_rule:
                                    variant_rule["meta"]["family"] = cluster.base_family
                                    variant_rule["meta"]["variant"] = cluster.variant_name
                                    variant_rule["meta"]["auto_generated"] = "true"
                                
                                # Add to definition
                                definition["detection_signatures"]["yara_rules"] = [
                                    f"rule {cluster.variant_name}_Variant {{",
                                    f"    meta:",
                                    f"        description = \"Auto-generated rule for {cluster.variant_name}\"",
                                    f"        author = \"Auto Variant Detector\"",
                                    f"        family = \"{cluster.base_family}\"",
                                    f"        variant = \"{cluster.variant_name}\"",
                                    f"        auto_generated = \"true\"",
                                    f"    strings:",
                                    f"        // Base strings from {cluster.base_family}"
                                ]
                                
                                # Add distinctive strings
                                distinctive_strings = []
                                for feature in cluster.distinctive_features:
                                    if feature["type"] == "new_items" and feature["category"] == "string_patterns":
                                        for i, item in enumerate(feature["items"]):
                                            if len(item) > 5:  # Only use meaningful strings
                                                distinctive_strings.append(
                                                    f"        $variant{i+1} = \"{item}\" ascii wide"
                                                )
                                
                                # Add condition
                                if distinctive_strings:
                                    definition["detection_signatures"]["yara_rules"].extend(distinctive_strings)
                                    definition["detection_signatures"]["yara_rules"].extend([
                                        f"    condition:",
                                        f"        uint16(0) == 0x5A4D and",
                                        f"        filesize < 15MB and",
                                        f"        2 of ($variant*)",
                                        f"}}"
                                    ])
                                else:
                                    # No distinctive strings, use generic condition
                                    definition["detection_signatures"]["yara_rules"].extend([
                                        f"        $s1 = \"{cluster.variant_name}\" ascii wide nocase",
                                        f"    condition:",
                                        f"        uint16(0) == 0x5A4D and",
                                        f"        filesize < 15MB and",
                                        f"        all of them",
                                        f"}}"
                                    ])
            
            return definition
            
        except Exception as e:
            logger.error(f"Error generating variant definition for {cluster_id}: {e}")
            return None
    
    def generate_all_variant_definitions(self) -> Dict[str, Dict[str, Any]]:
        """
        Generate family definitions for all valid variants
        
        Returns:
            Dictionary mapping cluster IDs to family definitions
        """
        definitions = {}
        
        # Get valid variants
        valid_variants = self.evaluate_clusters()
        
        # Generate definitions for each valid variant
        for variant in valid_variants:
            cluster_id = variant["cluster_id"]
            definition = self.generate_variant_definition(cluster_id)
            if definition:
                definitions[cluster_id] = definition
        
        return definitions
    
    def save_variant_definitions(self, output_dir: Optional[str] = None) -> Dict[str, str]:
        """
        Save variant definitions to files
        
        Args:
            output_dir: Output directory (defaults to families directory)
            
        Returns:
            Dictionary mapping cluster IDs to file paths
        """
        # Use enhanced detector's families directory if available
        if not output_dir and self.enhanced_detector:
            output_dir = self.enhanced_detector.families_dir
        
        if not output_dir:
            logger.error("No output directory specified")
            return {}
        
        # Create directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate definitions
        definitions = self.generate_all_variant_definitions()
        
        # Save to files
        saved_files = {}
        
        for cluster_id, definition in definitions.items():
            variant_name = definition.get("name", cluster_id).lower().replace(" ", "_")
            filepath = os.path.join(output_dir, f"{variant_name}.json")
            
            try:
                with open(filepath, 'w') as f:
                    json.dump(definition, f, indent=2)
                    
                saved_files[cluster_id] = filepath
                logger.info(f"Saved variant definition for {cluster_id} to {filepath}")
                
            except Exception as e:
                logger.error(f"Error saving variant definition for {cluster_id}: {e}")
        
        return saved_files
    
    def clear_cache(self) -> None:
        """Clear the sample cache"""
        self.sample_cache = {}
        logger.info("Sample cache cleared")


def process_sample_batch(detector: AutoVariantDetector, samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Process a batch of samples for variant detection
    
    Args:
        detector: Auto variant detector
        samples: List of sample analysis data
        
    Returns:
        Batch processing results
    """
    results = {
        "timestamp": datetime.datetime.now().isoformat(),
        "samples_processed": len(samples),
        "variant_matches": [],
        "new_variants": []
    }
    
    # Process each sample
    for sample in samples:
        sample_result = detector.process_sample(sample)
        
        variant_detection = sample_result.get("variant_detection", {})
        if variant_detection.get("is_variant", False):
            if variant_detection.get("is_new_variant", False):
                results["new_variants"].append({
                    "sample_id": sample_result.get("sample_id", "unknown"),
                    "base_family": variant_detection.get("base_family", "unknown"),
                    "variant_name": variant_detection.get("variant_name", "unknown"),
                    "cluster_id": variant_detection.get("cluster_id", "unknown"),
                    "confidence": variant_detection.get("confidence", 0.0)
                })
            else:
                results["variant_matches"].append({
                    "sample_id": sample_result.get("sample_id", "unknown"),
                    "base_family": variant_detection.get("base_family", "unknown"),
                    "variant_name": variant_detection.get("variant_name", "unknown"),
                    "cluster_id": variant_detection.get("cluster_id", "unknown"),
                    "confidence": variant_detection.get("confidence", 0.0)
                })
    
    # Evaluate clusters to find valid variants
    valid_variants = detector.evaluate_clusters()
    results["valid_variants"] = valid_variants
    
    return results


if __name__ == "__main__":
    import sys
    import argparse
    
    # Try to import EnhancedFamilyDetector
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(script_dir)
        sys.path.append(parent_dir)
        
        from family_detection.enhanced_family_detector import EnhancedFamilyDetector
    except ImportError:
        EnhancedFamilyDetector = None
    
    parser = argparse.ArgumentParser(description="Automatic Ransomware Variant Detector")
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Process sample command
    process_parser = subparsers.add_parser('process', help='Process a sample')
    process_parser.add_argument('--sample', required=True, help='Path to sample analysis JSON file')
    process_parser.add_argument('--families-dir', help='Directory containing family definitions')
    process_parser.add_argument('--output', help='Output file for results')
    
    # Process batch command
    batch_parser = subparsers.add_parser('batch', help='Process a batch of samples')
    batch_parser.add_argument('--samples-dir', required=True, help='Directory containing sample analysis JSON files')
    batch_parser.add_argument('--families-dir', help='Directory containing family definitions')
    batch_parser.add_argument('--output', help='Output file for results')
    
    # List clusters command
    list_parser = subparsers.add_parser('list', help='List variant clusters')
    list_parser.add_argument('--clusters-dir', help='Directory containing variant clusters')
    list_parser.add_argument('--output', help='Output file for results')
    
    # Generate definitions command
    generate_parser = subparsers.add_parser('generate', help='Generate variant definitions')
    generate_parser.add_argument('--clusters-dir', help='Directory containing variant clusters')
    generate_parser.add_argument('--families-dir', help='Directory containing family definitions')
    generate_parser.add_argument('--output-dir', help='Output directory for variant definitions')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Create enhanced detector if possible
    enhanced_detector = None
    if EnhancedFamilyDetector:
        enhanced_detector = EnhancedFamilyDetector(
            families_dir=args.families_dir if hasattr(args, 'families_dir') else None
        )
    
    # Create variant detector
    variant_detector = AutoVariantDetector(
        enhanced_detector=enhanced_detector,
        clusters_dir=args.clusters_dir if hasattr(args, 'clusters_dir') else None
    )
    
    if args.command == 'process':
        # Load sample data
        try:
            with open(args.sample, 'r') as f:
                sample_data = json.load(f)
            
            # Process sample
            result = variant_detector.process_sample(sample_data)
            
            # Output result
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(result, f, indent=2)
            else:
                print(json.dumps(result, indent=2))
            
            # Print summary
            variant_detection = result.get("variant_detection", {})
            if variant_detection.get("is_variant", False):
                print(f"\nSample {result.get('sample_id', 'unknown')} identified as a variant:")
                print(f"Base Family: {variant_detection.get('base_family', 'unknown')}")
                print(f"Variant: {variant_detection.get('variant_name', 'unknown')}")
                print(f"Confidence: {variant_detection.get('confidence', 0.0):.2f}")
                print(f"Cluster ID: {variant_detection.get('cluster_id', 'unknown')}")
                print(f"New Variant: {'Yes' if variant_detection.get('is_new_variant', False) else 'No'}")
            else:
                print(f"\nSample {result.get('sample_id', 'unknown')} is not identified as a variant")
            
        except Exception as e:
            print(f"Error processing sample: {e}")
            sys.exit(1)
    
    elif args.command == 'batch':
        # Load sample files
        samples = []
        
        if not os.path.exists(args.samples_dir):
            print(f"Samples directory not found: {args.samples_dir}")
            sys.exit(1)
        
        for filename in os.listdir(args.samples_dir):
            if filename.endswith('.json'):
                try:
                    filepath = os.path.join(args.samples_dir, filename)
                    with open(filepath, 'r') as f:
                        sample_data = json.load(f)
                    
                    samples.append(sample_data)
                except Exception as e:
                    print(f"Error loading sample from {filename}: {e}")
        
        if not samples:
            print("No valid sample files found")
            sys.exit(1)
        
        # Process batch
        result = process_sample_batch(variant_detector, samples)
        
        # Output result
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2)
        else:
            print(json.dumps(result, indent=2))
        
        # Print summary
        print(f"\nProcessed {result.get('samples_processed', 0)} samples")
        print(f"Variant matches: {len(result.get('variant_matches', []))}")
        print(f"New variants: {len(result.get('new_variants', []))}")
        print(f"Valid variants: {len(result.get('valid_variants', []))}")
    
    elif args.command == 'list':
        # List variant clusters
        clusters = variant_detector.evaluate_clusters()
        
        # Output result
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(clusters, f, indent=2)
        else:
            print(json.dumps(clusters, indent=2))
        
        # Print summary
        print(f"\nFound {len(clusters)} valid variant clusters")
    
    elif args.command == 'generate':
        # Generate variant definitions
        saved_files = variant_detector.save_variant_definitions(
            output_dir=args.output_dir
        )
        
        # Print summary
        print(f"\nGenerated {len(saved_files)} variant definitions")
        for cluster_id, filepath in saved_files.items():
            print(f"- {cluster_id}: {filepath}")
    
    else:
        parser.print_help()