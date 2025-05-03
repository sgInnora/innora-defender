#!/usr/bin/env python3
"""
Integration Module for Deep Learning Ransomware Detection

This module integrates deep learning models with the existing
enhanced family detection and auto variant detection systems.
"""

import os
import json
import logging
import numpy as np
from typing import Dict, List, Optional, Any, Tuple, Union, Set
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('dl_integration')

class DeepLearningIntegration:
    """
    Integration of deep learning models with existing ransomware detection systems
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the integration module
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.enhanced_detector = None
        self.variant_detector = None
        self.feature_extractor = None
        self.embedding_model = None
        self.classifier_model = None
        self.variant_model = None
        self.initialized = False
        
        # Default paths
        self.default_paths = {
            "models_dir": os.path.join(os.path.dirname(os.path.abspath(__file__)), "models"),
            "features_dir": os.path.join(os.path.dirname(os.path.abspath(__file__)), "features"),
            "data_dir": os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"),
            "reference_embeddings": os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "reference_embeddings.json")
        }
        
        # Initialize if auto_initialize is enabled
        if self.config.get('auto_initialize', True):
            self.initialize()
    
    def initialize(self) -> bool:
        """
        Initialize the integration module
        
        Returns:
            Success status
        """
        if self.initialized:
            return True
        
        try:
            # Try to import required modules
            import_successful = self._import_required_modules()
            if not import_successful:
                logger.warning("Required modules not available, using fallback modes")
            
            # Initialize deep learning components
            dl_init_successful = self._initialize_deep_learning_components()
            if not dl_init_successful:
                logger.warning("Deep learning components not initialized, using fallback modes")
            
            # Try to link to existing detectors
            self._link_to_detectors()
            
            self.initialized = True
            logger.info("Deep learning integration initialized")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing deep learning integration: {e}")
            return False
    
    def _import_required_modules(self) -> bool:
        """
        Import required modules dynamically
        
        Returns:
            Success status
        """
        try:
            # Try to import deep learning feature extractor
            try:
                global DeepFeatureExtractor
                from ai_detection.features.deep_feature_extractor import DeepFeatureExtractor
                logger.info("Imported DeepFeatureExtractor")
            except ImportError:
                logger.warning("DeepFeatureExtractor not available")
                DeepFeatureExtractor = None
            
            # Try to import deep learning models
            try:
                global RansomwareEmbeddingModel, RansomwareFamilyClassifier, RansomwareVariantDetector
                from ai_detection.models.deep_learning_model import (
                    RansomwareEmbeddingModel, 
                    RansomwareFamilyClassifier, 
                    RansomwareVariantDetector
                )
                logger.info("Imported deep learning models")
            except ImportError:
                logger.warning("Deep learning models not available")
                RansomwareEmbeddingModel = None
                RansomwareFamilyClassifier = None
                RansomwareVariantDetector = None
            
            # Try to import enhanced family detector
            try:
                global EnhancedFamilyDetector
                from threat_intel.family_detection.enhanced_family_detector import EnhancedFamilyDetector
                logger.info("Imported EnhancedFamilyDetector")
            except ImportError:
                logger.warning("EnhancedFamilyDetector not available")
                EnhancedFamilyDetector = None
            
            # Try to import auto variant detector
            try:
                global AutoVariantDetector
                from threat_intel.family_detection.auto_variant_detector import AutoVariantDetector
                logger.info("Imported AutoVariantDetector")
            except ImportError:
                logger.warning("AutoVariantDetector not available")
                AutoVariantDetector = None
            
            return True
            
        except Exception as e:
            logger.error(f"Error importing required modules: {e}")
            return False
    
    def _initialize_deep_learning_components(self) -> bool:
        """
        Initialize deep learning components
        
        Returns:
            Success status
        """
        try:
            # Initialize feature extractor if available
            if DeepFeatureExtractor is not None:
                feature_config = self.config.get('feature_extractor', {})
                self.feature_extractor = DeepFeatureExtractor(feature_config)
                logger.info("Initialized deep feature extractor")
            
            # Initialize embedding model if available
            if RansomwareEmbeddingModel is not None:
                embedding_config = self.config.get('embedding_model', {})
                
                # Set default model path if not provided
                if 'model_path' not in embedding_config:
                    model_path = os.path.join(self.default_paths['models_dir'], "embedding_model.pt")
                    if os.path.exists(model_path):
                        embedding_config['model_path'] = model_path
                
                self.embedding_model = RansomwareEmbeddingModel(embedding_config)
                logger.info("Initialized ransomware embedding model")
            
            # Initialize classifier model if available
            if RansomwareFamilyClassifier is not None:
                classifier_config = self.config.get('classifier_model', {})
                
                # Set default model path if not provided
                if 'model_path' not in classifier_config:
                    model_path = os.path.join(self.default_paths['models_dir'], "classifier_model.pt")
                    if os.path.exists(model_path):
                        classifier_config['model_path'] = model_path
                
                self.classifier_model = RansomwareFamilyClassifier(classifier_config)
                logger.info("Initialized ransomware family classifier")
            
            # Initialize variant detector if available
            if RansomwareVariantDetector is not None:
                variant_config = self.config.get('variant_detector', {})
                
                # Set default reference embeddings path if not provided
                if 'reference_embeddings_path' not in variant_config:
                    ref_path = self.default_paths['reference_embeddings']
                    if os.path.exists(ref_path):
                        variant_config['reference_embeddings_path'] = ref_path
                
                self.variant_model = RansomwareVariantDetector(variant_config)
                logger.info("Initialized ransomware variant detector")
            
            return True
            
        except Exception as e:
            logger.error(f"Error initializing deep learning components: {e}")
            return False
    
    def _link_to_detectors(self) -> None:
        """Link to existing detector instances if provided in config"""
        # Link to enhanced family detector
        detector_config = self.config.get('detectors', {})
        
        if 'enhanced_detector' in detector_config:
            self.enhanced_detector = detector_config['enhanced_detector']
            logger.info("Linked to existing enhanced family detector")
        
        if 'variant_detector' in detector_config:
            self.variant_detector = detector_config['variant_detector']
            logger.info("Linked to existing auto variant detector")
    
    def extract_deep_features(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract deep learning features from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            Deep learning features
        """
        if not self.initialized:
            if not self.initialize():
                return {"error": "Failed to initialize deep learning integration"}
        
        try:
            # Use feature extractor if available
            if self.feature_extractor:
                features = self.feature_extractor.extract_features(sample_data)
                return features
            
            # Fallback to basic features
            return self._extract_basic_features(sample_data)
            
        except Exception as e:
            logger.error(f"Error extracting deep features: {e}")
            return {"error": str(e)}
    
    def _extract_basic_features(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract basic features when deep learning is unavailable
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            Basic extracted features
        """
        # Create dummy embedding with basic statistics
        feature_dim = self.config.get('feature_dim', 256)
        basic_embedding = np.zeros(feature_dim, dtype=np.float32)
        
        # Fill first few dimensions with basic statistics
        strings = sample_data.get("analysis", {}).get("strings", [])
        behaviors = sample_data.get("analysis", {}).get("behaviors", {})
        
        # Basic string statistics
        if strings:
            string_count = len(strings)
            avg_length = np.mean([len(s) for s in strings])
            
            # Set first two dimensions
            if len(basic_embedding) > 0:
                basic_embedding[0] = min(string_count / 1000, 1.0)  # Normalize
            if len(basic_embedding) > 1:
                basic_embedding[1] = min(avg_length / 100, 1.0)  # Normalize
        
        # Basic behavior statistics
        file_ops = behaviors.get("file_operations", [])
        if file_ops and len(basic_embedding) > 2:
            basic_embedding[2] = min(len(file_ops) / 500, 1.0)  # Normalize
        
        # Basic result with dummy embedding
        result = {
            "deep_embedding": basic_embedding.tolist(),
            "feature_confidence": 0.3,  # Low confidence for basic features
            "classification_scores": {},
            "similarity_features": {
                "mean": float(np.mean(basic_embedding)),
                "variance": float(np.var(basic_embedding)),
                "non_zero_ratio": float(np.count_nonzero(basic_embedding) / len(basic_embedding)),
                "spectral_norm": float(np.linalg.norm(basic_embedding, ord=2))
            }
        }
        
        return result
    
    def detect_family_with_dl(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect ransomware family using deep learning
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            Family detection results
        """
        if not self.initialized:
            if not self.initialize():
                return {"error": "Failed to initialize deep learning integration"}
        
        try:
            # Extract deep features
            deep_features = self.extract_deep_features(sample_data)
            
            # Store features in sample data for later use
            if "deep_features" not in sample_data:
                sample_data["deep_features"] = deep_features
            
            # Get classification scores from deep features if available
            classification_scores = deep_features.get("classification_scores", {})
            
            # If no classification scores and classifier model is available, generate them
            if not classification_scores and self.classifier_model:
                # Get deep embedding
                embedding = deep_features.get("deep_embedding", [])
                
                # Generate classification scores
                classification_scores = self.classifier_model.predict(embedding)
            
            # Process classification scores
            dl_results = []
            
            for family, score in sorted(classification_scores.items(), key=lambda x: x[1], reverse=True):
                # Only include scores above threshold
                if score >= 0.1:  # Minimum threshold to include in results
                    family_data = {
                        "family_id": family.lower().replace(" ", "_"),
                        "family_name": family,
                        "confidence": score,
                        "detection_method": "deep_learning"
                    }
                    
                    dl_results.append(family_data)
            
            # Get traditional results if enhanced detector is available
            traditional_results = []
            
            if self.enhanced_detector:
                traditional_results = self.enhanced_detector.identify_family(
                    sample_data,
                    min_score=0.4
                )
            
            # Combine results with enhanced detection if available
            combined_results = self._combine_detection_results(dl_results, traditional_results)
            
            return {
                "deep_learning_results": dl_results,
                "traditional_results": traditional_results,
                "combined_results": combined_results
            }
            
        except Exception as e:
            logger.error(f"Error detecting family with deep learning: {e}")
            return {"error": str(e)}
    
    def _combine_detection_results(self, dl_results: List[Dict[str, Any]], 
                                 traditional_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Combine deep learning and traditional detection results
        
        Args:
            dl_results: Deep learning detection results
            traditional_results: Traditional detection results
            
        Returns:
            Combined detection results
        """
        # Track families seen
        family_scores = {}
        
        # Process deep learning results
        for result in dl_results:
            family_id = result["family_id"]
            confidence = result["confidence"]
            
            if family_id not in family_scores:
                family_scores[family_id] = {
                    "family_id": family_id,
                    "family_name": result["family_name"],
                    "dl_confidence": confidence,
                    "traditional_confidence": 0.0,
                    "combined_confidence": confidence * 0.7,  # Weight DL results at 70%
                    "detection_methods": ["deep_learning"]
                }
            else:
                # Update DL confidence if higher
                if confidence > family_scores[family_id]["dl_confidence"]:
                    family_scores[family_id]["dl_confidence"] = confidence
                    family_scores[family_id]["combined_confidence"] = (
                        family_scores[family_id]["dl_confidence"] * 0.7 +
                        family_scores[family_id]["traditional_confidence"] * 0.3
                    )
        
        # Process traditional results
        for result in traditional_results:
            family_id = result["family_id"]
            confidence = result["confidence"]
            
            if family_id not in family_scores:
                family_scores[family_id] = {
                    "family_id": family_id,
                    "family_name": result["family_name"],
                    "dl_confidence": 0.0,
                    "traditional_confidence": confidence,
                    "combined_confidence": confidence * 0.3,  # Weight traditional results at 30%
                    "detection_methods": ["traditional"]
                }
            else:
                # Update traditional confidence if higher
                if confidence > family_scores[family_id]["traditional_confidence"]:
                    family_scores[family_id]["traditional_confidence"] = confidence
                    family_scores[family_id]["combined_confidence"] = (
                        family_scores[family_id]["dl_confidence"] * 0.7 +
                        family_scores[family_id]["traditional_confidence"] * 0.3
                    )
                
                # Add detection method if not already present
                if "traditional" not in family_scores[family_id]["detection_methods"]:
                    family_scores[family_id]["detection_methods"].append("traditional")
        
        # Convert to list and sort by combined confidence
        combined_results = list(family_scores.values())
        combined_results.sort(key=lambda x: x["combined_confidence"], reverse=True)
        
        return combined_results
    
    def detect_variant_with_dl(self, sample_data: Dict[str, Any], 
                             reference_family: Optional[str] = None) -> Dict[str, Any]:
        """
        Detect if sample is a variant using deep learning
        
        Args:
            sample_data: Sample analysis data
            reference_family: Optional family to check against (if None, check all families)
            
        Returns:
            Variant detection results
        """
        if not self.initialized:
            if not self.initialize():
                return {"error": "Failed to initialize deep learning integration"}
        
        try:
            # Extract deep features if not already present
            if "deep_features" not in sample_data:
                deep_features = self.extract_deep_features(sample_data)
                sample_data["deep_features"] = deep_features
            else:
                deep_features = sample_data["deep_features"]
            
            # Get deep embedding
            embedding = deep_features.get("deep_embedding", [])
            
            # Use variant model if available
            if self.variant_model:
                # Detect variant
                variant_result = self.variant_model.detect_variant(embedding, reference_family)
                
                # Add detection method
                variant_result["detection_method"] = "deep_learning"
                
                # Add feature confidence
                variant_result["feature_confidence"] = deep_features.get("feature_confidence", 0.0)
                
                return variant_result
            
            # Fallback if variant model not available but traditional detector is
            if self.variant_detector:
                # Run traditional variant detection
                traditional_result = self.variant_detector.process_sample(sample_data)
                
                # Add detection method
                traditional_result["detection_method"] = "traditional"
                
                return traditional_result
            
            # No detection method available
            return {
                "is_variant": False,
                "similarity": 0.0,
                "closest_variant": None,
                "family": reference_family,
                "confidence": 0.0,
                "message": "No variant detection method available"
            }
            
        except Exception as e:
            logger.error(f"Error detecting variant with deep learning: {e}")
            return {"error": str(e)}
    
    def train_embedding_model(self, samples: List[Dict[str, Any]], 
                            output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Train embedding model on samples
        
        Args:
            samples: List of sample data
            output_path: Optional path to save model
            
        Returns:
            Training results
        """
        # This is a placeholder for the actual training logic
        # In a real implementation, this would set up and run model training
        
        return {
            "status": "not_implemented",
            "message": "Training embedding model is not yet implemented",
            "samples_provided": len(samples)
        }
    
    def train_classifier_model(self, samples: List[Dict[str, Any]], 
                             output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Train classifier model on samples
        
        Args:
            samples: List of sample data
            output_path: Optional path to save model
            
        Returns:
            Training results
        """
        # This is a placeholder for the actual training logic
        # In a real implementation, this would set up and run model training
        
        return {
            "status": "not_implemented",
            "message": "Training classifier model is not yet implemented",
            "samples_provided": len(samples)
        }
    
    def update_reference_embeddings(self, family_id: str, variant_name: str, 
                                  embedding: Union[List[float], np.ndarray],
                                  confidence: float = 1.0) -> bool:
        """
        Update reference embeddings with a new variant
        
        Args:
            family_id: Family ID
            variant_name: Variant name
            embedding: Variant embedding
            confidence: Confidence in the embedding
            
        Returns:
            Success status
        """
        if not self.initialized:
            if not self.initialize():
                return False
        
        try:
            # Use variant model if available
            if self.variant_model:
                # Add reference embedding
                success = self.variant_model.add_reference_embedding(
                    variant=variant_name,
                    embedding=embedding,
                    family=family_id,
                    confidence=confidence
                )
                
                # Save reference embeddings
                if success:
                    ref_path = self.config.get('variant_detector', {}).get(
                        'reference_embeddings_path',
                        self.default_paths['reference_embeddings']
                    )
                    
                    save_success = self.variant_model.save_reference_embeddings(ref_path)
                    
                    if save_success:
                        logger.info(f"Updated reference embeddings for {variant_name}")
                        return True
                    else:
                        logger.error(f"Failed to save reference embeddings")
                        return False
                
                logger.error(f"Failed to add reference embedding for {variant_name}")
                return False
            
            logger.error("Variant model not available")
            return False
            
        except Exception as e:
            logger.error(f"Error updating reference embeddings: {e}")
            return False

# Example usage when run as a script
if __name__ == "__main__":
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description="Deep Learning Integration for Ransomware Detection")
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Extract features command
    extract_parser = subparsers.add_parser('extract', help='Extract deep learning features')
    extract_parser.add_argument('--sample', required=True, help='Path to sample analysis JSON file')
    extract_parser.add_argument('--config', help='Path to configuration JSON file')
    extract_parser.add_argument('--output', help='Output file for features')
    
    # Detect family command
    detect_parser = subparsers.add_parser('detect', help='Detect ransomware family')
    detect_parser.add_argument('--sample', required=True, help='Path to sample analysis JSON file')
    detect_parser.add_argument('--config', help='Path to configuration JSON file')
    detect_parser.add_argument('--output', help='Output file for detection results')
    
    # Detect variant command
    variant_parser = subparsers.add_parser('variant', help='Detect ransomware variant')
    variant_parser.add_argument('--sample', required=True, help='Path to sample analysis JSON file')
    variant_parser.add_argument('--family', help='Reference family to check against')
    variant_parser.add_argument('--config', help='Path to configuration JSON file')
    variant_parser.add_argument('--output', help='Output file for variant detection results')
    
    # Update reference embeddings command
    update_parser = subparsers.add_parser('update-ref', help='Update reference embeddings')
    update_parser.add_argument('--family', required=True, help='Family ID')
    update_parser.add_argument('--variant', required=True, help='Variant name')
    update_parser.add_argument('--embedding', required=True, help='Path to embedding JSON file')
    update_parser.add_argument('--confidence', type=float, default=1.0, help='Confidence in embedding')
    update_parser.add_argument('--config', help='Path to configuration JSON file')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Load configuration if provided
    config = None
    if hasattr(args, 'config') and args.config:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
        except Exception as e:
            print(f"Error loading configuration: {e}")
            sys.exit(1)
    
    # Create integration
    integration = DeepLearningIntegration(config)
    
    if args.command == 'extract':
        # Load sample
        try:
            with open(args.sample, 'r') as f:
                sample_data = json.load(f)
            
            # Extract features
            features = integration.extract_deep_features(sample_data)
            
            # Output features
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(features, f, indent=2)
                print(f"Features saved to {args.output}")
            else:
                print(json.dumps(features, indent=2))
                
        except Exception as e:
            print(f"Error extracting features: {e}")
            sys.exit(1)
    
    elif args.command == 'detect':
        # Load sample
        try:
            with open(args.sample, 'r') as f:
                sample_data = json.load(f)
            
            # Detect family
            results = integration.detect_family_with_dl(sample_data)
            
            # Output results
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"Detection results saved to {args.output}")
            else:
                print(json.dumps(results, indent=2))
                
        except Exception as e:
            print(f"Error detecting family: {e}")
            sys.exit(1)
    
    elif args.command == 'variant':
        # Load sample
        try:
            with open(args.sample, 'r') as f:
                sample_data = json.load(f)
            
            # Detect variant
            results = integration.detect_variant_with_dl(sample_data, args.family)
            
            # Output results
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"Variant detection results saved to {args.output}")
            else:
                print(json.dumps(results, indent=2))
                
        except Exception as e:
            print(f"Error detecting variant: {e}")
            sys.exit(1)
    
    elif args.command == 'update-ref':
        # Load embedding
        try:
            with open(args.embedding, 'r') as f:
                embedding_data = json.load(f)
            
            # Extract embedding
            embedding = None
            
            if "embedding" in embedding_data:
                embedding = embedding_data["embedding"]
            elif "deep_embedding" in embedding_data:
                embedding = embedding_data["deep_embedding"]
            else:
                print("No valid embedding found in input file")
                sys.exit(1)
            
            # Update reference embeddings
            success = integration.update_reference_embeddings(
                family_id=args.family,
                variant_name=args.variant,
                embedding=embedding,
                confidence=args.confidence
            )
            
            if success:
                print(f"Successfully updated reference embeddings for {args.variant}")
            else:
                print(f"Failed to update reference embeddings")
                sys.exit(1)
                
        except Exception as e:
            print(f"Error updating reference embeddings: {e}")
            sys.exit(1)
    
    else:
        parser.print_help()