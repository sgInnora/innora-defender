#!/usr/bin/env python3
"""
Deep Learning Enhanced Ransomware Detector

Extends the existing EnhancedFamilyDetector and AutoVariantDetector classes
with deep learning capabilities for improved detection accuracy.
"""

import os
import json
import logging
import numpy as np
from typing import Dict, List, Set, Optional, Any, Tuple, Union
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('dl_enhanced_detector')

class DLEnhancedFamilyDetector:
    """
    Enhanced ransomware family detector with deep learning capabilities
    """
    
    def __init__(self, 
                families_dir: Optional[str] = None, 
                yara_rules_dir: Optional[str] = None,
                dl_config: Optional[Dict[str, Any]] = None):
        """
        Initialize the DL-enhanced family detector
        
        Args:
            families_dir: Directory containing family definition files
            yara_rules_dir: Directory containing YARA rules
            dl_config: Configuration for deep learning components
        """
        # Set up paths
        self.families_dir = families_dir
        self.yara_rules_dir = yara_rules_dir
        self.dl_config = dl_config or {}
        
        # Import required components
        self._import_components()
        
        # Initialize components
        self.enhanced_detector = None
        self.variant_detector = None
        self.dl_integration = None
        self.initialized = False
        
        # Initialize components
        self._initialize_components()
    
    def _import_components(self) -> bool:
        """
        Import required components
        
        Returns:
            Success status
        """
        try:
            # Import enhanced family detector
            try:
                global EnhancedFamilyDetector
                from threat_intel.family_detection.enhanced_family_detector import EnhancedFamilyDetector
                logger.info("Imported EnhancedFamilyDetector")
            except ImportError:
                logger.warning("EnhancedFamilyDetector not available")
                EnhancedFamilyDetector = None
            
            # Import auto variant detector
            try:
                global AutoVariantDetector
                from threat_intel.family_detection.auto_variant_detector import AutoVariantDetector
                logger.info("Imported AutoVariantDetector")
            except ImportError:
                logger.warning("AutoVariantDetector not available")
                AutoVariantDetector = None
            
            # Import deep learning integration
            try:
                global DeepLearningIntegration
                from ai_detection.integration import DeepLearningIntegration
                logger.info("Imported DeepLearningIntegration")
            except ImportError:
                logger.warning("DeepLearningIntegration not available")
                DeepLearningIntegration = None
            
            return True
            
        except Exception as e:
            logger.error(f"Error importing components: {e}")
            return False
    
    def _initialize_components(self) -> None:
        """Initialize detector components"""
        try:
            # Initialize enhanced family detector if available
            if EnhancedFamilyDetector is not None:
                self.enhanced_detector = EnhancedFamilyDetector(
                    families_dir=self.families_dir,
                    yara_rules_dir=self.yara_rules_dir
                )
                logger.info("Initialized enhanced family detector")
            else:
                logger.warning("Enhanced family detector not available")
            
            # Initialize auto variant detector if available
            if AutoVariantDetector is not None and self.enhanced_detector is not None:
                self.variant_detector = AutoVariantDetector(
                    enhanced_detector=self.enhanced_detector
                )
                logger.info("Initialized auto variant detector")
            else:
                logger.warning("Auto variant detector not available")
            
            # Initialize deep learning integration if available
            if DeepLearningIntegration is not None:
                # Set up configuration with detector references
                dl_config = self.dl_config.copy()
                if 'detectors' not in dl_config:
                    dl_config['detectors'] = {}
                
                # Add detector references
                if self.enhanced_detector is not None:
                    dl_config['detectors']['enhanced_detector'] = self.enhanced_detector
                
                if self.variant_detector is not None:
                    dl_config['detectors']['variant_detector'] = self.variant_detector
                
                # Create integration
                self.dl_integration = DeepLearningIntegration(dl_config)
                logger.info("Initialized deep learning integration")
            else:
                logger.warning("Deep learning integration not available")
            
            self.initialized = (
                self.enhanced_detector is not None and 
                (self.variant_detector is not None or self.dl_integration is not None)
            )
            
            if self.initialized:
                logger.info("DL-enhanced family detector initialized successfully")
            else:
                logger.warning("DL-enhanced family detector initialization incomplete")
            
        except Exception as e:
            logger.error(f"Error initializing components: {e}")
    
    def identify_family(self, sample_data: Dict[str, Any], min_score: float = 0.5, 
                      use_dl: bool = True) -> List[Dict[str, Any]]:
        """
        Identify the most likely ransomware family for a sample
        
        Args:
            sample_data: Sample analysis data
            min_score: Minimum score threshold for family identification
            use_dl: Whether to use deep learning enhancement
            
        Returns:
            List of identified families with scores, sorted by confidence
        """
        if not self.initialized:
            logger.warning("DL-enhanced family detector not fully initialized")
            
            # Fallback to enhanced detector if available
            if self.enhanced_detector is not None:
                return self.enhanced_detector.identify_family(sample_data, min_score)
            
            return []
        
        try:
            # Use deep learning if available and requested
            if use_dl and self.dl_integration is not None:
                # Get deep learning results
                dl_results = self.dl_integration.detect_family_with_dl(sample_data)
                
                # Use combined results if available
                if "combined_results" in dl_results and dl_results["combined_results"]:
                    # Convert to compatible format
                    results = []
                    
                    for family in dl_results["combined_results"]:
                        if family["combined_confidence"] >= min_score:
                            # Map to output format expected by other components
                            result = {
                                "family_id": family["family_id"],
                                "family_name": family["family_name"],
                                "confidence": family["combined_confidence"],
                                "detection_methods": family["detection_methods"]
                            }
                            
                            # Add DL-specific confidence scores
                            if "dl_confidence" in family:
                                result["dl_confidence"] = family["dl_confidence"]
                            
                            if "traditional_confidence" in family:
                                result["traditional_confidence"] = family["traditional_confidence"]
                            
                            # Check for variant detected by enhanced detector
                            if (self.enhanced_detector is not None and 
                                "traditional_results" in dl_results and 
                                dl_results["traditional_results"]):
                                
                                # Look for this family in traditional results
                                for trad_result in dl_results["traditional_results"]:
                                    if trad_result["family_id"] == family["family_id"] and "variant" in trad_result:
                                        result["variant"] = trad_result["variant"]
                                        break
                            
                            results.append(result)
                    
                    return results
                
                # Fallback to traditional results if combined results not available
                if "traditional_results" in dl_results and dl_results["traditional_results"]:
                    return dl_results["traditional_results"]
            
            # Use enhanced detector if deep learning not available or not used
            if self.enhanced_detector is not None:
                return self.enhanced_detector.identify_family(sample_data, min_score)
            
            return []
            
        except Exception as e:
            logger.error(f"Error identifying family: {e}")
            
            # Fallback to enhanced detector if available
            if self.enhanced_detector is not None:
                return self.enhanced_detector.identify_family(sample_data, min_score)
            
            return []
    
    def detect_variants(self, sample_data: Dict[str, Any], base_family: Optional[str] = None,
                      use_dl: bool = True) -> Dict[str, Any]:
        """
        Detect if sample is a variant of a known ransomware family
        
        Args:
            sample_data: Sample analysis data
            base_family: Optional family to check against (if None, check all families)
            use_dl: Whether to use deep learning enhancement
            
        Returns:
            Variant detection results
        """
        if not self.initialized:
            logger.warning("DL-enhanced family detector not fully initialized")
            
            # Fallback to auto variant detector if available
            if self.variant_detector is not None:
                return self.variant_detector.process_sample(sample_data)
            
            return {
                "variant_detection": {
                    "is_variant": False,
                    "confidence": 0.0,
                    "message": "Detector not initialized"
                }
            }
        
        try:
            # Use deep learning if available and requested
            if use_dl and self.dl_integration is not None:
                # Get deep learning variant detection results
                dl_result = self.dl_integration.detect_variant_with_dl(sample_data, base_family)
                
                # Check for success
                if "error" not in dl_result:
                    return {
                        "sample_id": sample_data.get("sha256", "unknown"),
                        "timestamp": sample_data.get("analysis_date", ""),
                        "variant_detection": dl_result
                    }
            
            # Use auto variant detector if deep learning not available or not used
            if self.variant_detector is not None:
                return self.variant_detector.process_sample(sample_data)
            
            return {
                "variant_detection": {
                    "is_variant": False,
                    "confidence": 0.0,
                    "message": "No variant detector available"
                }
            }
            
        except Exception as e:
            logger.error(f"Error detecting variants: {e}")
            
            # Fallback to auto variant detector if available
            if self.variant_detector is not None:
                return self.variant_detector.process_sample(sample_data)
            
            return {
                "variant_detection": {
                    "is_variant": False,
                    "confidence": 0.0,
                    "message": f"Error detecting variants: {e}"
                }
            }
    
    def extract_deep_features(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract deep learning features from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            Deep learning features
        """
        if not self.initialized or self.dl_integration is None:
            logger.warning("Deep learning integration not available")
            return {"error": "Deep learning integration not available"}
        
        try:
            # Extract deep features
            features = self.dl_integration.extract_deep_features(sample_data)
            return features
            
        except Exception as e:
            logger.error(f"Error extracting deep features: {e}")
            return {"error": str(e)}
    
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
        if not self.initialized or self.dl_integration is None:
            logger.warning("Deep learning integration not available")
            return False
        
        try:
            # Update reference embeddings
            success = self.dl_integration.update_reference_embeddings(
                family_id=family_id,
                variant_name=variant_name,
                embedding=embedding,
                confidence=confidence
            )
            
            return success
            
        except Exception as e:
            logger.error(f"Error updating reference embeddings: {e}")
            return False
    
    def add_family_definition(self, family_data: Dict[str, Any]) -> bool:
        """
        Add a new family definition
        
        Args:
            family_data: Family definition data
            
        Returns:
            True if family was added, False otherwise
        """
        if not self.initialized or self.enhanced_detector is None:
            logger.warning("Enhanced family detector not available")
            return False
        
        try:
            # Add family definition using enhanced detector
            return self.enhanced_detector.add_family_definition(family_data)
            
        except Exception as e:
            logger.error(f"Error adding family definition: {e}")
            return False
    
    def evaluate_variant_clusters(self) -> List[Dict[str, Any]]:
        """
        Evaluate all clusters to identify valid new variants
        
        Returns:
            List of valid variant clusters
        """
        if not self.initialized or self.variant_detector is None:
            logger.warning("Auto variant detector not available")
            return []
        
        try:
            # Evaluate clusters using variant detector
            return self.variant_detector.evaluate_clusters()
            
        except Exception as e:
            logger.error(f"Error evaluating variant clusters: {e}")
            return []
    
    def generate_variant_definition(self, cluster_id: str) -> Optional[Dict[str, Any]]:
        """
        Generate a family definition for a variant
        
        Args:
            cluster_id: Cluster identifier
            
        Returns:
            Family definition dictionary or None if cluster not found
        """
        if not self.initialized or self.variant_detector is None:
            logger.warning("Auto variant detector not available")
            return None
        
        try:
            # Generate variant definition using variant detector
            return self.variant_detector.generate_variant_definition(cluster_id)
            
        except Exception as e:
            logger.error(f"Error generating variant definition: {e}")
            return None

# Example usage when run as a script
if __name__ == "__main__":
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description="Deep Learning Enhanced Ransomware Detector")
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Identify command
    identify_parser = subparsers.add_parser('identify', help='Identify ransomware family')
    identify_parser.add_argument('--sample', required=True, help='Path to sample analysis JSON file')
    identify_parser.add_argument('--min-score', type=float, default=0.5, help='Minimum score threshold')
    identify_parser.add_argument('--no-dl', action='store_true', help='Disable deep learning')
    identify_parser.add_argument('--output', help='Output file for results')
    
    # Detect variants command
    variant_parser = subparsers.add_parser('detect-variants', help='Detect ransomware variants')
    variant_parser.add_argument('--sample', required=True, help='Path to sample analysis JSON file')
    variant_parser.add_argument('--family', help='Base family to check against')
    variant_parser.add_argument('--no-dl', action='store_true', help='Disable deep learning')
    variant_parser.add_argument('--output', help='Output file for results')
    
    # Extract features command
    features_parser = subparsers.add_parser('extract-features', help='Extract deep learning features')
    features_parser.add_argument('--sample', required=True, help='Path to sample analysis JSON file')
    features_parser.add_argument('--output', help='Output file for features')
    
    # Update reference embeddings command
    update_parser = subparsers.add_parser('update-embeddings', help='Update reference embeddings')
    update_parser.add_argument('--family', required=True, help='Family ID')
    update_parser.add_argument('--variant', required=True, help='Variant name')
    update_parser.add_argument('--embedding', required=True, help='Path to embedding JSON file')
    update_parser.add_argument('--confidence', type=float, default=1.0, help='Confidence in embedding')
    
    # Evaluate clusters command
    evaluate_parser = subparsers.add_parser('evaluate-clusters', help='Evaluate variant clusters')
    evaluate_parser.add_argument('--output', help='Output file for results')
    
    # Generate variant definition command
    generate_parser = subparsers.add_parser('generate-definition', help='Generate variant definition')
    generate_parser.add_argument('--cluster', required=True, help='Cluster ID')
    generate_parser.add_argument('--output', help='Output file for definition')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Get directories
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(os.path.dirname(script_dir))
    
    families_dir = os.path.join(parent_dir, 'data', 'families')
    yara_rules_dir = os.path.join(parent_dir, 'rules')
    
    # Create detector
    detector = DLEnhancedFamilyDetector(
        families_dir=families_dir,
        yara_rules_dir=yara_rules_dir
    )
    
    if args.command == 'identify':
        # Load sample
        try:
            with open(args.sample, 'r') as f:
                sample_data = json.load(f)
            
            # Identify family
            results = detector.identify_family(
                sample_data=sample_data,
                min_score=args.min_score,
                use_dl=not args.no_dl
            )
            
            # Output results
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
            else:
                print(json.dumps(results, indent=2))
            
            # Print summary
            print(f"\nIdentified {len(results)} potential families")
            for i, result in enumerate(results):
                detection_methods = result.get("detection_methods", ["traditional"])
                methods_str = ", ".join(detection_methods)
                
                print(f"{i+1}. {result['family_name']} - Confidence: {result['confidence']:.2f} ({methods_str})")
                if "variant" in result:
                    print(f"   Variant: {result['variant']['name']} (Confidence: {result['variant']['confidence']:.2f})")
                
        except Exception as e:
            print(f"Error identifying family: {e}")
            sys.exit(1)
    
    elif args.command == 'detect-variants':
        # Load sample
        try:
            with open(args.sample, 'r') as f:
                sample_data = json.load(f)
            
            # Detect variants
            results = detector.detect_variants(
                sample_data=sample_data,
                base_family=args.family,
                use_dl=not args.no_dl
            )
            
            # Output results
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
            else:
                print(json.dumps(results, indent=2))
            
            # Print summary
            variant_detection = results.get("variant_detection", {})
            if variant_detection.get("is_variant", False):
                print(f"\nSample is a variant:")
                print(f"Base Family: {variant_detection.get('family', 'unknown')}")
                print(f"Closest Variant: {variant_detection.get('closest_variant', 'unknown')}")
                print(f"Similarity: {variant_detection.get('similarity', 0.0):.2f}")
                print(f"Confidence: {variant_detection.get('confidence', 0.0):.2f}")
                print(f"Detection Method: {variant_detection.get('detection_method', 'unknown')}")
            else:
                print(f"\nSample is not identified as a variant")
                
        except Exception as e:
            print(f"Error detecting variants: {e}")
            sys.exit(1)
    
    elif args.command == 'extract-features':
        # Load sample
        try:
            with open(args.sample, 'r') as f:
                sample_data = json.load(f)
            
            # Extract features
            features = detector.extract_deep_features(sample_data)
            
            # Output features
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(features, f, indent=2)
            else:
                print(json.dumps(features, indent=2))
                
        except Exception as e:
            print(f"Error extracting features: {e}")
            sys.exit(1)
    
    elif args.command == 'update-embeddings':
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
            success = detector.update_reference_embeddings(
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
    
    elif args.command == 'evaluate-clusters':
        # Evaluate clusters
        try:
            clusters = detector.evaluate_variant_clusters()
            
            # Output results
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(clusters, f, indent=2)
            else:
                print(json.dumps(clusters, indent=2))
            
            # Print summary
            print(f"\nFound {len(clusters)} valid variant clusters")
            for i, cluster in enumerate(clusters):
                print(f"{i+1}. {cluster['variant_name']} - Base Family: {cluster['base_family']}")
                print(f"   Samples: {cluster['samples']}, Confidence: {cluster['confidence']:.2f}")
                print(f"   Cohesion: {cluster['cohesion']:.2f}, Distinctive Features: {cluster['distinctive_features_count']}")
                
        except Exception as e:
            print(f"Error evaluating clusters: {e}")
            sys.exit(1)
    
    elif args.command == 'generate-definition':
        # Generate variant definition
        try:
            definition = detector.generate_variant_definition(args.cluster)
            
            if not definition:
                print(f"No definition generated for cluster {args.cluster}")
                sys.exit(1)
            
            # Output definition
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(definition, f, indent=2)
                print(f"Definition saved to {args.output}")
            else:
                print(json.dumps(definition, indent=2))
                
        except Exception as e:
            print(f"Error generating definition: {e}")
            sys.exit(1)
    
    else:
        parser.print_help()