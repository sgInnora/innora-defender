#!/usr/bin/env python3
"""
Deep Learning Feature Extractor for Ransomware Analysis

This module provides functionality to extract deep learning-based features 
from ransomware samples for improved detection and classification.
"""

import os
import json
import logging
import numpy as np
from typing import Dict, List, Optional, Any, Tuple, Union
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('deep_feature_extractor')

class DeepFeatureExtractor:
    """
    Extract deep learning-based features from ransomware samples
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the deep feature extractor
        
        Args:
            config: Configuration dictionary for the extractor
        """
        self.config = config or {}
        self.feature_dim = self.config.get('feature_dim', 256)
        self.initialized = False
        self.models = {}
        
        # Attempt to load pre-trained models during initialization
        if self.config.get('auto_initialize', True):
            self.initialize()
    
    def initialize(self) -> bool:
        """
        Initialize the deep learning models
        
        Returns:
            Success status
        """
        if self.initialized:
            return True
            
        try:
            # Import deep learning libraries dynamically to avoid hard dependencies
            import_successful = self._import_deep_learning_libs()
            if not import_successful:
                logger.warning("Deep learning libraries not available, feature extraction will be limited")
                return False
            
            # Load pre-trained models
            models_loaded = self._load_pretrained_models()
            if not models_loaded:
                logger.warning("Pre-trained models not found or failed to load")
                return False
            
            self.initialized = True
            logger.info("Deep feature extractor initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing deep feature extractor: {e}")
            return False
    
    def _import_deep_learning_libs(self) -> bool:
        """
        Import deep learning libraries dynamically
        
        Returns:
            Success status
        """
        try:
            # Try to import relevant libraries based on configuration
            backend = self.config.get('backend', 'keras').lower()
            
            if backend == 'keras':
                # Try import TensorFlow/Keras
                try:
                    global tf, keras
                    import tensorflow as tf
                    from tensorflow import keras
                    logger.info("Using TensorFlow/Keras backend")
                    self.backend = 'keras'
                    return True
                except ImportError:
                    pass
            
            if backend == 'pytorch' or self.backend is None:
                # Try import PyTorch
                try:
                    global torch, nn
                    import torch
                    from torch import nn
                    logger.info("Using PyTorch backend")
                    self.backend = 'pytorch'
                    return True
                except ImportError:
                    pass
            
            if backend == 'onnx' or self.backend is None:
                # Try import ONNX Runtime
                try:
                    global ort
                    import onnxruntime as ort
                    logger.info("Using ONNX Runtime backend")
                    self.backend = 'onnx'
                    return True
                except ImportError:
                    pass
            
            # No backend available
            logger.warning("No deep learning backend available")
            self.backend = None
            return False
            
        except Exception as e:
            logger.error(f"Error importing deep learning libraries: {e}")
            self.backend = None
            return False
    
    def _load_pretrained_models(self) -> bool:
        """
        Load pre-trained models for feature extraction
        
        Returns:
            Success status
        """
        # Get models directory from config
        models_dir = self.config.get('models_dir')
        if not models_dir:
            # Try to locate models relative to this file
            current_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(os.path.dirname(current_dir))
            models_dir = os.path.join(parent_dir, 'ai_detection', 'models')
        
        if not os.path.exists(models_dir):
            logger.warning(f"Models directory not found: {models_dir}")
            return False
        
        try:
            # Load models based on backend
            if self.backend == 'keras':
                return self._load_keras_models(models_dir)
            elif self.backend == 'pytorch':
                return self._load_pytorch_models(models_dir)
            elif self.backend == 'onnx':
                return self._load_onnx_models(models_dir)
            else:
                return False
                
        except Exception as e:
            logger.error(f"Error loading pre-trained models: {e}")
            return False
    
    def _load_keras_models(self, models_dir: str) -> bool:
        """
        Load Keras models from the models directory
        
        Args:
            models_dir: Directory containing models
            
        Returns:
            Success status
        """
        try:
            # Look for Keras model files (.h5)
            model_files = [f for f in os.listdir(models_dir) if f.endswith('.h5')]
            
            if not model_files:
                logger.warning(f"No Keras model files found in {models_dir}")
                return False
            
            # Load each model
            for model_file in model_files:
                model_path = os.path.join(models_dir, model_file)
                model_name = os.path.splitext(model_file)[0]
                
                try:
                    model = keras.models.load_model(model_path)
                    self.models[model_name] = model
                    logger.info(f"Loaded Keras model: {model_name}")
                except Exception as e:
                    logger.error(f"Error loading Keras model {model_name}: {e}")
            
            return len(self.models) > 0
            
        except Exception as e:
            logger.error(f"Error loading Keras models: {e}")
            return False
    
    def _load_pytorch_models(self, models_dir: str) -> bool:
        """
        Load PyTorch models from the models directory
        
        Args:
            models_dir: Directory containing models
            
        Returns:
            Success status
        """
        try:
            # Look for PyTorch model files (.pt or .pth)
            model_files = [f for f in os.listdir(models_dir) if f.endswith('.pt') or f.endswith('.pth')]
            
            if not model_files:
                logger.warning(f"No PyTorch model files found in {models_dir}")
                return False
            
            # Load each model
            for model_file in model_files:
                model_path = os.path.join(models_dir, model_file)
                model_name = os.path.splitext(model_file)[0]
                
                try:
                    # Load model architecture from config file if available
                    config_path = os.path.join(models_dir, f"{model_name}_config.json")
                    if os.path.exists(config_path):
                        with open(config_path, 'r') as f:
                            config = json.load(f)
                        
                        # Dynamically create model architecture
                        model = self._create_pytorch_model_from_config(config)
                        model.load_state_dict(torch.load(model_path, map_location='cpu'))
                    else:
                        # Load entire model object
                        model = torch.load(model_path, map_location='cpu')
                    
                    model.eval()  # Set to evaluation mode
                    self.models[model_name] = model
                    logger.info(f"Loaded PyTorch model: {model_name}")
                except Exception as e:
                    logger.error(f"Error loading PyTorch model {model_name}: {e}")
            
            return len(self.models) > 0
            
        except Exception as e:
            logger.error(f"Error loading PyTorch models: {e}")
            return False
    
    def _create_pytorch_model_from_config(self, config: Dict[str, Any]) -> nn.Module:
        """
        Create a PyTorch model from config
        
        Args:
            config: Model configuration
            
        Returns:
            PyTorch model
        """
        # Implement a simple model architecture
        class FeatureExtractor(nn.Module):
            def __init__(self, feature_dim):
                super(FeatureExtractor, self).__init__()
                self.feature_dim = feature_dim
                
                # Create layers based on config
                layers = []
                input_dim = config.get('input_dim', 512)
                hidden_dims = config.get('hidden_dims', [256, 128])
                
                # Input layer
                layers.append(nn.Linear(input_dim, hidden_dims[0]))
                layers.append(nn.ReLU())
                
                # Hidden layers
                for i in range(len(hidden_dims) - 1):
                    layers.append(nn.Linear(hidden_dims[i], hidden_dims[i+1]))
                    layers.append(nn.ReLU())
                
                # Output layer
                layers.append(nn.Linear(hidden_dims[-1], feature_dim))
                
                self.model = nn.Sequential(*layers)
            
            def forward(self, x):
                return self.model(x)
        
        return FeatureExtractor(self.feature_dim)
    
    def _load_onnx_models(self, models_dir: str) -> bool:
        """
        Load ONNX models from the models directory
        
        Args:
            models_dir: Directory containing models
            
        Returns:
            Success status
        """
        try:
            # Look for ONNX model files (.onnx)
            model_files = [f for f in os.listdir(models_dir) if f.endswith('.onnx')]
            
            if not model_files:
                logger.warning(f"No ONNX model files found in {models_dir}")
                return False
            
            # Load each model
            for model_file in model_files:
                model_path = os.path.join(models_dir, model_file)
                model_name = os.path.splitext(model_file)[0]
                
                try:
                    session = ort.InferenceSession(model_path)
                    self.models[model_name] = session
                    logger.info(f"Loaded ONNX model: {model_name}")
                except Exception as e:
                    logger.error(f"Error loading ONNX model {model_name}: {e}")
            
            return len(self.models) > 0
            
        except Exception as e:
            logger.error(f"Error loading ONNX models: {e}")
            return False
    
    def extract_features(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract deep learning features from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            Extracted features
        """
        if not self.initialized:
            if not self.initialize():
                # Fallback to basic features if initialization failed
                return self._extract_basic_features(sample_data)
        
        try:
            # Extract input features
            input_features = self._extract_input_features(sample_data)
            
            # Apply deep learning models
            results = {
                "deep_embedding": self._compute_deep_embedding(input_features),
                "feature_confidence": 0.0,
                "classification_scores": {},
                "similarity_features": {}
            }
            
            # Calculate confidence in features
            results["feature_confidence"] = self._calculate_feature_confidence(input_features)
            
            # Get classification scores if models are available
            if self.models:
                results["classification_scores"] = self._get_classification_scores(input_features)
            
            # Compute similarity features
            results["similarity_features"] = self._compute_similarity_features(input_features)
            
            return results
            
        except Exception as e:
            logger.error(f"Error extracting deep features: {e}")
            # Fallback to basic features
            return self._extract_basic_features(sample_data)
    
    def _extract_input_features(self, sample_data: Dict[str, Any]) -> Union[np.ndarray, torch.Tensor]:
        """
        Extract input features from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            Input features for deep learning models
        """
        # Extract numeric features from sample data
        features = []
        
        # Process strings (if available)
        strings = sample_data.get("analysis", {}).get("strings", [])
        if strings:
            # Count special keywords
            crypto_count = sum(1 for s in strings if any(c in s.lower() for c in ["crypt", "encrypt", "decrypt", "aes", "rsa"]))
            features.append(crypto_count)
            
            ransom_count = sum(1 for s in strings if any(r in s.lower() for r in ["ransom", "bitcoin", "payment", "wallet"]))
            features.append(ransom_count)
            
            file_count = sum(1 for s in strings if any(f in s.lower() for r in ["file", "files", "folder", "directory"]))
            features.append(file_count)
            
            # String length statistics
            string_lengths = [len(s) for s in strings]
            if string_lengths:
                features.extend([
                    np.mean(string_lengths),
                    np.std(string_lengths),
                    np.max(string_lengths),
                    len(strings)
                ])
            else:
                features.extend([0, 0, 0, 0])
        else:
            features.extend([0, 0, 0, 0, 0, 0, 0])
        
        # Process file operations (if available)
        behaviors = sample_data.get("analysis", {}).get("behaviors", {})
        file_ops = behaviors.get("file_operations", [])
        if file_ops:
            # Count operation types
            read_count = sum(1 for op in file_ops if op.get("type") == "read")
            write_count = sum(1 for op in file_ops if op.get("type") == "write")
            delete_count = sum(1 for op in file_ops if op.get("type") == "delete")
            rename_count = sum(1 for op in file_ops if op.get("type") == "rename")
            
            features.extend([read_count, write_count, delete_count, rename_count, len(file_ops)])
        else:
            features.extend([0, 0, 0, 0, 0])
        
        # Process registry operations (if available)
        registry = behaviors.get("registry", {})
        keys_set = registry.get("keys_set", [])
        keys_deleted = registry.get("keys_deleted", [])
        
        features.extend([len(keys_set), len(keys_deleted)])
        
        # Process network indicators (if available)
        network = behaviors.get("network", {})
        domains = network.get("domains", [])
        ips = network.get("ips", [])
        urls = network.get("urls", [])
        
        features.extend([len(domains), len(ips), len(urls)])
        
        # Process static features (if available)
        static = sample_data.get("analysis", {}).get("static", {})
        
        # PE sections
        sections = static.get("pe_sections", [])
        if sections:
            # Calculate average section entropy
            entropies = [section.get("entropy", 0) for section in sections]
            features.extend([np.mean(entropies), np.max(entropies), len(sections)])
        else:
            features.extend([0, 0, 0])
        
        # Imports and exports
        imports = static.get("imports", {})
        exports = static.get("exports", [])
        
        features.extend([len(imports), len(exports)])
        
        # Convert to numpy array
        feature_array = np.array(features, dtype=np.float32)
        
        # Normalize features
        normalized_features = self._normalize_features(feature_array)
        
        # Convert to appropriate format based on backend
        if self.backend == 'pytorch':
            return torch.tensor(normalized_features, dtype=torch.float32)
        else:
            return normalized_features
    
    def _normalize_features(self, features: np.ndarray) -> np.ndarray:
        """
        Normalize input features
        
        Args:
            features: Input features
            
        Returns:
            Normalized features
        """
        # Simple min-max normalization
        # Get scaling factors from config or use defaults
        scaling_factors = self.config.get('scaling_factors', {})
        max_values = scaling_factors.get('max_values')
        
        if max_values is None or len(max_values) != len(features):
            # Use empirical max values (can be tuned based on dataset)
            max_values = np.array([
                100,   # crypto_count
                100,   # ransom_count
                100,   # file_count
                500,   # mean string length
                300,   # std string length
                10000, # max string length
                10000, # string count
                1000,  # read_count
                1000,  # write_count
                1000,  # delete_count
                1000,  # rename_count
                5000,  # total file ops
                100,   # registry keys set
                100,   # registry keys deleted
                100,   # domains count
                100,   # ips count
                100,   # urls count
                8.0,   # mean section entropy
                8.0,   # max section entropy
                30,    # section count
                1000,  # imports count
                1000   # exports count
            ])
            
            # Pad or truncate to match feature length
            if len(max_values) < len(features):
                max_values = np.pad(max_values, (0, len(features) - len(max_values)), 'constant', constant_values=1000)
            elif len(max_values) > len(features):
                max_values = max_values[:len(features)]
        
        # Apply normalization with small epsilon to avoid division by zero
        epsilon = 1e-8
        return features / (max_values + epsilon)
    
    def _compute_deep_embedding(self, input_features: Union[np.ndarray, torch.Tensor]) -> List[float]:
        """
        Compute deep embedding using available models
        
        Args:
            input_features: Input features
            
        Returns:
            Deep embedding vector
        """
        # Default embedding (fallback if no models are available)
        default_embedding = np.zeros(self.feature_dim, dtype=np.float32)
        
        # If no models available, return default embedding
        if not self.models:
            return default_embedding.tolist()
        
        try:
            # Get primary model for embedding
            primary_model_name = self.config.get('primary_embedding_model')
            if primary_model_name and primary_model_name in self.models:
                model = self.models[primary_model_name]
            else:
                # Use first available model
                model_name = next(iter(self.models))
                model = self.models[model_name]
            
            # Compute embedding based on backend
            if self.backend == 'keras':
                # Reshape input for Keras (add batch dimension)
                input_tensor = np.expand_dims(input_features, axis=0)
                embedding = model.predict(input_tensor)[0]
                
            elif self.backend == 'pytorch':
                # Ensure model is in evaluation mode
                model.eval()
                
                # Compute embedding
                with torch.no_grad():
                    input_tensor = input_features.unsqueeze(0)
                    embedding = model(input_tensor).squeeze(0).cpu().numpy()
                    
            elif self.backend == 'onnx':
                # Reshape input for ONNX (add batch dimension)
                input_tensor = np.expand_dims(input_features, axis=0).astype(np.float32)
                
                # Get input and output names
                input_name = model.get_inputs()[0].name
                output_name = model.get_outputs()[0].name
                
                # Run inference
                embedding = model.run([output_name], {input_name: input_tensor})[0][0]
            
            # Ensure embedding is the correct size
            if len(embedding) != self.feature_dim:
                logger.warning(f"Embedding dimension mismatch: expected {self.feature_dim}, got {len(embedding)}")
                
                # Resize embedding
                if len(embedding) > self.feature_dim:
                    embedding = embedding[:self.feature_dim]
                else:
                    embedding = np.pad(embedding, (0, self.feature_dim - len(embedding)), 'constant')
            
            return embedding.tolist()
            
        except Exception as e:
            logger.error(f"Error computing deep embedding: {e}")
            return default_embedding.tolist()
    
    def _calculate_feature_confidence(self, input_features: Union[np.ndarray, torch.Tensor]) -> float:
        """
        Calculate confidence in extracted features
        
        Args:
            input_features: Input features
            
        Returns:
            Confidence score (0.0 to 1.0)
        """
        # Convert to numpy if needed
        if self.backend == 'pytorch' and isinstance(input_features, torch.Tensor):
            features = input_features.cpu().numpy()
        else:
            features = input_features
        
        # Calculate confidence based on feature values
        # This is a heuristic measure of how informative the features are
        non_zero_ratio = np.count_nonzero(features) / len(features)
        feature_variance = np.var(features)
        
        # Combine metrics (can be tuned based on empirical analysis)
        confidence = (0.7 * non_zero_ratio) + (0.3 * min(feature_variance * 10, 1.0))
        
        return float(min(max(confidence, 0.0), 1.0))
    
    def _get_classification_scores(self, input_features: Union[np.ndarray, torch.Tensor]) -> Dict[str, float]:
        """
        Get classification scores from models
        
        Args:
            input_features: Input features
            
        Returns:
            Dictionary of classification scores
        """
        scores = {}
        
        try:
            # Get classification model
            model_name = self.config.get('classification_model')
            if model_name and model_name in self.models:
                model = self.models[model_name]
            else:
                # If no specific classification model, return empty scores
                return scores
            
            # Run classification based on backend
            if self.backend == 'keras':
                # Reshape input for Keras (add batch dimension)
                input_tensor = np.expand_dims(input_features, axis=0)
                predictions = model.predict(input_tensor)[0]
                
                # Get class labels from config
                class_labels = self.config.get('class_labels', [f"class_{i}" for i in range(len(predictions))])
                
                # Create scores dictionary
                for i, score in enumerate(predictions):
                    if i < len(class_labels):
                        scores[class_labels[i]] = float(score)
                    
            elif self.backend == 'pytorch':
                # Ensure model is in evaluation mode
                model.eval()
                
                # Compute predictions
                with torch.no_grad():
                    input_tensor = input_features.unsqueeze(0)
                    predictions = model(input_tensor).squeeze(0)
                    
                    # Apply softmax if needed
                    if hasattr(predictions, 'softmax'):
                        predictions = predictions.softmax(dim=0)
                    
                    predictions = predictions.cpu().numpy()
                
                # Get class labels from config
                class_labels = self.config.get('class_labels', [f"class_{i}" for i in range(len(predictions))])
                
                # Create scores dictionary
                for i, score in enumerate(predictions):
                    if i < len(class_labels):
                        scores[class_labels[i]] = float(score)
                    
            elif self.backend == 'onnx':
                # Reshape input for ONNX (add batch dimension)
                input_tensor = np.expand_dims(input_features, axis=0).astype(np.float32)
                
                # Get input and output names
                input_name = model.get_inputs()[0].name
                output_name = model.get_outputs()[0].name
                
                # Run inference
                predictions = model.run([output_name], {input_name: input_tensor})[0][0]
                
                # Get class labels from config
                class_labels = self.config.get('class_labels', [f"class_{i}" for i in range(len(predictions))])
                
                # Create scores dictionary
                for i, score in enumerate(predictions):
                    if i < len(class_labels):
                        scores[class_labels[i]] = float(score)
            
            return scores
            
        except Exception as e:
            logger.error(f"Error getting classification scores: {e}")
            return scores
    
    def _compute_similarity_features(self, input_features: Union[np.ndarray, torch.Tensor]) -> Dict[str, Any]:
        """
        Compute similarity features for comparison
        
        Args:
            input_features: Input features
            
        Returns:
            Similarity features
        """
        # Convert to numpy if needed
        if self.backend == 'pytorch' and isinstance(input_features, torch.Tensor):
            features = input_features.cpu().numpy()
        else:
            features = input_features
        
        # Compute simple statistical features for similarity comparison
        similarity_features = {
            "mean": float(np.mean(features)),
            "variance": float(np.var(features)),
            "non_zero_ratio": float(np.count_nonzero(features) / len(features)),
            "max_value": float(np.max(features)),
            "min_value": float(np.min(features)),
            "spectral_norm": float(np.linalg.norm(features, ord=2))
        }
        
        return similarity_features
    
    def _extract_basic_features(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract basic features when deep learning is unavailable
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            Basic extracted features
        """
        # Create dummy embedding with basic statistics
        basic_embedding = np.zeros(self.feature_dim, dtype=np.float32)
        
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

# Example usage when run as a script
if __name__ == "__main__":
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description="Deep Learning Feature Extractor")
    parser.add_argument('--sample', required=True, help='Path to sample analysis JSON file')
    parser.add_argument('--config', help='Path to extractor configuration JSON file')
    parser.add_argument('--output', help='Output file for features')
    
    args = parser.parse_args()
    
    # Load configuration if provided
    config = None
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
        except Exception as e:
            print(f"Error loading configuration: {e}")
            sys.exit(1)
    
    # Create feature extractor
    extractor = DeepFeatureExtractor(config)
    
    # Load sample data
    try:
        with open(args.sample, 'r') as f:
            sample_data = json.load(f)
    except Exception as e:
        print(f"Error loading sample data: {e}")
        sys.exit(1)
    
    # Extract features
    features = extractor.extract_features(sample_data)
    
    # Output features
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(features, f, indent=2)
        except Exception as e:
            print(f"Error writing output: {e}")
            sys.exit(1)
    else:
        print(json.dumps(features, indent=2))