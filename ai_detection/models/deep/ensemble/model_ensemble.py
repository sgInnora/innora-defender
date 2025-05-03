#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Model Ensemble Framework for Ransomware Detection

This module implements a flexible ensemble framework that combines predictions from
multiple ransomware detection models to improve accuracy and robustness. The framework
supports various ensemble methods such as voting, weighted averaging, stacking, and
feature-level fusion.
"""

import os
import sys
import json
import logging
import pickle
import time
from typing import Dict, List, Any, Tuple, Optional, Union, Callable
from enum import Enum
from datetime import datetime

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


class EnsembleMethod(Enum):
    """Ensemble methods"""
    MAJORITY_VOTE = "majority_vote"
    WEIGHTED_AVERAGE = "weighted_average"
    STACKING = "stacking"
    FEATURE_FUSION = "feature_fusion"
    CUSTOM = "custom"


class ModelEnsemble:
    """
    Model Ensemble Framework
    
    This class implements a flexible ensemble framework that combines predictions
    from multiple ransomware detection models.
    """
    
    def __init__(
        self,
        model_configs: List[Dict[str, Any]],
        method: Union[str, EnsembleMethod] = EnsembleMethod.WEIGHTED_AVERAGE,
        weights: Optional[List[float]] = None,
        meta_classifier: str = "logistic_regression",
        meta_classifier_params: Optional[Dict[str, Any]] = None,
        feature_fusion_dim: int = 128,
        custom_ensemble_func: Optional[Callable] = None,
        confidence_threshold: float = 0.5,
        cache_dir: str = "./ensemble_cache"
    ):
        """
        Initialize model ensemble
        
        Args:
            model_configs: List of model configurations
                Each config should contain:
                - 'type': Model type (e.g., 'cnn', 'lstm', 'transformer')
                - 'model_path': Path to model file (optional)
                - 'model_params': Parameters for model initialization (optional)
                - 'weight': Weight for model in ensemble (optional)
            method: Ensemble method to use
            weights: Optional list of weights for weighted average (one per model)
            meta_classifier: Type of meta-classifier for stacking ('logistic_regression' or 'random_forest')
            meta_classifier_params: Parameters for meta-classifier
            feature_fusion_dim: Dimension for feature fusion
            custom_ensemble_func: Custom function for ensemble (if method is CUSTOM)
            confidence_threshold: Confidence threshold for binary classification
            cache_dir: Directory for caching ensemble results
        """
        self.model_configs = model_configs
        
        # Set ensemble method
        if isinstance(method, str):
            try:
                self.method = EnsembleMethod(method)
            except ValueError:
                logger.warning(f"Unknown ensemble method: {method}, using WEIGHTED_AVERAGE")
                self.method = EnsembleMethod.WEIGHTED_AVERAGE
        else:
            self.method = method
        
        # Set weights
        if weights:
            if len(weights) != len(model_configs):
                logger.warning(f"Number of weights ({len(weights)}) doesn't match number of models ({len(model_configs)}), using equal weights")
                self.weights = [1.0 / len(model_configs)] * len(model_configs)
            else:
                # Normalize weights
                weight_sum = sum(weights)
                self.weights = [w / weight_sum for w in weights]
        else:
            # Use equal weights
            self.weights = [1.0 / len(model_configs)] * len(model_configs)
        
        # Set meta-classifier
        self.meta_classifier_type = meta_classifier
        self.meta_classifier_params = meta_classifier_params or {}
        self.meta_classifier = None
        
        # Set feature fusion dimension
        self.feature_fusion_dim = feature_fusion_dim
        
        # Set custom ensemble function
        self.custom_ensemble_func = custom_ensemble_func
        
        # Set confidence threshold
        self.confidence_threshold = confidence_threshold
        
        # Set cache directory
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)
        
        # Initialize feature fusion layers
        self.feature_fusion_layers = {}
        
        # Initialize models
        self.models = self._initialize_models()
    
    def _initialize_models(self) -> Dict[str, Any]:
        """
        Initialize models based on configurations
        
        Returns:
            Dictionary mapping model IDs to initialized models
        """
        models = {}
        
        for idx, config in enumerate(self.model_configs):
            model_type = config.get('type', '').lower()
            model_id = config.get('id', f"model_{idx}")
            model_path = config.get('model_path')
            model_params = config.get('model_params', {})
            
            try:
                if model_type == 'cnn':
                    # Import CNN detector
                    from ai_detection.models.deep.cnn.binary_cnn_extractor import BinaryCNNExtractor
                    
                    # Initialize CNN detector
                    if model_path and os.path.exists(model_path):
                        model = BinaryCNNExtractor.load(model_path, **model_params)
                    else:
                        model = BinaryCNNExtractor(**model_params)
                
                elif model_type == 'lstm':
                    # Import LSTM detector
                    from ai_detection.models.deep.lstm.integration import create_lstm_sequence_detector
                    
                    # Initialize LSTM detector
                    model = create_lstm_sequence_detector(
                        model_path=model_path if model_path and os.path.exists(model_path) else None,
                        **model_params
                    )
                
                elif model_type == 'transformer':
                    # Import Transformer detector
                    from ai_detection.models.deep.transformer.integration import create_transformer_detector
                    
                    # Initialize Transformer detector
                    model = create_transformer_detector(
                        model_path=model_path if model_path and os.path.exists(model_path) else None,
                        **model_params
                    )
                
                elif model_type == 'llm':
                    # Import LLM analyzer
                    from ai_detection.models.deep.llm_integration.llm_analyzer import LLMRansomwareAnalyzer
                    
                    # Initialize LLM analyzer
                    if model_path and os.path.exists(model_path):
                        with open(model_path, 'r') as f:
                            llm_config = json.load(f)
                        model = LLMRansomwareAnalyzer(**llm_config)
                    else:
                        model = LLMRansomwareAnalyzer(**model_params)
                
                elif model_type == 'two_stage':
                    # Import Two-Stage detector
                    from ai_detection.models.deep.two_stage.two_stage_detector import TwoStageRansomwareDetector
                    
                    # Initialize Two-Stage detector
                    if model_path and os.path.exists(model_path) and os.path.isdir(model_path):
                        # Load from saved state directory
                        model = TwoStageRansomwareDetector.load(model_path)
                    else:
                        # Create new detector
                        model = TwoStageRansomwareDetector(**model_params)
                
                else:
                    logger.warning(f"Unknown model type: {model_type}, skipping")
                    continue
                
                # Add model to dictionary
                models[model_id] = {
                    'model': model,
                    'type': model_type,
                    'weight': config.get('weight', self.weights[idx])
                }
                
            except Exception as e:
                logger.error(f"Error initializing model {model_id} ({model_type}): {str(e)}")
        
        logger.info(f"Initialized {len(models)} models for ensemble")
        return models
    
    def _initialize_meta_classifier(self, input_dim: int):
        """
        Initialize meta-classifier for stacking
        
        Args:
            input_dim: Input dimension for meta-classifier
        """
        if self.meta_classifier_type == 'logistic_regression':
            self.meta_classifier = LogisticRegression(
                max_iter=1000,
                **self.meta_classifier_params
            )
        elif self.meta_classifier_type == 'random_forest':
            self.meta_classifier = RandomForestClassifier(
                **self.meta_classifier_params
            )
        else:
            logger.warning(f"Unknown meta-classifier type: {self.meta_classifier_type}, using LogisticRegression")
            self.meta_classifier = LogisticRegression(max_iter=1000)
    
    def _initialize_feature_fusion_layer(self, model_id: str, feature_dim: int):
        """
        Initialize feature fusion layer for a model
        
        Args:
            model_id: Model ID
            feature_dim: Feature dimension
        """
        import torch
        import torch.nn as nn
        
        # Create feature fusion layer
        layer = nn.Sequential(
            nn.Linear(feature_dim, self.feature_fusion_dim),
            nn.LayerNorm(self.feature_fusion_dim),
            nn.ReLU(),
            nn.Dropout(0.1)
        )
        
        # Determine device
        device = 'cuda' if torch.cuda.is_available() else 'cpu'
        
        # Move to device
        layer.to(device)
        
        # Set to evaluation mode
        layer.eval()
        
        # Add to dictionary
        self.feature_fusion_layers[model_id] = {
            'layer': layer,
            'input_dim': feature_dim,
            'device': device
        }
    
    def predict(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make ensemble prediction for a single sample
        
        Args:
            sample_data: Sample data for prediction
            
        Returns:
            Prediction result
        """
        # Get predictions from all models
        model_predictions = {}
        for model_id, model_info in self.models.items():
            model = model_info['model']
            model_type = model_info['type']
            
            try:
                # Get prediction
                if model_type == 'cnn':
                    # Get binary path
                    binary_path = sample_data.get('binary_path')
                    if not binary_path or not os.path.exists(binary_path):
                        logger.warning(f"Binary path not provided or doesn't exist for CNN model {model_id}")
                        continue
                    
                    # Analyze binary
                    prediction = model.analyze(binary_path)
                
                elif model_type == 'lstm':
                    # Get execution logs
                    execution_logs = sample_data.get('execution_logs', [])
                    if not execution_logs:
                        logger.warning(f"Execution logs not provided for LSTM model {model_id}")
                        continue
                    
                    # Detect ransomware
                    prediction = model.detect(execution_logs)
                
                elif model_type == 'transformer':
                    # Detect ransomware
                    prediction = model.detect(sample_data)
                
                elif model_type == 'llm':
                    # Analyze sample
                    prediction = model.analyze_sample(sample_data)
                
                elif model_type == 'two_stage':
                    # Get binary path and execution logs
                    binary_path = sample_data.get('binary_path')
                    execution_logs = sample_data.get('execution_logs', [])
                    
                    if (not binary_path or not os.path.exists(binary_path)) and not execution_logs:
                        logger.warning(f"Neither binary path nor execution logs provided for Two-Stage model {model_id}")
                        continue
                    
                    # Detect ransomware
                    prediction = model.detect(binary_path, execution_logs)
                
                else:
                    logger.warning(f"Unknown model type: {model_type}, skipping")
                    continue
                
                # Add prediction to dictionary
                model_predictions[model_id] = prediction
                
            except Exception as e:
                logger.error(f"Error making prediction with model {model_id} ({model_type}): {str(e)}")
        
        # Check if any predictions were made
        if not model_predictions:
            logger.warning("No predictions made by any model")
            return {
                'is_ransomware': False,
                'confidence': 0.0,
                'model_predictions': {},
                'ensemble_method': self.method.value,
                'error': 'No predictions made by any model'
            }
        
        # Combine predictions using the selected ensemble method
        if self.method == EnsembleMethod.MAJORITY_VOTE:
            result = self._majority_vote(model_predictions)
        elif self.method == EnsembleMethod.WEIGHTED_AVERAGE:
            result = self._weighted_average(model_predictions)
        elif self.method == EnsembleMethod.STACKING:
            result = self._stacking(model_predictions, model_training=False)
        elif self.method == EnsembleMethod.FEATURE_FUSION:
            result = self._feature_fusion(model_predictions, model_training=False)
        elif self.method == EnsembleMethod.CUSTOM and self.custom_ensemble_func:
            result = self.custom_ensemble_func(model_predictions)
        else:
            # Default to weighted average
            result = self._weighted_average(model_predictions)
        
        # Add model predictions to result
        result['model_predictions'] = model_predictions
        
        # Add ensemble method to result
        result['ensemble_method'] = self.method.value
        
        return result
    
    def batch_predict(self, samples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Make ensemble predictions for a batch of samples
        
        Args:
            samples: List of sample data for prediction
            
        Returns:
            List of prediction results
        """
        results = []
        for sample in samples:
            result = self.predict(sample)
            results.append(result)
        
        return results
    
    def _majority_vote(self, model_predictions: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Combine predictions using majority vote
        
        Args:
            model_predictions: Dictionary mapping model IDs to predictions
            
        Returns:
            Combined prediction
        """
        # Count votes
        votes = 0
        total = 0
        
        for model_id, prediction in model_predictions.items():
            if 'is_ransomware' in prediction:
                total += 1
                if prediction['is_ransomware']:
                    votes += 1
        
        # Determine majority
        is_ransomware = votes > total / 2
        
        # Calculate confidence
        if total > 0:
            confidence = votes / total if is_ransomware else (total - votes) / total
        else:
            confidence = 0.0
        
        return {
            'is_ransomware': is_ransomware,
            'confidence': confidence
        }
    
    def _weighted_average(self, model_predictions: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Combine predictions using weighted average
        
        Args:
            model_predictions: Dictionary mapping model IDs to predictions
            
        Returns:
            Combined prediction
        """
        # Calculate weighted average
        weighted_sum = 0.0
        total_weight = 0.0
        
        for model_id, prediction in model_predictions.items():
            if 'is_ransomware' not in prediction or 'confidence' not in prediction:
                continue
            
            weight = self.models.get(model_id, {}).get('weight', 1.0)
            
            # Add to weighted sum
            weighted_sum += weight * (prediction['confidence'] if prediction['is_ransomware'] else 1.0 - prediction['confidence'])
            total_weight += weight
        
        # Calculate confidence
        if total_weight > 0:
            confidence = weighted_sum / total_weight
        else:
            confidence = 0.0
        
        # Determine classification
        is_ransomware = confidence >= self.confidence_threshold
        
        return {
            'is_ransomware': is_ransomware,
            'confidence': confidence if is_ransomware else 1.0 - confidence
        }
    
    def _stacking(
        self, 
        model_predictions: Dict[str, Dict[str, Any]], 
        model_training: bool = False, 
        true_label: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Combine predictions using stacking
        
        Args:
            model_predictions: Dictionary mapping model IDs to predictions
            model_training: Whether this is for training the meta-classifier
            true_label: True label for training
            
        Returns:
            Combined prediction
        """
        # Check if meta-classifier is trained
        if not model_training and self.meta_classifier is None:
            # Use weighted average instead
            logger.warning("Meta-classifier not trained, using weighted average")
            return self._weighted_average(model_predictions)
        
        # Extract features (predictions and confidences)
        features = []
        for model_id in sorted(self.models.keys()):
            if model_id in model_predictions:
                prediction = model_predictions[model_id]
                
                # Extract features
                if 'is_ransomware' in prediction and 'confidence' in prediction:
                    is_ransomware = int(prediction['is_ransomware'])
                    confidence = float(prediction['confidence'])
                    
                    # Add to features
                    features.extend([is_ransomware, confidence])
                else:
                    # Add zeros for missing predictions
                    features.extend([0, 0.0])
            else:
                # Add zeros for missing predictions
                features.extend([0, 0.0])
        
        # Convert to array
        features = np.array(features).reshape(1, -1)
        
        # If training, initialize meta-classifier and fit
        if model_training:
            if self.meta_classifier is None:
                # Initialize meta-classifier
                self._initialize_meta_classifier(len(features[0]))
            
            # Add to training data (stored in meta-classifier)
            if not hasattr(self, 'meta_X'):
                self.meta_X = features
                self.meta_y = np.array([true_label])
            else:
                self.meta_X = np.vstack([self.meta_X, features])
                self.meta_y = np.append(self.meta_y, true_label)
            
            # Return dummy result
            return {
                'is_ransomware': true_label == 1,
                'confidence': 1.0,
                'meta_training': True
            }
        
        # Make prediction using meta-classifier
        proba = self.meta_classifier.predict_proba(features)[0]
        is_ransomware = proba[1] >= self.confidence_threshold
        
        return {
            'is_ransomware': is_ransomware,
            'confidence': proba[1] if is_ransomware else proba[0]
        }
    
    def _feature_fusion(
        self, 
        model_predictions: Dict[str, Dict[str, Any]], 
        model_training: bool = False, 
        true_label: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Combine predictions using feature fusion
        
        Args:
            model_predictions: Dictionary mapping model IDs to predictions
            model_training: Whether this is for training the meta-classifier
            true_label: True label for training
            
        Returns:
            Combined prediction
        """
        # Check if feature fusion is initialized
        if not model_training and not self.feature_fusion_layers:
            # Use weighted average instead
            logger.warning("Feature fusion not initialized, using weighted average")
            return self._weighted_average(model_predictions)
        
        # Extract features
        import torch
        
        feature_vectors = []
        for model_id, prediction in model_predictions.items():
            if 'features' in prediction:
                features = prediction['features']
                
                # Check if feature fusion layer exists for this model
                if model_id not in self.feature_fusion_layers:
                    # Initialize feature fusion layer
                    self._initialize_feature_fusion_layer(model_id, len(features))
                
                # Convert to tensor
                features_tensor = torch.tensor(features, dtype=torch.float)
                
                # Move to device
                device = self.feature_fusion_layers[model_id]['device']
                features_tensor = features_tensor.to(device)
                
                # Apply feature fusion layer
                with torch.no_grad():
                    fused_features = self.feature_fusion_layers[model_id]['layer'](features_tensor.unsqueeze(0))
                
                # Add to feature vectors
                feature_vectors.append(fused_features.cpu().numpy())
        
        # Check if any features were extracted
        if not feature_vectors:
            # Use weighted average instead
            logger.warning("No features extracted, using weighted average")
            return self._weighted_average(model_predictions)
        
        # Combine feature vectors
        combined_features = np.concatenate(feature_vectors, axis=1)
        
        # If training, initialize meta-classifier and fit
        if model_training:
            if self.meta_classifier is None:
                # Initialize meta-classifier
                self._initialize_meta_classifier(combined_features.shape[1])
            
            # Add to training data (stored in meta-classifier)
            if not hasattr(self, 'meta_X'):
                self.meta_X = combined_features
                self.meta_y = np.array([true_label])
            else:
                self.meta_X = np.vstack([self.meta_X, combined_features])
                self.meta_y = np.append(self.meta_y, true_label)
            
            # Return dummy result
            return {
                'is_ransomware': true_label == 1,
                'confidence': 1.0,
                'meta_training': True
            }
        
        # Make prediction using meta-classifier
        proba = self.meta_classifier.predict_proba(combined_features)[0]
        is_ransomware = proba[1] >= self.confidence_threshold
        
        return {
            'is_ransomware': is_ransomware,
            'confidence': proba[1] if is_ransomware else proba[0]
        }
    
    def train(
        self,
        train_samples: List[Dict[str, Any]],
        train_labels: List[int],
        val_samples: Optional[List[Dict[str, Any]]] = None,
        val_labels: Optional[List[int]] = None
    ) -> Dict[str, Any]:
        """
        Train the ensemble model
        
        Args:
            train_samples: List of training samples
            train_labels: List of training labels
            val_samples: Optional list of validation samples
            val_labels: Optional list of validation labels
            
        Returns:
            Training results
        """
        start_time = time.time()
        
        # Only stacking and feature fusion need training
        if self.method not in [EnsembleMethod.STACKING, EnsembleMethod.FEATURE_FUSION]:
            logger.info(f"Ensemble method {self.method.value} doesn't require training")
            return {
                'trained': False,
                'method': self.method.value,
                'message': f"Ensemble method {self.method.value} doesn't require training"
            }
        
        # Reset meta-classifier training data
        if hasattr(self, 'meta_X'):
            del self.meta_X
        if hasattr(self, 'meta_y'):
            del self.meta_y
        
        # Train on all samples
        logger.info(f"Training ensemble with {len(train_samples)} samples")
        for i, (sample, label) in enumerate(zip(train_samples, train_labels)):
            # Get predictions from all models
            result = self.predict(sample)
            
            # Add to meta-classifier training data
            if self.method == EnsembleMethod.STACKING:
                self._stacking(result['model_predictions'], model_training=True, true_label=label)
            elif self.method == EnsembleMethod.FEATURE_FUSION:
                self._feature_fusion(result['model_predictions'], model_training=True, true_label=label)
        
        # Fit meta-classifier
        logger.info("Fitting meta-classifier")
        self.meta_classifier.fit(self.meta_X, self.meta_y)
        
        # Evaluate on validation set if provided
        val_results = None
        if val_samples and val_labels:
            logger.info(f"Evaluating on {len(val_samples)} validation samples")
            
            # Get predictions
            val_preds = []
            for sample in val_samples:
                result = self.predict(sample)
                val_preds.append(int(result['is_ransomware']))
            
            # Calculate metrics
            report = classification_report(val_labels, val_preds, output_dict=True)
            
            val_results = {
                'accuracy': report['accuracy'],
                'precision': report['1']['precision'] if '1' in report else 0.0,
                'recall': report['1']['recall'] if '1' in report else 0.0,
                'f1': report['1']['f1-score'] if '1' in report else 0.0,
                'report': report
            }
        
        # Calculate training time
        training_time = time.time() - start_time
        
        return {
            'trained': True,
            'method': self.method.value,
            'training_time': training_time,
            'val_results': val_results
        }
    
    def save(self, path: str):
        """
        Save ensemble model
        
        Args:
            path: Path to save model
        """
        # Create directory if it doesn't exist
        os.makedirs(path, exist_ok=True)
        
        # Save configuration
        config = {
            'model_configs': self.model_configs,
            'method': self.method.value,
            'weights': self.weights,
            'meta_classifier_type': self.meta_classifier_type,
            'meta_classifier_params': self.meta_classifier_params,
            'feature_fusion_dim': self.feature_fusion_dim,
            'confidence_threshold': self.confidence_threshold,
            'cache_dir': self.cache_dir
        }
        
        with open(os.path.join(path, 'config.json'), 'w') as f:
            json.dump(config, f, indent=2)
        
        # Save meta-classifier if trained
        if self.meta_classifier is not None:
            joblib.dump(self.meta_classifier, os.path.join(path, 'meta_classifier.pkl'))
        
        # Save feature fusion layers if initialized
        if self.feature_fusion_layers:
            import torch
            
            # Create directory for feature fusion layers
            os.makedirs(os.path.join(path, 'feature_fusion'), exist_ok=True)
            
            for model_id, layer_info in self.feature_fusion_layers.items():
                # Save layer
                torch.save(layer_info['layer'].state_dict(), os.path.join(path, 'feature_fusion', f"{model_id}.pt"))
                
                # Save metadata
                with open(os.path.join(path, 'feature_fusion', f"{model_id}.json"), 'w') as f:
                    json.dump({
                        'input_dim': layer_info['input_dim']
                    }, f, indent=2)
        
        logger.info(f"Ensemble model saved to {path}")
    
    @classmethod
    def load(cls, path: str) -> 'ModelEnsemble':
        """
        Load ensemble model
        
        Args:
            path: Path to load model from
            
        Returns:
            Loaded ensemble model
        """
        # Load configuration
        with open(os.path.join(path, 'config.json'), 'r') as f:
            config = json.load(f)
        
        # Create ensemble
        ensemble = cls(
            model_configs=config['model_configs'],
            method=config['method'],
            weights=config['weights'],
            meta_classifier_type=config['meta_classifier_type'],
            meta_classifier_params=config['meta_classifier_params'],
            feature_fusion_dim=config['feature_fusion_dim'],
            confidence_threshold=config['confidence_threshold'],
            cache_dir=config['cache_dir']
        )
        
        # Load meta-classifier if exists
        meta_classifier_path = os.path.join(path, 'meta_classifier.pkl')
        if os.path.exists(meta_classifier_path):
            ensemble.meta_classifier = joblib.load(meta_classifier_path)
        
        # Load feature fusion layers if exist
        feature_fusion_dir = os.path.join(path, 'feature_fusion')
        if os.path.exists(feature_fusion_dir):
            import torch
            import torch.nn as nn
            
            for file in os.listdir(feature_fusion_dir):
                if file.endswith('.pt'):
                    model_id = file[:-3]
                    
                    # Load metadata
                    metadata_path = os.path.join(feature_fusion_dir, f"{model_id}.json")
                    if os.path.exists(metadata_path):
                        with open(metadata_path, 'r') as f:
                            metadata = json.load(f)
                        
                        input_dim = metadata['input_dim']
                        
                        # Create feature fusion layer
                        layer = nn.Sequential(
                            nn.Linear(input_dim, ensemble.feature_fusion_dim),
                            nn.LayerNorm(ensemble.feature_fusion_dim),
                            nn.ReLU(),
                            nn.Dropout(0.1)
                        )
                        
                        # Determine device
                        device = 'cuda' if torch.cuda.is_available() else 'cpu'
                        
                        # Move to device
                        layer.to(device)
                        
                        # Load state dict
                        layer.load_state_dict(torch.load(os.path.join(feature_fusion_dir, file), map_location=device))
                        
                        # Set to evaluation mode
                        layer.eval()
                        
                        # Add to dictionary
                        ensemble.feature_fusion_layers[model_id] = {
                            'layer': layer,
                            'input_dim': input_dim,
                            'device': device
                        }
        
        logger.info(f"Ensemble model loaded from {path}")
        return ensemble