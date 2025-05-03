#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Integration module for the Hybrid Transformer with the overall detection system.

This module provides a standardized interface for the Hybrid Transformer model
to interact with other components of the ransomware detection system, such as
the two-stage detector and model ensemble frameworks.
"""

import os
import sys
import json
import logging
import pickle
import numpy as np
from typing import Dict, List, Any, Tuple, Optional, Union

import torch

# Adjust path to find modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from ai_detection.models.deep.transformer.hybrid_transformer import (
    HybridTransformerAnalyzer,
    HybridDataset,
    SequenceEmbedding
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


class TransformerRansomwareDetector:
    """
    Detector interface for the Hybrid Transformer model
    
    This class provides a standardized interface for using the Hybrid Transformer
    model for ransomware detection, compatible with the two-stage detector and
    model ensemble frameworks.
    """
    
    def __init__(
        self,
        model_path: Optional[str] = None,
        cnn_feature_dim: int = 64,
        lstm_feature_dim: int = 64,
        static_feature_dim: int = 32,
        embed_dim: int = 128,
        num_heads: int = 8,
        ff_dim: int = 256,
        num_layers: int = 4,
        dropout: float = 0.1,
        batch_size: int = 32,
        device: Optional[str] = None,
        confidence_threshold: float = 0.5,
        use_sequences: bool = True,
        vocab_size: int = 1000,
        max_seq_len: int = 500
    ):
        """
        Initialize detector
        
        Args:
            model_path: Optional path to pre-trained model
            cnn_feature_dim: Dimension of CNN features
            lstm_feature_dim: Dimension of LSTM features
            static_feature_dim: Dimension of static analysis features
            embed_dim: Dimension of embedding
            num_heads: Number of attention heads
            ff_dim: Dimension of feed-forward layer
            num_layers: Number of transformer layers
            dropout: Dropout probability
            batch_size: Batch size for processing
            device: Device to use for computation
            confidence_threshold: Threshold for binary classification
            use_sequences: Whether to use sequence data
            vocab_size: Size of vocabulary for sequences
            max_seq_len: Maximum sequence length
        """
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        self.batch_size = batch_size
        self.confidence_threshold = confidence_threshold
        self.use_sequences = use_sequences
        self.vocab_size = vocab_size
        self.max_seq_len = max_seq_len
        
        # Initialize sequence embedding if needed
        self.sequence_embedding = None
        if use_sequences:
            self.sequence_embedding = HybridTransformerAnalyzer.create_sequence_embedding(
                vocab_size=vocab_size,
                embed_dim=embed_dim,
                max_seq_len=max_seq_len,
                dropout=dropout,
                padding_idx=0
            )
        
        # Initialize analyzer
        self.analyzer = HybridTransformerAnalyzer(
            cnn_feature_dim=cnn_feature_dim,
            lstm_feature_dim=lstm_feature_dim,
            static_feature_dim=static_feature_dim,
            embed_dim=embed_dim,
            num_heads=num_heads,
            ff_dim=ff_dim,
            num_layers=num_layers,
            dropout=dropout,
            batch_size=batch_size,
            device=self.device,
            sequence_embedding=self.sequence_embedding
        )
        
        # Load model if path provided
        if model_path and os.path.exists(model_path):
            logger.info(f"Loading model from {model_path}")
            self.analyzer.load(model_path)
    
    def get_default_feature_dims(self) -> Dict[str, int]:
        """
        Get default feature dimensions
        
        Returns:
            Dictionary with default feature dimensions
        """
        return {
            'cnn_feature_dim': self.analyzer.cnn_feature_dim,
            'lstm_feature_dim': self.analyzer.lstm_feature_dim,
            'static_feature_dim': self.analyzer.static_feature_dim
        }
    
    def load_features(
        self, 
        sample_data: Dict[str, Any]
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, Optional[List[int]]]:
        """
        Load features from sample data
        
        Args:
            sample_data: Sample data dictionary
            
        Returns:
            Tuple of (cnn_features, lstm_features, static_features, sequence)
        """
        # Get cnn features
        cnn_features = sample_data.get('cnn_features', None)
        if cnn_features is None:
            # Use all zeros if not available
            cnn_features = np.zeros(self.analyzer.cnn_feature_dim)
        
        # Get lstm features
        lstm_features = sample_data.get('lstm_features', None)
        if lstm_features is None:
            # Use all zeros if not available
            lstm_features = np.zeros(self.analyzer.lstm_feature_dim)
        
        # Get static features
        static_features = sample_data.get('static_features', None)
        if static_features is None:
            # Use all zeros if not available
            static_features = np.zeros(self.analyzer.static_feature_dim)
        
        # Get sequence if available and needed
        sequence = None
        if self.use_sequences:
            sequence = sample_data.get('sequence', None)
        
        return cnn_features, lstm_features, static_features, sequence
    
    def prepare_dataset(
        self,
        samples: List[Dict[str, Any]],
        labels: Optional[List[int]] = None
    ) -> HybridDataset:
        """
        Prepare dataset from samples
        
        Args:
            samples: List of sample data dictionaries
            labels: Optional list of labels
            
        Returns:
            Prepared dataset
        """
        # Extract features
        cnn_features = []
        lstm_features = []
        static_features = []
        sequences = [] if self.use_sequences else None
        
        for sample in samples:
            # Load features
            cnn_feature, lstm_feature, static_feature, sequence = self.load_features(sample)
            
            # Add to lists
            cnn_features.append(cnn_feature)
            lstm_features.append(lstm_feature)
            static_features.append(static_feature)
            
            if self.use_sequences and sequence is not None:
                sequences.append(sequence)
        
        # Create dataset
        return HybridDataset(
            cnn_features=cnn_features,
            lstm_features=lstm_features,
            static_features=static_features,
            labels=labels,
            sequences=sequences,
            max_seq_len=self.max_seq_len
        )
    
    def detect(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect ransomware in a single sample
        
        Args:
            sample_data: Sample data dictionary
            
        Returns:
            Detection result
        """
        # Prepare dataset
        dataset = self.prepare_dataset([sample_data])
        
        # Get prediction
        probs = self.analyzer.predict(dataset, return_probabilities=True)
        probability = probs[0] if probs else 0.0
        
        # Determine if ransomware
        is_ransomware = probability >= self.confidence_threshold
        
        # Extract features
        features = self.analyzer.extract_features(dataset)[0].tolist()
        
        # Build result
        result = {
            'is_ransomware': is_ransomware,
            'confidence': float(probability),
            'features': features,
            'model_type': 'transformer'
        }
        
        # Add attention analysis if sequence data is available
        if self.use_sequences and 'sequence' in sample_data:
            try:
                attention_results = self.analyzer.analyze_attention(dataset)
                if 'attention_analysis' in attention_results and attention_results['attention_analysis']:
                    result['attention_analysis'] = attention_results['attention_analysis'][0]
            except Exception as e:
                logger.warning(f"Error analyzing attention: {str(e)}")
        
        return result
    
    def batch_detect(self, samples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect ransomware in a batch of samples
        
        Args:
            samples: List of sample data dictionaries
            
        Returns:
            List of detection results
        """
        # Prepare dataset
        dataset = self.prepare_dataset(samples)
        
        # Get predictions
        probs = self.analyzer.predict(dataset, return_probabilities=True)
        
        # Extract features
        features = self.analyzer.extract_features(dataset)
        
        # Build results
        results = []
        for i, probability in enumerate(probs):
            # Determine if ransomware
            is_ransomware = probability >= self.confidence_threshold
            
            # Build result
            result = {
                'is_ransomware': is_ransomware,
                'confidence': float(probability),
                'features': features[i].tolist(),
                'model_type': 'transformer'
            }
            
            results.append(result)
        
        return results
    
    def train(
        self,
        train_samples: List[Dict[str, Any]],
        train_labels: List[int],
        val_samples: Optional[List[Dict[str, Any]]] = None,
        val_labels: Optional[List[int]] = None,
        model_save_path: Optional[str] = None,
        epochs: int = 10,
        patience: int = 3
    ) -> Dict[str, Any]:
        """
        Train the detector
        
        Args:
            train_samples: List of training sample dictionaries
            train_labels: List of training labels
            val_samples: Optional list of validation sample dictionaries
            val_labels: Optional list of validation labels
            model_save_path: Optional path to save the model
            epochs: Number of training epochs
            patience: Patience for early stopping
            
        Returns:
            Training result
        """
        # Prepare datasets
        train_dataset = self.prepare_dataset(train_samples, train_labels)
        
        if val_samples and val_labels:
            val_dataset = self.prepare_dataset(val_samples, val_labels)
        else:
            val_dataset = None
        
        # Train model
        history = self.analyzer.train(
            train_dataset=train_dataset,
            val_dataset=val_dataset,
            epochs=epochs,
            patience=patience,
            model_save_path=model_save_path
        )
        
        # Build result
        result = {
            'history': history,
            'model_save_path': model_save_path
        }
        
        return result
    
    def extract_features(self, sample_data: Dict[str, Any]) -> np.ndarray:
        """
        Extract features from a single sample
        
        Args:
            sample_data: Sample data dictionary
            
        Returns:
            Extracted features
        """
        # Prepare dataset
        dataset = self.prepare_dataset([sample_data])
        
        # Extract features
        features = self.analyzer.extract_features(dataset)[0]
        
        return features
    
    def save(self, path: str):
        """
        Save model to file
        
        Args:
            path: Path to save model
        """
        self.analyzer.save(path)
    
    def load(self, path: str):
        """
        Load model from file
        
        Args:
            path: Path to load model from
        """
        self.analyzer.load(path)


# Factory function for creating the detector
def create_transformer_detector(**kwargs) -> TransformerRansomwareDetector:
    """
    Factory function to create a transformer detector
    
    Args:
        **kwargs: Keyword arguments for detector initialization
        
    Returns:
        Initialized transformer detector
    """
    return TransformerRansomwareDetector(**kwargs)