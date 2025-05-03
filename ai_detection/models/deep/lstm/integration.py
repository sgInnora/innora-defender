#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Integration module for LSTM sequence analyzer with the overall detection framework.
"""

import os
import sys
import logging
from typing import Dict, List, Any, Optional

import numpy as np
import torch

# Adjust path to find modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from ai_detection.models.deep.lstm.sequence_lstm_analyzer import (
    SequenceLSTMAnalyzer,
    SequenceTokenizer,
    SequenceExtractor
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


class LSTMSequenceDetector:
    """
    LSTM-based sequence detector for integration with the ransomware detection framework.
    This provides a standardized interface for the LSTM sequence analyzer to interact
    with other components of the detection system.
    """
    
    def __init__(
        self,
        model_path: Optional[str] = None,
        tokenizer_path: Optional[str] = None,
        device: str = None,
        batch_size: int = 32,
        max_seq_length: int = 500,
        embedding_dim: int = 64,
        hidden_dim: int = 128,
        confidence_threshold: float = 0.5
    ):
        """
        Initialize the LSTM sequence detector
        
        Args:
            model_path: Optional path to pre-trained model
            tokenizer_path: Optional path to pre-trained tokenizer
            device: Computation device ('cuda' or 'cpu')
            batch_size: Batch size for processing
            max_seq_length: Maximum sequence length
            embedding_dim: Dimension of token embeddings
            hidden_dim: Dimension of LSTM hidden states
            confidence_threshold: Threshold for positive detection
        """
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        self.batch_size = batch_size
        self.max_seq_length = max_seq_length
        self.embedding_dim = embedding_dim
        self.hidden_dim = hidden_dim
        self.confidence_threshold = confidence_threshold
        
        # Load or initialize analyzer
        if model_path and tokenizer_path and os.path.exists(model_path) and os.path.exists(tokenizer_path):
            logger.info(f"Loading LSTM sequence analyzer from {model_path}")
            self.analyzer = SequenceLSTMAnalyzer.load(
                model_path=model_path,
                tokenizer_path=tokenizer_path,
                device=self.device
            )
        else:
            logger.info("Initializing new LSTM sequence analyzer")
            self.analyzer = SequenceLSTMAnalyzer(
                device=self.device,
                batch_size=batch_size,
                max_seq_length=max_seq_length,
                embedding_dim=embedding_dim,
                hidden_dim=hidden_dim
            )
    
    def train(
        self,
        execution_logs: Dict[str, List[str]],
        model_save_dir: str = './models',
        epochs: int = 10,
        learning_rate: float = 0.001
    ) -> Dict[str, Any]:
        """
        Train the LSTM sequence detector
        
        Args:
            execution_logs: Dictionary mapping sample IDs to execution log paths
            model_save_dir: Directory to save trained models
            epochs: Number of training epochs
            learning_rate: Learning rate for training
            
        Returns:
            Dictionary with training results
        """
        # Prepare paths and labels
        train_paths = []
        train_labels = []
        
        for sample_id, log_paths in execution_logs.items():
            # Extract label from sample_id (assuming format like 'ransomware_123' or 'benign_456')
            is_ransomware = 1 if 'ransomware' in sample_id.lower() else 0
            
            # Add each log path with its label
            for log_path in log_paths:
                train_paths.append(log_path)
                train_labels.append(is_ransomware)
        
        # Ensure model save directory exists
        os.makedirs(model_save_dir, exist_ok=True)
        model_save_path = os.path.join(model_save_dir, 'sequence_lstm_model.pt')
        tokenizer_save_path = os.path.join(model_save_dir, 'sequence_tokenizer.pkl')
        
        # Train model
        logger.info(f"Training LSTM model on {len(train_paths)} samples...")
        history = self.analyzer.train(
            train_log_paths=train_paths,
            train_labels=train_labels,
            epochs=epochs,
            learning_rate=learning_rate,
            model_save_path=model_save_path
        )
        
        # Save tokenizer
        self.analyzer.save(
            model_path=model_save_path,
            tokenizer_path=tokenizer_save_path
        )
        
        return {
            'history': history,
            'model_path': model_save_path,
            'tokenizer_path': tokenizer_save_path,
            'samples_trained': len(train_paths)
        }
    
    def detect(self, execution_logs: List[str]) -> Dict[str, Any]:
        """
        Detect ransomware based on execution logs
        
        Args:
            execution_logs: List of paths to execution logs
            
        Returns:
            Detection results
        """
        if not execution_logs:
            return {
                'is_ransomware': False,
                'confidence': 0.0,
                'features': None,
                'details': {
                    'error': 'No execution logs provided'
                }
            }
        
        try:
            # Get probabilities for each log
            probabilities = self.analyzer.predict(
                execution_logs, 
                return_probabilities=True
            )
            
            # Extract features
            features = self.analyzer.extract_features(execution_logs)
            
            # Overall probability (max of individual probabilities)
            overall_probability = max(probabilities) if probabilities else 0.0
            
            # Determine if it's ransomware
            is_ransomware = overall_probability >= self.confidence_threshold
            
            # Get attention analysis for the log with highest probability
            attention_details = {}
            if probabilities:
                max_prob_idx = np.argmax(probabilities)
                max_prob_log = execution_logs[max_prob_idx]
                
                try:
                    api_calls, weights = self.analyzer.analyze_attention(max_prob_log)
                    
                    # Get top 10 API calls by attention weight
                    top_indices = np.argsort(weights)[-10:][::-1]
                    top_api_calls = [api_calls[i] for i in top_indices]
                    top_weights = [weights[i] for i in top_indices]
                    
                    attention_details = {
                        'top_api_calls': top_api_calls,
                        'top_weights': top_weights,
                        'log_path': max_prob_log
                    }
                except Exception as e:
                    logger.error(f"Error analyzing attention: {str(e)}")
                    attention_details = {
                        'error': str(e)
                    }
            
            return {
                'is_ransomware': is_ransomware,
                'confidence': float(overall_probability),
                'features': features.tolist() if isinstance(features, np.ndarray) else None,
                'details': {
                    'probabilities': [float(p) for p in probabilities],
                    'log_paths': execution_logs,
                    'attention_analysis': attention_details
                }
            }
        
        except Exception as e:
            logger.error(f"Error in ransomware detection: {str(e)}")
            return {
                'is_ransomware': False,
                'confidence': 0.0,
                'features': None,
                'error': str(e)
            }
    
    def extract_behavioral_features(self, execution_logs: List[str]) -> Dict[str, Any]:
        """
        Extract behavioral features from execution logs
        
        Args:
            execution_logs: List of paths to execution logs
            
        Returns:
            Dictionary of extracted features
        """
        try:
            # Extract features
            features = self.analyzer.extract_features(execution_logs)
            
            # Analyze a random log for attention insights
            if execution_logs:
                log_path = execution_logs[0]
                api_calls, weights = self.analyzer.analyze_attention(log_path)
                
                # Get top API calls by attention weight
                top_indices = np.argsort(weights)[-10:][::-1]
                top_api_calls = [api_calls[i] for i in top_indices]
                top_weights = [weights[i] for i in top_indices]
                
                return {
                    'features': features.tolist() if isinstance(features, np.ndarray) else None,
                    'feature_dim': features.shape[1] if isinstance(features, np.ndarray) else None,
                    'behavioral_indicators': {
                        'top_api_calls': top_api_calls,
                        'importance_scores': top_weights
                    },
                    'sequence_length': len(api_calls)
                }
            else:
                return {
                    'features': None,
                    'error': 'No execution logs provided'
                }
        
        except Exception as e:
            logger.error(f"Error extracting behavioral features: {str(e)}")
            return {
                'features': None,
                'error': str(e)
            }


# Factory function for creating the detector
def create_lstm_sequence_detector(
    model_path: Optional[str] = None,
    tokenizer_path: Optional[str] = None,
    **kwargs
) -> LSTMSequenceDetector:
    """
    Factory function to create an LSTM sequence detector
    
    Args:
        model_path: Optional path to pre-trained model
        tokenizer_path: Optional path to pre-trained tokenizer
        **kwargs: Additional arguments for detector initialization
        
    Returns:
        Initialized LSTM sequence detector
    """
    return LSTMSequenceDetector(
        model_path=model_path,
        tokenizer_path=tokenizer_path,
        **kwargs
    )