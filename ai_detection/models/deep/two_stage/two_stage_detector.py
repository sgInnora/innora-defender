#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Two-Stage Ransomware Detection System

This module implements a two-stage detection system that combines:
1. Stage 1: Specialized deep learning models (CNN, LSTM) for efficient initial screening
2. Stage 2: Large language models for in-depth analysis of suspicious samples

The specialized models quickly process all samples, filtering out clear negatives.
Suspicious samples are then sent to the more computationally expensive LLM stage
for detailed analysis and explanation.
"""

import os
import sys
import json
import logging
import pickle
from typing import Dict, List, Any, Tuple, Optional, Union, Set
from enum import Enum
from datetime import datetime
import time

import numpy as np
import torch
from sklearn.metrics import classification_report

# Adjust path to find modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from ai_detection.models.deep.cnn.binary_cnn_extractor import BinaryCNNExtractor
from ai_detection.models.deep.lstm.sequence_lstm_analyzer import SequenceLSTMAnalyzer
from ai_detection.models.deep.lstm.integration import LSTMSequenceDetector
from ai_detection.models.deep.llm_integration.llm_analyzer import LLMRansomwareAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


class DetectionStage(Enum):
    """Enum for detection stages"""
    INITIAL_SCREENING = 1
    DEEP_ANALYSIS = 2


class ModelType(Enum):
    """Enum for model types"""
    CNN = 1
    LSTM = 2
    TRANSFORMER = 3
    LLM = 4


class TwoStageRansomwareDetector:
    """
    Two-Stage Ransomware Detector
    
    Implements a two-stage detection system:
    1. Fast initial screening using specialized models (CNN, LSTM)
    2. Deep analysis of suspicious samples using large language models
    
    The system is designed to be efficient, with clear negative samples
    filtered out early, and only suspicious samples sent for deeper analysis.
    """
    
    def __init__(
        self,
        cnn_model_path: Optional[str] = None,
        lstm_model_path: Optional[str] = None,
        lstm_tokenizer_path: Optional[str] = None,
        llm_config_path: Optional[str] = None,
        initial_threshold: float = 0.3,
        confirmation_threshold: float = 0.7,
        device: str = None,
        cache_dir: str = "./model_cache",
        enable_llm: bool = True
    ):
        """
        Initialize the two-stage detector
        
        Args:
            cnn_model_path: Path to pre-trained CNN model
            lstm_model_path: Path to pre-trained LSTM model
            lstm_tokenizer_path: Path to LSTM tokenizer
            llm_config_path: Path to LLM configuration
            initial_threshold: Threshold for initial screening (lower means more samples pass to stage 2)
            confirmation_threshold: Threshold for confirmation in stage 1 (higher means more confidence needed)
            device: Computation device ('cuda' or 'cpu')
            cache_dir: Directory for model caching
            enable_llm: Whether to enable the LLM stage
        """
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        self.initial_threshold = initial_threshold
        self.confirmation_threshold = confirmation_threshold
        self.cache_dir = cache_dir
        self.enable_llm = enable_llm
        
        # Ensure cache directory exists
        os.makedirs(cache_dir, exist_ok=True)
        
        # Initialize specialized models for stage 1
        self.cnn_model = self._init_cnn_model(cnn_model_path)
        self.lstm_model = self._init_lstm_model(lstm_model_path, lstm_tokenizer_path)
        
        # Initialize LLM for stage 2
        self.llm_analyzer = self._init_llm_analyzer(llm_config_path) if enable_llm else None
        
        # Detection statistics
        self.stats = {
            'samples_processed': 0,
            'detected_stage1': 0,
            'cleared_stage1': 0,
            'sent_to_stage2': 0,
            'detected_stage2': 0,
            'cleared_stage2': 0,
            'processing_times': {
                'stage1': [],
                'stage2': []
            }
        }
    
    def _init_cnn_model(self, model_path: Optional[str]) -> Optional[BinaryCNNExtractor]:
        """
        Initialize CNN model for binary feature extraction
        
        Args:
            model_path: Path to pre-trained model
            
        Returns:
            Initialized CNN model or None if initialization fails
        """
        try:
            if model_path and os.path.exists(model_path):
                logger.info(f"Loading CNN model from {model_path}")
                return BinaryCNNExtractor.load(model_path, device=self.device)
            else:
                logger.warning("CNN model path not provided or doesn't exist. Initializing new model.")
                return BinaryCNNExtractor(device=self.device)
        except Exception as e:
            logger.error(f"Error initializing CNN model: {str(e)}")
            return None
    
    def _init_lstm_model(
        self, 
        model_path: Optional[str], 
        tokenizer_path: Optional[str]
    ) -> Optional[LSTMSequenceDetector]:
        """
        Initialize LSTM model for sequence analysis
        
        Args:
            model_path: Path to pre-trained model
            tokenizer_path: Path to tokenizer
            
        Returns:
            Initialized LSTM detector or None if initialization fails
        """
        try:
            if model_path and tokenizer_path and os.path.exists(model_path) and os.path.exists(tokenizer_path):
                logger.info(f"Loading LSTM model from {model_path}")
                return LSTMSequenceDetector(
                    model_path=model_path,
                    tokenizer_path=tokenizer_path,
                    device=self.device
                )
            else:
                logger.warning("LSTM model path not provided or doesn't exist. Initializing new model.")
                return LSTMSequenceDetector(device=self.device)
        except Exception as e:
            logger.error(f"Error initializing LSTM model: {str(e)}")
            return None
    
    def _init_llm_analyzer(self, config_path: Optional[str]) -> Optional[LLMRansomwareAnalyzer]:
        """
        Initialize LLM analyzer for deep analysis
        
        Args:
            config_path: Path to LLM configuration
            
        Returns:
            Initialized LLM analyzer or None if initialization fails
        """
        try:
            if config_path and os.path.exists(config_path):
                logger.info(f"Loading LLM configuration from {config_path}")
                with open(config_path, 'r') as f:
                    config = json.load(f)
                return LLMRansomwareAnalyzer(**config)
            else:
                logger.warning("LLM config path not provided or doesn't exist. Using default configuration.")
                return LLMRansomwareAnalyzer()
        except Exception as e:
            logger.error(f"Error initializing LLM analyzer: {str(e)}")
            return None
    
    def stage1_detection(
        self, 
        binary_path: str, 
        execution_logs: List[str]
    ) -> Dict[str, Any]:
        """
        Stage 1: Initial screening using specialized models
        
        Args:
            binary_path: Path to binary sample
            execution_logs: List of paths to execution logs
            
        Returns:
            Dictionary with detection results
        """
        start_time = time.time()
        
        # Results from each model
        cnn_result = None
        lstm_result = None
        
        # CNN analysis (if model is available)
        if self.cnn_model is not None and os.path.exists(binary_path):
            try:
                cnn_result = self.cnn_model.analyze(binary_path)
            except Exception as e:
                logger.error(f"Error in CNN analysis: {str(e)}")
        
        # LSTM analysis (if model is available and logs exist)
        if self.lstm_model is not None and execution_logs:
            try:
                lstm_result = self.lstm_model.detect(execution_logs)
            except Exception as e:
                logger.error(f"Error in LSTM analysis: {str(e)}")
        
        # Combine results
        combined_result = self._combine_stage1_results(cnn_result, lstm_result)
        
        # Calculate processing time
        processing_time = time.time() - start_time
        self.stats['processing_times']['stage1'].append(processing_time)
        
        # Add processing time to result
        combined_result['processing_time'] = processing_time
        
        return combined_result
    
    def _combine_stage1_results(
        self, 
        cnn_result: Optional[Dict[str, Any]], 
        lstm_result: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Combine results from CNN and LSTM models
        
        Args:
            cnn_result: Results from CNN model
            lstm_result: Results from LSTM model
            
        Returns:
            Combined detection result
        """
        # Default result
        combined_result = {
            'is_ransomware': False,
            'confidence': 0.0,
            'needs_deep_analysis': False,
            'model_confidences': {},
            'features': {}
        }
        
        # Process CNN result
        if cnn_result:
            combined_result['model_confidences']['cnn'] = cnn_result.get('confidence', 0.0)
            if 'features' in cnn_result:
                combined_result['features']['cnn'] = cnn_result['features']
            
            # Check if ransomware was detected by CNN
            if cnn_result.get('is_ransomware', False):
                combined_result['detection_model'] = 'cnn'
                combined_result['is_ransomware'] = True
                combined_result['confidence'] = max(
                    combined_result['confidence'],
                    cnn_result.get('confidence', 0.0)
                )
        
        # Process LSTM result
        if lstm_result:
            combined_result['model_confidences']['lstm'] = lstm_result.get('confidence', 0.0)
            if 'features' in lstm_result:
                combined_result['features']['lstm'] = lstm_result['features']
            
            # Check if ransomware was detected by LSTM
            if lstm_result.get('is_ransomware', False):
                combined_result['detection_model'] = combined_result.get('detection_model', '') + ',lstm'
                combined_result['is_ransomware'] = True
                combined_result['confidence'] = max(
                    combined_result['confidence'],
                    lstm_result.get('confidence', 0.0)
                )
        
        # Determine if deep analysis is needed
        if combined_result['confidence'] < self.confirmation_threshold and combined_result['confidence'] > self.initial_threshold:
            combined_result['needs_deep_analysis'] = True
        
        return combined_result
    
    def stage2_detection(
        self, 
        binary_path: str, 
        execution_logs: List[str], 
        stage1_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Stage 2: Deep analysis using large language model
        
        Args:
            binary_path: Path to binary sample
            execution_logs: List of paths to execution logs
            stage1_result: Results from stage 1
            
        Returns:
            Dictionary with detection results
        """
        start_time = time.time()
        
        # Check if LLM analyzer is available
        if not self.llm_analyzer or not self.enable_llm:
            logger.warning("LLM analysis is not available or disabled")
            return {
                'is_ransomware': stage1_result.get('is_ransomware', False),
                'confidence': stage1_result.get('confidence', 0.0),
                'llm_analysis': {
                    'error': 'LLM analysis not available'
                },
                'processing_time': 0.0
            }
        
        # Prepare data for LLM analysis
        analysis_data = {
            'binary_path': binary_path,
            'execution_logs': execution_logs,
            'stage1_features': stage1_result.get('features', {}),
            'stage1_confidences': stage1_result.get('model_confidences', {})
        }
        
        # Perform LLM analysis
        try:
            llm_result = self.llm_analyzer.analyze_sample(analysis_data)
        except Exception as e:
            logger.error(f"Error in LLM analysis: {str(e)}")
            llm_result = {
                'is_ransomware': False,
                'confidence': 0.0,
                'error': str(e)
            }
        
        # Calculate processing time
        processing_time = time.time() - start_time
        self.stats['processing_times']['stage2'].append(processing_time)
        
        # Add processing time to result
        llm_result['processing_time'] = processing_time
        
        return llm_result
    
    def detect(self, binary_path: str, execution_logs: List[str]) -> Dict[str, Any]:
        """
        Detect ransomware using the two-stage system
        
        Args:
            binary_path: Path to binary sample
            execution_logs: List of paths to execution logs
            
        Returns:
            Dictionary with detection results
        """
        # Update statistics
        self.stats['samples_processed'] += 1
        
        # Stage 1: Initial screening
        stage1_result = self.stage1_detection(binary_path, execution_logs)
        
        # Decision based on stage 1 result
        if stage1_result['is_ransomware'] and stage1_result['confidence'] >= self.confirmation_threshold:
            # High confidence detection in stage 1
            self.stats['detected_stage1'] += 1
            return {
                'is_ransomware': True,
                'confidence': stage1_result['confidence'],
                'detection_stage': DetectionStage.INITIAL_SCREENING.name,
                'detection_model': stage1_result.get('detection_model', 'combined'),
                'stage1_result': stage1_result,
                'stage2_result': None
            }
        elif stage1_result['confidence'] < self.initial_threshold:
            # Low confidence in being ransomware, clear in stage 1
            self.stats['cleared_stage1'] += 1
            return {
                'is_ransomware': False,
                'confidence': 1.0 - stage1_result['confidence'],  # Confidence it's benign
                'detection_stage': DetectionStage.INITIAL_SCREENING.name,
                'stage1_result': stage1_result,
                'stage2_result': None
            }
        else:
            # Suspicious sample, needs deep analysis
            self.stats['sent_to_stage2'] += 1
            
            # Stage 2: Deep analysis
            if self.enable_llm:
                stage2_result = self.stage2_detection(binary_path, execution_logs, stage1_result)
                
                # Decision based on stage 2 result
                if stage2_result.get('is_ransomware', False):
                    self.stats['detected_stage2'] += 1
                    return {
                        'is_ransomware': True,
                        'confidence': stage2_result.get('confidence', 0.0),
                        'detection_stage': DetectionStage.DEEP_ANALYSIS.name,
                        'stage1_result': stage1_result,
                        'stage2_result': stage2_result
                    }
                else:
                    self.stats['cleared_stage2'] += 1
                    return {
                        'is_ransomware': False,
                        'confidence': 1.0 - stage2_result.get('confidence', 0.0),
                        'detection_stage': DetectionStage.DEEP_ANALYSIS.name,
                        'stage1_result': stage1_result,
                        'stage2_result': stage2_result
                    }
            else:
                # LLM disabled, use stage 1 result with lower confidence
                if stage1_result['confidence'] > 0.5:
                    self.stats['detected_stage2'] += 1
                    return {
                        'is_ransomware': True,
                        'confidence': stage1_result['confidence'],
                        'detection_stage': DetectionStage.INITIAL_SCREENING.name,
                        'detection_model': stage1_result.get('detection_model', 'combined'),
                        'stage1_result': stage1_result,
                        'stage2_result': None,
                        'note': 'LLM analysis disabled, using stage 1 result with lower confidence'
                    }
                else:
                    self.stats['cleared_stage2'] += 1
                    return {
                        'is_ransomware': False,
                        'confidence': 1.0 - stage1_result['confidence'],
                        'detection_stage': DetectionStage.INITIAL_SCREENING.name,
                        'stage1_result': stage1_result,
                        'stage2_result': None,
                        'note': 'LLM analysis disabled, using stage 1 result with lower confidence'
                    }
    
    def batch_detect(
        self, 
        sample_paths: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Detect ransomware in a batch of samples
        
        Args:
            sample_paths: Dictionary mapping sample IDs to sample data
                          Each sample data should have 'binary_path' and 'execution_logs' keys
            
        Returns:
            Dictionary mapping sample IDs to detection results
        """
        results = {}
        
        for sample_id, sample_data in sample_paths.items():
            binary_path = sample_data.get('binary_path', '')
            execution_logs = sample_data.get('execution_logs', [])
            
            # Detect ransomware
            result = self.detect(binary_path, execution_logs)
            
            # Add metadata
            result['sample_id'] = sample_id
            result['timestamp'] = datetime.now().isoformat()
            
            results[sample_id] = result
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get detection statistics
        
        Returns:
            Dictionary with detection statistics
        """
        stats = dict(self.stats)
        
        # Calculate averages
        if stats['processing_times']['stage1']:
            stats['avg_stage1_time'] = sum(stats['processing_times']['stage1']) / len(stats['processing_times']['stage1'])
        else:
            stats['avg_stage1_time'] = 0
        
        if stats['processing_times']['stage2']:
            stats['avg_stage2_time'] = sum(stats['processing_times']['stage2']) / len(stats['processing_times']['stage2'])
        else:
            stats['avg_stage2_time'] = 0
        
        # Calculate percentages
        if stats['samples_processed'] > 0:
            stats['percent_detected_stage1'] = (stats['detected_stage1'] / stats['samples_processed']) * 100
            stats['percent_cleared_stage1'] = (stats['cleared_stage1'] / stats['samples_processed']) * 100
            stats['percent_sent_to_stage2'] = (stats['sent_to_stage2'] / stats['samples_processed']) * 100
            
            if stats['sent_to_stage2'] > 0:
                stats['percent_detected_stage2'] = (stats['detected_stage2'] / stats['sent_to_stage2']) * 100
                stats['percent_cleared_stage2'] = (stats['cleared_stage2'] / stats['sent_to_stage2']) * 100
        
        return stats
    
    def train_stage1_models(
        self,
        training_data: Dict[str, Dict[str, Any]],
        validation_data: Optional[Dict[str, Dict[str, Any]]] = None,
        model_save_dir: str = './models',
        cnn_params: Optional[Dict[str, Any]] = None,
        lstm_params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Train stage 1 models (CNN and LSTM)
        
        Args:
            training_data: Dictionary mapping sample IDs to training data
                          Each sample data should have 'binary_path', 'execution_logs', and 'label' keys
            validation_data: Optional validation data in the same format as training_data
            model_save_dir: Directory to save trained models
            cnn_params: Parameters for CNN training
            lstm_params: Parameters for LSTM training
            
        Returns:
            Dictionary with training results
        """
        # Ensure save directory exists
        os.makedirs(model_save_dir, exist_ok=True)
        
        # Prepare data for CNN training
        cnn_binaries = []
        cnn_labels = []
        
        for sample_id, sample_data in training_data.items():
            binary_path = sample_data.get('binary_path', '')
            label = sample_data.get('label', 0)
            
            if binary_path and os.path.exists(binary_path):
                cnn_binaries.append(binary_path)
                cnn_labels.append(label)
        
        # Prepare data for LSTM training
        lstm_logs = {}
        
        for sample_id, sample_data in training_data.items():
            execution_logs = sample_data.get('execution_logs', [])
            
            if execution_logs:
                lstm_logs[sample_id] = execution_logs
        
        # Train CNN model
        cnn_result = None
        if self.cnn_model is not None and cnn_binaries:
            try:
                cnn_save_path = os.path.join(model_save_dir, 'binary_cnn_model.pt')
                cnn_result = self.cnn_model.train(
                    binary_paths=cnn_binaries,
                    labels=cnn_labels,
                    model_save_path=cnn_save_path,
                    **(cnn_params or {})
                )
            except Exception as e:
                logger.error(f"Error training CNN model: {str(e)}")
        
        # Train LSTM model
        lstm_result = None
        if self.lstm_model is not None and lstm_logs:
            try:
                lstm_result = self.lstm_model.train(
                    execution_logs=lstm_logs,
                    model_save_dir=os.path.join(model_save_dir, 'lstm'),
                    **(lstm_params or {})
                )
            except Exception as e:
                logger.error(f"Error training LSTM model: {str(e)}")
        
        return {
            'cnn_result': cnn_result,
            'lstm_result': lstm_result,
            'model_save_dir': model_save_dir
        }
    
    def evaluate(
        self,
        test_data: Dict[str, Dict[str, Any]],
        detailed: bool = False
    ) -> Dict[str, Any]:
        """
        Evaluate the detector on test data
        
        Args:
            test_data: Dictionary mapping sample IDs to test data
                       Each sample data should have 'binary_path', 'execution_logs', and 'label' keys
            detailed: Whether to include detailed analysis
            
        Returns:
            Dictionary with evaluation results
        """
        # Reset statistics
        old_stats = dict(self.stats)
        self.stats = {
            'samples_processed': 0,
            'detected_stage1': 0,
            'cleared_stage1': 0,
            'sent_to_stage2': 0,
            'detected_stage2': 0,
            'cleared_stage2': 0,
            'processing_times': {
                'stage1': [],
                'stage2': []
            }
        }
        
        # Run detection on test data
        y_true = []
        y_pred = []
        y_scores = []
        sample_results = {}
        
        for sample_id, sample_data in test_data.items():
            binary_path = sample_data.get('binary_path', '')
            execution_logs = sample_data.get('execution_logs', [])
            true_label = sample_data.get('label', 0)
            
            # Add true label
            y_true.append(true_label)
            
            # Detect ransomware
            result = self.detect(binary_path, execution_logs)
            
            # Add prediction
            pred_label = 1 if result['is_ransomware'] else 0
            y_pred.append(pred_label)
            
            # Add score
            score = result['confidence'] if result['is_ransomware'] else 1.0 - result['confidence']
            y_scores.append(score)
            
            # Add to sample results
            sample_results[sample_id] = result
        
        # Calculate metrics
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
        
        # Restore old statistics
        eval_stats = dict(self.stats)
        self.stats = old_stats
        
        metrics = {
            'accuracy': accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred, zero_division=0),
            'recall': recall_score(y_true, y_pred, zero_division=0),
            'f1': f1_score(y_true, y_pred, zero_division=0),
            'auc': roc_auc_score(y_true, y_scores) if len(set(y_true)) > 1 else 0.0,
            'classification_report': classification_report(y_true, y_pred, zero_division=0, output_dict=True)
        }
        
        # Detailed analysis
        if detailed:
            # Stage-wise performance
            stage1_samples = {}
            stage2_samples = {}
            
            for sample_id, result in sample_results.items():
                if result.get('detection_stage') == DetectionStage.INITIAL_SCREENING.name:
                    stage1_samples[sample_id] = test_data[sample_id]
                    stage1_samples[sample_id]['prediction'] = 1 if result['is_ransomware'] else 0
                else:
                    stage2_samples[sample_id] = test_data[sample_id]
                    stage2_samples[sample_id]['prediction'] = 1 if result['is_ransomware'] else 0
            
            # Calculate stage-wise metrics
            stage_metrics = {}
            
            if stage1_samples:
                stage1_true = [sample_data.get('label', 0) for sample_data in stage1_samples.values()]
                stage1_pred = [sample_data.get('prediction', 0) for sample_data in stage1_samples.values()]
                
                stage_metrics['stage1'] = {
                    'accuracy': accuracy_score(stage1_true, stage1_pred),
                    'precision': precision_score(stage1_true, stage1_pred, zero_division=0),
                    'recall': recall_score(stage1_true, stage1_pred, zero_division=0),
                    'f1': f1_score(stage1_true, stage1_pred, zero_division=0),
                    'samples': len(stage1_samples)
                }
            
            if stage2_samples:
                stage2_true = [sample_data.get('label', 0) for sample_data in stage2_samples.values()]
                stage2_pred = [sample_data.get('prediction', 0) for sample_data in stage2_samples.values()]
                
                stage_metrics['stage2'] = {
                    'accuracy': accuracy_score(stage2_true, stage2_pred),
                    'precision': precision_score(stage2_true, stage2_pred, zero_division=0),
                    'recall': recall_score(stage2_true, stage2_pred, zero_division=0),
                    'f1': f1_score(stage2_true, stage2_pred, zero_division=0),
                    'samples': len(stage2_samples)
                }
            
            metrics['stage_metrics'] = stage_metrics
        
        return {
            'metrics': metrics,
            'stats': eval_stats,
            'sample_results': sample_results if detailed else None
        }
    
    def save(self, directory: str) -> Dict[str, str]:
        """
        Save the detector state
        
        Args:
            directory: Directory to save state
            
        Returns:
            Dictionary with paths to saved components
        """
        # Ensure directory exists
        os.makedirs(directory, exist_ok=True)
        
        # Save CNN model
        cnn_path = None
        if self.cnn_model is not None:
            cnn_path = os.path.join(directory, 'binary_cnn_model.pt')
            try:
                self.cnn_model.save(cnn_path)
                logger.info(f"CNN model saved to {cnn_path}")
            except Exception as e:
                logger.error(f"Error saving CNN model: {str(e)}")
        
        # Save LSTM model
        lstm_model_path = None
        lstm_tokenizer_path = None
        if self.lstm_model is not None and hasattr(self.lstm_model, 'analyzer'):
            lstm_model_path = os.path.join(directory, 'lstm_model.pt')
            lstm_tokenizer_path = os.path.join(directory, 'lstm_tokenizer.pkl')
            try:
                self.lstm_model.analyzer.save(lstm_model_path, lstm_tokenizer_path)
                logger.info(f"LSTM model saved to {lstm_model_path}")
                logger.info(f"LSTM tokenizer saved to {lstm_tokenizer_path}")
            except Exception as e:
                logger.error(f"Error saving LSTM model: {str(e)}")
        
        # Save LLM configuration
        llm_config_path = None
        if self.llm_analyzer is not None:
            llm_config_path = os.path.join(directory, 'llm_config.json')
            try:
                with open(llm_config_path, 'w') as f:
                    json.dump(self.llm_analyzer.get_config(), f, indent=2)
                logger.info(f"LLM configuration saved to {llm_config_path}")
            except Exception as e:
                logger.error(f"Error saving LLM configuration: {str(e)}")
        
        # Save detector configuration
        config_path = os.path.join(directory, 'detector_config.json')
        try:
            with open(config_path, 'w') as f:
                json.dump({
                    'initial_threshold': self.initial_threshold,
                    'confirmation_threshold': self.confirmation_threshold,
                    'device': self.device,
                    'cache_dir': self.cache_dir,
                    'enable_llm': self.enable_llm,
                    'cnn_model_path': cnn_path,
                    'lstm_model_path': lstm_model_path,
                    'lstm_tokenizer_path': lstm_tokenizer_path,
                    'llm_config_path': llm_config_path
                }, f, indent=2)
            logger.info(f"Detector configuration saved to {config_path}")
        except Exception as e:
            logger.error(f"Error saving detector configuration: {str(e)}")
        
        # Save statistics
        stats_path = os.path.join(directory, 'detector_stats.json')
        try:
            with open(stats_path, 'w') as f:
                json.dump(self.get_statistics(), f, indent=2)
            logger.info(f"Detector statistics saved to {stats_path}")
        except Exception as e:
            logger.error(f"Error saving detector statistics: {str(e)}")
        
        return {
            'cnn_model_path': cnn_path,
            'lstm_model_path': lstm_model_path,
            'lstm_tokenizer_path': lstm_tokenizer_path,
            'llm_config_path': llm_config_path,
            'config_path': config_path,
            'stats_path': stats_path
        }
    
    @classmethod
    def load(cls, directory: str) -> 'TwoStageRansomwareDetector':
        """
        Load detector from saved state
        
        Args:
            directory: Directory containing saved state
            
        Returns:
            Loaded detector
        """
        # Load configuration
        config_path = os.path.join(directory, 'detector_config.json')
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
        except Exception as e:
            logger.error(f"Error loading detector configuration: {str(e)}")
            config = {}
        
        # Create detector
        detector = cls(
            cnn_model_path=config.get('cnn_model_path'),
            lstm_model_path=config.get('lstm_model_path'),
            lstm_tokenizer_path=config.get('lstm_tokenizer_path'),
            llm_config_path=config.get('llm_config_path'),
            initial_threshold=config.get('initial_threshold', 0.3),
            confirmation_threshold=config.get('confirmation_threshold', 0.7),
            device=config.get('device'),
            cache_dir=config.get('cache_dir', './model_cache'),
            enable_llm=config.get('enable_llm', True)
        )
        
        # Load statistics
        stats_path = os.path.join(directory, 'detector_stats.json')
        try:
            with open(stats_path, 'r') as f:
                stats = json.load(f)
            
            # Update statistics
            detector.stats.update({
                k: v for k, v in stats.items() 
                if k in detector.stats and k != 'processing_times'
            })
        except Exception as e:
            logger.error(f"Error loading detector statistics: {str(e)}")
        
        return detector