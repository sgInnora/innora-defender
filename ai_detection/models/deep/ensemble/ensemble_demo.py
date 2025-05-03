#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Demo script for the Model Ensemble Framework for ransomware detection.

This script demonstrates how to use the Model Ensemble Framework to combine
predictions from multiple ransomware detection models for improved accuracy
and robustness.
"""

import os
import sys
import json
import argparse
import logging
import tempfile
import time
import shutil
from typing import Dict, List, Any, Tuple, Optional

import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_curve, auc,
    precision_recall_curve, average_precision_score
)

# Adjust path to find modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from ai_detection.models.deep.ensemble.model_ensemble import ModelEnsemble, EnsembleMethod
from ai_detection.models.deep.two_stage.utils import (
    load_sample_data, split_dataset, visualize_results, generate_report
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


def create_demo_models(output_dir: str) -> List[Dict[str, Any]]:
    """
    Create demo models for ensemble
    
    Args:
        output_dir: Directory to save demo models
        
    Returns:
        List of model configurations for ensemble
    """
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Create model configs
    model_configs = []
    
    # CNN model
    cnn_dir = os.path.join(output_dir, 'cnn')
    os.makedirs(cnn_dir, exist_ok=True)
    
    try:
        # Import CNN detector
        from ai_detection.models.deep.cnn.binary_cnn_extractor import BinaryCNNExtractor
        
        # Create CNN model
        cnn_model = BinaryCNNExtractor(feature_dim=64)
        
        # Save model
        cnn_model_path = os.path.join(cnn_dir, 'binary_cnn_model.pt')
        cnn_model.save(cnn_model_path)
        
        # Add to configs
        model_configs.append({
            'id': 'cnn_model',
            'type': 'cnn',
            'model_path': cnn_model_path,
            'weight': 1.0
        })
        
        logger.info(f"Created CNN model at {cnn_model_path}")
    except Exception as e:
        logger.error(f"Error creating CNN model: {str(e)}")
    
    # LSTM model
    lstm_dir = os.path.join(output_dir, 'lstm')
    os.makedirs(lstm_dir, exist_ok=True)
    
    try:
        # Import LSTM detector
        from ai_detection.models.deep.lstm.integration import LSTMSequenceDetector
        
        # Create LSTM model
        lstm_model = LSTMSequenceDetector(
            batch_size=32,
            max_seq_length=200,
            embedding_dim=64,
            hidden_dim=128
        )
        
        # Save model
        lstm_model_path = os.path.join(lstm_dir, 'lstm_model.pt')
        lstm_tokenizer_path = os.path.join(lstm_dir, 'lstm_tokenizer.pkl')
        lstm_model.analyzer.save(lstm_model_path, lstm_tokenizer_path)
        
        # Add to configs
        model_configs.append({
            'id': 'lstm_model',
            'type': 'lstm',
            'model_path': lstm_model_path,
            'tokenizer_path': lstm_tokenizer_path,
            'weight': 1.0
        })
        
        logger.info(f"Created LSTM model at {lstm_model_path}")
    except Exception as e:
        logger.error(f"Error creating LSTM model: {str(e)}")
    
    # Transformer model
    transformer_dir = os.path.join(output_dir, 'transformer')
    os.makedirs(transformer_dir, exist_ok=True)
    
    try:
        # Import Transformer detector
        from ai_detection.models.deep.transformer.integration import TransformerRansomwareDetector
        
        # Create Transformer model
        transformer_model = TransformerRansomwareDetector(
            cnn_feature_dim=64,
            lstm_feature_dim=128,
            static_feature_dim=32,
            embed_dim=128,
            num_heads=8,
            ff_dim=256,
            num_layers=4,
            dropout=0.1,
            batch_size=32,
            use_sequences=False
        )
        
        # Save model
        transformer_model_path = os.path.join(transformer_dir, 'transformer_model.pt')
        transformer_model.save(transformer_model_path)
        
        # Add to configs
        model_configs.append({
            'id': 'transformer_model',
            'type': 'transformer',
            'model_path': transformer_model_path,
            'weight': 1.0,
            'model_params': {
                'cnn_feature_dim': 64,
                'lstm_feature_dim': 128,
                'static_feature_dim': 32,
                'use_sequences': False
            }
        })
        
        logger.info(f"Created Transformer model at {transformer_model_path}")
    except Exception as e:
        logger.error(f"Error creating Transformer model: {str(e)}")
    
    return model_configs


def create_mock_data(output_dir: str, num_samples: int = 20):
    """
    Create mock data for testing the ensemble framework
    
    Args:
        output_dir: Directory to save mock data
        num_samples: Number of mock samples to create
    """
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Create sample directories
    for i in range(num_samples // 2):
        # Create benign sample
        sample_id = f"benign_{i}"
        sample_dir = os.path.join(output_dir, sample_id)
        os.makedirs(sample_dir, exist_ok=True)
        
        # Create binary directory
        binary_dir = os.path.join(sample_dir, 'binary')
        os.makedirs(binary_dir, exist_ok=True)
        
        # Create mock binary file
        binary_path = os.path.join(binary_dir, f"{sample_id}.bin")
        with open(binary_path, 'wb') as f:
            f.write(os.urandom(1024))  # 1KB random data
        
        # Create execution logs directory
        logs_dir = os.path.join(sample_dir, 'execution_logs')
        os.makedirs(logs_dir, exist_ok=True)
        
        # Create mock execution log
        log_path = os.path.join(logs_dir, f"{sample_id}.json")
        
        # Generate benign API calls
        benign_apis = [
            "NtCreateFile", "NtReadFile", "NtWriteFile", "NtClose",
            "RegOpenKeyEx", "RegQueryValueEx", "RegCloseKey",
            "CreateProcessW", "GetSystemTime", "GetModuleHandle",
            "LoadLibrary", "GetProcAddress", "HeapAlloc", "HeapFree"
        ]
        
        # Generate log data
        num_calls = np.random.randint(30, 100)
        log_data = []
        
        for _ in range(num_calls):
            api_name = np.random.choice(benign_apis)
            log_data.append({"api_name": api_name})
        
        with open(log_path, 'w') as f:
            json.dump(log_data, f, indent=2)
    
    for i in range(num_samples // 2):
        # Create ransomware sample
        sample_id = f"ransomware_{i}"
        sample_dir = os.path.join(output_dir, sample_id)
        os.makedirs(sample_dir, exist_ok=True)
        
        # Create binary directory
        binary_dir = os.path.join(sample_dir, 'binary')
        os.makedirs(binary_dir, exist_ok=True)
        
        # Create mock binary file
        binary_path = os.path.join(binary_dir, f"{sample_id}.bin")
        with open(binary_path, 'wb') as f:
            f.write(os.urandom(1024))  # 1KB random data
        
        # Create execution logs directory
        logs_dir = os.path.join(sample_dir, 'execution_logs')
        os.makedirs(logs_dir, exist_ok=True)
        
        # Create mock execution log
        log_path = os.path.join(logs_dir, f"{sample_id}.json")
        
        # Generate ransomware API calls
        ransomware_apis = [
            "CryptEncrypt", "CryptDecrypt", "CryptCreateHash",
            "NtEnumerateKey", "RegSetValueEx", "DeleteFile",
            "GetFileAttributes", "SetFileAttributes", "GetVolumeInformation",
            "FindFirstFileEx", "FindNextFile", "CreateFileMapping",
            "SystemFunction036"  # RtlGenRandom
        ]
        
        benign_apis = [
            "NtCreateFile", "NtReadFile", "NtWriteFile", "NtClose",
            "RegOpenKeyEx", "RegQueryValueEx", "RegCloseKey"
        ]
        
        # Generate log data
        num_calls = np.random.randint(50, 150)
        log_data = []
        
        # Start with some benign calls
        for _ in range(num_calls // 3):
            api_name = np.random.choice(benign_apis)
            log_data.append({"api_name": api_name})
        
        # Add ransomware-specific calls
        for _ in range(num_calls // 3, num_calls):
            # 70% chance of ransomware API, 30% chance of benign API
            if np.random.random() < 0.7:
                api_name = np.random.choice(ransomware_apis)
            else:
                api_name = np.random.choice(benign_apis)
            
            log_data.append({"api_name": api_name})
        
        with open(log_path, 'w') as f:
            json.dump(log_data, f, indent=2)
    
    logger.info(f"Created {num_samples} mock samples in {output_dir}")


def plot_ensemble_comparison(
    methods: List[str],
    metrics: List[Dict[str, float]],
    output_path: Optional[str] = None
):
    """
    Plot comparison of ensemble methods
    
    Args:
        methods: List of ensemble method names
        metrics: List of metric dictionaries for each method
        output_path: Optional path to save the plot
    """
    # Extract metrics
    accuracies = [m.get('accuracy', 0.0) for m in metrics]
    precisions = [m.get('precision', 0.0) for m in metrics]
    recalls = [m.get('recall', 0.0) for m in metrics]
    f1_scores = [m.get('f1', 0.0) for m in metrics]
    
    # Create figure
    plt.figure(figsize=(12, 8))
    
    # Set width of bars
    bar_width = 0.2
    index = np.arange(len(methods))
    
    # Create bars
    plt.bar(index, accuracies, bar_width, label='Accuracy')
    plt.bar(index + bar_width, precisions, bar_width, label='Precision')
    plt.bar(index + 2 * bar_width, recalls, bar_width, label='Recall')
    plt.bar(index + 3 * bar_width, f1_scores, bar_width, label='F1 Score')
    
    # Set labels and title
    plt.xlabel('Ensemble Method')
    plt.ylabel('Metric Value')
    plt.title('Comparison of Ensemble Methods')
    plt.xticks(index + 1.5 * bar_width, methods)
    plt.legend()
    
    # Add values on top of bars
    for i, v in enumerate(accuracies):
        plt.text(i - 0.05, v + 0.02, f"{v:.2f}")
    for i, v in enumerate(precisions):
        plt.text(i + bar_width - 0.05, v + 0.02, f"{v:.2f}")
    for i, v in enumerate(recalls):
        plt.text(i + 2 * bar_width - 0.05, v + 0.02, f"{v:.2f}")
    for i, v in enumerate(f1_scores):
        plt.text(i + 3 * bar_width - 0.05, v + 0.02, f"{v:.2f}")
    
    plt.tight_layout()
    
    if output_path:
        plt.savefig(output_path)
        logger.info(f"Ensemble comparison plot saved to {output_path}")
    else:
        plt.show()


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Model Ensemble Framework Demo')
    
    parser.add_argument('--data_dir', type=str, help='Directory containing sample data')
    parser.add_argument('--output_dir', type=str, default='./ensemble_results', help='Output directory for results')
    parser.add_argument('--create_mock_data', action='store_true', help='Create mock data for testing')
    parser.add_argument('--num_samples', type=int, default=20, help='Number of mock samples to create')
    parser.add_argument('--create_demo_models', action='store_true', help='Create demo models for testing')
    parser.add_argument('--ensemble_method', type=str, choices=['majority_vote', 'weighted_average', 'stacking', 'feature_fusion'], 
                        default='weighted_average', help='Ensemble method to use')
    parser.add_argument('--confidence_threshold', type=float, default=0.5, help='Confidence threshold for classification')
    parser.add_argument('--compare_methods', action='store_true', help='Compare different ensemble methods')
    parser.add_argument('--save_ensemble', action='store_true', help='Save ensemble model')
    parser.add_argument('--load_ensemble', action='store_true', help='Load ensemble model')
    parser.add_argument('--ensemble_path', type=str, help='Path to save/load ensemble model')
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Create mock data if requested
    if args.create_mock_data:
        mock_data_dir = os.path.join(args.output_dir, 'mock_data')
        create_mock_data(mock_data_dir, args.num_samples)
        args.data_dir = mock_data_dir
    
    # Create demo models if requested
    model_configs = None
    if args.create_demo_models:
        logger.info("Creating demo models")
        model_configs = create_demo_models(os.path.join(args.output_dir, 'models'))
    
    # Ensure data directory is provided
    if not args.data_dir:
        logger.error("Data directory must be provided")
        return
    
    # Load sample data
    logger.info(f"Loading samples from {args.data_dir}")
    sample_data = load_sample_data(args.data_dir)
    
    if not sample_data:
        logger.error(f"No samples found in {args.data_dir}")
        return
    
    # Split dataset
    train_data, val_data, test_data = split_dataset(sample_data)
    
    # Compare different ensemble methods if requested
    if args.compare_methods:
        logger.info("Comparing different ensemble methods")
        
        # Methods to compare
        methods = [
            EnsembleMethod.MAJORITY_VOTE.value,
            EnsembleMethod.WEIGHTED_AVERAGE.value,
            EnsembleMethod.STACKING.value,
            EnsembleMethod.FEATURE_FUSION.value
        ]
        
        # Results for each method
        method_results = []
        method_metrics = []
        
        for method in methods:
            logger.info(f"Testing ensemble method: {method}")
            
            # Create ensemble
            ensemble = ModelEnsemble(
                model_configs=model_configs,
                method=method,
                confidence_threshold=args.confidence_threshold,
                cache_dir=os.path.join(args.output_dir, 'cache', method)
            )
            
            # Train ensemble if needed
            if method in [EnsembleMethod.STACKING.value, EnsembleMethod.FEATURE_FUSION.value]:
                # Convert train_data to list of samples
                train_samples = []
                train_labels = []
                
                for sample_id, sample_info in train_data.items():
                    sample = {
                        'binary_path': sample_info.get('binary_path', ''),
                        'execution_logs': sample_info.get('execution_logs', []),
                    }
                    
                    train_samples.append(sample)
                    train_labels.append(sample_info.get('label', 0))
                
                # Convert val_data to list of samples
                val_samples = []
                val_labels = []
                
                for sample_id, sample_info in val_data.items():
                    sample = {
                        'binary_path': sample_info.get('binary_path', ''),
                        'execution_logs': sample_info.get('execution_logs', []),
                    }
                    
                    val_samples.append(sample)
                    val_labels.append(sample_info.get('label', 0))
                
                # Train ensemble
                logger.info(f"Training ensemble with method: {method}")
                train_result = ensemble.train(
                    train_samples=train_samples,
                    train_labels=train_labels,
                    val_samples=val_samples,
                    val_labels=val_labels
                )
                
                logger.info(f"Training result: {train_result}")
            
            # Test on test data
            logger.info(f"Testing ensemble with method: {method}")
            
            # Predictions
            y_true = []
            y_pred = []
            
            for sample_id, sample_info in test_data.items():
                sample = {
                    'binary_path': sample_info.get('binary_path', ''),
                    'execution_logs': sample_info.get('execution_logs', []),
                }
                
                true_label = sample_info.get('label', 0)
                
                # Predict
                result = ensemble.predict(sample)
                
                # Add to lists
                y_true.append(true_label)
                y_pred.append(int(result['is_ransomware']))
            
            # Calculate metrics
            report = classification_report(y_true, y_pred, output_dict=True)
            
            metrics = {
                'accuracy': report['accuracy'],
                'precision': report['1']['precision'] if '1' in report else 0.0,
                'recall': report['1']['recall'] if '1' in report else 0.0,
                'f1': report['1']['f1-score'] if '1' in report else 0.0,
                'report': report
            }
            
            logger.info(f"Metrics for {method}: {metrics}")
            
            # Add to lists
            method_results.append({
                'method': method,
                'metrics': metrics
            })
            
            method_metrics.append(metrics)
        
        # Plot comparison
        plot_ensemble_comparison(
            methods=methods,
            metrics=method_metrics,
            output_path=os.path.join(args.output_dir, 'ensemble_comparison.png')
        )
        
        # Save results
        with open(os.path.join(args.output_dir, 'method_comparison.json'), 'w') as f:
            json.dump(method_results, f, indent=2)
    
    # Create ensemble with the specified method
    if args.load_ensemble and args.ensemble_path and os.path.exists(args.ensemble_path):
        # Load ensemble
        logger.info(f"Loading ensemble from {args.ensemble_path}")
        ensemble = ModelEnsemble.load(args.ensemble_path)
    else:
        # Create ensemble
        logger.info(f"Creating ensemble with method: {args.ensemble_method}")
        ensemble = ModelEnsemble(
            model_configs=model_configs,
            method=args.ensemble_method,
            confidence_threshold=args.confidence_threshold,
            cache_dir=os.path.join(args.output_dir, 'cache', args.ensemble_method)
        )
        
        # Train ensemble if needed
        if args.ensemble_method in [EnsembleMethod.STACKING.value, EnsembleMethod.FEATURE_FUSION.value]:
            # Convert train_data to list of samples
            train_samples = []
            train_labels = []
            
            for sample_id, sample_info in train_data.items():
                sample = {
                    'binary_path': sample_info.get('binary_path', ''),
                    'execution_logs': sample_info.get('execution_logs', []),
                }
                
                train_samples.append(sample)
                train_labels.append(sample_info.get('label', 0))
            
            # Convert val_data to list of samples
            val_samples = []
            val_labels = []
            
            for sample_id, sample_info in val_data.items():
                sample = {
                    'binary_path': sample_info.get('binary_path', ''),
                    'execution_logs': sample_info.get('execution_logs', []),
                }
                
                val_samples.append(sample)
                val_labels.append(sample_info.get('label', 0))
            
            # Train ensemble
            logger.info(f"Training ensemble with method: {args.ensemble_method}")
            train_result = ensemble.train(
                train_samples=train_samples,
                train_labels=train_labels,
                val_samples=val_samples,
                val_labels=val_labels
            )
            
            logger.info(f"Training result: {train_result}")
    
    # Test ensemble on test data
    logger.info("Testing ensemble on test data")
    
    # Predictions
    y_true = []
    y_pred = []
    
    for sample_id, sample_info in test_data.items():
        sample = {
            'binary_path': sample_info.get('binary_path', ''),
            'execution_logs': sample_info.get('execution_logs', []),
        }
        
        true_label = sample_info.get('label', 0)
        
        # Predict
        result = ensemble.predict(sample)
        
        # Add to lists
        y_true.append(true_label)
        y_pred.append(int(result['is_ransomware']))
    
    # Calculate metrics
    report = classification_report(y_true, y_pred, output_dict=True)
    
    metrics = {
        'accuracy': report['accuracy'],
        'precision': report['1']['precision'] if '1' in report else 0.0,
        'recall': report['1']['recall'] if '1' in report else 0.0,
        'f1': report['1']['f1-score'] if '1' in report else 0.0,
        'report': report
    }
    
    logger.info(f"Metrics: {metrics}")
    
    # Save results
    with open(os.path.join(args.output_dir, 'ensemble_results.json'), 'w') as f:
        json.dump({
            'method': args.ensemble_method,
            'metrics': metrics
        }, f, indent=2)
    
    # Save ensemble if requested
    if args.save_ensemble:
        ensemble_path = args.ensemble_path or os.path.join(args.output_dir, 'ensemble_model')
        logger.info(f"Saving ensemble to {ensemble_path}")
        ensemble.save(ensemble_path)
    
    logger.info("Demo completed")


if __name__ == "__main__":
    main()