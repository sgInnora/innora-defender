#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Demo script for the two-stage ransomware detection system.

This script demonstrates how to use the two-stage detection system for ransomware detection,
combining specialized deep learning models (CNN, LSTM) with large language models (LLMs).
"""

import os
import sys
import json
import argparse
import logging
import tempfile
import time
from typing import Dict, List, Any, Tuple, Optional

import numpy as np

# Adjust path to find modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from ai_detection.models.deep.two_stage.two_stage_detector import TwoStageRansomwareDetector
from ai_detection.models.deep.two_stage.utils import (
    load_sample_data, split_dataset, visualize_results, generate_report, compare_results
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


def create_mock_data(output_dir: str, num_samples: int = 20):
    """
    Create mock data for testing the two-stage detector
    
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


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Two-Stage Ransomware Detection System Demo')
    
    parser.add_argument('--data_dir', type=str, help='Directory containing sample data')
    parser.add_argument('--output_dir', type=str, default='./two_stage_results', help='Output directory for results')
    parser.add_argument('--create_mock_data', action='store_true', help='Create mock data for testing')
    parser.add_argument('--num_samples', type=int, default=20, help='Number of mock samples to create')
    parser.add_argument('--mode', type=str, choices=['train', 'eval', 'detect'], default='eval', help='Operation mode')
    parser.add_argument('--model_dir', type=str, help='Directory for saving/loading models')
    parser.add_argument('--train_ratio', type=float, default=0.7, help='Ratio of samples for training')
    parser.add_argument('--val_ratio', type=float, default=0.15, help='Ratio of samples for validation')
    parser.add_argument('--random_seed', type=int, default=42, help='Random seed for reproducibility')
    parser.add_argument('--initial_threshold', type=float, default=0.3, help='Initial threshold for stage 1')
    parser.add_argument('--confirmation_threshold', type=float, default=0.7, help='Confirmation threshold for stage 1')
    parser.add_argument('--enable_llm', action='store_true', help='Enable LLM analysis in stage 2')
    parser.add_argument('--api_key', type=str, help='API key for LLM service')
    parser.add_argument('--model_name', type=str, default='gpt-4o', help='LLM model name')
    parser.add_argument('--api_type', type=str, default='openai', help='LLM API type (openai, anthropic, custom)')
    parser.add_argument('--max_samples', type=int, help='Maximum number of samples to process')
    parser.add_argument('--generate_report', action='store_true', help='Generate detailed report')
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Create mock data if requested
    if args.create_mock_data:
        mock_data_dir = os.path.join(args.output_dir, 'mock_data')
        create_mock_data(mock_data_dir, args.num_samples)
        args.data_dir = mock_data_dir
    
    # Ensure data directory is provided
    if not args.data_dir:
        logger.error("Data directory must be provided")
        return
    
    # Use default model directory if not provided
    if not args.model_dir:
        args.model_dir = os.path.join(args.output_dir, 'models')
    
    # Create model directory
    os.makedirs(args.model_dir, exist_ok=True)
    
    # Paths for saved models
    cnn_model_path = os.path.join(args.model_dir, 'binary_cnn_model.pt')
    lstm_model_path = os.path.join(args.model_dir, 'lstm_model.pt')
    lstm_tokenizer_path = os.path.join(args.model_dir, 'lstm_tokenizer.pkl')
    llm_config_path = os.path.join(args.model_dir, 'llm_config.json')
    
    # Check if models exist
    models_exist = (
        os.path.exists(cnn_model_path) and
        os.path.exists(lstm_model_path) and
        os.path.exists(lstm_tokenizer_path)
    )
    
    # Load sample data
    logger.info(f"Loading samples from {args.data_dir}")
    sample_data = load_sample_data(
        args.data_dir, 
        max_samples=args.max_samples,
        require_logs=True,
        require_binary=True
    )
    
    if not sample_data:
        logger.error(f"No valid samples found in {args.data_dir}")
        return
    
    logger.info(f"Loaded {len(sample_data)} samples")
    
    # Split dataset for training and evaluation
    if args.mode in ['train', 'eval']:
        train_data, val_data, test_data = split_dataset(
            sample_data,
            train_ratio=args.train_ratio,
            val_ratio=args.val_ratio,
            random_seed=args.random_seed
        )
    
    # Initialize detector
    if args.mode == 'train' or not models_exist:
        # Create new detector
        logger.info("Initializing new detector")
        detector = TwoStageRansomwareDetector(
            initial_threshold=args.initial_threshold,
            confirmation_threshold=args.confirmation_threshold,
            enable_llm=args.enable_llm,
            cache_dir=os.path.join(args.output_dir, 'cache')
        )
    else:
        # Load existing detector
        logger.info(f"Loading detector from {args.model_dir}")
        detector = TwoStageRansomwareDetector(
            cnn_model_path=cnn_model_path if os.path.exists(cnn_model_path) else None,
            lstm_model_path=lstm_model_path if os.path.exists(lstm_model_path) else None,
            lstm_tokenizer_path=lstm_tokenizer_path if os.path.exists(lstm_tokenizer_path) else None,
            llm_config_path=llm_config_path if os.path.exists(llm_config_path) else None,
            initial_threshold=args.initial_threshold,
            confirmation_threshold=args.confirmation_threshold,
            enable_llm=args.enable_llm,
            cache_dir=os.path.join(args.output_dir, 'cache')
        )
    
    # Configure LLM analyzer if enabled
    if args.enable_llm and args.api_key and detector.llm_analyzer:
        detector.llm_analyzer.api_key = args.api_key
        detector.llm_analyzer.model_name = args.model_name
        detector.llm_analyzer.api_type = args.api_type
    
    # Perform operations based on mode
    if args.mode == 'train':
        logger.info("Training mode selected")
        
        # Train stage 1 models
        logger.info("Training stage 1 models")
        train_results = detector.train_stage1_models(
            training_data=train_data,
            validation_data=val_data,
            model_save_dir=args.model_dir
        )
        
        # Save results
        with open(os.path.join(args.output_dir, 'train_results.json'), 'w') as f:
            json.dump(train_results, f, indent=2)
        
        # Save detector
        logger.info(f"Saving detector to {args.model_dir}")
        detector.save(args.model_dir)
        
        # Optionally evaluate on test data
        logger.info("Evaluating on test data")
        eval_results = detector.evaluate(test_data, detailed=True)
        
        # Save evaluation results
        with open(os.path.join(args.output_dir, 'eval_results.json'), 'w') as f:
            json.dump(eval_results, f, indent=2)
        
        # Visualize results
        visualize_results(eval_results, args.output_dir)
        
        # Generate report if requested
        if args.generate_report:
            generate_report(eval_results, os.path.join(args.output_dir, 'evaluation_report.md'))
        
    elif args.mode == 'eval':
        logger.info("Evaluation mode selected")
        
        # Evaluate on test data
        logger.info("Evaluating on test data")
        eval_results = detector.evaluate(test_data, detailed=True)
        
        # Save evaluation results
        with open(os.path.join(args.output_dir, 'eval_results.json'), 'w') as f:
            json.dump(eval_results, f, indent=2)
        
        # Visualize results
        visualize_results(eval_results, args.output_dir)
        
        # Generate report if requested
        if args.generate_report:
            generate_report(eval_results, os.path.join(args.output_dir, 'evaluation_report.md'))
        
    elif args.mode == 'detect':
        logger.info("Detection mode selected")
        
        # Detect ransomware in all samples
        logger.info(f"Detecting ransomware in {len(sample_data)} samples")
        results = detector.batch_detect(sample_data)
        
        # Save detection results
        with open(os.path.join(args.output_dir, 'detection_results.json'), 'w') as f:
            json.dump(results, f, indent=2)
        
        # Count detected samples
        detected = sum(1 for result in results.values() if result.get('is_ransomware', False))
        logger.info(f"Detected {detected} ransomware samples out of {len(sample_data)}")
        
        # Print statistics
        stats = detector.get_statistics()
        logger.info(f"Detection statistics: {stats}")
    
    logger.info(f"Results saved to {args.output_dir}")


if __name__ == "__main__":
    main()