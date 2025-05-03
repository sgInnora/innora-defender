#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Demo script for the LSTM sequence analyzer.
Shows how to extract sequences, train the model, and make predictions.
"""

import os
import sys
import json
import argparse
import logging
from typing import List, Dict, Tuple

import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, confusion_matrix, roc_curve, auc
from sklearn.model_selection import train_test_split

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


def create_mock_sequence_data(output_dir: str, num_samples: int = 100):
    """
    Create mock sequence data for testing the analyzer.
    
    Args:
        output_dir: Directory to save mock data
        num_samples: Number of samples to generate
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # Define API calls for benign and ransomware samples
    benign_apis = [
        "NtCreateFile", "NtReadFile", "NtWriteFile", "NtClose",
        "RegOpenKeyEx", "RegQueryValueEx", "RegCloseKey",
        "CreateProcessW", "GetSystemTime", "GetModuleHandle",
        "LoadLibrary", "GetProcAddress", "HeapAlloc", "HeapFree"
    ]
    
    ransomware_apis = [
        "CryptEncrypt", "CryptDecrypt", "CryptCreateHash",
        "NtEnumerateKey", "RegSetValueEx", "DeleteFile",
        "GetFileAttributes", "SetFileAttributes", "GetVolumeInformation",
        "FindFirstFileEx", "FindNextFile", "CreateFileMapping",
        "SystemFunction036"  # RtlGenRandom
    ]
    
    # Create benign and ransomware samples
    benign_samples = []
    ransomware_samples = []
    
    for i in range(num_samples // 2):
        # Generate benign sequence
        benign_seq_length = np.random.randint(50, 200)
        benign_seq = np.random.choice(benign_apis, benign_seq_length).tolist()
        
        # Occasionally add a few ransomware APIs (but not too many)
        if np.random.random() < 0.1:
            positions = np.random.choice(
                range(benign_seq_length), 
                size=np.random.randint(1, 3), 
                replace=False
            )
            for pos in positions:
                benign_seq[pos] = np.random.choice(ransomware_apis)
        
        benign_samples.append(benign_seq)
        
        # Generate ransomware sequence
        ransomware_seq_length = np.random.randint(50, 200)
        
        # Start with some benign APIs
        ransomware_seq = np.random.choice(benign_apis, ransomware_seq_length // 2).tolist()
        
        # Add ransomware-specific APIs
        ransomware_specific = np.random.choice(
            ransomware_apis,
            ransomware_seq_length - (ransomware_seq_length // 2)
        ).tolist()
        
        # Mix them in
        positions = sorted(np.random.choice(
            range(ransomware_seq_length),
            size=len(ransomware_specific),
            replace=False
        ))
        
        for pos, api in zip(positions, ransomware_specific):
            ransomware_seq.insert(pos, api)
        
        ransomware_samples.append(ransomware_seq)
    
    # Save to files
    for i, seq in enumerate(benign_samples):
        log_data = [{"api_name": api} for api in seq]
        with open(os.path.join(output_dir, f"benign_{i}.json"), 'w') as f:
            json.dump(log_data, f, indent=2)
    
    for i, seq in enumerate(ransomware_samples):
        log_data = [{"api_name": api} for api in seq]
        with open(os.path.join(output_dir, f"ransomware_{i}.json"), 'w') as f:
            json.dump(log_data, f, indent=2)
    
    return len(benign_samples), len(ransomware_samples)


def get_sample_paths_and_labels(data_dir: str) -> Tuple[List[str], List[int]]:
    """
    Get sample paths and labels.
    
    Args:
        data_dir: Directory containing sample files
        
    Returns:
        Tuple of (sample paths, labels)
    """
    sample_paths = []
    labels = []
    
    # Check directory exists
    if not os.path.exists(data_dir):
        raise ValueError(f"Data directory {data_dir} does not exist")
    
    # Get all json files
    for filename in os.listdir(data_dir):
        if filename.endswith('.json'):
            file_path = os.path.join(data_dir, filename)
            sample_paths.append(file_path)
            
            # Set label based on filename
            if 'ransomware' in filename.lower():
                labels.append(1)
            else:
                labels.append(0)
    
    return sample_paths, labels


def plot_training_history(history: Dict[str, List[float]], output_path: str = None):
    """
    Plot training history
    
    Args:
        history: Training history dictionary
        output_path: Optional path to save plot
    """
    plt.figure(figsize=(12, 5))
    
    # Plot loss
    plt.subplot(1, 2, 1)
    plt.plot(history['train_loss'], label='Train Loss')
    if 'val_loss' in history and history['val_loss']:
        plt.plot(history['val_loss'], label='Validation Loss')
    plt.title('Loss')
    plt.xlabel('Epoch')
    plt.ylabel('Loss')
    plt.legend()
    plt.grid(True)
    
    # Plot accuracy
    plt.subplot(1, 2, 2)
    plt.plot(history['train_acc'], label='Train Accuracy')
    if 'val_acc' in history and history['val_acc']:
        plt.plot(history['val_acc'], label='Validation Accuracy')
    plt.title('Accuracy')
    plt.xlabel('Epoch')
    plt.ylabel('Accuracy')
    plt.legend()
    plt.grid(True)
    
    plt.tight_layout()
    
    if output_path:
        plt.savefig(output_path)
        logger.info(f"Training history plot saved to {output_path}")
    else:
        plt.show()


def plot_attention_weights(api_calls: List[str], weights: List[float], output_path: str = None):
    """
    Plot attention weights for a sequence
    
    Args:
        api_calls: List of API calls
        weights: List of attention weights
        output_path: Optional path to save plot
    """
    # Limit to top 50 for readability
    if len(api_calls) > 50:
        indices = np.argsort(weights)[-50:]
        api_calls = [api_calls[i] for i in indices]
        weights = [weights[i] for i in indices]
    
    plt.figure(figsize=(10, 8))
    y_pos = range(len(api_calls))
    
    # Sort by weight for better visualization
    sorted_data = sorted(zip(api_calls, weights), key=lambda x: x[1])
    api_calls = [x[0] for x in sorted_data]
    weights = [x[1] for x in sorted_data]
    
    plt.barh(y_pos, weights, align='center')
    plt.yticks(y_pos, api_calls)
    plt.xlabel('Attention Weight')
    plt.title('API Call Attention Weights')
    plt.tight_layout()
    
    if output_path:
        plt.savefig(output_path)
        logger.info(f"Attention weights plot saved to {output_path}")
    else:
        plt.show()


def plot_roc_curve(y_true: List[int], y_probs: List[float], output_path: str = None):
    """
    Plot ROC curve for predictions
    
    Args:
        y_true: True labels
        y_probs: Predicted probabilities
        output_path: Optional path to save plot
    """
    fpr, tpr, _ = roc_curve(y_true, y_probs)
    roc_auc = auc(fpr, tpr)
    
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, label=f'ROC curve (area = {roc_auc:.3f})')
    plt.plot([0, 1], [0, 1], 'k--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic')
    plt.legend(loc="lower right")
    plt.grid(True)
    
    if output_path:
        plt.savefig(output_path)
        logger.info(f"ROC curve plot saved to {output_path}")
    else:
        plt.show()


def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description='LSTM Sequence Analyzer Demo')
    parser.add_argument('--data_dir', type=str, help='Directory containing sample data')
    parser.add_argument('--output_dir', type=str, default='./lstm_demo_output',
                        help='Output directory for models and results')
    parser.add_argument('--generate_data', action='store_true',
                        help='Generate mock data for demo')
    parser.add_argument('--num_samples', type=int, default=100,
                        help='Number of mock samples to generate')
    parser.add_argument('--epochs', type=int, default=10,
                        help='Number of training epochs')
    parser.add_argument('--batch_size', type=int, default=16,
                        help='Batch size for training')
    parser.add_argument('--embedding_dim', type=int, default=64,
                        help='Embedding dimension')
    parser.add_argument('--hidden_dim', type=int, default=128,
                        help='LSTM hidden dimension')
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Generate mock data if requested
    if args.generate_data:
        logger.info(f"Generating {args.num_samples} mock samples...")
        data_dir = os.path.join(args.output_dir, 'mock_data')
        num_benign, num_ransomware = create_mock_sequence_data(data_dir, args.num_samples)
        logger.info(f"Generated {num_benign} benign and {num_ransomware} ransomware samples in {data_dir}")
        args.data_dir = data_dir
    
    # Ensure data directory is provided
    if not args.data_dir:
        logger.error("Data directory must be provided")
        return
    
    # Get sample paths and labels
    logger.info(f"Loading samples from {args.data_dir}...")
    sample_paths, labels = get_sample_paths_and_labels(args.data_dir)
    
    if not sample_paths:
        logger.error(f"No samples found in {args.data_dir}")
        return
    
    logger.info(f"Found {len(sample_paths)} samples ({sum(labels)} ransomware, {len(labels) - sum(labels)} benign)")
    
    # Split data
    train_paths, test_paths, train_labels, test_labels = train_test_split(
        sample_paths, labels, test_size=0.2, random_state=42, stratify=labels
    )
    
    logger.info(f"Training set: {len(train_paths)} samples")
    logger.info(f"Test set: {len(test_paths)} samples")
    
    # Initialize analyzer
    analyzer = SequenceLSTMAnalyzer(
        batch_size=args.batch_size,
        embedding_dim=args.embedding_dim,
        hidden_dim=args.hidden_dim
    )
    
    # Train model
    logger.info("Training LSTM model...")
    history = analyzer.train(
        train_log_paths=train_paths,
        train_labels=train_labels,
        val_log_paths=test_paths,
        val_labels=test_labels,
        epochs=args.epochs,
        model_save_path=os.path.join(args.output_dir, 'sequence_lstm_model.pt')
    )
    
    # Plot training history
    plot_training_history(
        history, 
        output_path=os.path.join(args.output_dir, 'training_history.png')
    )
    
    # Make predictions
    logger.info("Making predictions on test set...")
    test_probs = analyzer.predict(test_paths, return_probabilities=True)
    test_preds = [1 if p >= 0.5 else 0 for p in test_probs]
    
    # Plot ROC curve
    plot_roc_curve(
        test_labels, 
        test_probs,
        output_path=os.path.join(args.output_dir, 'roc_curve.png')
    )
    
    # Print classification report
    report = classification_report(test_labels, test_preds)
    logger.info(f"Classification Report:\n{report}")
    
    with open(os.path.join(args.output_dir, 'classification_report.txt'), 'w') as f:
        f.write(report)
    
    # Analyze attention weights for a ransomware sample
    ransomware_samples = [p for p, l in zip(test_paths, test_labels) if l == 1]
    if ransomware_samples:
        logger.info("Analyzing attention weights for a ransomware sample...")
        sample_path = ransomware_samples[0]
        api_calls, weights = analyzer.analyze_attention(sample_path)
        
        plot_attention_weights(
            api_calls, 
            weights,
            output_path=os.path.join(args.output_dir, 'attention_weights.png')
        )
    
    # Save model and tokenizer
    logger.info("Saving model and tokenizer...")
    analyzer.save(
        model_path=os.path.join(args.output_dir, 'sequence_lstm_model.pt'),
        tokenizer_path=os.path.join(args.output_dir, 'sequence_tokenizer.pkl')
    )
    
    logger.info(f"Demo completed. Results saved to {args.output_dir}")


if __name__ == "__main__":
    main()