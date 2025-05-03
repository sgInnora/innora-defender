#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Demo script for the Hybrid Transformer model for ransomware detection.

This script demonstrates how to use the Hybrid Transformer model to process
hybrid features from different sources (CNN, LSTM, static analysis) and
capture complex relationships for improved ransomware detection.
"""

import os
import sys
import json
import argparse
import logging
import tempfile
import time
import pickle
from typing import Dict, List, Any, Tuple, Optional

import numpy as np
import torch
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, confusion_matrix, roc_curve, auc
from sklearn.model_selection import train_test_split

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


def create_mock_data(
    num_samples: int = 100,
    cnn_feature_dim: int = 64,
    lstm_feature_dim: int = 64,
    static_feature_dim: int = 32,
    vocab_size: int = 1000,
    max_seq_len: int = 500,
    with_sequences: bool = True
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, Optional[List[List[int]]]]:
    """
    Create mock data for demonstration
    
    Args:
        num_samples: Number of samples to create
        cnn_feature_dim: Dimension of CNN features
        lstm_feature_dim: Dimension of LSTM features
        static_feature_dim: Dimension of static features
        vocab_size: Size of vocabulary for sequences
        max_seq_len: Maximum sequence length
        with_sequences: Whether to include sequence data
        
    Returns:
        Tuple of mock data (cnn_features, lstm_features, static_features, labels, sequences)
    """
    # Create features
    cnn_features = np.random.randn(num_samples, cnn_feature_dim)
    lstm_features = np.random.randn(num_samples, lstm_feature_dim)
    static_features = np.random.randn(num_samples, static_feature_dim)
    
    # Create labels (balanced)
    labels = np.zeros(num_samples)
    labels[:num_samples//2] = 1
    np.random.shuffle(labels)
    
    # Create sequences if requested
    if with_sequences:
        sequences = []
        
        for i in range(num_samples):
            # Generate random sequence length
            seq_len = np.random.randint(50, max_seq_len)
            
            # Generate sequence
            if labels[i] == 1:  # Ransomware
                # Include some "ransomware-like" patterns
                sequence = np.random.randint(1, vocab_size, size=seq_len).tolist()
                
                # Insert some specific tokens that might indicate ransomware
                ransomware_tokens = list(range(10, 20))
                for j in range(seq_len // 10):
                    idx = np.random.randint(0, seq_len)
                    sequence[idx] = np.random.choice(ransomware_tokens)
            else:  # Benign
                # Just random tokens
                sequence = np.random.randint(1, vocab_size, size=seq_len).tolist()
            
            sequences.append(sequence)
    else:
        sequences = None
    
    return cnn_features, lstm_features, static_features, labels, sequences


def plot_training_history(history: Dict[str, List[float]], output_path: Optional[str] = None):
    """
    Plot training history
    
    Args:
        history: Training history dictionary
        output_path: Optional path to save the plot
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


def plot_attention_heatmap(attention_matrix: np.ndarray, output_path: Optional[str] = None):
    """
    Plot attention heatmap
    
    Args:
        attention_matrix: Attention matrix
        output_path: Optional path to save the plot
    """
    plt.figure(figsize=(10, 8))
    plt.imshow(attention_matrix, cmap='viridis')
    plt.colorbar(label='Attention Weight')
    plt.title('Attention Heatmap')
    plt.xlabel('Token Index')
    plt.ylabel('Token Index')
    plt.tight_layout()
    
    if output_path:
        plt.savefig(output_path)
        logger.info(f"Attention heatmap saved to {output_path}")
    else:
        plt.show()


def plot_feature_attention(feature_attention: np.ndarray, output_path: Optional[str] = None):
    """
    Plot feature attention
    
    Args:
        feature_attention: Feature attention matrix of shape (3, seq_len)
        output_path: Optional path to save the plot
    """
    feature_types = ['CNN', 'LSTM', 'Static']
    seq_len = feature_attention.shape[1]
    
    plt.figure(figsize=(12, 6))
    
    for i, feature_type in enumerate(feature_types):
        plt.plot(range(seq_len), feature_attention[i], label=feature_type)
    
    plt.title('Feature Attention to Sequence Tokens')
    plt.xlabel('Token Index')
    plt.ylabel('Attention Weight')
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    
    if output_path:
        plt.savefig(output_path)
        logger.info(f"Feature attention plot saved to {output_path}")
    else:
        plt.show()


def plot_roc_curve(y_true: np.ndarray, y_pred: np.ndarray, output_path: Optional[str] = None):
    """
    Plot ROC curve
    
    Args:
        y_true: True labels
        y_pred: Predicted probabilities
        output_path: Optional path to save the plot
    """
    # Compute ROC curve and AUC
    fpr, tpr, _ = roc_curve(y_true, y_pred)
    roc_auc = auc(fpr, tpr)
    
    plt.figure(figsize=(10, 8))
    plt.plot(fpr, tpr, lw=2, label=f'ROC curve (AUC = {roc_auc:.3f})')
    plt.plot([0, 1], [0, 1], 'k--', lw=2)
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic')
    plt.legend(loc="lower right")
    plt.grid(True)
    
    if output_path:
        plt.savefig(output_path)
        logger.info(f"ROC curve saved to {output_path}")
    else:
        plt.show()


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Hybrid Transformer Model Demo')
    
    parser.add_argument('--cnn_feature_dim', type=int, default=64, help='Dimension of CNN features')
    parser.add_argument('--lstm_feature_dim', type=int, default=64, help='Dimension of LSTM features')
    parser.add_argument('--static_feature_dim', type=int, default=32, help='Dimension of static features')
    parser.add_argument('--embed_dim', type=int, default=128, help='Dimension of embedding')
    parser.add_argument('--num_heads', type=int, default=8, help='Number of attention heads')
    parser.add_argument('--ff_dim', type=int, default=256, help='Dimension of feed-forward layer')
    parser.add_argument('--num_layers', type=int, default=4, help='Number of transformer layers')
    parser.add_argument('--dropout', type=float, default=0.1, help='Dropout probability')
    parser.add_argument('--learning_rate', type=float, default=0.001, help='Learning rate')
    parser.add_argument('--weight_decay', type=float, default=1e-5, help='Weight decay')
    parser.add_argument('--batch_size', type=int, default=32, help='Batch size')
    parser.add_argument('--epochs', type=int, default=10, help='Number of epochs')
    parser.add_argument('--num_samples', type=int, default=500, help='Number of samples for mock data')
    parser.add_argument('--vocab_size', type=int, default=1000, help='Size of vocabulary for sequences')
    parser.add_argument('--max_seq_len', type=int, default=200, help='Maximum sequence length')
    parser.add_argument('--output_dir', type=str, default='./transformer_results', help='Output directory')
    parser.add_argument('--with_sequences', action='store_true', help='Include sequence data')
    parser.add_argument('--model_path', type=str, help='Path to pre-trained model')
    parser.add_argument('--no_cuda', action='store_true', help='Disable CUDA')
    
    args = parser.parse_args()
    
    # Determine device
    device = 'cpu' if args.no_cuda or not torch.cuda.is_available() else 'cuda'
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Create mock data
    logger.info("Creating mock data...")
    cnn_features, lstm_features, static_features, labels, sequences = create_mock_data(
        num_samples=args.num_samples,
        cnn_feature_dim=args.cnn_feature_dim,
        lstm_feature_dim=args.lstm_feature_dim,
        static_feature_dim=args.static_feature_dim,
        vocab_size=args.vocab_size,
        max_seq_len=args.max_seq_len,
        with_sequences=args.with_sequences
    )
    
    # Create sequence embedding if needed
    sequence_embedding = None
    if args.with_sequences:
        logger.info("Creating sequence embedding...")
        sequence_embedding = HybridTransformerAnalyzer.create_sequence_embedding(
            vocab_size=args.vocab_size,
            embed_dim=args.embed_dim,
            max_seq_len=args.max_seq_len,
            dropout=args.dropout,
            padding_idx=0
        )
    
    # Initialize transformer analyzer
    if args.model_path and os.path.exists(args.model_path):
        # Load pre-trained model
        logger.info(f"Loading pre-trained model from {args.model_path}...")
        analyzer = HybridTransformerAnalyzer(
            cnn_feature_dim=args.cnn_feature_dim,
            lstm_feature_dim=args.lstm_feature_dim,
            static_feature_dim=args.static_feature_dim,
            embed_dim=args.embed_dim,
            num_heads=args.num_heads,
            ff_dim=args.ff_dim,
            num_layers=args.num_layers,
            dropout=args.dropout,
            learning_rate=args.learning_rate,
            weight_decay=args.weight_decay,
            batch_size=args.batch_size,
            device=device,
            sequence_embedding=sequence_embedding
        )
        analyzer.load(args.model_path)
    else:
        # Create new model
        logger.info("Initializing new model...")
        analyzer = HybridTransformerAnalyzer(
            cnn_feature_dim=args.cnn_feature_dim,
            lstm_feature_dim=args.lstm_feature_dim,
            static_feature_dim=args.static_feature_dim,
            embed_dim=args.embed_dim,
            num_heads=args.num_heads,
            ff_dim=args.ff_dim,
            num_layers=args.num_layers,
            dropout=args.dropout,
            learning_rate=args.learning_rate,
            weight_decay=args.weight_decay,
            batch_size=args.batch_size,
            device=device,
            sequence_embedding=sequence_embedding
        )
    
    # Split data into train, validation, and test sets
    logger.info("Splitting data into train, validation, and test sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        np.arange(len(labels)), 
        labels, 
        test_size=0.2, 
        random_state=42, 
        stratify=labels
    )
    
    X_train, X_val, y_train, y_val = train_test_split(
        X_train, 
        y_train, 
        test_size=0.25, 
        random_state=42, 
        stratify=y_train
    )
    
    # Create datasets
    logger.info("Creating datasets...")
    train_cnn = [cnn_features[i] for i in X_train]
    train_lstm = [lstm_features[i] for i in X_train]
    train_static = [static_features[i] for i in X_train]
    train_labels = [labels[i] for i in X_train]
    
    val_cnn = [cnn_features[i] for i in X_val]
    val_lstm = [lstm_features[i] for i in X_val]
    val_static = [static_features[i] for i in X_val]
    val_labels = [labels[i] for i in X_val]
    
    test_cnn = [cnn_features[i] for i in X_test]
    test_lstm = [lstm_features[i] for i in X_test]
    test_static = [static_features[i] for i in X_test]
    test_labels = [labels[i] for i in X_test]
    
    if args.with_sequences:
        train_sequences = [sequences[i] for i in X_train]
        val_sequences = [sequences[i] for i in X_val]
        test_sequences = [sequences[i] for i in X_test]
    else:
        train_sequences = None
        val_sequences = None
        test_sequences = None
    
    # Create datasets
    train_dataset = HybridDataset(
        cnn_features=train_cnn,
        lstm_features=train_lstm,
        static_features=train_static,
        labels=train_labels,
        sequences=train_sequences,
        max_seq_len=args.max_seq_len
    )
    
    val_dataset = HybridDataset(
        cnn_features=val_cnn,
        lstm_features=val_lstm,
        static_features=val_static,
        labels=val_labels,
        sequences=val_sequences,
        max_seq_len=args.max_seq_len
    )
    
    test_dataset = HybridDataset(
        cnn_features=test_cnn,
        lstm_features=test_lstm,
        static_features=test_static,
        labels=test_labels,
        sequences=test_sequences,
        max_seq_len=args.max_seq_len
    )
    
    # Train model
    logger.info("Training model...")
    history = analyzer.train(
        train_dataset=train_dataset,
        val_dataset=val_dataset,
        epochs=args.epochs,
        patience=3,
        model_save_path=os.path.join(args.output_dir, 'hybrid_transformer_model.pt')
    )
    
    # Plot training history
    logger.info("Plotting training history...")
    plot_training_history(history, os.path.join(args.output_dir, 'training_history.png'))
    
    # Evaluate model
    logger.info("Evaluating model...")
    y_pred = analyzer.predict(test_dataset, return_probabilities=True)
    y_pred_binary = [1 if p >= 0.5 else 0 for p in y_pred]
    
    # Plot ROC curve
    logger.info("Plotting ROC curve...")
    plot_roc_curve(test_labels, y_pred, os.path.join(args.output_dir, 'roc_curve.png'))
    
    # Print evaluation metrics
    logger.info("Calculating evaluation metrics...")
    report = classification_report(test_labels, y_pred_binary, output_dict=True)
    
    logger.info(f"Accuracy: {report['accuracy']:.4f}")
    logger.info(f"Precision: {report['1']['precision']:.4f}")
    logger.info(f"Recall: {report['1']['recall']:.4f}")
    logger.info(f"F1 Score: {report['1']['f1-score']:.4f}")
    
    # Save evaluation metrics
    with open(os.path.join(args.output_dir, 'evaluation_metrics.json'), 'w') as f:
        json.dump(report, f, indent=2)
    
    # Extract features
    logger.info("Extracting features...")
    features = analyzer.extract_features(test_dataset)
    
    # Save features
    np.save(os.path.join(args.output_dir, 'transformer_features.npy'), features)
    
    # Analyze attention if sequence data is available
    if args.with_sequences:
        logger.info("Analyzing attention...")
        attention_results = analyzer.analyze_attention(test_dataset)
        
        if 'attention_analysis' in attention_results:
            # Plot attention for first sample
            if attention_results['attention_analysis']:
                sample = attention_results['attention_analysis'][0]
                
                # Plot feature attention
                feature_attention = np.array(sample['feature_attention'])
                plot_feature_attention(
                    feature_attention, 
                    os.path.join(args.output_dir, 'feature_attention.png')
                )
                
                # Plot sequence attention
                seq_attention = np.array(sample['seq_attention'])
                plot_attention_heatmap(
                    seq_attention, 
                    os.path.join(args.output_dir, 'seq_attention.png')
                )
                
                # Save attention results
                with open(os.path.join(args.output_dir, 'attention_analysis.json'), 'w') as f:
                    json.dump(attention_results, f, indent=2)
    
    logger.info(f"Results saved to {args.output_dir}")


if __name__ == "__main__":
    main()