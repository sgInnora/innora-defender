#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Demo Script for Distributed Processing Architecture

This script demonstrates the functionality of the distributed processing
architecture using Apache Spark for ransomware detection. It processes a
batch of samples, extracts features, makes predictions, and evaluates results.
"""

import os
import sys
import json
import logging
import argparse
import time
from typing import Dict, List, Any, Optional
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import confusion_matrix, roc_curve, auc, precision_recall_curve

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import Spark processor
from spark_processor import (
    SparkProcessor, 
    create_feature_extractors, 
    simple_static_analyzer
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Demo for distributed ransomware detection using Spark"
    )
    
    parser.add_argument(
        "--sample-dir",
        dest="sample_dir",
        type=str,
        required=True,
        help="Directory containing ransomware and benign samples"
    )
    
    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        type=str,
        default="./output",
        help="Directory to store results"
    )
    
    parser.add_argument(
        "--max-samples",
        dest="max_samples",
        type=int,
        default=None,
        help="Maximum number of samples to process"
    )
    
    parser.add_argument(
        "--include-binary",
        dest="include_binary",
        action="store_true",
        help="Include binary content in DataFrame"
    )
    
    parser.add_argument(
        "--master",
        dest="master",
        type=str,
        default="local[*]",
        help="Spark master URL"
    )
    
    parser.add_argument(
        "--app-name",
        dest="app_name",
        type=str,
        default="RansomwareDetectionDemo",
        help="Spark application name"
    )
    
    parser.add_argument(
        "--ensemble-method",
        dest="ensemble_method",
        type=str,
        choices=["majority_vote", "weighted_average"],
        default="weighted_average",
        help="Ensemble method for combining model predictions"
    )
    
    parser.add_argument(
        "--visualize",
        dest="visualize",
        action="store_true",
        help="Generate visualization of results"
    )
    
    return parser.parse_args()


def mock_cnn_model(sample: Dict[str, Any]) -> Dict[str, Any]:
    """
    Mock CNN model for demonstration purposes
    
    Args:
        sample: Sample data with features
        
    Returns:
        Prediction results
    """
    # Get features
    features = sample.get('cnn_features', [])
    
    # Calculate score (simplified prediction logic)
    score = sum(features) / max(1, len(features))
    confidence = min(1.0, max(0.0, score))
    
    # Random noise to simulate model variance
    import random
    confidence = min(1.0, max(0.0, confidence + random.uniform(-0.1, 0.1)))
    
    return {
        'is_ransomware': confidence > 0.5,
        'confidence': confidence,
        'features': features
    }


def mock_lstm_model(sample: Dict[str, Any]) -> Dict[str, Any]:
    """
    Mock LSTM model for demonstration purposes
    
    Args:
        sample: Sample data with features
        
    Returns:
        Prediction results
    """
    # Get features
    features = sample.get('lstm_features', [])
    
    # Calculate score (simplified prediction logic)
    score = sum(features) / max(1, len(features))
    confidence = min(1.0, max(0.0, score))
    
    # Random noise to simulate model variance
    import random
    confidence = min(1.0, max(0.0, confidence + random.uniform(-0.15, 0.15)))
    
    return {
        'is_ransomware': confidence > 0.5,
        'confidence': confidence,
        'features': features
    }


def mock_transformer_model(sample: Dict[str, Any]) -> Dict[str, Any]:
    """
    Mock transformer model for demonstration purposes
    
    Args:
        sample: Sample data with features
        
    Returns:
        Prediction results
    """
    # Get all features
    cnn_features = sample.get('cnn_features', [])
    lstm_features = sample.get('lstm_features', [])
    static_features = sample.get('static_features', [])
    
    # Combine features
    all_features = []
    all_features.extend(cnn_features[:10])  # Use first 10 CNN features
    all_features.extend(lstm_features[:10])  # Use first 10 LSTM features
    all_features.extend(static_features[:10])  # Use first 10 static features
    
    # Calculate score (simplified prediction logic)
    score = sum(all_features) / max(1, len(all_features))
    confidence = min(1.0, max(0.0, score))
    
    # Random noise to simulate model variance
    import random
    confidence = min(1.0, max(0.0, confidence + random.uniform(-0.05, 0.05)))
    
    return {
        'is_ransomware': confidence > 0.5,
        'confidence': confidence,
        'features': all_features
    }


def mock_ensemble_model(sample: Dict[str, Any]) -> Dict[str, Any]:
    """
    Mock ensemble model for demonstration purposes
    
    Args:
        sample: Sample data with features
        
    Returns:
        Prediction results
    """
    # Get predictions from individual models
    cnn_pred = mock_cnn_model(sample)
    lstm_pred = mock_lstm_model(sample)
    transformer_pred = mock_transformer_model(sample)
    
    # Weighted average of confidence scores
    weights = {'cnn': 0.3, 'lstm': 0.3, 'transformer': 0.4}
    
    weighted_sum = (
        weights['cnn'] * cnn_pred['confidence'] + 
        weights['lstm'] * lstm_pred['confidence'] + 
        weights['transformer'] * transformer_pred['confidence']
    )
    
    confidence = weighted_sum / sum(weights.values())
    
    # Combine features
    features = []
    features.extend(cnn_pred['features'][:5])
    features.extend(lstm_pred['features'][:5])
    features.extend(transformer_pred['features'][:5])
    
    return {
        'is_ransomware': confidence > 0.5,
        'confidence': confidence,
        'features': features
    }


def visualize_results(metrics: Dict[str, Any], output_dir: str):
    """
    Visualize evaluation results
    
    Args:
        metrics: Evaluation metrics
        output_dir: Directory to save visualizations
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Plot confusion matrix
    cm = [
        [metrics['true_negatives'], metrics['false_positives']],
        [metrics['false_negatives'], metrics['true_positives']]
    ]
    
    plt.figure(figsize=(10, 8))
    plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    plt.title('Confusion Matrix')
    plt.colorbar()
    
    classes = ['Benign', 'Ransomware']
    tick_marks = np.arange(len(classes))
    plt.xticks(tick_marks, classes, rotation=45)
    plt.yticks(tick_marks, classes)
    
    # Add text annotations
    thresh = np.max(cm) / 2.0
    for i in range(len(cm)):
        for j in range(len(cm[i])):
            plt.text(j, i, format(cm[i][j], 'd'),
                    horizontalalignment="center",
                    color="white" if cm[i][j] > thresh else "black")
    
    plt.xlabel('Predicted label')
    plt.ylabel('True label')
    plt.tight_layout()
    
    # Save plot
    plt.savefig(os.path.join(output_dir, 'confusion_matrix.png'))
    
    # Plot metrics bar chart
    metrics_to_plot = ['accuracy', 'precision', 'recall', 'f1', 'auc']
    values = [metrics[m] for m in metrics_to_plot]
    
    plt.figure(figsize=(10, 6))
    plt.bar(metrics_to_plot, values, color='teal')
    plt.ylim(0, 1.0)
    plt.xlabel('Metric')
    plt.ylabel('Value')
    plt.title('Performance Metrics')
    
    # Add value labels
    for i, v in enumerate(values):
        plt.text(i, v + 0.02, f'{v:.2f}', ha='center')
    
    plt.tight_layout()
    
    # Save plot
    plt.savefig(os.path.join(output_dir, 'performance_metrics.png'))
    
    # Create a simple dashboard HTML
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Ransomware Detection Results</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            .header {{ background-color: #4CAF50; color: white; padding: 20px; }}
            .metrics {{ display: flex; flex-wrap: wrap; margin: 20px 0; }}
            .metric-card {{ 
                background-color: #f1f1f1; 
                border-radius: 5px; 
                padding: 15px; 
                margin: 10px; 
                flex: 1 0 200px;
                box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            }}
            .metric-value {{ 
                font-size: 24px; 
                font-weight: bold; 
                margin: 10px 0; 
                color: #2196F3;
            }}
            .images {{ display: flex; flex-wrap: wrap; }}
            .image-container {{ margin: 10px; flex: 1 0 45%; }}
            img {{ max-width: 100%; height: auto; border: 1px solid #ddd; }}
            h3 {{ color: #333; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Distributed Ransomware Detection Results</h1>
                <p>Analysis completed: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <h2>Performance Metrics</h2>
            <div class="metrics">
                <div class="metric-card">
                    <h3>Accuracy</h3>
                    <div class="metric-value">{metrics['accuracy']:.2f}</div>
                </div>
                <div class="metric-card">
                    <h3>Precision</h3>
                    <div class="metric-value">{metrics['precision']:.2f}</div>
                </div>
                <div class="metric-card">
                    <h3>Recall</h3>
                    <div class="metric-value">{metrics['recall']:.2f}</div>
                </div>
                <div class="metric-card">
                    <h3>F1 Score</h3>
                    <div class="metric-value">{metrics['f1']:.2f}</div>
                </div>
                <div class="metric-card">
                    <h3>AUC</h3>
                    <div class="metric-value">{metrics['auc']:.2f}</div>
                </div>
            </div>
            
            <h2>Sample Distribution</h2>
            <div class="metrics">
                <div class="metric-card">
                    <h3>Total Samples</h3>
                    <div class="metric-value">{metrics['samples']}</div>
                </div>
                <div class="metric-card">
                    <h3>Ransomware Samples</h3>
                    <div class="metric-value">{metrics['positive_samples']}</div>
                </div>
                <div class="metric-card">
                    <h3>Benign Samples</h3>
                    <div class="metric-value">{metrics['negative_samples']}</div>
                </div>
            </div>
            
            <h2>Results Visualization</h2>
            <div class="images">
                <div class="image-container">
                    <h3>Confusion Matrix</h3>
                    <img src="confusion_matrix.png" alt="Confusion Matrix">
                </div>
                <div class="image-container">
                    <h3>Performance Metrics</h3>
                    <img src="performance_metrics.png" alt="Performance Metrics">
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Save HTML
    with open(os.path.join(output_dir, 'dashboard.html'), 'w') as f:
        f.write(html_content)


def main():
    """Main function"""
    # Parse arguments
    args = parse_arguments()
    
    logger.info("Starting distributed ransomware detection demo")
    
    # Create Spark processor
    logger.info(f"Initializing Spark with master: {args.master}")
    processor = SparkProcessor(
        app_name=args.app_name,
        master=args.master
    )
    
    try:
        # Create feature extractors
        logger.info("Creating feature extractors")
        feature_extractors = create_feature_extractors(
            static_analyzer=simple_static_analyzer
        )
        
        # Define model function
        logger.info("Setting up ensemble model")
        model_func = mock_ensemble_model
        
        # Create output directory
        os.makedirs(args.output_dir, exist_ok=True)
        
        # Run pipeline
        logger.info(f"Running pipeline on samples from: {args.sample_dir}")
        start_time = time.time()
        results = processor.run_pipeline(
            sample_directory=args.sample_dir,
            model_func=model_func,
            feature_extractors=feature_extractors,
            output_directory=args.output_dir,
            max_samples=args.max_samples,
            include_binary=args.include_binary,
            save_format="json"
        )
        elapsed_time = time.time() - start_time
        
        # Print results
        logger.info(f"Pipeline completed in {elapsed_time:.2f} seconds")
        logger.info(f"Processed {results['samples_processed']} samples")
        logger.info(f"Accuracy: {results['metrics']['accuracy']:.4f}")
        logger.info(f"Precision: {results['metrics']['precision']:.4f}")
        logger.info(f"Recall: {results['metrics']['recall']:.4f}")
        logger.info(f"F1 Score: {results['metrics']['f1']:.4f}")
        logger.info(f"AUC: {results['metrics']['auc']:.4f}")
        
        # Visualize results if requested
        if args.visualize:
            logger.info("Generating visualizations")
            visualize_results(results['metrics'], args.output_dir)
            logger.info(f"Visualizations saved to {args.output_dir}")
        
        # Save detailed results
        with open(os.path.join(args.output_dir, 'demo_results.json'), 'w') as f:
            json.dump({
                'runtime': {
                    'elapsed_time': elapsed_time,
                    'samples_processed': results['samples_processed'],
                    'app_name': args.app_name,
                    'master': args.master,
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                },
                'metrics': results['metrics']
            }, f, indent=2)
        
        logger.info(f"Results saved to {args.output_dir}")
        
    finally:
        # Clean up
        logger.info("Cleaning up resources")
        processor.cleanup()
    
    logger.info("Demo completed successfully")


if __name__ == "__main__":
    main()