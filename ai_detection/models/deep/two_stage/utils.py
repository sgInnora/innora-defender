#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Utility functions for the two-stage ransomware detection system.
"""

import os
import sys
import json
import logging
import pickle
import hashlib
from typing import Dict, List, Any, Tuple, Optional, Union
from datetime import datetime

import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import (
    roc_curve, precision_recall_curve, auc, 
    average_precision_score, confusion_matrix
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


def load_sample_data(
    sample_dir: str, 
    max_samples: Optional[int] = None, 
    require_logs: bool = True,
    require_binary: bool = True
) -> Dict[str, Dict[str, Any]]:
    """
    Load sample data from directory
    
    Args:
        sample_dir: Directory containing sample directories
        max_samples: Maximum number of samples to load
        require_logs: Whether to require execution logs
        require_binary: Whether to require binary file
        
    Returns:
        Dictionary mapping sample IDs to sample data
    """
    sample_data = {}
    
    # Get subdirectories (each representing a sample)
    try:
        subdirs = [d for d in os.listdir(sample_dir) if os.path.isdir(os.path.join(sample_dir, d))]
    except Exception as e:
        logger.error(f"Error listing directory {sample_dir}: {str(e)}")
        return {}
    
    # Process each sample
    for sample_id in subdirs:
        sample_path = os.path.join(sample_dir, sample_id)
        
        # Skip if max_samples reached
        if max_samples and len(sample_data) >= max_samples:
            break
        
        try:
            # Find binary file
            binary_path = ""
            binary_dir = os.path.join(sample_path, 'binary')
            if os.path.isdir(binary_dir):
                binary_files = [f for f in os.listdir(binary_dir) if os.path.isfile(os.path.join(binary_dir, f))]
                if binary_files:
                    binary_path = os.path.join(binary_dir, binary_files[0])
            
            # Skip if binary is required but not found
            if require_binary and not binary_path:
                continue
            
            # Find execution logs
            logs_dir = os.path.join(sample_path, 'execution_logs')
            execution_logs = []
            
            if os.path.isdir(logs_dir):
                log_files = [
                    os.path.join(logs_dir, f) 
                    for f in os.listdir(logs_dir) 
                    if f.endswith('.json') and os.path.isfile(os.path.join(logs_dir, f))
                ]
                execution_logs = log_files
            
            # Skip if logs are required but not found
            if require_logs and not execution_logs:
                continue
            
            # Determine label from sample_id
            label = 1 if 'ransomware' in sample_id.lower() else 0
            
            # Add to sample data
            sample_data[sample_id] = {
                'binary_path': binary_path,
                'execution_logs': execution_logs,
                'label': label
            }
            
        except Exception as e:
            logger.error(f"Error processing sample {sample_id}: {str(e)}")
    
    logger.info(f"Loaded {len(sample_data)} samples from {sample_dir}")
    return sample_data


def split_dataset(
    sample_data: Dict[str, Dict[str, Any]], 
    train_ratio: float = 0.7, 
    val_ratio: float = 0.15,
    random_seed: int = 42
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """
    Split dataset into train, validation, and test sets
    
    Args:
        sample_data: Dictionary mapping sample IDs to sample data
        train_ratio: Ratio of samples for training
        val_ratio: Ratio of samples for validation
        random_seed: Random seed for reproducibility
        
    Returns:
        Tuple of (train_data, val_data, test_data)
    """
    # Set random seed
    np.random.seed(random_seed)
    
    # Get sample IDs and labels
    sample_ids = list(sample_data.keys())
    labels = [sample_data[sample_id]['label'] for sample_id in sample_ids]
    
    # Get indices for each class
    positive_indices = [i for i, label in enumerate(labels) if label == 1]
    negative_indices = [i for i, label in enumerate(labels) if label == 0]
    
    # Shuffle indices
    np.random.shuffle(positive_indices)
    np.random.shuffle(negative_indices)
    
    # Calculate split sizes for each class
    n_pos_train = int(len(positive_indices) * train_ratio)
    n_pos_val = int(len(positive_indices) * val_ratio)
    n_neg_train = int(len(negative_indices) * train_ratio)
    n_neg_val = int(len(negative_indices) * val_ratio)
    
    # Split indices
    pos_train_indices = positive_indices[:n_pos_train]
    pos_val_indices = positive_indices[n_pos_train:n_pos_train + n_pos_val]
    pos_test_indices = positive_indices[n_pos_train + n_pos_val:]
    
    neg_train_indices = negative_indices[:n_neg_train]
    neg_val_indices = negative_indices[n_neg_train:n_neg_train + n_neg_val]
    neg_test_indices = negative_indices[n_neg_train + n_neg_val:]
    
    # Combine indices
    train_indices = pos_train_indices + neg_train_indices
    val_indices = pos_val_indices + neg_val_indices
    test_indices = pos_test_indices + neg_test_indices
    
    # Create split datasets
    train_data = {sample_ids[i]: sample_data[sample_ids[i]] for i in train_indices}
    val_data = {sample_ids[i]: sample_data[sample_ids[i]] for i in val_indices}
    test_data = {sample_ids[i]: sample_data[sample_ids[i]] for i in test_indices}
    
    # Log split sizes
    logger.info(f"Dataset split: {len(train_data)} train, {len(val_data)} validation, {len(test_data)} test")
    logger.info(f"Train set: {sum(sample_data[sample_ids[i]]['label'] for i in train_indices)} positive, "
                f"{len(train_indices) - sum(sample_data[sample_ids[i]]['label'] for i in train_indices)} negative")
    logger.info(f"Validation set: {sum(sample_data[sample_ids[i]]['label'] for i in val_indices)} positive, "
                f"{len(val_indices) - sum(sample_data[sample_ids[i]]['label'] for i in val_indices)} negative")
    logger.info(f"Test set: {sum(sample_data[sample_ids[i]]['label'] for i in test_indices)} positive, "
                f"{len(test_indices) - sum(sample_data[sample_ids[i]]['label'] for i in test_indices)} negative")
    
    return train_data, val_data, test_data


def visualize_results(
    eval_results: Dict[str, Any], 
    output_dir: str = './results',
    prefix: str = ''
):
    """
    Visualize evaluation results
    
    Args:
        eval_results: Evaluation results
        output_dir: Directory to save visualizations
        prefix: Prefix for filenames
    """
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Extract data
    metrics = eval_results.get('metrics', {})
    sample_results = eval_results.get('sample_results', {})
    
    if not sample_results:
        logger.warning("No sample results for visualization")
        return
    
    # Get true labels, predictions, and scores
    y_true = []
    y_pred = []
    y_scores = []
    
    for sample_id, result in sample_results.items():
        label = 1 if result.get('is_ransomware', False) else 0
        confidence = result.get('confidence', 0.0)
        
        sample_label = result.get('sample_id_label', None)
        if sample_label is None:
            # Try to infer from sample_id
            sample_label = 1 if 'ransomware' in sample_id.lower() else 0
        
        y_true.append(sample_label)
        y_pred.append(label)
        y_scores.append(confidence if label == 1 else 1.0 - confidence)
    
    # Plot ROC curve
    fpr, tpr, _ = roc_curve(y_true, y_scores)
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
    plt.savefig(os.path.join(output_dir, f'{prefix}roc_curve.png'))
    plt.close()
    
    # Plot precision-recall curve
    precision, recall, _ = precision_recall_curve(y_true, y_scores)
    avg_precision = average_precision_score(y_true, y_scores)
    
    plt.figure(figsize=(10, 8))
    plt.plot(recall, precision, lw=2, label=f'PR curve (AP = {avg_precision:.3f})')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curve')
    plt.legend(loc="lower left")
    plt.grid(True)
    plt.savefig(os.path.join(output_dir, f'{prefix}pr_curve.png'))
    plt.close()
    
    # Plot confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    
    plt.figure(figsize=(8, 6))
    plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    plt.title('Confusion Matrix')
    plt.colorbar()
    tick_marks = [0, 1]
    plt.xticks(tick_marks, ['Benign', 'Ransomware'])
    plt.yticks(tick_marks, ['Benign', 'Ransomware'])
    
    # Add text to cells
    for i in range(2):
        for j in range(2):
            plt.text(j, i, str(cm[i, j]), ha='center', va='center',
                     color='white' if cm[i, j] > cm.max() / 2 else 'black')
    
    plt.tight_layout()
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
    plt.savefig(os.path.join(output_dir, f'{prefix}confusion_matrix.png'))
    plt.close()
    
    # Plot stage distribution
    if 'stats' in eval_results:
        stats = eval_results['stats']
        
        # Create stage distribution pie chart
        stage_counts = {
            'Detected in Stage 1': stats.get('detected_stage1', 0),
            'Cleared in Stage 1': stats.get('cleared_stage1', 0),
            'Detected in Stage 2': stats.get('detected_stage2', 0),
            'Cleared in Stage 2': stats.get('cleared_stage2', 0)
        }
        
        labels = stage_counts.keys()
        sizes = stage_counts.values()
        
        # Only create chart if there's data
        if sum(sizes) > 0:
            plt.figure(figsize=(10, 8))
            plt.pie(sizes, labels=labels, autopct='%1.1f%%', shadow=True, startangle=140)
            plt.axis('equal')
            plt.title('Sample Distribution Across Detection Stages')
            plt.savefig(os.path.join(output_dir, f'{prefix}stage_distribution.png'))
            plt.close()
    
    # Save metrics
    metrics_path = os.path.join(output_dir, f'{prefix}metrics.json')
    with open(metrics_path, 'w') as f:
        json.dump(metrics, f, indent=2)
    
    logger.info(f"Visualization saved to {output_dir}")


def sample_hash(sample_path: str) -> str:
    """
    Compute hash for a sample file
    
    Args:
        sample_path: Path to sample file
        
    Returns:
        MD5 hash of the file
    """
    try:
        with open(sample_path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except Exception as e:
        logger.error(f"Error computing hash for {sample_path}: {str(e)}")
        return "unknown"


def extract_api_calls(log_path: str, max_calls: int = 100) -> List[str]:
    """
    Extract API calls from execution log
    
    Args:
        log_path: Path to execution log
        max_calls: Maximum number of API calls to extract
        
    Returns:
        List of API call strings
    """
    try:
        with open(log_path, 'r') as f:
            log_data = json.load(f)
        
        api_calls = []
        
        if isinstance(log_data, list):
            # Assuming a list of API call records
            for entry in log_data[:max_calls]:
                if "api_name" in entry:
                    api_calls.append(entry["api_name"])
        elif isinstance(log_data, dict) and "api_calls" in log_data:
            # Assuming a dict with an "api_calls" key
            for entry in log_data["api_calls"][:max_calls]:
                if "api_name" in entry:
                    api_calls.append(entry["api_name"])
        
        return api_calls
        
    except Exception as e:
        logger.error(f"Error extracting API calls from {log_path}: {str(e)}")
        return []


def save_stage_result(result: Dict[str, Any], output_dir: str, sample_id: str):
    """
    Save stage result to file
    
    Args:
        result: Stage result
        output_dir: Output directory
        sample_id: Sample ID
    """
    try:
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Save result
        result_path = os.path.join(output_dir, f"{sample_id}_result.json")
        with open(result_path, 'w') as f:
            json.dump(result, f, indent=2)
            
    except Exception as e:
        logger.error(f"Error saving stage result for {sample_id}: {str(e)}")


def generate_report(eval_results: Dict[str, Any], output_path: str):
    """
    Generate detailed report
    
    Args:
        eval_results: Evaluation results
        output_path: Path to save report
    """
    try:
        # Create report directory
        report_dir = os.path.dirname(output_path)
        os.makedirs(report_dir, exist_ok=True)
        
        # Extract data
        metrics = eval_results.get('metrics', {})
        stats = eval_results.get('stats', {})
        sample_results = eval_results.get('sample_results', {})
        
        # Generate report
        with open(output_path, 'w') as f:
            f.write("# Two-Stage Ransomware Detection System - Evaluation Report\n\n")
            f.write(f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Performance metrics
            f.write("## Performance Metrics\n\n")
            f.write(f"- Accuracy: {metrics.get('accuracy', 0.0):.4f}\n")
            f.write(f"- Precision: {metrics.get('precision', 0.0):.4f}\n")
            f.write(f"- Recall: {metrics.get('recall', 0.0):.4f}\n")
            f.write(f"- F1 Score: {metrics.get('f1', 0.0):.4f}\n")
            f.write(f"- AUC-ROC: {metrics.get('auc', 0.0):.4f}\n\n")
            
            # Stage metrics if available
            if 'stage_metrics' in metrics:
                stage_metrics = metrics['stage_metrics']
                
                if 'stage1' in stage_metrics:
                    s1 = stage_metrics['stage1']
                    f.write("### Stage 1 Performance\n\n")
                    f.write(f"- Samples: {s1.get('samples', 0)}\n")
                    f.write(f"- Accuracy: {s1.get('accuracy', 0.0):.4f}\n")
                    f.write(f"- Precision: {s1.get('precision', 0.0):.4f}\n")
                    f.write(f"- Recall: {s1.get('recall', 0.0):.4f}\n")
                    f.write(f"- F1 Score: {s1.get('f1', 0.0):.4f}\n\n")
                
                if 'stage2' in stage_metrics:
                    s2 = stage_metrics['stage2']
                    f.write("### Stage 2 Performance\n\n")
                    f.write(f"- Samples: {s2.get('samples', 0)}\n")
                    f.write(f"- Accuracy: {s2.get('accuracy', 0.0):.4f}\n")
                    f.write(f"- Precision: {s2.get('precision', 0.0):.4f}\n")
                    f.write(f"- Recall: {s2.get('recall', 0.0):.4f}\n")
                    f.write(f"- F1 Score: {s2.get('f1', 0.0):.4f}\n\n")
            
            # Statistics
            f.write("## Detection Statistics\n\n")
            f.write(f"- Total samples processed: {stats.get('samples_processed', 0)}\n")
            f.write(f"- Detected in Stage 1: {stats.get('detected_stage1', 0)} ({stats.get('percent_detected_stage1', 0.0):.1f}%)\n")
            f.write(f"- Cleared in Stage 1: {stats.get('cleared_stage1', 0)} ({stats.get('percent_cleared_stage1', 0.0):.1f}%)\n")
            f.write(f"- Sent to Stage 2: {stats.get('sent_to_stage2', 0)} ({stats.get('percent_sent_to_stage2', 0.0):.1f}%)\n")
            
            if stats.get('sent_to_stage2', 0) > 0:
                f.write(f"- Detected in Stage 2: {stats.get('detected_stage2', 0)} ({stats.get('percent_detected_stage2', 0.0):.1f}%)\n")
                f.write(f"- Cleared in Stage 2: {stats.get('cleared_stage2', 0)} ({stats.get('percent_cleared_stage2', 0.0):.1f}%)\n")
            
            f.write(f"\n- Average Stage 1 processing time: {stats.get('avg_stage1_time', 0.0):.3f} seconds\n")
            f.write(f"- Average Stage 2 processing time: {stats.get('avg_stage2_time', 0.0):.3f} seconds\n\n")
            
            # Errors and failures
            f.write("## Error Analysis\n\n")
            
            # Find false positives
            false_positives = []
            for sample_id, result in sample_results.items():
                sample_label = result.get('sample_id_label', None)
                if sample_label is None:
                    # Try to infer from sample_id
                    sample_label = 1 if 'ransomware' in sample_id.lower() else 0
                
                if sample_label == 0 and result.get('is_ransomware', False):
                    false_positives.append((sample_id, result))
            
            f.write(f"### False Positives: {len(false_positives)}\n\n")
            for sample_id, result in false_positives[:5]:  # Show top 5
                stage = result.get('detection_stage', 'Unknown')
                confidence = result.get('confidence', 0.0)
                model = result.get('detection_model', 'Unknown')
                
                f.write(f"- **{sample_id}**:\n")
                f.write(f"  - Detected in: {stage}\n")
                f.write(f"  - Confidence: {confidence:.4f}\n")
                f.write(f"  - Detection model: {model}\n\n")
            
            if len(false_positives) > 5:
                f.write(f"  ... and {len(false_positives) - 5} more\n\n")
            
            # Find false negatives
            false_negatives = []
            for sample_id, result in sample_results.items():
                sample_label = result.get('sample_id_label', None)
                if sample_label is None:
                    # Try to infer from sample_id
                    sample_label = 1 if 'ransomware' in sample_id.lower() else 0
                
                if sample_label == 1 and not result.get('is_ransomware', False):
                    false_negatives.append((sample_id, result))
            
            f.write(f"### False Negatives: {len(false_negatives)}\n\n")
            for sample_id, result in false_negatives[:5]:  # Show top 5
                stage = result.get('detection_stage', 'Unknown')
                confidence = result.get('confidence', 0.0)
                
                f.write(f"- **{sample_id}**:\n")
                f.write(f"  - Cleared in: {stage}\n")
                f.write(f"  - Confidence: {confidence:.4f}\n\n")
            
            if len(false_negatives) > 5:
                f.write(f"  ... and {len(false_negatives) - 5} more\n\n")
            
            # Conclusion and recommendations
            f.write("## Conclusion and Recommendations\n\n")
            
            # Basic conclusions based on metrics
            if metrics.get('accuracy', 0.0) > 0.9:
                f.write("The two-stage detection system is performing excellently with high accuracy.\n\n")
            elif metrics.get('accuracy', 0.0) > 0.8:
                f.write("The two-stage detection system is performing well but has room for improvement.\n\n")
            else:
                f.write("The two-stage detection system requires significant improvements.\n\n")
            
            # Recommendations based on stage statistics
            if stats.get('percent_sent_to_stage2', 0.0) > 50:
                f.write("- A large proportion of samples are being sent to Stage 2. Consider adjusting the initial_threshold to filter out more samples in Stage 1.\n")
            
            if stats.get('percent_detected_stage1', 0.0) < 30:
                f.write("- Stage 1 models may need retraining to improve detection rates.\n")
            
            if false_positives and len(false_positives) > len(sample_results) * 0.1:
                f.write("- High false positive rate suggests the need for more specific features or higher confirmation thresholds.\n")
            
            if false_negatives and len(false_negatives) > len(sample_results) * 0.1:
                f.write("- High false negative rate suggests the need for more sensitive detection or lower thresholds.\n")
            
        logger.info(f"Report saved to {output_path}")
            
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")


def load_results(results_path: str) -> Dict[str, Any]:
    """
    Load evaluation results from file
    
    Args:
        results_path: Path to results file
        
    Returns:
        Evaluation results
    """
    try:
        with open(results_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading results from {results_path}: {str(e)}")
        return {}


def compare_results(
    results1: Dict[str, Any], 
    results2: Dict[str, Any], 
    name1: str = "Results 1", 
    name2: str = "Results 2",
    output_path: str = None
) -> Dict[str, Any]:
    """
    Compare two sets of evaluation results
    
    Args:
        results1: First set of results
        results2: Second set of results
        name1: Name for first set
        name2: Name for second set
        output_path: Optional path to save comparison
        
    Returns:
        Comparison results
    """
    # Extract metrics
    metrics1 = results1.get('metrics', {})
    metrics2 = results2.get('metrics', {})
    
    # Metrics to compare
    metric_keys = ['accuracy', 'precision', 'recall', 'f1', 'auc']
    
    # Compute differences
    comparison = {
        'metric_comparison': {
            metric: {
                name1: metrics1.get(metric, 0.0),
                name2: metrics2.get(metric, 0.0),
                'diff': metrics2.get(metric, 0.0) - metrics1.get(metric, 0.0)
            }
            for metric in metric_keys
        }
    }
    
    # Compare stats
    stats1 = results1.get('stats', {})
    stats2 = results2.get('stats', {})
    
    stat_keys = [
        'samples_processed', 'detected_stage1', 'cleared_stage1', 
        'sent_to_stage2', 'detected_stage2', 'cleared_stage2',
        'avg_stage1_time', 'avg_stage2_time'
    ]
    
    comparison['stat_comparison'] = {
        stat: {
            name1: stats1.get(stat, 0),
            name2: stats2.get(stat, 0),
            'diff': stats2.get(stat, 0) - stats1.get(stat, 0) if isinstance(stats1.get(stat, 0), (int, float)) else 'N/A'
        }
        for stat in stat_keys if stat in stats1 or stat in stats2
    }
    
    # Compare sample results
    sample_results1 = results1.get('sample_results', {})
    sample_results2 = results2.get('sample_results', {})
    
    # Find samples in both sets
    common_samples = set(sample_results1.keys()) & set(sample_results2.keys())
    
    # Find disagreements
    disagreements = []
    
    for sample_id in common_samples:
        is_ransomware1 = sample_results1[sample_id].get('is_ransomware', False)
        is_ransomware2 = sample_results2[sample_id].get('is_ransomware', False)
        
        if is_ransomware1 != is_ransomware2:
            disagreements.append({
                'sample_id': sample_id,
                name1: {
                    'is_ransomware': is_ransomware1,
                    'confidence': sample_results1[sample_id].get('confidence', 0.0),
                    'detection_stage': sample_results1[sample_id].get('detection_stage', 'Unknown')
                },
                name2: {
                    'is_ransomware': is_ransomware2,
                    'confidence': sample_results2[sample_id].get('confidence', 0.0),
                    'detection_stage': sample_results2[sample_id].get('detection_stage', 'Unknown')
                }
            })
    
    comparison['disagreements'] = disagreements
    
    # Save comparison if requested
    if output_path:
        try:
            with open(output_path, 'w') as f:
                json.dump(comparison, f, indent=2)
            logger.info(f"Comparison saved to {output_path}")
        except Exception as e:
            logger.error(f"Error saving comparison to {output_path}: {str(e)}")
    
    return comparison