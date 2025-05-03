#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Utility functions for sequence analysis and integration with variant detection.
"""

import os
import json
import logging
import hashlib
from typing import Dict, List, Tuple, Any, Optional, Set

import numpy as np
from scipy.spatial.distance import cosine
from sklearn.cluster import DBSCAN, KMeans
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE

import torch

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


def extract_api_sequences_from_logs(log_paths: List[str], api_key: str = "api_name") -> List[List[str]]:
    """
    Extract API call sequences from execution logs
    
    Args:
        log_paths: List of paths to execution logs
        api_key: Key for API name in log entries
        
    Returns:
        List of API call sequences
    """
    sequences = []
    
    for log_path in log_paths:
        try:
            with open(log_path, 'r') as f:
                log_data = json.load(f)
            
            if isinstance(log_data, list):
                # Assuming a list of API call records
                sequence = [
                    entry[api_key] for entry in log_data if api_key in entry
                ]
            elif isinstance(log_data, dict) and "api_calls" in log_data:
                # Assuming a dict with an "api_calls" key
                sequence = [
                    entry[api_key] for entry in log_data["api_calls"] if api_key in entry
                ]
            else:
                logger.warning(f"Unsupported log format in {log_path}")
                sequence = []
                
            sequences.append(sequence)
            
        except Exception as e:
            logger.error(f"Error extracting sequence from {log_path}: {str(e)}")
            sequences.append([])
    
    return sequences


def compute_sequence_similarity(seq1: List[str], seq2: List[str]) -> float:
    """
    Compute similarity between two API call sequences using Jaccard similarity
    
    Args:
        seq1: First API call sequence
        seq2: Second API call sequence
        
    Returns:
        Similarity score (0 to 1)
    """
    set1 = set(seq1)
    set2 = set(seq2)
    
    if not set1 or not set2:
        return 0.0
    
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    
    return intersection / union if union > 0 else 0.0


def compute_ngram_similarity(seq1: List[str], seq2: List[str], n: int = 3) -> float:
    """
    Compute similarity between two API call sequences using n-gram similarity
    
    Args:
        seq1: First API call sequence
        seq2: Second API call sequence
        n: Size of n-grams
        
    Returns:
        Similarity score (0 to 1)
    """
    # Generate n-grams
    def get_ngrams(sequence, n):
        return [tuple(sequence[i:i+n]) for i in range(len(sequence) - n + 1)]
    
    if len(seq1) < n or len(seq2) < n:
        return compute_sequence_similarity(seq1, seq2)
    
    ngrams1 = set(get_ngrams(seq1, n))
    ngrams2 = set(get_ngrams(seq2, n))
    
    intersection = len(ngrams1.intersection(ngrams2))
    union = len(ngrams1.union(ngrams2))
    
    return intersection / union if union > 0 else 0.0


def identify_critical_sequences(sequences: List[List[str]], labels: List[int], k: int = 10) -> List[Tuple[List[str], float]]:
    """
    Identify critical API sequences that are indicative of ransomware behavior
    
    Args:
        sequences: List of API call sequences
        labels: Labels for sequences (1 for ransomware, 0 for benign)
        k: Number of critical sequences to return
        
    Returns:
        List of critical sequences with importance scores
    """
    # Count API sequences in ransomware and benign samples
    ransomware_seqs = [seq for seq, label in zip(sequences, labels) if label == 1]
    benign_seqs = [seq for seq, label in zip(sequences, labels) if label == 0]
    
    # Extract unique APIs in ransomware samples
    ransomware_apis = set()
    for seq in ransomware_seqs:
        ransomware_apis.update(seq)
    
    # Calculate importance score for each API
    api_importance = {}
    
    for api in ransomware_apis:
        # Count occurrences in ransomware samples
        ransomware_count = sum(1 for seq in ransomware_seqs if api in seq)
        ransomware_ratio = ransomware_count / len(ransomware_seqs) if ransomware_seqs else 0
        
        # Count occurrences in benign samples
        benign_count = sum(1 for seq in benign_seqs if api in seq)
        benign_ratio = benign_count / len(benign_seqs) if benign_seqs else 0
        
        # Importance score: ratio in ransomware - ratio in benign
        importance = ransomware_ratio - benign_ratio
        
        api_importance[api] = importance
    
    # Extract common API sequences (tuples of 2-3 consecutive APIs)
    ransomware_seqs_2gram = []
    ransomware_seqs_3gram = []
    
    for seq in ransomware_seqs:
        # 2-grams
        for i in range(len(seq) - 1):
            ransomware_seqs_2gram.append((seq[i], seq[i+1]))
        
        # 3-grams
        for i in range(len(seq) - 2):
            ransomware_seqs_3gram.append((seq[i], seq[i+1], seq[i+2]))
    
    # Count occurrences of each n-gram
    seq_2gram_counts = {}
    for seq in ransomware_seqs_2gram:
        seq_2gram_counts[seq] = seq_2gram_counts.get(seq, 0) + 1
    
    seq_3gram_counts = {}
    for seq in ransomware_seqs_3gram:
        seq_3gram_counts[seq] = seq_3gram_counts.get(seq, 0) + 1
    
    # Sort by count (descending)
    sorted_2grams = sorted(
        seq_2gram_counts.items(), 
        key=lambda x: x[1], 
        reverse=True
    )[:k//2]
    
    sorted_3grams = sorted(
        seq_3gram_counts.items(), 
        key=lambda x: x[1], 
        reverse=True
    )[:k//2]
    
    # Combine results
    critical_sequences = []
    
    # 2-grams
    for seq, count in sorted_2grams:
        seq_importance = sum(api_importance.get(api, 0) for api in seq)
        critical_sequences.append((list(seq), seq_importance))
    
    # 3-grams
    for seq, count in sorted_3grams:
        seq_importance = sum(api_importance.get(api, 0) for api in seq)
        critical_sequences.append((list(seq), seq_importance))
    
    # Sort by importance (descending)
    critical_sequences.sort(key=lambda x: x[1], reverse=True)
    
    return critical_sequences[:k]


def compute_feature_similarity(feature1: np.ndarray, feature2: np.ndarray) -> float:
    """
    Compute similarity between two feature vectors using cosine similarity
    
    Args:
        feature1: First feature vector
        feature2: Second feature vector
        
    Returns:
        Similarity score (0 to 1)
    """
    if feature1.shape != feature2.shape:
        raise ValueError(f"Feature shapes don't match: {feature1.shape} vs {feature2.shape}")
    
    # Cosine distance is in [0, 2], convert to similarity in [0, 1]
    distance = cosine(feature1, feature2)
    similarity = 1.0 - (distance / 2.0)
    
    return similarity


def cluster_samples_by_features(features: np.ndarray, eps: float = 0.3, min_samples: int = 5) -> Dict[str, Any]:
    """
    Cluster samples by their features using DBSCAN
    
    Args:
        features: Sample features
        eps: DBSCAN epsilon parameter
        min_samples: DBSCAN min_samples parameter
        
    Returns:
        Dictionary with clustering results
    """
    if len(features) < min_samples:
        return {
            'labels': np.zeros(len(features), dtype=int),
            'n_clusters': 1,
            'noise_points': 0
        }
    
    # Perform clustering
    clustering = DBSCAN(eps=eps, min_samples=min_samples).fit(features)
    labels = clustering.labels_
    
    # Number of clusters (excluding noise)
    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
    
    # Number of noise points
    n_noise = list(labels).count(-1)
    
    logger.info(f"Clustered {len(features)} samples into {n_clusters} clusters")
    logger.info(f"Identified {n_noise} noise points")
    
    # If DBSCAN doesn't find good clusters, try K-Means
    if n_clusters <= 1 and len(features) > 2:
        logger.info("DBSCAN clustering ineffective, trying K-Means")
        
        # Estimate number of clusters using silhouette score
        from sklearn.metrics import silhouette_score
        
        best_score = -1
        best_k = 2
        max_k = min(8, len(features) - 1)
        
        for k in range(2, max_k + 1):
            try:
                kmeans = KMeans(n_clusters=k, random_state=42)
                cluster_labels = kmeans.fit_predict(features)
                
                if len(set(cluster_labels)) > 1:  # Ensure we have at least 2 clusters
                    score = silhouette_score(features, cluster_labels)
                    
                    if score > best_score:
                        best_score = score
                        best_k = k
            except Exception as e:
                logger.error(f"Error in K-Means clustering with k={k}: {str(e)}")
        
        # Perform K-Means with best k
        kmeans = KMeans(n_clusters=best_k, random_state=42)
        labels = kmeans.fit_predict(features)
        n_clusters = best_k
        n_noise = 0
        
        logger.info(f"K-Means clustered samples into {n_clusters} clusters")
    
    return {
        'labels': labels,
        'n_clusters': n_clusters,
        'noise_points': n_noise
    }


def visualize_features(features: np.ndarray, labels: Optional[List[int]] = None) -> Dict[str, Any]:
    """
    Generate visualizations of sample features
    
    Args:
        features: Sample features
        labels: Optional labels for samples
        
    Returns:
        Dictionary with visualization data
    """
    if len(features) < 2:
        return {
            'pca': None,
            'tsne': None,
            'error': 'Not enough samples for visualization'
        }
    
    try:
        # PCA for dimensionality reduction to 2D
        pca = PCA(n_components=2)
        pca_result = pca.fit_transform(features)
        
        # t-SNE for non-linear dimensionality reduction to 2D
        tsne = TSNE(n_components=2, random_state=42)
        tsne_result = tsne.fit_transform(features)
        
        return {
            'pca': pca_result.tolist(),
            'tsne': tsne_result.tolist(),
            'labels': labels,
            'variance_explained': pca.explained_variance_ratio_.tolist()
        }
    
    except Exception as e:
        logger.error(f"Error generating visualizations: {str(e)}")
        return {
            'pca': None,
            'tsne': None,
            'error': str(e)
        }


def hash_sequence(sequence: List[str]) -> str:
    """
    Generate a hash for an API call sequence
    
    Args:
        sequence: API call sequence
        
    Returns:
        Hash string
    """
    # Join sequence with delimiter
    sequence_str = "|".join(sequence)
    
    # Generate hash
    return hashlib.md5(sequence_str.encode('utf-8')).hexdigest()


def extract_variant_signatures(sequences: List[List[str]], cluster_labels: List[int]) -> Dict[int, Any]:
    """
    Extract signature patterns for each variant cluster
    
    Args:
        sequences: List of API call sequences
        cluster_labels: Cluster labels for each sequence
        
    Returns:
        Dictionary mapping cluster IDs to signature patterns
    """
    # Get unique cluster labels
    unique_clusters = set(cluster_labels)
    
    # Initialize signatures
    signatures = {}
    
    for cluster_id in unique_clusters:
        if cluster_id == -1:  # Skip noise points
            continue
        
        # Get sequences in this cluster
        cluster_sequences = [
            seq for seq, label in zip(sequences, cluster_labels) if label == cluster_id
        ]
        
        if not cluster_sequences:
            continue
        
        # Find common APIs across sequences
        common_apis = set(cluster_sequences[0])
        for seq in cluster_sequences[1:]:
            common_apis.intersection_update(seq)
        
        # Find common API patterns (2-grams)
        common_patterns = []
        
        if len(cluster_sequences) > 1:
            # Extract all 2-grams from first sequence
            patterns = set()
            for i in range(len(cluster_sequences[0]) - 1):
                patterns.add((cluster_sequences[0][i], cluster_sequences[0][i+1]))
            
            # Intersect with patterns from other sequences
            for seq in cluster_sequences[1:]:
                seq_patterns = set()
                for i in range(len(seq) - 1):
                    seq_patterns.add((seq[i], seq[i+1]))
                
                patterns.intersection_update(seq_patterns)
            
            # Convert to list
            common_patterns = [list(pattern) for pattern in patterns]
        
        # Calculate API frequencies
        api_frequencies = {}
        
        for seq in cluster_sequences:
            for api in seq:
                api_frequencies[api] = api_frequencies.get(api, 0) + 1
        
        # Sort by frequency
        sorted_apis = sorted(
            api_frequencies.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        # Extract top APIs
        top_apis = [api for api, _ in sorted_apis[:20]]
        
        # Store signature
        signatures[cluster_id] = {
            'common_apis': list(common_apis),
            'common_patterns': common_patterns,
            'top_apis': top_apis,
            'sequence_count': len(cluster_sequences),
            'avg_sequence_length': np.mean([len(seq) for seq in cluster_sequences]),
            'hash': hash_sequence(top_apis[:10] if len(top_apis) >= 10 else top_apis)
        }
    
    return signatures


def variant_distance_matrix(signatures: Dict[int, Any]) -> Dict[str, Any]:
    """
    Compute distance matrix between variant signatures
    
    Args:
        signatures: Dictionary of variant signatures
        
    Returns:
        Dictionary with distance matrix and related data
    """
    # Extract signature keys
    variant_ids = list(signatures.keys())
    n_variants = len(variant_ids)
    
    if n_variants < 2:
        return {
            'distances': None,
            'variant_ids': variant_ids,
            'error': 'Need at least 2 variants to compute distances'
        }
    
    # Initialize distance matrix
    distances = np.zeros((n_variants, n_variants))
    
    # Compute pairwise distances
    for i in range(n_variants):
        id1 = variant_ids[i]
        for j in range(i+1, n_variants):
            id2 = variant_ids[j]
            
            # Get top APIs for each variant
            apis1 = set(signatures[id1]['top_apis'])
            apis2 = set(signatures[id2]['top_apis'])
            
            # Compute Jaccard distance
            intersection = len(apis1.intersection(apis2))
            union = len(apis1.union(apis2))
            
            distance = 1.0 - (intersection / union if union > 0 else 0.0)
            
            # Set symmetric distances
            distances[i, j] = distance
            distances[j, i] = distance
    
    return {
        'distances': distances.tolist(),
        'variant_ids': variant_ids
    }


def load_execution_logs(sample_dir: str, max_samples: int = None) -> Dict[str, List[str]]:
    """
    Load execution logs for samples
    
    Args:
        sample_dir: Directory containing sample directories
        max_samples: Maximum number of samples to load
        
    Returns:
        Dictionary mapping sample IDs to lists of execution log paths
    """
    execution_logs = {}
    
    # Iterate over subdirectories (each representing a sample)
    for sample_id in os.listdir(sample_dir):
        sample_path = os.path.join(sample_dir, sample_id)
        
        if not os.path.isdir(sample_path):
            continue
        
        # Check for execution logs directory
        logs_dir = os.path.join(sample_path, 'execution_logs')
        if not os.path.isdir(logs_dir):
            continue
        
        # Get log files
        log_files = [
            os.path.join(logs_dir, f) 
            for f in os.listdir(logs_dir) 
            if f.endswith('.json')
        ]
        
        if log_files:
            execution_logs[sample_id] = log_files
        
        # Check if we've reached max_samples
        if max_samples and len(execution_logs) >= max_samples:
            break
    
    return execution_logs


def get_common_apis(sequences: List[List[str]], min_occurrence: float = 0.5) -> Set[str]:
    """
    Get common APIs across multiple sequences
    
    Args:
        sequences: List of API call sequences
        min_occurrence: Minimum occurrence ratio (0 to 1)
        
    Returns:
        Set of common APIs
    """
    if not sequences:
        return set()
    
    # Count API occurrences
    api_counts = {}
    
    for seq in sequences:
        for api in set(seq):  # Count each API once per sequence
            api_counts[api] = api_counts.get(api, 0) + 1
    
    # Get common APIs
    min_count = min_occurrence * len(sequences)
    common_apis = {api for api, count in api_counts.items() if count >= min_count}
    
    return common_apis