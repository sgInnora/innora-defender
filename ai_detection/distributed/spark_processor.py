#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Distributed Processing Architecture for Ransomware Detection

This module implements a distributed processing architecture using Apache Spark
for large-scale ransomware sample analysis. It enables parallel processing of
samples across a cluster of machines, improving throughput and scalability.
"""

import os
import sys
import json
import logging
import pickle
import tempfile
import shutil
import time
from typing import Dict, List, Any, Tuple, Optional, Union, Callable
from datetime import datetime
import uuid

try:
    from pyspark import SparkContext, SparkConf
    from pyspark.sql import SparkSession
    from pyspark.ml import Pipeline
    from pyspark.ml.feature import VectorAssembler
    from pyspark.sql.types import StructType, StructField, StringType, BinaryType, ArrayType, FloatType, IntegerType
    from pyspark.sql.functions import udf, col, explode, struct, lit
except ImportError:
    logger = logging.getLogger(__name__)
    logger.error("PySpark is not installed. Please install it with 'pip install pyspark'")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


class SparkProcessor:
    """
    Distributed processor for ransomware detection using Apache Spark
    
    This class provides a scalable architecture for processing large numbers of
    samples in parallel across a cluster of machines.
    """
    
    def __init__(
        self,
        app_name: str = "RansomwareDetection",
        master: str = "local[*]",
        config: Optional[Dict[str, str]] = None,
        checkpoint_dir: Optional[str] = None,
        temp_dir: Optional[str] = None,
        log_level: str = "INFO"
    ):
        """
        Initialize Spark processor
        
        Args:
            app_name: Name of the Spark application
            master: Spark master URL
            config: Additional Spark configuration
            checkpoint_dir: Directory for checkpointing
            temp_dir: Temporary directory for intermediate files
            log_level: Logging level
        """
        self.app_name = app_name
        self.master = master
        self.config = config or {}
        
        # Create checkpoint directory if specified
        self.checkpoint_dir = checkpoint_dir
        if checkpoint_dir:
            os.makedirs(checkpoint_dir, exist_ok=True)
        
        # Create temporary directory
        self.temp_dir = temp_dir or tempfile.mkdtemp()
        os.makedirs(self.temp_dir, exist_ok=True)
        
        # Set log level
        self.log_level = log_level
        
        # Initialize Spark session
        self.spark = self._create_spark_session()
        
        # Register cleanup handler
        import atexit
        atexit.register(self.cleanup)
    
    def _create_spark_session(self) -> SparkSession:
        """
        Create Spark session
        
        Returns:
            Initialized Spark session
        """
        # Create SparkConf
        conf = SparkConf().setAppName(self.app_name).setMaster(self.master)
        
        # Add additional configuration
        for key, value in self.config.items():
            conf = conf.set(key, value)
        
        # Create SparkSession
        spark = SparkSession.builder \
            .config(conf=conf) \
            .getOrCreate()
        
        # Set log level
        spark.sparkContext.setLogLevel(self.log_level)
        
        # Set checkpoint directory if specified
        if self.checkpoint_dir:
            spark.sparkContext.setCheckpointDir(self.checkpoint_dir)
        
        return spark
    
    def cleanup(self):
        """Clean up resources"""
        # Stop Spark session
        if hasattr(self, 'spark') and self.spark:
            self.spark.stop()
        
        # Remove temporary directory
        if self.temp_dir and os.path.exists(self.temp_dir) and os.path.isdir(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def _prepare_sample_df_schema(self) -> StructType:
        """
        Prepare schema for sample DataFrame
        
        Returns:
            Spark schema for sample DataFrame
        """
        return StructType([
            StructField("sample_id", StringType(), False),
            StructField("binary_path", StringType(), True),
            StructField("binary_content", BinaryType(), True),
            StructField("execution_logs", ArrayType(StringType()), True),
            StructField("label", IntegerType(), True),
            StructField("metadata", StringType(), True)
        ])
    
    def _prepare_features_df_schema(self) -> StructType:
        """
        Prepare schema for features DataFrame
        
        Returns:
            Spark schema for features DataFrame
        """
        return StructType([
            StructField("sample_id", StringType(), False),
            StructField("cnn_features", ArrayType(FloatType()), True),
            StructField("lstm_features", ArrayType(FloatType()), True),
            StructField("static_features", ArrayType(FloatType()), True),
            StructField("label", IntegerType(), True)
        ])
    
    def _prepare_prediction_df_schema(self) -> StructType:
        """
        Prepare schema for prediction DataFrame
        
        Returns:
            Spark schema for prediction DataFrame
        """
        return StructType([
            StructField("sample_id", StringType(), False),
            StructField("is_ransomware", IntegerType(), True),
            StructField("confidence", FloatType(), True),
            StructField("model_name", StringType(), True),
            StructField("detection_time", FloatType(), True),
            StructField("features", ArrayType(FloatType()), True),
            StructField("metadata", StringType(), True)
        ])
    
    def load_samples_from_directory(
        self,
        directory: str,
        max_samples: Optional[int] = None,
        include_binary: bool = True
    ) -> Any:  # pyspark.sql.DataFrame
        """
        Load samples from directory into DataFrame
        
        Args:
            directory: Directory containing sample directories
            max_samples: Maximum number of samples to load
            include_binary: Whether to include binary content
            
        Returns:
            DataFrame with samples
        """
        # Get sample directories
        sample_dirs = []
        for item in os.listdir(directory):
            item_path = os.path.join(directory, item)
            if os.path.isdir(item_path):
                sample_dirs.append((item, item_path))
        
        # Limit number of samples if specified
        if max_samples and len(sample_dirs) > max_samples:
            sample_dirs = sample_dirs[:max_samples]
        
        # Create list of sample data
        samples = []
        for sample_id, sample_path in sample_dirs:
            try:
                # Get binary path
                binary_path = ""
                binary_content = None
                binary_dir = os.path.join(sample_path, 'binary')
                
                if os.path.isdir(binary_dir):
                    binary_files = [f for f in os.listdir(binary_dir) if os.path.isfile(os.path.join(binary_dir, f))]
                    if binary_files:
                        binary_path = os.path.join(binary_dir, binary_files[0])
                        
                        if include_binary and os.path.exists(binary_path):
                            with open(binary_path, 'rb') as f:
                                binary_content = f.read()
                
                # Get execution logs
                execution_logs = []
                logs_dir = os.path.join(sample_path, 'execution_logs')
                
                if os.path.isdir(logs_dir):
                    log_files = [
                        os.path.join(logs_dir, f) 
                        for f in os.listdir(logs_dir) 
                        if f.endswith('.json') and os.path.isfile(os.path.join(logs_dir, f))
                    ]
                    execution_logs = log_files
                
                # Determine label from sample_id
                label = 1 if 'ransomware' in sample_id.lower() else 0
                
                # Add sample
                samples.append({
                    "sample_id": sample_id,
                    "binary_path": binary_path,
                    "binary_content": binary_content,
                    "execution_logs": execution_logs,
                    "label": label,
                    "metadata": json.dumps({
                        "original_path": sample_path,
                        "timestamp": datetime.now().isoformat()
                    })
                })
                
            except Exception as e:
                logger.error(f"Error loading sample {sample_id}: {str(e)}")
        
        # Create DataFrame
        schema = self._prepare_sample_df_schema()
        df = self.spark.createDataFrame(samples, schema)
        
        logger.info(f"Loaded {df.count()} samples into DataFrame")
        return df
    
    def extract_features(
        self,
        sample_df: Any,  # pyspark.sql.DataFrame
        feature_extractors: Dict[str, Callable],
        cnn_feature_dim: int = 64,
        lstm_feature_dim: int = 128,
        static_feature_dim: int = 32
    ) -> Any:  # pyspark.sql.DataFrame
        """
        Extract features from samples
        
        Args:
            sample_df: DataFrame with samples
            feature_extractors: Dictionary mapping feature types to extractor functions
            cnn_feature_dim: Dimension of CNN features
            lstm_feature_dim: Dimension of LSTM features
            static_feature_dim: Dimension of static features
            
        Returns:
            DataFrame with extracted features
        """
        # Define UDFs for feature extraction
        def extract_cnn_features_udf(binary_path, binary_content):
            try:
                # Use binary content if available
                if binary_content is not None:
                    # Save to temporary file
                    with tempfile.NamedTemporaryFile(delete=False) as tmp:
                        tmp.write(binary_content)
                        tmp_path = tmp.name
                    
                    try:
                        # Extract features
                        features = feature_extractors.get('cnn')(tmp_path)
                        
                        # Remove temporary file
                        os.unlink(tmp_path)
                        
                        return features
                    except Exception as e:
                        # Remove temporary file
                        os.unlink(tmp_path)
                        raise e
                
                # Use binary path if content not available
                elif binary_path and os.path.exists(binary_path):
                    return feature_extractors.get('cnn')(binary_path)
                
                # Return zeros if no binary available
                return [0.0] * cnn_feature_dim
                
            except Exception as e:
                logger.error(f"Error extracting CNN features: {str(e)}")
                return [0.0] * cnn_feature_dim
        
        def extract_lstm_features_udf(execution_logs):
            try:
                if execution_logs and len(execution_logs) > 0:
                    return feature_extractors.get('lstm')(execution_logs)
                
                # Return zeros if no logs available
                return [0.0] * lstm_feature_dim
                
            except Exception as e:
                logger.error(f"Error extracting LSTM features: {str(e)}")
                return [0.0] * lstm_feature_dim
        
        def extract_static_features_udf(binary_path, binary_content):
            try:
                # Use binary content if available
                if binary_content is not None:
                    # Save to temporary file
                    with tempfile.NamedTemporaryFile(delete=False) as tmp:
                        tmp.write(binary_content)
                        tmp_path = tmp.name
                    
                    try:
                        # Extract features
                        features = feature_extractors.get('static')(tmp_path)
                        
                        # Remove temporary file
                        os.unlink(tmp_path)
                        
                        return features
                    except Exception as e:
                        # Remove temporary file
                        os.unlink(tmp_path)
                        raise e
                
                # Use binary path if content not available
                elif binary_path and os.path.exists(binary_path):
                    return feature_extractors.get('static')(binary_path)
                
                # Return zeros if no binary available
                return [0.0] * static_feature_dim
                
            except Exception as e:
                logger.error(f"Error extracting static features: {str(e)}")
                return [0.0] * static_feature_dim
        
        # Register UDFs
        cnn_udf = udf(extract_cnn_features_udf, ArrayType(FloatType()))
        lstm_udf = udf(extract_lstm_features_udf, ArrayType(FloatType()))
        static_udf = udf(extract_static_features_udf, ArrayType(FloatType()))
        
        # Extract features
        features_df = sample_df.select(
            col("sample_id"),
            cnn_udf(col("binary_path"), col("binary_content")).alias("cnn_features"),
            lstm_udf(col("execution_logs")).alias("lstm_features"),
            static_udf(col("binary_path"), col("binary_content")).alias("static_features"),
            col("label")
        )
        
        logger.info(f"Extracted features for {features_df.count()} samples")
        return features_df
    
    def predict_with_model(
        self,
        features_df: Any,  # pyspark.sql.DataFrame
        model_func: Callable,
        model_name: str
    ) -> Any:  # pyspark.sql.DataFrame
        """
        Make predictions using a model
        
        Args:
            features_df: DataFrame with features
            model_func: Function that takes features and returns predictions
            model_name: Name of the model
            
        Returns:
            DataFrame with predictions
        """
        # Define UDF for prediction
        def predict_udf(sample_id, cnn_features, lstm_features, static_features, label):
            try:
                # Start timer
                start_time = time.time()
                
                # Prepare sample data
                sample = {
                    'sample_id': sample_id,
                    'cnn_features': cnn_features,
                    'lstm_features': lstm_features,
                    'static_features': static_features
                }
                
                # Make prediction
                result = model_func(sample)
                
                # Calculate detection time
                detection_time = time.time() - start_time
                
                # Get features
                features = result.get('features', [])
                if not isinstance(features, list):
                    features = []
                
                # Return prediction
                return {
                    'sample_id': sample_id,
                    'is_ransomware': 1 if result.get('is_ransomware', False) else 0,
                    'confidence': float(result.get('confidence', 0.0)),
                    'model_name': model_name,
                    'detection_time': float(detection_time),
                    'features': features,
                    'metadata': json.dumps({
                        'true_label': label,
                        'timestamp': datetime.now().isoformat()
                    })
                }
                
            except Exception as e:
                logger.error(f"Error making prediction for {sample_id}: {str(e)}")
                return {
                    'sample_id': sample_id,
                    'is_ransomware': 0,
                    'confidence': 0.0,
                    'model_name': model_name,
                    'detection_time': 0.0,
                    'features': [],
                    'metadata': json.dumps({
                        'error': str(e),
                        'true_label': label,
                        'timestamp': datetime.now().isoformat()
                    })
                }
        
        # Register UDF
        prediction_schema = self._prepare_prediction_df_schema()
        predict_udf = udf(predict_udf, prediction_schema)
        
        # Make predictions
        predictions_df = features_df.select(
            predict_udf(
                col("sample_id"),
                col("cnn_features"),
                col("lstm_features"),
                col("static_features"),
                col("label")
            ).alias("prediction")
        ).select("prediction.*")
        
        logger.info(f"Made predictions for {predictions_df.count()} samples using {model_name}")
        return predictions_df
    
    def ensemble_predictions(
        self,
        predictions_df: Any,  # pyspark.sql.DataFrame
        method: str = "weighted_average",
        weights: Optional[Dict[str, float]] = None
    ) -> Any:  # pyspark.sql.DataFrame
        """
        Combine predictions from multiple models
        
        Args:
            predictions_df: DataFrame with predictions
            method: Ensemble method ('majority_vote', 'weighted_average')
            weights: Optional dictionary mapping model names to weights
            
        Returns:
            DataFrame with ensemble predictions
        """
        # Prepare weights
        if weights is None:
            # Group by model name and count
            model_counts = predictions_df.groupBy("model_name").count().collect()
            
            # Use equal weights
            total_models = len(model_counts)
            weights = {row["model_name"]: 1.0 / total_models for row in model_counts}
        
        # Register UDF for ensemble
        def ensemble_udf(predictions):
            try:
                if method == "majority_vote":
                    # Count votes
                    votes = sum(p["is_ransomware"] for p in predictions)
                    total = len(predictions)
                    
                    # Determine majority
                    is_ransomware = votes > total / 2
                    
                    # Calculate confidence
                    confidence = votes / total if is_ransomware else (total - votes) / total
                    
                elif method == "weighted_average":
                    # Calculate weighted average
                    weighted_sum = 0.0
                    total_weight = 0.0
                    
                    for p in predictions:
                        model_name = p["model_name"]
                        weight = weights.get(model_name, 1.0)
                        
                        # Add to weighted sum
                        weighted_sum += weight * (p["confidence"] if p["is_ransomware"] == 1 else 1.0 - p["confidence"])
                        total_weight += weight
                    
                    # Calculate confidence
                    confidence = weighted_sum / total_weight if total_weight > 0 else 0.0
                    
                    # Determine classification
                    is_ransomware = confidence >= 0.5
                    
                else:
                    # Default to majority vote
                    return ensemble_udf(predictions)
                
                return {
                    'is_ransomware': 1 if is_ransomware else 0,
                    'confidence': float(confidence)
                }
                
            except Exception as e:
                logger.error(f"Error in ensemble: {str(e)}")
                return {
                    'is_ransomware': 0,
                    'confidence': 0.0
                }
        
        # Register UDF
        ensemble_schema = StructType([
            StructField("is_ransomware", IntegerType(), False),
            StructField("confidence", FloatType(), False)
        ])
        ensemble_udf = udf(ensemble_udf, ensemble_schema)
        
        # Group predictions by sample_id
        grouped_df = predictions_df.groupBy("sample_id").agg(
            collect_list(
                struct(
                    col("is_ransomware"),
                    col("confidence"),
                    col("model_name")
                )
            ).alias("predictions")
        )
        
        # Apply ensemble
        ensemble_df = grouped_df.select(
            col("sample_id"),
            ensemble_udf(col("predictions")).alias("ensemble")
        ).select(
            col("sample_id"),
            col("ensemble.is_ransomware").alias("is_ransomware"),
            col("ensemble.confidence").alias("confidence")
        )
        
        logger.info(f"Created ensemble predictions for {ensemble_df.count()} samples using {method}")
        return ensemble_df
    
    def evaluate_predictions(
        self,
        predictions_df: Any,  # pyspark.sql.DataFrame
        true_labels_df: Any  # pyspark.sql.DataFrame
    ) -> Dict[str, Any]:
        """
        Evaluate predictions against true labels
        
        Args:
            predictions_df: DataFrame with predictions
            true_labels_df: DataFrame with true labels
            
        Returns:
            Dictionary with evaluation metrics
        """
        # Join predictions with true labels
        joined_df = predictions_df.join(
            true_labels_df.select("sample_id", "label"),
            on="sample_id",
            how="inner"
        )
        
        # Convert to Pandas for easier calculation
        pandas_df = joined_df.toPandas()
        
        # Calculate metrics
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
        
        y_true = pandas_df["label"].values
        y_pred = pandas_df["is_ransomware"].values
        y_probs = pandas_df["confidence"].values
        
        metrics = {
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, zero_division=0)),
            "f1": float(f1_score(y_true, y_pred, zero_division=0)),
            "auc": float(roc_auc_score(y_true, y_probs)) if len(set(y_true)) > 1 else 0.0,
            "samples": len(y_true),
            "positive_samples": int(sum(y_true)),
            "negative_samples": int(len(y_true) - sum(y_true)),
            "true_positives": int(sum((y_true == 1) & (y_pred == 1))),
            "true_negatives": int(sum((y_true == 0) & (y_pred == 0))),
            "false_positives": int(sum((y_true == 0) & (y_pred == 1))),
            "false_negatives": int(sum((y_true == 1) & (y_pred == 0)))
        }
        
        logger.info(f"Evaluation metrics: {metrics}")
        return metrics
    
    def save_predictions(
        self,
        predictions_df: Any,  # pyspark.sql.DataFrame
        output_dir: str,
        format: str = "json"
    ):
        """
        Save predictions to files
        
        Args:
            predictions_df: DataFrame with predictions
            output_dir: Directory to save predictions
            format: Output format ('json', 'csv', 'parquet')
        """
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Save predictions
        output_path = os.path.join(output_dir, f"predictions.{format}")
        
        if format == "json":
            predictions_df.write.json(output_path, mode="overwrite")
        elif format == "csv":
            predictions_df.write.csv(output_path, mode="overwrite", header=True)
        elif format == "parquet":
            predictions_df.write.parquet(output_path, mode="overwrite")
        else:
            logger.error(f"Unsupported format: {format}")
            return
        
        logger.info(f"Saved predictions to {output_path}")
    
    def run_pipeline(
        self,
        sample_directory: str,
        model_func: Callable,
        feature_extractors: Dict[str, Callable],
        output_directory: str,
        max_samples: Optional[int] = None,
        include_binary: bool = False,
        save_format: str = "json"
    ) -> Dict[str, Any]:
        """
        Run complete pipeline from sample loading to prediction
        
        Args:
            sample_directory: Directory containing sample directories
            model_func: Function that takes features and returns predictions
            feature_extractors: Dictionary mapping feature types to extractor functions
            output_directory: Directory to save results
            max_samples: Maximum number of samples to process
            include_binary: Whether to include binary content
            save_format: Format for saving results
            
        Returns:
            Dictionary with pipeline results
        """
        # Start timer
        start_time = time.time()
        
        # Create output directory if it doesn't exist
        os.makedirs(output_directory, exist_ok=True)
        
        # Load samples
        logger.info(f"Loading samples from {sample_directory}")
        sample_df = self.load_samples_from_directory(
            directory=sample_directory,
            max_samples=max_samples,
            include_binary=include_binary
        )
        
        # Extract features
        logger.info("Extracting features")
        features_df = self.extract_features(
            sample_df=sample_df,
            feature_extractors=feature_extractors
        )
        
        # Make predictions
        logger.info("Making predictions")
        predictions_df = self.predict_with_model(
            features_df=features_df,
            model_func=model_func,
            model_name="ensemble"
        )
        
        # Save predictions
        logger.info(f"Saving predictions to {output_directory}")
        self.save_predictions(
            predictions_df=predictions_df,
            output_dir=output_directory,
            format=save_format
        )
        
        # Evaluate predictions
        logger.info("Evaluating predictions")
        metrics = self.evaluate_predictions(
            predictions_df=predictions_df,
            true_labels_df=sample_df.select("sample_id", "label")
        )
        
        # Save metrics
        metrics_path = os.path.join(output_directory, "metrics.json")
        with open(metrics_path, 'w') as f:
            json.dump(metrics, f, indent=2)
        
        # Calculate elapsed time
        elapsed_time = time.time() - start_time
        
        return {
            "metrics": metrics,
            "elapsed_time": elapsed_time,
            "samples_processed": metrics["samples"],
            "output_directory": output_directory
        }


# Simple in-memory cache for feature extraction
class FeatureCache:
    """Simple in-memory cache for feature extraction"""
    
    def __init__(self, max_size: int = 1000):
        """
        Initialize cache
        
        Args:
            max_size: Maximum number of items to cache
        """
        self.cache = {}
        self.max_size = max_size
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get item from cache
        
        Args:
            key: Cache key
            
        Returns:
            Cached item or None if not found
        """
        return self.cache.get(key)
    
    def put(self, key: str, value: Any):
        """
        Put item in cache
        
        Args:
            key: Cache key
            value: Item to cache
        """
        # Check if cache is full
        if len(self.cache) >= self.max_size:
            # Remove random item
            import random
            random_key = random.choice(list(self.cache.keys()))
            del self.cache[random_key]
        
        # Add to cache
        self.cache[key] = value
    
    def clear(self):
        """Clear cache"""
        self.cache.clear()


# Feature extraction functions for distributed processing
def create_feature_extractors(
    cnn_model_path: Optional[str] = None,
    lstm_model_path: Optional[str] = None,
    lstm_tokenizer_path: Optional[str] = None,
    static_analyzer = None
) -> Dict[str, Callable]:
    """
    Create feature extraction functions for distributed processing
    
    Args:
        cnn_model_path: Path to CNN model
        lstm_model_path: Path to LSTM model
        lstm_tokenizer_path: Path to LSTM tokenizer
        static_analyzer: Static analysis function
        
    Returns:
        Dictionary mapping feature types to extractor functions
    """
    # Initialize cache
    cache = FeatureCache(max_size=1000)
    
    # CNN feature extraction
    def extract_cnn_features(binary_path: str) -> List[float]:
        # Check cache
        cache_key = f"cnn:{binary_path}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
        
        try:
            if cnn_model_path and os.path.exists(cnn_model_path):
                # Import CNN extractor
                from ai_detection.models.deep.cnn.binary_cnn_extractor import BinaryCNNExtractor
                
                # Load model
                cnn_model = BinaryCNNExtractor.load(cnn_model_path)
                
                # Extract features
                features = cnn_model.extract_features(binary_path)
                
                # Cache features
                cache.put(cache_key, features)
                
                return features
            else:
                # Return zeros
                return [0.0] * 64
        except Exception as e:
            logger.error(f"Error extracting CNN features: {str(e)}")
            return [0.0] * 64
    
    # LSTM feature extraction
    def extract_lstm_features(execution_logs: List[str]) -> List[float]:
        # Check cache
        cache_key = f"lstm:{','.join(execution_logs)}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
        
        try:
            if lstm_model_path and lstm_tokenizer_path and \
               os.path.exists(lstm_model_path) and os.path.exists(lstm_tokenizer_path):
                # Import LSTM analyzer
                from ai_detection.models.deep.lstm.integration import LSTMSequenceDetector
                
                # Create detector
                lstm_detector = LSTMSequenceDetector(
                    model_path=lstm_model_path,
                    tokenizer_path=lstm_tokenizer_path
                )
                
                # Extract features
                features = lstm_detector.extract_behavioral_features(execution_logs)
                
                if isinstance(features, dict) and 'features' in features:
                    features = features['features']
                
                # Cache features
                cache.put(cache_key, features)
                
                return features
            else:
                # Return zeros
                return [0.0] * 128
        except Exception as e:
            logger.error(f"Error extracting LSTM features: {str(e)}")
            return [0.0] * 128
    
    # Static feature extraction
    def extract_static_features(binary_path: str) -> List[float]:
        # Check cache
        cache_key = f"static:{binary_path}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
        
        try:
            if static_analyzer is not None:
                # Extract features
                features = static_analyzer(binary_path)
                
                # Cache features
                cache.put(cache_key, features)
                
                return features
            else:
                # Return zeros
                return [0.0] * 32
        except Exception as e:
            logger.error(f"Error extracting static features: {str(e)}")
            return [0.0] * 32
    
    return {
        'cnn': extract_cnn_features,
        'lstm': extract_lstm_features,
        'static': extract_static_features
    }


# Simple static analysis function
def simple_static_analyzer(binary_path: str) -> List[float]:
    """
    Simple static analysis function
    
    Args:
        binary_path: Path to binary file
        
    Returns:
        Static features
    """
    try:
        # Read file
        with open(binary_path, 'rb') as f:
            content = f.read()
        
        # Calculate basic features
        file_size = len(content)
        entropy = calculate_entropy(content)
        
        # Count string-like sequences
        string_count = count_strings(content)
        
        # Count specific byte patterns
        zero_count = content.count(b'\x00')
        ff_count = content.count(b'\xff')
        
        # Create feature vector (32 dimensions)
        features = [
            # File size features
            file_size / 1_000_000,  # Normalized file size (MB)
            min(1.0, file_size / 10_000_000),  # Capped normalized file size
            
            # Entropy features
            entropy / 8.0,  # Normalized entropy
            
            # String features
            min(1.0, string_count / 1000),  # Normalized string count
            
            # Byte distribution features
            zero_count / max(1, file_size),  # Ratio of zero bytes
            ff_count / max(1, file_size),  # Ratio of 0xFF bytes
        ]
        
        # Pad to 32 dimensions
        features.extend([0.0] * (32 - len(features)))
        
        return features
    except Exception as e:
        logger.error(f"Error in static analysis: {str(e)}")
        return [0.0] * 32


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data
    
    Args:
        data: Bytes to calculate entropy for
        
    Returns:
        Entropy value
    """
    if not data:
        return 0.0
    
    # Count byte frequencies
    byte_counts = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    for count in byte_counts.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    
    return entropy


def count_strings(data: bytes, min_length: int = 4) -> int:
    """
    Count string-like sequences in binary data
    
    Args:
        data: Binary data
        min_length: Minimum length of strings to count
        
    Returns:
        Number of strings found
    """
    import re
    
    # Convert to string
    data_str = data.decode('latin-1')
    
    # Find ASCII strings
    ascii_pattern = re.compile(r'[ -~]{%d,}' % min_length)
    ascii_strings = ascii_pattern.findall(data_str)
    
    return len(ascii_strings)