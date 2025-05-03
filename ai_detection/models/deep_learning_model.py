#!/usr/bin/env python3
"""
Deep Learning Models for Ransomware Analysis

This module provides deep learning models for ransomware detection and classification.
"""

import os
import json
import logging
import numpy as np
from typing import Dict, List, Optional, Any, Tuple, Union
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('deep_learning_model')

class RansomwareEmbeddingModel:
    """
    Deep learning model for embedding ransomware samples into a vector space
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the ransomware embedding model
        
        Args:
            config: Configuration dictionary for the model
        """
        self.config = config or {}
        self.input_dim = self.config.get('input_dim', 22)  # Default number of numeric features
        self.embedding_dim = self.config.get('embedding_dim', 256)
        self.model = None
        self.initialized = False
        self.backend = None
        
        # Initialize if auto_initialize is enabled
        if self.config.get('auto_initialize', True):
            self.initialize()
    
    def initialize(self) -> bool:
        """
        Initialize the model
        
        Returns:
            Success status
        """
        if self.initialized:
            return True
        
        try:
            # Import deep learning libraries dynamically to avoid hard dependencies
            import_successful = self._import_deep_learning_libs()
            if not import_successful:
                logger.warning("Deep learning libraries not available")
                return False
            
            # Create model architecture
            self._create_model()
            
            # Load pre-trained weights if available
            model_path = self.config.get('model_path')
            if model_path and os.path.exists(model_path):
                self._load_model_weights(model_path)
            
            self.initialized = True
            logger.info("Ransomware embedding model initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing embedding model: {e}")
            return False
    
    def _import_deep_learning_libs(self) -> bool:
        """
        Import deep learning libraries dynamically
        
        Returns:
            Success status
        """
        try:
            # Try to import relevant libraries based on configuration
            backend = self.config.get('backend', 'keras').lower()
            
            if backend == 'keras':
                # Try import TensorFlow/Keras
                try:
                    global tf, keras
                    import tensorflow as tf
                    from tensorflow import keras
                    logger.info("Using TensorFlow/Keras backend")
                    self.backend = 'keras'
                    return True
                except ImportError:
                    pass
            
            if backend == 'pytorch' or self.backend is None:
                # Try import PyTorch
                try:
                    global torch, nn, F
                    import torch
                    from torch import nn
                    import torch.nn.functional as F
                    logger.info("Using PyTorch backend")
                    self.backend = 'pytorch'
                    return True
                except ImportError:
                    pass
            
            # No backend available
            logger.warning("No deep learning backend available")
            self.backend = None
            return False
            
        except Exception as e:
            logger.error(f"Error importing deep learning libraries: {e}")
            self.backend = None
            return False
    
    def _create_model(self) -> None:
        """Create model architecture based on backend"""
        if self.backend == 'keras':
            self._create_keras_model()
        elif self.backend == 'pytorch':
            self._create_pytorch_model()
    
    def _create_keras_model(self) -> None:
        """Create Keras model architecture"""
        # Get model configuration
        hidden_layers = self.config.get('hidden_layers', [512, 256])
        dropout_rate = self.config.get('dropout_rate', 0.3)
        
        # Create model
        inputs = keras.layers.Input(shape=(self.input_dim,))
        x = inputs
        
        # Hidden layers
        for units in hidden_layers:
            x = keras.layers.Dense(units, activation='relu')(x)
            x = keras.layers.BatchNormalization()(x)
            x = keras.layers.Dropout(dropout_rate)(x)
        
        # Embedding layer
        embeddings = keras.layers.Dense(self.embedding_dim)(x)
        embeddings = keras.layers.LayerNormalization()(embeddings)
        
        # Create model
        self.model = keras.Model(inputs=inputs, outputs=embeddings)
        
        # Compile model
        self.model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='mse'
        )
    
    def _create_pytorch_model(self) -> None:
        """Create PyTorch model architecture"""
        # Define model architecture as a PyTorch module
        class RansomwareEmbedder(nn.Module):
            def __init__(self, input_dim, hidden_layers, embedding_dim, dropout_rate):
                super(RansomwareEmbedder, self).__init__()
                
                # Create model layers
                layers = []
                
                # Input layer
                layers.append(nn.Linear(input_dim, hidden_layers[0]))
                layers.append(nn.ReLU())
                layers.append(nn.BatchNorm1d(hidden_layers[0]))
                layers.append(nn.Dropout(dropout_rate))
                
                # Hidden layers
                for i in range(len(hidden_layers) - 1):
                    layers.append(nn.Linear(hidden_layers[i], hidden_layers[i+1]))
                    layers.append(nn.ReLU())
                    layers.append(nn.BatchNorm1d(hidden_layers[i+1]))
                    layers.append(nn.Dropout(dropout_rate))
                
                # Embedding layer
                layers.append(nn.Linear(hidden_layers[-1], embedding_dim))
                layers.append(nn.LayerNorm(embedding_dim))
                
                self.model = nn.Sequential(*layers)
            
            def forward(self, x):
                return self.model(x)
        
        # Get model configuration
        hidden_layers = self.config.get('hidden_layers', [512, 256])
        dropout_rate = self.config.get('dropout_rate', 0.3)
        
        # Create model
        self.model = RansomwareEmbedder(
            input_dim=self.input_dim,
            hidden_layers=hidden_layers,
            embedding_dim=self.embedding_dim,
            dropout_rate=dropout_rate
        )
    
    def _load_model_weights(self, model_path: str) -> bool:
        """
        Load pre-trained model weights
        
        Args:
            model_path: Path to model weights
            
        Returns:
            Success status
        """
        try:
            if self.backend == 'keras':
                # Load Keras model weights
                if model_path.endswith('.h5'):
                    self.model.load_weights(model_path)
                else:
                    # Try to load as full model
                    self.model = keras.models.load_model(model_path)
                
                logger.info(f"Loaded Keras model weights from {model_path}")
                return True
                
            elif self.backend == 'pytorch':
                # Load PyTorch model weights
                if model_path.endswith('.pt') or model_path.endswith('.pth'):
                    self.model.load_state_dict(torch.load(model_path, map_location='cpu'))
                    self.model.eval()  # Set to evaluation mode
                    
                    logger.info(f"Loaded PyTorch model weights from {model_path}")
                    return True
                
            return False
            
        except Exception as e:
            logger.error(f"Error loading model weights from {model_path}: {e}")
            return False
    
    def predict(self, features: Union[np.ndarray, List[float]]) -> np.ndarray:
        """
        Generate embeddings for input features
        
        Args:
            features: Input features (single sample)
            
        Returns:
            Embedding vector
        """
        if not self.initialized or self.model is None:
            # Return zeros if model is not initialized
            return np.zeros(self.embedding_dim, dtype=np.float32)
        
        try:
            # Convert input to appropriate format
            if isinstance(features, list):
                features = np.array(features, dtype=np.float32)
            
            if self.backend == 'keras':
                # Add batch dimension if needed
                if len(features.shape) == 1:
                    features = np.expand_dims(features, axis=0)
                
                # Generate embedding
                embedding = self.model.predict(features)
                
                # Remove batch dimension for single sample
                if embedding.shape[0] == 1:
                    embedding = embedding[0]
                
                return embedding
                
            elif self.backend == 'pytorch':
                # Convert to PyTorch tensor
                if not isinstance(features, torch.Tensor):
                    features = torch.tensor(features, dtype=torch.float32)
                
                # Add batch dimension if needed
                if len(features.shape) == 1:
                    features = features.unsqueeze(0)
                
                # Set model to evaluation mode
                self.model.eval()
                
                # Generate embedding
                with torch.no_grad():
                    embedding = self.model(features)
                
                # Remove batch dimension for single sample
                if embedding.shape[0] == 1:
                    embedding = embedding[0]
                
                # Convert to numpy
                return embedding.cpu().numpy()
            
            # Fallback to zeros
            return np.zeros(self.embedding_dim, dtype=np.float32)
            
        except Exception as e:
            logger.error(f"Error generating embedding: {e}")
            return np.zeros(self.embedding_dim, dtype=np.float32)
    
    def save_model(self, model_path: str) -> bool:
        """
        Save model to file
        
        Args:
            model_path: Path to save model
            
        Returns:
            Success status
        """
        if not self.initialized or self.model is None:
            logger.error("Cannot save uninitialized model")
            return False
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(model_path)), exist_ok=True)
            
            if self.backend == 'keras':
                # Save Keras model
                if model_path.endswith('.h5'):
                    self.model.save_weights(model_path)
                else:
                    self.model.save(model_path)
                
                logger.info(f"Saved Keras model to {model_path}")
                return True
                
            elif self.backend == 'pytorch':
                # Save PyTorch model
                if model_path.endswith('.pt') or model_path.endswith('.pth'):
                    torch.save(self.model.state_dict(), model_path)
                    
                    logger.info(f"Saved PyTorch model to {model_path}")
                    return True
                
            return False
            
        except Exception as e:
            logger.error(f"Error saving model to {model_path}: {e}")
            return False


class RansomwareFamilyClassifier:
    """
    Deep learning model for classifying ransomware families
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the ransomware family classifier
        
        Args:
            config: Configuration dictionary for the model
        """
        self.config = config or {}
        self.input_dim = self.config.get('input_dim', 256)  # Default to embedding dimension
        self.num_classes = self.config.get('num_classes', 10)  # Default number of families
        self.class_names = self.config.get('class_names', [f"family_{i}" for i in range(self.num_classes)])
        self.model = None
        self.initialized = False
        self.backend = None
        
        # Initialize if auto_initialize is enabled
        if self.config.get('auto_initialize', True):
            self.initialize()
    
    def initialize(self) -> bool:
        """
        Initialize the model
        
        Returns:
            Success status
        """
        if self.initialized:
            return True
        
        try:
            # Import deep learning libraries dynamically to avoid hard dependencies
            import_successful = self._import_deep_learning_libs()
            if not import_successful:
                logger.warning("Deep learning libraries not available")
                return False
            
            # Create model architecture
            self._create_model()
            
            # Load pre-trained weights if available
            model_path = self.config.get('model_path')
            if model_path and os.path.exists(model_path):
                self._load_model_weights(model_path)
            
            self.initialized = True
            logger.info("Ransomware family classifier initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing family classifier: {e}")
            return False
    
    def _import_deep_learning_libs(self) -> bool:
        """
        Import deep learning libraries dynamically
        
        Returns:
            Success status
        """
        try:
            # Try to import relevant libraries based on configuration
            backend = self.config.get('backend', 'keras').lower()
            
            if backend == 'keras':
                # Try import TensorFlow/Keras
                try:
                    global tf, keras
                    import tensorflow as tf
                    from tensorflow import keras
                    logger.info("Using TensorFlow/Keras backend")
                    self.backend = 'keras'
                    return True
                except ImportError:
                    pass
            
            if backend == 'pytorch' or self.backend is None:
                # Try import PyTorch
                try:
                    global torch, nn, F
                    import torch
                    from torch import nn
                    import torch.nn.functional as F
                    logger.info("Using PyTorch backend")
                    self.backend = 'pytorch'
                    return True
                except ImportError:
                    pass
            
            # No backend available
            logger.warning("No deep learning backend available")
            self.backend = None
            return False
            
        except Exception as e:
            logger.error(f"Error importing deep learning libraries: {e}")
            self.backend = None
            return False
    
    def _create_model(self) -> None:
        """Create model architecture based on backend"""
        if self.backend == 'keras':
            self._create_keras_model()
        elif self.backend == 'pytorch':
            self._create_pytorch_model()
    
    def _create_keras_model(self) -> None:
        """Create Keras model architecture"""
        # Get model configuration
        hidden_layers = self.config.get('hidden_layers', [128, 64])
        dropout_rate = self.config.get('dropout_rate', 0.3)
        
        # Create model
        inputs = keras.layers.Input(shape=(self.input_dim,))
        x = inputs
        
        # Hidden layers
        for units in hidden_layers:
            x = keras.layers.Dense(units, activation='relu')(x)
            x = keras.layers.BatchNormalization()(x)
            x = keras.layers.Dropout(dropout_rate)(x)
        
        # Output layer
        outputs = keras.layers.Dense(self.num_classes, activation='softmax')(x)
        
        # Create model
        self.model = keras.Model(inputs=inputs, outputs=outputs)
        
        # Compile model
        self.model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )
    
    def _create_pytorch_model(self) -> None:
        """Create PyTorch model architecture"""
        # Define model architecture as a PyTorch module
        class RansomwareClassifier(nn.Module):
            def __init__(self, input_dim, hidden_layers, num_classes, dropout_rate):
                super(RansomwareClassifier, self).__init__()
                
                # Create model layers
                layers = []
                
                # Input layer
                layers.append(nn.Linear(input_dim, hidden_layers[0]))
                layers.append(nn.ReLU())
                layers.append(nn.BatchNorm1d(hidden_layers[0]))
                layers.append(nn.Dropout(dropout_rate))
                
                # Hidden layers
                for i in range(len(hidden_layers) - 1):
                    layers.append(nn.Linear(hidden_layers[i], hidden_layers[i+1]))
                    layers.append(nn.ReLU())
                    layers.append(nn.BatchNorm1d(hidden_layers[i+1]))
                    layers.append(nn.Dropout(dropout_rate))
                
                # Output layer
                layers.append(nn.Linear(hidden_layers[-1], num_classes))
                
                self.model = nn.Sequential(*layers)
            
            def forward(self, x):
                logits = self.model(x)
                return F.softmax(logits, dim=-1)
        
        # Get model configuration
        hidden_layers = self.config.get('hidden_layers', [128, 64])
        dropout_rate = self.config.get('dropout_rate', 0.3)
        
        # Create model
        self.model = RansomwareClassifier(
            input_dim=self.input_dim,
            hidden_layers=hidden_layers,
            num_classes=self.num_classes,
            dropout_rate=dropout_rate
        )
    
    def _load_model_weights(self, model_path: str) -> bool:
        """
        Load pre-trained model weights
        
        Args:
            model_path: Path to model weights
            
        Returns:
            Success status
        """
        try:
            if self.backend == 'keras':
                # Load Keras model weights
                if model_path.endswith('.h5'):
                    self.model.load_weights(model_path)
                else:
                    # Try to load as full model
                    self.model = keras.models.load_model(model_path)
                
                logger.info(f"Loaded Keras model weights from {model_path}")
                return True
                
            elif self.backend == 'pytorch':
                # Load PyTorch model weights
                if model_path.endswith('.pt') or model_path.endswith('.pth'):
                    self.model.load_state_dict(torch.load(model_path, map_location='cpu'))
                    self.model.eval()  # Set to evaluation mode
                    
                    logger.info(f"Loaded PyTorch model weights from {model_path}")
                    return True
                
            return False
            
        except Exception as e:
            logger.error(f"Error loading model weights from {model_path}: {e}")
            return False
    
    def predict(self, features: Union[np.ndarray, List[float]]) -> Dict[str, float]:
        """
        Predict ransomware family probabilities
        
        Args:
            features: Input features (single sample)
            
        Returns:
            Dictionary of family probabilities
        """
        if not self.initialized or self.model is None:
            # Return empty dictionary if model is not initialized
            return {}
        
        try:
            # Convert input to appropriate format
            if isinstance(features, list):
                features = np.array(features, dtype=np.float32)
            
            if self.backend == 'keras':
                # Add batch dimension if needed
                if len(features.shape) == 1:
                    features = np.expand_dims(features, axis=0)
                
                # Generate predictions
                predictions = self.model.predict(features)
                
                # Remove batch dimension for single sample
                if predictions.shape[0] == 1:
                    predictions = predictions[0]
                
            elif self.backend == 'pytorch':
                # Convert to PyTorch tensor
                if not isinstance(features, torch.Tensor):
                    features = torch.tensor(features, dtype=torch.float32)
                
                # Add batch dimension if needed
                if len(features.shape) == 1:
                    features = features.unsqueeze(0)
                
                # Set model to evaluation mode
                self.model.eval()
                
                # Generate predictions
                with torch.no_grad():
                    predictions = self.model(features)
                
                # Remove batch dimension for single sample
                if predictions.shape[0] == 1:
                    predictions = predictions[0]
                
                # Convert to numpy
                predictions = predictions.cpu().numpy()
            
            else:
                # No backend, return empty dict
                return {}
            
            # Create dictionary of family probabilities
            result = {}
            for i, prob in enumerate(predictions):
                if i < len(self.class_names):
                    result[self.class_names[i]] = float(prob)
            
            return result
            
        except Exception as e:
            logger.error(f"Error predicting family probabilities: {e}")
            return {}
    
    def save_model(self, model_path: str) -> bool:
        """
        Save model to file
        
        Args:
            model_path: Path to save model
            
        Returns:
            Success status
        """
        if not self.initialized or self.model is None:
            logger.error("Cannot save uninitialized model")
            return False
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(model_path)), exist_ok=True)
            
            # Also save class names if possible
            class_names_path = os.path.join(
                os.path.dirname(model_path),
                f"{os.path.splitext(os.path.basename(model_path))[0]}_classes.json"
            )
            
            try:
                with open(class_names_path, 'w') as f:
                    json.dump(self.class_names, f, indent=2)
            except Exception as e:
                logger.warning(f"Error saving class names to {class_names_path}: {e}")
            
            if self.backend == 'keras':
                # Save Keras model
                if model_path.endswith('.h5'):
                    self.model.save_weights(model_path)
                else:
                    self.model.save(model_path)
                
                logger.info(f"Saved Keras model to {model_path}")
                return True
                
            elif self.backend == 'pytorch':
                # Save PyTorch model
                if model_path.endswith('.pt') or model_path.endswith('.pth'):
                    torch.save(self.model.state_dict(), model_path)
                    
                    logger.info(f"Saved PyTorch model to {model_path}")
                    return True
                
            return False
            
        except Exception as e:
            logger.error(f"Error saving model to {model_path}: {e}")
            return False


class RansomwareVariantDetector:
    """
    Deep learning model for detecting new ransomware variants
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the ransomware variant detector
        
        Args:
            config: Configuration dictionary for the model
        """
        self.config = config or {}
        self.input_dim = self.config.get('input_dim', 256)  # Default to embedding dimension
        self.similarity_threshold = self.config.get('similarity_threshold', 0.85)
        self.model = None
        self.initialized = False
        self.backend = None
        
        # Reference embeddings for known variants
        self.reference_embeddings = {}
        
        # Initialize if auto_initialize is enabled
        if self.config.get('auto_initialize', True):
            self.initialize()
    
    def initialize(self) -> bool:
        """
        Initialize the model
        
        Returns:
            Success status
        """
        if self.initialized:
            return True
        
        try:
            # Import deep learning libraries dynamically to avoid hard dependencies
            import_successful = self._import_deep_learning_libs()
            if not import_successful:
                logger.warning("Deep learning libraries not available")
                return False
            
            # Load reference embeddings if available
            embeddings_path = self.config.get('reference_embeddings_path')
            if embeddings_path and os.path.exists(embeddings_path):
                self._load_reference_embeddings(embeddings_path)
            
            self.initialized = True
            logger.info(f"Ransomware variant detector initialized with {len(self.reference_embeddings)} reference embeddings")
            return True
            
        except Exception as e:
            logger.error(f"Error initializing variant detector: {e}")
            return False
    
    def _import_deep_learning_libs(self) -> bool:
        """
        Import deep learning libraries dynamically
        
        Returns:
            Success status
        """
        try:
            # Try to import NumPy and SciPy
            import numpy as np
            from scipy.spatial.distance import cosine
            
            # These are the minimum required libraries
            self.backend = 'numpy'
            return True
            
        except Exception as e:
            logger.error(f"Error importing required libraries: {e}")
            self.backend = None
            return False
    
    def _load_reference_embeddings(self, embeddings_path: str) -> bool:
        """
        Load reference embeddings for known variants
        
        Args:
            embeddings_path: Path to embeddings file
            
        Returns:
            Success status
        """
        try:
            with open(embeddings_path, 'r') as f:
                data = json.load(f)
            
            if isinstance(data, dict):
                # Load embeddings
                self.reference_embeddings = {}
                
                for variant, embedding_data in data.items():
                    if "embedding" in embedding_data:
                        self.reference_embeddings[variant] = {
                            "embedding": np.array(embedding_data["embedding"], dtype=np.float32),
                            "family": embedding_data.get("family", "unknown"),
                            "confidence": embedding_data.get("confidence", 1.0)
                        }
            
            logger.info(f"Loaded {len(self.reference_embeddings)} reference embeddings")
            return True
            
        except Exception as e:
            logger.error(f"Error loading reference embeddings from {embeddings_path}: {e}")
            return False
    
    def detect_variant(self, embedding: Union[np.ndarray, List[float]], 
                     reference_family: Optional[str] = None) -> Dict[str, Any]:
        """
        Detect if sample is a variant of a known ransomware family
        
        Args:
            embedding: Sample embedding
            reference_family: Optional family to check against (if None, check all families)
            
        Returns:
            Dictionary with variant detection results
        """
        if not self.initialized:
            return {
                "is_variant": False,
                "similarity": 0.0,
                "closest_variant": None,
                "family": None,
                "confidence": 0.0
            }
        
        try:
            # Convert embedding to numpy array if needed
            if isinstance(embedding, list):
                embedding = np.array(embedding, dtype=np.float32)
            
            # Filter reference embeddings by family if specified
            references = self.reference_embeddings
            if reference_family:
                references = {
                    variant: data for variant, data in references.items()
                    if data.get("family", "").lower() == reference_family.lower()
                }
            
            if not references:
                return {
                    "is_variant": False,
                    "similarity": 0.0,
                    "closest_variant": None,
                    "family": reference_family,
                    "confidence": 0.0,
                    "message": "No reference embeddings available for comparison"
                }
            
            # Find closest variant
            closest_variant = None
            highest_similarity = 0.0
            family = None
            confidence = 0.0
            
            for variant, data in references.items():
                ref_embedding = data["embedding"]
                
                # Calculate cosine similarity
                similarity = self._calculate_similarity(embedding, ref_embedding)
                
                if similarity > highest_similarity:
                    highest_similarity = similarity
                    closest_variant = variant
                    family = data.get("family", "unknown")
                    confidence = data.get("confidence", 1.0) * similarity
            
            # Determine if it's a variant based on similarity threshold
            is_variant = highest_similarity >= self.similarity_threshold
            
            return {
                "is_variant": is_variant,
                "similarity": float(highest_similarity),
                "closest_variant": closest_variant,
                "family": family,
                "confidence": float(confidence),
                "threshold": self.similarity_threshold
            }
            
        except Exception as e:
            logger.error(f"Error detecting variant: {e}")
            return {
                "is_variant": False,
                "similarity": 0.0,
                "closest_variant": None,
                "family": None,
                "confidence": 0.0,
                "error": str(e)
            }
    
    def _calculate_similarity(self, embedding1: np.ndarray, embedding2: np.ndarray) -> float:
        """
        Calculate similarity between two embeddings
        
        Args:
            embedding1: First embedding
            embedding2: Second embedding
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        try:
            from scipy.spatial.distance import cosine
            
            # Calculate cosine similarity (1 - cosine distance)
            similarity = 1.0 - cosine(embedding1, embedding2)
            
            return float(similarity)
            
        except Exception as e:
            logger.error(f"Error calculating similarity: {e}")
            
            # Fallback to manual calculation
            try:
                # Normalize embeddings
                norm1 = np.linalg.norm(embedding1)
                norm2 = np.linalg.norm(embedding2)
                
                if norm1 == 0 or norm2 == 0:
                    return 0.0
                
                # Calculate cosine similarity
                similarity = np.dot(embedding1, embedding2) / (norm1 * norm2)
                
                return float(similarity)
                
            except Exception as e2:
                logger.error(f"Error with fallback similarity calculation: {e2}")
                return 0.0
    
    def add_reference_embedding(self, variant: str, embedding: Union[np.ndarray, List[float]], 
                              family: str, confidence: float = 1.0) -> bool:
        """
        Add a reference embedding for a known variant
        
        Args:
            variant: Variant name
            embedding: Variant embedding
            family: Family name
            confidence: Confidence in the embedding (0.0 to 1.0)
            
        Returns:
            Success status
        """
        try:
            # Convert embedding to numpy array if needed
            if isinstance(embedding, list):
                embedding = np.array(embedding, dtype=np.float32)
            
            # Add to reference embeddings
            self.reference_embeddings[variant] = {
                "embedding": embedding,
                "family": family,
                "confidence": confidence
            }
            
            return True
            
        except Exception as e:
            logger.error(f"Error adding reference embedding for {variant}: {e}")
            return False
    
    def save_reference_embeddings(self, embeddings_path: str) -> bool:
        """
        Save reference embeddings to file
        
        Args:
            embeddings_path: Path to save embeddings
            
        Returns:
            Success status
        """
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(embeddings_path)), exist_ok=True)
            
            # Convert numpy arrays to lists
            data = {}
            for variant, embedding_data in self.reference_embeddings.items():
                data[variant] = {
                    "embedding": embedding_data["embedding"].tolist(),
                    "family": embedding_data.get("family", "unknown"),
                    "confidence": float(embedding_data.get("confidence", 1.0))
                }
            
            # Save to file
            with open(embeddings_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Saved {len(data)} reference embeddings to {embeddings_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving reference embeddings to {embeddings_path}: {e}")
            return False

# Example usage when run as a script
if __name__ == "__main__":
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description="Deep Learning Models for Ransomware Analysis")
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Create embedding model command
    embed_parser = subparsers.add_parser('embed', help='Generate embedding for sample')
    embed_parser.add_argument('--input', required=True, help='Input features file')
    embed_parser.add_argument('--config', help='Model configuration file')
    embed_parser.add_argument('--output', help='Output file for embedding')
    
    # Classify sample command
    classify_parser = subparsers.add_parser('classify', help='Classify sample')
    classify_parser.add_argument('--input', required=True, help='Input features or embedding file')
    classify_parser.add_argument('--config', help='Model configuration file')
    classify_parser.add_argument('--output', help='Output file for classification results')
    
    # Detect variant command
    detect_parser = subparsers.add_parser('detect-variant', help='Detect variant')
    detect_parser.add_argument('--input', required=True, help='Input embedding file')
    detect_parser.add_argument('--references', required=True, help='Reference embeddings file')
    detect_parser.add_argument('--family', help='Reference family to check against')
    detect_parser.add_argument('--threshold', type=float, help='Similarity threshold')
    detect_parser.add_argument('--output', help='Output file for detection results')
    
    # Parse arguments
    args = parser.parse_args()
    
    if args.command == 'embed':
        # Load input features
        try:
            with open(args.input, 'r') as f:
                input_data = json.load(f)
            
            # Extract features
            if "deep_embedding" in input_data:
                # Already have embedding
                embedding = input_data["deep_embedding"]
                print(f"Using existing embedding with dimension {len(embedding)}")
            else:
                # Need to generate embedding
                # Load configuration if provided
                config = None
                if args.config:
                    try:
                        with open(args.config, 'r') as f:
                            config = json.load(f)
                    except Exception as e:
                        print(f"Error loading configuration: {e}")
                        sys.exit(1)
                
                # Create embedding model
                model = RansomwareEmbeddingModel(config)
                if not model.initialized:
                    print("Failed to initialize embedding model")
                    sys.exit(1)
                
                # Generate embedding
                # Extract numeric features for the model
                numeric_features = []
                
                # Extract string counts
                if "analysis" in input_data and "strings" in input_data["analysis"]:
                    strings = input_data["analysis"]["strings"]
                    numeric_features.append(len(strings))
                else:
                    numeric_features.append(0)
                
                # Extract file operation counts
                if "analysis" in input_data and "behaviors" in input_data["analysis"] and "file_operations" in input_data["analysis"]["behaviors"]:
                    file_ops = input_data["analysis"]["behaviors"]["file_operations"]
                    numeric_features.append(len(file_ops))
                else:
                    numeric_features.append(0)
                
                # If not enough features, pad with zeros
                while len(numeric_features) < model.input_dim:
                    numeric_features.append(0)
                
                # Truncate if too many features
                if len(numeric_features) > model.input_dim:
                    numeric_features = numeric_features[:model.input_dim]
                
                # Generate embedding
                embedding = model.predict(numeric_features).tolist()
                print(f"Generated embedding with dimension {len(embedding)}")
            
            # Output embedding
            result = {"embedding": embedding}
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"Embedding saved to {args.output}")
            else:
                print(json.dumps(result, indent=2))
                
        except Exception as e:
            print(f"Error generating embedding: {e}")
            sys.exit(1)
    
    elif args.command == 'classify':
        # Load input features or embedding
        try:
            with open(args.input, 'r') as f:
                input_data = json.load(f)
            
            # Extract features or embedding
            features = None
            
            if "embedding" in input_data:
                # Use provided embedding
                features = input_data["embedding"]
            elif "deep_embedding" in input_data:
                # Use deep embedding from features
                features = input_data["deep_embedding"]
            else:
                print("No valid embedding found in input file")
                sys.exit(1)
            
            # Load configuration if provided
            config = None
            if args.config:
                try:
                    with open(args.config, 'r') as f:
                        config = json.load(f)
                except Exception as e:
                    print(f"Error loading configuration: {e}")
                    sys.exit(1)
            
            # Create classifier model
            model = RansomwareFamilyClassifier(config)
            if not model.initialized:
                print("Failed to initialize classifier model")
                sys.exit(1)
            
            # Generate classification
            classifications = model.predict(features)
            
            # Output classifications
            result = {"classifications": classifications}
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"Classifications saved to {args.output}")
            else:
                print(json.dumps(result, indent=2))
                
        except Exception as e:
            print(f"Error classifying sample: {e}")
            sys.exit(1)
    
    elif args.command == 'detect-variant':
        # Load input embedding
        try:
            with open(args.input, 'r') as f:
                input_data = json.load(f)
            
            # Extract embedding
            embedding = None
            
            if "embedding" in input_data:
                # Use provided embedding
                embedding = input_data["embedding"]
            elif "deep_embedding" in input_data:
                # Use deep embedding from features
                embedding = input_data["deep_embedding"]
            else:
                print("No valid embedding found in input file")
                sys.exit(1)
            
            # Create variant detector
            config = {
                "reference_embeddings_path": args.references
            }
            
            if args.threshold:
                config["similarity_threshold"] = args.threshold
            
            detector = RansomwareVariantDetector(config)
            if not detector.initialized:
                print("Failed to initialize variant detector")
                sys.exit(1)
            
            # Detect variant
            result = detector.detect_variant(embedding, args.family)
            
            # Output result
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"Detection result saved to {args.output}")
            else:
                print(json.dumps(result, indent=2))
                
        except Exception as e:
            print(f"Error detecting variant: {e}")
            sys.exit(1)
    
    else:
        parser.print_help()