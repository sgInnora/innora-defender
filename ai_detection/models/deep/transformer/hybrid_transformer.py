#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Transformer-based model for processing hybrid features in ransomware detection.

This module implements a transformer architecture that can process and integrate
multiple types of features from various sources (binary PE data, API call sequences,
static analysis, etc.) to better capture long-distance dependencies and complex 
relationships between features.
"""

import os
import sys
import json
import logging
import pickle
from typing import Dict, List, Any, Tuple, Optional, Union, Set
import math
from datetime import datetime
import time

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader, random_split
from sklearn.metrics import classification_report, confusion_matrix

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


class MultiHeadSelfAttention(nn.Module):
    """Multi-head self-attention mechanism"""
    
    def __init__(self, embed_dim: int, num_heads: int, dropout: float = 0.1):
        """
        Initialize multi-head attention
        
        Args:
            embed_dim: Dimension of embedding
            num_heads: Number of attention heads
            dropout: Dropout probability
        """
        super().__init__()
        self.embed_dim = embed_dim
        self.num_heads = num_heads
        self.head_dim = embed_dim // num_heads
        
        assert self.head_dim * num_heads == embed_dim, "embed_dim must be divisible by num_heads"
        
        self.query = nn.Linear(embed_dim, embed_dim)
        self.key = nn.Linear(embed_dim, embed_dim)
        self.value = nn.Linear(embed_dim, embed_dim)
        
        self.output = nn.Linear(embed_dim, embed_dim)
        self.dropout = nn.Dropout(dropout)
    
    def forward(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        Forward pass
        
        Args:
            x: Input tensor of shape (batch_size, seq_len, embed_dim)
            mask: Optional attention mask of shape (batch_size, seq_len, seq_len)
            
        Returns:
            Output tensor of shape (batch_size, seq_len, embed_dim)
        """
        batch_size, seq_len, _ = x.size()
        
        # Linear projections and reshape for multi-head attention
        q = self.query(x).view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1, 2)
        k = self.key(x).view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1, 2)
        v = self.value(x).view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1, 2)
        
        # Compute attention scores
        scores = torch.matmul(q, k.transpose(-2, -1)) / math.sqrt(self.head_dim)
        
        # Apply mask if provided
        if mask is not None:
            scores = scores.masked_fill(mask == 0, -1e9)
        
        # Apply softmax and dropout
        attention = F.softmax(scores, dim=-1)
        attention = self.dropout(attention)
        
        # Apply attention to values
        context = torch.matmul(attention, v)
        
        # Reshape and apply output projection
        context = context.transpose(1, 2).contiguous().view(batch_size, seq_len, self.embed_dim)
        output = self.output(context)
        
        return output


class PositionwiseFeedForward(nn.Module):
    """Position-wise feed-forward network"""
    
    def __init__(self, embed_dim: int, ff_dim: int, dropout: float = 0.1):
        """
        Initialize feed-forward network
        
        Args:
            embed_dim: Dimension of embedding
            ff_dim: Dimension of feed-forward layer
            dropout: Dropout probability
        """
        super().__init__()
        self.linear1 = nn.Linear(embed_dim, ff_dim)
        self.linear2 = nn.Linear(ff_dim, embed_dim)
        self.dropout = nn.Dropout(dropout)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass
        
        Args:
            x: Input tensor of shape (batch_size, seq_len, embed_dim)
            
        Returns:
            Output tensor of shape (batch_size, seq_len, embed_dim)
        """
        return self.linear2(self.dropout(F.relu(self.linear1(x))))


class PositionalEncoding(nn.Module):
    """Positional encoding for transformer"""
    
    def __init__(self, embed_dim: int, max_seq_len: int = 1000, dropout: float = 0.1):
        """
        Initialize positional encoding
        
        Args:
            embed_dim: Dimension of embedding
            max_seq_len: Maximum sequence length
            dropout: Dropout probability
        """
        super().__init__()
        self.dropout = nn.Dropout(p=dropout)
        
        # Create positional encoding
        pe = torch.zeros(max_seq_len, embed_dim)
        position = torch.arange(0, max_seq_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, embed_dim, 2).float() * (-math.log(10000.0) / embed_dim))
        
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        
        # Register buffer to be saved with model
        self.register_buffer('pe', pe.unsqueeze(0))
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass
        
        Args:
            x: Input tensor of shape (batch_size, seq_len, embed_dim)
            
        Returns:
            Output tensor with positional encoding
        """
        x = x + self.pe[:, :x.size(1)]
        return self.dropout(x)


class TransformerEncoderLayer(nn.Module):
    """Transformer encoder layer"""
    
    def __init__(
        self, 
        embed_dim: int, 
        num_heads: int, 
        ff_dim: int, 
        dropout: float = 0.1
    ):
        """
        Initialize transformer encoder layer
        
        Args:
            embed_dim: Dimension of embedding
            num_heads: Number of attention heads
            ff_dim: Dimension of feed-forward layer
            dropout: Dropout probability
        """
        super().__init__()
        self.self_attn = MultiHeadSelfAttention(embed_dim, num_heads, dropout)
        self.feed_forward = PositionwiseFeedForward(embed_dim, ff_dim, dropout)
        
        self.norm1 = nn.LayerNorm(embed_dim)
        self.norm2 = nn.LayerNorm(embed_dim)
        
        self.dropout1 = nn.Dropout(dropout)
        self.dropout2 = nn.Dropout(dropout)
    
    def forward(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        Forward pass
        
        Args:
            x: Input tensor of shape (batch_size, seq_len, embed_dim)
            mask: Optional attention mask
            
        Returns:
            Output tensor of shape (batch_size, seq_len, embed_dim)
        """
        # Self-attention with residual connection and layer normalization
        attn_output = self.self_attn(x, mask)
        x = self.norm1(x + self.dropout1(attn_output))
        
        # Feed-forward with residual connection and layer normalization
        ff_output = self.feed_forward(x)
        x = self.norm2(x + self.dropout2(ff_output))
        
        return x


class FeatureEmbedding(nn.Module):
    """Feature embedding module for hybrid features"""
    
    def __init__(
        self,
        cnn_feature_dim: int,
        lstm_feature_dim: int,
        static_feature_dim: int,
        embed_dim: int,
        dropout: float = 0.1
    ):
        """
        Initialize feature embedding
        
        Args:
            cnn_feature_dim: Dimension of CNN features
            lstm_feature_dim: Dimension of LSTM features
            static_feature_dim: Dimension of static analysis features
            embed_dim: Dimension of embedding
            dropout: Dropout probability
        """
        super().__init__()
        
        # Linear projections for each feature type
        self.cnn_projection = nn.Linear(cnn_feature_dim, embed_dim)
        self.lstm_projection = nn.Linear(lstm_feature_dim, embed_dim)
        self.static_projection = nn.Linear(static_feature_dim, embed_dim)
        
        # Feature type embeddings (to differentiate feature sources)
        self.feature_type_embedding = nn.Embedding(3, embed_dim)
        
        self.dropout = nn.Dropout(dropout)
        
        # Layer normalization
        self.layer_norm = nn.LayerNorm(embed_dim)
    
    def forward(
        self,
        cnn_features: torch.Tensor,
        lstm_features: torch.Tensor,
        static_features: torch.Tensor
    ) -> torch.Tensor:
        """
        Forward pass
        
        Args:
            cnn_features: CNN features of shape (batch_size, cnn_feature_dim)
            lstm_features: LSTM features of shape (batch_size, lstm_feature_dim)
            static_features: Static features of shape (batch_size, static_feature_dim)
            
        Returns:
            Combined feature embeddings of shape (batch_size, 3, embed_dim)
        """
        batch_size = cnn_features.size(0)
        
        # Project features to embedding space
        cnn_embed = self.cnn_projection(cnn_features).unsqueeze(1)  # (batch_size, 1, embed_dim)
        lstm_embed = self.lstm_projection(lstm_features).unsqueeze(1)  # (batch_size, 1, embed_dim)
        static_embed = self.static_projection(static_features).unsqueeze(1)  # (batch_size, 1, embed_dim)
        
        # Concatenate feature embeddings
        features = torch.cat([cnn_embed, lstm_embed, static_embed], dim=1)  # (batch_size, 3, embed_dim)
        
        # Add feature type embeddings
        feature_types = torch.arange(3, device=features.device).expand(batch_size, 3)
        type_embeddings = self.feature_type_embedding(feature_types)
        
        # Combine feature embeddings with type embeddings
        features = features + type_embeddings
        
        # Apply dropout and layer normalization
        features = self.dropout(features)
        features = self.layer_norm(features)
        
        return features


class SequenceEmbedding(nn.Module):
    """Sequence embedding module for token sequences"""
    
    def __init__(
        self,
        vocab_size: int,
        embed_dim: int,
        max_seq_len: int = 500,
        dropout: float = 0.1,
        padding_idx: int = 0
    ):
        """
        Initialize sequence embedding
        
        Args:
            vocab_size: Size of vocabulary
            embed_dim: Dimension of embedding
            max_seq_len: Maximum sequence length
            dropout: Dropout probability
            padding_idx: Index used for padding
        """
        super().__init__()
        
        # Token embedding
        self.token_embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=padding_idx)
        
        # Positional encoding
        self.positional_encoding = PositionalEncoding(embed_dim, max_seq_len, dropout)
        
        self.dropout = nn.Dropout(dropout)
        
        # Layer normalization
        self.layer_norm = nn.LayerNorm(embed_dim)
        
        # Parameters
        self.embed_dim = embed_dim
    
    def forward(self, sequences: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        """
        Forward pass
        
        Args:
            sequences: Token sequences of shape (batch_size, seq_len)
            mask: Optional mask of shape (batch_size, seq_len)
            
        Returns:
            Sequence embeddings of shape (batch_size, seq_len, embed_dim)
        """
        # Apply token embedding
        embeddings = self.token_embedding(sequences) * math.sqrt(self.embed_dim)
        
        # Apply positional encoding
        embeddings = self.positional_encoding(embeddings)
        
        # Apply dropout and layer normalization
        embeddings = self.dropout(embeddings)
        embeddings = self.layer_norm(embeddings)
        
        return embeddings


class HybridTransformerModel(nn.Module):
    """
    Hybrid Transformer model for ransomware detection
    
    This model combines features from different sources (CNN, LSTM, static analysis)
    and processes them using a transformer architecture to capture complex relationships
    between features.
    """
    
    def __init__(
        self,
        cnn_feature_dim: int,
        lstm_feature_dim: int,
        static_feature_dim: int,
        embed_dim: int,
        num_heads: int,
        ff_dim: int,
        num_layers: int,
        dropout: float = 0.1,
        sequence_embedding: Optional[SequenceEmbedding] = None
    ):
        """
        Initialize hybrid transformer model
        
        Args:
            cnn_feature_dim: Dimension of CNN features
            lstm_feature_dim: Dimension of LSTM features
            static_feature_dim: Dimension of static analysis features
            embed_dim: Dimension of embedding
            num_heads: Number of attention heads
            ff_dim: Dimension of feed-forward layer
            num_layers: Number of transformer layers
            dropout: Dropout probability
            sequence_embedding: Optional sequence embedding module
        """
        super().__init__()
        
        # Feature embedding module
        self.feature_embedding = FeatureEmbedding(
            cnn_feature_dim=cnn_feature_dim,
            lstm_feature_dim=lstm_feature_dim,
            static_feature_dim=static_feature_dim,
            embed_dim=embed_dim,
            dropout=dropout
        )
        
        # Sequence embedding module
        self.sequence_embedding = sequence_embedding
        
        # Transformer encoder layers
        self.layers = nn.ModuleList([
            TransformerEncoderLayer(
                embed_dim=embed_dim,
                num_heads=num_heads,
                ff_dim=ff_dim,
                dropout=dropout
            )
            for _ in range(num_layers)
        ])
        
        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(embed_dim, embed_dim // 2),
            nn.LayerNorm(embed_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(embed_dim // 2, 1)
        )
        
        # Feature extraction head
        self.feature_extractor = nn.Linear(embed_dim, embed_dim)
        
        # Store parameters
        self.embed_dim = embed_dim
        self.num_heads = num_heads
        self.ff_dim = ff_dim
        self.num_layers = num_layers
        self.dropout_prob = dropout
    
    def forward(
        self,
        cnn_features: torch.Tensor,
        lstm_features: torch.Tensor,
        static_features: torch.Tensor,
        sequences: Optional[torch.Tensor] = None,
        sequence_mask: Optional[torch.Tensor] = None,
        return_features: bool = False,
        return_attention: bool = False
    ) -> Union[torch.Tensor, Tuple[torch.Tensor, torch.Tensor], Tuple[torch.Tensor, torch.Tensor, torch.Tensor]]:
        """
        Forward pass
        
        Args:
            cnn_features: CNN features of shape (batch_size, cnn_feature_dim)
            lstm_features: LSTM features of shape (batch_size, lstm_feature_dim)
            static_features: Static features of shape (batch_size, static_feature_dim)
            sequences: Optional token sequences of shape (batch_size, seq_len)
            sequence_mask: Optional sequence mask of shape (batch_size, seq_len)
            return_features: Whether to return feature embeddings
            return_attention: Whether to return attention weights
            
        Returns:
            Model outputs depending on return_features and return_attention
        """
        # Get feature embeddings
        feature_embed = self.feature_embedding(cnn_features, lstm_features, static_features)
        
        # Include sequence embedding if provided
        if self.sequence_embedding is not None and sequences is not None:
            seq_embed = self.sequence_embedding(sequences, sequence_mask)
            
            # Combine feature and sequence embeddings
            x = torch.cat([feature_embed, seq_embed], dim=1)
        else:
            x = feature_embed
        
        # Prepare attention mask
        batch_size, seq_len, _ = x.size()
        
        if sequence_mask is not None:
            # Extend mask to full sequence length (feature_embed + seq_embed)
            feature_mask = torch.ones(batch_size, feature_embed.size(1), device=x.device)
            full_mask = torch.cat([feature_mask, sequence_mask], dim=1)
            
            # Create attention mask
            mask = torch.zeros(batch_size, seq_len, seq_len, device=x.device)
            
            for i in range(batch_size):
                # Set attention mask based on sequence mask
                valid_len = full_mask[i].sum().int()
                mask[i, :valid_len, :valid_len] = 1
        else:
            # No mask
            mask = None
        
        # Store attention weights if requested
        attention_weights = []
        
        # Apply transformer layers
        for layer in self.layers:
            x = layer(x, mask)
            
            # Store attention weights if requested
            if return_attention and hasattr(layer.self_attn, 'attention'):
                attention_weights.append(layer.self_attn.attention)
        
        # Global average pooling
        x = x.mean(dim=1)
        
        # Extract features
        features = self.feature_extractor(x)
        
        # Classification
        output = self.classifier(x)
        
        # Return outputs based on parameters
        if return_features and return_attention:
            return output, features, attention_weights
        elif return_features:
            return output, features
        elif return_attention:
            return output, attention_weights
        else:
            return output


class HybridDataset(Dataset):
    """Dataset for hybrid transformer model"""
    
    def __init__(
        self,
        cnn_features: List[np.ndarray],
        lstm_features: List[np.ndarray],
        static_features: List[np.ndarray],
        labels: Optional[List[int]] = None,
        sequences: Optional[List[List[int]]] = None,
        max_seq_len: int = 500
    ):
        """
        Initialize hybrid dataset
        
        Args:
            cnn_features: List of CNN feature arrays
            lstm_features: List of LSTM feature arrays
            static_features: List of static feature arrays
            labels: Optional list of labels (1 for ransomware, 0 for benign)
            sequences: Optional list of token sequences
            max_seq_len: Maximum sequence length
        """
        # Check that all feature lists have the same length
        assert len(cnn_features) == len(lstm_features) == len(static_features), \
            "All feature lists must have the same length"
        
        if labels is not None:
            assert len(cnn_features) == len(labels), "Features and labels must have the same length"
        
        if sequences is not None:
            assert len(cnn_features) == len(sequences), "Features and sequences must have the same length"
        
        self.cnn_features = cnn_features
        self.lstm_features = lstm_features
        self.static_features = static_features
        self.labels = labels
        self.sequences = sequences
        self.max_seq_len = max_seq_len
    
    def __len__(self):
        return len(self.cnn_features)
    
    def __getitem__(self, idx):
        # Get features
        cnn_feature = torch.tensor(self.cnn_features[idx], dtype=torch.float)
        lstm_feature = torch.tensor(self.lstm_features[idx], dtype=torch.float)
        static_feature = torch.tensor(self.static_features[idx], dtype=torch.float)
        
        # Get sequence if available
        if self.sequences is not None:
            sequence = self.sequences[idx]
            
            # Truncate or pad sequence
            if len(sequence) > self.max_seq_len:
                sequence = sequence[:self.max_seq_len]
            else:
                sequence = sequence + [0] * (self.max_seq_len - len(sequence))
            
            sequence_tensor = torch.tensor(sequence, dtype=torch.long)
            sequence_mask = (sequence_tensor != 0).float()
        else:
            sequence_tensor = None
            sequence_mask = None
        
        # Get label if available
        if self.labels is not None:
            label = self.labels[idx]
            label_tensor = torch.tensor(label, dtype=torch.float)
            
            if sequence_tensor is not None:
                return (cnn_feature, lstm_feature, static_feature, sequence_tensor, sequence_mask, label_tensor)
            else:
                return (cnn_feature, lstm_feature, static_feature, label_tensor)
        else:
            if sequence_tensor is not None:
                return (cnn_feature, lstm_feature, static_feature, sequence_tensor, sequence_mask)
            else:
                return (cnn_feature, lstm_feature, static_feature)


class HybridTransformerAnalyzer:
    """
    Hybrid Transformer Analyzer for ransomware detection
    
    This class provides a high-level interface for using the hybrid transformer
    model for ransomware detection.
    """
    
    def __init__(
        self,
        cnn_feature_dim: int,
        lstm_feature_dim: int,
        static_feature_dim: int,
        embed_dim: int = 128,
        num_heads: int = 8,
        ff_dim: int = 256,
        num_layers: int = 4,
        dropout: float = 0.1,
        learning_rate: float = 0.001,
        weight_decay: float = 1e-5,
        batch_size: int = 32,
        device: Optional[str] = None,
        model: Optional[HybridTransformerModel] = None,
        sequence_embedding: Optional[SequenceEmbedding] = None
    ):
        """
        Initialize hybrid transformer analyzer
        
        Args:
            cnn_feature_dim: Dimension of CNN features
            lstm_feature_dim: Dimension of LSTM features
            static_feature_dim: Dimension of static analysis features
            embed_dim: Dimension of embedding
            num_heads: Number of attention heads
            ff_dim: Dimension of feed-forward layer
            num_layers: Number of transformer layers
            dropout: Dropout probability
            learning_rate: Learning rate for optimizer
            weight_decay: Weight decay for optimizer
            batch_size: Batch size for training and inference
            device: Device to use for computation
            model: Optional pre-initialized model
            sequence_embedding: Optional sequence embedding module
        """
        # Set device
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Store parameters
        self.cnn_feature_dim = cnn_feature_dim
        self.lstm_feature_dim = lstm_feature_dim
        self.static_feature_dim = static_feature_dim
        self.embed_dim = embed_dim
        self.num_heads = num_heads
        self.ff_dim = ff_dim
        self.num_layers = num_layers
        self.dropout = dropout
        self.learning_rate = learning_rate
        self.weight_decay = weight_decay
        self.batch_size = batch_size
        
        # Initialize model
        if model is not None:
            self.model = model
        else:
            self.model = HybridTransformerModel(
                cnn_feature_dim=cnn_feature_dim,
                lstm_feature_dim=lstm_feature_dim,
                static_feature_dim=static_feature_dim,
                embed_dim=embed_dim,
                num_heads=num_heads,
                ff_dim=ff_dim,
                num_layers=num_layers,
                dropout=dropout,
                sequence_embedding=sequence_embedding
            )
        
        # Move model to device
        self.model.to(self.device)
        
        # Initialize optimizer
        self.optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=learning_rate,
            weight_decay=weight_decay
        )
        
        # Initialize sequence embedding
        self.sequence_embedding = sequence_embedding
    
    def train(
        self,
        train_dataset: HybridDataset,
        val_dataset: Optional[HybridDataset] = None,
        epochs: int = 10,
        patience: int = 3,
        model_save_path: Optional[str] = None
    ) -> Dict[str, List[float]]:
        """
        Train the model
        
        Args:
            train_dataset: Training dataset
            val_dataset: Optional validation dataset
            epochs: Number of training epochs
            patience: Patience for early stopping
            model_save_path: Optional path to save the best model
            
        Returns:
            Dictionary with training history
        """
        # Set model to training mode
        self.model.train()
        
        # Initialize data loaders
        train_loader = DataLoader(
            train_dataset,
            batch_size=self.batch_size,
            shuffle=True,
            num_workers=0
        )
        
        if val_dataset:
            val_loader = DataLoader(
                val_dataset,
                batch_size=self.batch_size,
                shuffle=False,
                num_workers=0
            )
        else:
            val_loader = None
        
        # Initialize loss function
        criterion = nn.BCEWithLogitsLoss()
        
        # Initialize training history
        history = {
            'train_loss': [],
            'train_acc': [],
            'val_loss': [],
            'val_acc': []
        }
        
        # Initialize early stopping variables
        best_val_loss = float('inf')
        no_improvement = 0
        
        # Training loop
        for epoch in range(epochs):
            # Initialize metrics
            train_loss = 0.0
            train_correct = 0
            train_total = 0
            
            # Training step
            for batch in train_loader:
                # Move batch to device
                if len(batch) == 4:  # No sequence data
                    cnn_features, lstm_features, static_features, labels = batch
                    cnn_features = cnn_features.to(self.device)
                    lstm_features = lstm_features.to(self.device)
                    static_features = static_features.to(self.device)
                    labels = labels.to(self.device)
                    
                    # Forward pass
                    outputs = self.model(cnn_features, lstm_features, static_features)
                else:  # With sequence data
                    cnn_features, lstm_features, static_features, sequences, sequence_mask, labels = batch
                    cnn_features = cnn_features.to(self.device)
                    lstm_features = lstm_features.to(self.device)
                    static_features = static_features.to(self.device)
                    sequences = sequences.to(self.device)
                    sequence_mask = sequence_mask.to(self.device)
                    labels = labels.to(self.device)
                    
                    # Forward pass
                    outputs = self.model(cnn_features, lstm_features, static_features, sequences, sequence_mask)
                
                # Compute loss
                loss = criterion(outputs.squeeze(), labels)
                
                # Backward pass and optimize
                self.optimizer.zero_grad()
                loss.backward()
                self.optimizer.step()
                
                # Update metrics
                train_loss += loss.item() * labels.size(0)
                train_total += labels.size(0)
                
                # Compute accuracy
                predictions = (torch.sigmoid(outputs) >= 0.5).float()
                train_correct += (predictions.squeeze() == labels).sum().item()
            
            # Compute epoch metrics
            epoch_train_loss = train_loss / train_total
            epoch_train_acc = train_correct / train_total
            
            # Update history
            history['train_loss'].append(epoch_train_loss)
            history['train_acc'].append(epoch_train_acc)
            
            # Validation step
            if val_loader:
                val_loss, val_acc = self._validate(val_loader, criterion)
                
                # Update history
                history['val_loss'].append(val_loss)
                history['val_acc'].append(val_acc)
                
                # Print epoch metrics
                logger.info(f"Epoch {epoch+1}/{epochs}: "
                           f"Train Loss: {epoch_train_loss:.4f}, Train Acc: {epoch_train_acc:.4f}, "
                           f"Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}")
                
                # Check for improvement
                if val_loss < best_val_loss:
                    best_val_loss = val_loss
                    no_improvement = 0
                    
                    # Save best model if path provided
                    if model_save_path:
                        self.save(model_save_path)
                        logger.info(f"Saved best model to {model_save_path}")
                else:
                    no_improvement += 1
                
                # Early stopping
                if no_improvement >= patience:
                    logger.info(f"Early stopping after {epoch+1} epochs")
                    break
            else:
                # Print epoch metrics
                logger.info(f"Epoch {epoch+1}/{epochs}: "
                           f"Train Loss: {epoch_train_loss:.4f}, Train Acc: {epoch_train_acc:.4f}")
        
        # Load best model if validation was used and path was provided
        if val_loader and model_save_path and os.path.exists(model_save_path):
            self.load(model_save_path)
            logger.info(f"Loaded best model from {model_save_path}")
        
        return history
    
    def _validate(self, val_loader: DataLoader, criterion: nn.Module) -> Tuple[float, float]:
        """
        Validate the model
        
        Args:
            val_loader: Validation data loader
            criterion: Loss function
            
        Returns:
            Tuple of (validation loss, validation accuracy)
        """
        # Set model to evaluation mode
        self.model.eval()
        
        # Initialize metrics
        val_loss = 0.0
        val_correct = 0
        val_total = 0
        
        # Validation loop
        with torch.no_grad():
            for batch in val_loader:
                # Move batch to device
                if len(batch) == 4:  # No sequence data
                    cnn_features, lstm_features, static_features, labels = batch
                    cnn_features = cnn_features.to(self.device)
                    lstm_features = lstm_features.to(self.device)
                    static_features = static_features.to(self.device)
                    labels = labels.to(self.device)
                    
                    # Forward pass
                    outputs = self.model(cnn_features, lstm_features, static_features)
                else:  # With sequence data
                    cnn_features, lstm_features, static_features, sequences, sequence_mask, labels = batch
                    cnn_features = cnn_features.to(self.device)
                    lstm_features = lstm_features.to(self.device)
                    static_features = static_features.to(self.device)
                    sequences = sequences.to(self.device)
                    sequence_mask = sequence_mask.to(self.device)
                    labels = labels.to(self.device)
                    
                    # Forward pass
                    outputs = self.model(cnn_features, lstm_features, static_features, sequences, sequence_mask)
                
                # Compute loss
                loss = criterion(outputs.squeeze(), labels)
                
                # Update metrics
                val_loss += loss.item() * labels.size(0)
                val_total += labels.size(0)
                
                # Compute accuracy
                predictions = (torch.sigmoid(outputs) >= 0.5).float()
                val_correct += (predictions.squeeze() == labels).sum().item()
        
        # Compute epoch metrics
        epoch_val_loss = val_loss / val_total
        epoch_val_acc = val_correct / val_total
        
        # Set model back to training mode
        self.model.train()
        
        return epoch_val_loss, epoch_val_acc
    
    def predict(
        self,
        test_dataset: HybridDataset,
        return_probabilities: bool = False
    ) -> Union[List[int], List[float]]:
        """
        Make predictions
        
        Args:
            test_dataset: Test dataset
            return_probabilities: Whether to return probabilities instead of binary predictions
            
        Returns:
            List of predictions or probabilities
        """
        # Set model to evaluation mode
        self.model.eval()
        
        # Initialize data loader
        test_loader = DataLoader(
            test_dataset,
            batch_size=self.batch_size,
            shuffle=False,
            num_workers=0
        )
        
        # Initialize predictions
        predictions = []
        
        # Prediction loop
        with torch.no_grad():
            for batch in test_loader:
                # Move batch to device
                if len(batch) == 3:  # No sequence data, no labels
                    cnn_features, lstm_features, static_features = batch
                    cnn_features = cnn_features.to(self.device)
                    lstm_features = lstm_features.to(self.device)
                    static_features = static_features.to(self.device)
                    
                    # Forward pass
                    outputs = self.model(cnn_features, lstm_features, static_features)
                elif len(batch) == 4:  # No sequence data, with labels
                    cnn_features, lstm_features, static_features, _ = batch
                    cnn_features = cnn_features.to(self.device)
                    lstm_features = lstm_features.to(self.device)
                    static_features = static_features.to(self.device)
                    
                    # Forward pass
                    outputs = self.model(cnn_features, lstm_features, static_features)
                elif len(batch) == 5:  # With sequence data, no labels
                    cnn_features, lstm_features, static_features, sequences, sequence_mask = batch
                    cnn_features = cnn_features.to(self.device)
                    lstm_features = lstm_features.to(self.device)
                    static_features = static_features.to(self.device)
                    sequences = sequences.to(self.device)
                    sequence_mask = sequence_mask.to(self.device)
                    
                    # Forward pass
                    outputs = self.model(cnn_features, lstm_features, static_features, sequences, sequence_mask)
                else:  # With sequence data, with labels
                    cnn_features, lstm_features, static_features, sequences, sequence_mask, _ = batch
                    cnn_features = cnn_features.to(self.device)
                    lstm_features = lstm_features.to(self.device)
                    static_features = static_features.to(self.device)
                    sequences = sequences.to(self.device)
                    sequence_mask = sequence_mask.to(self.device)
                    
                    # Forward pass
                    outputs = self.model(cnn_features, lstm_features, static_features, sequences, sequence_mask)
                
                # Get predictions or probabilities
                if return_probabilities:
                    probs = torch.sigmoid(outputs).squeeze().cpu().numpy()
                    predictions.extend(probs.tolist() if probs.ndim > 0 else [probs.item()])
                else:
                    preds = (torch.sigmoid(outputs) >= 0.5).float().squeeze().cpu().numpy()
                    predictions.extend(preds.tolist() if preds.ndim > 0 else [preds.item()])
        
        return predictions
    
    def extract_features(self, test_dataset: HybridDataset) -> np.ndarray:
        """
        Extract features
        
        Args:
            test_dataset: Test dataset
            
        Returns:
            Array of extracted features
        """
        # Set model to evaluation mode
        self.model.eval()
        
        # Initialize data loader
        test_loader = DataLoader(
            test_dataset,
            batch_size=self.batch_size,
            shuffle=False,
            num_workers=0
        )
        
        # Initialize features
        features_list = []
        
        # Feature extraction loop
        with torch.no_grad():
            for batch in test_loader:
                # Move batch to device
                if len(batch) == 3:  # No sequence data, no labels
                    cnn_features, lstm_features, static_features = batch
                    cnn_features = cnn_features.to(self.device)
                    lstm_features = lstm_features.to(self.device)
                    static_features = static_features.to(self.device)
                    
                    # Forward pass with feature extraction
                    _, features = self.model(cnn_features, lstm_features, static_features, return_features=True)
                elif len(batch) == 4:  # No sequence data, with labels
                    cnn_features, lstm_features, static_features, _ = batch
                    cnn_features = cnn_features.to(self.device)
                    lstm_features = lstm_features.to(self.device)
                    static_features = static_features.to(self.device)
                    
                    # Forward pass with feature extraction
                    _, features = self.model(cnn_features, lstm_features, static_features, return_features=True)
                elif len(batch) == 5:  # With sequence data, no labels
                    cnn_features, lstm_features, static_features, sequences, sequence_mask = batch
                    cnn_features = cnn_features.to(self.device)
                    lstm_features = lstm_features.to(self.device)
                    static_features = static_features.to(self.device)
                    sequences = sequences.to(self.device)
                    sequence_mask = sequence_mask.to(self.device)
                    
                    # Forward pass with feature extraction
                    _, features = self.model(
                        cnn_features, lstm_features, static_features, 
                        sequences, sequence_mask, return_features=True
                    )
                else:  # With sequence data, with labels
                    cnn_features, lstm_features, static_features, sequences, sequence_mask, _ = batch
                    cnn_features = cnn_features.to(self.device)
                    lstm_features = lstm_features.to(self.device)
                    static_features = static_features.to(self.device)
                    sequences = sequences.to(self.device)
                    sequence_mask = sequence_mask.to(self.device)
                    
                    # Forward pass with feature extraction
                    _, features = self.model(
                        cnn_features, lstm_features, static_features, 
                        sequences, sequence_mask, return_features=True
                    )
                
                # Add to features list
                features_list.append(features.cpu().numpy())
        
        # Concatenate features
        if features_list:
            return np.vstack(features_list)
        else:
            return np.array([])
    
    def analyze_attention(self, test_dataset: HybridDataset) -> Dict[str, Any]:
        """
        Analyze attention weights
        
        Args:
            test_dataset: Test dataset
            
        Returns:
            Dictionary with attention analysis results
        """
        # Set model to evaluation mode
        self.model.eval()
        
        # Initialize data loader (batch size 1 for easier analysis)
        test_loader = DataLoader(
            test_dataset,
            batch_size=1,
            shuffle=False,
            num_workers=0
        )
        
        # Initialize results
        results = []
        
        # Analysis loop
        with torch.no_grad():
            for i, batch in enumerate(test_loader):
                # Move batch to device
                if len(batch) == 3 or len(batch) == 4:  # No sequence data
                    logger.warning("Attention analysis requires sequence data")
                    return {"error": "Attention analysis requires sequence data"}
                else:  # With sequence data
                    if len(batch) == 6:  # With labels
                        cnn_features, lstm_features, static_features, sequences, sequence_mask, labels = batch
                        label = labels.item()
                    else:  # No labels
                        cnn_features, lstm_features, static_features, sequences, sequence_mask = batch
                        label = None
                    
                    cnn_features = cnn_features.to(self.device)
                    lstm_features = lstm_features.to(self.device)
                    static_features = static_features.to(self.device)
                    sequences = sequences.to(self.device)
                    sequence_mask = sequence_mask.to(self.device)
                    
                    # Forward pass with attention
                    _, attention_weights = self.model(
                        cnn_features, lstm_features, static_features, 
                        sequences, sequence_mask, return_attention=True
                    )
                    
                    # Get non-padding tokens
                    valid_length = sequence_mask.sum().int().item()
                    
                    # Get attention from last layer (typically most interpretable)
                    if attention_weights:
                        last_attention = attention_weights[-1][0].cpu().numpy()  # (num_heads, seq_len, seq_len)
                        
                        # Average across heads
                        avg_attention = last_attention.mean(axis=0)  # (seq_len, seq_len)
                        
                        # Get attention to feature tokens (first 3 tokens)
                        feature_attention = avg_attention[:3, 3:valid_length]  # (3, valid_length - 3)
                        
                        # Get attention between sequence tokens
                        seq_attention = avg_attention[3:valid_length, 3:valid_length]  # (valid_length - 3, valid_length - 3)
                        
                        results.append({
                            "sample_idx": i,
                            "label": label,
                            "feature_attention": feature_attention.tolist(),
                            "seq_attention": seq_attention.tolist(),
                            "valid_length": valid_length - 3  # Exclude feature tokens
                        })
                    else:
                        logger.warning("No attention weights returned from model")
        
        return {"attention_analysis": results}
    
    def save(self, path: str):
        """
        Save model to file
        
        Args:
            path: Path to save model
        """
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        # Save model
        torch.save({
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'model_params': {
                'cnn_feature_dim': self.cnn_feature_dim,
                'lstm_feature_dim': self.lstm_feature_dim,
                'static_feature_dim': self.static_feature_dim,
                'embed_dim': self.embed_dim,
                'num_heads': self.num_heads,
                'ff_dim': self.ff_dim,
                'num_layers': self.num_layers,
                'dropout': self.dropout
            }
        }, path)
        
        logger.info(f"Model saved to {path}")
    
    def load(self, path: str):
        """
        Load model from file
        
        Args:
            path: Path to load model from
        """
        # Load checkpoint
        checkpoint = torch.load(path, map_location=self.device)
        
        # Load model parameters
        model_params = checkpoint['model_params']
        
        # Create new model if parameters don't match
        if (model_params['cnn_feature_dim'] != self.cnn_feature_dim or
            model_params['lstm_feature_dim'] != self.lstm_feature_dim or
            model_params['static_feature_dim'] != self.static_feature_dim or
            model_params['embed_dim'] != self.embed_dim or
            model_params['num_heads'] != self.num_heads or
            model_params['ff_dim'] != self.ff_dim or
            model_params['num_layers'] != self.num_layers):
            
            logger.warning("Model parameters don't match, creating new model with loaded parameters")
            
            # Update parameters
            self.cnn_feature_dim = model_params['cnn_feature_dim']
            self.lstm_feature_dim = model_params['lstm_feature_dim']
            self.static_feature_dim = model_params['static_feature_dim']
            self.embed_dim = model_params['embed_dim']
            self.num_heads = model_params['num_heads']
            self.ff_dim = model_params['ff_dim']
            self.num_layers = model_params['num_layers']
            self.dropout = model_params['dropout']
            
            # Create new model
            self.model = HybridTransformerModel(
                cnn_feature_dim=self.cnn_feature_dim,
                lstm_feature_dim=self.lstm_feature_dim,
                static_feature_dim=self.static_feature_dim,
                embed_dim=self.embed_dim,
                num_heads=self.num_heads,
                ff_dim=self.ff_dim,
                num_layers=self.num_layers,
                dropout=self.dropout,
                sequence_embedding=self.sequence_embedding
            )
            
            # Move model to device
            self.model.to(self.device)
            
            # Initialize optimizer
            self.optimizer = torch.optim.AdamW(
                self.model.parameters(),
                lr=self.learning_rate,
                weight_decay=self.weight_decay
            )
        
        # Load model state
        self.model.load_state_dict(checkpoint['model_state_dict'])
        
        # Load optimizer state
        if 'optimizer_state_dict' in checkpoint:
            self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        
        logger.info(f"Model loaded from {path}")
    
    @classmethod
    def create_sequence_embedding(
        cls,
        vocab_size: int,
        embed_dim: int,
        max_seq_len: int = 500,
        dropout: float = 0.1,
        padding_idx: int = 0
    ) -> SequenceEmbedding:
        """
        Create sequence embedding module
        
        Args:
            vocab_size: Size of vocabulary
            embed_dim: Dimension of embedding
            max_seq_len: Maximum sequence length
            dropout: Dropout probability
            padding_idx: Index used for padding
            
        Returns:
            Sequence embedding module
        """
        return SequenceEmbedding(
            vocab_size=vocab_size,
            embed_dim=embed_dim,
            max_seq_len=max_seq_len,
            dropout=dropout,
            padding_idx=padding_idx
        )