#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LSTM-based sequence analyzer for ransomware detection.
This module analyzes execution sequences to identify temporal behavior patterns
characteristic of ransomware activity.
"""

import os
import json
import pickle
import logging
import numpy as np
from typing import List, Dict, Tuple, Union, Optional, Any

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader

from tqdm import tqdm

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

class SequenceDataset(Dataset):
    """Dataset for sequence data processing"""
    
    def __init__(
        self, 
        sequences: List[List[int]], 
        labels: Optional[List[int]] = None, 
        max_length: int = 500, 
        vocab_size: int = None
    ):
        """
        Initialize sequence dataset
        
        Args:
            sequences: List of tokenized sequences
            labels: Optional sequence labels (1 for ransomware, 0 for benign)
            max_length: Maximum sequence length (will be padded/truncated)
            vocab_size: Size of vocabulary (number of unique tokens)
        """
        self.sequences = sequences
        self.labels = labels
        self.max_length = max_length
        self.vocab_size = vocab_size or max(max(seq) for seq in sequences) + 1
        
        if labels is not None and len(sequences) != len(labels):
            raise ValueError("Number of sequences and labels must match")
    
    def __len__(self):
        return len(self.sequences)
    
    def __getitem__(self, idx):
        sequence = self.sequences[idx]
        
        # Truncate or pad sequence to max_length
        if len(sequence) > self.max_length:
            sequence = sequence[:self.max_length]
        else:
            sequence = sequence + [0] * (self.max_length - len(sequence))
        
        # Convert to tensor
        sequence_tensor = torch.tensor(sequence, dtype=torch.long)
        
        if self.labels is not None:
            label = self.labels[idx]
            label_tensor = torch.tensor(label, dtype=torch.float)
            return sequence_tensor, label_tensor
        
        return sequence_tensor


class SequenceLSTMModel(nn.Module):
    """LSTM model for sequence analysis"""
    
    def __init__(
        self,
        vocab_size: int,
        embedding_dim: int = 64,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.2,
        bidirectional: bool = True,
        output_dim: int = 1,
        max_seq_length: int = 500
    ):
        """
        Initialize LSTM model for sequence analysis
        
        Args:
            vocab_size: Size of the vocabulary
            embedding_dim: Dimension of token embeddings
            hidden_dim: Dimension of LSTM hidden states
            num_layers: Number of LSTM layers
            dropout: Dropout probability
            bidirectional: Whether to use bidirectional LSTM
            output_dim: Output dimension (1 for binary classification)
            max_seq_length: Maximum sequence length
        """
        super(SequenceLSTMModel, self).__init__()
        
        self.vocab_size = vocab_size
        self.embedding_dim = embedding_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.bidirectional = bidirectional
        self.output_dim = output_dim
        self.max_seq_length = max_seq_length
        
        # Embedding layer
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        
        # LSTM layer
        self.lstm = nn.LSTM(
            embedding_dim,
            hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0,
            bidirectional=bidirectional
        )
        
        # Attention mechanism
        self.attention = nn.Linear(
            hidden_dim * 2 if bidirectional else hidden_dim, 1
        )
        
        # Output layer for classification or feature extraction
        self.fc = nn.Linear(
            hidden_dim * 2 if bidirectional else hidden_dim, 
            output_dim
        )
        
        # Dropout
        self.dropout = nn.Dropout(dropout)
    
    def forward(
        self, 
        x: torch.Tensor, 
        return_features: bool = False,
        return_attention: bool = False
    ):
        """
        Forward pass through the model
        
        Args:
            x: Input sequence tensor of shape (batch_size, seq_length)
            return_features: Whether to return features instead of predictions
            return_attention: Whether to return attention weights
            
        Returns:
            Predictions, features, or attention weights based on parameters
        """
        # Embedding layer
        embedded = self.embedding(x)  # (batch_size, seq_length, embedding_dim)
        
        # Create mask for padding (value 0)
        mask = (x != 0).float()  # (batch_size, seq_length)
        
        # LSTM layer
        lstm_out, (hidden, cell) = self.lstm(embedded)
        # lstm_out: (batch_size, seq_length, hidden_dim*2 if bidirectional else hidden_dim)
        
        # Attention mechanism
        attention_weights = self.attention(lstm_out).squeeze(-1)  # (batch_size, seq_length)
        
        # Apply mask to attention weights
        attention_weights = attention_weights.masked_fill(mask == 0, -1e10)
        attention_weights = F.softmax(attention_weights, dim=1)  # (batch_size, seq_length)
        
        # Apply attention to LSTM outputs
        context = torch.bmm(
            attention_weights.unsqueeze(1), 
            lstm_out
        ).squeeze(1)  # (batch_size, hidden_dim*2 if bidirectional else hidden_dim)
        
        # Apply dropout
        context = self.dropout(context)
        
        # Features (for feature extraction)
        features = context
        
        # Output layer
        output = self.fc(features)
        
        if return_features and return_attention:
            return output, features, attention_weights
        elif return_features:
            return output, features
        elif return_attention:
            return output, attention_weights
        
        return output


class SequenceTokenizer:
    """Tokenizer for converting API call sequences to token indices"""
    
    def __init__(self, vocab: Optional[Dict[str, int]] = None):
        """
        Initialize tokenizer
        
        Args:
            vocab: Optional predefined vocabulary mapping API calls to token indices
        """
        self.vocab = vocab or {}
        self.inverse_vocab = {v: k for k, v in self.vocab.items()} if vocab else {}
        self.unk_token = "<UNK>"
        
        if self.vocab and self.unk_token not in self.vocab:
            self.vocab[self.unk_token] = len(self.vocab)
            self.inverse_vocab[len(self.inverse_vocab)] = self.unk_token
    
    def fit(self, sequences: List[List[str]]):
        """
        Build vocabulary from sequences
        
        Args:
            sequences: List of API call sequences
        """
        if self.vocab:
            logger.warning("Vocabulary already exists. Using existing vocabulary.")
            return
        
        unique_tokens = set()
        for sequence in sequences:
            unique_tokens.update(sequence)
        
        # Create vocabulary
        self.vocab = {token: idx + 1 for idx, token in enumerate(sorted(unique_tokens))}
        self.vocab[self.unk_token] = 0
        self.inverse_vocab = {v: k for k, v in self.vocab.items()}
    
    def encode(self, sequence: List[str]) -> List[int]:
        """
        Encode a sequence of API calls to token indices
        
        Args:
            sequence: List of API calls
            
        Returns:
            List of token indices
        """
        if not self.vocab:
            raise ValueError("Vocabulary not initialized. Call fit() first.")
        
        return [self.vocab.get(token, self.vocab[self.unk_token]) for token in sequence]
    
    def decode(self, indices: List[int]) -> List[str]:
        """
        Decode token indices back to API calls
        
        Args:
            indices: List of token indices
            
        Returns:
            List of API calls
        """
        return [self.inverse_vocab.get(idx, self.unk_token) for idx in indices]
    
    def save(self, path: str):
        """
        Save tokenizer vocabulary to file
        
        Args:
            path: Path to save vocabulary
        """
        with open(path, 'wb') as f:
            pickle.dump({
                'vocab': self.vocab,
                'inverse_vocab': self.inverse_vocab
            }, f)
    
    @classmethod
    def load(cls, path: str) -> 'SequenceTokenizer':
        """
        Load tokenizer from file
        
        Args:
            path: Path to load vocabulary from
            
        Returns:
            Loaded tokenizer
        """
        with open(path, 'rb') as f:
            data = pickle.load(f)
        
        tokenizer = cls(vocab=data['vocab'])
        tokenizer.inverse_vocab = data['inverse_vocab']
        return tokenizer


class SequenceExtractor:
    """Extracts API call sequences from execution logs"""
    
    def __init__(
        self, 
        log_parser=None, 
        max_sequence_length: int = 500,
        api_whitelist: Optional[List[str]] = None,
        tokenizer: Optional[SequenceTokenizer] = None
    ):
        """
        Initialize sequence extractor
        
        Args:
            log_parser: Parser for execution logs
            max_sequence_length: Maximum sequence length
            api_whitelist: Optional list of API calls to include
            tokenizer: Optional tokenizer for encoding sequences
        """
        self.log_parser = log_parser
        self.max_sequence_length = max_sequence_length
        self.api_whitelist = set(api_whitelist) if api_whitelist else None
        self.tokenizer = tokenizer or SequenceTokenizer()
    
    def extract_from_log(self, log_path: str) -> List[str]:
        """
        Extract API call sequence from execution log
        
        Args:
            log_path: Path to execution log
            
        Returns:
            List of API calls
        """
        if self.log_parser:
            # Use provided log parser if available
            return self.log_parser.parse(log_path)
        
        # Simple default parser for JSON execution logs
        try:
            with open(log_path, 'r') as f:
                log_data = json.load(f)
            
            if isinstance(log_data, list):
                # Assuming a list of API call records
                sequence = [
                    entry["api_name"] 
                    for entry in log_data 
                    if "api_name" in entry and (
                        self.api_whitelist is None or 
                        entry["api_name"] in self.api_whitelist
                    )
                ]
            elif isinstance(log_data, dict) and "api_calls" in log_data:
                # Assuming a dict with an "api_calls" key
                sequence = [
                    entry["api_name"] 
                    for entry in log_data["api_calls"] 
                    if "api_name" in entry and (
                        self.api_whitelist is None or 
                        entry["api_name"] in self.api_whitelist
                    )
                ]
            else:
                logger.error(f"Unsupported log format in {log_path}")
                sequence = []
                
            # Truncate if needed
            if len(sequence) > self.max_sequence_length:
                sequence = sequence[:self.max_sequence_length]
                
            return sequence
            
        except Exception as e:
            logger.error(f"Error extracting sequence from {log_path}: {str(e)}")
            return []
    
    def extract_from_logs(self, log_paths: List[str]) -> List[List[str]]:
        """
        Extract API call sequences from multiple execution logs
        
        Args:
            log_paths: List of paths to execution logs
            
        Returns:
            List of API call sequences
        """
        sequences = []
        for log_path in tqdm(log_paths, desc="Extracting sequences"):
            sequence = self.extract_from_log(log_path)
            sequences.append(sequence)
        return sequences
    
    def extract_and_tokenize(self, log_paths: List[str]) -> List[List[int]]:
        """
        Extract API call sequences and encode them using tokenizer
        
        Args:
            log_paths: List of paths to execution logs
            
        Returns:
            List of tokenized sequences
        """
        sequences = self.extract_from_logs(log_paths)
        
        # Fit tokenizer if not already fitted
        if not self.tokenizer.vocab:
            logger.info("Building vocabulary from sequences")
            self.tokenizer.fit(sequences)
        
        # Encode sequences
        encoded_sequences = [
            self.tokenizer.encode(sequence) for sequence in sequences
        ]
        return encoded_sequences


class SequenceLSTMAnalyzer:
    """LSTM-based analyzer for execution sequences"""
    
    def __init__(
        self,
        model: Optional[SequenceLSTMModel] = None,
        tokenizer: Optional[SequenceTokenizer] = None,
        sequence_extractor: Optional[SequenceExtractor] = None,
        device: str = None,
        max_seq_length: int = 500,
        batch_size: int = 32,
        vocab_size: int = None,
        embedding_dim: int = 64,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.2,
        bidirectional: bool = True
    ):
        """
        Initialize sequence LSTM analyzer
        
        Args:
            model: Optional pre-initialized model
            tokenizer: Optional pre-initialized tokenizer
            sequence_extractor: Optional pre-initialized sequence extractor
            device: Computation device ('cuda' or 'cpu')
            max_seq_length: Maximum sequence length
            batch_size: Batch size for processing
            vocab_size: Size of vocabulary (if not provided by tokenizer)
            embedding_dim: Dimension of token embeddings
            hidden_dim: Dimension of LSTM hidden states
            num_layers: Number of LSTM layers
            dropout: Dropout probability
            bidirectional: Whether to use bidirectional LSTM
        """
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        self.max_seq_length = max_seq_length
        self.batch_size = batch_size
        
        # Initialize tokenizer if not provided
        self.tokenizer = tokenizer or SequenceTokenizer()
        
        # Initialize sequence extractor if not provided
        self.sequence_extractor = sequence_extractor or SequenceExtractor(
            max_sequence_length=max_seq_length,
            tokenizer=self.tokenizer
        )
        
        # Determine vocabulary size
        self.vocab_size = vocab_size
        if self.vocab_size is None and self.tokenizer.vocab:
            self.vocab_size = len(self.tokenizer.vocab)
        
        # Initialize model if not provided
        self.model = model
        if self.model is None and self.vocab_size is not None:
            self.model = SequenceLSTMModel(
                vocab_size=self.vocab_size,
                embedding_dim=embedding_dim,
                hidden_dim=hidden_dim,
                num_layers=num_layers,
                dropout=dropout,
                bidirectional=bidirectional,
                max_seq_length=max_seq_length
            )
        
        if self.model:
            self.model.to(self.device)
    
    def prepare_data(
        self, 
        log_paths: List[str], 
        labels: Optional[List[int]] = None
    ) -> Dataset:
        """
        Prepare dataset from log paths
        
        Args:
            log_paths: List of paths to execution logs
            labels: Optional list of labels (1 for ransomware, 0 for benign)
            
        Returns:
            Dataset ready for training or inference
        """
        # Extract and tokenize sequences
        sequences = self.sequence_extractor.extract_and_tokenize(log_paths)
        
        # Update vocabulary size if needed
        if self.vocab_size is None:
            self.vocab_size = len(self.tokenizer.vocab)
        
        # Create dataset
        dataset = SequenceDataset(
            sequences=sequences,
            labels=labels,
            max_length=self.max_seq_length,
            vocab_size=self.vocab_size
        )
        
        return dataset
    
    def train(
        self,
        train_log_paths: List[str],
        train_labels: List[int],
        val_log_paths: Optional[List[str]] = None,
        val_labels: Optional[List[int]] = None,
        epochs: int = 10,
        learning_rate: float = 0.001,
        weight_decay: float = 1e-5,
        early_stopping_patience: int = 3,
        model_save_path: Optional[str] = None
    ) -> Dict[str, List[float]]:
        """
        Train the model
        
        Args:
            train_log_paths: List of paths to training execution logs
            train_labels: List of training labels (1 for ransomware, 0 for benign)
            val_log_paths: Optional list of paths to validation execution logs
            val_labels: Optional list of validation labels
            epochs: Number of training epochs
            learning_rate: Learning rate
            weight_decay: L2 regularization strength
            early_stopping_patience: Number of epochs to wait for improvement
            model_save_path: Optional path to save the best model
            
        Returns:
            Dictionary of training history
        """
        # Prepare training data
        train_dataset = self.prepare_data(train_log_paths, train_labels)
        train_loader = DataLoader(
            train_dataset, 
            batch_size=self.batch_size,
            shuffle=True
        )
        
        # Prepare validation data if provided
        val_loader = None
        if val_log_paths and val_labels:
            val_dataset = self.prepare_data(val_log_paths, val_labels)
            val_loader = DataLoader(
                val_dataset, 
                batch_size=self.batch_size,
                shuffle=False
            )
        
        # Initialize model if needed
        if self.model is None:
            if self.vocab_size is None:
                self.vocab_size = len(self.tokenizer.vocab)
            
            self.model = SequenceLSTMModel(
                vocab_size=self.vocab_size,
                max_seq_length=self.max_seq_length
            )
            self.model.to(self.device)
        
        # Loss function and optimizer
        criterion = nn.BCEWithLogitsLoss()
        optimizer = torch.optim.Adam(
            self.model.parameters(), 
            lr=learning_rate,
            weight_decay=weight_decay
        )
        
        # Early stopping
        best_val_loss = float('inf')
        best_epoch = 0
        no_improvement = 0
        
        # Training history
        history = {
            'train_loss': [],
            'train_acc': [],
            'val_loss': [],
            'val_acc': []
        }
        
        # Training loop
        for epoch in range(epochs):
            # Training phase
            self.model.train()
            train_loss = 0.0
            train_correct = 0
            train_total = 0
            
            for sequences, labels in tqdm(train_loader, desc=f"Epoch {epoch+1}/{epochs} (Training)"):
                sequences = sequences.to(self.device)
                labels = labels.to(self.device)
                
                # Forward pass
                outputs = self.model(sequences)
                
                # Calculate loss
                loss = criterion(outputs, labels.unsqueeze(1))
                
                # Backward pass and optimize
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
                
                # Calculate statistics
                train_loss += loss.item() * sequences.size(0)
                train_total += labels.size(0)
                predictions = (torch.sigmoid(outputs) >= 0.5).float()
                train_correct += (predictions == labels.unsqueeze(1)).sum().item()
            
            train_loss /= train_total
            train_acc = train_correct / train_total
            history['train_loss'].append(train_loss)
            history['train_acc'].append(train_acc)
            
            # Validation phase
            if val_loader:
                self.model.eval()
                val_loss = 0.0
                val_correct = 0
                val_total = 0
                
                with torch.no_grad():
                    for sequences, labels in tqdm(val_loader, desc=f"Epoch {epoch+1}/{epochs} (Validation)"):
                        sequences = sequences.to(self.device)
                        labels = labels.to(self.device)
                        
                        # Forward pass
                        outputs = self.model(sequences)
                        
                        # Calculate loss
                        loss = criterion(outputs, labels.unsqueeze(1))
                        
                        # Calculate statistics
                        val_loss += loss.item() * sequences.size(0)
                        val_total += labels.size(0)
                        predictions = (torch.sigmoid(outputs) >= 0.5).float()
                        val_correct += (predictions == labels.unsqueeze(1)).sum().item()
                
                val_loss /= val_total
                val_acc = val_correct / val_total
                history['val_loss'].append(val_loss)
                history['val_acc'].append(val_acc)
                
                # Early stopping check
                if val_loss < best_val_loss:
                    best_val_loss = val_loss
                    best_epoch = epoch
                    no_improvement = 0
                    
                    # Save best model
                    if model_save_path:
                        os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
                        torch.save(self.model.state_dict(), model_save_path)
                else:
                    no_improvement += 1
                
                logger.info(
                    f"Epoch {epoch+1}/{epochs}: "
                    f"Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f}, "
                    f"Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}"
                )
                
                # Early stopping
                if no_improvement >= early_stopping_patience:
                    logger.info(f"Early stopping at epoch {epoch+1}. Best epoch: {best_epoch+1}")
                    break
            else:
                logger.info(
                    f"Epoch {epoch+1}/{epochs}: "
                    f"Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f}"
                )
        
        # Load best model if saved
        if val_loader and model_save_path and os.path.exists(model_save_path):
            self.model.load_state_dict(torch.load(model_save_path))
        
        return history
    
    def predict(
        self, 
        log_paths: List[str],
        return_probabilities: bool = False
    ) -> Union[List[int], List[float]]:
        """
        Make predictions on sequences
        
        Args:
            log_paths: List of paths to execution logs
            return_probabilities: Whether to return probabilities instead of binary predictions
            
        Returns:
            List of predictions (1 for ransomware, 0 for benign) or probabilities
        """
        if self.model is None:
            raise ValueError("Model not initialized. Train or load a model first.")
        
        # Prepare data
        dataset = self.prepare_data(log_paths)
        dataloader = DataLoader(dataset, batch_size=self.batch_size, shuffle=False)
        
        # Predictions
        self.model.eval()
        predictions = []
        
        with torch.no_grad():
            for sequences in tqdm(dataloader, desc="Predicting"):
                sequences = sequences.to(self.device)
                
                # Forward pass
                outputs = self.model(sequences)
                
                # Convert to probabilities
                probs = torch.sigmoid(outputs).cpu().numpy().flatten()
                
                if return_probabilities:
                    predictions.extend(probs.tolist())
                else:
                    preds = (probs >= 0.5).astype(int).tolist()
                    predictions.extend(preds)
        
        return predictions
    
    def extract_features(self, log_paths: List[str]) -> np.ndarray:
        """
        Extract features from sequences using the model
        
        Args:
            log_paths: List of paths to execution logs
            
        Returns:
            Array of features of shape (n_samples, hidden_dim*2 if bidirectional else hidden_dim)
        """
        if self.model is None:
            raise ValueError("Model not initialized. Train or load a model first.")
        
        # Prepare data
        dataset = self.prepare_data(log_paths)
        dataloader = DataLoader(dataset, batch_size=self.batch_size, shuffle=False)
        
        # Feature extraction
        self.model.eval()
        features_list = []
        
        with torch.no_grad():
            for sequences in tqdm(dataloader, desc="Extracting features"):
                sequences = sequences.to(self.device)
                
                # Forward pass with feature extraction
                _, features = self.model(sequences, return_features=True)
                
                # Add to list
                features_list.append(features.cpu().numpy())
        
        # Concatenate features
        features_array = np.vstack(features_list)
        return features_array
    
    def analyze_attention(self, log_path: str) -> Tuple[List[str], List[float]]:
        """
        Analyze attention weights for a single sequence
        
        Args:
            log_path: Path to execution log
            
        Returns:
            Tuple of (API calls, attention weights)
        """
        if self.model is None:
            raise ValueError("Model not initialized. Train or load a model first.")
        
        # Extract sequence
        sequence = self.sequence_extractor.extract_from_log(log_path)
        
        # Encode sequence
        encoded_sequence = self.tokenizer.encode(sequence)
        
        # Truncate or pad sequence
        if len(encoded_sequence) > self.max_seq_length:
            encoded_sequence = encoded_sequence[:self.max_seq_length]
        else:
            encoded_sequence = encoded_sequence + [0] * (self.max_seq_length - len(encoded_sequence))
        
        # Convert to tensor
        sequence_tensor = torch.tensor(encoded_sequence, dtype=torch.long).unsqueeze(0)
        sequence_tensor = sequence_tensor.to(self.device)
        
        # Get attention weights
        self.model.eval()
        with torch.no_grad():
            _, attention_weights = self.model(sequence_tensor, return_attention=True)
        
        # Convert to list
        attention_weights = attention_weights.cpu().numpy().flatten()
        
        # Filter out padding
        valid_length = min(len(sequence), self.max_seq_length)
        api_calls = sequence[:valid_length]
        weights = attention_weights[:valid_length]
        
        return api_calls, weights.tolist()
    
    def save(self, model_path: str, tokenizer_path: str):
        """
        Save model and tokenizer
        
        Args:
            model_path: Path to save model
            tokenizer_path: Path to save tokenizer
        """
        if self.model is None:
            raise ValueError("Model not initialized. Train or load a model first.")
        
        # Create directories if not exist
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        os.makedirs(os.path.dirname(tokenizer_path), exist_ok=True)
        
        # Save model
        torch.save({
            'model_state_dict': self.model.state_dict(),
            'vocab_size': self.vocab_size,
            'max_seq_length': self.max_seq_length,
            'model_params': {
                'embedding_dim': self.model.embedding_dim,
                'hidden_dim': self.model.hidden_dim,
                'num_layers': self.model.num_layers,
                'dropout': self.model.dropout.p,
                'bidirectional': self.model.bidirectional,
                'output_dim': self.model.output_dim
            }
        }, model_path)
        
        # Save tokenizer
        self.tokenizer.save(tokenizer_path)
        
        logger.info(f"Model saved to {model_path}")
        logger.info(f"Tokenizer saved to {tokenizer_path}")
    
    @classmethod
    def load(
        cls, 
        model_path: str, 
        tokenizer_path: str,
        device: str = None,
        sequence_extractor: Optional[SequenceExtractor] = None,
    ) -> 'SequenceLSTMAnalyzer':
        """
        Load model and tokenizer
        
        Args:
            model_path: Path to load model from
            tokenizer_path: Path to load tokenizer from
            device: Computation device ('cuda' or 'cpu')
            sequence_extractor: Optional sequence extractor
            
        Returns:
            Loaded SequenceLSTMAnalyzer
        """
        # Load tokenizer
        tokenizer = SequenceTokenizer.load(tokenizer_path)
        
        # Load model
        checkpoint = torch.load(model_path, map_location='cpu')
        model_params = checkpoint['model_params']
        
        # Create model
        model = SequenceLSTMModel(
            vocab_size=checkpoint['vocab_size'],
            embedding_dim=model_params['embedding_dim'],
            hidden_dim=model_params['hidden_dim'],
            num_layers=model_params['num_layers'],
            dropout=model_params['dropout'],
            bidirectional=model_params['bidirectional'],
            output_dim=model_params['output_dim'],
            max_seq_length=checkpoint['max_seq_length']
        )
        
        # Load weights
        model.load_state_dict(checkpoint['model_state_dict'])
        
        # Create sequence extractor if not provided
        if sequence_extractor is None:
            sequence_extractor = SequenceExtractor(
                max_sequence_length=checkpoint['max_seq_length'],
                tokenizer=tokenizer
            )
        
        # Create analyzer
        analyzer = cls(
            model=model,
            tokenizer=tokenizer,
            sequence_extractor=sequence_extractor,
            device=device,
            max_seq_length=checkpoint['max_seq_length'],
            vocab_size=checkpoint['vocab_size']
        )
        
        return analyzer