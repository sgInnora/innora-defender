#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test script for the LSTM sequence analyzer implementation.
"""

import os
import sys
import json
import unittest
import tempfile
import shutil
from typing import List, Dict

import numpy as np
import torch

# Adjust path to find modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from ai_detection.models.deep.lstm.sequence_lstm_analyzer import (
    SequenceLSTMAnalyzer,
    SequenceTokenizer,
    SequenceExtractor,
    SequenceLSTMModel,
    SequenceDataset
)
from ai_detection.models.deep.lstm.integration import (
    LSTMSequenceDetector,
    create_lstm_sequence_detector
)
from ai_detection.models.deep.lstm.utils import (
    extract_api_sequences_from_logs,
    compute_sequence_similarity,
    compute_ngram_similarity,
    identify_critical_sequences
)


class TestSequenceLSTMImplementation(unittest.TestCase):
    """Test class for LSTM sequence analyzer implementation"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test class"""
        # Create temporary directory for test files
        cls.temp_dir = tempfile.mkdtemp()
        
        # Create test data
        cls.create_test_data()
    
    @classmethod
    def tearDownClass(cls):
        """Clean up after tests"""
        # Remove temporary directory
        shutil.rmtree(cls.temp_dir)
    
    @classmethod
    def create_test_data(cls):
        """Create test data for LSTM sequence analyzer"""
        # Create test logs directory
        logs_dir = os.path.join(cls.temp_dir, 'logs')
        os.makedirs(logs_dir, exist_ok=True)
        
        # Benign sample logs
        benign_apis = [
            "NtCreateFile", "NtReadFile", "NtWriteFile", "NtClose",
            "RegOpenKeyEx", "RegQueryValueEx", "RegCloseKey",
            "CreateProcessW", "GetSystemTime", "GetModuleHandle"
        ]
        
        # Ransomware sample logs
        ransomware_apis = [
            "CryptEncrypt", "CryptCreateHash",
            "NtEnumerateKey", "RegSetValueEx", "DeleteFile",
            "SetFileAttributes", "FindFirstFileEx", "FindNextFile"
        ]
        
        # Create 5 benign sample logs
        for i in range(5):
            # Generate benign sequence
            benign_seq_length = np.random.randint(20, 50)
            benign_seq = np.random.choice(benign_apis, benign_seq_length).tolist()
            
            # Create log file
            log_data = [{"api_name": api} for api in benign_seq]
            with open(os.path.join(logs_dir, f"benign_{i}.json"), 'w') as f:
                json.dump(log_data, f)
        
        # Create 5 ransomware sample logs
        for i in range(5):
            # Generate ransomware sequence
            ransomware_seq_length = np.random.randint(20, 50)
            
            # Start with some benign APIs
            ransomware_seq = np.random.choice(benign_apis, ransomware_seq_length // 2).tolist()
            
            # Add ransomware-specific APIs
            ransomware_specific = np.random.choice(
                ransomware_apis,
                ransomware_seq_length - (ransomware_seq_length // 2)
            ).tolist()
            
            # Mix them in
            ransomware_seq = ransomware_seq + ransomware_specific
            np.random.shuffle(ransomware_seq)
            
            # Create log file
            log_data = [{"api_name": api} for api in ransomware_seq]
            with open(os.path.join(logs_dir, f"ransomware_{i}.json"), 'w') as f:
                json.dump(log_data, f)
        
        cls.logs_dir = logs_dir
        cls.benign_logs = [os.path.join(logs_dir, f"benign_{i}.json") for i in range(5)]
        cls.ransomware_logs = [os.path.join(logs_dir, f"ransomware_{i}.json") for i in range(5)]
        cls.all_logs = cls.benign_logs + cls.ransomware_logs
        cls.all_labels = [0] * 5 + [1] * 5
    
    def test_sequence_tokenizer(self):
        """Test SequenceTokenizer"""
        # Extract sequences from logs
        sequences = extract_api_sequences_from_logs(self.all_logs)
        
        # Create tokenizer
        tokenizer = SequenceTokenizer()
        
        # Fit tokenizer on sequences
        tokenizer.fit(sequences)
        
        # Check that vocabulary is created
        self.assertGreater(len(tokenizer.vocab), 0)
        
        # Encode a sequence
        encoded = tokenizer.encode(sequences[0])
        self.assertEqual(len(encoded), len(sequences[0]))
        
        # Decode back to API calls
        decoded = tokenizer.decode(encoded)
        self.assertEqual(decoded, sequences[0])
        
        # Save and load tokenizer
        tokenizer_path = os.path.join(self.temp_dir, 'tokenizer.pkl')
        tokenizer.save(tokenizer_path)
        
        # Load tokenizer
        loaded_tokenizer = SequenceTokenizer.load(tokenizer_path)
        
        # Check that loaded tokenizer is equivalent
        self.assertEqual(tokenizer.vocab, loaded_tokenizer.vocab)
    
    def test_sequence_extractor(self):
        """Test SequenceExtractor"""
        # Create tokenizer
        tokenizer = SequenceTokenizer()
        
        # Create extractor
        extractor = SequenceExtractor(tokenizer=tokenizer)
        
        # Extract sequence from a single log
        log_path = self.benign_logs[0]
        sequence = extractor.extract_from_log(log_path)
        
        # Check that sequence is extracted
        self.assertIsInstance(sequence, list)
        self.assertGreater(len(sequence), 0)
        
        # Extract sequences from multiple logs
        sequences = extractor.extract_from_logs(self.all_logs)
        
        # Check that sequences are extracted
        self.assertEqual(len(sequences), len(self.all_logs))
        
        # Extract and tokenize sequences
        encoded_sequences = extractor.extract_and_tokenize(self.all_logs)
        
        # Check that sequences are encoded
        self.assertEqual(len(encoded_sequences), len(self.all_logs))
        
        # Check that tokenizer vocabulary is created
        self.assertGreater(len(tokenizer.vocab), 0)
    
    def test_sequence_lstm_model(self):
        """Test SequenceLSTMModel"""
        # Create a small model for testing
        model = SequenceLSTMModel(
            vocab_size=100,
            embedding_dim=16,
            hidden_dim=32,
            num_layers=1,
            max_seq_length=50
        )
        
        # Create a random input tensor
        batch_size = 2
        seq_length = 30
        x = torch.randint(0, 100, (batch_size, seq_length))
        
        # Test forward pass
        output = model(x)
        self.assertEqual(output.shape, (batch_size, 1))
        
        # Test forward pass with feature extraction
        output, features = model(x, return_features=True)
        self.assertEqual(output.shape, (batch_size, 1))
        self.assertEqual(features.shape, (batch_size, 32))
        
        # Test forward pass with attention
        output, attention = model(x, return_attention=True)
        self.assertEqual(output.shape, (batch_size, 1))
        self.assertEqual(attention.shape, (batch_size, seq_length))
    
    def test_sequence_dataset(self):
        """Test SequenceDataset"""
        # Create tokenizer and extractor
        tokenizer = SequenceTokenizer()
        extractor = SequenceExtractor(tokenizer=tokenizer)
        
        # Extract and tokenize sequences
        sequences = extractor.extract_and_tokenize(self.all_logs)
        
        # Create dataset
        dataset = SequenceDataset(
            sequences=sequences,
            labels=self.all_labels,
            max_length=50
        )
        
        # Check dataset length
        self.assertEqual(len(dataset), len(self.all_logs))
        
        # Get first item
        sequence_tensor, label_tensor = dataset[0]
        
        # Check item types and shapes
        self.assertIsInstance(sequence_tensor, torch.Tensor)
        self.assertIsInstance(label_tensor, torch.Tensor)
        self.assertEqual(sequence_tensor.shape, (50,))
        self.assertEqual(label_tensor.shape, ())
    
    def test_sequence_lstm_analyzer(self):
        """Test SequenceLSTMAnalyzer"""
        # Create analyzer
        analyzer = SequenceLSTMAnalyzer(
            batch_size=2,
            embedding_dim=16,
            hidden_dim=32,
            num_layers=1,
            max_seq_length=50
        )
        
        # Prepare data
        dataset = analyzer.prepare_data(
            log_paths=self.all_logs,
            labels=self.all_labels
        )
        
        # Check dataset
        self.assertEqual(len(dataset), len(self.all_logs))
        
        # Train model (very small number of epochs for testing)
        history = analyzer.train(
            train_log_paths=self.all_logs,
            train_labels=self.all_labels,
            epochs=1
        )
        
        # Check training history
        self.assertIn('train_loss', history)
        self.assertIn('train_acc', history)
        
        # Make predictions
        predictions = analyzer.predict(self.all_logs)
        
        # Check predictions
        self.assertEqual(len(predictions), len(self.all_logs))
        
        # Extract features
        features = analyzer.extract_features(self.all_logs)
        
        # Check features
        self.assertEqual(len(features), len(self.all_logs))
        
        # Analyze attention
        api_calls, weights = analyzer.analyze_attention(self.benign_logs[0])
        
        # Check attention analysis
        self.assertIsInstance(api_calls, list)
        self.assertIsInstance(weights, list)
        
        # Save and load model
        model_path = os.path.join(self.temp_dir, 'model.pt')
        tokenizer_path = os.path.join(self.temp_dir, 'tokenizer.pkl')
        
        analyzer.save(model_path, tokenizer_path)
        
        # Load analyzer
        loaded_analyzer = SequenceLSTMAnalyzer.load(
            model_path=model_path,
            tokenizer_path=tokenizer_path
        )
        
        # Check loaded analyzer
        self.assertIsNotNone(loaded_analyzer.model)
        self.assertIsNotNone(loaded_analyzer.tokenizer)
    
    def test_lstm_sequence_detector(self):
        """Test LSTMSequenceDetector"""
        # Create detector
        detector = LSTMSequenceDetector(
            batch_size=2,
            embedding_dim=16,
            hidden_dim=32
        )
        
        # Prepare execution logs
        execution_logs = {}
        for i, log_path in enumerate(self.benign_logs):
            execution_logs[f"benign_{i}"] = [log_path]
        
        for i, log_path in enumerate(self.ransomware_logs):
            execution_logs[f"ransomware_{i}"] = [log_path]
        
        # Train detector
        train_results = detector.train(
            execution_logs=execution_logs,
            model_save_dir=self.temp_dir,
            epochs=1
        )
        
        # Check training results
        self.assertIn('history', train_results)
        self.assertIn('model_path', train_results)
        self.assertIn('tokenizer_path', train_results)
        
        # Test detection on a benign sample
        detection_result = detector.detect([self.benign_logs[0]])
        
        # Check detection result
        self.assertIn('is_ransomware', detection_result)
        self.assertIn('confidence', detection_result)
        self.assertIn('features', detection_result)
        
        # Test detection on a ransomware sample
        detection_result = detector.detect([self.ransomware_logs[0]])
        
        # Check detection result
        self.assertIn('is_ransomware', detection_result)
        self.assertIn('confidence', detection_result)
        self.assertIn('features', detection_result)
        
        # Test feature extraction
        feature_result = detector.extract_behavioral_features([self.benign_logs[0]])
        
        # Check feature extraction result
        self.assertIn('features', feature_result)
        self.assertIn('behavioral_indicators', feature_result)
    
    def test_utility_functions(self):
        """Test utility functions"""
        # Extract sequences
        sequences = extract_api_sequences_from_logs(self.all_logs)
        
        # Compute sequence similarity
        similarity = compute_sequence_similarity(sequences[0], sequences[1])
        self.assertGreaterEqual(similarity, 0.0)
        self.assertLessEqual(similarity, 1.0)
        
        # Compute n-gram similarity
        ngram_similarity = compute_ngram_similarity(sequences[0], sequences[1], n=2)
        self.assertGreaterEqual(ngram_similarity, 0.0)
        self.assertLessEqual(ngram_similarity, 1.0)
        
        # Identify critical sequences
        critical_sequences = identify_critical_sequences(
            sequences=sequences,
            labels=self.all_labels,
            k=5
        )
        
        # Check critical sequences
        self.assertLessEqual(len(critical_sequences), 5)
        for seq, score in critical_sequences:
            self.assertIsInstance(seq, list)
            self.assertIsInstance(score, float)


if __name__ == "__main__":
    unittest.main()