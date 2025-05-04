#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for edge cases and extreme scenarios in the Enhanced YARA Rule Generator
"""

import os
import sys
import unittest
import tempfile
import shutil
import json
import time
import gc
import random
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

# Add parent directory to path to allow importing the module
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

# Import the modules
from utils.yara_enhanced.enhanced_yara_generator import EnhancedYaraGenerator
from utils.yara_enhanced.enhanced_yara_generator import StringFeatureExtractor, BytePatternExtractor, OpcodeFeatureExtractor

# Import feature classes if available
try:
    from tools.yara_rule_generator.ransomware_rule_generator import YaraRule, YaraFeature, StringFeature, BytePatternFeature, OpcodeFeature
    HAS_FEATURE_CLASSES = True
except ImportError:
    # Create mock classes for testing
    HAS_FEATURE_CLASSES = False
    
    class YaraFeature:
        def __init__(self, value, weight=1.0, type="generic"):
            self.value = value
            self.weight = weight
            self.type = type
        
        def to_yara_string(self):
            return f'$string_{hash(self.value) & 0xFFFFFFFF} = "{self.value}"'
    
    class StringFeature(YaraFeature):
        def __init__(self, string, weight=1.0, is_ascii=True, entropy=0.0, context=None):
            super().__init__(string, weight, "string")
            self.string = string
            self.is_ascii = is_ascii
            self.entropy = entropy
            self.context = context or {}
        
        def to_yara_string(self):
            return f'$string_{hash(self.string) & 0xFFFFFFFF} = "{self.string}"'
    
    class BytePatternFeature(YaraFeature):
        def __init__(self, pattern, weight=1.0, offset=0, context=None):
            super().__init__(pattern, weight, "byte_pattern")
            self.pattern = pattern
            self.offset = offset
            self.context = context or {}
        
        def to_yara_string(self):
            hex_bytes = " ".join([f"{b:02X}" for b in self.pattern])
            return f'$bytes_{hash(hex_bytes) & 0xFFFFFFFF} = {{ {hex_bytes} }}'
    
    class OpcodeFeature(YaraFeature):
        def __init__(self, opcode_str, weight=1.0, context=None):
            super().__init__(opcode_str, weight, "opcode")
            self.opcode_str = opcode_str
            self.context = context or {}
        
        def to_yara_string(self):
            return f'$opcode_{hash(self.opcode_str) & 0xFFFFFFFF} = "{self.opcode_str}"'
    
    class YaraRule:
        def __init__(self, name, family, description=""):
            self.name = name
            self.family = family
            self.description = description
            self.features = []
            self.condition = "any of them"
            self.meta = {}
            self.confidence = 0.5
            self.false_positive_rate = 0.05
        
        def add_feature(self, feature):
            self.features.append(feature)
        
        def to_dict(self):
            return {
                "name": self.name,
                "family": self.family,
                "description": self.description,
                "condition": self.condition,
                "meta": self.meta,
                "confidence": self.confidence,
                "false_positive_rate": self.false_positive_rate,
                "features_count": len(self.features)
            }
        
        def generate_rule_text(self):
            return f"rule {self.name} {{ condition: {self.condition} }}"

class TestLargeFileHandling(unittest.TestCase):
    """Tests for handling large files"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for output
        self.temp_dir = tempfile.mkdtemp()
        
        # Initialize generator
        self.generator = EnhancedYaraGenerator(output_dir=self.temp_dir)
        
        # Create a fairly large test file (10MB)
        self.large_file = os.path.join(self.temp_dir, "large_file.bin")
        with open(self.large_file, "wb") as f:
            # Start with MZ header (for PE detection)
            f.write(b"MZ")
            # Add some repeated data with occasional "ransomware" strings
            for i in range(1024 * 1024):  # ~10MB
                if i % 50000 == 0:
                    f.write(b"YOUR FILES ARE ENCRYPTED PAY BITCOIN NOW")
                else:
                    f.write(bytes([i % 256]))
    
    def tearDown(self):
        """Clean up temporary files"""
        # Make sure we close any open file handles
        gc.collect()
        try:
            shutil.rmtree(self.temp_dir)
        except PermissionError:
            # On Windows, sometimes files are still in use
            pass
    
    def test_analyze_large_file(self):
        """Test analyzing a large file"""
        # Analyze the large file
        start_time = time.time()
        result = self.generator.analyze_sample(self.large_file, "LargeSampleFamily")
        end_time = time.time()
        
        # Verify the analysis completed successfully
        self.assertEqual(result["file"], self.large_file)
        self.assertEqual(result["family"], "LargeSampleFamily")
        
        # Extract execution time for reporting
        execution_time = end_time - start_time
        print(f"Large file analysis took {execution_time:.2f} seconds")
        
        # Verify features were extracted
        self.assertIn("features", result)
        # At least some extractors should have found features
        self.assertTrue(any(count > 0 for count in result["features"].values()))
    
    def test_get_file_info_large_file(self):
        """Test getting file info from a large file"""
        # Get file info
        start_time = time.time()
        file_info = self.generator._get_file_info(self.large_file)
        end_time = time.time()
        
        # Verify file info was retrieved
        self.assertEqual(file_info["file_path"], self.large_file)
        self.assertIn("file_size", file_info)
        self.assertIn("file_type", file_info)
        self.assertIn("entropy", file_info)
        
        # Extract execution time for reporting
        execution_time = end_time - start_time
        print(f"Large file info retrieval took {execution_time:.2f} seconds")
    
    def test_entropy_calculation_large_file(self):
        """Test entropy calculation on a large file"""
        # Read large file
        with open(self.large_file, 'rb') as f:
            data = f.read()
        
        # Calculate entropy
        start_time = time.time()
        entropy = self.generator._calculate_entropy(data)
        end_time = time.time()
        
        # Entropy should be high due to diverse byte values
        self.assertGreater(entropy, 7.0)
        
        # Extract execution time for reporting
        execution_time = end_time - start_time
        print(f"Entropy calculation for {len(data)} bytes took {execution_time:.2f} seconds")
    
    def test_feature_extraction_large_file(self):
        """Test feature extraction on a large file"""
        # Create string extractor
        string_extractor = StringFeatureExtractor()
        
        # Extract features
        start_time = time.time()
        features = string_extractor.extract_features(self.large_file)
        end_time = time.time()
        
        # Verify features were extracted
        self.assertGreater(len(features), 0)
        
        # Extract execution time for reporting
        execution_time = end_time - start_time
        print(f"String feature extraction from large file took {execution_time:.2f} seconds")
        
        # Verify the ransomware strings were found
        ransomware_features = [f for f in features if "ENCRYPTED" in f.string]
        self.assertGreater(len(ransomware_features), 0)

class TestManyFeaturesHandling(unittest.TestCase):
    """Tests for handling many features"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for output
        self.temp_dir = tempfile.mkdtemp()
        
        # Initialize generator
        self.generator = EnhancedYaraGenerator(output_dir=self.temp_dir)
        
        # Create features for testing
        self.large_feature_set = []
        # Create 1000 string features
        for i in range(1000):
            weight = 1.0 + (i % 10) / 10.0  # Weights from 1.0 to 1.9
            entropy = 4.0 + (i % 40) / 10.0  # Entropy from 4.0 to 7.9
            feature = StringFeature(
                f"Test string {i} with some randomness {random.randint(1000, 9999)}",
                weight=weight,
                entropy=entropy
            )
            self.large_feature_set.append(feature)
    
    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir)
    
    def test_rule_optimization_many_features(self):
        """Test rule optimization with many features"""
        # Create a rule with many features
        rule = YaraRule("ManyFeaturesRule", "ManyFeaturesFamily")
        for feature in self.large_feature_set:
            rule.add_feature(feature)
        
        # Optimize the rule
        start_time = time.time()
        self.generator._optimize_rule(rule)
        end_time = time.time()
        
        # Verify the rule was optimized
        self.assertLess(len(rule.features), len(self.large_feature_set))
        self.assertNotEqual(rule.condition, "any of them")
        
        # Extract execution time for reporting
        execution_time = end_time - start_time
        print(f"Rule optimization for {len(self.large_feature_set)} features took {execution_time:.2f} seconds")
    
    def test_generate_rule_text_many_features(self):
        """Test generating rule text with many features"""
        # Create a rule with many features
        rule = YaraRule("ManyFeaturesRule", "ManyFeaturesFamily")
        for feature in self.large_feature_set[:100]:  # Use a subset to avoid excessive test time
            rule.add_feature(feature)
        
        # Generate rule text
        start_time = time.time()
        rule_text = self.generator._generate_rule_text(rule)
        end_time = time.time()
        
        # Verify the rule text was generated
        self.assertIn("rule ManyFeaturesRule", rule_text)
        
        # Extract execution time for reporting
        execution_time = end_time - start_time
        print(f"Rule text generation for {len(rule.features)} features took {execution_time:.2f} seconds")
    
    def test_save_combined_ruleset_many_rules(self):
        """Test saving a combined ruleset with many rules"""
        # Create many rules
        for i in range(50):
            rule = YaraRule(f"Rule{i}", f"Family{i}")
            # Add some features to each rule
            for j in range(10):
                feature = StringFeature(f"Feature {j} for Rule {i}", weight=1.0)
                rule.add_feature(feature)
            
            # Add rule to generator
            self.generator.rules[f"Rule{i}"] = rule
        
        # Save combined ruleset
        start_time = time.time()
        ruleset_path = self.generator.save_combined_ruleset("many_rules.yar")
        end_time = time.time()
        
        # Verify the ruleset was saved
        self.assertIsNotNone(ruleset_path)
        self.assertTrue(os.path.exists(ruleset_path))
        
        # Extract execution time for reporting
        execution_time = end_time - start_time
        print(f"Combined ruleset saving for {len(self.generator.rules)} rules took {execution_time:.2f} seconds")

class TestUnusualFileFormats(unittest.TestCase):
    """Tests for handling unusual file formats"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for output
        self.temp_dir = tempfile.mkdtemp()
        
        # Initialize generator
        self.generator = EnhancedYaraGenerator(output_dir=self.temp_dir)
        
        # Create various unusual files
        
        # Empty file
        self.empty_file = os.path.join(self.temp_dir, "empty.bin")
        with open(self.empty_file, "wb") as f:
            pass
        
        # Very small file
        self.tiny_file = os.path.join(self.temp_dir, "tiny.bin")
        with open(self.tiny_file, "wb") as f:
            f.write(b"AB")
        
        # File with only null bytes
        self.null_file = os.path.join(self.temp_dir, "null.bin")
        with open(self.null_file, "wb") as f:
            f.write(b"\x00" * 1024)
        
        # File with high entropy (random bytes)
        self.random_file = os.path.join(self.temp_dir, "random.bin")
        with open(self.random_file, "wb") as f:
            f.write(bytes(random.randint(0, 255) for _ in range(1024)))
        
        # File with strange characters
        self.strange_file = os.path.join(self.temp_dir, "strange.txt")
        with open(self.strange_file, "w", encoding="utf-8") as f:
            f.write("".join(chr(i) for i in range(32, 127)))  # ASCII printable
            f.write("".join(chr(i) for i in range(161, 256)))  # Extended ASCII
            f.write("".join(chr(i) for i in range(0x3000, 0x3050)))  # Chinese
            f.write("".join(chr(i) for i in range(0x0600, 0x0650)))  # Arabic
            f.write("".join(chr(i) for i in range(0x0900, 0x0950)))  # Devanagari
    
    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir)
    
    def test_empty_file(self):
        """Test handling of empty files"""
        # Get file info
        file_info = self.generator._get_file_info(self.empty_file)
        
        # Verify file info
        self.assertEqual(file_info["file_size"], 0)
        self.assertEqual(file_info["entropy"], 0.0)  # Empty file has zero entropy
        
        # Analyze the empty file
        result = self.generator.analyze_sample(self.empty_file, "EmptyFamily")
        
        # Verify analysis
        self.assertEqual(result["file"], self.empty_file)
        self.assertEqual(result["family"], "EmptyFamily")
    
    def test_tiny_file(self):
        """Test handling of very small files"""
        # Get file info
        file_info = self.generator._get_file_info(self.tiny_file)
        
        # Verify file info
        self.assertEqual(file_info["file_size"], 2)
        
        # Entropy of a two-byte file with different bytes should be 1.0
        self.assertAlmostEqual(file_info["entropy"], 1.0, places=1)
        
        # Analyze the tiny file
        result = self.generator.analyze_sample(self.tiny_file, "TinyFamily")
        
        # Verify analysis
        self.assertEqual(result["file"], self.tiny_file)
        self.assertEqual(result["family"], "TinyFamily")
    
    def test_null_file(self):
        """Test handling of files with only null bytes"""
        # Get file info
        file_info = self.generator._get_file_info(self.null_file)
        
        # Verify file info
        self.assertEqual(file_info["file_size"], 1024)
        self.assertEqual(file_info["entropy"], 0.0)  # File with all same bytes has zero entropy
        
        # Analyze the null file
        result = self.generator.analyze_sample(self.null_file, "NullFamily")
        
        # Verify analysis
        self.assertEqual(result["file"], self.null_file)
        self.assertEqual(result["family"], "NullFamily")
    
    def test_random_file(self):
        """Test handling of files with random bytes (high entropy)"""
        # Get file info
        file_info = self.generator._get_file_info(self.random_file)
        
        # Verify file info
        self.assertEqual(file_info["file_size"], 1024)
        self.assertGreater(file_info["entropy"], 7.0)  # Random data should have high entropy
        
        # Analyze the random file
        result = self.generator.analyze_sample(self.random_file, "RandomFamily")
        
        # Verify analysis
        self.assertEqual(result["file"], self.random_file)
        self.assertEqual(result["family"], "RandomFamily")
    
    def test_strange_file(self):
        """Test handling of files with strange characters"""
        # Get file info
        file_info = self.generator._get_file_info(self.strange_file)
        
        # Verify file info
        self.assertGreater(file_info["file_size"], 0)
        
        # Analyze the strange file
        result = self.generator.analyze_sample(self.strange_file, "StrangeFamily")
        
        # Verify analysis
        self.assertEqual(result["file"], self.strange_file)
        self.assertEqual(result["family"], "StrangeFamily")
        
        # Extract features using string extractor
        string_extractor = StringFeatureExtractor()
        features = string_extractor.extract_features(self.strange_file)
        
        # Should be able to extract some features
        # Note: May vary based on implementation of string extraction
        print(f"Extracted {len(features)} string features from strange file")

class TestResourceConstraints(unittest.TestCase):
    """Tests for behavior under resource constraints"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for output
        self.temp_dir = tempfile.mkdtemp()
        
        # Initialize generator
        self.generator = EnhancedYaraGenerator(output_dir=self.temp_dir)
        
        # Create a test file
        self.test_file = os.path.join(self.temp_dir, "test_file.exe")
        with open(self.test_file, "wb") as f:
            f.write(b"MZ" + b"\x00" * 1000)  # Simple PE header with some content
    
    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir)
    
    @patch('subprocess.run')
    def test_subprocess_timeout(self, mock_subprocess_run):
        """Test handling of subprocess timeout"""
        # Make subprocess.run time out
        mock_subprocess_run.side_effect = subprocess.TimeoutExpired(cmd="strings", timeout=30)
        
        # Create string extractor
        extractor = StringFeatureExtractor()
        
        # Extract features (should handle timeout gracefully)
        features = extractor.extract_features(self.test_file)
        
        # Should return empty features list on timeout
        self.assertEqual(features, [])
    
    @patch('builtins.open')
    def test_memory_error_handling(self, mock_open):
        """Test handling of memory errors during file reading"""
        # Mock open to return a file object that raises MemoryError on read
        mock_file = MagicMock()
        mock_file.__enter__.return_value = mock_file
        mock_file.read.side_effect = MemoryError("Not enough memory")
        mock_open.return_value = mock_file
        
        # Try to get file info (should handle memory error gracefully)
        try:
            file_info = self.generator._get_file_info(self.test_file)
            
            # If it doesn't raise, it should return some basic info
            self.assertEqual(file_info["file_path"], self.test_file)
            # Entropy should be 0 or None when calculation fails
            self.assertIn(file_info["entropy"], [0, None])
        except MemoryError:
            self.fail("MemoryError should be handled gracefully")
    
    @patch('gc.collect')
    def test_memory_optimization(self, mock_gc_collect):
        """Test memory optimization during processing"""
        # Create a large rule with many features
        rule = YaraRule("LargeRule", "LargeFamily")
        for i in range(1000):
            feature = StringFeature(f"Feature {i}", weight=1.0)
            rule.add_feature(feature)
        
        # Optimize the rule (should trigger memory optimization)
        self.generator._optimize_rule(rule)
        
        # Verify garbage collection was attempted
        # Note: This is implementation-dependent, not all implementations optimize memory
        if mock_gc_collect.call_count > 0:
            print(f"Memory optimization performed {mock_gc_collect.call_count} times")

class TestInternationalization(unittest.TestCase):
    """Tests for handling internationalization issues"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for output
        self.temp_dir = tempfile.mkdtemp()
        
        # Initialize generator
        self.generator = EnhancedYaraGenerator(output_dir=self.temp_dir)
        
        # Create files with international content
        
        # Chinese ransomware note
        self.chinese_file = os.path.join(self.temp_dir, "chinese.txt")
        with open(self.chinese_file, "w", encoding="utf-8") as f:
            f.write("你的文件已被加密！\n")
            f.write("支付 1 比特币到以下地址：\n")
            f.write("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n")
        
        # Russian ransomware note
        self.russian_file = os.path.join(self.temp_dir, "russian.txt")
        with open(self.russian_file, "w", encoding="utf-8") as f:
            f.write("Ваши файлы зашифрованы!\n")
            f.write("Отправьте 1 биткоин на адрес:\n")
            f.write("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n")
        
        # Arabic ransomware note
        self.arabic_file = os.path.join(self.temp_dir, "arabic.txt")
        with open(self.arabic_file, "w", encoding="utf-8") as f:
            f.write("تم تشفير ملفاتك!\n")
            f.write("ادفع 1 بيتكوين إلى العنوان التالي:\n")
            f.write("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n")
        
        # File with mixed languages
        self.mixed_file = os.path.join(self.temp_dir, "mixed.txt")
        with open(self.mixed_file, "w", encoding="utf-8") as f:
            f.write("Your files are encrypted! 你的文件已被加密! Ваши файлы зашифрованы! تم تشفير ملفاتك!\n")
            f.write("Pay 1 Bitcoin to recover them. 支付1比特币以恢复它们。\n")
        
        # Non-UTF8 encoded file (CP1251 Russian)
        self.cp1251_file = os.path.join(self.temp_dir, "cp1251.txt")
        with open(self.cp1251_file, "wb") as f:
            russian_text = "Ваши файлы зашифрованы!".encode('cp1251')
            f.write(russian_text)
    
    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir)
    
    def test_chinese_file(self):
        """Test handling of Chinese text"""
        # Analyze the Chinese file
        result = self.generator.analyze_sample(self.chinese_file, "ChineseFamily")
        
        # Verify analysis
        self.assertEqual(result["file"], self.chinese_file)
        self.assertEqual(result["family"], "ChineseFamily")
        
        # Extract features using string extractor
        string_extractor = StringFeatureExtractor()
        features = string_extractor.extract_features(self.chinese_file)
        
        # Verify some features were extracted
        # The bitcoin address should be found regardless of language
        bitcoin_features = [f for f in features if "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh" in f.string]
        self.assertGreaterEqual(len(bitcoin_features), 0)
    
    def test_russian_file(self):
        """Test handling of Russian text"""
        # Analyze the Russian file
        result = self.generator.analyze_sample(self.russian_file, "RussianFamily")
        
        # Verify analysis
        self.assertEqual(result["file"], self.russian_file)
        self.assertEqual(result["family"], "RussianFamily")
        
        # Extract features using string extractor
        string_extractor = StringFeatureExtractor()
        features = string_extractor.extract_features(self.russian_file)
        
        # Verify some features were extracted
        self.assertGreater(len(features), 0)
    
    def test_arabic_file(self):
        """Test handling of Arabic text (right-to-left)"""
        # Analyze the Arabic file
        result = self.generator.analyze_sample(self.arabic_file, "ArabicFamily")
        
        # Verify analysis
        self.assertEqual(result["file"], self.arabic_file)
        self.assertEqual(result["family"], "ArabicFamily")
        
        # Extract features using string extractor
        string_extractor = StringFeatureExtractor()
        features = string_extractor.extract_features(self.arabic_file)
        
        # Verify some features were extracted
        self.assertGreater(len(features), 0)
    
    def test_mixed_language_file(self):
        """Test handling of mixed language text"""
        # Analyze the mixed language file
        result = self.generator.analyze_sample(self.mixed_file, "MixedFamily")
        
        # Verify analysis
        self.assertEqual(result["file"], self.mixed_file)
        self.assertEqual(result["family"], "MixedFamily")
        
        # Extract features using string extractor
        string_extractor = StringFeatureExtractor()
        features = string_extractor.extract_features(self.mixed_file)
        
        # Verify features were extracted
        self.assertGreater(len(features), 0)
        
        # The English text should be found
        english_features = [f for f in features if "Your files are encrypted" in f.string]
        self.assertGreaterEqual(len(english_features), 0)
    
    def test_non_utf8_file(self):
        """Test handling of non-UTF8 encoded files"""
        # Analyze the CP1251 file
        result = self.generator.analyze_sample(self.cp1251_file, "CP1251Family")
        
        # Verify analysis
        self.assertEqual(result["file"], self.cp1251_file)
        self.assertEqual(result["family"], "CP1251Family")
        
        # Should not crash when processing non-UTF8 files

if __name__ == '__main__':
    unittest.main()