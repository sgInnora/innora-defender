#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Final coverage tests for the Enhanced YARA Generator
This module specifically targets remaining uncovered code paths
"""

import os
import sys
import unittest
import tempfile
import shutil
import json
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open, ANY

# Add parent directory to path to allow importing the module
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

# Import the modules
from utils.yara_enhanced.enhanced_yara_generator import EnhancedYaraGenerator
from utils.yara_enhanced.enhanced_yara_generator import StringFeatureExtractor
from utils.yara_enhanced.enhanced_yara_generator import OpcodeFeatureExtractor
from utils.yara_enhanced.enhanced_yara_generator import BytePatternExtractor
from utils.yara_enhanced.enhanced_yara_generator import ScriptFeatureExtractor

class TestFileInfoRemainingPaths(unittest.TestCase):
    """Tests specifically targeting remaining uncovered paths in _get_file_info"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for output
        self.temp_dir = tempfile.mkdtemp()
        
        # Initialize generator
        self.generator = EnhancedYaraGenerator(output_dir=self.temp_dir)
        
        # Create test files with various extensions
        self.extensions = ['.exe', '.dll', '.sys', '.sh', '.bash', '.bat', 
                          '.cmd', '.js', '.vbs', '.ps1', '.py', '.txt']
        
        self.test_files = {}
        for ext in self.extensions:
            file_path = os.path.join(self.temp_dir, f"test_file{ext}")
            with open(file_path, "w") as f:
                f.write(f"Test content for {ext} file")
            self.test_files[ext] = file_path
    
    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir)
    
    def test_file_info_fallback_detection(self):
        """Test file type detection fallback based on extension"""
        # Mock the 'file' command to fail
        file_command_mock = MagicMock(side_effect=Exception("Command failed"))
        
        # Test each file extension
        with patch('subprocess.run', file_command_mock):
            for ext, file_path in self.test_files.items():
                # Get file info - should use extension-based detection
                file_info = self.generator._get_file_info(file_path)
                
                # Check that file_type was set based on extension
                self.assertIn("file_type", file_info)
                
                # Verify expected type based on extension
                if ext in ['.exe', '.dll', '.sys']:
                    self.assertEqual(file_info["file_type"], "PE executable")
                elif ext in ['.sh', '.bash']:
                    self.assertEqual(file_info["file_type"], "Shell script")
                elif ext in ['.bat', '.cmd']:
                    self.assertEqual(file_info["file_type"], "Batch script")
                elif ext == '.js':
                    self.assertEqual(file_info["file_type"], "JavaScript")
                elif ext == '.vbs':
                    self.assertEqual(file_info["file_type"], "VBScript")
                elif ext == '.ps1':
                    self.assertEqual(file_info["file_type"], "PowerShell script")
                elif ext == '.py':
                    self.assertEqual(file_info["file_type"], "Python script")
                else:
                    self.assertEqual(file_info["file_type"], "Unknown")

class TestStringExtractorEdgeCases(unittest.TestCase):
    """Tests targeting uncovered code in StringFeatureExtractor"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test file with high entropy string
        self.test_file = os.path.join(self.temp_dir, "test_file.txt")
        with open(self.test_file, "w") as f:
            f.write("This is a normal string.\n")
            f.write("This string has 7zipm32w942mjfa random high entropy content.\n")
    
    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir)
    
    def test_entropy_based_weight_adjustment(self):
        """Test weight adjustment based on entropy (line 233)"""
        # Create a string extractor
        extractor = StringFeatureExtractor()
        
        # Mock subprocess to return our test strings
        with patch('subprocess.run') as mock_run:
            # Configure the mock to return our test strings
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.stdout = b"This is a normal string.\nThis string has 7zipm32w942mjfa random high entropy content."
            mock_run.return_value = mock_process
            
            # Extract features
            features = extractor.extract_features(self.test_file)
            
            # Verify features were extracted
            self.assertGreater(len(features), 0)
            
            # Find a feature with high entropy but no pattern match
            # (To hit the code branch where entropy adjusts weight without a pattern match)
            high_entropy_feature = None
            for feature in features:
                # For a feature that matches the high entropy line but not a ransomware pattern
                if "7zipm32w942mjfa" in feature.string and feature.entropy > extractor._calculate_entropy(b"This is a normal string."):
                    high_entropy_feature = feature
                    break
            
            # Should have found a high entropy feature
            self.assertIsNotNone(high_entropy_feature, "No high entropy feature found")
            
            # Verify weight adjustment happened
            # Weight should be higher than base weight due to entropy
            self.assertGreater(high_entropy_feature.weight, extractor.weight)
    
    def test_is_common_string_edge_cases(self):
        """Test is_common_string edge case (line 281)"""
        extractor = StringFeatureExtractor()
        
        # Test a case that matches the path regex but not an exact match or substring
        result = extractor._is_common_string("C:\\SomeUnusualPath\\NotInTheList")
        self.assertTrue(result, "Windows path should be detected as common")
        
        # Test another type of path
        result = extractor._is_common_string("/usr/custom/path/not/in/ignore/list")
        self.assertTrue(result, "Unix path should be detected as common")
        
        # Test URL not in ignore list
        result = extractor._is_common_string("https://example.org/not/in/list")
        self.assertTrue(result, "URL should be detected as common")

class TestOpcodeExtractorRemainingPaths(unittest.TestCase):
    """Tests targeting uncovered code in OpcodeFeatureExtractor"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test executable file
        self.test_file = os.path.join(self.temp_dir, "test_file.exe")
        with open(self.test_file, "wb") as f:
            f.write(b"MZ\x90\x00" + b"\x00" * 100)
    
    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir)
    
    def test_opcode_extraction_skip_empty_line(self):
        """Test opcode extraction with empty lines (line 401, 411)"""
        extractor = OpcodeFeatureExtractor()
        
        # Mock disassembly to include empty lines and invalid lines
        disassembly = """
        00000001: push eax
        
        00000002: mov ebx, ecx
        00000003: 
        00000004: xor eax, eax
        
        00000005: invalid line with no opcode
        """
        
        with patch.object(extractor, '_get_disassembly', return_value=disassembly):
            # Extract features
            features = extractor.extract_features(self.test_file)
            
            # Should still extract valid opcodes
            self.assertEqual(len(features), 0)  # No patterns matched in this simple disassembly
    
    def test_extract_features_encryption_pattern(self):
        """Test extraction of encryption patterns (lines 428-429)"""
        extractor = OpcodeFeatureExtractor()
        
        # Create disassembly with an encryption pattern match
        # This matches the pattern: [^\n]+?aes(?:enc|keygenassist|imc)[^\n]+?\n[^\n]+?(?:pshufd|pextrq)[^\n]+?\n
        disassembly = """
        00000100: mov eax, [ebp+8]
        00000103: aesenc xmm0, xmm1
        00000108: pshufd xmm2, xmm0, 0xff
        0000010D: ret
        """
        
        with patch.object(extractor, '_get_disassembly', return_value=disassembly):
            # Extract features
            features = extractor.extract_features(self.test_file)
            
            # Should extract the encryption pattern
            self.assertGreater(len(features), 0)
            
            # Verify the feature is an encryption pattern
            encryption_features = [f for f in features if f.context.get("type") == "encryption"]
            self.assertGreater(len(encryption_features), 0)
            
            # Verify the pattern contains aesenc and pshufd
            pattern_string = encryption_features[0].opcode_str if hasattr(encryption_features[0], 'opcode_str') else str(encryption_features[0].value)
            self.assertIn("aesenc", pattern_string)
            self.assertIn("pshufd", pattern_string)

class TestScriptFeatureExtractorRemainingPaths(unittest.TestCase):
    """Tests targeting uncovered code in ScriptFeatureExtractor"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test script file with encryption keywords
        self.test_file = os.path.join(self.temp_dir, "test_script.js")
        with open(self.test_file, "w") as f:
            f.write("// This is a test script\n")
            f.write("function encryptFile() {\n")
            f.write("  var key = 'encryption_key';\n")
            f.write("  // Sensitive encryption operation\n")
            f.write("}\n\n")
            
            # Add line with ransomware indicator
            f.write("var message = 'Your files are encrypted! Pay bitcoin to restore.';\n\n")
            
            # Add lines with file operations
            f.write("function readFiles() {\n")
            f.write("  var data = readFile('important.doc');\n")
            f.write("  return data;\n")
            f.write("}\n\n")
            
            # Add BASE64 data (high entropy)
            f.write("var base64Data = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/==';\n")
    
    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir)
    
    def test_script_encryption_context_no_limit(self):
        """Test script encryption context not limited (line 716)"""
        extractor = ScriptFeatureExtractor()
        
        # Extract features
        features = extractor.extract_features(self.test_file)
        
        # Verify features were extracted
        self.assertGreater(len(features), 0)
        
        # Find the encryption feature
        encryption_features = [f for f in features if "encrypt" in f.string.lower()]
        self.assertGreater(len(encryption_features), 0)
        
        # Test specific encryption feature - context should include multiple lines
        encryption_feature = encryption_features[0]
        self.assertIn("function encryptFile", encryption_feature.string)
        self.assertIn("var key", encryption_feature.string)
        
        # Verify context has type
        self.assertEqual(encryption_feature.context.get("type"), "encryption_code")
    
    def test_script_ransomware_context_limit(self):
        """Test script ransomware context length limiting (line 744)"""
        extractor = ScriptFeatureExtractor()
        
        # Create a very long ransomware message (over 500 characters)
        long_file = os.path.join(self.temp_dir, "long_script.js")
        with open(long_file, "w") as f:
            f.write("// This is a test script with a very long ransomware message\n")
            # Write a very long line containing a ransomware indicator
            f.write("var ransomMessage = 'Your files are encrypted! " + "A" * 600 + "';\n")
        
        # Extract features
        features = extractor.extract_features(long_file)
        
        # Find the ransomware feature
        ransomware_features = [f for f in features if "files are encrypted" in f.string.lower()]
        self.assertGreater(len(ransomware_features), 0)
        
        # Check that context was limited
        ransomware_feature = ransomware_features[0]
        self.assertLessEqual(len(ransomware_feature.string), 500)
    
    def test_script_base64_detection(self):
        """Test BASE64 data detection (lines 786, 794)"""
        extractor = ScriptFeatureExtractor()
        
        # Extract features
        features = extractor.extract_features(self.test_file)
        
        # Find the BASE64 feature
        base64_features = [f for f in features 
                          if f.context.get("type") == "base64_data" or 
                          (hasattr(f, 'string') and 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' in f.string)]
        
        self.assertGreater(len(base64_features), 0)
        
        # Check that it has high entropy
        base64_feature = base64_features[0]
        self.assertGreater(base64_feature.entropy, 5.5)  # Should be above MEDIUM_ENTROPY_THRESHOLD

class TestEnhancedYaraGeneratorRemainingPaths(unittest.TestCase):
    """Tests targeting uncovered code in EnhancedYaraGenerator"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for output
        self.temp_dir = tempfile.mkdtemp()
        
        # Create samples directory
        self.samples_dir = os.path.join(self.temp_dir, "samples")
        os.makedirs(self.samples_dir, exist_ok=True)
        
        # Create a sample file
        self.sample_file = os.path.join(self.samples_dir, "test_sample.exe")
        with open(self.sample_file, "wb") as f:
            f.write(b"MZ" + b"\x00" * 100)
    
    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir)
    
    def test_legacy_generators_initialization(self):
        """Test legacy generators initialization (lines 877-878, 883-884)"""
        # Mock the legacy generator imports to appear available
        with patch('utils.yara_enhanced.enhanced_yara_generator.LEGACY_IMPORTS_AVAILABLE', True):
            # Mock the YaraRuleGenerator and RansomwareRuleGenerator classes
            yara_generator_mock = MagicMock()
            ransomware_generator_mock = MagicMock()
            
            with patch('utils.yara_enhanced.enhanced_yara_generator.YaraRuleGenerator', return_value=yara_generator_mock):
                with patch('utils.yara_enhanced.enhanced_yara_generator.RansomwareRuleGenerator', return_value=ransomware_generator_mock):
                    # Create an enhanced generator with legacy mode
                    generator = EnhancedYaraGenerator(
                        output_dir=self.temp_dir,
                        legacy_mode=True
                    )
                    
                    # Verify that legacy generators were initialized
                    self.assertIn("basic", generator.legacy_generators)
                    self.assertIn("advanced", generator.legacy_generators)
                    
                    # Verify that the mocks were used
                    self.assertEqual(generator.legacy_generators["basic"], yara_generator_mock)
                    self.assertEqual(generator.legacy_generators["advanced"], ransomware_generator_mock)
    
    def test_test_rule_against_benign_condition_adjustment(self):
        """Test benign sample testing condition adjustment (lines 1265, 1269-1270)"""
        # Create generator with benign samples directory
        benign_dir = os.path.join(self.temp_dir, "benign")
        os.makedirs(benign_dir, exist_ok=True)
        
        # Create a few benign samples
        for i in range(5):
            with open(os.path.join(benign_dir, f"benign{i}.txt"), "w") as f:
                f.write(f"Benign content {i}")
        
        generator = EnhancedYaraGenerator(
            output_dir=self.temp_dir,
            benign_samples_dir=benign_dir
        )
        
        # Create a rule with a high false positive rate
        rule = MagicMock()
        rule.features = [MagicMock() for _ in range(10)]  # More than 5 features
        rule.condition = "2 of them"
        rule.false_positive_rate = 0.06  # Higher than 0.05
        
        # Mock YARA compilation and matching
        mock_yara = MagicMock()
        mock_compiled_rule = MagicMock()
        # Simulate matches on all benign files (100% false positive)
        mock_compiled_rule.match.return_value = [MagicMock()]
        mock_yara.compile.return_value = mock_compiled_rule
        
        with patch.dict('sys.modules', {'yara': mock_yara}):
            # Run the test
            generator._test_rule_against_benign(rule)
            
            # Verify that the condition was made stricter
            self.assertEqual(rule.condition, "3 of them")
    
    def test_benign_test_false_positive_handling(self):
        """Test benign test false positive handling (line 1299)"""
        # Create generator with benign samples directory
        benign_dir = os.path.join(self.temp_dir, "benign")
        os.makedirs(benign_dir, exist_ok=True)
        
        # Create a few benign samples
        for i in range(5):
            with open(os.path.join(benign_dir, f"benign{i}.txt"), "w") as f:
                f.write(f"Benign content {i}")
        
        generator = EnhancedYaraGenerator(
            output_dir=self.temp_dir,
            benign_samples_dir=benign_dir
        )
        
        # Create a rule without "of them" in the condition
        rule = MagicMock()
        rule.features = [MagicMock() for _ in range(10)]
        rule.condition = "uint16(0) == 0x5A4D"  # Not using "of them" format
        rule.false_positive_rate = 0.06  # Higher than 0.05
        
        # Mock YARA compilation and matching
        mock_yara = MagicMock()
        mock_compiled_rule = MagicMock()
        # Simulate matches on all benign files (100% false positive)
        mock_compiled_rule.match.return_value = [MagicMock()]
        mock_yara.compile.return_value = mock_compiled_rule
        
        with patch.dict('sys.modules', {'yara': mock_yara}):
            # Run the test
            generator._test_rule_against_benign(rule)
            
            # Verify that the condition was changed to use "of them"
            self.assertEqual(rule.condition, "3 of them")

if __name__ == '__main__':
    unittest.main()