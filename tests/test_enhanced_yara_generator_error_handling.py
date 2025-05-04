#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for advanced error handling in the Enhanced YARA Rule Generator
"""

import os
import sys
import unittest
import tempfile
import shutil
import json
import datetime
import errno
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open, ANY, PropertyMock

# Add parent directory to path to allow importing the module
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

# Import the modules
from utils.yara_enhanced.enhanced_yara_generator import EnhancedYaraGenerator

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

class TestFileSystemErrors(unittest.TestCase):
    """Tests for file system error handling"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for output
        self.temp_dir = tempfile.mkdtemp()
        
        # Initialize generator with a valid output directory
        self.generator = EnhancedYaraGenerator(output_dir=self.temp_dir)
        
        # Create a test rule for saving tests
        self.rule = YaraRule("Ransomware_Test", "TestFamily")
        self.rule.add_feature(StringFeature("Test string", weight=1.0))
    
    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir)
    
    def test_output_dir_creation_error(self):
        """Test handling of output directory creation errors"""
        # Mock os.makedirs to raise an OSError
        with patch('os.makedirs', side_effect=OSError("Permission denied")):
            # Create a new generator with non-existent directory
            # This should handle the error gracefully
            nonexistent_dir = "/nonexistent/directory"
            generator = EnhancedYaraGenerator(output_dir=nonexistent_dir)
            
            # Verify that fallback to current directory was used
            self.assertNotEqual(generator.output_dir, nonexistent_dir)
            # Should use current directory as fallback
            self.assertTrue(os.path.exists(generator.output_dir))
    
    def test_read_nonexistent_file(self):
        """Test error handling when reading a nonexistent file"""
        # Try to analyze a non-existent file
        result = self.generator.analyze_sample("/nonexistent/file.exe", "TestFamily")
        
        # Verify error handling
        self.assertIn("error", result)
        self.assertEqual(result["error"], "File not found")
    
    def test_save_rule_permission_error(self):
        """Test error handling when saving a rule with permission issues"""
        # Mock open to raise a permission error
        mocked_open = mock_open()
        mocked_open.side_effect = PermissionError("Permission denied")
        
        # Try to save the rule
        with patch('builtins.open', mocked_open):
            # Should not raise an exception despite the error
            self.generator._save_rule(self.rule)
            
            # Verify that open was called (attempt was made)
            mocked_open.assert_called()
    
    def test_save_rule_disk_full_error(self):
        """Test error handling when disk is full during rule saving"""
        # Mock open to successfully open but write to fail with disk full error
        mocked_file = MagicMock()
        mocked_file.write.side_effect = OSError(errno.ENOSPC, "No space left on device")
        mocked_open = mock_open()
        mocked_open.return_value = mocked_file
        
        # Try to save the rule
        with patch('builtins.open', mocked_open):
            # Should not raise an exception despite the error
            self.generator._save_rule(self.rule)
            
            # Verify that open was called (attempt was made)
            mocked_open.assert_called()
    
    def test_save_combined_ruleset_io_error(self):
        """Test error handling when IO error occurs during ruleset saving"""
        # Add a rule to save
        self.generator.rules = {"TestRule": self.rule}
        
        # Mock open to raise an IOError
        mocked_open = mock_open()
        mocked_open.side_effect = IOError("IO error occurred")
        
        # Try to save the combined ruleset
        with patch('builtins.open', mocked_open):
            # Should return None on error, not raise exception
            result = self.generator.save_combined_ruleset("test_ruleset.yar")
            self.assertIsNone(result)
            
            # Verify that open was called (attempt was made)
            mocked_open.assert_called()

class TestExternalToolErrors(unittest.TestCase):
    """Tests for handling errors with external tools"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for output
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a test file
        self.test_file = os.path.join(self.temp_dir, "test_file.exe")
        with open(self.test_file, "wb") as f:
            f.write(b"MZ" + b"\x00" * 100)  # Simple PE header
        
        # Initialize generator
        self.generator = EnhancedYaraGenerator(output_dir=self.temp_dir)
    
    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir)
    
    def test_file_command_error(self):
        """Test error handling when 'file' command fails"""
        # Mock subprocess.run to raise an exception for file command
        def mock_subprocess_run(args, **kwargs):
            if args[0] == 'file':
                raise FileNotFoundError("Command 'file' not found")
            
            # For other commands, return a mock result
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = b""
            return mock_result
        
        # Try to get file info with missing 'file' command
        with patch('subprocess.run', side_effect=mock_subprocess_run):
            file_info = self.generator._get_file_info(self.test_file)
            
            # Should fallback to extension-based detection
            self.assertIn("file_type", file_info)
            # Since test_file.exe has .exe extension, should detect as PE
            self.assertEqual(file_info["file_type"], "PE executable")
    
    def test_strings_command_error(self):
        """Test error handling when 'strings' command fails"""
        # Create a StringFeatureExtractor
        from utils.yara_enhanced.enhanced_yara_generator import StringFeatureExtractor
        extractor = StringFeatureExtractor()
        
        # Mock subprocess.run to raise an exception for strings command
        def mock_subprocess_run(args, **kwargs):
            if args[0] == 'strings':
                raise FileNotFoundError("Command 'strings' not found")
            
            # For other commands, return a mock result
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = b""
            return mock_result
        
        # Try to extract features with missing 'strings' command
        with patch('subprocess.run', side_effect=mock_subprocess_run):
            # Should return empty features list, not raise exception
            features = extractor.extract_features(self.test_file)
            self.assertEqual(features, [])
    
    def test_objdump_and_radare_unavailable(self):
        """Test error handling when both objdump and radare are unavailable"""
        # Create an OpcodeFeatureExtractor
        from utils.yara_enhanced.enhanced_yara_generator import OpcodeFeatureExtractor
        extractor = OpcodeFeatureExtractor()
        
        # Mock subprocess.run to raise exceptions for disassembly tools
        def mock_subprocess_run(args, **kwargs):
            if args[0] == 'objdump' or args[0] == 'r2':
                raise FileNotFoundError(f"Command '{args[0]}' not found")
            
            # For other commands, return a mock result
            mock_result = MagicMock()
            mock_result.returncode = 1  # Command failed
            mock_result.stdout = b""
            return mock_result
        
        # Also mock os.path.exists to make radare check fail
        with patch('subprocess.run', side_effect=mock_subprocess_run):
            with patch('os.path.exists', return_value=False):
                # Should return empty string for disassembly, not raise exception
                disasm = extractor._get_disassembly(self.test_file)
                self.assertEqual(disasm, "")
                
                # Feature extraction should also handle this gracefully
                features = extractor.extract_features(self.test_file)
                self.assertEqual(features, [])

class TestYaraModuleErrors(unittest.TestCase):
    """Tests for handling YARA module errors and unavailability"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for output
        self.temp_dir = tempfile.mkdtemp()
        
        # Create benign samples directory
        self.benign_dir = os.path.join(self.temp_dir, "benign")
        os.makedirs(self.benign_dir, exist_ok=True)
        
        # Create a test file in benign directory
        self.test_file = os.path.join(self.benign_dir, "benign_file.txt")
        with open(self.test_file, "w") as f:
            f.write("This is a benign test file")
        
        # Initialize generator with benign directory
        self.generator = EnhancedYaraGenerator(
            output_dir=self.temp_dir,
            benign_samples_dir=self.benign_dir
        )
        
        # Create a test rule
        self.rule = YaraRule("TestRule", "TestFamily")
        self.rule.add_feature(StringFeature("Test string", weight=1.0))
    
    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir)
    
    def test_yara_module_import_error(self):
        """Test handling of YARA module import error"""
        # Force import error for yara module
        with patch.dict('sys.modules', {'yara': None}):
            with patch('importlib.import_module', side_effect=ImportError("No module named 'yara'")):
                # Call the method that would use yara
                self.generator._test_rule_against_benign(self.rule)
                
                # Should not have modified the rule (no testing occurred)
                self.assertEqual(self.rule.condition, "any of them")
    
    def test_yara_compile_error(self):
        """Test handling of YARA rule compile errors"""
        # Create a mock YARA module with compile raising an exception
        mock_yara = MagicMock()
        mock_yara.compile.side_effect = Exception("Error compiling rule: syntax error")
        
        with patch.dict('sys.modules', {'yara': mock_yara}):
            # Call the method that would use yara
            self.generator._test_rule_against_benign(self.rule)
            
            # Verify yara.compile was called
            mock_yara.compile.assert_called_once()
            
            # Should not have modified the rule (compilation failed)
            self.assertEqual(self.rule.condition, "any of them")
    
    def test_yara_match_error(self):
        """Test handling of errors during YARA rule matching"""
        # Create a mock compiled rule with match raising an exception
        mock_compiled_rule = MagicMock()
        mock_compiled_rule.match.side_effect = Exception("Error scanning file")
        
        # Create a mock YARA module that returns the mock rule
        mock_yara = MagicMock()
        mock_yara.compile.return_value = mock_compiled_rule
        
        with patch.dict('sys.modules', {'yara': mock_yara}):
            # Call the method that would use yara
            self.generator._test_rule_against_benign(self.rule)
            
            # Verify yara.compile and rule.match were called
            mock_yara.compile.assert_called_once()
            mock_compiled_rule.match.assert_called()
            
            # Should not have modified the rule (matching failed)
            self.assertEqual(self.rule.condition, "any of them")

class TestLegacyIntegrationErrors(unittest.TestCase):
    """Tests for handling errors in legacy integration"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for output
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a test file
        self.test_file = os.path.join(self.temp_dir, "test_file.exe")
        with open(self.test_file, "wb") as f:
            f.write(b"MZ" + b"\x00" * 100)  # Simple PE header
        
        # Initialize generator with legacy mode enabled
        self.generator = EnhancedYaraGenerator(
            output_dir=self.temp_dir,
            legacy_mode=True
        )
        
        # Create mocks for legacy generators
        self.mock_basic_generator = MagicMock()
        self.mock_advanced_generator = MagicMock()
        
        # Add mocks to generator
        self.generator.legacy_generators = {
            "basic": self.mock_basic_generator,
            "advanced": self.mock_advanced_generator
        }
    
    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir)
    
    def test_legacy_basic_generator_error(self):
        """Test handling of errors in legacy basic generator"""
        # Make basic generator raise an exception
        self.mock_basic_generator.generate_yara_rule.side_effect = Exception("Error in basic generator")
        
        # Test analysis with legacy mode
        with patch.object(self.generator, '_get_file_info', return_value={
            "file_path": self.test_file,
            "file_name": os.path.basename(self.test_file),
            "file_size": 102,
            "file_type": "PE executable",
            "md5": "test_md5",
            "sha1": "test_sha1",
            "sha256": "test_sha256",
            "entropy": 3.5
        }):
            # Call analyze_sample with legacy mode
            # This should handle the error in basic generator
            result = self.generator.analyze_sample(
                self.test_file, 
                "TestFamily", 
                analysis_data={"test": "data"}
            )
            
            # Verify that the method completed despite the error
            self.assertEqual(result["file"], self.test_file)
            self.assertEqual(result["family"], "TestFamily")
            
            # Verify legacy generators were called
            self.mock_basic_generator.generate_yara_rule.assert_called_once()
            
            # Verify legacy results were included
            self.assertIn("legacy_results", result)
            # But should not include basic_rule_path due to error
            self.assertNotIn("basic_rule_path", result["legacy_results"])
    
    def test_legacy_advanced_generator_error(self):
        """Test handling of errors in legacy advanced generator"""
        # Make advanced generator raise an exception
        self.mock_advanced_generator.analyze_sample.side_effect = Exception("Error in advanced generator")
        
        # Test analysis with legacy mode
        with patch.object(self.generator, '_get_file_info', return_value={
            "file_path": self.test_file,
            "file_name": os.path.basename(self.test_file),
            "file_size": 102,
            "file_type": "PE executable",
            "md5": "test_md5",
            "sha1": "test_sha1",
            "sha256": "test_sha256",
            "entropy": 3.5
        }):
            # Call analyze_sample with legacy mode
            # This should handle the error in advanced generator
            result = self.generator.analyze_sample(
                self.test_file, 
                "TestFamily", 
                analysis_data={"test": "data"}
            )
            
            # Verify that the method completed despite the error
            self.assertEqual(result["file"], self.test_file)
            self.assertEqual(result["family"], "TestFamily")
            
            # Verify advanced generator was called
            self.mock_advanced_generator.analyze_sample.assert_called_once()
            
            # Verify legacy results were included
            self.assertIn("legacy_results", result)
            # But should not include advanced_analysis due to error
            self.assertNotIn("advanced_analysis", result["legacy_results"])
    
    def test_legacy_mode_module_missing(self):
        """Test handling of missing legacy modules"""
        # Reset legacy generators to simulate missing modules
        self.generator.legacy_generators = {}
        
        # Set legacy mode to True
        self.generator.legacy_mode = True
        
        # Test analysis with legacy mode
        with patch.object(self.generator, '_get_file_info', return_value={
            "file_path": self.test_file,
            "file_name": os.path.basename(self.test_file),
            "file_size": 102,
            "file_type": "PE executable",
            "md5": "test_md5",
            "sha1": "test_sha1",
            "sha256": "test_sha256",
            "entropy": 3.5
        }):
            # Call analyze_sample with legacy mode
            # This should handle the missing legacy generators
            result = self.generator.analyze_sample(
                self.test_file, 
                "TestFamily", 
                analysis_data={"test": "data"}
            )
            
            # Verify that the method completed despite missing legacy generators
            self.assertEqual(result["file"], self.test_file)
            self.assertEqual(result["family"], "TestFamily")
            
            # Should not include legacy_results
            self.assertNotIn("legacy_results", result)

class TestMalformedInputAndEdgeCases(unittest.TestCase):
    """Tests for handling malformed inputs and edge cases"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for output
        self.temp_dir = tempfile.mkdtemp()
        
        # Initialize generator
        self.generator = EnhancedYaraGenerator(output_dir=self.temp_dir)
    
    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir)
    
    def test_analyze_sample_with_bytes_path(self):
        """Test analyzing a sample with bytes path instead of string"""
        # Get current path as bytes
        bytes_path = os.path.abspath(__file__).encode('utf-8')
        
        # Call analyze_sample with bytes path
        # This should handle the conversion or raise a meaningful error
        try:
            result = self.generator.analyze_sample(bytes_path, "TestFamily")
            # If it succeeds, verify the result
            self.assertIn("file", result)
        except TypeError:
            # If it raises TypeError, that's also acceptable
            pass
    
    def test_empty_family_name(self):
        """Test rule generation with empty family name"""
        # Create features for empty family
        self.generator.family_features[""] = [
            StringFeature("Test string", weight=1.0)
        ]
        
        # Generate rule with empty family name
        rule = self.generator.generate_rule_for_family("")
        
        # Verify rule properties
        self.assertIsNotNone(rule)
        self.assertEqual(rule.family, "")
        self.assertEqual(rule.name, "Ransomware_")
    
    def test_malformed_rule_template(self):
        """Test handling of malformed rule template"""
        # Create malformed template
        template_path = os.path.join(self.templates_dir, 'ransomware_template.yara')
        os.makedirs(os.path.dirname(template_path), exist_ok=True)
        
        with open(template_path, 'w') as f:
            f.write("This is not a valid template {unclosed_brace")
        
        # Create a rule
        rule = YaraRule("TestRule", "TestFamily")
        rule.add_feature(StringFeature("Test string", weight=1.0))
        
        # Generate rule text
        # This should handle the malformed template
        try:
            rule_text = self.generator._generate_rule_text(rule)
            # If it succeeds, some fallback or error handling was used
            self.assertIn("TestRule", rule_text)
        except Exception as e:
            # If it raises an exception, it should be a KeyError or ValueError,
            # not something unexpected like TypeError or AttributeError
            self.assertIsInstance(e, (KeyError, ValueError, IndexError))
    
    def test_unicode_in_family_name(self):
        """Test handling of Unicode characters in family name"""
        # Family name with Unicode characters
        family_name = "Тест家族ฟิชเชอร์"
        
        # Create features for Unicode family
        self.generator.family_features[family_name] = [
            StringFeature("Test string", weight=1.0)
        ]
        
        # Generate rule with Unicode family name
        rule = self.generator.generate_rule_for_family(family_name)
        
        # Verify rule properties
        self.assertIsNotNone(rule)
        self.assertEqual(rule.family, family_name)
        
        # Generate rule text
        rule_text = self.generator._generate_rule_text(rule)
        
        # Verify Unicode was handled correctly
        self.assertIn(family_name, rule_text)
    
    def test_extremely_long_family_name(self):
        """Test handling of extremely long family name"""
        # Generate an extremely long family name
        long_family_name = "A" * 1000
        
        # Create features for long family
        self.generator.family_features[long_family_name] = [
            StringFeature("Test string", weight=1.0)
        ]
        
        # Generate rule with long family name
        rule = self.generator.generate_rule_for_family(long_family_name)
        
        # Verify rule was created
        self.assertIsNotNone(rule)
        self.assertEqual(rule.family, long_family_name)
        
        # Rule name should use the long family name
        self.assertEqual(rule.name, f"Ransomware_{long_family_name}")
        
        # Generate rule text (should not raise exception)
        rule_text = self.generator._generate_rule_text(rule)
        
        # Verify long name was used
        self.assertIn(long_family_name, rule_text)

if __name__ == '__main__':
    unittest.main()