#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for the complete rule generation workflow in the Enhanced YARA Rule Generator
"""

import os
import sys
import unittest
import tempfile
import shutil
import json
import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open, ANY

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

class TestRuleGenerationWorkflow(unittest.TestCase):
    """Tests for the complete rule generation workflow"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for output
        self.temp_dir = tempfile.mkdtemp()
        
        # Create sample directory
        self.samples_dir = os.path.join(self.temp_dir, "samples")
        os.makedirs(self.samples_dir, exist_ok=True)
        
        # Create benign samples directory
        self.benign_dir = os.path.join(self.temp_dir, "benign")
        os.makedirs(self.benign_dir, exist_ok=True)
        
        # Create ransomware sample files (simulated)
        self.create_test_samples()
        
        # Create benign files for testing
        self.create_benign_samples()
        
        # Initialize generator with the benign samples directory
        self.generator = EnhancedYaraGenerator(
            output_dir=os.path.join(self.temp_dir, "rules"),
            benign_samples_dir=self.benign_dir
        )
        
        # Initialize extractors for patching
        self.mock_string_extractor = MagicMock()
        self.mock_byte_extractor = MagicMock()
        self.mock_opcode_extractor = MagicMock()
        self.mock_script_extractor = MagicMock()
        
        # Set up return values for mock extractors
        self.mock_string_extractor.extract_features.return_value = [
            StringFeature("Ransomware String 1", weight=1.5),
            StringFeature("encrypted files", weight=1.8),
            StringFeature("bitcoin payment", weight=2.0)
        ]
        self.mock_string_extractor.can_handle.return_value = True
        self.mock_string_extractor.name = "string_extractor"
        self.mock_string_extractor.weight = 1.0
        self.mock_string_extractor.enabled = True
        
        self.mock_byte_extractor.extract_features.return_value = [
            BytePatternFeature(b"MZ\x90\x00", weight=1.2, offset=0, context={"type": "file_header"})
        ]
        self.mock_byte_extractor.can_handle.return_value = True
        self.mock_byte_extractor.name = "byte_pattern_extractor"
        self.mock_byte_extractor.weight = 1.2
        self.mock_byte_extractor.enabled = True
        
        self.mock_opcode_extractor.extract_features.return_value = [
            OpcodeFeature("mov eax, ebx; xor eax, eax", weight=1.5, context={"type": "encryption"})
        ]
        self.mock_opcode_extractor.can_handle.return_value = False  # Only match on exe files
        self.mock_opcode_extractor.name = "opcode_extractor"
        self.mock_opcode_extractor.weight = 1.5
        self.mock_opcode_extractor.enabled = True
        
        self.mock_script_extractor.extract_features.return_value = [
            StringFeature("ransom script feature", weight=1.3, context={"type": "ransomware_indicator"})
        ]
        self.mock_script_extractor.can_handle.return_value = False  # Only match on script files
        self.mock_script_extractor.name = "script_extractor"
        self.mock_script_extractor.weight = 1.3
        self.mock_script_extractor.enabled = True
    
    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir)
    
    def create_test_samples(self):
        """Create test ransomware sample files"""
        # Sample 1: Executable with MZ header
        sample1_path = os.path.join(self.samples_dir, "sample1.exe")
        with open(sample1_path, "wb") as f:
            f.write(b'MZ')
            f.write(b'This is a test executable with encryption functions')
            f.write(b'AES_Encrypt')
            f.write(b'Your files are encrypted')
        
        # Sample 2: JavaScript file
        sample2_path = os.path.join(self.samples_dir, "sample2.js")
        with open(sample2_path, "w") as f:
            f.write("function encryptFiles() {\n")
            f.write("  var files = getAllUserFiles();\n")
            f.write("  for (var i = 0; i < files.length; i++) {\n")
            f.write("    var encrypted = AES.encrypt(files[i].data);\n")
            f.write("    writeFile(files[i].path + '.locked', encrypted);\n")
            f.write("  }\n")
            f.write("  displayRansomNote('Pay 1 bitcoin to unlock your files');\n")
            f.write("}\n")
        
        # Sample 3: Text file with ransom note
        sample3_path = os.path.join(self.samples_dir, "sample3.txt")
        with open(sample3_path, "w") as f:
            f.write("YOUR FILES HAVE BEEN ENCRYPTED!\n\n")
            f.write("To recover your files, you need to pay 1 Bitcoin to this address:\n")
            f.write("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n\n")
            f.write("After payment, contact us at evil@ransomware.example.com with your payment ID.\n")
        
        # Store sample paths for later use
        self.sample_paths = [sample1_path, sample2_path, sample3_path]
    
    def create_benign_samples(self):
        """Create benign sample files for testing"""
        # Benign 1: Regular executable
        benign1_path = os.path.join(self.benign_dir, "benign1.exe")
        with open(benign1_path, "wb") as f:
            f.write(b'MZ')
            f.write(b'This is a benign executable file')
            f.write(b'with normal functionality')
        
        # Benign 2: Regular JavaScript file
        benign2_path = os.path.join(self.benign_dir, "benign2.js")
        with open(benign2_path, "w") as f:
            f.write("function calculateTotal(items) {\n")
            f.write("  var total = 0;\n")
            f.write("  for (var i = 0; i < items.length; i++) {\n")
            f.write("    total += items[i].price;\n")
            f.write("  }\n")
            f.write("  return total;\n")
            f.write("}\n")
        
        # Benign 3: Regular text file
        benign3_path = os.path.join(self.benign_dir, "benign3.txt")
        with open(benign3_path, "w") as f:
            f.write("This is a regular text file.\n")
            f.write("It contains no malicious content.\n")
            f.write("Just some normal text for testing purposes.\n")
    
    def test_full_analysis_to_rule_workflow(self):
        """Test the complete workflow from analysis to rule generation"""
        # Define the test family
        family_name = "TestRansomware"
        
        # Patch the feature extractors to return controllable results
        with patch.object(self.generator, 'extractors', [
            self.mock_string_extractor,
            self.mock_byte_extractor,
            self.mock_opcode_extractor,
            self.mock_script_extractor
        ]):
            # Mock _get_file_info to return a consistent result
            with patch.object(self.generator, '_get_file_info', return_value={
                "file_path": self.sample_paths[0],
                "file_name": os.path.basename(self.sample_paths[0]),
                "file_size": 1024,
                "file_type": "PE executable",
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "entropy": 7.2
            }):
                # Check that no families are present initially
                self.assertEqual(len(self.generator.family_features), 0)
                
                # Analyze the first sample
                result1 = self.generator.analyze_sample(self.sample_paths[0], family_name)
                
                # Verify that the family was added
                self.assertIn(family_name, self.generator.family_features)
                
                # Verify the result contains expected data
                self.assertEqual(result1["file"], self.sample_paths[0])
                self.assertEqual(result1["family"], family_name)
                self.assertIn("file_info", result1)
                self.assertIn("features", result1)
                
                # Analyze the second sample (with generate_rule=True)
                result2 = self.generator.analyze_sample(self.sample_paths[0], family_name, generate_rule=True)
                
                # Verify the result contains rule information
                self.assertIn("rule", result2)
                self.assertIn("rule_path", result2)
                
                # Check that the rule was generated with the expected name
                expected_rule_name = f"Ransomware_{family_name}"
                self.assertEqual(result2["rule"], expected_rule_name)
                
                # Check that the rule file exists
                rule_path = result2["rule_path"]
                self.assertTrue(os.path.exists(rule_path))
                
                # Check rule content
                with open(rule_path, "r") as f:
                    rule_content = f.read()
                    self.assertIn(expected_rule_name, rule_content)
                    self.assertIn("meta:", rule_content)
                    self.assertIn("strings:", rule_content)
                    self.assertIn("condition:", rule_content)
    
    def test_generate_rule_for_family(self):
        """Test generating a rule for a specific family"""
        family_name = "TestFamily"
        
        # Create mock features
        string_feature = StringFeature("Ransomware Feature", weight=1.5)
        byte_feature = BytePatternFeature(b"MZ\x90\x00", weight=1.2, offset=0)
        
        # Add features for the family
        self.generator.family_features[family_name] = [string_feature, byte_feature]
        
        # Generate a rule
        rule = self.generator.generate_rule_for_family(family_name)
        
        # Verify the rule was generated
        self.assertIsNotNone(rule)
        self.assertEqual(rule.name, f"Ransomware_{family_name}")
        self.assertEqual(rule.family, family_name)
        self.assertEqual(len(rule.features), 2)
        
        # Check that the rule file was created
        rule_path = os.path.join(self.generator.output_dir, f"{rule.name}.yar")
        self.assertTrue(os.path.exists(rule_path))
        
        # Check that the metadata file was created
        metadata_path = os.path.join(self.generator.metadata_dir, f"{rule.name}.json")
        self.assertTrue(os.path.exists(metadata_path))
        
        # Verify metadata content
        with open(metadata_path, "r") as f:
            metadata = json.load(f)
            self.assertEqual(metadata["name"], rule.name)
            self.assertEqual(metadata["family"], family_name)
            self.assertEqual(metadata["features_count"], 2)
    
    def test_generate_rule_for_family_no_features(self):
        """Test generating a rule when no features are available"""
        family_name = "EmptyFamily"
        
        # Don't add any features
        # self.generator.family_features[family_name] = []
        
        # Try to generate a rule
        rule = self.generator.generate_rule_for_family(family_name)
        
        # Rule should be None
        self.assertIsNone(rule)
    
    def test_generate_rule_for_family_update_existing(self):
        """Test updating an existing rule with new features"""
        family_name = "UpdateFamily"
        
        # Create initial features and rule
        initial_feature = StringFeature("Initial Feature", weight=1.0)
        self.generator.family_features[family_name] = [initial_feature]
        
        # Generate initial rule
        initial_rule = self.generator.generate_rule_for_family(family_name)
        
        # Add new features
        new_feature = StringFeature("New Feature", weight=1.5)
        self.generator.family_features[family_name].append(new_feature)
        
        # Generate updated rule
        updated_rule = self.generator.generate_rule_for_family(family_name)
        
        # Verify the rule was updated
        self.assertEqual(updated_rule.name, initial_rule.name)
        self.assertEqual(len(updated_rule.features), 2)
        
        # Check the rule content was updated
        rule_path = os.path.join(self.generator.output_dir, f"{updated_rule.name}.yar")
        with open(rule_path, "r") as f:
            rule_content = f.read()
            # Both features should be present in the updated rule
            self.assertIn("Initial Feature", rule_content)
            self.assertIn("New Feature", rule_content)
    
    def test_generate_all_rules(self):
        """Test generating rules for all families"""
        # Add features for multiple families
        families = ["Family1", "Family2", "Family3"]
        
        for family in families:
            self.generator.family_features[family] = [
                StringFeature(f"{family} Feature 1", weight=1.0),
                StringFeature(f"{family} Feature 2", weight=1.5)
            ]
        
        # Generate rules for all families
        rules = self.generator.generate_all_rules()
        
        # Verify rules were generated for all families
        self.assertEqual(len(rules), len(families))
        
        # Verify each rule was saved to disk
        for family in families:
            rule_name = f"Ransomware_{family}"
            rule_path = os.path.join(self.generator.output_dir, f"{rule_name}.yar")
            metadata_path = os.path.join(self.generator.metadata_dir, f"{rule_name}.json")
            
            self.assertTrue(os.path.exists(rule_path))
            self.assertTrue(os.path.exists(metadata_path))
    
    def test_save_combined_ruleset(self):
        """Test saving all rules as a combined ruleset"""
        # Add features for multiple families
        families = ["Family1", "Family2", "Family3"]
        
        for family in families:
            self.generator.family_features[family] = [
                StringFeature(f"{family} Feature 1", weight=1.0),
                StringFeature(f"{family} Feature 2", weight=1.5)
            ]
        
        # Generate rules for all families
        rules = self.generator.generate_all_rules()
        
        # Save combined ruleset
        output_file = "combined_rules.yar"
        ruleset_path = self.generator.save_combined_ruleset(output_file)
        
        # Verify ruleset was saved
        self.assertIsNotNone(ruleset_path)
        self.assertTrue(os.path.exists(ruleset_path))
        
        # Check ruleset content
        with open(ruleset_path, "r") as f:
            ruleset_content = f.read()
            
            # Verify header
            self.assertIn("Enhanced Ransomware Detection YARA Rules", ruleset_content)
            self.assertIn("Generated:", ruleset_content)
            
            # Verify all families are included
            for family in families:
                self.assertIn(f"Ransomware_{family}", ruleset_content)
                self.assertIn(f"{family} Feature 1", ruleset_content)
                self.assertIn(f"{family} Feature 2", ruleset_content)
    
    def test_save_combined_ruleset_no_rules(self):
        """Test saving combined ruleset when no rules exist"""
        # Don't add any families or generate any rules
        
        # Try to save combined ruleset
        output_file = "empty_ruleset.yar"
        ruleset_path = self.generator.save_combined_ruleset(output_file)
        
        # Ruleset path should be None
        self.assertIsNone(ruleset_path)
        
        # File should not exist
        expected_path = os.path.join(self.generator.output_dir, output_file)
        self.assertFalse(os.path.exists(expected_path))

    @patch('yara.compile')
    def test_test_rule_against_benign(self, mock_yara_compile):
        """Test the benign sample testing functionality with mock YARA"""
        # Create a rule for testing
        rule = YaraRule("TestRule", "TestFamily")
        rule.add_feature(StringFeature("This is a benign", weight=1.0))
        rule.condition = "all of them"
        
        # Mock the YARA compile and match functionality
        mock_compiled_rule = MagicMock()
        # Configure to 'match' our benign files
        mock_compiled_rule.match.return_value = ["fake_match"]
        mock_yara_compile.return_value = mock_compiled_rule
        
        # Test the rule against benign samples
        self.generator._test_rule_against_benign(rule)
        
        # Verify that YARA was called to compile the rule
        mock_yara_compile.assert_called_once()
        
        # Verify that matches were checked
        mock_compiled_rule.match.assert_called()
        
        # Rule condition should have been adjusted due to false positives
        self.assertNotEqual(rule.condition, "all of them")
        self.assertIn("of them", rule.condition)
        
        # Verify false positive rate was updated
        self.assertTrue(hasattr(rule, "false_positive_rate"))
        self.assertGreaterEqual(rule.false_positive_rate, 0)

    def test_analyze_sample_file_not_found(self):
        """Test analyzing a non-existent sample file"""
        # Try to analyze a non-existent file
        result = self.generator.analyze_sample("/nonexistent/file.exe", "TestFamily")
        
        # Verify error result
        self.assertIn("error", result)
        self.assertEqual(result["error"], "File not found")

    def test_analyze_sample_legacy_mode(self):
        """Test analyzing a sample in legacy mode"""
        # Set up generator with legacy mode
        legacy_generator = EnhancedYaraGenerator(
            output_dir=os.path.join(self.temp_dir, "legacy_rules"),
            legacy_mode=True
        )
        
        # Mock the legacy generators
        mock_basic_generator = MagicMock()
        mock_basic_generator.generate_yara_rule.return_value = "/path/to/basic_rule.yar"
        
        mock_advanced_generator = MagicMock()
        mock_advanced_generator.analyze_sample.return_value = {"success": True}
        
        legacy_generator.legacy_generators = {
            "basic": mock_basic_generator,
            "advanced": mock_advanced_generator
        }
        
        # Patch the feature extractors and file info
        with patch.object(legacy_generator, 'extractors', [self.mock_string_extractor]):
            with patch.object(legacy_generator, '_get_file_info', return_value={
                "file_path": self.sample_paths[0],
                "file_name": os.path.basename(self.sample_paths[0]),
                "file_size": 1024,
                "file_type": "PE executable",
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "entropy": 7.2
            }):
                # Analyze the sample with legacy mode
                result = legacy_generator.analyze_sample(
                    self.sample_paths[0], 
                    "TestFamily",
                    analysis_data={"some": "analysis"}
                )
                
                # Verify that legacy generators were called
                mock_basic_generator.generate_yara_rule.assert_called_once()
                mock_advanced_generator.analyze_sample.assert_called_once_with(
                    self.sample_paths[0], "TestFamily"
                )
                
                # Verify the result contains legacy results
                self.assertIn("legacy_results", result)
                self.assertIn("basic_rule_path", result["legacy_results"])
                self.assertIn("advanced_analysis", result["legacy_results"])

    def test_legacy_imports_handling(self):
        """Test handling of legacy imports"""
        with patch.dict('sys.modules', {
            'threat_intel.rules.yara_generator': None,
            'tools.yara_rule_generator.ransomware_rule_generator': None
        }):
            with patch('importlib.import_module', side_effect=ImportError("Module not found")):
                # Create a generator, should work without legacy imports
                generator = EnhancedYaraGenerator(
                    output_dir=os.path.join(self.temp_dir, "no_legacy_rules")
                )
                
                # Verify that LEGACY_IMPORTS_AVAILABLE is False
                self.assertFalse(generator.legacy_mode)
                
                # Should be able to analyze samples without legacy imports
                with patch.object(generator, '_get_file_info', return_value={
                    "file_path": self.sample_paths[0],
                    "file_name": os.path.basename(self.sample_paths[0]),
                    "file_size": 1024,
                    "file_type": "PE executable",
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "entropy": 7.2
                }):
                    with patch.object(generator, 'extractors', [self.mock_string_extractor]):
                        # This should not raise an exception
                        result = generator.analyze_sample(self.sample_paths[0], "TestFamily")
                        
                        # Verify basic functionality still works
                        self.assertEqual(result["file"], self.sample_paths[0])
                        self.assertEqual(result["family"], "TestFamily")
                        self.assertIn("features", result)

if __name__ == '__main__':
    unittest.main()