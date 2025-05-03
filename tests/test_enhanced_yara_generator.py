#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for the Enhanced YARA Rule Generator
"""

import os
import sys
import unittest
import tempfile
import shutil
from pathlib import Path

# Add parent directory to path to allow importing relative modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from utils.yara_enhanced.enhanced_yara_generator import (
    EnhancedYaraGenerator,
    StringFeatureExtractor,
    OpcodeFeatureExtractor,
    BytePatternExtractor,
    ScriptFeatureExtractor
)

class TestEnhancedYaraGenerator(unittest.TestCase):
    """Test case for the Enhanced YARA Rule Generator"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        # Create temporary directory for output
        cls.temp_dir = tempfile.mkdtemp()
        
        # Get sample directory
        cls.sample_dir = os.path.join(parent_dir, 'output', 'analysis')
        
        # Create generator
        cls.generator = EnhancedYaraGenerator(output_dir=cls.temp_dir)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment"""
        # Remove temporary directory
        shutil.rmtree(cls.temp_dir)
    
    def test_feature_extractors(self):
        """Test feature extractors"""
        # Create extractors
        string_extractor = StringFeatureExtractor()
        opcode_extractor = OpcodeFeatureExtractor()
        byte_extractor = BytePatternExtractor()
        script_extractor = ScriptFeatureExtractor()
        
        # Check extractor names
        self.assertEqual(string_extractor.name, "string_extractor")
        self.assertEqual(opcode_extractor.name, "opcode_extractor")
        self.assertEqual(byte_extractor.name, "byte_pattern_extractor")
        self.assertEqual(script_extractor.name, "script_extractor")
        
        # Check extractor weights
        self.assertEqual(string_extractor.weight, 1.0)
        self.assertEqual(opcode_extractor.weight, 1.5)
        self.assertEqual(byte_extractor.weight, 1.2)
        self.assertEqual(script_extractor.weight, 1.3)
        
        # Check extractor enabled state
        self.assertTrue(string_extractor.enabled)
        self.assertTrue(opcode_extractor.enabled)
        self.assertTrue(byte_extractor.enabled)
        self.assertTrue(script_extractor.enabled)
    
    def test_entropy_calculation(self):
        """Test entropy calculation"""
        # Test data
        data1 = b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'  # Low entropy
        data2 = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'  # Medium entropy
        data3 = os.urandom(32)  # High entropy (random data)
        
        # Calculate entropy
        entropy1 = self.generator._calculate_entropy(data1)
        entropy2 = self.generator._calculate_entropy(data2)
        entropy3 = self.generator._calculate_entropy(data3)
        
        # Check entropy values
        self.assertLess(entropy1, 1.0)  # Low entropy
        self.assertGreater(entropy2, 3.5)  # Medium entropy
        self.assertLess(entropy2, 5.0)
        self.assertGreater(entropy3, 7.5)  # High entropy
    
    def test_file_info(self):
        """Test file information extraction"""
        # Create a test file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'Test file content')
            test_file = f.name
        
        try:
            # Get file info
            file_info = self.generator._get_file_info(test_file)
            
            # Check file info
            self.assertEqual(file_info['file_name'], os.path.basename(test_file))
            self.assertEqual(file_info['file_size'], os.path.getsize(test_file))
            self.assertIn('md5', file_info)
            self.assertIn('sha1', file_info)
            self.assertIn('sha256', file_info)
            self.assertIn('entropy', file_info)
            
        finally:
            # Clean up
            os.unlink(test_file)
    
    def test_analyze_sample(self):
        """Test sample analysis"""
        # Find a sample file
        sample_files = list(Path(self.sample_dir).glob('**/*.exe'))
        if not sample_files:
            sample_files = list(Path(self.sample_dir).glob('**/*.*'))
        
        if not sample_files:
            self.skipTest("No sample files found")
            return
        
        # Use the first sample file
        sample_file = str(sample_files[0])
        
        # Analyze sample
        result = self.generator.analyze_sample(
            file_path=sample_file,
            family='TestRansomware',
            generate_rule=True
        )
        
        # Check result
        self.assertEqual(result['family'], 'TestRansomware')
        self.assertIn('file_info', result)
        self.assertIn('features', result)
        
        # Check if rule was generated
        self.assertIn('TestRansomware', self.generator.family_features)
        
        # Generate rule
        rule = self.generator.generate_rule_for_family('TestRansomware')
        
        # Check rule
        self.assertIsNotNone(rule)
        self.assertEqual(rule.family, 'TestRansomware')
        self.assertGreater(len(rule.features), 0)
        
        # Check rule file
        rule_path = os.path.join(self.generator.output_dir, f"{rule.name}.yar")
        self.assertTrue(os.path.exists(rule_path))
        
        # Check rule content
        with open(rule_path, 'r') as f:
            rule_content = f.read()
            self.assertIn('rule Ransomware_TestRansomware', rule_content)
            self.assertIn('condition:', rule_content)
    
    def test_rule_optimization(self):
        """Test rule optimization"""
        # Create a mock rule
        if not hasattr(self.generator, 'rules'):
            self.generator.rules = {}
        
        try:
            # Import required classes
            from tools.yara_rule_generator.ransomware_rule_generator import YaraRule, StringFeature
            
            # Create rule
            rule = YaraRule('Test_Rule', 'TestFamily', 'Test description')
            
            # Add features
            for i in range(30):
                feature = StringFeature(
                    f"Test string {i}",
                    weight=1.0 + (i % 5) * 0.1,
                    is_ascii=True,
                    entropy=5.0
                )
                rule.add_feature(feature)
            
            # Optimize rule
            self.generator._optimize_rule(rule)
            
            # Check optimized rule
            self.assertLessEqual(len(rule.features), 25)  # Should be limited to MAX_STRINGS_PER_RULE
            self.assertIn('of them', rule.condition)  # Should include 'of them' in condition
            
        except ImportError:
            self.skipTest("Required classes not available")
    
    def test_generate_rule_text(self):
        """Test rule text generation"""
        try:
            # Import required classes
            from tools.yara_rule_generator.ransomware_rule_generator import YaraRule
            
            # Create rule
            rule = YaraRule('Test_Rule', 'TestFamily', 'Test description')
            rule.meta['sample_count'] = 5
            rule.condition = "2 of them"
            
            # Generate rule text
            rule_text = self.generator._generate_rule_text(rule)
            
            # Check rule text
            self.assertIn('rule Test_Rule', rule_text)
            self.assertIn('meta:', rule_text)
            self.assertIn('strings:', rule_text)
            self.assertIn('condition:', rule_text)
            self.assertIn('2 of them', rule_text)
            
        except ImportError:
            self.skipTest("Required classes not available")

if __name__ == '__main__':
    unittest.main()