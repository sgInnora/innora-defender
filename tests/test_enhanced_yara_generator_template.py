#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for the template handling functionality in the Enhanced YARA Rule Generator
"""

import os
import sys
import unittest
import tempfile
import shutil
import datetime
import json
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

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

class TestTemplateHandling(unittest.TestCase):
    """Tests for the template handling functionality"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for output
        self.temp_dir = tempfile.mkdtemp()
        
        # Create templates directory
        self.templates_dir = os.path.join(self.temp_dir, 'templates')
        os.makedirs(self.templates_dir, exist_ok=True)
        
        # Initialize generator
        self.generator = EnhancedYaraGenerator(output_dir=self.temp_dir)
        
        # Create a test rule with features of different types
        self.rule = YaraRule("Ransomware_Test", "TestFamily", "Test rule")
        self.rule.meta = {
            "description": "Test rule for ransomware detection",
            "sample_count": 5,
            "generated_date": datetime.datetime.now().strftime("%Y-%m-%d")
        }
        
        # Add string features with different weights
        for i in range(3):
            weight = 1.0 + (i % 3) * 0.5  # Weights: 1.0, 1.5, 2.0
            feature = StringFeature(
                f"Test string {i}",
                weight=weight,
                is_ascii=True,
                entropy=5.0 + (i % 3) * 0.5  # Entropy values between 5.0 and 6.0
            )
            self.rule.add_feature(feature)
    
    def tearDown(self):
        """Clean up temporary files"""
        shutil.rmtree(self.temp_dir)
    
    def test_create_default_templates(self):
        """Test creation of default templates"""
        # Explicitly call the method to create templates
        self.generator._create_default_templates()
        
        # Check if template file exists
        template_file = os.path.join(self.templates_dir, 'ransomware_template.yara')
        self.assertTrue(os.path.exists(template_file), "Default template file should be created")
        
        # Check if template contains expected sections
        with open(template_file, 'r') as f:
            template_content = f.read()
            self.assertIn("{rule_name}", template_content)
            self.assertIn("{description}", template_content)
            self.assertIn("{date}", template_content)
            self.assertIn("{hash}", template_content)
            self.assertIn("{family}", template_content)
            self.assertIn("{confidence}", template_content)
            self.assertIn("{string_definitions}", template_content)
            self.assertIn("{condition}", template_content)
    
    def test_create_default_templates_existing(self):
        """Test behavior when template already exists"""
        # Create a custom template file first
        template_file = os.path.join(self.templates_dir, 'ransomware_template.yara')
        custom_content = "CUSTOM TEMPLATE CONTENT"
        with open(template_file, 'w') as f:
            f.write(custom_content)
        
        # Call method to create templates
        self.generator._create_default_templates()
        
        # Check if template file still contains our custom content
        with open(template_file, 'r') as f:
            template_content = f.read()
            self.assertEqual(template_content, custom_content, 
                          "Existing template file should not be overwritten")
    
    def test_generate_rule_text(self):
        """Test rule text generation using template"""
        # Set up a custom template for testing
        custom_template = """rule {rule_name}
{
    meta:
        description = "{description}"
        family = "{family}"
        date = "{date}"
        hash = "{hash}"
        confidence = "{confidence}"
    
    strings:
{string_definitions}
    
    condition:
        {condition}
}"""
        template_file = os.path.join(self.templates_dir, 'ransomware_template.yara')
        with open(template_file, 'w') as f:
            f.write(custom_template)
        
        # Generate rule text
        rule_text = self.generator._generate_rule_text(self.rule)
        
        # Check if rule text contains expected content
        self.assertIn(f"rule {self.rule.name}", rule_text)
        self.assertIn(f'description = "{self.rule.meta.get("description")}"', rule_text)
        self.assertIn(f'family = "{self.rule.family}"', rule_text)
        self.assertIn(f'condition = "{self.rule.condition}"', rule_text)
        
        # Check if string definitions were included
        for feature in self.rule.features:
            feature_string = feature.to_yara_string()
            self.assertIn(feature_string, rule_text)
    
    def test_generate_rule_text_missing_template(self):
        """Test rule text generation when template is missing"""
        # Remove the template file
        template_file = os.path.join(self.templates_dir, 'ransomware_template.yara')
        if os.path.exists(template_file):
            os.remove(template_file)
        
        # Call the method (should automatically create the template first)
        rule_text = self.generator._generate_rule_text(self.rule)
        
        # Check if rule text was generated with the default template
        self.assertIn(f"rule {self.rule.name}", rule_text)
        self.assertIn("meta:", rule_text)
        self.assertIn("strings:", rule_text)
        self.assertIn("condition:", rule_text)
    
    def test_generate_rule_text_with_special_chars(self):
        """Test rule text generation with special characters in feature strings"""
        # Create rule with special character strings
        special_rule = YaraRule("Special_Test", "TestSpecial")
        
        # Add string with quotes and backslashes
        special_rule.add_feature(StringFeature(r'String with "quotes" and \backslashes\\', weight=1.0))
        
        # Add string with newlines
        special_rule.add_feature(StringFeature("String with\nnewlines\nand\r\ncarriage returns", weight=1.0))
        
        # Add string with regex-like content
        special_rule.add_feature(StringFeature(r'[a-zA-Z0-9]+\.\*\+\?', weight=1.0))
        
        # Generate rule text
        rule_text = self.generator._generate_rule_text(special_rule)
        
        # Check if rule text was generated correctly
        self.assertIn(f"rule {special_rule.name}", rule_text)
        
        # Check if each feature is present in the output
        for feature in special_rule.features:
            # We don't check for the exact string representation as that depends on
            # the escaping logic in to_yara_string() which we're not testing here
            self.assertIn("$string_", rule_text)
    
    def test_save_rule(self):
        """Test saving rule to disk"""
        # Save the rule
        self.generator._save_rule(self.rule)
        
        # Check if rule file exists
        rule_file = os.path.join(self.temp_dir, f"{self.rule.name}.yar")
        self.assertTrue(os.path.exists(rule_file), "Rule file should be created")
        
        # Check if metadata file exists
        metadata_file = os.path.join(self.temp_dir, 'metadata', f"{self.rule.name}.json")
        self.assertTrue(os.path.exists(metadata_file), "Metadata file should be created")
        
        # Check rule file content
        with open(rule_file, 'r') as f:
            rule_content = f.read()
            self.assertIn(f"rule {self.rule.name}", rule_content)
            self.assertIn("condition:", rule_content)
        
        # Check metadata file content
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
            self.assertEqual(metadata["name"], self.rule.name)
            self.assertEqual(metadata["family"], self.rule.family)
            self.assertEqual(metadata["condition"], self.rule.condition)
    
    def test_save_combined_ruleset(self):
        """Test saving combined ruleset"""
        # Create a few rules
        family_names = ["TestFamily1", "TestFamily2", "TestFamily3"]
        for i, family in enumerate(family_names):
            rule_name = f"Ransomware_{family}"
            rule = YaraRule(rule_name, family, f"Test rule for {family}")
            rule.add_feature(StringFeature(f"Test string for {family}", weight=1.0))
            self.generator.rules[rule_name] = rule
        
        # Save combined ruleset
        output_file = "combined_test_rules.yar"
        output_path = self.generator.save_combined_ruleset(output_file)
        
        # Check if output file exists
        self.assertTrue(os.path.exists(output_path), "Combined ruleset file should be created")
        
        # Check file content
        with open(output_path, 'r') as f:
            ruleset_content = f.read()
            # Check header
            self.assertIn("Enhanced Ransomware Detection YARA Rules", ruleset_content)
            self.assertIn("Generated:", ruleset_content)
            # Check all family names are mentioned
            for family in family_names:
                self.assertIn(family, ruleset_content)
    
    def test_save_combined_ruleset_no_rules(self):
        """Test saving combined ruleset with no rules"""
        # Clear existing rules
        self.generator.rules = {}
        
        # Attempt to save combined ruleset
        output_file = "empty_combined_rules.yar"
        output_path = self.generator.save_combined_ruleset(output_file)
        
        # Should return None
        self.assertIsNone(output_path, "Should return None when no rules exist")
        
        # Check that no file was created
        expected_path = os.path.join(self.temp_dir, output_file)
        self.assertFalse(os.path.exists(expected_path), "No file should be created when no rules exist")
    
    def test_template_variable_substitution(self):
        """Test template variable substitution with various values"""
        # Create a simple template with all variables
        simple_template = """rule {rule_name}
// Description: {description}
// Family: {family}
// Date: {date}
// Hash: {hash}
// Confidence: {confidence}
// Threat Level: {threat_level}
// Reference: {reference}
// Sample Count: {sample_count}

strings:
{string_definitions}

condition:
    {condition}
"""
        template_file = os.path.join(self.templates_dir, 'ransomware_template.yara')
        with open(template_file, 'w') as f:
            f.write(simple_template)
        
        # Create a rule with various metadata values
        test_rule = YaraRule("TemplateTest", "TemplateFamily", "Template test rule")
        test_rule.meta = {
            "description": "Rule with special characters: %$#@!",
            "sample_count": 42,
            "reference": "https://example.com/sample?id=123&ref=test"
        }
        test_rule.confidence = 0.95
        test_rule.add_feature(StringFeature("Template test string", weight=1.0))
        
        # Generate rule text
        rule_text = self.generator._generate_rule_text(test_rule)
        
        # Check variable substitution
        self.assertIn("rule TemplateTest", rule_text)
        self.assertIn("// Description: Rule with special characters: %$#@!", rule_text)
        self.assertIn("// Family: TemplateFamily", rule_text)
        self.assertIn(f"// Date: {datetime.datetime.now().strftime('%Y-%m-%d')}", rule_text)
        self.assertIn("// Confidence: high", rule_text)
        self.assertIn("// Sample Count: 42", rule_text)
        self.assertIn("Template test string", rule_text)
    
    def test_template_with_format_escapes(self):
        """Test template with escaped curly braces"""
        # Create a template that contains formatting escape sequences
        escaped_template = """rule {rule_name}
{{
    // Double braces should be escaped: {{ escaped }}
    meta:
        description = "{description}"
        sample_count = {sample_count}
        
    strings:
{string_definitions}
        
    condition:
        {condition}
}}
"""
        template_file = os.path.join(self.templates_dir, 'ransomware_template.yara')
        with open(template_file, 'w') as f:
            f.write(escaped_template)
        
        # Generate rule text
        rule_text = self.generator._generate_rule_text(self.rule)
        
        # Check if braces were properly escaped
        self.assertIn("{ escaped }", rule_text)
        self.assertIn("rule Ransomware_Test", rule_text)
        self.assertIn("description = ", rule_text)

if __name__ == '__main__':
    unittest.main()