#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Special test file that focuses on specific uncovered code sections
"""

import os
import sys
import unittest
import tempfile
import json
import hashlib
import shutil
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import module with testing mode
from decryption_tools.network_forensics import lockbit_optimized_recovery

# Set up a test fixture class
class TestUncoveredSections(unittest.TestCase):
    """Test class focusing on uncovered sections"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create recovery instance with testing mode
        self.recovery = lockbit_optimized_recovery.OptimizedLockBitRecovery(
            testing_mode=True,
            work_dir=self.temp_dir
        )
        
        # Create sample encrypted file
        self.encrypted_file = os.path.join(self.temp_dir, "test.docx.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}")
        with open(self.encrypted_file, 'wb') as f:
            # Write header with realistic data
            header = b'\x00' * 16 + b'\x01' * 16
            f.write(header)
            # Write encrypted data
            f.write(b'\x02' * 1024)
            # Write footer with KEY marker
            f.write(b'KEY' + b'\x03' * 32)
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir)
    
    def test_parse_file_variants(self):
        """Test EnhancedFileFormat with different file variants"""
        # Test with LockBit 2.0 UUID format
        file_2_0 = self.encrypted_file
        format_2_0 = lockbit_optimized_recovery.EnhancedFileFormat(file_2_0, testing_mode=True)
        self.assertEqual(format_2_0.version, "2.0")
        self.assertTrue(format_2_0.has_uuid_extension)
        
        # Test with LockBit 3.0 format
        lb3_file = os.path.join(self.temp_dir, "test.docx.lockbit3")
        with open(lb3_file, 'wb') as f:
            # Write LockBit 3.0 header
            header = b'LOCKBIT3\x01\x00\x00\x00' + b'\x01' * 16
            f.write(header)
            # Write encrypted data
            f.write(b'\x02' * 1024)
        
        format_3_0 = lockbit_optimized_recovery.EnhancedFileFormat(lb3_file, testing_mode=True)
        self.assertEqual(format_3_0.version, "3.0")
        self.assertFalse(format_3_0.has_uuid_extension)
        
        # Test with RestoreBackup format
        restore_file = os.path.join(self.temp_dir, "test.docx.restorebackup")
        with open(restore_file, 'wb') as f:
            # Write some data
            f.write(b'\x01' * 1024)
        
        format_restore = lockbit_optimized_recovery.EnhancedFileFormat(restore_file, testing_mode=True)
        self.assertEqual(format_restore.version, "RestoreBackup")
    
    def test_fallback_methods(self):
        """Test fallback methods with testing mode"""
        # Create file format instance
        file_format = lockbit_optimized_recovery.EnhancedFileFormat(self.encrypted_file, testing_mode=True)
        
        # Test keys and IVs
        key_candidates = [b'A' * 32]
        iv_candidates = [b'B' * 16]
        output_file = os.path.join(self.temp_dir, "decrypted.bin")
        
        # Call fallback methods directly
        result = self.recovery._try_fallback_methods(
            file_format, key_candidates, iv_candidates, output_file
        )
        
        # In testing mode, this should succeed
        self.assertTrue(result['success'])
        self.assertTrue(os.path.exists(output_file))
    
    def test_batch_processing(self):
        """Test batch processing directory"""
        # Create a batch directory
        batch_dir = os.path.join(self.temp_dir, "batch")
        os.makedirs(batch_dir)
        
        # Create a few test files
        for i in range(3):
            file_path = os.path.join(batch_dir, f"test{i}.docx.{{1765FE8E-2103-66E3-7DCB-72284ABD03AA}}")
            with open(file_path, 'wb') as f:
                # Simple header and data
                f.write(b'\x00' * 32)
                f.write(b'\x01' * 1024)
        
        # Process the directory
        result = self.recovery.batch_process_directory(batch_dir)
        
        # We should have found and processed 3 files
        self.assertEqual(result['total'], 3)
        # In testing mode, all should decrypt successfully
        self.assertEqual(result['success'], 3)
    
    def test_export_keys(self):
        """Test exporting successful keys to JSON"""
        # Add some successful keys
        self.recovery.successful_keys = {
            'key1': {
                'key': b'A' * 32,
                'iv': b'B' * 16,
                'algorithm': 'AES-CBC'
            }
        }
        
        # Export keys to file
        keys_file = os.path.join(self.temp_dir, "keys.json")
        self.recovery.export_keys(keys_file)
        
        # Check that file was created
        self.assertTrue(os.path.exists(keys_file))
        
        # Read and validate contents
        with open(keys_file, 'r') as f:
            keys_data = json.load(f)
        
        self.assertIn('key1', keys_data)
        self.assertEqual(keys_data['key1']['algorithm'], 'AES-CBC')
    
    def test_main_with_key_export(self):
        """Test the main function with key export"""
        # Create arguments for main
        test_args = [
            "--encrypted", self.encrypted_file,
            "--output", os.path.join(self.temp_dir, "output.docx"),
            "--export-keys", os.path.join(self.temp_dir, "exported_keys.json")
        ]
        
        # Mock sys.argv
        with patch('sys.argv', ['lockbit_optimized_recovery.py'] + test_args):
            # Run main function
            result = lockbit_optimized_recovery.main()
            
            # Should succeed
            self.assertEqual(result, 0)
            
            # Keys should be exported
            self.assertTrue(os.path.exists(os.path.join(self.temp_dir, "exported_keys.json")))
    
    def test_main_with_dir(self):
        """Test the main function with directory processing"""
        # Create a batch directory
        batch_dir = os.path.join(self.temp_dir, "main_batch")
        os.makedirs(batch_dir)
        
        # Create a test file
        test_file = os.path.join(batch_dir, "test.docx.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}")
        with open(test_file, 'wb') as f:
            f.write(b'\x00' * 32)
            f.write(b'\x01' * 1024)
        
        # Create arguments for main
        test_args = [
            "--dir", batch_dir
        ]
        
        # Mock sys.argv
        with patch('sys.argv', ['lockbit_optimized_recovery.py'] + test_args):
            # Run main function
            result = lockbit_optimized_recovery.main()
            
            # Should succeed
            self.assertEqual(result, 0)
            
            # Output file should exist
            self.assertTrue(os.path.exists(os.path.join(batch_dir, "test.docx")))


if __name__ == '__main__':
    unittest.main()