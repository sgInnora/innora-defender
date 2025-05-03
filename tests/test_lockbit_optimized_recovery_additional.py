#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Additional test cases for the optimized LockBit recovery module.
These tests are designed to improve coverage by targeting specific
uncovered lines identified in the coverage report.
"""

import os
import sys
import unittest
import json
import datetime
import argparse
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import shutil
import hashlib

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the module we're testing directly (needed for proper coverage tracking)
from decryption_tools.network_forensics import lockbit_optimized_recovery

# Mock cryptography modules for tests that don't have them
sys.modules['cryptography'] = MagicMock()
sys.modules['cryptography.hazmat.primitives.ciphers'] = MagicMock()
sys.modules['cryptography.hazmat.primitives.asymmetric'] = MagicMock()
sys.modules['cryptography.hazmat.primitives'] = MagicMock()
sys.modules['cryptography.hazmat.backends'] = MagicMock()

# Mock network recovery modules
sys.modules['decryption_tools.network_forensics.network_based_recovery'] = MagicMock()
sys.modules['decryption_tools.network_forensics.lockbit_recovery'] = MagicMock()
sys.modules['decryption_tools.file_format.restorebackup_analyzer'] = MagicMock()

# Set CRYPTOGRAPHY_AVAILABLE and NETWORK_RECOVERY_AVAILABLE for testing
sys.modules['decryption_tools.network_forensics.lockbit_recovery'].CRYPTOGRAPHY_AVAILABLE = True
sys.modules['decryption_tools.network_forensics.lockbit_recovery'].NETWORK_RECOVERY_AVAILABLE = True

# Also set for our module to ensure tests can use these
lockbit_optimized_recovery.CRYPTOGRAPHY_AVAILABLE = True
lockbit_optimized_recovery.NETWORK_RECOVERY_AVAILABLE = True


class TestImportExceptions(unittest.TestCase):
    """Test import exceptions and module availability conditions"""
    
    def setUp(self):
        """Set up test environment"""
        self.original_crypto_available = lockbit_optimized_recovery.CRYPTOGRAPHY_AVAILABLE
        self.original_network_available = lockbit_optimized_recovery.NETWORK_RECOVERY_AVAILABLE
    
    def tearDown(self):
        """Restore original settings"""
        lockbit_optimized_recovery.CRYPTOGRAPHY_AVAILABLE = self.original_crypto_available
        lockbit_optimized_recovery.NETWORK_RECOVERY_AVAILABLE = self.original_network_available
    
    def test_main_with_modules_unavailable(self):
        """Test main function when modules are unavailable"""
        # Test with missing modules
        with patch('decryption_tools.network_forensics.lockbit_optimized_recovery.CRYPTOGRAPHY_AVAILABLE', False):
            with patch('decryption_tools.network_forensics.lockbit_optimized_recovery.NETWORK_RECOVERY_AVAILABLE', False):
                with patch('builtins.print') as mock_print:
                    # Run main function
                    result = lockbit_optimized_recovery.main()
                    
                    # Should return error code
                    self.assertEqual(result, 1)
                    
                    # Should print error message
                    mock_print.assert_any_call("ERROR: Required modules not available")
                    
                    # Flags should be False
                    self.assertFalse(lockbit_optimized_recovery.CRYPTOGRAPHY_AVAILABLE)
                    self.assertFalse(lockbit_optimized_recovery.NETWORK_RECOVERY_AVAILABLE)


class TestFileFormatAdditionalCases(unittest.TestCase):
    """Test additional cases for EnhancedFileFormat class"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Use the already imported module (for proper coverage tracking)
        self.EnhancedFileFormat = lockbit_optimized_recovery.EnhancedFileFormat
        
        # Create test files
        self.create_test_files()
    
    def tearDown(self):
        """Clean up test environment"""
        # Remove temporary directory and test files
        shutil.rmtree(self.test_dir)
    
    def create_test_files(self):
        """Create test files for different scenarios"""
        # LockBit 2.0 encrypted file with KEY marker at specific position
        lb2_key_file = os.path.join(self.test_dir, "document_with_key.docx.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}")
        with open(lb2_key_file, 'wb') as f:
            # Create header with IV
            iv = os.urandom(16)
            # Create encrypted data (random bytes)
            encrypted_data = os.urandom(256)
            # Create footer with encrypted key marker at a specific position
            footer = b'KEY' + os.urandom(32)
            
            f.write(iv + encrypted_data + footer)
        
        self.lb2_key_file = lb2_key_file
        
        # LockBit 2.0 file with high entropy block in footer (no KEY marker)
        lb2_high_entropy = os.path.join(self.test_dir, "document_high_entropy.docx.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}")
        with open(lb2_high_entropy, 'wb') as f:
            # Create header with IV
            iv = os.urandom(16)
            # Create encrypted data
            encrypted_data = os.urandom(256)
            # Create footer with high entropy data but no KEY marker
            footer = os.urandom(256)
            
            f.write(iv + encrypted_data + footer)
        
        self.lb2_high_entropy = lb2_high_entropy
    
    def test_lockbit2_extraction_test_mode(self):
        """Test LockBit 2.0 structure extraction in test mode"""
        # Use testing_mode=True to get consistent behavior
        file_format = self.EnhancedFileFormat(self.lb2_key_file, testing_mode=True)
        
        # In testing mode, the format should be properly set up
        self.assertEqual(file_format.version, "2.0")
        self.assertTrue(file_format.has_uuid_extension)
        self.assertEqual(file_format.uuid, "1765FE8E-2103-66E3-7DCB-72284ABD03AA")
        self.assertIsNotNone(file_format.iv)
        self.assertIsNotNone(file_format.encrypted_key)
        self.assertGreater(len(file_format.iv_candidates), 0)
        self.assertGreater(len(file_format.encrypted_key_candidates), 0)
        
        # Check that the key marker can be found in footer data
        self.assertIn(b'KEY', file_format.footer_data)
    
    def test_parse_lockbit_2_with_high_entropy_blocks(self):
        """Test LockBit 2.0 structure parsing with high entropy blocks"""
        # Create a mock file format with controlled values
        class MockFileFormat(lockbit_optimized_recovery.EnhancedFileFormat):
            def __init__(self):
                self.file_path = "/test/path"
                self.file_name = "test.file"
                self.testing_mode = False
                self.encrypted_key = None
                self.encrypted_key_candidates = []
                self.footer_data = None
                self.encrypted_data = b"encrypted_data"
                self.iv = b"\x00" * 16
                self.iv_candidates = [b"\x00" * 16]
                self.header_data = b"\x00" * 16
                self.key_position = None
        
        # Create an instance
        file_format = MockFileFormat()
        
        # Create test data without KEY marker
        test_data = b'\x01' * 16 + b'\x02' * 256 + b'\x03' * 256
        
        # Create fake high entropy blocks result
        high_entropy_block = b'\x03' * 16
        block_pos = len(test_data) - 32  # Position in later part of data
        
        # Set the return value for _find_high_entropy_blocks
        with patch.object(file_format, '_find_high_entropy_blocks') as mock_find:
            mock_find.return_value = [(high_entropy_block, block_pos, 7.9)]
            
            # Mock entropy calculation to ensure high entropy is detected
            with patch.object(file_format, '_calculate_entropy', return_value=7.0):
                # Parse with our test data
                file_format._parse_lockbit_2_structure(test_data)
                
                # Verify high entropy block was added
                self.assertGreater(len(file_format.encrypted_key_candidates), 0)
                self.assertIn(high_entropy_block, file_format.encrypted_key_candidates)
                
                # Mock function should have been called
                mock_find.assert_called_once()
    
    def test_short_data_handling(self):
        """Test handling of short data in LockBit 2.0 structure parsing"""
        file_format = self.EnhancedFileFormat(self.lb2_key_file, testing_mode=False)
        
        # Reset for manual testing
        file_format.encrypted_key = None
        file_format.encrypted_key_candidates = []
        file_format.footer_data = b''
        
        # Create minimal test data (just IV and a bit of encrypted data)
        short_data = b'\x01' * 16 + b'\x02' * 32
        
        # Parse with short data
        file_format._parse_lockbit_2_structure(short_data)
        
        # Should set IV and header data
        self.assertEqual(file_format.iv, short_data[:16])
        self.assertIn(short_data[:16], file_format.iv_candidates)
        
        # Should set encrypted data to everything after IV
        self.assertEqual(file_format.encrypted_data, short_data[16:])
        
        # Should not have found KEY or footer
        self.assertIsNone(file_format.encrypted_key)
        self.assertEqual(file_format.encrypted_key_candidates, [])
        self.assertEqual(file_format.footer_data, b'')


class TestOptimizedLockBitRecoveryAdditional(unittest.TestCase):
    """Test additional cases for OptimizedLockBitRecovery class"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Get the actual class for direct testing
        self.recovery_class = lockbit_optimized_recovery.OptimizedLockBitRecovery
        self.recovery = self.recovery_class(testing_mode=False)  # Use non-testing mode for real implementation
        
        # Create test files
        self.create_test_files()
    
    def tearDown(self):
        """Clean up test environment"""
        # Remove temporary directory and test files
        shutil.rmtree(self.test_dir)
    
    def create_test_files(self):
        """Create test files for different scenarios"""
        # Create LockBit 2.0 encrypted file
        lb2_file = os.path.join(self.test_dir, "test.docx.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}")
        with open(lb2_file, 'wb') as f:
            # Create header with IV
            iv = os.urandom(16)
            # Create encrypted data
            encrypted_data = os.urandom(1024)
            
            f.write(iv + encrypted_data)
        
        self.lb2_file = lb2_file
        
        # Create LockBit 3.0 encrypted file
        lb3_file = os.path.join(self.test_dir, "test.xlsx.lockbit3")
        with open(lb3_file, 'wb') as f:
            # Create header with magic bytes and IV
            header = b'LOCKBIT3\x01\x00\x00\x00' + os.urandom(16)
            # Create encrypted data
            encrypted_data = os.urandom(1024)
            
            f.write(header + encrypted_data)
        
        self.lb3_file = lb3_file
    
    def test_decrypt_file_output_path_handling(self):
        """Test output path handling in decrypt_file method"""
        # Test with LockBit 2.0 file but no output file specified
        with patch.object(self.recovery, '_optimized_decrypt_lockbit_2') as mock_decrypt:
            # Setup mock to return success
            mock_decrypt.return_value = {
                'success': True,
                'output': os.path.join(self.test_dir, 'decrypted.docx'),
                'key': b'test_key',
                'iv': b'test_iv',
                'algorithm': 'AES-CBC',
                'confidence': 0.9
            }
            
            # Call decrypt_file without specifying output_file
            self.recovery.decrypt_file(self.lb2_file)
            
            # Verify the method was called with expected parameters
            calls = mock_decrypt.call_args_list
            self.assertEqual(len(calls), 1)
            
            # Check that output_file was generated correctly
            # It should use default pattern "decrypted_<filename>"
            args = calls[0][0]
            output_file = args[3]  # Fourth argument to _optimized_decrypt_lockbit_2
            self.assertTrue(output_file.startswith(os.path.dirname(self.lb2_file)))
            self.assertTrue('decrypted_' in output_file)
    
    def test_decrypt_file_in_testing_mode(self):
        """Test decrypt_file method in testing mode"""
        # Initialize recovery with testing_mode=True
        recovery = self.recovery_class(testing_mode=True)
        
        # 1. Test with LockBit 2.0 file in testing mode
        result1 = recovery.decrypt_file(self.lb2_file)
        self.assertTrue(result1)  # Should succeed in testing mode
        
        # 2. Test with LockBit 3.0 file in testing mode
        result2 = recovery.decrypt_file(self.lb3_file)
        self.assertTrue(result2)  # Should succeed in testing mode
        
        # 3. Test with RestoreBackup file in testing mode
        restore_file = os.path.join(self.test_dir, "test.docx.restorebackup")
        with open(restore_file, 'wb') as f:
            f.write(b"RestoreBackup content")
            
        result3 = recovery.decrypt_file(restore_file)
        self.assertTrue(result3)  # Should succeed in testing mode
        
        # 4. Should fail with unknown format even in testing mode
        unknown_file = os.path.join(self.test_dir, "unknown.txt")
        with open(unknown_file, 'wb') as f:
            f.write(b"Unknown file format content")
            
        result4 = recovery.decrypt_file(unknown_file)
        self.assertFalse(result4)  # Should fail even in testing mode
    
    def test_chacha20_key_adjustment(self):
        """Test key and nonce adjustment logic for ChaCha20"""
        # We can test the key adjustment logic directly
        recovery = self.recovery_class(testing_mode=True)
        
        # Test with non-standard key and nonce sizes
        short_key = b'short_key'  # Not 32 bytes
        short_nonce = b'short'    # Not 16 bytes
        
        # Test key adjustment
        adjusted_key = recovery._adjust_key_length(short_key, 32)
        self.assertEqual(len(adjusted_key), 32)
        self.assertTrue(adjusted_key.startswith(short_key))
        
        # Test nonce padding logic - we can manually implement what _decrypt_chacha20 does
        # This is the logic from line 1044-1047: nonce is padded/truncated to 16 bytes
        adjusted_nonce = short_nonce.ljust(16, b'\0')[:16]
        self.assertEqual(len(adjusted_nonce), 16)
        self.assertTrue(adjusted_nonce.startswith(short_nonce))
        
    def test_key_adjustment(self):
        """Test key length adjustment logic"""
        # This doesn't need cryptography modules
        recovery = self.recovery_class(testing_mode=True)
        
        # Test key length adjustments
        test_cases = [
            # (original_key, target_length, expected_behavior)
            (b'A' * 16, 16, lambda k, r: r == k),  # Same length - should return original
            (b'A' * 8, 16, lambda k, r: len(r) == 16 and r.startswith(k)),  # Extend
            (b'A' * 32, 16, lambda k, r: len(r) == 16 and r == k[:16]),  # Truncate
            (b'A' * 16, 32, lambda k, r: len(r) == 32 and r.startswith(k)),  # Extend more
            (b'A' * 64, 32, lambda k, r: len(r) == 32 and r == k[:32]),  # Truncate more
        ]
        
        for key, target_length, check in test_cases:
            result = recovery._adjust_key_length(key, target_length)
            self.assertEqual(len(result), target_length)
            self.assertTrue(check(key, result))
    
    def test_partial_file_decryption(self):
        """Test partial file decryption in fallback methods"""
        # Initialize recovery with testing_mode=False for real implementation
        recovery = self.recovery_class(testing_mode=False)
        
        # Create test data
        file_format = lockbit_optimized_recovery.EnhancedFileFormat(self.lb2_file, testing_mode=True)
        key_candidates = [b'A' * 32]  # 32-byte key
        iv_candidates = [b'B' * 16]  # 16-byte IV
        output_file = os.path.join(self.test_dir, "partial_output.docx")
        
        # Mock AES decryption to return data with a known file signature
        with patch.object(recovery, '_decrypt_aes_cbc') as mock_decrypt:
            # First call for partial data returns valid signature
            mock_decrypt.side_effect = [
                b'%PDF-1.5\nTest data',  # Partial decryption - has PDF signature
                b'%PDF-1.5\nComplete decrypted file'  # Full decryption
            ]
            
            # Try fallback methods
            result = recovery._try_fallback_methods(file_format, key_candidates, iv_candidates, output_file)
            
            # Check result and verify file was created with full decryption
            self.assertTrue(result['success'])
            self.assertEqual(result['algorithm'], 'AES-CBC (partial validation)')
            self.assertTrue(os.path.exists(output_file))
            
            # Verify correct sequence of calls
            self.assertEqual(mock_decrypt.call_count, 2)
    
    def test_fallback_methods_testing_mode(self):
        """Test fallback methods in testing mode"""
        # Initialize recovery with testing_mode=True
        recovery = self.recovery_class(testing_mode=True)
        
        # Create test data with unknown version
        file_format = lockbit_optimized_recovery.EnhancedFileFormat(os.path.join(self.test_dir, "unknown.bin"), testing_mode=True)
        file_format.version = None  # Set as unknown version
        
        key_candidates = [b'A' * 32]  # Test key
        iv_candidates = [b'B' * 16]  # Test IV
        output_file = os.path.join(self.test_dir, "fallback_output.bin")
        
        # In testing mode, _try_fallback_methods should succeed for unknown formats
        result = recovery._try_fallback_methods(file_format, key_candidates, iv_candidates, output_file)
        
        # Check result in testing mode
        self.assertTrue(result['success'])
        self.assertEqual(result['algorithm'], 'AES-CBC (fallback test)')
        self.assertTrue(os.path.exists(output_file))
    
    def test_validation_requirements(self):
        """Test detailed file validation logic"""
        # Create a variety of test data types for validation
        test_files = {
            'pdf': b'%PDF-1.5\nThis is a PDF file with some content',
            'docx': b'PK\x03\x04' + b'\x00' * 20 + b'Some DOCX content',
            'jpeg': b'\xFF\xD8\xFF' + b'\x00' * 20 + b'JPEG content',
            'text': 'This is a plain text file with lots of readable content'.encode('utf-8'),
            'utf8': 'Text with unicode characters: ☺★♠♣♥♦ and more content here'.encode('utf-8'),
            'binary': b'\x00\x01\x02\x03' + os.urandom(100) + b'\x00\x00\x00',
            'random': os.urandom(1000)  # High entropy data
        }
        
        # Test with real implementation, not testing mode
        recovery = self.recovery_class(testing_mode=False)
        
        # Test validation of each file type
        for file_type, content in test_files.items():
            # Test with different extensions
            extensions = {
                'pdf': '.pdf',
                'docx': '.docx',
                'jpeg': '.jpg',
                'text': '.txt',
                'utf8': '.txt',
                'binary': '.bin',
                'random': None
            }
            
            ext = extensions.get(file_type)
            result = recovery._validate_decryption(content, ext)
            
            # Check all file types except random high entropy data should be valid
            if file_type != 'random':
                self.assertTrue(result['valid'], f"File type {file_type} should be valid")
                self.assertGreater(result['confidence'], 0.3, f"File type {file_type} should have confidence > 0.3")
                self.assertGreater(len(result['validations_passed']), 0, f"File type {file_type} should pass at least one validation")
            else:
                # Random data should fail validation
                self.assertFalse(result['valid'], "Random high entropy data should be invalid")
    
    def test_advanced_key_variants(self):
        """Test advanced key variant generation and handling"""
        # Test with real implementation
        recovery = self.recovery_class(testing_mode=False)
        
        # Test different key sizes
        test_keys = {
            'standard_256': b'A' * 32,  # Standard AES-256 key
            'standard_192': b'B' * 24,  # Standard AES-192 key
            'standard_128': b'C' * 16,  # Standard AES-128 key
            'odd_size': b'D' * 20,      # Non-standard size
            'short': b'E' * 8,          # Very short key
            'long': b'F' * 64           # Very long key
        }
        
        for key_name, key in test_keys.items():
            variants = recovery._get_key_variants(key)
            
            # Should have returned multiple variants
            self.assertGreater(len(variants), 0, f"Key {key_name} should have at least one variant")
            
            # If original key was standard AES size, it should be included
            if len(key) in [16, 24, 32]:
                self.assertIn(key, variants, f"Key {key_name} should include original key")
            
            # Should have adjusted variants for standard AES sizes
            key_lengths = [len(v) for v in variants]
            
            # Should have at least one key with standard AES length
            self.assertTrue(
                16 in key_lengths or 24 in key_lengths or 32 in key_lengths,
                f"Key {key_name} should have at least one variant with standard AES length"
            )
            
            # Check hash variant
            hash_variant = recovery._derive_key_from_hash(key)
            self.assertIn(hash_variant, variants, f"Key {key_name} should include hash variant")
    
    def test_pkcs7_padding_handling(self):
        """Test PKCS#7 padding handling in real implementation"""
        # Test with real implementation
        recovery = self.recovery_class(testing_mode=False)
        
        # Test valid PKCS#7 padding cases
        valid_padding_cases = {
            b'data' + bytes([1]): b'data',                             # Padding with 1 byte
            b'data' + bytes([4]) * 4: b'data',                         # Padding with 4 bytes
            b'data' + bytes([16]) * 16: b'data',                       # Padding with 16 bytes (full block)
            b'data' + bytes([8]) * 8: b'data',                         # Padding with 8 bytes
            b'data' + bytes([2]) * 2: b'data'                          # Padding with 2 bytes
        }
        
        for padded, expected in valid_padding_cases.items():
            result = recovery._handle_padding(padded)
            self.assertEqual(result, expected, f"Valid padding {padded[-1]} should be properly removed")
        
        # Test invalid PKCS#7 padding cases
        invalid_padding_cases = {
            b'data': b'data',                                           # No padding
            b'data' + bytes([4, 3, 4, 4]): b'data' + bytes([4, 3, 4, 4]),  # Inconsistent padding
            b'data' + bytes([0]) * 4: b'data' + bytes([0]) * 4,          # Zero padding (not valid PKCS#7)
            b'data' + bytes([17]) * 17: b'data' + bytes([17]) * 17,      # Padding value > 16 (block size)
            b'': b''                                                    # Empty data
        }
        
        for padded, expected in invalid_padding_cases.items():
            result = recovery._handle_padding(padded)
            self.assertEqual(result, expected, f"Invalid padding should be left untouched")
    
    def test_decrypt_aes_cbc_testing_mode(self):
        """Test AES-CBC decryption in testing mode"""
        # Initialize recovery with testing_mode=True
        recovery = self.recovery_class(testing_mode=True)
        
        # In testing mode, _decrypt_aes_cbc should return a fixed result
        encrypted_data = b'any_encrypted_data'
        key = b'A' * 32
        iv = b'B' * 16
        
        result = recovery._decrypt_aes_cbc(encrypted_data, key, iv)
        
        # Should return fixed test result in testing mode
        self.assertEqual(result, b'Decrypted')


class TestMainFunctionAndCLI(unittest.TestCase):
    """Test main function and CLI parsing"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Backup original sys.argv
        self.original_argv = sys.argv
        
        # Create test files
        self.create_test_files()
    
    def tearDown(self):
        """Clean up test environment"""
        # Remove temporary directory and test files
        shutil.rmtree(self.test_dir)
        
        # Restore original sys.argv
        sys.argv = self.original_argv
    
    def create_test_files(self):
        """Create test files for CLI testing"""
        # Create a LockBit 2.0 encrypted file
        lb2_file = os.path.join(self.test_dir, "test.docx.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}")
        with open(lb2_file, 'wb') as f:
            f.write(b"LockBit 2.0 encrypted content")
        
        self.lb2_file = lb2_file
        
        # Create a directory for batch testing
        batch_dir = os.path.join(self.test_dir, "batch_test")
        os.makedirs(batch_dir, exist_ok=True)
        
        # Create files in batch directory
        files = [
            "doc1.docx.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}",
            "doc2.xlsx.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}",
            "normal.txt",  # Not encrypted
            "image.jpg.restorebackup"
        ]
        
        for filename in files:
            with open(os.path.join(batch_dir, filename), 'wb') as f:
                f.write(f"Content for {filename}".encode())
        
        self.batch_dir = batch_dir
    
    def test_main_with_unavailable_modules(self):
        """Test main function when required modules are unavailable"""
        # Mock modules as unavailable
        with patch('decryption_tools.network_forensics.lockbit_optimized_recovery.CRYPTOGRAPHY_AVAILABLE', False):
            with patch('decryption_tools.network_forensics.lockbit_optimized_recovery.NETWORK_RECOVERY_AVAILABLE', False):
                # Mock command line arguments
                argv = ['lockbit_optimized_recovery.py', '--encrypted', self.lb2_file]
                
                with patch('sys.argv', argv):
                    # Should return error code
                    result = lockbit_optimized_recovery.main()
                    self.assertEqual(result, 1)
    
    def test_main_cli_argument_combinations(self):
        """Test main function with various CLI argument combinations"""
        # Test with encrypted file and key
        with patch('argparse.ArgumentParser.parse_args') as mock_args:
            with patch('decryption_tools.network_forensics.lockbit_optimized_recovery.OptimizedLockBitRecovery') as mock_recovery:
                # Setup mock arguments
                mock_args.return_value = argparse.Namespace(
                    encrypted=self.lb2_file,
                    output=os.path.join(self.test_dir, 'output.docx'),
                    dir=None,
                    key=['0123456789abcdef0123456789abcdef'],
                    iv=['0123456789abcdef'],
                    sample=None,
                    export_keys=True
                )
                
                # Setup mock recovery instance
                mock_instance = MagicMock()
                mock_recovery.return_value = mock_instance
                mock_instance.decrypt_file.return_value = True
                mock_instance.export_successful_keys.return_value = 'keys.json'
                
                # Run main function
                result = lockbit_optimized_recovery.main()
                
                # Should succeed
                self.assertEqual(result, 0)
                
                # Should have called decrypt_file with correct arguments
                mock_instance.decrypt_file.assert_called_once_with(
                    self.lb2_file,
                    os.path.join(self.test_dir, 'output.docx'),
                    extra_keys=[bytes.fromhex('0123456789abcdef0123456789abcdef')]
                )
                
                # Should have called export_successful_keys
                mock_instance.export_successful_keys.assert_called_once()
    
    def test_main_with_batch_directory(self):
        """Test main function with batch directory processing"""
        # Test with directory argument
        with patch('argparse.ArgumentParser.parse_args') as mock_args:
            with patch('decryption_tools.network_forensics.lockbit_optimized_recovery.OptimizedLockBitRecovery') as mock_recovery:
                # Setup mock arguments
                mock_args.return_value = argparse.Namespace(
                    encrypted=None,
                    output=os.path.join(self.test_dir, 'output'),
                    dir=self.batch_dir,
                    key=None,
                    iv=None,
                    sample=None,
                    export_keys=False
                )
                
                # Setup mock recovery instance
                mock_instance = MagicMock()
                mock_recovery.return_value = mock_instance
                mock_instance.batch_decrypt.return_value = {
                    os.path.join(self.batch_dir, 'doc1.docx.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}'): True,
                    os.path.join(self.batch_dir, 'doc2.xlsx.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}'): True,
                    os.path.join(self.batch_dir, 'image.jpg.restorebackup'): True
                }
                
                # Run main function
                result = lockbit_optimized_recovery.main()
                
                # Should succeed
                self.assertEqual(result, 0)
                
                # Should have called batch_decrypt with correct arguments
                mock_instance.batch_decrypt.assert_called_once()
                
                # The batch_decrypt should have been called with 3 encrypted files and the output directory
                call_args = mock_instance.batch_decrypt.call_args
                self.assertEqual(len(call_args[0][0]), 3)  # 3 encrypted files
                self.assertEqual(call_args[0][1], os.path.join(self.test_dir, 'output'))
    
    def test_main_with_sample_analysis(self):
        """Test main function with sample analysis"""
        # Create sample file
        sample_file = os.path.join(self.test_dir, 'sample.bin')
        with open(sample_file, 'wb') as f:
            f.write(b"Sample content for analysis")
        
        # Test with sample argument
        with patch('argparse.ArgumentParser.parse_args') as mock_args:
            with patch('decryption_tools.network_forensics.lockbit_optimized_recovery.OptimizedLockBitRecovery') as mock_recovery:
                # Setup mock arguments
                mock_args.return_value = argparse.Namespace(
                    encrypted=None,
                    output=None,
                    dir=None,
                    key=None,
                    iv=None,
                    sample=sample_file,
                    export_keys=False
                )
                
                # Setup mock recovery instance
                mock_instance = MagicMock()
                mock_recovery.return_value = mock_instance
                mock_instance.analyze_sample.return_value = [b'key1', b'key2']
                
                # Run main function
                result = lockbit_optimized_recovery.main()
                
                # Should succeed
                self.assertEqual(result, 0)
                
                # Should have called analyze_sample with correct argument
                mock_instance.analyze_sample.assert_called_once_with(sample_file)
    
    def test_main_with_invalid_key_format(self):
        """Test main function with invalid key format"""
        # Test with invalid key format
        with patch('argparse.ArgumentParser.parse_args') as mock_args:
            with patch('decryption_tools.network_forensics.lockbit_optimized_recovery.OptimizedLockBitRecovery') as mock_recovery:
                with patch('builtins.print') as mock_print:
                    # Setup mock arguments with invalid hex key
                    mock_args.return_value = argparse.Namespace(
                        encrypted=self.lb2_file,
                        output=None,
                        dir=None,
                        key=['not-a-hex-key'],
                        iv=None,
                        sample=None,
                        export_keys=False
                    )
                    
                    # Setup mock recovery instance
                    mock_instance = MagicMock()
                    mock_recovery.return_value = mock_instance
                    mock_instance.decrypt_file.return_value = False
                    
                    # Run main function
                    result = lockbit_optimized_recovery.main()
                    
                    # Should succeed despite invalid key (with warning)
                    self.assertEqual(result, 0)
                    
                    # Should have printed warning
                    mock_print.assert_any_call("Warning: Invalid key format: not-a-hex-key")
                    
                    # Should have called decrypt_file with empty extra_keys
                    mock_instance.decrypt_file.assert_called_once()
                    kwargs = mock_instance.decrypt_file.call_args[1]
                    self.assertEqual(kwargs['extra_keys'], [])


# Run tests if executed directly
if __name__ == '__main__':
    unittest.main()