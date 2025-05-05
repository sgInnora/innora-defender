#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Additional tests to improve coverage for batch_decrypt.py
Target: 95% coverage
"""

import os
import sys
import time
import unittest
import tempfile
from unittest.mock import patch, MagicMock

# Add project root to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the module to test
import batch_decrypt


class TestUpdateProgressCoverage(unittest.TestCase):
    """Test cases specifically designed to improve coverage for update_progress"""
    
    def test_update_progress_with_eta_and_throughput(self):
        """Test update_progress with ETA calculation and throughput information"""
        # Create a test stats dictionary with start_time and throughput
        stats = {
            "total_files": 100,
            "completed_files": 25,
            "successful_files": 20,
            "failed_files": 5,
            "current_progress": 0.25,
            "start_time": time.time() - 60,  # Started 60 seconds ago
            "throughput_bps": 1024 * 1024 * 5  # 5 MB/s
        }
        
        # Patch sys.stdout to capture the output
        with patch('sys.stdout') as mock_stdout:
            # Call update_progress
            batch_decrypt.update_progress(stats)
            
            # Verify write was called
            mock_stdout.write.assert_called_once()
            
            # Get the progress text
            progress_text = mock_stdout.write.call_args[0][0]
            
            # Verify ETA and throughput information is included
            self.assertIn("ETA:", progress_text)
            self.assertIn("MB/s", progress_text)
    
    def test_update_progress_with_different_eta_formats(self):
        """Test update_progress with different ETA time formats"""
        # Test seconds format (under 60 seconds)
        stats_seconds = {
            "total_files": 100,
            "completed_files": 25,
            "successful_files": 20,
            "failed_files": 5,
            "current_progress": 0.25,
            "start_time": time.time() - 10,  # Started 10 seconds ago, with 30 seconds remaining
            "throughput_bps": 1024 * 1024
        }
        
        with patch('sys.stdout') as mock_stdout:
            batch_decrypt.update_progress(stats_seconds)
            progress_text = mock_stdout.write.call_args[0][0]
            self.assertIn("s", progress_text)  # Should show seconds format
        
        # Test minutes format (between 60 and 3600 seconds)
        stats_minutes = {
            "total_files": 1000,
            "completed_files": 100,
            "successful_files": 90,
            "failed_files": 10,
            "current_progress": 0.1,
            "start_time": time.time() - 360,  # Started 6 minutes ago, with ~54 minutes remaining
            "throughput_bps": 1024 * 1024
        }
        
        with patch('sys.stdout') as mock_stdout:
            batch_decrypt.update_progress(stats_minutes)
            progress_text = mock_stdout.write.call_args[0][0]
            self.assertIn("m", progress_text)  # Should show minutes format
        
        # Test hours format (over 3600 seconds)
        stats_hours = {
            "total_files": 10000,
            "completed_files": 1000,
            "successful_files": 900,
            "failed_files": 100,
            "current_progress": 0.1,
            "start_time": time.time() - 3600,  # Started 1 hour ago, with ~9 hours remaining
            "throughput_bps": 1024 * 1024
        }
        
        with patch('sys.stdout') as mock_stdout:
            batch_decrypt.update_progress(stats_hours)
            progress_text = mock_stdout.write.call_args[0][0]
            self.assertIn("h", progress_text)  # Should show hours format


class TestPrintSummaryCoverage(unittest.TestCase):
    """Test cases specifically designed to improve coverage for print_summary"""
    
    def test_print_summary_with_duration_formats(self):
        """Test print_summary with different duration formats"""
        # Test seconds format
        summary_seconds = {
            "files": {
                "total": 10,
                "successful": 9,
                "failed": 1,
            },
            "timing": {
                "duration": 45.5,  # Less than 60 seconds
                "avg_file_time": 4.55,
                "start_time": time.time() - 45.5,
                "end_time": time.time()
            },
            "performance": {
                "total_bytes_processed": 1024 * 1024 * 10,
                "avg_throughput_bps": 1024 * 1024 * 2
            }
        }
        
        with patch('builtins.print') as mock_print:
            batch_decrypt.print_summary(summary_seconds)
            
            # Check if seconds format was used
            printed_lines = [call_args[0][0] for call_args in mock_print.call_args_list if call_args[0]]
            duration_line = next((line for line in printed_lines if "Total duration:" in line), None)
            self.assertIsNotNone(duration_line)
            self.assertIn("seconds", duration_line)
            self.assertNotIn("m", duration_line)
            self.assertNotIn("h", duration_line)
        
        # Test minutes format
        summary_minutes = {
            "files": {
                "total": 100,
                "successful": 90,
                "failed": 10,
            },
            "timing": {
                "duration": 185.3,  # 3 minutes and 5.3 seconds
                "avg_file_time": 1.85,
                "start_time": time.time() - 185.3,
                "end_time": time.time()
            },
            "performance": {
                "total_bytes_processed": 1024 * 1024 * 100,
                "avg_throughput_bps": 1024 * 1024 * 2
            }
        }
        
        with patch('builtins.print') as mock_print:
            batch_decrypt.print_summary(summary_minutes)
            
            # Check if minutes format was used
            printed_lines = [call_args[0][0] for call_args in mock_print.call_args_list if call_args[0]]
            duration_line = next((line for line in printed_lines if "Total duration:" in line), None)
            self.assertIsNotNone(duration_line)
            self.assertIn("m", duration_line)
            self.assertNotIn("h", duration_line)
        
        # Test hours format
        summary_hours = {
            "files": {
                "total": 1000,
                "successful": 900,
                "failed": 100,
            },
            "timing": {
                "duration": 3723.5,  # 1 hour, 2 minutes, 3.5 seconds
                "avg_file_time": 3.72,
                "start_time": time.time() - 3723.5,
                "end_time": time.time()
            },
            "performance": {
                "total_bytes_processed": 1024 * 1024 * 1000,
                "avg_throughput_bps": 1024 * 1024 * 2
            }
        }
        
        with patch('builtins.print') as mock_print:
            batch_decrypt.print_summary(summary_hours)
            
            # Check if hours format was used
            printed_lines = [call_args[0][0] for call_args in mock_print.call_args_list if call_args[0]]
            duration_line = next((line for line in printed_lines if "Total duration:" in line), None)
            self.assertIsNotNone(duration_line)
            self.assertIn("h", duration_line)
    
    def test_print_summary_with_warnings(self):
        """Test print_summary with warnings section"""
        # Create a summary with warnings
        summary_with_warnings = {
            "files": {
                "total": 10,
                "successful": 9,
                "failed": 1,
                "partial_success": 0
            },
            "timing": {
                "duration": 5.0,
                "avg_file_time": 0.5
            },
            "performance": {
                "total_bytes_processed": 1024 * 1024 * 10,
                "avg_throughput_bps": 1024 * 1024 * 2
            },
            "warnings": {
                "total_warnings": 2,
                "summary": {
                    "Possible format inconsistency": {
                        "count": 1
                    },
                    "Unknown file encoding": {
                        "count": 1
                    }
                }
            }
        }
        
        with patch('builtins.print') as mock_print:
            batch_decrypt.print_summary(summary_with_warnings)
            
            # Check if warnings section was printed
            printed_lines = [call_args[0][0] for call_args in mock_print.call_args_list if call_args[0]]
            self.assertTrue(any("WARNINGS:" in line for line in printed_lines))
            self.assertTrue(any("Possible format inconsistency" in line for line in printed_lines))
            self.assertTrue(any("Unknown file encoding" in line for line in printed_lines))
    
    def test_print_summary_with_recommended_params(self):
        """Test print_summary with recommendations section"""
        # Create a summary with recommendations
        summary_with_recommendations = {
            "files": {
                "total": 10,
                "successful": 9,
                "failed": 1,
                "partial_success": 0
            },
            "timing": {
                "duration": 5.0,
                "avg_file_time": 0.5
            },
            "performance": {
                "total_bytes_processed": 1024 * 1024 * 10,
                "avg_throughput_bps": 1024 * 1024 * 2
            },
            "error_insights": {
                "recommendations": [
                    "Try using AES-CBC algorithm with 256-bit key",
                    "Check file permissions for failed files",
                    "If issues persist, try --header-size=16"
                ]
            }
        }
        
        with patch('builtins.print') as mock_print:
            batch_decrypt.print_summary(summary_with_recommendations)
            
            # Check if recommendations section was printed
            printed_lines = [call_args[0][0] for call_args in mock_print.call_args_list if call_args[0]]
            self.assertTrue(any("RECOMMENDATIONS:" in line for line in printed_lines))
            self.assertTrue(any("Try using AES-CBC" in line for line in printed_lines))
            self.assertTrue(any("Check file permissions" in line for line in printed_lines))
            self.assertTrue(any("If issues persist" in line for line in printed_lines))


class TestDetectTerminalColorSupport(unittest.TestCase):
    """Test cases for detect_terminal_color_support function"""
    
    def test_detect_terminal_color_support_unix(self):
        """Test terminal color detection on Unix systems"""
        # We're already on a Unix-like system (macOS), so let's test the Unix path directly
        with patch('sys.platform', 'darwin'):
            result = batch_decrypt.detect_terminal_color_support()
            self.assertTrue(result)  # Unix systems should typically return True
    
    def test_detect_terminal_color_support_windows(self):
        """Test terminal color detection on Windows systems"""
        # Patch sys.platform to simulate Windows
        with patch('sys.platform', 'win32'):
            # Test with no environment variables set
            with patch.dict('os.environ', {}, clear=True):
                result = batch_decrypt.detect_terminal_color_support()
                self.assertFalse(result)  # Should return False without any env vars
            
            # Test with TERM=xterm
            with patch.dict('os.environ', {'TERM': 'xterm'}):
                result = batch_decrypt.detect_terminal_color_support()
                self.assertTrue(result)  # Should return True with TERM=xterm
            
            # Test with WT_SESSION set (Windows Terminal)
            with patch.dict('os.environ', {'WT_SESSION': '1'}):
                result = batch_decrypt.detect_terminal_color_support()
                self.assertTrue(result)  # Should return True with WT_SESSION
            
            # Test with ANSICON set
            with patch.dict('os.environ', {'ANSICON': '1'}):
                result = batch_decrypt.detect_terminal_color_support()
                self.assertTrue(result)  # Should return True with ANSICON


if __name__ == "__main__":
    unittest.main()