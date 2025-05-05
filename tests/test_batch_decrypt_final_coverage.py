#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Final coverage tests for batch_decrypt.py
Target: 95% coverage
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add project root to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the module to test
import batch_decrypt


class TestPrintSummaryFinalCoverage(unittest.TestCase):
    """Test cases to cover remaining code paths in print_summary"""
    
    def test_print_summary_remaining_branches(self):
        """Test the remaining branches in print_summary"""
        # Test with large GB file size
        summary_large_data = {
            "files": {
                "total": 10,
                "successful": 9,
                "failed": 1
            },
            "timing": {
                "duration": 120.0,
                "avg_file_time": 12.0
            },
            "performance": {
                "total_bytes_processed": 1024 * 1024 * 1024 * 5,  # 5 GB
                "avg_throughput_bps": 1024 * 1024 * 10
            }
        }
        
        with patch('builtins.print') as mock_print:
            batch_decrypt.print_summary(summary_large_data)
            
            # Check if GB was used for data size
            printed_lines = [call_args[0][0] for call_args in mock_print.call_args_list if call_args[0]]
            size_line = next((line for line in printed_lines if "Data processed:" in line), None)
            self.assertIsNotNone(size_line)
            self.assertIn("GB", size_line)
    
    def test_print_summary_with_single_file(self):
        """Test print_summary with single file (total_files=1)"""
        summary_single_file = {
            "files": {
                "total": 1,
                "successful": 1,
                "failed": 0
            },
            "timing": {
                "duration": 5.0,
                "avg_file_time": 5.0
            },
            "performance": {
                "total_bytes_processed": 1024 * 1024 * 10,
                "avg_throughput_bps": 1024 * 1024 * 2,
                "max_throughput_bps": 1024 * 1024 * 2,
                "min_throughput_bps": 1024 * 1024 * 2
            }
        }
        
        with patch('builtins.print') as mock_print:
            batch_decrypt.print_summary(summary_single_file)
            
            # Check that max/min throughput wasn't shown
            printed_lines = [call_args[0][0] for call_args in mock_print.call_args_list if call_args[0]]
            self.assertTrue(any("Avg. throughput:" in line for line in printed_lines))
            self.assertFalse(any("Max throughput:" in line for line in printed_lines))
            self.assertFalse(any("Min throughput:" in line for line in printed_lines))
    
    def test_print_summary_with_timing_details(self):
        """Test print_summary function with different timing formats and error categories"""
        # Create a summary with all error severities and timing details
        comprehensive_summary = {
            "files": {
                "total": 100,
                "successful": 80,
                "failed": 15,
                "partial_success": 5
            },
            "timing": {
                "duration": 3725.5,  # 1h, 2m, 5.5s
                "avg_file_time": 37.3,
                "start_time": 1714992000,  # May 6, 2025 at 00:00:00 GMT
                "end_time": 1714995725    # May 6, 2025 at 01:02:05 GMT
            },
            "performance": {
                "total_bytes_processed": 1024 * 1024 * 500,
                "avg_throughput_bps": 1024 * 1024 * 2,
                "max_throughput_bps": 1024 * 1024 * 5,
                "min_throughput_bps": 1024 * 1024 * 1
            },
            "concurrency": {
                "max_concurrent_threads": 8
            },
            "errors": {
                "total_errors": 15,
                "summary": {
                    "Critical system failure": {
                        "severity": "critical",
                        "count": 1
                    },
                    "File access denied": {
                        "severity": "high",
                        "count": 4
                    },
                    "Unexpected file format": {
                        "severity": "medium",
                        "count": 5
                    },
                    "Minor processing issue": {
                        "severity": "low",
                        "count": 5
                    }
                }
            },
            "warnings": {
                "total_warnings": 10,
                "summary": {
                    "Performance might be degraded": {
                        "count": 5
                    },
                    "File might contain mixed encodings": {
                        "count": 5
                    }
                }
            },
            "error_insights": {
                "recommendations": [
                    "Try using a different algorithm for encrypted files",
                    "Ensure all input files have appropriate permissions"
                ]
            }
        }
        
        with patch('builtins.print') as mock_print:
            batch_decrypt.print_summary(comprehensive_summary)
            
            # Check all sections are printed
            printed_lines = [call_args[0][0] for call_args in mock_print.call_args_list if call_args[0]]
            
            # Verify timing format
            duration_line = next((line for line in printed_lines if "Total duration:" in line), None)
            self.assertIsNotNone(duration_line)
            self.assertIn("1h 2m", duration_line)
            
            # Verify all error severities are printed
            self.assertTrue(any("[CRITICAL]" in line for line in printed_lines))
            self.assertTrue(any("[HIGH]" in line for line in printed_lines))
            self.assertTrue(any("[MEDIUM]" in line for line in printed_lines))
            self.assertTrue(any("[LOW]" in line for line in printed_lines))


class TestUpdateProgressFinalCoverage(unittest.TestCase):
    """Final test cases for update_progress"""
    
    def test_update_progress_adjustment_logic(self):
        """Test the adjustment logic in update_progress"""
        # This specifically tests the block adjustment logic
        stats = {
            "total_files": 100,
            "completed_files": 10,
            "successful_files": 5,  # 50% success rate
            "failed_files": 5,      # 50% failure rate
            "current_progress": 0.1,
            "start_time": 1714992000,  # Fixed time for consistent testing
            "throughput_bps": 1024 * 1024  # 1 MB/s
        }
        
        with patch('sys.stdout') as mock_stdout:
            # First call with stats that should trigger adjustment logic
            batch_decrypt.update_progress(stats)
            
            # Verify write was called
            mock_stdout.write.assert_called_once()
            
            # Get the progress text to make sure both colors are present
            progress_text = mock_stdout.write.call_args[0][0]
            self.assertIn('\033[92m', progress_text)  # Success color
            self.assertIn('\033[91m', progress_text)  # Error color
            
        # Now test the edge case with very few completed files
        edge_stats = {
            "total_files": 1000,
            "completed_files": 3,
            "successful_files": 1,  # 33.3% success rate
            "failed_files": 2,      # 66.7% failure rate
            "current_progress": 0.003,
            "start_time": 1714992000,  # Fixed time for consistent testing
            "throughput_bps": 1024 * 1024  # 1 MB/s
        }
        
        with patch('sys.stdout') as mock_stdout:
            batch_decrypt.update_progress(edge_stats)
            
            # Verify write was called
            mock_stdout.write.assert_called_once()
            
            # Get the progress text to make sure both colors are present
            progress_text = mock_stdout.write.call_args[0][0]
            self.assertIn('\033[92m', progress_text)  # Success color
            self.assertIn('\033[91m', progress_text)  # Error color


if __name__ == "__main__":
    unittest.main()