#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Measure final code coverage for the batch decrypt module (quick version)
"""

import os
import sys
import unittest
import coverage
import json
from datetime import datetime

# Add project root to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import all test suites
from tests.test_batch_decrypt_cli import TestBatchDecryptCLI, TestModuleCoverage
from tests.test_batch_decrypt_coverage_improvement import (
    TestUpdateProgressCoverage,
    TestPrintSummaryCoverage,
    TestDetectTerminalColorSupport
)
from tests.test_batch_decrypt_final_coverage import (
    TestPrintSummaryFinalCoverage,
    TestUpdateProgressFinalCoverage
)

def measure_coverage():
    """Measure code coverage for batch processing with all coverage tests (quick version)"""
    print("=" * 80)
    print("Quick FINAL coverage measurement")
    print("=" * 80)
    
    try:
        # First ensure module is not loaded
        if 'batch_decrypt' in sys.modules:
            del sys.modules['batch_decrypt']
            
        # Start coverage here
        cov = coverage.Coverage(
            source=["batch_decrypt"],
            omit=["*/__pycache__/*", "*/test_*.py"],
            branch=True
        )
        cov.start()
        
        # Force import to cover module-level code
        import batch_decrypt
        
        # Add only the new tests that are likely to improve coverage
        test_suite = unittest.TestSuite()
        
        # Add only improved and final coverage tests
        test_suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestUpdateProgressCoverage))
        test_suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestPrintSummaryCoverage))
        test_suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestDetectTerminalColorSupport))
        test_suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestPrintSummaryFinalCoverage))
        test_suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestUpdateProgressFinalCoverage))
        
        # Run tests with minimal output
        print("\nRunning quick coverage tests...\n")
        test_runner = unittest.TextTestRunner(verbosity=1)
        result = test_runner.run(test_suite)
        
        # Stop coverage measurement
        cov.stop()
        cov.save()
        
        # Report coverage
        print("\n\nQuick Final Coverage Summary:")
        cov.report(show_missing=True)
        
        # Return exit code based on test result
        return 0 if result.wasSuccessful() else 1
    
    except Exception as e:
        print(f"Error during coverage measurement: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(measure_coverage())