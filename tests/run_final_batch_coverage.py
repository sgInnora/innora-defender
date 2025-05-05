#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Measure final code coverage for the batch decrypt module
"""

import os
import sys
import unittest
import coverage
import json
import importlib
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
    """Measure code coverage for batch processing with all coverage tests"""
    print("=" * 80)
    print("Measuring FINAL code coverage for batch processing")
    print(f"Target: 95% coverage for security-critical modules")
    print("=" * 80)
    
    # Pre-import to record all module-level code
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
        
        # Create and run test suite with all tests
        test_suite = unittest.TestSuite()
        
        # Add original tests
        test_suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestBatchDecryptCLI))
        test_suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestModuleCoverage))
        
        # Add improved coverage tests
        test_suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestUpdateProgressCoverage))
        test_suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestPrintSummaryCoverage))
        test_suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestDetectTerminalColorSupport))
        
        # Add final coverage tests
        test_suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestPrintSummaryFinalCoverage))
        test_suite.addTest(unittest.defaultTestLoader.loadTestsFromTestCase(TestUpdateProgressFinalCoverage))
        
        # Run tests
        print("\nRunning FINAL batch processing coverage tests...\n")
        test_runner = unittest.TextTestRunner(verbosity=2)
        result = test_runner.run(test_suite)
        
        # Stop coverage measurement
        cov.stop()
        cov.save()
        
        # Report coverage
        print("\n\nFINAL Coverage Summary:")
        cov.report(show_missing=True)
        
        # Generate HTML report
        html_dir = "htmlcov_batch_processing_final"
        print(f"\nGenerating HTML report in {html_dir}...")
        cov.html_report(directory=html_dir)
        print(f"HTML report is available at {html_dir}/index.html")
        
        # Generate JSON report to file
        json_file = "batch_coverage_final_data.json"
        cov.json_report(outfile=json_file)
        
        # Read the JSON report
        with open(json_file, 'r') as f:
            coverage_data = json.load(f)
        
        # Extract overall coverage percentage
        total_coverage = coverage_data.get("totals", {}).get("percent_covered", 0)
        
        # Write report
        report_file = "batch_coverage_final_report.json"
        with open(report_file, "w") as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "total_coverage": total_coverage,
                "target_coverage": 95.0,
                "meets_target": total_coverage >= 95.0,
                "details": coverage_data
            }, f, indent=2)
        
        print(f"\nJSON coverage report saved to {report_file}")
        
        # Check if coverage target is met
        if total_coverage >= 95.0:
            print(f"\n✅ Coverage target met: {total_coverage:.2f}% (target: 95%)")
        else:
            print(f"\n❌ Coverage target not met: {total_coverage:.2f}% (target: 95%)")
            print("Please add more tests to improve coverage.")
            
        # Print missing lines
        if "files" in coverage_data and "batch_decrypt.py" in coverage_data["files"]:
            file_data = coverage_data["files"]["batch_decrypt.py"]
            missing_lines = file_data.get("missing_lines", [])
            print("\nMissing lines in batch_decrypt.py:")
            for line in missing_lines:
                print(f"  Line {line}")
        
        # Return exit code based on test result
        return 0 if result.wasSuccessful() else 1
    
    except Exception as e:
        print(f"Error during coverage measurement: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(measure_coverage())