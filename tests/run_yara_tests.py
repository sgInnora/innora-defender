#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Run all YARA-related test modules and measure code coverage.
This script is designed to run tests for the enhanced YARA generator
modules and generate coverage reports in multiple formats.
"""

import os
import sys
import json
import unittest
import datetime
import importlib
import subprocess
from pathlib import Path

# Add parent directory to path to allow importing modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

# Import coverage module for measuring test coverage
try:
    import coverage
    COVERAGE_AVAILABLE = True
except ImportError:
    print("Warning: coverage module not installed. Coverage analysis will be disabled.")
    print("To install coverage, run: pip install coverage")
    COVERAGE_AVAILABLE = False

# Constants
TARGET_MODULES = [
    'utils.yara_enhanced.enhanced_yara_generator',
    'utils.yara_enhanced.integration',
    'utils.yara_enhanced.yara_cli'
]
TARGET_TEST_MODULES = [
    # Enhanced YARA Generator tests
    'test_enhanced_yara_generator',
    'test_enhanced_yara_generator_enhanced',
    'test_enhanced_yara_generator_fixed',
    'test_enhanced_yara_generator_adapter',
    'test_enhanced_yara_generator_main',
    'test_enhanced_yara_generator_entropy',
    'test_enhanced_yara_generator_optimize',
    'test_enhanced_yara_generator_save',
    'test_enhanced_yara_generator_extractors',
    'test_enhanced_yara_generator_file_info',
    'test_enhanced_yara_generator_analysis',
    'test_enhanced_yara_generator_cli',
    'test_enhanced_yara_generator_cli_advanced',
    'test_enhanced_yara_generator_core',
    'test_enhanced_yara_generator_template',
    'test_enhanced_yara_generator_rule_workflow',
    'test_enhanced_yara_generator_error_handling',
    'test_enhanced_yara_generator_edge_cases',
    
    # Integration tests
    'test_integration_test_rule',
    'test_integration_get_family',
    'test_integration_with_threat_intel',
    'test_integration_batch_process',
    'test_integration_class',
    'test_integration_main',
    
    # CLI tests
    'test_yara_cli'
]

def run_tests(test_modules, verbosity=2):
    """
    Run specified test modules
    
    Args:
        test_modules: List of test module names to run
        verbosity: Level of verbosity for test output
        
    Returns:
        Tuple of (TestResult, dict of test result metadata)
    """
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    print(f"Loading {len(test_modules)} test modules...")
    
    for module_name in test_modules:
        try:
            # Try to import the module
            module = importlib.import_module(module_name)
            tests = loader.loadTestsFromModule(module)
            suite.addTests(tests)
            print(f"  - Added {tests.countTestCases()} tests from {module_name}")
        except Exception as e:
            print(f"  - Error loading {module_name}: {e}")
    
    print(f"Running {suite.countTestCases()} tests...")
    
    # Run the tests
    runner = unittest.TextTestRunner(verbosity=verbosity)
    start_time = datetime.datetime.now()
    result = runner.run(suite)
    end_time = datetime.datetime.now()
    run_time = (end_time - start_time).total_seconds()
    
    # Gather metadata
    metadata = {
        'test_count': suite.countTestCases(),
        'failures': len(result.failures),
        'errors': len(result.errors),
        'skipped': len(result.skipped),
        'run_time': run_time,
        'start_time': start_time.isoformat(),
        'end_time': end_time.isoformat()
    }
    
    return result, metadata

def measure_coverage(target_modules, test_modules, verbosity=2):
    """
    Measure code coverage of specified modules when running tests
    
    Args:
        target_modules: List of target module paths to measure coverage for
        test_modules: List of test module names to run
        verbosity: Level of verbosity for test output
        
    Returns:
        Tuple of (TestResult, coverage data, dict of test result metadata)
    """
    if not COVERAGE_AVAILABLE:
        print("Coverage analysis disabled. Running tests without coverage.")
        result, metadata = run_tests(test_modules, verbosity)
        return result, None, metadata
    
    # Initialize coverage with target modules
    cov = coverage.Coverage(
        source=target_modules,
        omit=['*/test_*', '*/tests/*'],
        config_file=os.path.join(parent_dir, '.coveragerc')
    )
    
    print(f"Starting coverage measurement for modules: {', '.join(target_modules)}")
    
    # Start coverage collection
    cov.start()
    
    # Run tests
    result, metadata = run_tests(test_modules, verbosity)
    
    # Stop coverage collection
    cov.stop()
    
    # Save coverage data
    cov.save()
    
    print("\nCoverage Summary:")
    total_percentage = cov.report()
    metadata['coverage_percentage'] = total_percentage
    
    # Generate HTML report
    html_dir = os.path.join(parent_dir, 'htmlcov')
    cov.html_report(directory=html_dir)
    print(f"HTML coverage report saved to: {html_dir}")
    
    # Generate JSON report
    json_file = os.path.join(parent_dir, 'coverage.json')
    cov.json_report(outfile=json_file)
    print(f"JSON coverage report saved to: {json_file}")
    
    return result, cov, metadata

def generate_markdown_report(test_result, metadata, cov=None):
    """
    Generate a markdown report summarizing test results and coverage
    
    Args:
        test_result: TestResult object
        metadata: Dictionary containing test metadata
        cov: Coverage object for detailed coverage data
        
    Returns:
        Markdown report as a string
    """
    # Format test results
    report = "# YARA Integration Test Coverage Report\n\n"
    report += f"Report generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    
    # Test summary
    report += "## Test Summary\n\n"
    report += f"- **Tests Run:** {metadata['test_count']}\n"
    report += f"- **Failures:** {metadata['failures']}\n"
    report += f"- **Errors:** {metadata['errors']}\n"
    report += f"- **Skipped:** {metadata['skipped']}\n"
    report += f"- **Run Time:** {metadata['run_time']:.2f} seconds\n"
    
    # Add coverage summary if available
    if cov:
        report += f"- **Overall Coverage:** {metadata['coverage_percentage']:.2f}%\n\n"
        
        # Get module-specific coverage
        report += "## Coverage by Module\n\n"
        report += "| Module | Coverage |\n"
        report += "|--------|----------|\n"
        
        # Coverage by module
        for module in sorted(TARGET_MODULES):
            # Get module coverage data from the coverage object
            if hasattr(cov, 'get_data'):
                data = cov.get_data()
                module_files = [f for f in data.measured_files() if module.replace('.', '/') in f]
                
                if module_files:
                    for module_file in module_files:
                        file_coverage = cov.analysis(module_file)
                        if file_coverage[1]:  # If there are executable lines
                            executable_lines = len(file_coverage[1])
                            missing_lines = len(file_coverage[3])
                            coverage_pct = 100.0 * (executable_lines - missing_lines) / executable_lines
                            report += f"| {os.path.basename(module_file)} | {coverage_pct:.2f}% |\n"
                        else:
                            report += f"| {os.path.basename(module_file)} | N/A (no executable lines) |\n"
                else:
                    report += f"| {module} | Not found |\n"
    
    # Add test failures if any
    if test_result.failures:
        report += "\n## Test Failures\n\n"
        for test, error in test_result.failures:
            report += f"### {test}\n\n"
            report += "```\n"
            report += error
            report += "\n```\n\n"
    
    # Add test errors if any
    if test_result.errors:
        report += "\n## Test Errors\n\n"
        for test, error in test_result.errors:
            report += f"### {test}\n\n"
            report += "```\n"
            report += error
            report += "\n```\n\n"
    
    # Add skipped tests if any
    if test_result.skipped:
        report += "\n## Skipped Tests\n\n"
        for test, reason in test_result.skipped:
            report += f"- {test}: {reason}\n"
    
    return report

def main():
    """Main function"""
    print("=== YARA Integration Test Suite ===")
    print(f"Testing modules: {', '.join(TARGET_MODULES)}")
    print(f"Using test modules: {', '.join(TARGET_TEST_MODULES)}")
    
    # Measure coverage
    result, cov, metadata = measure_coverage(TARGET_MODULES, TARGET_TEST_MODULES)
    
    # Generate markdown report
    report = generate_markdown_report(result, metadata, cov)
    
    # Save report
    report_file = os.path.join(parent_dir, 'tests', 'YARA_INTEGRATION_COVERAGE_REPORT.md')
    with open(report_file, 'w') as f:
        f.write(report)
    
    print(f"Markdown report saved to: {report_file}")
    
    # Return appropriate exit code
    if result.failures or result.errors:
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())