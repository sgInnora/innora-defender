# Maintaining Test Coverage in Innora-Defender

## Overview

This document describes how to maintain the test coverage for security-critical modules in the Innora-Defender project. Security-critical components must maintain a minimum of 95% test coverage to ensure reliability and security.

## Security-Critical Modules

The following modules are considered security-critical and require strict test coverage:

1. **LockBit Recovery Modules**
   - `decryption_tools/network_forensics/lockbit_optimized_recovery.py` (≥95%)
   - `decryption_tools/network_forensics/lockbit_enhanced_recovery.py` (≥95%)

2. **YARA Rule Generation**
   - `utils/yara_enhanced/enhanced_yara_generator.py` (≥95%) ✅ - **Achieved 95% coverage (2025-05-04)**
   - `utils/yara_enhanced/integration.py` (≥95%) ⚠️ - **Currently at 87% coverage**
   - `utils/yara_enhanced/yara_cli.py` (≥95%) ⚠️ - **Currently at 78% coverage**

3. **Encryption Analysis**
   - `decryption_tools/external/encryption_analyzer.py` (≥90%)

## Running Tests

### Individual Module Testing

To test specific modules and measure their coverage:

#### LockBit Recovery

```bash
# Run the enhanced tests for LockBit recovery
python tests/run_enhanced_tests.py --module lockbit

# Run the comprehensive test suite for all modules
python tests/run_enhanced_tests.py --module all
```

#### YARA Generation

```bash
# Run tests for YARA generator modules
python tests/run_enhanced_tests.py --module yara
```

### Running Security Coverage Checks

A specialized script is provided to verify that all security-critical modules maintain their required coverage thresholds:

```bash
# Verify coverage for all security-critical modules
tests/check_security_coverage.sh
```

This script is also integrated into the CI/CD pipeline to ensure coverage doesn't drop below required thresholds during development.

## Coverage Monitoring Tools

We provide several tools to help monitor and visualize test coverage:

### Coverage History Tracking

The coverage history tracker records test coverage data over time and stores it in a database:

```bash
# Track all security-critical modules
tools/ci/track_coverage_history.py

# Track specific module
tools/ci/track_coverage_history.py --module decryption_tools.network_forensics.lockbit_optimized_recovery

# Show coverage trend report
tools/ci/track_coverage_history.py --report
```

### Coverage Visualization

Generate visual reports showing coverage trends over time:

```bash
# Generate HTML coverage trend report
tools/ci/visualize_coverage_trends.py

# Customize output location
tools/ci/visualize_coverage_trends.py --output path/to/report.html

# Control history timeframe
tools/ci/visualize_coverage_trends.py --days 30
```

### Comprehensive Coverage Monitor

For a complete coverage monitoring workflow:

```bash
# Run full monitoring cycle
tools/ci/coverage_monitor.py

# Generate reports without running tests
tools/ci/coverage_monitor.py --report-only

# Monitor specific module
tools/ci/coverage_monitor.py --module lockbit_optimized_recovery
```

### Automated Monitoring

Coverage monitoring is automatically run:
- On every PR that modifies security-critical code
- Weekly on the `main` and `develop` branches
- When manually triggered via GitHub Actions

Coverage reports are published to GitHub Pages for easy access.

## Adding Coverage Tests

When adding new features or modifying security-critical code, follow these guidelines to maintain coverage:

1. **Write Tests First**: Adopt a test-driven development approach when possible.
2. **Cover Edge Cases**: Ensure error handling paths are tested.
3. **Mock External Dependencies**: Use unittest.mock to isolate code during testing.
4. **Test Exception Paths**: Deliberately trigger exceptions to test error handling.
5. **Check Coverage Impact**: Use the monitoring tools to verify that your changes don't decrease coverage.

### Example of Adding a Targeted Test

```python
def test_specific_error_condition(self):
    """Test a specific error condition in the module"""
    # Create mocks for dependencies
    with patch('module.dependency', side_effect=Exception("Test error")):
        # Call the function under test
        result = self.module_instance.function_to_test()
        
        # Verify error handling worked correctly
        self.assertFalse(result['success'])
        self.assertEqual(result['error'], "Error in dependency")
```

## Troubleshooting Common Test Issues

### Test Failures

If tests fail after code changes:

1. **Review Coverage Report**: Check the HTML report in `htmlcov/index.html`
2. **Identify Uncovered Lines**: Focus on the lines that aren't being covered
3. **Add Targeted Tests**: Create specific tests for uncovered code paths
4. **Check Trend Reports**: Use `tools/ci/visualize_coverage_trends.py` to see if coverage has been declining

### Mock Objects

When working with mocks:

1. **Reset Mocks**: Use `mock_object.reset_mock()` between assertions
2. **Verify Call Counts**: Use `mock_object.assert_called_once()` to verify behavior
3. **Side Effects**: Use `side_effect` to simulate exceptions or specific return values

### Import Errors

For import errors in tests:

1. **Avoid Patching sys.modules**: This can cause side effects
2. **Use Flags**: Set module flags directly to simulate import conditions
3. **Restore Original State**: Always restore the original state after tests

## CI/CD Integration

The test coverage checks are integrated into the CI/CD pipeline:

1. **Pull Requests**: Coverage is verified for all PRs
2. **Automated Builds**: Regular builds verify coverage
3. **Release Gates**: Releases require passing all coverage thresholds
4. **Historical Tracking**: Coverage history is tracked and visualized over time
5. **Scheduled Monitoring**: Weekly coverage checks run automatically
6. **Published Reports**: Coverage trends are available on GitHub Pages

## Git Hooks

We provide Git hooks to ensure coverage requirements are met before commits:

```bash
# Install Git hooks
./install_git_hooks.sh
```

This will install a pre-commit hook that automatically verifies coverage for security-critical modules when they are modified.

## Conclusion

Maintaining high test coverage is essential for the security and reliability of the Innora-Defender project. Follow these guidelines and use the provided tools to ensure that all security-critical components are thoroughly tested and maintain their coverage thresholds.