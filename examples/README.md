# Innora-Defender Examples

This directory contains example scripts demonstrating various capabilities of the Innora-Defender project.

## Available Examples

### Enhanced Error Pattern Analysis

- [**integrated_error_pattern_analysis.py**](integrated_error_pattern_analysis.py): Demonstrates the end-to-end usage of the Enhanced Error Pattern Detection System. This example shows how to use the system in both integrated and standalone modes, with various command-line options.

  ```bash
  # Using integrated analysis
  python examples/integrated_error_pattern_analysis.py \
      --input_dir /path/to/encrypted/files \
      --output_dir /path/to/output \
      --key your_decryption_key \
      --recursive \
      --summary_file error_analysis.md
  ```

- [**enhanced_error_detection.py**](enhanced_error_detection.py): An implementation focusing on the core error pattern detection capabilities, showing how to use the EnhancedErrorPatternDetector with StreamingEngine.

### Adaptive Decryption

- [**adaptive_decryption.py**](adaptive_decryption.py): Demonstrates the adaptive decryption capabilities of the Innora-Defender project, showing how to automatically select and apply the most appropriate decryption algorithms based on file characteristics.

## Usage Guidelines

### Prerequisites

Before running these examples, ensure you have:

1. Installed all required dependencies (see main README.md)
2. Access to encrypted files for testing (or use the provided test files)
3. Valid decryption keys where applicable

### Command-Line Options

Most example scripts provide detailed help via the `--help` option:

```bash
python examples/integrated_error_pattern_analysis.py --help
```

### Output Formats

Examples typically support various output formats:

- Console output for immediate feedback
- Detailed summary files (usually in Markdown format)
- JSON output for programmatic processing

## Integration into Custom Workflows

The example scripts are designed to be both educational and practical. You can use them as a starting point for building custom solutions by:

1. Copying and modifying the scripts for your specific needs
2. Importing the core functionality into your own Python code
3. Using them as reference for API usage patterns

## Documentation

For more detailed information about the features demonstrated in these examples, refer to the following documentation:

- [Enhanced Error Pattern Detection](../docs/ENHANCED_ERROR_PATTERN_DETECTION.md)
- [Integration Guide](../docs/INTEGRATION_GUIDE.md)
- [End-to-End Testing Summary](../docs/SUMMARY_OF_END_TO_END_TESTING.md)
- [Implementation Summary](../docs/IMPLEMENTATION_SUMMARY_2025_05_06.md)

## Examples in Development

Future examples will include:

- Multi-algorithm batch processing
- Custom error pattern detection
- Integration with external reporting tools
- Advanced encryption type analysis