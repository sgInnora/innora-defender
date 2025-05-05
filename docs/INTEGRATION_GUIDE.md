# Enhanced Error Pattern Analysis - Integration Guide

This document provides detailed information about integrating the Enhanced Error Pattern Analysis system with your existing ransomware decryption workflows.

## Overview

The Enhanced Error Pattern Analysis system analyzes errors encountered during batch decryption operations to identify patterns, provide insights, and offer recommendations for improving decryption success rates. You can use this system either integrated with the StreamingEngine or as a standalone component.

## Integration Methods

### Method 1: Integrated with StreamingEngine

The simplest way to use the error pattern analysis is to enable it in the StreamingEngine's batch_decrypt method:

```python
from decryption_tools.streaming_engine import StreamingEngine

engine = StreamingEngine()

# Enable error pattern analysis in batch parameters
batch_params = {
    "parallel_execution": True,
    "auto_detect_algorithm": True,
    "max_workers": 4,
    "continue_on_error": True,
    "error_pattern_analysis": True  # Enable error pattern analysis
}

result = engine.batch_decrypt(
    encrypted_files,
    output_dir="/path/to/output",
    key=decryption_key,
    batch_params=batch_params
)

# Access the error analysis results
if hasattr(result, 'enhanced_error_analysis') and result.enhanced_error_analysis:
    error_analysis = result.enhanced_error_analysis
    
    # Example: Print recommendations
    print("Recommendations:")
    for recommendation in error_analysis["recommendations"]:
        print(f"- {recommendation}")
```

With this approach, the error pattern analysis is performed automatically if there are any failed files in the batch processing result.

### Method 2: Standalone Analysis

You can also use the EnhancedErrorPatternDetector as a standalone component to analyze the results from a previous batch decryption operation:

```python
from decryption_tools.enhanced_error_pattern_detector import EnhancedErrorPatternDetector
from decryption_tools.streaming_engine import StreamingEngine

# First run batch decryption without error analysis
engine = StreamingEngine()
result = engine.batch_decrypt(
    encrypted_files,
    output_dir="/path/to/output",
    key=decryption_key
)

# Now analyze the results separately
if result.failed_files > 0:
    detector = EnhancedErrorPatternDetector()
    error_analysis = detector.analyze_error_patterns(result.file_results)
    
    # Use the analysis results
    print(f"Detected {len(error_analysis['error_patterns'])} error patterns")
    print(f"Generated {len(error_analysis['recommendations'])} recommendations")
```

This approach is useful when you want to perform additional customization or only run the analysis in certain scenarios.

## Generating Error Analysis Summaries

The EnhancedErrorPatternDetector can generate comprehensive error analysis summaries in Markdown format:

```python
from decryption_tools.enhanced_error_pattern_detector import EnhancedErrorPatternDetector

detector = EnhancedErrorPatternDetector()

# Analyze file results
error_analysis = detector.analyze_error_patterns(file_results)

# Generate a summary report
detector.generate_error_analysis_summary(
    error_analysis,
    "/path/to/error_analysis_summary.md"
)
```

The generated summary includes:
- Error statistics
- Error type distribution
- Detected error patterns and their severity
- Recommendations based on the patterns
- File characteristics analysis
- Path pattern analysis

## Custom Pattern Detection

You can extend the EnhancedErrorPatternDetector by adding custom error patterns:

```python
from decryption_tools.enhanced_error_pattern_detector import EnhancedErrorPatternDetector

detector = EnhancedErrorPatternDetector()

# Add a custom error pattern
detector.add_error_pattern(
    pattern_name="custom_network_error",
    pattern_regex=r"network connection (failed|timed out|refused)",
    description="Network connectivity issues during decryption",
    severity="medium",
    recommendation="Check network settings and ensure stable connectivity"
)

# Now use the detector with the additional pattern
error_analysis = detector.analyze_error_patterns(file_results)
```

## Complete Example Workflow

Here's a complete example of processing a batch of encrypted files with error pattern analysis:

```python
import os
import glob
from decryption_tools.streaming_engine import StreamingEngine

# Find encrypted files
encrypted_files = glob.glob("/path/to/encrypted/files/*.encrypted")

# Initialize the streaming engine
engine = StreamingEngine()

# Set up batch parameters with error pattern analysis
batch_params = {
    "parallel_execution": True,
    "auto_detect_algorithm": True,
    "max_workers": 4,
    "continue_on_error": True,
    "error_pattern_analysis": True
}

# Process the files
result = engine.batch_decrypt(
    encrypted_files,
    output_dir="/path/to/output",
    key="your_decryption_key",
    batch_params=batch_params
)

# Print results
print(f"Processed {result.total_files} files")
print(f"Successfully decrypted: {result.successful_files}")
print(f"Failed: {result.failed_files}")

# Check if error analysis was performed
if hasattr(result, 'enhanced_error_analysis') and result.enhanced_error_analysis:
    analysis = result.enhanced_error_analysis
    
    print("\nError Statistics:")
    stats = analysis["error_statistics"]
    print(f"Total errors: {stats['total_errors']}")
    print(f"Unique error types: {stats['unique_error_types']}")
    
    print("\nDetected Error Patterns:")
    for pattern in analysis["error_patterns"]:
        print(f"- {pattern['description']} (Severity: {pattern['severity']})")
    
    print("\nRecommendations:")
    for recommendation in analysis["recommendations"]:
        print(f"- {recommendation}")
    
    # Generate a detailed summary
    from decryption_tools.enhanced_error_pattern_detector import EnhancedErrorPatternDetector
    detector = EnhancedErrorPatternDetector()
    detector.generate_error_analysis_summary(
        analysis,
        "error_analysis_summary.md"
    )
    print("\nDetailed error analysis has been saved to 'error_analysis_summary.md'")
```

## Performance Considerations

The error pattern analysis adds minimal overhead to the batch processing operation, as it's only performed once after all files have been processed. However, for very large batches (thousands of files) with many errors, you may want to consider:

1. Running the analysis in a separate thread
2. Using the standalone approach for more control
3. Setting a limit on the number of files analyzed if memory usage is a concern

## Command-line Usage

You can use the included example script to run error pattern analysis from the command line:

```bash
# Using integrated analysis
python examples/integrated_error_pattern_analysis.py \
    --input_dir /path/to/encrypted/files \
    --output_dir /path/to/output \
    --key your_decryption_key \
    --summary_file error_analysis.md

# Using standalone analysis
python examples/integrated_error_pattern_analysis.py \
    --input_dir /path/to/encrypted/files \
    --output_dir /path/to/output \
    --key your_decryption_key \
    --standalone \
    --summary_file error_analysis.md
```

## Troubleshooting

If you encounter issues with the error pattern analysis:

1. Ensure you're using Python 3.6 or later
2. Make sure the `error_pattern_analysis` parameter is set to `True` in batch_params
3. Verify that there are failed files in the batch result (the analysis is only performed if there are errors)
4. Check the error message if an exception occurs during analysis

For any additional assistance, please open an issue on the project repository.