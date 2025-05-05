# Universal Streaming Engine Enhancements

## Batch Processing Improvements

The Universal Streaming Engine's batch processing capabilities have been enhanced with improved error handling, better progress reporting, and more detailed analytics. These improvements make the system more robust for large-scale batch operations while providing users with more meaningful information about the decryption process.

### Key Enhancements

#### 1. Enhanced Progress Visualization

- **Color-coded Progress Bar**: The progress bar now shows successful and failed files in different colors for immediate visual feedback.
- **Estimated Time Remaining (ETA)**: Calculates and displays the estimated time to completion based on current processing speed.
- **Real-time Throughput Statistics**: Shows current processing speed in MB/s for better performance monitoring.
- **Auto-detecting Terminal Support**: Automatically disables colors in terminals that don't support ANSI color codes.

#### 2. Comprehensive Error Handling

- **Structured Error Categorization**: Errors are now categorized by severity (critical, high, medium, low) for better prioritization.
- **Enhanced Exception Handling**: Improved try/except blocks throughout the code to catch and handle specific exceptions.
- **Error Threshold Controls**: Added finer control over when batch processing should abort based on error rates.
- **Validation Level Selection**: New command-line option for selecting validation level (none, basic, standard, strict).

#### 3. Detailed Reporting

- **Rich Summary Output**: Completely redesigned summary output with color-coded sections and better formatting.
- **Performance Analytics**: More detailed performance metrics including min/max throughput and processing times.
- **Error Insights**: Advanced error analysis that provides patterns and recommendations based on observed errors.
- **Time Tracking**: Improved time tracking that distinguishes between setup time and actual processing time.

#### 4. Usability Improvements

- **Better Command-line Interface**: Command-line options organized into logical groups with improved help text and defaults.
- **Quiet Mode**: Option to suppress all non-essential output for use in scripts and automated workflows.
- **No-Progress Mode**: Option to disable the progress bar for use in non-interactive environments.
- **Detailed Summary Files**: Option to include detailed file-level information in summary JSON files.

### Command-line Options

```
Usage: batch_decrypt.py [options]

Input/Output Options:
  --input-dir PATH         Directory containing encrypted files
  --file-list FILE         File containing list of input,output file pairs
  --output-dir PATH        Directory for decrypted output (required with --input-dir)
  --extensions LIST        Comma-separated list of file extensions to process (e.g. '.enc,.encrypted')
  --recursive              Process subdirectories recursively (default: True)
  --no-recursive           Do not process subdirectories

Decryption Options:
  --algorithm ALGORITHM    Encryption algorithm to use
  --key KEY                Decryption key (hex or string)
  --key-file FILE          File containing decryption key
  --auto-detect            Auto-detect encryption algorithm
  --header-size SIZE       Size of header to skip
  --iv IV                  Initialization vector (hex)
  --iv-in-file             Extract IV from file
  --iv-offset OFFSET       Offset of IV in file
  --iv-size SIZE           Size of IV in file

Batch Processing Options:
  --parallel               Process files in parallel (default)
  --no-parallel            Process files sequentially
  --threads N              Number of threads for parallel processing (default: auto)
  --max-retries N          Maximum number of retries per file (default: 1)
  --error-threshold PCT    Percentage of failures before aborting (default: 100)
  --continue-on-error      Continue processing after errors (default)
  --no-continue-on-error   Abort on any error
  --validation-level LEVEL Validation level for decryption results (none, basic, standard, strict)

Output Options:
  --summary-file FILE      File to save summary JSON
  --detailed-summary       Include detailed file information in summary
  --verbose                Enable verbose output
  --quiet                  Suppress informational output
  --no-progress            Disable progress bar
  --no-color               Disable colored output
```

### Example Usage

#### Basic Usage with Auto-detection

```bash
python batch_decrypt.py --input-dir /path/to/encrypted/files --output-dir /path/to/output --auto-detect
```

#### Processing Specific File Types with Parallel Processing

```bash
python batch_decrypt.py --input-dir /path/to/encrypted/files --output-dir /path/to/output \
    --extensions ".enc,.locked" --algorithm aes-cbc --key-file /path/to/key.bin \
    --parallel --threads 8
```

#### Using File List with Detailed Summary

```bash
python batch_decrypt.py --file-list files.txt --algorithm aes-cbc \
    --key 0123456789abcdef0123456789abcdef --summary-file summary.json \
    --detailed-summary
```

#### Non-interactive Usage in Scripts

```bash
python batch_decrypt.py --input-dir /path/to/encrypted/files --output-dir /path/to/output \
    --auto-detect --key-file /path/to/key.bin --no-progress --quiet \
    --summary-file summary.json
```

### Implementation Notes

#### Performance Considerations

- The enhanced progress bar and detailed reporting add minimal overhead to the processing.
- For very large batches (thousands of files), consider using the `--no-progress` option to reduce overhead.
- The `--detailed-summary` option can create large JSON files when processing many files.

#### Error Handling

- The system now provides better feedback when errors occur, helping users diagnose issues more effectively.
- When auto-detection is enabled, the system will try to provide recommendations for specific algorithms if detection fails.
- Validation levels allow users to balance between speed and thoroughness when verifying decryption results.

#### Future Enhancements

- Integration with centralized logging systems
- Support for resuming interrupted batch operations
- Machine learning-based algorithm detection improvements
- Interactive mode for handling problematic files during batch processing

#### Compatibility

These enhancements maintain full backwards compatibility with existing batch_decrypt.py command-line usage. All previous command-line options continue to work as before, with the new options being optional enhancements.

## Adaptive Algorithm Selection Improvements

The Universal Streaming Engine now features significantly enhanced adaptive algorithm selection capabilities, enabling more robust and efficient decryption of ransomware-encrypted files with minimal user input.

### Key Enhancements

1. **Intelligent Algorithm Detection**
   - Extended pattern recognition for common ransomware families
   - File extension-based family detection (30+ extensions supported)
   - File signature-based detection with high-confidence markers
   - Entropy analysis for encrypted data recognition
   - Header structure analysis for encryption parameters

2. **Adaptive Parameter Learning**
   - Runtime learning from successful decryptions
   - Extension-based parameter adaptation
   - Family-specific parameter optimization
   - Confidence-based algorithm selection

3. **Multi-Strategy Approach**
   - Automatic algorithm selection when family is unknown
   - Fallback and retry mechanisms for failed decryptions
   - Parallel batch processing for efficiency
   - Comprehensive success rate tracking

### Implementation Details

The enhanced algorithm selection is implemented through several components:

- **AlgorithmDetector**: A specialized class that analyzes files to determine the most likely encryption algorithm and parameters
- **Batch Processing**: Improved batch_decrypt method that can learn from successful decryptions
- **Parameter Adaptation**: Intelligent adjustment of decryption parameters based on file characteristics

### Supported Algorithms and Families

The system now features improved detection for the following algorithms:
- AES-CBC, AES-ECB (common in many ransomware families)
- ChaCha20 (used by BlackCat/ALPHV, Maze)
- Salsa20 (used by REvil/Sodinokibi, STOP/DJVU)

Enhanced family detection includes:
- Ryuk
- LockBit
- BlackCat/ALPHV
- WannaCry
- REvil/Sodinokibi
- STOP/DJVU
- Conti
- Maze
- Rhysida

### Usage Examples

#### Basic Usage with Auto-Detection

```python
from decryption_tools.streaming_engine import StreamingDecryptionEngine

engine = StreamingDecryptionEngine()
result = engine.decrypt_file(
    "encrypted_file.locked",
    "decrypted_file.txt",
    None,  # No family specified, will use auto-detection
    key_bytes,
    auto_detect=True,
    retry_algorithms=True
)
```

#### Batch Processing with Adaptive Learning

```python
from decryption_tools.streaming_engine import StreamingDecryptionEngine

engine = StreamingDecryptionEngine()
results = engine.batch_decrypt(
    ["file1.encrypted", "file2.encrypted", "file3.encrypted"],
    "/output/directory",
    None,  # No family specified
    key_bytes,
    auto_detect=True,
    retry_algorithms=True,
    adaptive_params=True,
    parallel=True  # Use parallel processing
)
```

### Demo Tool

The repository includes a demonstration utility at `examples/adaptive_decryption.py` that showcases these capabilities. This tool can be used to:

- Analyze files to detect encryption algorithms without decryption
- Extract decryption parameters from encrypted files
- Perform single-file decryption with auto-detection
- Batch process multiple files with adaptive learning

#### Example Commands:

```bash
# Analyze a file to detect its encryption algorithm
python adaptive_decryption.py --file encrypted.locked --analyze-algorithm

# Extract parameters without decrypting
python adaptive_decryption.py --file encrypted.locked --extract-params

# Decrypt a single file with automatic algorithm detection
python adaptive_decryption.py --file encrypted.locked --output decrypted.txt --key 5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A --auto-detect

# Batch process multiple files with adaptive learning
python adaptive_decryption.py --batch "samples/*.locked" --key-file key.bin --output-dir decrypted/ --parallel
```

### Benefits

- **Reduced User Input**: Users no longer need to know the specific ransomware family or encryption details
- **Higher Success Rate**: Multiple detection strategies and retry mechanisms significantly increase decryption success
- **Improved Efficiency**: Parallel processing and learning from past successes optimize large batch operations
- **Better Unknown Variant Handling**: Can effectively decrypt files from unknown ransomware variants by analyzing their characteristics

## Enhanced Error Handling and Resilience

The Universal Streaming Engine has been significantly improved with robust error handling mechanisms, making it more resilient when processing corrupted or malformed encrypted files. These enhancements apply to both the AlgorithmDetector class and the StreamingDecryptionEngine class.

### Key Improvements in AlgorithmDetector

1. **Comprehensive Error Tracking**
   - Added "errors" array to detection results to track all encountered issues
   - Granular error reporting for specific processing stages (file opening, signature checking, entropy calculation)
   - Ability to continue processing despite non-critical errors
   - Centralized error collection from all detection steps

2. **Robust File Analysis**
   - Improved file existence and accessibility checks with detailed error messages
   - Safer file reading with specific exception handling for different I/O errors
   - Graceful handling of partial or corrupted files with section-specific error tracking
   - Multi-stage protection against file reading errors with fallback mechanisms
   - Header, middle and footer section validation with independent error handling

3. **Resilient Algorithm Detection**
   - Enhanced signature checking with type safety and bounds checking
   - Boundary validation before accessing file sections
   - Improved entropy calculation with fallback implementations
   - Independent pattern matching with error isolation to prevent complete detection failure
   - Strong fallback mechanisms when external dependencies are unavailable

4. **Family Parameter Handling**
   - Safe handling of None-type family parameters with explicit checks
   - Proper type-checking for family name processing and case conversion
   - Protected family-specific parameter application with error boundaries
   - Detailed tracking of which family-specific parameters were successfully applied
   - Verification of parameter validity before application

5. **Runtime Safety Features**
   - Default values provided when calculations fail
   - Safe type conversions with error recovery mechanisms
   - Nested exception handling for maximum reliability
   - Algorithm-specific error isolation
   - Value validation before mathematical operations

### Key Improvements in StreamingDecryptionEngine

1. **Enhanced Decryption File Processing**
   - Comprehensive input validation (file existence, readability, key presence)
   - Output directory creation and permission verification
   - Structured error reporting with both summary "error" and detailed "errors" array
   - Proper error propagation from algorithm detection to calling code
   - Complete error isolation between detection, configuration, and decryption phases

2. **Improved In-Memory Data Decryption**
   - Thorough input validation for data content and key parameters
   - Simplified algorithm detection specifically for in-memory data
   - Adaptive fallback to default algorithms when detection is limited
   - Enhanced alternative algorithm handling for retry operations
   - Better error propagation in nested function calls

3. **Robust Batch Processing**
   - Error isolation for individual file processing operations
   - Protection against batch failure due to individual file issues
   - Enhanced adaptive parameter learning with error resilience
   - Continued batch processing despite individual file failures
   - Comprehensive error recording for each file in results
   - Improved parallel processing error management

### Benefits

- **Increased Reliability**: Successfully processes damaged or non-standard encrypted files
- **Better Diagnostics**: Detailed error information helps identify specific issues
- **Reduced Failures**: Continues operation even with partial information
- **Dependency Tolerance**: Functions even when optional dependencies are missing
- **Improved Transparency**: Errors are tracked but don't prevent results from being returned
- **Enhanced Recovery**: Better ability to extract useful information from damaged files
- **Higher Success Rate**: More files can be processed successfully even with some errors

### Usage Examples

#### Working with Algorithm Detection Errors

```python
from decryption_tools.streaming_engine import AlgorithmDetector

detector = AlgorithmDetector()
result = detector.detect_algorithm("corrupted_encrypted_file.locked")

# Check for any errors encountered during detection
if "errors" in result and result["errors"]:
    print("Detection completed with the following issues:")
    for error in result["errors"]:
        print(f" - {error}")

# Algorithm detection still provides results even with errors
print(f"Detected algorithm: {result['algorithm']} (confidence: {result['confidence']:.2f})")
print(f"Detected parameters: {result['params']}")
```

#### Handling File Decryption Errors

```python
from decryption_tools.streaming_engine import StreamingDecryptionEngine

engine = StreamingDecryptionEngine()
result = engine.decrypt_file(
    "partially_corrupted_file.encrypted",
    "recovered_output.txt",
    key=key_bytes,
    auto_detect=True,
    retry_algorithms=True
)

# Check for decryption errors
if "errors" in result and result["errors"]:
    print("Decryption completed with the following issues:")
    for error in result["errors"]:
        print(f" - {error}")
    
    if result.get("success", False):
        print("Despite errors, decryption was successful!")
    elif result.get("partial_success", False):
        print("Partial decryption was achieved. Some data may be recoverable.")
    else:
        print("Decryption failed.")
```

#### Robust Batch Processing with Error Handling

```python
from decryption_tools.streaming_engine import StreamingDecryptionEngine

engine = StreamingDecryptionEngine()
batch_result = engine.batch_decrypt(
    ["file1.encrypted", "damaged_file.encrypted", "file3.encrypted"],
    "output_directory/",
    key=key_bytes,
    auto_detect=True,
    retry_algorithms=True,
    parallel=True
)

# Check overall statistics
print(f"Processed {batch_result['total']} files")
print(f"Successfully decrypted: {batch_result['successful']}")
print(f"Partially successful: {batch_result.get('partial', 0)}")
print(f"Failed: {batch_result['failed']}")

# Check individual file results
for file_result in batch_result["files"]:
    if not file_result["success"]:
        print(f"Issues with {file_result['input']}:")
        if "errors" in file_result:
            for error in file_result["errors"]:
                print(f"  - {error}")
```

### Implementing Custom Error Handling

When using the Universal Streaming Engine, you can implement custom error handling logic:

```python
def custom_error_handler(result):
    """Process results with custom error handling logic"""
    # Extract all errors
    all_errors = []
    if "errors" in result:
        all_errors.extend(result["errors"])
    
    # Categorize errors
    critical_errors = []
    warnings = []
    
    for error in all_errors:
        if "file not found" in error or "key" in error:
            critical_errors.append(error)
        else:
            warnings.append(error)
    
    # Handle based on error types
    if critical_errors:
        print("Critical errors prevented successful operation:")
        for error in critical_errors:
            print(f"  - {error}")
        return False
    
    if warnings:
        print("Operation completed with warnings:")
        for warning in warnings:
            print(f"  - {warning}")
    
    # Process was successful despite warnings
    return True
```

The enhanced error handling system provides significant improvements in diagnosing and recovering from issues during the decryption process, making the Universal Streaming Engine more robust and effective in real-world scenarios.