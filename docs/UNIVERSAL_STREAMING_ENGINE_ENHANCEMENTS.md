# Universal Streaming Engine Enhancements

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

The Universal Streaming Engine has been significantly improved with robust error handling mechanisms, making it more resilient when processing corrupted or malformed encrypted files.

### Key Improvements

1. **Comprehensive Error Tracking**
   - Added "errors" array to detection results to track all encountered issues
   - Granular error reporting for specific processing stages
   - Ability to continue processing despite non-critical errors

2. **Robust File Analysis**
   - Improved file existence and accessibility checks
   - Safer file reading with specific exception handling
   - Graceful handling of partial or corrupted files
   - Multiple-stage protection against file reading errors

3. **Resilient Algorithm Detection**
   - Enhanced signature checking with type safety and bounds checking
   - Improved entropy calculation with fallback implementations
   - Isolating pattern matching errors to prevent complete detection failure
   - Fallback mechanisms when external dependencies are unavailable

4. **Family Parameter Handling**
   - Safe handling of None-type family parameters
   - Type-checking for family name processing
   - Protected family-specific parameter application
   - Detailed tracking of applied parameters

5. **Runtime Safety Features**
   - Default values when calculations fail
   - Safe type conversions with error recovery
   - Nested exception handling for maximum reliability
   - Algorithm-specific error isolation

### Benefits

- **Increased Reliability**: Successfully processes damaged or non-standard encrypted files
- **Better Diagnostics**: Detailed error information helps identify specific issues
- **Reduced Failures**: Continues operation even with partial information
- **Dependency Tolerance**: Functions even when optional dependencies are missing
- **Improved Transparency**: Errors are tracked but don't prevent results from being returned

### Usage Example

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