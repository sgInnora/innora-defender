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