# Innora-Defender: Advanced Ransomware Decryption Framework

<div align="center">
<p>
    <img width="140" src="screenshots/logo.png" alt="Innora-Defender logo">
</p>
<p>
    <b>Advanced Ransomware Analysis and Recovery System</b>
</p>
<p>
    <b>高级勒索软件分析与恢复系统</b>
</p>
</div>

---

**English** | [中文](./README_CN.md)

## Overview

**Innora-Defender** is a comprehensive ransomware decryption framework focused on helping victims recover their files without paying ransom. Our system combines advanced cryptographic analysis, memory forensics, and binary analysis to recover encryption keys and decrypt files affected by various ransomware families.

### Key Features

- **Specialized Decryption Tools**: Industry-leading recovery tools for LockBit, BlackCat, and other major ransomware families
- **Multi-Stage Key Recovery**: Advanced techniques for extracting encryption keys from memory, network traffic, and binary analysis
- **Enhanced File Format Analysis**: Intelligent recovery of corrupted files and sophisticated encryption structures
- **Memory Forensics**: Extracts encryption keys and artifacts from memory dumps with advanced pattern recognition
- **Optimized Recovery Algorithms**: Supports AES-CBC, ChaCha20, and multiple custom encryption schemes
- **Automated Family Detection**: Identifies specific ransomware families with high accuracy to apply the right decryption techniques
- **Multi-Ransomware Recovery Framework**: Unified approach to handling different ransomware families
- **Binary Analysis Tools**: Identifies weaknesses in ransomware implementations to enable decryption
- **Partial Recovery Capabilities**: Recovers data even when complete decryption isn't possible
- **Cost-Optimized LLM Analysis**: Advanced ransomware analysis using large language models with intelligent provider selection to minimize operational costs while maximizing analysis quality

## Project Structure

```
innora-defender/
├── decryption_tools/          # Ransomware-specific decryption tools
├── tools/                     # Analysis and recovery utilities
│   ├── crypto/                # Cryptographic analysis tools
│   ├── memory/                # Memory forensics for key extraction
│   ├── static/                # Binary analysis tools
├── threat_intel/              # Ransomware family information
├── ai_detection/              # AI-based detection and analysis
│   ├── llm_service/           # Cost-optimized LLM service
│   │   ├── config/            # Service configuration
│   │   ├── cli.py             # Command-line interface
│   │   ├── llm_provider_manager.py # Multi-provider LLM manager
│   │   └── ransomware_analyzer.py  # Specialized ransomware analyzer
├── utils/                     # Common utilities and helper functions
└── docs/                      # Documentation and technical guides
```

## Installation

### Prerequisites

- Python 3.9 or higher
- Required Python packages (see `requirements.txt`)
- Optional: Memory analysis tools (Volatility)

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/sgInnora/innora-defender.git
   cd innora-defender
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Universal Streaming Engine

Our high-performance streaming engine with enhanced error handling provides efficient file decryption:

```python
from decryption_tools.streaming_engine import StreamingDecryptor

# Initialize the streaming decryptor
decryptor = StreamingDecryptor()

# Decrypt a single file
result = decryptor.decrypt_file(
    input_file="path/to/encrypted_file",
    output_file="path/to/decrypted_file",
    algorithm="aes-cbc",
    key=key_bytes,
    iv=iv_bytes,
    header_size=16  # Optional: skip header bytes
)

if result["success"]:
    print("File successfully decrypted")
else:
    print(f"Decryption failed: {result.get('error')}")

# Batch decrypt multiple files with enhanced parallel processing
file_mappings = [
    {"input": "file1.enc", "output": "file1.dec"},
    {"input": "file2.enc", "output": "file2.dec"},
    {"input": "file3.enc", "output": "file3.dec"}
]

# Define a progress callback for real-time updates
def progress_callback(stats):
    print(f"Progress: {stats['current_progress']*100:.1f}% | "
          f"Completed: {stats['completed_files']}/{stats['total_files']} | "
          f"Success: {stats['successful_files']} | Errors: {stats['failed_files']}")

batch_result = decryptor.batch_decrypt(
    file_mappings=file_mappings,
    algorithm="aes-cbc",
    key=key_bytes,
    batch_params={
        "parallel_execution": True,        # Enable parallel processing
        "max_workers": 8,                  # Number of worker threads
        "auto_detect_algorithm": True,     # Try to detect algorithm if specified one fails
        "retry_count": 3,                  # Retry failed files
        "include_error_patterns": True,    # Analyze error patterns
        "progress_callback": progress_callback,  # Real-time progress updates
        "save_summary": True,
        "summary_file": "batch_summary.json"
    }
)

print(f"Processed {batch_result['total_files']} files")
print(f"Successfully decrypted: {batch_result['successful_files']}")
print(f"Failed to decrypt: {batch_result['failed_files']}")

# Access error patterns for insights
if "error_patterns" in batch_result and batch_result["error_patterns"]:
    print("\nError Patterns Detected:")
    for pattern, details in batch_result["error_patterns"].items():
        print(f"- {pattern}: {details['count']} files")
        if "recommendation" in details:
            print(f"  Recommendation: {details['recommendation']}")
```

### Command-Line Batch Decryption

The enhanced batch decryption tool provides a powerful command-line interface with real-time progress visualization and comprehensive error reporting:

```bash
# Process all encrypted files in a directory
./batch_decrypt.py --input-dir /path/to/encrypted/files --output-dir /path/to/output --algorithm aes-cbc --key 0123456789abcdef

# Auto-detect algorithm with parallel processing (8 threads)
./batch_decrypt.py --input-dir /path/to/encrypted/files --output-dir /path/to/output \
    --auto-detect --parallel --threads 8 --key-file /path/to/key.bin

# Process files from a list with detailed summary and error pattern analysis
./batch_decrypt.py --file-list files.txt --algorithm aes-cbc --key-file key.bin \
    --summary-file report.json --max-retries 3

# Process only files with specific extensions
./batch_decrypt.py --input-dir /path/to/encrypted/files --output-dir /path/to/output \
    --algorithm xor --key DEADBEEF --extensions .enc,.locked,.crypted

# Advanced decryption with initialization vector in file
./batch_decrypt.py --input-dir /path/to/encrypted/files --output-dir /path/to/output \
    --algorithm aes-cbc --key-file key.bin --iv-in-file --iv-offset 16 --iv-size 16 --header-size 32
```

The tool provides real-time progress visualization:

```
[█████████████████████████████████-----------] 75.0% | 15/20 files | ✓ 13 | ✗ 2
```

And generates comprehensive summary reports with error pattern analysis and recommendations.

### LockBit Decryption

```python
from decryption_tools.network_forensics.lockbit_optimized_recovery import OptimizedLockBitRecovery

# Initialize the optimized LockBit recovery module
recovery = OptimizedLockBitRecovery()

# Decrypt a single encrypted file
success = recovery.decrypt_file(
    encrypted_file="path/to/encrypted_file.docx.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}",
    output_file="path/to/recovered_file.docx"
)

if success:
    print("File successfully decrypted")

# Batch decrypt multiple files
results = recovery.batch_decrypt(
    encrypted_files=["file1.xlsx.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}", "file2.pdf.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}"],
    output_dir="recovered_files"
)

# Export successful keys for future use
recovery.export_successful_keys("lockbit_successful_keys.json")
```

### Multi-Ransomware Recovery

```python
from decryption_tools.multi_ransomware_recovery import MultiRecoveryOrchestrator

# Initialize the recovery orchestrator
recovery = MultiRecoveryOrchestrator()

# Attempt to decrypt a file (automatic ransomware family detection)
result = recovery.decrypt_file(
    encrypted_file="path/to/encrypted_file",
    output_file="path/to/recovered_file"
)

print(f"Decryption success: {result['success']}")
print(f"Ransomware family: {result['family']}")
print(f"Method used: {result['method']}")
```

### Memory-Based Key Extraction

```python
from tools.memory.key_extractors.advanced_memory_key_extractor import AdvancedMemoryKeyExtractor

# Initialize the advanced memory key extractor
extractor = AdvancedMemoryKeyExtractor()

# Extract encryption keys from memory dump with ransomware family hint
keys = extractor.scan_memory_dump(
    memory_path="path/to/memory.dmp",
    ransomware_family="lockbit"  # Optional family hint
)

for key in keys:
    print(f"Found key: {key['data'].hex()[:16]}... (confidence: {key['confidence']:.2f})")
    print(f"Algorithm: {key['algorithm']}, Offset: {key['offset']}")
```

### Binary Analysis

```python
from tools.static.binary_analyzer import RansomwareBinaryAnalyzer

# Initialize the binary analyzer
analyzer = RansomwareBinaryAnalyzer()

# Analyze a ransomware binary
results = analyzer.analyze_binary("path/to/ransomware_sample")

# Print analysis results
print(f"Detected algorithms: {results['static_analysis']['crypto']['detected_algorithms']}")
print(f"Weaknesses found: {len(results['weaknesses'])}")
print(f"Potential keys: {len(results['potential_keys'])}")
```

### LLM-Powered Ransomware Analysis

```python
from ai_detection.llm_service import RansomwareAnalyzer

# Initialize the LLM-based analyzer
analyzer = RansomwareAnalyzer()

# Analyze a ransomware sample (optionally with upstream results)
result = analyzer.analyze(
    sample_path="path/to/ransomware_sample.bin",
    upstream_results={  # Optional: results from other detection systems
        "family": "LockBit",
        "confidence": 0.75,
        "key_features": ["Registry modifications", "Command and control traffic"]
    }
)

# Access analysis results
print(f"LLM-detected family: {result['llm_family']}")
print(f"Confidence score: {result['confidence']}")
print(f"Variant details: {result['variant_details']}")

# Access potential weaknesses identified by the LLM
for weakness in result.get("potential_weaknesses", []):
    print(f"Potential weakness: {weakness['description']}")
    print(f"Exploitation difficulty: {weakness['difficulty']}")
    print(f"Recommended approach: {weakness['approach']}")
```

You can also use the command-line interface:

```bash
# Analyze a ransomware sample with detailed output
python -m ai_detection.llm_service.cli analyze --sample path/to/ransomware.bin --detail high

# Batch analyze multiple samples
python -m ai_detection.llm_service.cli batch --input samples.json --output results.json

# View cost and usage statistics
python -m ai_detection.llm_service.cli stats
```

## Documentation

For detailed documentation, see the `docs/` directory:

### Decryption Documentation
- [Universal Streaming Engine Batch Processing](docs/UNIVERSAL_STREAMING_ENGINE_BATCH_PROCESSING.md) - Advanced batch decryption capabilities
- [Enhanced Error Pattern Detection](docs/ENHANCED_ERROR_PATTERN_DETECTION.md) - AI-powered error analysis and recommendation system
- [Streaming Engine Error Handling](tests/SUMMARY_OF_ERROR_HANDLING_IMPROVEMENTS_UPDATED.md) - Comprehensive error handling improvements
- [Batch Processing Summary](tests/STREAMING_ENGINE_BATCH_PROCESSING_SUMMARY.md) - Summary of batch processing enhancements
- [LockBit Decryption Optimization](docs/LOCKBIT_DECRYPTION_OPTIMIZATION.md) - Details on our industry-leading LockBit recovery
- [Enhanced Decryption Capabilities Plan](docs/DECRYPTION_CAPABILITIES_PLAN.md) - Roadmap for multi-family decryption support
- [Future Development Plan](docs/FUTURE_DEVELOPMENT_PLAN_UPDATED.md) - Updated plan focusing on decryption capabilities

### Technical Documentation
- [Ransomware Relationship Graph](docs/RANSOMWARE_RELATIONSHIP_GRAPH.md) - Visualizing connections between ransomware families
- [Implementation Summary](docs/IMPLEMENTATION_SUMMARY.md) - Technical overview of the project
- [Project Overview](docs/PROJECT_OVERVIEW.md) - Architecture and design principles
- [LLM Service Optimization](docs/LLM_SERVICE_OPTIMIZATION.md) - Cost-efficient LLM integration for ransomware analysis

### Machine Learning Documentation
- [Machine Learning Enhancement](docs/MACHINE_LEARNING_ENHANCEMENT.md) - AI-based detection capabilities
- [ML Enhancement Update Log](docs/MACHINE_LEARNING_ENHANCEMENT_UPDATE_LOG.md) - History of ML improvements

## Testing and Quality Assurance

We maintain strict quality standards for our code, especially for security-critical components:

### Coverage Requirements and Status

- **Security-Critical Modules**: Minimum 95% test coverage
  - ✅ YARA Enhanced Generator: 95% coverage
  - ✅ LockBit Optimized Recovery: 96% coverage
  - ✅ No More Ransom Integration: 95% coverage
  - ✅ Universal Streaming Engine Batch Processing: 95% coverage
  - ⚠️ YARA Integration: 87% coverage (in progress)
  - ⚠️ YARA CLI: 78% coverage (in progress)
- **Core Components**: Minimum 90% test coverage
- **Utility Modules**: Minimum 80% test coverage

### Running Tests

```bash
# Run all tests
python tests/run_all_tests.py

# Run YARA tests with coverage measurement
python tests/run_yara_tests.py

# Run No More Ransom tests with custom tracer
tests/run_nomoreransom_tests.sh --coverage --report

# Test specific modules with different testing modes
tests/run_nomoreransom_tests.sh --mode comprehensive
tests/run_nomoreransom_tests.sh --mode integration

# Run enhanced tests for specific modules
python tests/run_enhanced_tests.py --module lockbit
python tests/run_enhanced_tests.py --module yara
python tests/measure_streaming_engine_coverage.py

# Test batch processing functionality
python -m tests.test_batch_decrypt_cli
python -m tests.test_streaming_engine_batch_processing

# Verify coverage for security-critical modules
tests/check_security_coverage.sh
```

### Advanced Testing Framework

We've implemented an advanced testing framework for complex modules with platform-specific behavior, which includes:

1. **Custom Code Execution Tracing** - Tracks execution of code paths that standard coverage tools miss
2. **Multi-Platform Testing** - Tests platform-specific code via environment simulation
3. **Edge Case Detection** - Specialized tests for boundary conditions and error handling
4. **Comprehensive Reporting** - Detailed coverage analysis with both standard and custom metrics

For more details on our advanced testing approach, see:
- [No More Ransom Testing Guide](tests/NOMORERANSOM_TESTING_README.md)
- [Direct NoMoreRansom Executor Coverage](tests/DIRECT_NOMORERANSOM_EXECUTOR_COVERAGE.md)
- [No More Ransom Coverage Summary](tests/NOMORERANSOM_COVERAGE_SUMMARY.md)

### Test Coverage Visualization

Our comprehensive test suite includes performance measurements for critical operations:

```
Large file analysis: 0.50 seconds
Entropy calculation: 0.20 seconds for 1,049,397 bytes
String feature extraction: 0.03 seconds for large files
Rule optimization: < 0.01 seconds for 1,000 features
```

### Setting Up Git Hooks

We provide Git hooks to ensure code quality before commits:

```bash
# Install Git hooks
./install_git_hooks.sh
```

This will install a pre-commit hook that checks coverage for security-critical modules before allowing commits.

For more information on our testing approach, see:
- [Maintaining Test Coverage](docs/MAINTAINING_TEST_COVERAGE.md)
- [Test Coverage Report](test_coverage_report.md)
- [YARA Coverage Improvements](tests/FINAL_COVERAGE_REPORT.md)
- [Test Coverage Improvement Plan](tests/TEST_COVERAGE_IMPROVEMENT_PLAN.md)

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

If you discover any security-related issues, please email info@innora.ai instead of using the issue tracker.

---

© 2025 Innora-Sentinel安全团队 | All Rights Reserved | [https://innora.ai](https://innora.ai)