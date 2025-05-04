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

## Project Structure

```
innora-defender/
├── decryption_tools/          # Ransomware-specific decryption tools
├── tools/                     # Analysis and recovery utilities
│   ├── crypto/                # Cryptographic analysis tools
│   ├── memory/                # Memory forensics for key extraction
│   ├── static/                # Binary analysis tools
├── threat_intel/              # Ransomware family information
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

## Documentation

For detailed documentation, see the `docs/` directory:

### Decryption Documentation
- [LockBit Decryption Optimization](docs/LOCKBIT_DECRYPTION_OPTIMIZATION.md) - Details on our industry-leading LockBit recovery
- [Enhanced Decryption Capabilities Plan](docs/DECRYPTION_CAPABILITIES_PLAN.md) - Roadmap for multi-family decryption support
- [Future Development Plan](docs/FUTURE_DEVELOPMENT_PLAN_UPDATED.md) - Updated plan focusing on decryption capabilities

### Technical Documentation
- [Ransomware Relationship Graph](docs/RANSOMWARE_RELATIONSHIP_GRAPH.md) - Visualizing connections between ransomware families
- [Implementation Summary](docs/IMPLEMENTATION_SUMMARY.md) - Technical overview of the project
- [Project Overview](docs/PROJECT_OVERVIEW.md) - Architecture and design principles

### Machine Learning Documentation
- [Machine Learning Enhancement](docs/MACHINE_LEARNING_ENHANCEMENT.md) - AI-based detection capabilities
- [ML Enhancement Update Log](docs/MACHINE_LEARNING_ENHANCEMENT_UPDATE_LOG.md) - History of ML improvements

## Testing and Quality Assurance

We maintain strict quality standards for our code, especially for security-critical components:

### Coverage Requirements and Status

- **Security-Critical Modules**: Minimum 95% test coverage
  - ✅ YARA Enhanced Generator: 95% coverage
  - ✅ LockBit Optimized Recovery: 96% coverage
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

# Run enhanced tests for specific modules
python tests/run_enhanced_tests.py --module lockbit
python tests/run_enhanced_tests.py --module yara

# Verify coverage for security-critical modules
tests/check_security_coverage.sh
```

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