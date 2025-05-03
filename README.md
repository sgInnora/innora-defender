# Innora-Defender: Ransomware Detection & Recovery Module

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

**Innora-Defender** is a comprehensive ransomware detection, analysis, and recovery module that serves as a core component of the Innora-Sentinel cybersecurity platform. The system provides advanced capabilities for identifying, analyzing, and responding to ransomware threats through a combination of static analysis, dynamic execution, memory forensics, and network traffic monitoring.

### Key Features

- **Automated Ransomware Analysis**: End-to-end workflow for analyzing suspected ransomware samples
- **Family Detection Engine**: Identifies specific ransomware families with high accuracy
- **Advanced File Recovery**: Specialized tools for recovering encrypted files from known ransomware families
- **Memory Forensics**: Extracts encryption keys and artifacts from memory dumps
- **Network Key Recovery**: Analyzes network traffic to capture encryption keys and command-and-control communications
- **AI-Enhanced Detection**: Machine learning and LLM-based models with 97% accuracy for ransomware detection
- **Two-Stage Detection System**: Combines traditional ML with LLM-based analysis for comprehensive detection
- **Multimodal Fusion**: Integrates static, dynamic, and network features with attention mechanisms
- **Incremental Learning**: Automatically adapts to new ransomware variants and strategies
- **Threat Intelligence Integration**: Correlates findings with external threat intelligence sources
- **YARA Rule Generation**: Automatically generates detection rules based on analysis results
- **Ransomware Relationship Visualization**: Displays connections between different ransomware families and variants

## Project Structure

```
innora-defender/
├── ai_detection/              # Machine learning models for ransomware detection
├── behavior_analysis/         # Dynamic analysis of ransomware behavior
├── decryption_tools/          # Tools for encrypted file recovery
├── memory_analysis/           # Memory forensics for key extraction
├── sandboxes/                 # Isolated environments for sample execution
├── threat_intel/              # Threat intelligence integration components
├── tools/                     # Utility tools for various analysis functions
├── utils/                     # Common utilities and helper functions
└── docs/                      # Documentation and technical guides
```

## Installation

### Prerequisites

- Python 3.9 or higher
- Required Python packages (see `requirements.txt`)
- Optional: Docker for containerized execution

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

3. Configure the system:
   ```bash
   python -m setup.configure
   ```

## Usage

### Basic Analysis

```python
from innora_defender import RansomwareAnalyzer

# Initialize the analyzer
analyzer = RansomwareAnalyzer()

# Analyze a suspicious file
results = analyzer.analyze_file("path/to/suspicious_file")

# Print analysis results
print(f"Ransomware Family: {results.family}")
print(f"Detection Confidence: {results.confidence}%")
print(f"Encryption Algorithm: {results.encryption_algorithm}")
```

### Decryption Attempt

```python
from innora_defender import RecoveryEngine

# Initialize the recovery engine
recovery = RecoveryEngine()

# Attempt to decrypt a file
success = recovery.attempt_decryption(
    encrypted_file="path/to/encrypted_file",
    output_file="path/to/recovered_file"
)

if success:
    print("File successfully recovered")
else:
    print("Recovery failed")
```

### Memory Analysis

```python
from innora_defender import MemoryAnalyzer

# Initialize memory analyzer
memory = MemoryAnalyzer()

# Extract encryption keys from memory dump
keys = memory.extract_keys("path/to/memory.dmp")

print(f"Found {len(keys)} potential encryption keys")
```

## Integration with Innora-Sentinel

Innora-Defender is designed to integrate seamlessly with the Innora-Sentinel cybersecurity platform:

- **API Integration**: Connect through the Sentinel API for automated analysis
- **Shared Threat Intelligence**: Contribute to and benefit from the central threat intelligence database
- **Coordinated Response**: Trigger automated response actions through the Sentinel orchestration engine
- **Unified Reporting**: Integrated reporting within the Sentinel dashboard

## Documentation

For detailed documentation, see the `docs/` directory:
- [Technical Architecture](docs/PROJECT_OVERVIEW.md)
- [API Reference](docs/IMPLEMENTATION_SUMMARY.md)
- [Development Guide](docs/FUTURE_DEVELOPMENT_PLAN.md)
- [Machine Learning Enhancement](docs/MACHINE_LEARNING_ENHANCEMENT.md)
- [ML Enhancement Update Log](docs/MACHINE_LEARNING_ENHANCEMENT_UPDATE_LOG.md)
- [LockBit Analysis Case Study](docs/LOCKBIT_DECRYPTION_OPTIMIZATION.md)

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- This project incorporates components from various open-source ransomware analysis tools
- Special thanks to the research teams who have published their findings on ransomware techniques

## Security

If you discover any security-related issues, please email info@innora.ai instead of using the issue tracker.

---

© 2025 Innora-Sentinel安全团队 | All Rights Reserved | [https://innora.ai](https://innora.ai)