# Memory Analysis Tools for Ransomware

A comprehensive toolkit for analyzing memory dumps and running processes to detect ransomware artifacts, extract encryption keys, and generate intelligence reports.

## Overview

This toolkit provides advanced memory analysis capabilities specialized for ransomware detection and investigation. It includes:

- **Pattern-based scanning** for encryption keys and algorithms
- **Crypto pattern matching** for ransomware-specific artifacts
- **YARA rule scanning** for known ransomware families
- **Threat intelligence integration** to enrich findings
- **MITRE ATT&CK mapping** for detected techniques
- **Recovery recommendations** based on analysis results

## Components

### Core Scanners

- **YARA Memory Scanner** (`scanners/yara_mem_scanner.py`): Scans memory for matches to YARA rules
- **Pattern Key Scanner** (`scanners/pattern_key_scanner.py`): Identifies encryption keys based on patterns and entropy
- **Crypto Pattern Matcher** (`scanners/crypto_pattern_matcher.py`): Detects cryptographic artifacts and ransomware patterns

### Integration Components

- **Memory Scanner Orchestrator** (`scanners/memory_scanner_orchestrator.py`): Coordinates multiple scanners and integrates results
- **Memory Threat Intel Integrator** (`scanners/memory_threat_intel_integrator.py`): Enriches findings with threat intelligence

### Main Interface

- **Memory Analysis Engine** (`analyze_memory.py`): Unified command-line interface for all analysis capabilities

## Usage

### Analyzing a Memory Dump

```bash
./analyze_memory.py analyze <dump_file> [options]
```

Options:
- `--output-dir`, `-o`: Directory to save results (default: results)
- `--report`, `-r`: Generate human-readable report
- `--generate-yara`, `-y`: Generate YARA rules from findings
- `--check-family FAMILY`: Check for a specific ransomware family
- `--extract-keys`, `-k`: Extract potential encryption keys
- `--no-threat-intel`: Skip threat intelligence integration
- `--scanner-weights`: Adjust scanner weights (e.g., 'yara:1.0,pattern:0.8')

### Analyzing a Running Process

```bash
./analyze_memory.py process <pid> [options]
```

Options:
- `--output-dir`, `-o`: Directory to save results (default: results)
- `--report`, `-r`: Generate human-readable report
- `--dump`, `-d`: Dump process memory before analysis
- `--generate-yara`, `-y`: Generate YARA rules from findings
- `--check-family FAMILY`: Check for a specific ransomware family
- `--extract-keys`, `-k`: Extract potential encryption keys
- `--no-threat-intel`: Skip threat intelligence integration

### Generating a Report from Results

```bash
./analyze_memory.py report <results_file> [--output OUTPUT]
```

### Getting Help

```bash
./analyze_memory.py help
```

## Examples

1. Analyze a memory dump with all default options:
   ```bash
   ./analyze_memory.py analyze memory_dump.dmp
   ```

2. Analyze a process, dump its memory, and generate a report:
   ```bash
   ./analyze_memory.py process 1234 --dump --report
   ```

3. Analyze a memory dump and check for a specific ransomware family:
   ```bash
   ./analyze_memory.py analyze memory_dump.dmp --check-family WannaCry
   ```

4. Generate a report from existing analysis results:
   ```bash
   ./analyze_memory.py report results/mem_scan_20250502_123456.json
   ```

## Supported Ransomware Families

The toolkit includes built-in detection for many ransomware families, including:

- WannaCry
- Ryuk
- REvil (Sodinokibi)
- LockBit (1.0, 2.0, 3.0/Black)
- BlackCat (ALPHV)
- Conti
- BlackBasta
- Hive
- AvosLocker
- Vice Society
- Cl0p

## Encryption Algorithms

The toolkit can detect and extract keys for common encryption algorithms:

- AES (128, 192, 256 bit)
- RSA
- ChaCha20/Salsa20
- RC4
- DES

## Requirements

- Python 3.7+
- Optional: YARA Python module for YARA scanning
- Platform-specific requirements for process memory dumping

## License

© 2025 Innora-Sentinel安全团队 | All Rights Reserved | [https://innora.ai](https://innora.ai)