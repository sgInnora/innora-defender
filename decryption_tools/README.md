# Ransomware Recovery and Analysis Toolkit

This toolkit provides comprehensive ransomware analysis and recovery capabilities by integrating publicly available decryption tools with advanced analysis techniques.

## Overview

The Ransomware Recovery and Analysis Toolkit includes:

1. **Encryption Analysis**: Identifies ransomware families and encryption methods used in encrypted files
2. **Decryption Tool Integration**: Automatically downloads and integrates public decryption tools
3. **Memory Analysis**: Extracts potential encryption keys from memory dumps
4. **File Recovery**: Attempts to decrypt files using appropriate tools

## Components

### Core Components

- **`ransomware_recovery.py`**: Main interface for all toolkit functions
- **`external/encryption_analyzer.py`**: Analyzes encrypted files to identify ransomware families
- **`external/tool_registry.py`**: Manages publicly available decryption tools
- **`external/tool_wrapper.py`**: Provides standardized interface for using decryption tools
- **`key_testers/key_validator.py`**: Tests potential encryption keys for validity
- **`file_recovery/decrypt_test.py`**: Tests decryption of files with various algorithms and keys

### Data Sources

- **`external/data/families/`**: Detailed information about ransomware families and their encryption methods

## Usage

### Analyzing an Encrypted File

```bash
./ransomware_recovery.py analyze path/to/encrypted_file.ext --report report.txt
```

### Scanning for Encrypted Files

```bash
./ransomware_recovery.py scan /path/to/directory
```

### Decrypting a File

```bash
./ransomware_recovery.py decrypt path/to/encrypted_file.ext --auto
```

Or with a specific tool:

```bash
./ransomware_recovery.py decrypt path/to/encrypted_file.ext --tool emsisoft_decryptor --family "STOP"
```

### Managing Decryption Tools

List available tools:
```bash
./ransomware_recovery.py tools --list
```

List tools for a specific ransomware family:
```bash
./ransomware_recovery.py tools --list --family WannaCry
```

Install a tool:
```bash
./ransomware_recovery.py tools --install emsisoft_decryptor
```

Update the tool database:
```bash
./ransomware_recovery.py tools --update
```

## Supported Ransomware Families

The toolkit can identify and potentially help recover files from various ransomware families, including:

- WannaCry
- STOP/DJVU
- Ryuk
- REvil (Sodinokibi)
- LockBit
- BlackCat (ALPHV)
- Conti
- Hive
- AvosLocker
- Many more...

## External Tool Integration

The toolkit integrates with public decryption tools from:

- Emsisoft
- Kaspersky
- Trend Micro
- Avast
- NoMoreRansom project
- McAfee
- European law enforcement agencies

## Disclaimer

This toolkit is for cybersecurity research and legitimate file recovery purposes only. It cannot guarantee recovery of files encrypted by ransomware, particularly newer variants with properly implemented encryption.

Always consult with cybersecurity professionals for critical ransomware incidents, and consider reporting incidents to appropriate law enforcement agencies.

## Requirements

- Python 3.6+
- Internet connection for tool downloads
- Administrator/root privileges for memory analysis

## License

© 2025 Innora-Sentinel安全团队 | All Rights Reserved | [https://innora.ai](https://innora.ai)