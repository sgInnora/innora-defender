# Innora-Defender: API Reference

**English** | [中文](./IMPLEMENTATION_SUMMARY_CN.md)

## Introduction

This document provides a comprehensive API reference for Innora-Defender, the ransomware detection and recovery module of the Innora-Sentinel cybersecurity platform. It covers the core modules, their interfaces, and usage examples.

## Core Modules

### 1. Ransomware Analyzer

The `RansomwareAnalyzer` class is the main entry point for analyzing suspicious files and identifying ransomware characteristics.

#### Key Classes and Methods

```python
class RansomwareAnalyzer:
    def __init__(self, config=None):
        """
        Initialize the analyzer with optional configuration.
        
        Parameters:
        - config (dict, optional): Configuration options including:
          - use_ai (bool): Whether to use AI-enhanced detection
          - sandbox_type (str): Type of sandbox to use ('docker', 'vm', 'emulation')
          - memory_analysis (bool): Whether to perform memory analysis
          - network_analysis (bool): Whether to analyze network traffic
        """
        pass
        
    def analyze_file(self, file_path, detailed=False):
        """
        Analyze a suspicious file for ransomware characteristics.
        
        Parameters:
        - file_path (str): Path to the file to analyze
        - detailed (bool): Whether to perform detailed analysis
        
        Returns:
        - AnalysisResult: Object containing analysis results
        """
        pass
        
    def analyze_directory(self, directory_path, recursive=True, file_types=None):
        """
        Analyze all files in a directory for ransomware characteristics.
        
        Parameters:
        - directory_path (str): Path to the directory
        - recursive (bool): Whether to analyze subdirectories
        - file_types (list): List of file extensions to analyze
        
        Returns:
        - list: List of AnalysisResult objects
        """
        pass
        
    def detect_family(self, file_path):
        """
        Identify the ransomware family of a file.
        
        Parameters:
        - file_path (str): Path to the file
        
        Returns:
        - tuple: (family_name, confidence_score)
        """
        pass
```

#### Usage Example

```python
from innora_defender import RansomwareAnalyzer

# Initialize with default configuration
analyzer = RansomwareAnalyzer()

# Analyze a suspicious file
result = analyzer.analyze_file("/path/to/suspicious_file.exe")

print(f"Ransomware detection: {result.is_ransomware}")
print(f"Family: {result.family} (Confidence: {result.confidence}%)")
print(f"Encryption algorithm: {result.encryption_algorithm}")
print(f"Behavior summary: {result.behavior_summary}")

# Get detailed information about the ransomware family
if result.is_ransomware and result.family:
    family_info = analyzer.get_family_info(result.family)
    print(f"Family description: {family_info.description}")
    print(f"Known encryption methods: {family_info.encryption_methods}")
    print(f"Recovery potential: {family_info.recovery_potential}/10")
```

### 2. Recovery Engine

The `RecoveryEngine` provides functionality for recovering files encrypted by ransomware.

#### Key Classes and Methods

```python
class RecoveryEngine:
    def __init__(self, config=None):
        """
        Initialize the recovery engine with optional configuration.
        
        Parameters:
        - config (dict, optional): Configuration options including:
          - use_memory_analysis (bool): Whether to use memory analysis for key recovery
          - use_network_forensics (bool): Whether to use network traffic analysis
          - brute_force_level (int): Intensity level for brute force attempts (0-3)
        """
        pass
        
    def attempt_decryption(self, encrypted_file, output_file=None, family=None, key=None):
        """
        Attempt to decrypt a file encrypted by ransomware.
        
        Parameters:
        - encrypted_file (str): Path to the encrypted file
        - output_file (str, optional): Path to save the decrypted file
        - family (str, optional): Ransomware family if known
        - key (str/bytes, optional): Encryption key if known
        
        Returns:
        - bool: Success or failure
        - str: Path to the decrypted file if successful
        """
        pass
        
    def batch_decrypt(self, file_list, output_dir, family=None, key=None):
        """
        Attempt to decrypt multiple files.
        
        Parameters:
        - file_list (list): List of paths to encrypted files
        - output_dir (str): Directory to save decrypted files
        - family (str, optional): Ransomware family if known
        - key (str/bytes, optional): Encryption key if known
        
        Returns:
        - dict: Dictionary mapping file paths to success/failure and output paths
        """
        pass
        
    def extract_keys_from_memory(self, memory_dump):
        """
        Extract encryption keys from a memory dump.
        
        Parameters:
        - memory_dump (str): Path to memory dump file
        
        Returns:
        - list: List of potential encryption keys
        """
        pass
        
    def extract_keys_from_network(self, pcap_file):
        """
        Extract encryption keys from network traffic capture.
        
        Parameters:
        - pcap_file (str): Path to the PCAP file
        
        Returns:
        - list: List of potential encryption keys
        """
        pass
```

#### Usage Example

```python
from innora_defender import RecoveryEngine

# Initialize the recovery engine
recovery = RecoveryEngine()

# Attempt to decrypt a single file
success, output_path = recovery.attempt_decryption(
    encrypted_file="/path/to/encrypted.file",
    output_file="/path/to/recovered.file",
    family="lockbit"  # Optional: specify the ransomware family if known
)

if success:
    print(f"Successfully recovered file to: {output_path}")
else:
    print("Recovery failed")
    
    # Try to extract keys from memory dump
    keys = recovery.extract_keys_from_memory("/path/to/memory.dmp")
    
    if keys:
        print(f"Found {len(keys)} potential keys in memory dump")
        
        # Try each key
        for idx, key in enumerate(keys):
            print(f"Trying key {idx+1}...")
            success, output_path = recovery.attempt_decryption(
                encrypted_file="/path/to/encrypted.file",
                output_file=f"/path/to/recovered_with_key_{idx+1}.file",
                key=key
            )
            
            if success:
                print(f"Key {idx+1} worked! Recovered file to: {output_path}")
                break
```

### 3. Memory Analyzer

The `MemoryAnalyzer` focuses on extracting encryption keys and ransomware artifacts from memory dumps.

#### Key Classes and Methods

```python
class MemoryAnalyzer:
    def __init__(self, config=None):
        """
        Initialize the memory analyzer with optional configuration.
        
        Parameters:
        - config (dict, optional): Configuration options including:
          - volatility_path (str): Path to Volatility framework
          - use_custom_plugins (bool): Whether to use custom plugins
          - temp_dir (str): Directory for temporary files
        """
        pass
        
    def analyze_dump(self, dump_path, ransomware_family=None):
        """
        Analyze a memory dump for ransomware artifacts.
        
        Parameters:
        - dump_path (str): Path to the memory dump file
        - ransomware_family (str, optional): Target ransomware family
        
        Returns:
        - MemoryAnalysisResult: Analysis results
        """
        pass
        
    def extract_keys(self, dump_path, ransomware_family=None, min_entropy=3.5):
        """
        Extract potential encryption keys from a memory dump.
        
        Parameters:
        - dump_path (str): Path to the memory dump file
        - ransomware_family (str, optional): Target ransomware family
        - min_entropy (float): Minimum entropy for key candidates
        
        Returns:
        - list: List of potential encryption keys
        """
        pass
        
    def extract_configuration(self, dump_path, ransomware_family):
        """
        Extract ransomware configuration from a memory dump.
        
        Parameters:
        - dump_path (str): Path to the memory dump file
        - ransomware_family (str): Target ransomware family
        
        Returns:
        - dict: Extracted configuration parameters
        """
        pass
        
    def find_key_schedules(self, dump_path, algorithm="aes"):
        """
        Find encryption key schedules in memory.
        
        Parameters:
        - dump_path (str): Path to the memory dump file
        - algorithm (str): Target encryption algorithm
        
        Returns:
        - list: List of potential key schedule addresses and derived keys
        """
        pass
```

#### Usage Example

```python
from innora_defender import MemoryAnalyzer

# Initialize memory analyzer
memory = MemoryAnalyzer()

# Analyze a memory dump
result = memory.analyze_dump("/path/to/memory.dmp", ransomware_family="lockbit")

print(f"Found {len(result.processes)} suspicious processes")
for proc in result.processes:
    print(f"Process: {proc.name} (PID: {proc.pid})")
    print(f"Matched indicators: {proc.indicators}")

# Extract encryption keys
keys = memory.extract_keys("/path/to/memory.dmp")
print(f"Found {len(keys)} potential encryption keys")

# Extract ransomware configuration
if result.identified_family:
    config = memory.extract_configuration("/path/to/memory.dmp", result.identified_family)
    print("Ransomware Configuration:")
    for key, value in config.items():
        print(f"  {key}: {value}")
```

### 4. YARA Rule Generator

The `YaraGenerator` creates detection rules based on analysis results.

#### Key Classes and Methods

```python
class YaraGenerator:
    def __init__(self, config=None):
        """
        Initialize the YARA rule generator with optional configuration.
        
        Parameters:
        - config (dict, optional): Configuration options including:
          - rule_template_dir (str): Directory containing rule templates
          - output_dir (str): Directory for generated rules
          - metadata_fields (list): Fields to include in rule metadata
        """
        pass
        
    def generate_from_sample(self, sample_path, rule_name=None, author=None):
        """
        Generate a YARA rule from a sample file.
        
        Parameters:
        - sample_path (str): Path to the sample file
        - rule_name (str, optional): Name for the generated rule
        - author (str, optional): Author name for rule metadata
        
        Returns:
        - str: Generated YARA rule content
        - str: Path to saved rule file
        """
        pass
        
    def generate_from_analysis(self, analysis_result, rule_name=None, author=None):
        """
        Generate a YARA rule from analysis results.
        
        Parameters:
        - analysis_result (AnalysisResult): Analysis result object
        - rule_name (str, optional): Name for the generated rule
        - author (str, optional): Author name for rule metadata
        
        Returns:
        - str: Generated YARA rule content
        - str: Path to saved rule file
        """
        pass
        
    def generate_family_ruleset(self, family_name, samples_dir, author=None):
        """
        Generate a comprehensive ruleset for a ransomware family.
        
        Parameters:
        - family_name (str): Name of the ransomware family
        - samples_dir (str): Directory containing family samples
        - author (str, optional): Author name for rule metadata
        
        Returns:
        - list: List of generated rule file paths
        """
        pass
        
    def test_rule(self, rule_path, test_samples_dir):
        """
        Test a YARA rule against a directory of samples.
        
        Parameters:
        - rule_path (str): Path to the YARA rule file
        - test_samples_dir (str): Directory containing test samples
        
        Returns:
        - dict: Dictionary of test results with match statistics
        """
        pass
```

#### Usage Example

```python
from innora_defender import YaraGenerator, RansomwareAnalyzer

# Initialize components
analyzer = RansomwareAnalyzer()
generator = YaraGenerator()

# Analyze a ransomware sample
analysis = analyzer.analyze_file("/path/to/ransomware_sample.exe")

# Generate a YARA rule from analysis results
if analysis.is_ransomware:
    rule_content, rule_path = generator.generate_from_analysis(
        analysis,
        rule_name=f"{analysis.family}_detector",
        author="Innora Security Team"
    )
    
    print(f"Generated YARA rule saved to: {rule_path}")
    print("\nRule preview:")
    print(rule_content[:500] + "..." if len(rule_content) > 500 else rule_content)
    
    # Test the rule against a directory of samples
    test_results = generator.test_rule(rule_path, "/path/to/test_samples")
    
    print("\nRule testing results:")
    print(f"True positives: {test_results['true_positives']}")
    print(f"False positives: {test_results['false_positives']}")
    print(f"True negatives: {test_results['true_negatives']}")
    print(f"False negatives: {test_results['false_negatives']}")
    print(f"Accuracy: {test_results['accuracy']:.2f}%")
```

### 5. Threat Intelligence Integration

The `ThreatIntelligence` class provides integration with external threat intelligence sources.

#### Key Classes and Methods

```python
class ThreatIntelligence:
    def __init__(self, config=None):
        """
        Initialize the threat intelligence module with optional configuration.
        
        Parameters:
        - config (dict, optional): Configuration options including:
          - api_keys (dict): API keys for threat intelligence sources
          - cache_dir (str): Directory for caching threat data
          - cache_timeout (int): Cache timeout in seconds
        """
        pass
        
    def query_sample(self, file_hash, sources=None):
        """
        Query information about a sample by hash.
        
        Parameters:
        - file_hash (str): Hash of the sample (MD5, SHA1, or SHA256)
        - sources (list, optional): List of intelligence sources to query
        
        Returns:
        - dict: Information about the sample from various sources
        """
        pass
        
    def get_family_info(self, family_name, full=False):
        """
        Get information about a ransomware family.
        
        Parameters:
        - family_name (str): Name of the ransomware family
        - full (bool): Whether to include full details
        
        Returns:
        - dict: Information about the ransomware family
        """
        pass
        
    def get_iocs(self, family_name=None, days=30):
        """
        Get indicators of compromise.
        
        Parameters:
        - family_name (str, optional): Filter by ransomware family
        - days (int): Timeframe in days
        
        Returns:
        - list: List of IOC dictionaries
        """
        pass
        
    def submit_sample(self, file_path, platforms=None):
        """
        Submit a sample to threat intelligence platforms.
        
        Parameters:
        - file_path (str): Path to the sample file
        - platforms (list, optional): Platforms to submit to
        
        Returns:
        - dict: Submission status and references
        """
        pass
        
    def correlate_iocs(self, ioc_list, threshold=0.6):
        """
        Correlate a list of IOCs to identify campaigns.
        
        Parameters:
        - ioc_list (list): List of IOCs to correlate
        - threshold (float): Similarity threshold
        
        Returns:
        - list: List of potential campaigns
        """
        pass
```

#### Usage Example

```python
from innora_defender import ThreatIntelligence

# Initialize the threat intelligence module
ti = ThreatIntelligence()

# Query information about a sample
sample_info = ti.query_sample("e5e7c213cf3333c9abcdf2871d896c7a5415b8da")

print("Sample information:")
for source, info in sample_info.items():
    print(f"\nSource: {source}")
    print(f"Detection name: {info.get('detection_name', 'N/A')}")
    print(f"First seen: {info.get('first_seen', 'N/A')}")
    print(f"Last seen: {info.get('last_seen', 'N/A')}")
    print(f"Detection rate: {info.get('detection_rate', 'N/A')}")

# Get information about a ransomware family
family_info = ti.get_family_info("lockbit", full=True)

print("\nRansomware family information:")
print(f"Family: {family_info['name']}")
print(f"Aliases: {', '.join(family_info.get('aliases', []))}")
print(f"First seen: {family_info.get('first_seen', 'N/A')}")
print(f"Active: {family_info.get('active', False)}")
print(f"Encryption algorithms: {', '.join(family_info.get('encryption_algorithms', []))}")
print(f"Ransom note patterns: {', '.join(family_info.get('ransom_note_patterns', []))}")

# Get indicators of compromise
iocs = ti.get_iocs(family_name="lockbit", days=30)

print(f"\nFound {len(iocs)} recent IOCs for LockBit:")
for idx, ioc in enumerate(iocs[:5]):  # Show first 5 IOCs
    print(f"IOC {idx+1}: {ioc['value']} ({ioc['type']})")
```

## Integration with Innora-Sentinel

### API Interface

To integrate Innora-Defender with the Innora-Sentinel platform, use the `SentinelConnector` class:

```python
from innora_defender import SentinelConnector

# Initialize the connector
connector = SentinelConnector(
    api_url="https://sentinel.innora.com/api/v1",
    api_key="your_api_key_here"
)

# Register the module with Sentinel
connector.register()

# Send analysis results to Sentinel
analysis_result = analyzer.analyze_file("/path/to/sample.exe")
connector.send_analysis_result(analysis_result)

# Retrieve tasks from Sentinel
tasks = connector.get_pending_tasks()
for task in tasks:
    print(f"Processing task {task['id']}: {task['type']}")
    
    if task['type'] == 'analyze_file':
        # Download the file
        file_path = connector.download_file(task['file_id'])
        
        # Analyze the file
        result = analyzer.analyze_file(file_path)
        
        # Send results back
        connector.update_task(task['id'], status='completed', result=result)
```

## Error Handling

All API methods in Innora-Defender follow consistent error handling patterns using custom exceptions:

```python
from innora_defender.exceptions import (
    AnalysisError,
    RecoveryError,
    MemoryAnalysisError,
    ThreatIntelError,
    ConfigurationError
)

try:
    result = analyzer.analyze_file("/path/to/file.exe")
except AnalysisError as e:
    print(f"Analysis failed: {e}")
    # Handle the error appropriately

try:
    success = recovery.attempt_decryption(
        encrypted_file="/path/to/encrypted.file",
        output_file="/path/to/output.file"
    )
except RecoveryError as e:
    print(f"Recovery failed: {e}")
    # Handle the error appropriately
```

## Logging

Innora-Defender provides extensive logging capabilities:

```python
import logging
from innora_defender import configure_logging

# Configure logging
configure_logging(
    log_file="/path/to/innora_defender.log",
    log_level=logging.INFO,
    rotation="daily",
    max_size_mb=100
)

# Logs will now be captured to the specified file
analyzer = RansomwareAnalyzer()
analyzer.analyze_file("/path/to/sample.exe")
```

## Testing

Innora-Defender has a comprehensive test framework to ensure functionality and reliability:

```python
# Run all tests
python -m unittest discover -s tests

# Run specific test suite
python -m unittest tests.test_lockbit_optimized_recovery

# Generate coverage report
python -m coverage run --source=decryption_tools.network_forensics.lockbit_optimized_recovery tests/test_lockbit_optimized_recovery.py
python -m coverage report
```

### Test Coverage

The project maintains high test coverage across critical components:

| Component | Coverage |
|-----------|----------|
| lockbit_optimized_recovery.py | 83% |
| threat_intel modules | 78% |
| memory_analysis modules | 75% |
| ai_detection modules | 80% |

### Test Framework Features

- **Unit Tests**: Testing individual components and functions
- **Integration Tests**: Testing interactions between modules
- **Mock Testing**: Testing with simulated dependencies
- **Test Mode**: Special testing mode flags for reliable test execution
- **Parameterized Tests**: Data-driven tests for multiple scenarios
- **Edge Case Testing**: Tests for boundary conditions and error handling
- **Performance Testing**: Tests to ensure optimization goals are met

## Configuration

Global configuration can be managed through the `Config` class:

```python
from innora_defender import Config

# Load configuration
config = Config.load_from_file("/path/to/config.json")

# Access configuration values
print(f"Using AI detection: {config.get('use_ai', True)}")
print(f"Sandbox type: {config.get('sandbox_type', 'docker')}")

# Update configuration
config.set('use_network_analysis', True)
config.set('api_keys.virustotal', 'your_api_key_here')

# Save configuration
config.save_to_file("/path/to/config.json")

# Initialize components with configuration
analyzer = RansomwareAnalyzer(config=config)
recovery = RecoveryEngine(config=config)
```

---

© 2025 Innora-Sentinel安全团队 | All Rights Reserved | [https://innora.ai](https://innora.ai)