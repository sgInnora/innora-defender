# Enhanced YARA Rule Generator for Ransomware Detection

This module provides an advanced YARA rule generation system specifically designed for ransomware detection. It combines multiple feature extraction approaches to create highly effective YARA signatures with low false positive rates.

## Key Features

- **Multi-feature extraction** from various file types (PE, ELF, scripts)
- **Advanced entropy analysis** for detecting encrypted content
- **Code pattern detection** for identifying encryption routines
- **Contextual string analysis** for better detection of ransomware indicators
- **Modular architecture** with pluggable feature extractors
- **Automatic rule optimization** to reduce false positives
- **Integration with existing threat intelligence infrastructure**
- **Standalone CLI** for easy usage

## Components

The enhanced YARA generator consists of the following components:

1. **enhanced_yara_generator.py** - Core implementation of the enhanced YARA rule generator
2. **integration.py** - Integration with the existing threat intelligence infrastructure
3. **yara_cli.py** - Command-line interface for using the enhanced generator

## Feature Extractors

The enhanced generator uses a modular approach with specialized feature extractors:

- **StringFeatureExtractor** - Extracts string features with contextual awareness
- **OpcodeFeatureExtractor** - Extracts code patterns from executable files
- **BytePatternExtractor** - Extracts byte patterns with entropy analysis
- **ScriptFeatureExtractor** - Extracts features from script files (JS, VBS, PowerShell, BAT)

## Usage

### Command-Line Interface

The enhanced YARA generator can be used directly via the `yara_cli.py` script:

```bash
# Analyze a single sample
python yara_cli.py analyze --file /path/to/sample.exe --family Locky

# Analyze a directory of samples
python yara_cli.py analyze-dir --directory /path/to/samples --family Locky

# Test a rule against samples
python yara_cli.py test --rule /path/to/rule.yar --directory /path/to/samples
```

### API Usage

The enhanced YARA generator can also be used programmatically:

```python
from utils.yara_enhanced.enhanced_yara_generator import EnhancedYaraGenerator

# Create a generator
generator = EnhancedYaraGenerator(output_dir='/path/to/output')

# Analyze a sample
result = generator.analyze_sample(
    file_path='/path/to/sample.exe',
    family='Locky',
    generate_rule=True
)

# Generate a rule for a family
rule = generator.generate_rule_for_family('Locky')

# Save all rules as a combined ruleset
generator.save_combined_ruleset('ransomware_rules.yar')
```

### Integration with Threat Intelligence

The enhanced generator can be used as a drop-in replacement for the existing YARA generators:

```python
from utils.yara_enhanced.integration import EnhancedYaraIntegration

# Create integration
integration = EnhancedYaraIntegration(output_dir='/path/to/output')

# Generate rule from sample data
rule_path = integration.generate_yara_rule(sample_data, correlation_result)

# Generate family rule from multiple samples
family_rule_path = integration.generate_family_rule(samples)
```

## Advantages Over Previous Implementations

The enhanced YARA generator offers several advantages over the previous implementations:

1. **Better feature extraction** - Uses multiple specialized extractors for different file types
2. **Improved entropy analysis** - More accurate detection of encrypted content
3. **Advanced code pattern detection** - Identifies encryption routines in executables
4. **Better string selection** - Uses contextual awareness to select relevant strings
5. **Automatic rule optimization** - Balances detection rate vs. false positives
6. **Modular architecture** - Easier to extend and customize
7. **Robust testing** - Can automatically test rules against benign samples

## Requirements

- Python 3.6+
- YARA Python module (`pip install yara-python`) for rule testing
- `strings` and `file` command-line utilities

## Integration with Existing Workflows

The enhanced YARA generator can be integrated into existing workflows:

1. **As a drop-in replacement** - Using the `EnhancedYaraIntegration` class
2. **As a standalone tool** - Using the command-line interface
3. **As a library** - Using the `EnhancedYaraGenerator` class directly

The integration allows for a smooth transition from the existing YARA generators while providing enhanced capabilities.

---

© 2025 Innora-Sentinel安全团队 | All Rights Reserved | [https://innora.ai](https://innora.ai)