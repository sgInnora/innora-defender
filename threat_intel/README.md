# Threat Intelligence Integration

This module provides advanced threat intelligence capabilities for ransomware analysis. It integrates with external threat intelligence sources, correlates findings, and generates comprehensive reports.

## Features

- **Multiple Threat Intelligence Sources**: Integrates with VirusTotal, AlienVault OTX, and MITRE ATT&CK
- **Correlation Engine**: Correlates analysis findings with threat intelligence data
- **Campaign Analysis**: Identifies potential ransomware campaigns across multiple samples
- **Comprehensive Reporting**: Generates detailed Markdown and HTML reports
- **MITRE ATT&CK Integration**: Maps findings to MITRE ATT&CK techniques and tactics
- **YARA Rule Generation**: Creates detection rules based on analysis results
- **IOC Extraction & Export**: Extracts indicators of compromise in multiple formats (STIX, OpenIOC, MISP, CSV, JSON)
- **Unified Integration**: Combines all components for seamless workflow

## Directory Structure

```
threat_intel/
├── connectors/           # Threat intelligence connectors
│   └── ti_connector.py   # Base connector and implementations
├── correlation/          # Correlation engine
│   └── correlation_engine.py  # Correlates findings with threat intelligence
├── reports/              # Report generation
│   ├── templates/        # Report templates
│   ├── generated/        # Generated reports
│   └── report_generator.py  # Generates reports from correlation results
├── rules/                # YARA rule generation
│   ├── templates/        # YARA rule templates
│   ├── generated/        # Generated YARA rules
│   └── yara_generator.py # Generates YARA rules from analysis
├── ioc_utils/            # IOC extraction utilities
│   ├── output/           # Exported IOCs
│   └── ioc_extractor.py  # Extracts and exports IOCs
├── data/                 # Data files
│   ├── ransomware_indicators.json  # Known ransomware indicators
│   ├── cache/            # Cache for threat intelligence data
│   └── sample_ransomware.json  # Example ransomware analysis
├── threat_intel_analyzer.py  # Main analysis script
└── integration.py        # Unified integration of all components
```

## Configuration

To use the external threat intelligence sources, you need to set the following environment variables or provide them as command-line arguments:

- `VIRUSTOTAL_API_KEY`: Your VirusTotal API key
- `ALIENVAULT_OTX_API_KEY`: Your AlienVault OTX API key

## Usage

### From Python

```python
from threat_intel.threat_intel_analyzer import ThreatIntelAnalyzer

# Create analyzer with API keys
analyzer = ThreatIntelAnalyzer(api_keys={
    'VIRUSTOTAL_API_KEY': 'your_vt_key',
    'ALIENVAULT_OTX_API_KEY': 'your_otx_key'
})

# Analyze a file
result = analyzer.analyze_file('/path/to/malware.bin')

# Analyze a directory of JSON files
result = analyzer.analyze_directory('/path/to/analysis/directory')
```

### Using the Analyzer

```bash
# Analyze a single file
python threat_intel_analyzer.py --file /path/to/malware.bin --vt-key YOUR_VT_KEY --otx-key YOUR_OTX_KEY

# Analyze a JSON file containing analysis data
python threat_intel_analyzer.py --analysis /path/to/analysis.json

# Analyze a directory of JSON files
python threat_intel_analyzer.py --directory /path/to/analysis/dir

# Save correlation results
python threat_intel_analyzer.py --file /path/to/malware.bin --output results.json

# Don't generate a report
python threat_intel_analyzer.py --file /path/to/malware.bin --no-report

# View the report immediately
python threat_intel_analyzer.py --file /path/to/malware.bin --view
```

### Using the Integrated Workflow

```bash
# Process a file with all components (threat intel, correlation, reporting, IOCs, YARA)
python integration.py --file /path/to/malware.bin --vt-key YOUR_VT_KEY --otx-key YOUR_OTX_KEY

# Process a JSON file with all components
python integration.py --analysis /path/to/analysis.json

# Process a directory of JSON files
python integration.py --directory /path/to/analysis/dir

# Specify output directory
python integration.py --file /path/to/malware.bin --output-dir /path/to/output

# Skip specific components
python integration.py --file /path/to/malware.bin --no-report --no-iocs --no-yara

# Export IOCs in specific formats
python integration.py --file /path/to/malware.bin --ioc-formats json csv stix misp

# View the report immediately
python integration.py --file /path/to/malware.bin --view
```

### Using Individual Components

```bash
# Generate YARA rules from a sample
python rules/yara_generator.py --file /path/to/analysis.json

# Extract IOCs from a sample
python ioc_utils/ioc_extractor.py --file /path/to/analysis.json --formats json csv stix
```

## Example

```bash
# Analyze the provided example
python integration.py --analysis data/sample_ransomware.json --view
```

## Integration with Analysis Environment

This threat intelligence module works best when integrated with your existing malware analysis environment. Here's how to use it with the other components:

1. **Static Analysis**: After performing static analysis, save the analysis results as JSON
2. **Dynamic Analysis**: After dynamic analysis, update the JSON with behavioral information
3. **Threat Intelligence**: Use this module to enrich the analysis with threat intelligence
4. **Reporting**: Generate comprehensive reports with the enriched data

## Report Templates

The report templates are located in the `reports/templates/` directory:

- `single_sample_template.md`: Template for single sample reports
- `multi_sample_template.md`: Template for multi-sample reports

You can customize these templates to fit your specific needs.

## Dependencies

- Python 3.6+
- requests
- markdown (for HTML report generation)

---

© 2025 Innora-Sentinel安全团队 | All Rights Reserved | [https://innora.ai](https://innora.ai)