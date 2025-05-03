# Real-time Ransomware Family Monitoring System

This document provides an overview of the real-time ransomware family monitoring system, which enhances the existing threat intelligence framework with continuous monitoring, automatic variant detection, and integration with tracking systems.

## Overview

The real-time monitoring system extends the enhanced family detection and automatic variant detection capabilities with continuous processing, alerts, and updates. It provides:

- **Continuous sample processing**: Process samples in batches for efficient resource usage
- **Automatic variant detection**: Identify new ransomware variants as they emerge
- **Real-time alerts**: Generate alerts when new variants are discovered
- **Tracking system integration**: Integrate with JIRA, Slack, MISP, and other systems
- **Family definition updates**: Automatically update family definitions
- **Detection rule generation**: Generate YARA rules for new variants
- **API access**: REST API for integration with other systems
- **Command-line interface**: Easy-to-use CLI for manual operations

## Architecture

The monitoring system consists of several components:

1. **RealtimeMonitor**: Core component that processes samples, identifies variants, and generates alerts
2. **TrackingSystemIntegration**: Integrates with tracking systems like JIRA, Slack, and MISP
3. **REST API**: Provides programmatic access to the monitoring system
4. **CLI**: Command-line interface for manual operations
5. **Tracking Handlers**: Pluggable handlers for different tracking systems

![Architecture Diagram](../docs/images/realtime_monitoring_architecture.png)

## Installation

The monitoring system is integrated with the existing threat intelligence framework. No additional installation is required beyond the dependencies for the enhanced family detection and automatic variant detection systems.

Additional optional dependencies:

- **Flask**: Required for the REST API (`pip install flask`)
- **Requests**: Required for the tracking system integration (`pip install requests`)
- **JIRA**: Required for the JIRA integration (`pip install jira`)

## Configuration

The monitoring system can be configured using a JSON configuration file. A sample configuration file is shown below:

```json
{
    "families_dir": "/path/to/families",
    "yara_rules_dir": "/path/to/yara_rules",
    "clusters_dir": "/path/to/variant_clusters",
    "update_interval": 3600,
    "batch_size": 10,
    "alert_threshold": 0.7,
    "auto_update": true,
    "auto_generate_rules": true,
    "tracking_systems": ["jira", "slack", "misp"]
}
```

Configuration options:

- **families_dir**: Directory containing family definition files
- **yara_rules_dir**: Directory containing YARA rules
- **clusters_dir**: Directory containing variant clusters
- **update_interval**: Interval in seconds for batch processing and updates (default: 3600)
- **batch_size**: Number of samples to process in each batch (default: 10)
- **alert_threshold**: Confidence threshold for generating alerts (default: 0.7)
- **auto_update**: Whether to automatically update family definitions (default: true)
- **auto_generate_rules**: Whether to automatically generate detection rules for new variants (default: true)
- **tracking_systems**: List of tracking systems to integrate with (default: ["jira", "slack", "misp"])

## Usage

### Command-line Interface

The monitoring system provides a command-line interface for manual operations.

```bash
# Start the monitoring system
python -m threat_intel.monitoring.monitoring_cli start --config /path/to/config.json

# Show current status
python -m threat_intel.monitoring.monitoring_cli status

# List ransomware families
python -m threat_intel.monitoring.monitoring_cli families

# Show family details
python -m threat_intel.monitoring.monitoring_cli family lockbit

# List variant clusters
python -m threat_intel.monitoring.monitoring_cli variants --min-confidence 0.7

# Show variant details
python -m threat_intel.monitoring.monitoring_cli variant lockbit_variant_123

# Save variant definitions
python -m threat_intel.monitoring.monitoring_cli save

# Update tracking systems
python -m threat_intel.monitoring.monitoring_cli update

# Run maintenance tasks
python -m threat_intel.monitoring.monitoring_cli maintenance

# Process a single sample
python -m threat_intel.monitoring.monitoring_cli process /path/to/sample.json --wait 10

# Monitor a directory for new samples
python -m threat_intel.monitoring.monitoring_cli monitor /path/to/samples --interval 5

# Run the REST API server
python -m threat_intel.monitoring.monitoring_cli server --host 127.0.0.1 --port 5000

# Stop the monitoring system
python -m threat_intel.monitoring.monitoring_cli stop
```

### REST API

The monitoring system provides a REST API for programmatic access.

API endpoints:

- **GET /api/status**: Get current detection status
- **POST /api/sample**: Submit a sample for analysis
- **GET /api/family/<family_name>**: Get family details
- **GET /api/variants**: Get variant clusters
- **GET /api/variant/<cluster_id>**: Get variant definition
- **POST /api/save**: Save variant definitions
- **POST /api/update**: Update tracking systems
- **POST /api/maintenance**: Perform maintenance tasks
- **POST /api/shutdown**: Shutdown the detection system

Example usage:

```bash
# Get current status
curl -X GET http://localhost:5000/api/status

# Submit a sample for analysis
curl -X POST -H "Content-Type: application/json" -d @sample.json http://localhost:5000/api/sample

# Get family details
curl -X GET http://localhost:5000/api/family/lockbit

# Get variant clusters
curl -X GET http://localhost:5000/api/variants?min_confidence=0.7

# Get variant definition
curl -X GET http://localhost:5000/api/variant/lockbit_variant_123

# Save variant definitions
curl -X POST http://localhost:5000/api/save

# Update tracking systems
curl -X POST http://localhost:5000/api/update

# Perform maintenance tasks
curl -X POST http://localhost:5000/api/maintenance

# Shutdown the detection system
curl -X POST http://localhost:5000/api/shutdown
```

### Programmatic Integration

The monitoring system can be integrated with other systems using the provided Python API.

```python
from threat_intel.monitoring.tracking_integration import create_tracking_integration

# Create tracking integration
integration = create_tracking_integration('/path/to/config.json')

# Start integration
integration.start()

# Submit a sample
with open('/path/to/sample.json', 'r') as f:
    sample_data = json.load(f)
integration.submit_sample(sample_data)

# Get statistics
stats = integration.get_statistics()
print(f"Samples processed: {stats.get('samples_processed', 0)}")
print(f"Variants detected: {stats.get('variants_detected', 0)}")

# Get recent alerts
alerts = integration.get_recent_alerts(5)
for alert in alerts:
    print(f"Alert: {alert.get('variant_info', {}).get('variant_name', 'unknown')}")

# Perform maintenance
integration.perform_maintenance()

# Stop integration
integration.stop()
```

## Custom Tracking System Integration

The monitoring system can be extended with custom tracking system handlers.

To create a custom tracking system handler:

1. Create a new file in the `threat_intel/monitoring/tracking_handlers` directory
2. Implement the `BaseHandler` protocol
3. Register the handler in the `tracking_systems` configuration

Example custom handler:

```python
class CustomHandler:
    """Custom tracking system handler"""
    
    def __init__(self):
        """Initialize the custom handler"""
        self.api_url = os.environ.get("CUSTOM_API_URL", "https://custom-api.example.com")
        self.api_key = os.environ.get("CUSTOM_API_KEY", "")
    
    def push_alert(self, alert_data: Dict[str, Any], report_file: str) -> str:
        """Push alert to custom tracking system"""
        # Extract variant info
        variant_info = alert_data.get("variant_info", {})
        variant_name = variant_info.get("variant_name", "unknown")
        base_family = variant_info.get("base_family", "unknown")
        
        # Create alert in custom system
        # ... implementation ...
        
        return "custom-alert-123"
    
    def push_update(self, update_data: Dict[str, Any], report_file: str) -> str:
        """Push update to custom tracking system"""
        # ... implementation ...
        
        return "custom-update-123"
```

## Alert Format

Alerts generated by the monitoring system have the following format:

```json
{
    "timestamp": "2023-01-01T12:00:00.000000",
    "type": "new_variant",
    "severity": "high",
    "variant_info": {
        "sample_id": "sample123",
        "base_family": "lockbit",
        "variant_name": "lockbit_variant_20230101",
        "cluster_id": "lockbit_variant_abc123",
        "confidence": 0.85
    },
    "action_required": true,
    "suggested_actions": [
        "Review variant definition for accuracy",
        "Test detection rules against samples",
        "Check for false positives"
    ]
}
```

## Update Format

Updates generated by the monitoring system have the following format:

```json
{
    "timestamp": "2023-01-01T12:00:00.000000",
    "variants_updated": 3,
    "files": {
        "lockbit_variant_abc123": "/path/to/lockbit_variant_20230101.json",
        "revil_variant_def456": "/path/to/revil_variant_20230101.json",
        "conti_variant_ghi789": "/path/to/conti_variant_20230101.json"
    }
}
```

## Directory Structure

The monitoring system uses the following directory structure:

```
threat_intel/
├── data/
│   ├── cache/          # Temporary cache files
│   ├── families/       # Family definition files
│   ├── variant_clusters/  # Variant cluster files
│   ├── alerts/         # Alert files
│   ├── reports/        # Report files
│   ├── stats/          # Statistics files
│   └── yara_rules/     # YARA rule files
├── monitoring/
│   ├── api.py             # REST API
│   ├── monitoring_cli.py  # Command-line interface
│   ├── realtime_monitor.py  # Core monitoring component
│   ├── tracking_integration.py  # Tracking system integration
│   └── tracking_handlers/  # Tracking system handlers
│       ├── __init__.py
│       ├── jira_handler.py
│       ├── slack_handler.py
│       └── misp_handler.py
└── family_detection/
    ├── enhanced_family_detector.py
    ├── auto_variant_detector.py
    └── integration_with_variant.py
```

## Performance Considerations

- The monitoring system is designed to process samples in batches to minimize resource usage
- The default batch size is 10 samples, which can be adjusted in the configuration
- The default update interval is 1 hour, which can be adjusted in the configuration
- The system uses a threaded architecture to avoid blocking the main thread
- Sample processing is queue-based, so new samples can be submitted while others are being processed
- The system uses caching to minimize redundant processing

## Security Considerations

- The monitoring system does not directly execute any code from analyzed samples
- All sample analysis is done through the existing analysis framework
- The API does not provide direct access to the file system
- Authentication and authorization must be implemented at the network level
- Environment variables are used for sensitive configuration (API keys, etc.)

## Troubleshooting

### Common Issues

#### API Server Won't Start

```
Error: Could not create Flask app. Install Flask with 'pip install flask'.
```

Solution: Install Flask with `pip install flask`.

#### JIRA Integration Not Working

```
Error pushing variant alert to jira: JIRA library not installed, using placeholder functionality
```

Solution: Install JIRA library with `pip install jira`.

#### Sample Processing Errors

```
Error processing sample for variant detection: ...
```

Solution: Check the sample data format and ensure it contains all required fields.

### Logging

The monitoring system logs to the standard output and to log files in the `logs` directory.

To enable debug logging, set the environment variable `LOG_LEVEL=DEBUG`:

```bash
LOG_LEVEL=DEBUG python -m threat_intel.monitoring.monitoring_cli status
```

## Future Enhancements

- **Distributed processing**: Support for distributed sample processing
- **Machine learning enhancement**: ML-based variant classification
- **Advanced visualization**: Interactive dashboards for variant relationships
- **Historical analysis**: Trend analysis and historical comparisons
- **Predictive analytics**: Prediction of new variant emergence
- **Additional tracking integrations**: Support for additional tracking systems

## Related Documentation

- [Enhanced Family Detection](ENHANCED_FAMILY_DETECTION.md)
- [Automatic Variant Detection](AUTO_VARIANT_DETECTION.md)
- [YARA Rule Generation](YARA_RULE_GENERATION.md)
- [Threat Intelligence Integration](THREAT_INTEL_INTEGRATION.md)