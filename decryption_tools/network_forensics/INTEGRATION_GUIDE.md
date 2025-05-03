# Integration Guide: Network-Based Ransomware Recovery

This guide provides detailed instructions for integrating the network-based ransomware recovery components with existing security systems, incident response workflows, and memory forensics tools.

## Table of Contents

1. [Integration Overview](#integration-overview)
2. [Integration with Security Monitoring Systems](#integration-with-security-monitoring-systems)
3. [Integration with Incident Response Workflows](#integration-with-incident-response-workflows)
4. [Integration with Memory Forensics](#integration-with-memory-forensics)
5. [Integration with Threat Intelligence Platforms](#integration-with-threat-intelligence-platforms)
6. [API Reference](#api-reference)
7. [Configuration Options](#configuration-options)
8. [Troubleshooting](#troubleshooting)

## Integration Overview

The network-based ransomware recovery system is designed to be modular and flexible, allowing for integration with various security systems and workflows. The system consists of three main components:

1. **NetworkKeyExtractor**: Extracts potential encryption keys from network traffic
2. **RansomwareNetworkDetector**: Identifies ransomware communication patterns in network traffic
3. **NetworkBasedRecovery**: Uses extracted keys to attempt decryption of ransomware-encrypted files

These components can be used independently or together, depending on your specific requirements.

## Integration with Security Monitoring Systems

### SIEM Integration

The network-based recovery components can be integrated with Security Information and Event Management (SIEM) systems by:

1. **Alert Generation**: The `RansomwareNetworkDetector` generates alerts that can be forwarded to SIEM systems.

```python
# Initialize detector
detector = RansomwareNetworkDetector(interface="eth0")

# Start monitoring
detector.start_monitoring()

# Periodically check for alerts
while True:
    alerts = detector.get_alerts(min_confidence=0.7)
    
    # Forward alerts to SIEM
    for alert in alerts:
        forward_to_siem(alert)
    
    time.sleep(60)  # Check every minute
```

2. **SIEM Integration Function Example**:

```python
def forward_to_siem(alert, siem_url="https://siem.example.com/api/alerts"):
    """Forward an alert to SIEM system"""
    import requests
    
    # Format alert for SIEM
    siem_alert = {
        "timestamp": alert.get("timestamp"),
        "event_type": "RANSOMWARE_NETWORK",
        "severity": "HIGH" if alert.get("confidence", 0) > 0.7 else "MEDIUM",
        "source": alert.get("source_ip"),
        "destination": alert.get("destination_ip"),
        "description": alert.get("description"),
        "details": alert
    }
    
    # Send to SIEM
    try:
        response = requests.post(siem_url, json=siem_alert)
        return response.status_code == 200
    except Exception as e:
        print(f"Error forwarding alert to SIEM: {e}")
        return False
```

### Network Monitoring Integration

The components can be integrated with existing network monitoring systems:

1. **Integration with Zeek (formerly Bro)**:

Create a Zeek script that calls our components when suspicious activity is detected:

```
# zeek-network-ransomware.zeek
@load base/protocols/http
@load base/protocols/dns

module RansomwareDetection;

export {
    redef enum Notice::Type += {
        RansomwareC2Detected,
        PotentialKeyExchange
    };
}

# Hook into HTTP traffic
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    # Call Python integration script via exec
    system(fmt("python3 /path/to/integration_script.py --check-http %s %s %s", 
               c$id$orig_h, c$id$resp_h, original_URI));
}

# Hook into DNS traffic
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    # Call Python integration script via exec
    system(fmt("python3 /path/to/integration_script.py --check-dns %s %s %s", 
               c$id$orig_h, c$id$resp_h, query));
}
```

2. **Integration with Suricata**:

Configure Suricata to log alerts, then process them with our components:

```python
def process_suricata_alerts(alert_file, output_dir):
    """Process Suricata alerts and extract keys from related traffic"""
    import json
    
    # Process Suricata alert file
    with open(alert_file, 'r') as f:
        for line in f:
            try:
                alert = json.loads(line)
                
                # Check if it's a ransomware-related alert
                if is_ransomware_alert(alert):
                    # Extract traffic related to this alert
                    pcap_file = extract_related_traffic(alert, output_dir)
                    
                    # Analyze extracted traffic
                    extractor = NetworkKeyExtractor(pcap_file)
                    keys = extractor.extract_potential_keys()
                    
                    # Save extracted keys
                    if keys:
                        extractor.save_keys_to_file(keys, 
                                                   f"{output_dir}/keys_{alert['timestamp']}.json")
            except json.JSONDecodeError:
                continue
```

### PCAP Collection Integration

For systems that collect network traffic (PCAP files), you can implement automated analysis:

```python
def analyze_new_pcaps(pcap_directory, output_directory):
    """Monitor for new PCAP files and analyze them"""
    import os
    import time
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    
    # Create file handler
    class PCAPHandler(FileSystemEventHandler):
        def on_created(self, event):
            if not event.is_directory and event.src_path.endswith('.pcap'):
                # New PCAP file detected
                analyze_pcap(event.src_path, output_directory)
    
    # Set up monitoring
    event_handler = PCAPHandler()
    observer = Observer()
    observer.schedule(event_handler, pcap_directory, recursive=True)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def analyze_pcap(pcap_file, output_directory):
    """Analyze a PCAP file for ransomware activity"""
    # Initialize analyzer
    analyzer = RansomwareNetworkAnalyzer(pcap_file)
    
    # Analyze PCAP
    results = analyzer.analyze_pcap()
    
    # Save results
    output_file = os.path.join(output_directory, 
                              f"analysis_{os.path.basename(pcap_file)}.json")
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Generate alerts if ransomware detected
    if results.get("identified_families"):
        generate_alert(results, output_directory)
```

## Integration with Incident Response Workflows

The network-based recovery components can be integrated into incident response workflows:

### Automated Response Integration

```python
def ransomware_incident_response(pcap_file, infected_directories):
    """Automated incident response for ransomware detection"""
    # Step 1: Analyze network traffic
    analyzer = RansomwareNetworkAnalyzer(pcap_file)
    network_results = analyzer.analyze_pcap()
    
    # Step 2: Check if ransomware was detected
    if network_results.get("identified_families"):
        families = network_results["identified_families"]
        print(f"Ransomware families detected: {families}")
        
        # Step 3: Extract encryption keys
        keys = network_results.get("extracted_keys", {}).get("network", [])
        if keys:
            # Step 4: Initialize recovery
            recovery = NetworkBasedRecovery()
            recovery.add_keys(keys)
            
            # Step 5: Attempt decryption of each directory
            for directory in infected_directories:
                decrypt_directory(recovery, directory)
            
            # Step 6: Generate recovery report
            generate_recovery_report(recovery.results, 
                                    f"recovery_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        else:
            print("No encryption keys found in network traffic")
    else:
        print("No ransomware detected in network traffic")

def decrypt_directory(recovery, directory):
    """Attempt to decrypt all files in a directory"""
    for root, _, files in os.walk(directory):
        for file in files:
            if is_likely_encrypted(file):
                file_path = os.path.join(root, file)
                output_path = file_path + ".decrypted"
                
                # Attempt decryption
                results = recovery.attempt_decryption(file_path, output_path)
                
                # Check if decryption was successful
                if any(r.success for r in results):
                    print(f"Successfully decrypted: {file_path}")
```

### Integration with SOAR Platforms

For Security Orchestration, Automation, and Response (SOAR) platforms, you can create a connector that uses our components:

```python
class RansomwareRecoveryConnector:
    """Connector for SOAR platforms to use network-based ransomware recovery"""
    
    def __init__(self, config=None):
        """Initialize the connector"""
        self.config = config or {}
        
    def run_action(self, action, params):
        """Run a specific action"""
        if action == "analyze_pcap":
            return self._analyze_pcap(params)
        elif action == "attempt_decryption":
            return self._attempt_decryption(params)
        elif action == "extract_keys":
            return self._extract_keys(params)
        else:
            return {"status": "error", "message": f"Unknown action: {action}"}
    
    def _analyze_pcap(self, params):
        """Analyze a PCAP file"""
        pcap_file = params.get("pcap_file")
        if not pcap_file:
            return {"status": "error", "message": "Missing pcap_file parameter"}
        
        analyzer = RansomwareNetworkAnalyzer(pcap_file)
        results = analyzer.analyze_pcap()
        return {"status": "success", "results": results}
    
    def _extract_keys(self, params):
        """Extract keys from a PCAP file"""
        pcap_file = params.get("pcap_file")
        if not pcap_file:
            return {"status": "error", "message": "Missing pcap_file parameter"}
        
        extractor = NetworkKeyExtractor(pcap_file)
        keys = extractor.extract_potential_keys()
        
        return {
            "status": "success", 
            "key_count": len(keys),
            "keys": [key.to_dict() for key in keys]
        }
    
    def _attempt_decryption(self, params):
        """Attempt to decrypt a file"""
        encrypted_file = params.get("encrypted_file")
        keys_file = params.get("keys_file")
        output_file = params.get("output_file")
        
        if not encrypted_file:
            return {"status": "error", "message": "Missing encrypted_file parameter"}
        if not keys_file:
            return {"status": "error", "message": "Missing keys_file parameter"}
        
        # Load keys and attempt decryption
        recovery = NetworkBasedRecovery()
        recovery.load_keys_from_file(keys_file)
        results = recovery.attempt_decryption(encrypted_file, output_file)
        
        return {
            "status": "success",
            "decryption_successful": any(r.success for r in results),
            "results": [r.to_dict() for r in results]
        }
```

## Integration with Memory Forensics

The network-based recovery components can be integrated with memory forensics tools to enhance recovery capabilities:

### Volatility Integration

```python
def integrate_with_volatility(memory_dump, pcap_file):
    """Integrate network analysis with Volatility memory analysis"""
    import subprocess
    import tempfile
    
    # Step 1: Extract network keys from PCAP
    extractor = NetworkKeyExtractor(pcap_file)
    network_keys = extractor.extract_potential_keys()
    
    # Step 2: Use Volatility to extract process information
    processes = extract_volatility_processes(memory_dump)
    
    # Step 3: Extract network connections from memory
    connections = extract_volatility_connections(memory_dump)
    
    # Step 4: Correlate network connections with processes
    correlated = correlate_connections_with_processes(connections, processes)
    
    # Step 5: Use Volatility to scan for encryption keys in memory
    memory_keys = extract_volatility_crypto_keys(memory_dump)
    
    # Step 6: Combine network and memory keys
    all_keys = network_keys + memory_keys
    
    # Step 7: Initialize recovery with all keys
    recovery = NetworkBasedRecovery(all_keys)
    
    return recovery

def extract_volatility_processes(memory_dump):
    """Extract process information using Volatility"""
    result = subprocess.run(
        ["vol", "-f", memory_dump, "windows.pslist"],
        capture_output=True, text=True
    )
    
    # Parse Volatility output
    processes = []
    for line in result.stdout.splitlines():
        # Parse process information
        # ...
        
    return processes

def extract_volatility_connections(memory_dump):
    """Extract network connections using Volatility"""
    result = subprocess.run(
        ["vol", "-f", memory_dump, "windows.netscan"],
        capture_output=True, text=True
    )
    
    # Parse Volatility output
    connections = []
    for line in result.stdout.splitlines():
        # Parse connection information
        # ...
        
    return connections

def extract_volatility_crypto_keys(memory_dump):
    """Extract potential encryption keys from memory using Volatility"""
    # This would use a custom Volatility plugin for key extraction
    # ...
    
    return []  # Placeholder
```

### Memory and Network Correlation

```python
def correlate_connections_with_processes(connections, processes):
    """Correlate network connections with processes"""
    correlated = {}
    
    for conn in connections:
        pid = conn.get("pid")
        if pid:
            # Find process with this PID
            process = next((p for p in processes if p.get("pid") == pid), None)
            if process:
                if pid not in correlated:
                    correlated[pid] = {
                        "process": process,
                        "connections": []
                    }
                correlated[pid]["connections"].append(conn)
    
    return correlated

def scan_process_memory_for_keys(pid, memory_dump):
    """Scan a specific process's memory for encryption keys"""
    import subprocess
    import tempfile
    
    # Extract process memory
    output_file = tempfile.NamedTemporaryFile(delete=False).name
    subprocess.run(
        ["vol", "-f", memory_dump, "windows.memmap", "--pid", str(pid), 
         "--dump", "--dump-dir", os.path.dirname(output_file)],
        capture_output=True
    )
    
    # Analyze extracted memory for keys
    # ...
    
    return []  # Placeholder
```

## Integration with Threat Intelligence Platforms

The network-based recovery components can be integrated with threat intelligence platforms:

### STIX/TAXII Integration

```python
def convert_network_patterns_to_stix(patterns_file):
    """Convert network patterns to STIX format"""
    from stix2 import Indicator, Malware, Relationship, Bundle
    
    # Load patterns
    with open(patterns_file, 'r') as f:
        patterns = json.load(f)
    
    stix_objects = []
    
    # Process each family
    for family_name, family_data in patterns.get("families", {}).items():
        # Create a malware SDO for the ransomware family
        malware_obj = Malware(
            name=family_name,
            is_family=True,
            malware_types=["ransomware"]
        )
        stix_objects.append(malware_obj)
        
        # Create indicators for C2 domains
        for domain in family_data.get("c2_domains", []):
            if isinstance(domain, str) and not domain.startswith("Dynamic"):
                indicator = Indicator(
                    name=f"{family_name} C2 Domain",
                    pattern=f"[domain-name:value = '{domain}']",
                    pattern_type="stix",
                    indicator_types=["malicious-activity"]
                )
                stix_objects.append(indicator)
                
                # Create relationship
                relationship = Relationship(
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=malware_obj.id
                )
                stix_objects.append(relationship)
        
        # Create indicators for C2 IPs
        # ...
        
    # Create STIX bundle
    bundle = Bundle(stix_objects)
    return bundle.serialize()

def publish_to_taxii(stix_data, server_url, collection_id, username, password):
    """Publish STIX data to a TAXII server"""
    from taxii2client.v20 import Server, Collection
    
    # Connect to TAXII server
    server = Server(server_url, user=username, password=password)
    
    # Get the collection
    api_root = server.api_roots[0]
    collection = Collection(f"{api_root.url}/collections/{collection_id}/")
    
    # Add STIX objects to collection
    collection.add_objects(stix_data)
    
    return True
```

### MISP Integration

```python
def push_to_misp(patterns_file, misp_url, misp_key):
    """Push network patterns to MISP"""
    from pymisp import PyMISP, MISPEvent, MISPAttribute
    
    # Initialize MISP
    misp = PyMISP(misp_url, misp_key, False)
    
    # Load patterns
    with open(patterns_file, 'r') as f:
        patterns = json.load(f)
    
    # Process each family
    for family_name, family_data in patterns.get("families", {}).items():
        # Create a MISP event
        event = MISPEvent()
        event.distribution = 0  # Your organization only
        event.threat_level_id = 2  # Medium
        event.analysis = 2  # Completed
        event.info = f"Ransomware Network Patterns: {family_name}"
        
        # Add event to MISP
        event = misp.add_event(event)
        
        # Add attributes for C2 domains
        for domain in family_data.get("c2_domains", []):
            if isinstance(domain, str) and not domain.startswith("Dynamic"):
                attribute = {
                    "type": "domain",
                    "category": "Network activity",
                    "value": domain,
                    "comment": f"{family_name} C2 domain"
                }
                misp.add_attribute(event, attribute)
        
        # Add attributes for C2 IPs
        # ...
        
        # Add detection rules
        for rule_type, rules in family_data.get("detection_signatures", {}).items():
            for rule in rules:
                attribute = {
                    "type": "snort",
                    "category": "Network activity",
                    "value": rule,
                    "comment": f"{family_name} {rule_type} detection rule"
                }
                misp.add_attribute(event, attribute)
    
    return True
```

## API Reference

### NetworkKeyExtractor API

```python
# Initialize with a PCAP file
extractor = NetworkKeyExtractor("capture.pcap")

# Extract potential keys
keys = extractor.extract_potential_keys()

# Save keys to a file
extractor.save_keys_to_file(keys, "extracted_keys.json")

# Load keys from a file
loaded_keys = extractor.load_keys_from_file("extracted_keys.json")
```

### RansomwareNetworkDetector API

```python
# Initialize with network interface
detector = RansomwareNetworkDetector(interface="eth0")

# Start network monitoring
detector.start_monitoring()

# Get alerts with minimum confidence
alerts = detector.get_alerts(min_confidence=0.7)

# Filter alerts by family
wannacry_alerts = detector.get_alerts(family="WannaCry")

# Stop monitoring
detector.stop_monitoring()

# Generate a report
report = detector.generate_report()
```

### NetworkBasedRecovery API

```python
# Initialize with keys
recovery = NetworkBasedRecovery(keys)

# Add more keys
recovery.add_key(new_key)
recovery.add_keys(more_keys)

# Load keys from a file
recovery.load_keys_from_file("keys.json")

# Attempt decryption
results = recovery.attempt_decryption(
    "encrypted_file.txt", 
    output_file="decrypted_file.txt",
    original_file="original_file.txt"  # Optional
)

# Generate a report
report = recovery.generate_report()
```

### RansomwareNetworkAnalyzer API

```python
# Initialize with a PCAP file
analyzer = RansomwareNetworkAnalyzer("capture.pcap")

# Analyze PCAP file
pcap_results = analyzer.analyze_pcap()

# Analyze sample files
sample_results = analyzer.analyze_samples("samples_directory")

# Analyze memory dumps
memory_results = analyzer.analyze_memory_dumps("memory_dumps_directory")

# Attempt decryption of a specific file
decryption_results = analyzer.attempt_file_decryption(
    "encrypted_file.txt", 
    output_dir="decrypted_files"
)

# Monitor network for ransomware
monitoring_results = analyzer.monitor_network(duration=300)  # 5 minutes

# Generate a comprehensive report
report = analyzer.generate_report()

# Perform comprehensive analysis
full_results = analyzer.analyze_all(
    samples_dir="samples_directory",
    memory_dir="memory_dumps_directory",
    output_dir="output_directory"
)
```

## Configuration Options

### NetworkKeyExtractor Configuration

| Option | Description | Default |
|--------|-------------|---------|
| `pcap_file` | PCAP file to analyze | None |
| `key_patterns` | Custom key identification patterns | Built-in patterns |
| `min_entropy` | Minimum entropy for key candidates | 6.5 |
| `max_key_size` | Maximum key size to consider | 512 bytes |

### RansomwareNetworkDetector Configuration

| Option | Description | Default |
|--------|-------------|---------|
| `interface` | Network interface to monitor | "any" |
| `pattern_matcher` | Custom pattern matcher | Built-in |
| `min_confidence` | Minimum confidence for alerts | 0.3 |
| `alert_limit` | Maximum number of alerts to retain | 1000 |

### NetworkBasedRecovery Configuration

| Option | Description | Default |
|--------|-------------|---------|
| `keys` | Initial keys to use | [] |
| `validation_methods` | Methods for validating decryption | All available |
| `max_attempts` | Maximum decryption attempts per file | 100 |

### RansomwareNetworkAnalyzer Configuration

| Option | Description | Default |
|--------|-------------|---------|
| `pcap_file` | PCAP file to analyze | None |
| `interface` | Network interface to monitor | "any" |
| `samples_dir` | Directory containing sample files | None |
| `memory_dir` | Directory containing memory dumps | None |
| `output_dir` | Directory for output files | None |

## Troubleshooting

### Common Issues and Solutions

1. **Missing Dependencies**:
   - Problem: ImportError when trying to use components
   - Solution: Install required dependencies using `pip install -r requirements.txt`

2. **PCAP Parsing Errors**:
   - Problem: Error when parsing PCAP files
   - Solution: Ensure the PCAP file is valid and not corrupted. Try using a different PCAP library.

3. **Decryption Fails**:
   - Problem: Decryption attempts fail with all extracted keys
   - Solution:
     - Check if the file is actually encrypted with a supported algorithm
     - Verify that keys were extracted correctly
     - Try different encryption modes (CBC, ECB, CTR)
     - Check if the file header contains encryption parameters

4. **No Alerts Generated**:
   - Problem: RansomwareNetworkDetector doesn't generate alerts
   - Solution:
     - Ensure network traffic contains relevant patterns
     - Lower the confidence threshold
     - Check if the network interface is capturing traffic
     - Update the network patterns database

### Diagnostic Tools

1. **Library Availability Checker**:

```python
def check_library_availability():
    """Check if required libraries are available"""
    availability = {}
    
    # Check for DPKT
    try:
        import dpkt
        availability["dpkt"] = True
    except ImportError:
        availability["dpkt"] = False
    
    # Check for cryptography
    try:
        import cryptography
        availability["cryptography"] = True
    except ImportError:
        availability["cryptography"] = False
    
    # Check for PyShark
    try:
        import pyshark
        availability["pyshark"] = True
    except ImportError:
        availability["pyshark"] = False
    
    # Check for Scapy
    try:
        import scapy.all
        availability["scapy"] = True
    except ImportError:
        availability["scapy"] = False
    
    return availability
```

2. **PCAP Validator**:

```python
def validate_pcap(pcap_file):
    """Validate a PCAP file"""
    try:
        with open(pcap_file, 'rb') as f:
            data = f.read(4)
            
        # Check magic numbers
        if data == b"\xd4\xc3\xb2\xa1":  # Little-endian
            return {"valid": True, "format": "pcap_le"}
        elif data == b"\xa1\xb2\xc3\xd4":  # Big-endian
            return {"valid": True, "format": "pcap_be"}
        elif data == b"\x0a\x0d\x0d\x0a":  # PCAPNG
            return {"valid": True, "format": "pcapng"}
        else:
            return {"valid": False, "reason": "Unknown format"}
    except Exception as e:
        return {"valid": False, "reason": str(e)}
```

3. **Logging Configuration**:

```python
def configure_logging(level=logging.INFO, log_file=None):
    """Configure logging for troubleshooting"""
    handlers = []
    
    # Add console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    handlers.append(console_handler)
    
    # Add file handler if log_file is specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)
    
    # Configure root logger
    logging.basicConfig(level=level, handlers=handlers)
    
    return True
```