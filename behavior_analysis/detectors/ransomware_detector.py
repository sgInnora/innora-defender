#!/usr/bin/env python3
"""
Ransomware Behavior Detector
Analyzes process behavior and file system operations to detect ransomware activity in real-time.
"""

import os
import re
import json
import time
import logging
import threading
import queue
import hashlib
import datetime
import collections
from typing import Dict, List, Any, Optional, Set, Tuple, Deque
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ransomware_detector')

class FilesystemMonitor:
    """Monitors filesystem activity for ransomware-like behavior"""
    
    def __init__(self, config_file=None):
        """
        Initialize the filesystem monitor
        
        Args:
            config_file: Path to configuration file (optional)
        """
        self.config = self._load_config(config_file)
        self.alert_queue = queue.Queue()
        self.file_operations = collections.deque(maxlen=self.config["file_operations_history_size"])
        self.extension_counts = {}
        self.extension_timestamps = {}
        self.file_entropy_cache = {}
        self.monitored_paths = self.config["monitored_paths"]
        self.excluded_paths = self.config["excluded_paths"]
        self.excluded_processes = self.config["excluded_processes"]
        self.running = False
        self.thread = None
    
    def _load_config(self, config_file=None) -> Dict:
        """
        Load configuration from file or use defaults
        
        Args:
            config_file: Path to configuration file
            
        Returns:
            Configuration dictionary
        """
        default_config = {
            "monitored_paths": [
                os.path.expanduser("~/Documents"),
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Pictures"),
                os.path.expanduser("~/Downloads")
            ],
            "excluded_paths": [
                "/tmp",
                "/var",
                os.path.expanduser("~/.cache")
            ],
            "excluded_processes": [
                "backup",
                "rsync",
                "dropbox",
                "onedrive",
                "google drive",
                "chrome",
                "firefox",
                "safari"
            ],
            "entropy_threshold": 7.0,  # High entropy threshold (0-8)
            "file_operations_history_size": 1000,
            "max_file_size_for_entropy": 10_000_000,  # 10MB
            "extension_count_threshold": 10,  # Number of new extensions to trigger alert
            "file_write_rate_threshold": 20,  # Files per second
            "extensions_to_monitor": [
                ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
                ".jpg", ".jpeg", ".png", ".gif", ".psd", ".ai", ".mp3",
                ".mp4", ".mov", ".avi", ".zip", ".rar", ".7z", ".txt",
                ".rtf", ".csv", ".json", ".xml", ".html", ".htm"
            ],
            "ransomware_extensions": [
                ".encrypted", ".locked", ".crypted", ".crypt", ".crypto", ".enc", ".ransomware", ".gdcb",
                ".wncry", ".wcry", ".wncrypt", ".wncryt", ".locky", ".zepto", ".thor",
                ".aesir", ".zzzzz", ".cryptowall", ".ecc", ".ezz", ".exx", ".sage", ".cerber", ".cerber2",
                ".cerber3", ".crypt", ".crypz", ".cryp1", ".onion", ".breaking_bad", ".legion", ".magic", 
                ".xtbl", ".coded", ".ha3", ".toxcrypt", ".0x0", ".bleep", ".btc", ".ctb2", ".ctbl", 
                ".rmd", ".lesli", ".rdmk", ".cryptolocker", ".scl", ".code", ".razy", ".xrtn"
            ],
            "ransom_note_patterns": [
                r"README.*\.txt",
                r"HOW.*DECRYPT.*\.(txt|html)",
                r"DECRYPT.*\.(txt|html)",
                r"HELP.*\.(txt|html)",
                r"RECOVERY.*\.(txt|html)",
                r"RESTORE.*\.(txt|html)",
                r"YOUR_FILES.*\.(txt|html)"
            ]
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                
                # Merge with defaults to ensure all keys exist
                merged_config = default_config.copy()
                merged_config.update(config)
                return merged_config
            except Exception as e:
                logger.error(f"Error loading configuration: {e}")
                return default_config
        else:
            return default_config
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data
        
        Args:
            data: Bytes to calculate entropy for
            
        Returns:
            Entropy value (0-8)
        """
        if not data:
            return 0.0
            
        entropy = 0.0
        for byte_value in range(256):
            p_x = data.count(bytes([byte_value])) / len(data)
            if p_x > 0:
                entropy -= p_x * (math.log(p_x, 2))
        return entropy
    
    def _check_file_entropy(self, file_path: str) -> float:
        """
        Check file entropy
        
        Args:
            file_path: Path to file
            
        Returns:
            Entropy value (0-8)
        """
        try:
            # Check if we have cached entropy
            if file_path in self.file_entropy_cache:
                return self.file_entropy_cache[file_path]
                
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size > self.config["max_file_size_for_entropy"]:
                return 0.0  # Skip large files
                
            # Read file and calculate entropy
            with open(file_path, 'rb') as f:
                data = f.read()
                
            entropy = self._calculate_entropy(data)
            
            # Cache the result
            self.file_entropy_cache[file_path] = entropy
            
            return entropy
        except Exception as e:
            logger.debug(f"Error calculating entropy for {file_path}: {e}")
            return 0.0
    
    def _is_path_excluded(self, path: str) -> bool:
        """
        Check if path is excluded from monitoring
        
        Args:
            path: Path to check
            
        Returns:
            True if path is excluded, False otherwise
        """
        for excluded_path in self.excluded_paths:
            if path.startswith(excluded_path):
                return True
        return False
    
    def _is_process_excluded(self, process_name: str) -> bool:
        """
        Check if process is excluded from monitoring
        
        Args:
            process_name: Process name to check
            
        Returns:
            True if process is excluded, False otherwise
        """
        process_name_lower = process_name.lower()
        for excluded_process in self.excluded_processes:
            if excluded_process.lower() in process_name_lower:
                return True
        return False
    
    def _check_extension_patterns(self, file_path: str) -> bool:
        """
        Check if file has a known ransomware extension
        
        Args:
            file_path: Path to check
            
        Returns:
            True if extension matches ransomware pattern, False otherwise
        """
        extension = os.path.splitext(file_path)[1].lower()
        return extension in self.config["ransomware_extensions"]
    
    def _check_ransom_note_patterns(self, file_path: str) -> bool:
        """
        Check if file matches a ransom note pattern
        
        Args:
            file_path: Path to check
            
        Returns:
            True if file matches ransom note pattern, False otherwise
        """
        filename = os.path.basename(file_path)
        for pattern in self.config["ransom_note_patterns"]:
            if re.match(pattern, filename, re.IGNORECASE):
                return True
        return False
    
    def process_file_creation(self, file_path: str, process_name: str = None) -> None:
        """
        Process file creation event
        
        Args:
            file_path: Path to created file
            process_name: Name of process that created the file (optional)
        """
        if self._is_path_excluded(file_path):
            return
            
        if process_name and self._is_process_excluded(process_name):
            return
            
        # Add to file operations history
        timestamp = time.time()
        operation = {
            "type": "create",
            "path": file_path,
            "timestamp": timestamp,
            "process": process_name
        }
        self.file_operations.append(operation)
        
        # Check for ransomware extension
        if self._check_extension_patterns(file_path):
            self._trigger_alert({
                "type": "ransomware_extension",
                "path": file_path,
                "extension": os.path.splitext(file_path)[1],
                "timestamp": timestamp,
                "process": process_name,
                "severity": "high"
            })
            return
            
        # Check for ransom note
        if self._check_ransom_note_patterns(file_path):
            self._trigger_alert({
                "type": "ransom_note",
                "path": file_path,
                "timestamp": timestamp,
                "process": process_name,
                "severity": "high"
            })
            return
            
        # Track new extensions
        extension = os.path.splitext(file_path)[1].lower()
        if extension and extension in self.config["extensions_to_monitor"]:
            if extension not in self.extension_counts:
                self.extension_counts[extension] = 0
                self.extension_timestamps[extension] = []
                
            self.extension_counts[extension] += 1
            self.extension_timestamps[extension].append(timestamp)
            
            # Clean old timestamps
            cutoff = timestamp - 60  # Last minute
            self.extension_timestamps[extension] = [ts for ts in self.extension_timestamps[extension] if ts > cutoff]
            
            # Check for high file modification rate
            if len(self.extension_timestamps[extension]) >= self.config["extension_count_threshold"]:
                # Calculate rate (files per second)
                if len(self.extension_timestamps[extension]) >= 2:
                    time_diff = self.extension_timestamps[extension][-1] - self.extension_timestamps[extension][0]
                    if time_diff > 0:
                        rate = len(self.extension_timestamps[extension]) / time_diff
                        if rate > self.config["file_write_rate_threshold"]:
                            self._trigger_alert({
                                "type": "high_file_modification_rate",
                                "extension": extension,
                                "files_per_second": rate,
                                "timestamp": timestamp,
                                "process": process_name,
                                "severity": "medium"
                            })
    
    def process_file_modification(self, file_path: str, process_name: str = None) -> None:
        """
        Process file modification event
        
        Args:
            file_path: Path to modified file
            process_name: Name of process that modified the file (optional)
        """
        if self._is_path_excluded(file_path):
            return
            
        if process_name and self._is_process_excluded(process_name):
            return
            
        # Add to file operations history
        timestamp = time.time()
        operation = {
            "type": "modify",
            "path": file_path,
            "timestamp": timestamp,
            "process": process_name
        }
        self.file_operations.append(operation)
        
        # Check entropy for modified files
        try:
            entropy = self._check_file_entropy(file_path)
            if entropy > self.config["entropy_threshold"]:
                self._trigger_alert({
                    "type": "high_entropy",
                    "path": file_path,
                    "entropy": entropy,
                    "timestamp": timestamp,
                    "process": process_name,
                    "severity": "medium"
                })
        except Exception as e:
            logger.debug(f"Error checking entropy: {e}")
    
    def process_file_deletion(self, file_path: str, process_name: str = None) -> None:
        """
        Process file deletion event
        
        Args:
            file_path: Path to deleted file
            process_name: Name of process that deleted the file (optional)
        """
        if self._is_path_excluded(file_path):
            return
            
        if process_name and self._is_process_excluded(process_name):
            return
            
        # Add to file operations history
        timestamp = time.time()
        operation = {
            "type": "delete",
            "path": file_path,
            "timestamp": timestamp,
            "process": process_name
        }
        self.file_operations.append(operation)
        
        # Remove from entropy cache
        if file_path in self.file_entropy_cache:
            del self.file_entropy_cache[file_path]
    
    def _trigger_alert(self, alert_data: Dict) -> None:
        """
        Trigger an alert
        
        Args:
            alert_data: Alert data dictionary
        """
        # Add basic info to the alert
        if "timestamp" not in alert_data:
            alert_data["timestamp"] = time.time()
            
        alert_data["id"] = hashlib.md5(f"{alert_data['type']}_{alert_data['timestamp']}".encode()).hexdigest()
        alert_data["timestamp_iso"] = datetime.datetime.fromtimestamp(alert_data["timestamp"]).isoformat()
        
        # Put in the queue
        self.alert_queue.put(alert_data)
        
        # Log the alert
        logger.warning(f"Ransomware Alert: {alert_data['type']} - {alert_data.get('path', '')}")
    
    def get_alerts(self) -> List[Dict]:
        """
        Get alerts from the queue
        
        Returns:
            List of alert dictionaries
        """
        alerts = []
        while not self.alert_queue.empty():
            alerts.append(self.alert_queue.get())
        return alerts
    
    def analyze_file_operations(self) -> None:
        """
        Analyze file operations history to detect patterns
        """
        if not self.file_operations:
            return
            
        timestamp = time.time()
        
        # Check for mass file operations
        operations_last_minute = [op for op in self.file_operations 
                               if timestamp - op["timestamp"] < 60]
        
        if len(operations_last_minute) > 100:  # More than 100 operations in a minute
            # Group by process
            process_counts = {}
            for op in operations_last_minute:
                process = op.get("process", "unknown")
                if process not in process_counts:
                    process_counts[process] = 0
                process_counts[process] += 1
            
            # Find processes with high operation counts
            for process, count in process_counts.items():
                if count > 50:  # More than 50 operations by a single process
                    self._trigger_alert({
                        "type": "mass_file_operations",
                        "process": process,
                        "operation_count": count,
                        "timestamp": timestamp,
                        "severity": "medium"
                    })
        
        # Check for extension replacement patterns
        extension_replacements = {}
        for op in operations_last_minute:
            if op["type"] in ["create", "modify"]:
                path = op["path"]
                base_name = os.path.splitext(path)[0]
                
                # Check if the same base filename exists with different extensions
                for ext in self.config["extensions_to_monitor"]:
                    test_path = f"{base_name}{ext}"
                    if test_path != path and os.path.exists(test_path):
                        # Check if the original was recently modified or deleted
                        for old_op in operations_last_minute:
                            if (old_op["type"] in ["modify", "delete"] and 
                                old_op["path"] == test_path):
                                # Found a replacement pattern
                                if base_name not in extension_replacements:
                                    extension_replacements[base_name] = []
                                extension_replacements[base_name].append({
                                    "original": test_path,
                                    "new": path
                                })
        
        # Trigger alerts for extension replacements
        if len(extension_replacements) > 5:  # More than 5 files had extensions replaced
            self._trigger_alert({
                "type": "extension_replacement",
                "count": len(extension_replacements),
                "examples": list(extension_replacements.items())[:5],
                "timestamp": timestamp,
                "severity": "high"
            })
    
    def start_monitoring(self) -> None:
        """Start monitoring in a separate thread"""
        if self.running:
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._monitoring_thread, daemon=True)
        self.thread.start()
        logger.info("Filesystem monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop monitoring thread"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
            self.thread = None
        logger.info("Filesystem monitoring stopped")
    
    def _monitoring_thread(self) -> None:
        """Background thread for analysis"""
        while self.running:
            try:
                self.analyze_file_operations()
            except Exception as e:
                logger.error(f"Error in monitoring thread: {e}")
            
            # Sleep for a short time
            time.sleep(1)


class ProcessActivityMonitor:
    """Monitors process activity for ransomware-like behavior"""
    
    def __init__(self, config_file=None):
        """
        Initialize the process activity monitor
        
        Args:
            config_file: Path to configuration file (optional)
        """
        self.config = self._load_config(config_file)
        self.alert_queue = queue.Queue()
        self.process_history = collections.deque(maxlen=self.config["process_history_size"])
        self.excluded_processes = self.config["excluded_processes"]
        self.running = False
        self.thread = None
    
    def _load_config(self, config_file=None) -> Dict:
        """
        Load configuration from file or use defaults
        
        Args:
            config_file: Path to configuration file
            
        Returns:
            Configuration dictionary
        """
        default_config = {
            "excluded_processes": [
                "backup",
                "rsync",
                "dropbox",
                "onedrive",
                "google drive",
                "chrome",
                "firefox",
                "safari"
            ],
            "process_history_size": 1000,
            "suspicious_commands": [
                "vssadmin delete shadows",
                "wmic shadowcopy delete",
                "bcdedit /set",
                "wbadmin delete catalog",
                "wevtutil",
                "taskkill /f",
                "net stop"
            ],
            "suspicious_process_patterns": [
                r"cmd\.exe.*delete",
                r"powershell\.exe.*encode",
                r"wmic.*delete",
                r"bcdedit.*set",
                r"vssadmin.*delete",
                r"wbadmin.*delete"
            ],
            "security_tool_termination": [
                "antivirus",
                "defender",
                "firewall",
                "protection",
                "security",
                "safeguard"
            ]
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                
                # Merge with defaults to ensure all keys exist
                merged_config = default_config.copy()
                merged_config.update(config)
                return merged_config
            except Exception as e:
                logger.error(f"Error loading configuration: {e}")
                return default_config
        else:
            return default_config
    
    def _is_process_excluded(self, process_name: str) -> bool:
        """
        Check if process is excluded from monitoring
        
        Args:
            process_name: Process name to check
            
        Returns:
            True if process is excluded, False otherwise
        """
        process_name_lower = process_name.lower()
        for excluded_process in self.excluded_processes:
            if excluded_process.lower() in process_name_lower:
                return True
        return False
    
    def _check_suspicious_command(self, command_line: str) -> Optional[str]:
        """
        Check if command line matches suspicious patterns
        
        Args:
            command_line: Command line to check
            
        Returns:
            Matched pattern if suspicious, None otherwise
        """
        # Check for exact command matches
        command_line_lower = command_line.lower()
        for suspicious_command in self.config["suspicious_commands"]:
            if suspicious_command.lower() in command_line_lower:
                return suspicious_command
        
        # Check for regex patterns
        for pattern in self.config["suspicious_process_patterns"]:
            if re.search(pattern, command_line, re.IGNORECASE):
                return pattern
        
        return None
    
    def _check_security_tool_termination(self, process_name: str, command_line: str) -> bool:
        """
        Check if command is terminating security tools
        
        Args:
            process_name: Process name
            command_line: Command line
            
        Returns:
            True if terminating security tools, False otherwise
        """
        command_line_lower = command_line.lower()
        if "taskkill" in command_line_lower or "stop" in command_line_lower or "delete" in command_line_lower:
            for security_term in self.config["security_tool_termination"]:
                if security_term in command_line_lower:
                    return True
        return False
    
    def process_creation(self, process_id: int, process_name: str, parent_process_id: int = None,
                        parent_process_name: str = None, command_line: str = None) -> None:
        """
        Process process creation event
        
        Args:
            process_id: Process ID
            process_name: Process name
            parent_process_id: Parent process ID (optional)
            parent_process_name: Parent process name (optional)
            command_line: Command line (optional)
        """
        if self._is_process_excluded(process_name):
            return
            
        # Add to process history
        timestamp = time.time()
        process_info = {
            "type": "create",
            "pid": process_id,
            "name": process_name,
            "parent_pid": parent_process_id,
            "parent_name": parent_process_name,
            "command_line": command_line,
            "timestamp": timestamp
        }
        self.process_history.append(process_info)
        
        # Check for suspicious commands
        if command_line:
            suspicious_pattern = self._check_suspicious_command(command_line)
            if suspicious_pattern:
                self._trigger_alert({
                    "type": "suspicious_command",
                    "process_id": process_id,
                    "process_name": process_name,
                    "command_line": command_line,
                    "pattern": suspicious_pattern,
                    "timestamp": timestamp,
                    "severity": "high"
                })
                
            # Check for security tool termination
            if self._check_security_tool_termination(process_name, command_line):
                self._trigger_alert({
                    "type": "security_tool_termination",
                    "process_id": process_id,
                    "process_name": process_name,
                    "command_line": command_line,
                    "timestamp": timestamp,
                    "severity": "high"
                })
    
    def process_termination(self, process_id: int, process_name: str) -> None:
        """
        Process process termination event
        
        Args:
            process_id: Process ID
            process_name: Process name
        """
        if self._is_process_excluded(process_name):
            return
            
        # Add to process history
        timestamp = time.time()
        process_info = {
            "type": "terminate",
            "pid": process_id,
            "name": process_name,
            "timestamp": timestamp
        }
        self.process_history.append(process_info)
    
    def _trigger_alert(self, alert_data: Dict) -> None:
        """
        Trigger an alert
        
        Args:
            alert_data: Alert data dictionary
        """
        # Add basic info to the alert
        if "timestamp" not in alert_data:
            alert_data["timestamp"] = time.time()
            
        alert_data["id"] = hashlib.md5(f"{alert_data['type']}_{alert_data['timestamp']}".encode()).hexdigest()
        alert_data["timestamp_iso"] = datetime.datetime.fromtimestamp(alert_data["timestamp"]).isoformat()
        
        # Put in the queue
        self.alert_queue.put(alert_data)
        
        # Log the alert
        logger.warning(f"Ransomware Alert: {alert_data['type']} - {alert_data.get('process_name', '')}")
    
    def get_alerts(self) -> List[Dict]:
        """
        Get alerts from the queue
        
        Returns:
            List of alert dictionaries
        """
        alerts = []
        while not self.alert_queue.empty():
            alerts.append(self.alert_queue.get())
        return alerts
    
    def analyze_process_activity(self) -> None:
        """
        Analyze process activity to detect patterns
        """
        if not self.process_history:
            return
            
        timestamp = time.time()
        
        # Check for process activity patterns in the last minute
        activities_last_minute = [act for act in self.process_history 
                               if timestamp - act["timestamp"] < 60]
        
        # Check for multiple suspicious process creations
        suspicious_count = 0
        for activity in activities_last_minute:
            if activity["type"] == "create" and activity.get("command_line"):
                if self._check_suspicious_command(activity["command_line"]):
                    suspicious_count += 1
        
        if suspicious_count >= 3:  # Multiple suspicious processes within a minute
            self._trigger_alert({
                "type": "multiple_suspicious_processes",
                "count": suspicious_count,
                "timestamp": timestamp,
                "severity": "high"
            })
    
    def start_monitoring(self) -> None:
        """Start monitoring in a separate thread"""
        if self.running:
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._monitoring_thread, daemon=True)
        self.thread.start()
        logger.info("Process activity monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop monitoring thread"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
            self.thread = None
        logger.info("Process activity monitoring stopped")
    
    def _monitoring_thread(self) -> None:
        """Background thread for analysis"""
        while self.running:
            try:
                self.analyze_process_activity()
            except Exception as e:
                logger.error(f"Error in monitoring thread: {e}")
            
            # Sleep for a short time
            time.sleep(1)


class RansomwareBehaviorDetector:
    """Integrates filesystem and process monitoring for ransomware detection"""
    
    def __init__(self, config_file=None):
        """
        Initialize the ransomware behavior detector
        
        Args:
            config_file: Path to configuration file (optional)
        """
        self.filesystem_monitor = FilesystemMonitor(config_file)
        self.process_monitor = ProcessActivityMonitor(config_file)
        self.alert_handlers = []
        self.running = False
        self.thread = None
    
    def register_alert_handler(self, handler_func) -> None:
        """
        Register a function to handle alerts
        
        Args:
            handler_func: Function that takes an alert dictionary
        """
        self.alert_handlers.append(handler_func)
    
    def process_file_event(self, event_type: str, file_path: str, process_name: str = None) -> None:
        """
        Process a file event
        
        Args:
            event_type: Event type ("create", "modify", "delete")
            file_path: Path to the file
            process_name: Name of the process (optional)
        """
        if event_type == "create":
            self.filesystem_monitor.process_file_creation(file_path, process_name)
        elif event_type == "modify":
            self.filesystem_monitor.process_file_modification(file_path, process_name)
        elif event_type == "delete":
            self.filesystem_monitor.process_file_deletion(file_path, process_name)
    
    def process_process_event(self, event_type: str, process_id: int, process_name: str,
                             parent_process_id: int = None, parent_process_name: str = None,
                             command_line: str = None) -> None:
        """
        Process a process event
        
        Args:
            event_type: Event type ("create", "terminate")
            process_id: Process ID
            process_name: Process name
            parent_process_id: Parent process ID (optional)
            parent_process_name: Parent process name (optional)
            command_line: Command line (optional)
        """
        if event_type == "create":
            self.process_monitor.process_creation(
                process_id, process_name, parent_process_id, parent_process_name, command_line
            )
        elif event_type == "terminate":
            self.process_monitor.process_termination(process_id, process_name)
    
    def get_alerts(self) -> List[Dict]:
        """
        Get all alerts from monitors
        
        Returns:
            List of alert dictionaries
        """
        alerts = []
        alerts.extend(self.filesystem_monitor.get_alerts())
        alerts.extend(self.process_monitor.get_alerts())
        return alerts
    
    def start(self) -> None:
        """Start all monitoring components"""
        if self.running:
            return
            
        self.running = True
        self.filesystem_monitor.start_monitoring()
        self.process_monitor.start_monitoring()
        self.thread = threading.Thread(target=self._alert_handler_thread, daemon=True)
        self.thread.start()
        logger.info("Ransomware behavior detection started")
    
    def stop(self) -> None:
        """Stop all monitoring components"""
        self.running = False
        self.filesystem_monitor.stop_monitoring()
        self.process_monitor.stop_monitoring()
        if self.thread:
            self.thread.join(timeout=2)
            self.thread = None
        logger.info("Ransomware behavior detection stopped")
    
    def _alert_handler_thread(self) -> None:
        """Background thread for handling alerts"""
        while self.running:
            try:
                # Get alerts
                alerts = self.get_alerts()
                
                # Handle alerts
                for alert in alerts:
                    for handler in self.alert_handlers:
                        try:
                            handler(alert)
                        except Exception as e:
                            logger.error(f"Error in alert handler: {e}")
            except Exception as e:
                logger.error(f"Error in alert handler thread: {e}")
            
            # Sleep for a short time
            time.sleep(0.5)
    
    def analyze_sample(self, sample_data: Dict) -> Dict:
        """
        Analyze sample data for ransomware behaviors
        
        Args:
            sample_data: Sample data dictionary
            
        Returns:
            Analysis results dictionary
        """
        results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "found_behaviors": [],
            "severity": "low"
        }
        
        # Check for file behaviors
        file_behaviors = sample_data.get("analysis", {}).get("behaviors", {})
        
        # Check for file operations
        if "file_operations" in file_behaviors:
            file_ops = file_behaviors["file_operations"]
            
            # Track extensions and files
            extensions = {}
            created_files = []
            
            for op in file_ops:
                if "path" in op:
                    path = op["path"]
                    ext = os.path.splitext(path)[1].lower()
                    
                    if ext:
                        if ext not in extensions:
                            extensions[ext] = 0
                        extensions[ext] += 1
                    
                    if op.get("type") == "write":
                        created_files.append(path)
            
            # Check for ransomware extensions
            for ext, count in extensions.items():
                if ext in self.filesystem_monitor.config["ransomware_extensions"]:
                    results["found_behaviors"].append({
                        "type": "ransomware_extension",
                        "extension": ext,
                        "count": count,
                        "severity": "high"
                    })
                    if results["severity"] != "high":
                        results["severity"] = "high"
            
            # Check for known ransom notes
            for file_path in created_files:
                filename = os.path.basename(file_path)
                for pattern in self.filesystem_monitor.config["ransom_note_patterns"]:
                    if re.match(pattern, filename, re.IGNORECASE):
                        results["found_behaviors"].append({
                            "type": "ransom_note",
                            "path": file_path,
                            "severity": "high"
                        })
                        if results["severity"] != "high":
                            results["severity"] = "high"
            
            # Check for high number of file operations
            if len(file_ops) > 100:
                results["found_behaviors"].append({
                    "type": "mass_file_operations",
                    "count": len(file_ops),
                    "severity": "medium"
                })
                if results["severity"] == "low":
                    results["severity"] = "medium"
        
        # Check for created files
        if "created_files" in file_behaviors:
            for file_path in file_behaviors["created_files"]:
                # Check for extensions
                if self._check_extension_patterns(file_path):
                    results["found_behaviors"].append({
                        "type": "ransomware_extension",
                        "path": file_path,
                        "extension": os.path.splitext(file_path)[1],
                        "severity": "high"
                    })
                    if results["severity"] != "high":
                        results["severity"] = "high"
                
                # Check for ransom notes
                if self._check_ransom_note_patterns(file_path):
                    results["found_behaviors"].append({
                        "type": "ransom_note",
                        "path": file_path,
                        "severity": "high"
                    })
                    if results["severity"] != "high":
                        results["severity"] = "high"
        
        # Check for process behaviors
        process_behaviors = sample_data.get("analysis", {}).get("behaviors", {}).get("processes", [])
        
        for process in process_behaviors:
            if "command_line" in process:
                # Check for suspicious commands
                suspicious_pattern = self.process_monitor._check_suspicious_command(process["command_line"])
                if suspicious_pattern:
                    results["found_behaviors"].append({
                        "type": "suspicious_command",
                        "process_name": process.get("name", "unknown"),
                        "command_line": process["command_line"],
                        "pattern": suspicious_pattern,
                        "severity": "high"
                    })
                    if results["severity"] != "high":
                        results["severity"] = "high"
                
                # Check for security tool termination
                if self.process_monitor._check_security_tool_termination(
                    process.get("name", ""), process["command_line"]):
                    results["found_behaviors"].append({
                        "type": "security_tool_termination",
                        "process_name": process.get("name", "unknown"),
                        "command_line": process["command_line"],
                        "severity": "high"
                    })
                    if results["severity"] != "high":
                        results["severity"] = "high"
        
        # Add overall conclusion based on severity and behaviors
        if results["severity"] == "high":
            results["conclusion"] = "Likely ransomware - high confidence"
        elif results["severity"] == "medium":
            results["conclusion"] = "Possible ransomware - medium confidence"
        else:
            results["conclusion"] = "No clear ransomware indicators found"
        
        return results
    
    def _check_extension_patterns(self, file_path: str) -> bool:
        """
        Check if file has a known ransomware extension
        
        Args:
            file_path: Path to check
            
        Returns:
            True if extension matches ransomware pattern, False otherwise
        """
        extension = os.path.splitext(file_path)[1].lower()
        return extension in self.filesystem_monitor.config["ransomware_extensions"]
    
    def _check_ransom_note_patterns(self, file_path: str) -> bool:
        """
        Check if file matches a ransom note pattern
        
        Args:
            file_path: Path to check
            
        Returns:
            True if file matches ransom note pattern, False otherwise
        """
        filename = os.path.basename(file_path)
        for pattern in self.filesystem_monitor.config["ransom_note_patterns"]:
            if re.match(pattern, filename, re.IGNORECASE):
                return True
        return False


def alert_to_json(alert_file, alert_data):
    """
    Write alert to JSON file
    
    Args:
        alert_file: File to write to
        alert_data: Alert data dictionary
    """
    with open(alert_file, 'a') as f:
        f.write(json.dumps(alert_data) + '\n')


def main():
    """Main function for command-line usage"""
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description="Ransomware Behavior Detector")
    parser.add_argument('--config', '-c', help='Path to configuration file')
    parser.add_argument('--monitor', '-m', action='store_true', help='Start live monitoring')
    parser.add_argument('--analyze', '-a', help='Analyze a sample JSON file')
    parser.add_argument('--output', '-o', help='Output file for analysis results')
    parser.add_argument('--alert-file', help='File to write alerts to')
    
    args = parser.parse_args()
    
    if not args.monitor and not args.analyze:
        parser.print_help()
        sys.exit(1)
    
    detector = RansomwareBehaviorDetector(args.config)
    
    if args.alert_file:
        detector.register_alert_handler(lambda alert: alert_to_json(args.alert_file, alert))
    
    if args.analyze:
        try:
            with open(args.analyze, 'r') as f:
                sample_data = json.load(f)
            
            results = detector.analyze_sample(sample_data)
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
            else:
                print(json.dumps(results, indent=2))
                
            # Return success or failure based on severity
            if results["severity"] == "high":
                sys.exit(2)  # High severity
            elif results["severity"] == "medium":
                sys.exit(1)  # Medium severity
            else:
                sys.exit(0)  # Low severity
                
        except Exception as e:
            logger.error(f"Error analyzing sample: {e}")
            sys.exit(3)
    
    if args.monitor:
        try:
            detector.start()
            
            # Register console alert handler
            detector.register_alert_handler(lambda alert: print(f"ALERT: {json.dumps(alert)}"))
            
            print("Monitoring started. Press Ctrl+C to stop.")
            
            # Keep the main thread alive
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\nStopping monitoring...")
            detector.stop()
        except Exception as e:
            logger.error(f"Error in monitoring: {e}")
            detector.stop()
            sys.exit(1)
    
    sys.exit(0)


if __name__ == "__main__":
    # Import math here to avoid module-level import issues
    import math
    main()