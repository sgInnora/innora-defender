#!/usr/bin/env python3
"""
Real-time Ransomware Variant Monitoring System

This module provides a real-time monitoring system for ransomware family detection
and variant analysis, supporting continuous updates and alerts.
"""

import os
import sys
import json
import time
import queue
import hashlib
import logging
import threading
import datetime
from typing import Dict, List, Any, Optional, Callable, Tuple, Set

# Add parent directory to path to import from threat_intel
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)
sys.path.append(parent_dir)

from family_detection.integration_with_variant import AdvancedFamilyDetectionIntegration
from family_detection.auto_variant_detector import process_sample_batch

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('realtime_monitor')

class RealtimeMonitor:
    """
    Real-time monitoring system for ransomware detection
    
    This class provides continuous monitoring of incoming samples,
    identifying ransomware families and variants, and generating
    alerts and updates for new variants.
    """
    
    def __init__(self, 
                families_dir: Optional[str] = None,
                yara_rules_dir: Optional[str] = None,
                clusters_dir: Optional[str] = None,
                update_interval: int = 3600,
                batch_size: int = 10,
                alert_threshold: float = 0.7,
                auto_update: bool = True,
                auto_generate_rules: bool = True,
                update_callback: Optional[Callable] = None):
        """
        Initialize the real-time monitor
        
        Args:
            families_dir: Directory containing family definition files
            yara_rules_dir: Directory containing YARA rules
            clusters_dir: Directory containing variant clusters
            update_interval: Interval in seconds for batch processing and updates (default: 1 hour)
            batch_size: Number of samples to process in each batch
            alert_threshold: Confidence threshold for generating alerts (0.0 to 1.0)
            auto_update: Whether to automatically update family definitions
            auto_generate_rules: Whether to automatically generate detection rules for new variants
            update_callback: Optional callback function to notify when updates are available
        """
        # Initialize integration with family detection and variant detection
        self.detection = AdvancedFamilyDetectionIntegration(
            families_dir=families_dir,
            yara_rules_dir=yara_rules_dir,
            clusters_dir=clusters_dir,
            auto_variant_detection=True,
            similarity_threshold=0.75,
            cohesion_threshold=0.7,
            min_variant_samples=2
        )
        
        # Initialize data directory
        self.data_dir = os.path.join(parent_dir, 'data')
        self.cache_dir = os.path.join(self.data_dir, 'cache')
        self.alert_dir = os.path.join(self.data_dir, 'alerts')
        self.stats_dir = os.path.join(self.data_dir, 'stats')
        
        # Create directories if they don't exist
        for directory in [self.cache_dir, self.alert_dir, self.stats_dir]:
            os.makedirs(directory, exist_ok=True)
        
        # Initialize configuration
        self.update_interval = update_interval
        self.batch_size = batch_size
        self.alert_threshold = alert_threshold
        self.auto_update = auto_update
        self.auto_generate_rules = auto_generate_rules
        self.update_callback = update_callback
        
        # Initialize sample queues
        self.sample_queue = queue.Queue()
        self.sample_batch = []
        self.processed_samples = set()
        
        # Initialize monitoring statistics
        self.stats = {
            "start_time": datetime.datetime.now().isoformat(),
            "samples_processed": 0,
            "families_detected": 0,
            "variants_detected": 0,
            "new_variants_detected": 0,
            "alerts_generated": 0,
            "updates_performed": 0,
            "last_update": None,
            "family_counts": {},
            "variant_counts": {}
        }
        
        # Initialize monitoring thread
        self.monitoring_active = False
        self.monitor_thread = None
        
        logger.info("Real-time monitor initialized")
    
    def start(self):
        """Start the monitoring thread"""
        if self.monitoring_active:
            logger.warning("Monitor is already running")
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        logger.info("Real-time monitoring started")
    
    def stop(self):
        """Stop the monitoring thread"""
        if not self.monitoring_active:
            logger.warning("Monitor is not running")
            return
        
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10)
        
        # Process any remaining samples
        self._process_batch(force=True)
        
        # Save final statistics
        self._save_statistics()
        
        logger.info("Real-time monitoring stopped")
    
    def submit_sample(self, sample_data: Dict[str, Any]) -> bool:
        """
        Submit a sample for analysis
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            True if sample was successfully queued, False otherwise
        """
        try:
            # Generate sample ID
            sample_id = sample_data.get("sha256", 
                hashlib.sha256(json.dumps(sample_data).encode()).hexdigest()
            )
            
            # Skip if already processed
            if sample_id in self.processed_samples:
                logger.info(f"Sample {sample_id} already processed, skipping")
                return False
            
            # Add to queue
            self.sample_queue.put((sample_id, sample_data))
            logger.info(f"Sample {sample_id} queued for processing")
            
            return True
            
        except Exception as e:
            logger.error(f"Error submitting sample: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get current monitoring statistics
        
        Returns:
            Dictionary containing monitoring statistics
        """
        # Update with current queue size
        current_stats = self.stats.copy()
        current_stats["queue_size"] = self.sample_queue.qsize() + len(self.sample_batch)
        current_stats["uptime_seconds"] = (
            datetime.datetime.now() - 
            datetime.datetime.fromisoformat(self.stats["start_time"])
        ).total_seconds()
        
        return current_stats
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        last_batch_time = time.time()
        
        while self.monitoring_active:
            try:
                # Check if it's time to process a batch
                current_time = time.time()
                if (current_time - last_batch_time >= self.update_interval or 
                        len(self.sample_batch) >= self.batch_size):
                    self._process_batch()
                    last_batch_time = current_time
                
                # Get a sample from the queue with a timeout
                try:
                    sample_id, sample_data = self.sample_queue.get(timeout=1)
                    self.sample_batch.append((sample_id, sample_data))
                    self.sample_queue.task_done()
                except queue.Empty:
                    # No sample available, continue loop
                    continue
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(5)  # Wait before retrying
    
    def _process_batch(self, force: bool = False):
        """
        Process a batch of samples
        
        Args:
            force: Whether to force processing even if batch is not full
        """
        # Skip if batch is empty
        if not self.sample_batch:
            return
        
        # Skip if batch is not full and not forced
        if len(self.sample_batch) < self.batch_size and not force:
            return
        
        logger.info(f"Processing batch of {len(self.sample_batch)} samples")
        
        try:
            # Extract sample data
            sample_ids = []
            samples = []
            
            for sample_id, sample_data in self.sample_batch:
                sample_ids.append(sample_id)
                samples.append(sample_data)
            
            # Process samples individually first
            processed_results = []
            for i, sample_data in enumerate(samples):
                try:
                    result = self.detection.identify_ransomware_family(sample_data)
                    processed_results.append({
                        "sample_id": sample_ids[i],
                        "results": result
                    })
                    
                    # Update statistics
                    self.stats["samples_processed"] += 1
                    
                    # Check if ransomware family was identified
                    if result:
                        # Update family counts
                        for family in result:
                            family_name = family.get("family_name", "unknown")
                            if family_name in self.stats["family_counts"]:
                                self.stats["family_counts"][family_name] += 1
                            else:
                                self.stats["family_counts"][family_name] = 1
                                self.stats["families_detected"] += 1
                            
                            # Check for variant
                            if "variant" in family:
                                variant_name = family.get("variant", "unknown")
                                variant_key = f"{family_name}:{variant_name}"
                                
                                if variant_key in self.stats["variant_counts"]:
                                    self.stats["variant_counts"][variant_key] += 1
                                else:
                                    self.stats["variant_counts"][variant_key] = 1
                                    self.stats["variants_detected"] += 1
                                
                                # Check if new variant
                                if family.get("is_new_variant", False):
                                    self._handle_new_variant(family, sample_data)
                except Exception as e:
                    logger.error(f"Error processing individual sample {sample_ids[i]}: {e}")
            
            # Process batch with variant detector
            if self.detection.variant_detector:
                batch_result = process_sample_batch(self.detection.variant_detector, samples)
                
                # Handle new variants
                if batch_result.get("new_variants"):
                    for new_variant in batch_result.get("new_variants", []):
                        self._generate_variant_alert(new_variant)
                
                # Check valid variants
                if batch_result.get("valid_variants"):
                    self._update_variant_definitions(batch_result.get("valid_variants", []))
            
            # Mark samples as processed
            self.processed_samples.update(sample_ids)
            
            # Save statistics
            self._save_statistics()
            
            # Clear batch
            self.sample_batch = []
            
        except Exception as e:
            logger.error(f"Error processing batch: {e}")
    
    def _handle_new_variant(self, family: Dict[str, Any], sample_data: Dict[str, Any]):
        """
        Handle a newly detected variant
        
        Args:
            family: Family detection result
            sample_data: Sample analysis data
        """
        # Update statistics
        self.stats["new_variants_detected"] += 1
        
        # Generate alert if confidence is above threshold
        if family.get("variant_confidence", 0) >= self.alert_threshold:
            self._generate_variant_alert({
                "sample_id": sample_data.get("sha256", "unknown"),
                "base_family": family.get("family_id", "unknown"),
                "variant_name": family.get("variant", "unknown"),
                "cluster_id": family.get("variant_cluster_id", "unknown"),
                "confidence": family.get("variant_confidence", 0)
            })
    
    def _generate_variant_alert(self, variant_info: Dict[str, Any]):
        """
        Generate an alert for a new variant
        
        Args:
            variant_info: Variant information
        """
        # Update statistics
        self.stats["alerts_generated"] += 1
        
        # Create alert data
        alert = {
            "timestamp": datetime.datetime.now().isoformat(),
            "type": "new_variant",
            "severity": "high" if variant_info.get("confidence", 0) > 0.8 else "medium",
            "variant_info": variant_info,
            "action_required": True,
            "suggested_actions": [
                "Review variant definition for accuracy",
                "Test detection rules against samples",
                "Check for false positives"
            ]
        }
        
        # Generate alert file
        alert_id = hashlib.md5(json.dumps(variant_info).encode()).hexdigest()[:8]
        alert_file = os.path.join(
            self.alert_dir, 
            f"variant_alert_{variant_info.get('base_family', 'unknown')}_{alert_id}.json"
        )
        
        with open(alert_file, 'w') as f:
            json.dump(alert, f, indent=2)
        
        logger.info(f"Generated variant alert: {alert_file}")
        
        # Trigger callback if provided
        if self.update_callback:
            try:
                self.update_callback("new_variant_alert", alert)
            except Exception as e:
                logger.error(f"Error in update callback: {e}")
    
    def _update_variant_definitions(self, valid_variants: List[Dict[str, Any]]):
        """
        Update variant definitions based on valid variants
        
        Args:
            valid_variants: List of valid variant information
        """
        if not self.auto_update:
            logger.info("Auto-update is disabled, skipping definition updates")
            return
        
        # Filter variants with high confidence
        high_confidence_variants = [
            variant for variant in valid_variants
            if variant.get("confidence", 0) >= self.alert_threshold
        ]
        
        if not high_confidence_variants:
            logger.info("No high-confidence variants found for updates")
            return
        
        try:
            # Update variant definitions
            saved_files = self.detection.save_variant_definitions()
            
            if saved_files:
                # Update statistics
                self.stats["updates_performed"] += 1
                self.stats["last_update"] = datetime.datetime.now().isoformat()
                
                # Generate detection rules if enabled
                if self.auto_generate_rules:
                    self._generate_detection_rules(high_confidence_variants)
                
                # Trigger callback if provided
                if self.update_callback:
                    try:
                        self.update_callback("definition_update", {
                            "timestamp": self.stats["last_update"],
                            "variants_updated": len(saved_files),
                            "files": saved_files
                        })
                    except Exception as e:
                        logger.error(f"Error in update callback: {e}")
                
                logger.info(f"Updated {len(saved_files)} variant definitions")
        except Exception as e:
            logger.error(f"Error updating variant definitions: {e}")
    
    def _generate_detection_rules(self, variants: List[Dict[str, Any]]):
        """
        Generate detection rules for variants
        
        Args:
            variants: List of variant information
        """
        try:
            # Import YARA rule generator here to avoid circular imports
            from rules.yara_generator import YaraRuleGenerator
            
            # Check for YARA rules directory
            if not hasattr(self.detection.enhanced_detector, 'yara_rules_dir') or not self.detection.enhanced_detector.yara_rules_dir:
                logger.warning("YARA rules directory not configured, skipping rule generation")
                return
            
            # Initialize generator
            generator = YaraRuleGenerator(
                output_dir=self.detection.enhanced_detector.yara_rules_dir
            )
            
            # Generate rules for each variant
            for variant in variants:
                cluster_id = variant.get("cluster_id")
                if not cluster_id or cluster_id not in self.detection.variant_detector.clusters:
                    continue
                
                # Get variant definition
                definition = self.detection.variant_detector.generate_variant_definition(cluster_id)
                if not definition:
                    continue
                
                # Generate YARA rule
                try:
                    rule = generator.generate_rule_from_family_definition(definition)
                    logger.info(f"Generated YARA rule for variant {variant.get('variant_name', 'unknown')}")
                except Exception as e:
                    logger.error(f"Error generating YARA rule for variant {variant.get('variant_name', 'unknown')}: {e}")
            
        except (ImportError, Exception) as e:
            logger.error(f"Error generating detection rules: {e}")
    
    def _save_statistics(self):
        """Save monitoring statistics to file"""
        try:
            # Create statistics file
            stats_file = os.path.join(self.stats_dir, "monitoring_stats.json")
            
            with open(stats_file, 'w') as f:
                json.dump(self.stats, f, indent=2)
            
            logger.debug("Monitoring statistics saved")
        except Exception as e:
            logger.error(f"Error saving statistics: {e}")
    
    def get_recent_alerts(self, count: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent variant alerts
        
        Args:
            count: Maximum number of alerts to return
            
        Returns:
            List of recent alerts
        """
        alerts = []
        
        try:
            # List alert files
            alert_files = []
            for filename in os.listdir(self.alert_dir):
                if filename.startswith("variant_alert_") and filename.endswith(".json"):
                    filepath = os.path.join(self.alert_dir, filename)
                    alert_files.append((
                        os.path.getmtime(filepath),
                        filepath
                    ))
            
            # Sort by modification time (newest first)
            alert_files.sort(reverse=True)
            
            # Load alerts
            for _, filepath in alert_files[:count]:
                with open(filepath, 'r') as f:
                    alert = json.load(f)
                    alerts.append(alert)
        except Exception as e:
            logger.error(f"Error getting recent alerts: {e}")
        
        return alerts
    
    def perform_maintenance(self):
        """Perform maintenance tasks"""
        try:
            # Clear old cache files
            cache_expiry = 7 * 24 * 60 * 60  # 7 days in seconds
            current_time = time.time()
            
            for filename in os.listdir(self.cache_dir):
                filepath = os.path.join(self.cache_dir, filename)
                if os.path.isfile(filepath) and current_time - os.path.getmtime(filepath) > cache_expiry:
                    os.remove(filepath)
            
            # Evaluate clusters
            if self.detection.variant_detector:
                self.detection.variant_detector.evaluate_clusters()
            
            # Save statistics
            self._save_statistics()
            
            logger.info("Maintenance completed")
        except Exception as e:
            logger.error(f"Error performing maintenance: {e}")


def create_monitor(config_file: Optional[str] = None) -> RealtimeMonitor:
    """
    Create a real-time monitor instance
    
    Args:
        config_file: Path to configuration file
        
    Returns:
        RealtimeMonitor instance
    """
    # Default configuration
    config = {
        "families_dir": os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                     "data", "families"),
        "yara_rules_dir": os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                      "data", "yara_rules"),
        "clusters_dir": os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                    "data", "variant_clusters"),
        "update_interval": 3600,  # 1 hour
        "batch_size": 10,
        "alert_threshold": 0.7,
        "auto_update": True,
        "auto_generate_rules": True
    }
    
    # Load configuration if provided
    if config_file and os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                loaded_config = json.load(f)
                config.update(loaded_config)
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
    
    # Create monitor instance
    monitor = RealtimeMonitor(
        families_dir=config["families_dir"],
        yara_rules_dir=config["yara_rules_dir"],
        clusters_dir=config["clusters_dir"],
        update_interval=config["update_interval"],
        batch_size=config["batch_size"],
        alert_threshold=config["alert_threshold"],
        auto_update=config["auto_update"],
        auto_generate_rules=config["auto_generate_rules"]
    )
    
    return monitor


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Real-time Ransomware Variant Monitoring System")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--families-dir", help="Directory containing family definitions")
    parser.add_argument("--yara-rules-dir", help="Directory containing YARA rules")
    parser.add_argument("--clusters-dir", help="Directory containing variant clusters")
    parser.add_argument("--update-interval", type=int, default=3600, help="Update interval in seconds")
    parser.add_argument("--batch-size", type=int, default=10, help="Batch size for processing")
    parser.add_argument("--alert-threshold", type=float, default=0.7, help="Threshold for generating alerts")
    parser.add_argument("--no-auto-update", action="store_true", help="Disable automatic updates")
    parser.add_argument("--no-auto-rules", action="store_true", help="Disable automatic rule generation")
    
    args = parser.parse_args()
    
    # Create configuration
    config = {
        "families_dir": args.families_dir,
        "yara_rules_dir": args.yara_rules_dir,
        "clusters_dir": args.clusters_dir,
        "update_interval": args.update_interval,
        "batch_size": args.batch_size,
        "alert_threshold": args.alert_threshold,
        "auto_update": not args.no_auto_update,
        "auto_generate_rules": not args.no_auto_rules
    }
    
    # Remove None values
    config = {k: v for k, v in config.items() if v is not None}
    
    # Create monitor
    monitor = create_monitor(args.config)
    
    # Update configuration
    for key, value in config.items():
        setattr(monitor, key, value)
    
    # Start monitor
    monitor.start()
    
    try:
        # Run until interrupted
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping monitor...")
        monitor.stop()