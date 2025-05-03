#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Memory Scanner Orchestrator for Ransomware Analysis

This module provides a unified interface for memory analysis by coordinating
multiple scanners and integrating their results. It orchestrates the execution
of YARA scanning, pattern-based scanning, and cryptographic pattern matching.
"""

import os
import sys
import logging
import json
import argparse
import tempfile
from typing import List, Dict, Any, Optional, Union, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import importlib.util

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('MemoryScannerOrchestrator')

class MemoryScannerOrchestrator:
    """
    Orchestrates multiple memory scanners and integrates their results.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the orchestrator with optional configuration.
        
        Args:
            config: Configuration dictionary with scanner settings
        """
        self.config = config or {}
        self.results = {}
        self.scanners = {}
        
        # Default scanner weights for combined scoring
        self.scanner_weights = {
            "yara": 1.0,
            "pattern": 0.8,
            "crypto": 0.9
        }
        
        # Initialize scanners
        self._initialize_scanners()
    
    def _initialize_scanners(self) -> None:
        """Initialize all available memory scanners."""
        try:
            # Import scanners - first check if they're available
            scanners_to_load = []
            
            # Check for YARA scanner
            yara_scanner_path = os.path.join(os.path.dirname(__file__), 'yara_mem_scanner.py')
            if os.path.exists(yara_scanner_path):
                scanners_to_load.append(('yara', yara_scanner_path, 'YaraMemScanner'))
            else:
                logger.warning("YARA memory scanner not found at %s", yara_scanner_path)
            
            # Check for Pattern Key Scanner
            pattern_scanner_path = os.path.join(os.path.dirname(__file__), 'pattern_key_scanner.py')
            if os.path.exists(pattern_scanner_path):
                scanners_to_load.append(('pattern', pattern_scanner_path, 'PatternKeyScanner'))
            else:
                logger.warning("Pattern Key Scanner not found at %s", pattern_scanner_path)
            
            # Check for Crypto Pattern Matcher
            crypto_scanner_path = os.path.join(os.path.dirname(__file__), 'crypto_pattern_matcher.py')
            if os.path.exists(crypto_scanner_path):
                scanners_to_load.append(('crypto', crypto_scanner_path, 'CryptoPatternMatcher'))
            else:
                logger.warning("Crypto Pattern Matcher not found at %s", crypto_scanner_path)
            
            # Load scanners dynamically
            for scanner_id, path, class_name in scanners_to_load:
                try:
                    # Load module dynamically
                    spec = importlib.util.spec_from_file_location(scanner_id, path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Get scanner class and create instance
                    scanner_class = getattr(module, class_name)
                    
                    # Pass any config specific to this scanner
                    scanner_config = self.config.get(scanner_id, {})
                    
                    # Initialize scanner with appropriate parameters based on its type
                    if scanner_id == 'yara':
                        # YARA scanner might need custom rules dir
                        rules_dir = scanner_config.get('rules_dir')
                        self.scanners[scanner_id] = scanner_class(rules_dir=rules_dir)
                    elif scanner_id == 'pattern':
                        # Pattern scanner may need entropy threshold
                        min_entropy = scanner_config.get('min_entropy', 7.0)
                        chunk_size = scanner_config.get('chunk_size', 10*1024*1024)
                        self.scanners[scanner_id] = scanner_class(min_entropy=min_entropy, chunk_size=chunk_size)
                    elif scanner_id == 'crypto':
                        # Crypto scanner may need chunk size
                        chunk_size = scanner_config.get('chunk_size', 10*1024*1024)
                        self.scanners[scanner_id] = scanner_class(chunk_size=chunk_size)
                    else:
                        # Generic initialization
                        self.scanners[scanner_id] = scanner_class()
                    
                    logger.info(f"Successfully loaded scanner: {scanner_id}")
                    
                except Exception as e:
                    logger.error(f"Error loading scanner {scanner_id} from {path}: {e}")
        
        except Exception as e:
            logger.error(f"Error initializing scanners: {e}")
            
    def set_scanner_weight(self, scanner_id: str, weight: float) -> None:
        """
        Set the weight for a specific scanner for result integration.
        
        Args:
            scanner_id: ID of the scanner
            weight: Weight value between 0.0 and 1.0
        """
        if scanner_id in self.scanners:
            self.scanner_weights[scanner_id] = max(0.0, min(1.0, weight))
            logger.info(f"Set weight for scanner {scanner_id} to {weight}")
        else:
            logger.warning(f"Cannot set weight for unknown scanner: {scanner_id}")
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Scan a memory dump file using all available scanners.
        
        Args:
            file_path: Path to the memory dump file
            
        Returns:
            Dictionary with integrated results
        """
        self.results = {}
        
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return self.results
            
        file_size = os.path.getsize(file_path)
        logger.info(f"Scanning file: {file_path} ({file_size/1024/1024:.2f} MB)")
        
        # Run scanners in parallel using threads
        with ThreadPoolExecutor(max_workers=min(len(self.scanners), 3)) as executor:
            future_to_scanner = {}
            
            for scanner_id, scanner in self.scanners.items():
                logger.info(f"Starting {scanner_id} scanner...")
                future = executor.submit(self._run_scanner, scanner_id, scanner, file_path)
                future_to_scanner[future] = scanner_id
            
            # Collect results as they complete
            for future in as_completed(future_to_scanner):
                scanner_id = future_to_scanner[future]
                try:
                    scanner_results = future.result()
                    self.results[scanner_id] = scanner_results
                    logger.info(f"Completed {scanner_id} scanner: found {len(scanner_results)} results")
                except Exception as e:
                    logger.error(f"Error running {scanner_id} scanner: {e}")
                    self.results[scanner_id] = []
        
        # Integrate results from different scanners
        integrated_results = self._integrate_results()
        
        return integrated_results
    
    def _run_scanner(self, scanner_id: str, scanner: Any, file_path: str) -> List[Dict[str, Any]]:
        """
        Run a specific scanner on the file.
        
        Args:
            scanner_id: ID of the scanner
            scanner: Scanner instance
            file_path: Path to the file to scan
            
        Returns:
            Scanner results
        """
        try:
            return scanner.scan_file(file_path)
        except Exception as e:
            logger.error(f"Error running {scanner_id} scanner: {e}")
            return []
    
    def scan_process(self, pid: int) -> Dict[str, Any]:
        """
        Scan a running process using all available scanners.
        
        Args:
            pid: Process ID to scan
            
        Returns:
            Dictionary with integrated results
        """
        self.results = {}
        
        logger.info(f"Scanning process with PID: {pid}")
        
        # Run scanners in parallel using threads
        with ThreadPoolExecutor(max_workers=min(len(self.scanners), 3)) as executor:
            future_to_scanner = {}
            
            for scanner_id, scanner in self.scanners.items():
                logger.info(f"Starting {scanner_id} scanner...")
                # Check if the scanner supports process scanning
                if hasattr(scanner, 'scan_process_memory'):
                    future = executor.submit(scanner.scan_process_memory, pid)
                    future_to_scanner[future] = scanner_id
                else:
                    logger.warning(f"Scanner {scanner_id} does not support process memory scanning")
            
            # Collect results as they complete
            for future in as_completed(future_to_scanner):
                scanner_id = future_to_scanner[future]
                try:
                    scanner_results = future.result()
                    self.results[scanner_id] = scanner_results
                    logger.info(f"Completed {scanner_id} scanner: found {len(scanner_results)} results")
                except Exception as e:
                    logger.error(f"Error running {scanner_id} scanner: {e}")
                    self.results[scanner_id] = []
        
        # Integrate results from different scanners
        integrated_results = self._integrate_results()
        
        return integrated_results
    
    def _integrate_results(self) -> Dict[str, Any]:
        """
        Integrate results from different scanners.
        
        Returns:
            Integrated results dictionary
        """
        integrated = {
            "scan_time": datetime.now().isoformat(),
            "summary": {
                "total_findings": 0,
                "scanners_used": list(self.results.keys()),
                "findings_by_type": {},
                "findings_by_family": {},
                "findings_by_confidence": {
                    "high": 0,
                    "medium": 0,
                    "low": 0
                },
                "potential_encryption_keys": 0,
                "potential_ransomware_markers": 0
            },
            "raw_results": self.results,
            "integrated_findings": []
        }
        
        # Process each scanner's results
        all_findings = []
        scanner_counts = {}
        
        for scanner_id, findings in self.results.items():
            scanner_counts[scanner_id] = len(findings)
            integrated["summary"]["total_findings"] += len(findings)
            
            for finding in findings:
                # Normalize the finding with scanner info
                normalized = self._normalize_finding(finding, scanner_id)
                all_findings.append(normalized)
                
                # Update summary counts
                finding_type = normalized.get("type", "unknown")
                integrated["summary"]["findings_by_type"][finding_type] = integrated["summary"]["findings_by_type"].get(finding_type, 0) + 1
                
                # Count by family if present
                family = normalized.get("family")
                if family:
                    integrated["summary"]["findings_by_family"][family] = integrated["summary"]["findings_by_family"].get(family, 0) + 1
                
                # Count by confidence level
                confidence = normalized.get("confidence", 0)
                if confidence >= 0.75:
                    integrated["summary"]["findings_by_confidence"]["high"] += 1
                elif confidence >= 0.5:
                    integrated["summary"]["findings_by_confidence"]["medium"] += 1
                else:
                    integrated["summary"]["findings_by_confidence"]["low"] += 1
                    
                # Count encryption keys
                if "key" in finding_type.lower() or finding_type == "crypto_constant":
                    integrated["summary"]["potential_encryption_keys"] += 1
                
                # Count ransomware markers
                if "ransomware" in finding_type.lower() or family:
                    integrated["summary"]["potential_ransomware_markers"] += 1
        
        # Add scanner_counts to summary
        integrated["summary"]["scanner_counts"] = scanner_counts
        
        # Group related findings and sort by combined confidence score
        grouped_findings = self._group_related_findings(all_findings)
        grouped_findings.sort(key=lambda x: x.get("combined_score", 0), reverse=True)
        
        integrated["integrated_findings"] = grouped_findings
        
        # Add a ransomware detection summary
        ransomware_families = integrated["summary"]["findings_by_family"]
        if ransomware_families:
            integrated["detection_summary"] = self._generate_detection_summary(ransomware_families, grouped_findings)
        
        return integrated
    
    def _normalize_finding(self, finding: Dict[str, Any], scanner_id: str) -> Dict[str, Any]:
        """
        Normalize a finding from a specific scanner to a standard format.
        
        Args:
            finding: Original finding from a scanner
            scanner_id: ID of the scanner that produced this finding
            
        Returns:
            Normalized finding dictionary
        """
        # Create a copy to avoid modifying the original
        normalized = dict(finding)
        
        # Add scanner information
        normalized["scanner"] = scanner_id
        normalized["scanner_weight"] = self.scanner_weights.get(scanner_id, 0.5)
        
        # Ensure standard fields exist
        if "confidence" not in normalized:
            normalized["confidence"] = 0.5  # Default confidence
            
        # Apply scanner weight to confidence
        normalized["weighted_confidence"] = normalized["confidence"] * normalized["scanner_weight"]
        
        # Ensure type field exists
        if "type" not in normalized:
            if scanner_id == "yara":
                normalized["type"] = "yara_match"
            elif scanner_id == "pattern":
                normalized["type"] = "pattern_match"
            elif scanner_id == "crypto":
                normalized["type"] = "crypto_match"
            else:
                normalized["type"] = "unknown"
                
        # Add timestamp
        normalized["timestamp"] = datetime.now().isoformat()
        
        return normalized
    
    def _group_related_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Group related findings together based on common attributes.
        
        Args:
            findings: List of normalized findings
            
        Returns:
            List of grouped findings
        """
        if not findings:
            return []
            
        # First, group by offset/address if available
        offset_groups = {}
        
        for finding in findings:
            offset = finding.get("offset")
            if offset is not None:
                # Check for nearby offsets (within 128 bytes)
                found_group = False
                for group_offset in list(offset_groups.keys()):
                    if abs(offset - group_offset) <= 128:
                        offset_groups[group_offset].append(finding)
                        found_group = True
                        break
                
                if not found_group:
                    offset_groups[offset] = [finding]
            
        # Next, group by family if available
        family_groups = {}
        
        for finding in findings:
            family = finding.get("family")
            if family and family != "Generic":
                if family not in family_groups:
                    family_groups[family] = []
                family_groups[family].append(finding)
        
        # Combine groups
        all_groups = []
        
        # Add offset-based groups
        for offset, group_findings in offset_groups.items():
            if len(group_findings) > 1:  # Only create groups with multiple findings
                combined_score = sum(f.get("weighted_confidence", 0) for f in group_findings)
                combined_score = min(1.0, combined_score)  # Cap at 1.0
                
                # Determine the primary type and family
                type_counts = {}
                family_counts = {}
                
                for f in group_findings:
                    f_type = f.get("type", "unknown")
                    type_counts[f_type] = type_counts.get(f_type, 0) + 1
                    
                    f_family = f.get("family")
                    if f_family:
                        family_counts[f_family] = family_counts.get(f_family, 0) + 1
                
                primary_type = max(type_counts.items(), key=lambda x: x[1])[0]
                primary_family = None
                if family_counts:
                    primary_family = max(family_counts.items(), key=lambda x: x[1])[0]
                
                group = {
                    "type": "finding_group",
                    "group_type": "memory_region",
                    "primary_finding_type": primary_type,
                    "offset": offset,
                    "findings_count": len(group_findings),
                    "findings": group_findings,
                    "combined_score": combined_score,
                    "scanners_involved": list(set(f.get("scanner") for f in group_findings))
                }
                
                if primary_family:
                    group["family"] = primary_family
                    
                all_groups.append(group)
        
        # Add family-based groups
        for family, group_findings in family_groups.items():
            if len(group_findings) > 1:  # Only create groups with multiple findings
                # Check if this family is already covered by an offset group
                already_covered = False
                for group in all_groups:
                    if group.get("family") == family:
                        already_covered = True
                        break
                
                if not already_covered:
                    combined_score = sum(f.get("weighted_confidence", 0) for f in group_findings)
                    combined_score = min(1.0, combined_score)  # Cap at 1.0
                    
                    group = {
                        "type": "finding_group",
                        "group_type": "ransomware_family",
                        "family": family,
                        "findings_count": len(group_findings),
                        "findings": group_findings,
                        "combined_score": combined_score,
                        "scanners_involved": list(set(f.get("scanner") for f in group_findings))
                    }
                    all_groups.append(group)
        
        # Add ungrouped findings
        grouped_offsets = set()
        for group in all_groups:
            if group["group_type"] == "memory_region":
                grouped_offsets.add(group["offset"])
                for finding in group["findings"]:
                    finding_offset = finding.get("offset")
                    if finding_offset is not None:
                        grouped_offsets.add(finding_offset)
        
        grouped_families = set(group["family"] for group in all_groups if "family" in group)
        
        for finding in findings:
            offset = finding.get("offset")
            family = finding.get("family")
            
            if (offset is None or offset not in grouped_offsets) and (family is None or family not in grouped_families):
                # This is a standalone finding - add it as its own group
                all_groups.append({
                    "type": "finding",
                    "combined_score": finding.get("weighted_confidence", 0),
                    "finding": finding
                })
        
        return all_groups
    
    def _generate_detection_summary(self, ransomware_families: Dict[str, int], 
                                   grouped_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a summary of ransomware detections.
        
        Args:
            ransomware_families: Dictionary mapping family names to detection counts
            grouped_findings: List of grouped findings
            
        Returns:
            Detection summary dictionary
        """
        # Sort families by detection count
        sorted_families = sorted(ransomware_families.items(), key=lambda x: x[1], reverse=True)
        
        # Calculate overall detection confidence
        if not sorted_families:
            return {
                "ransomware_detected": False,
                "confidence": 0,
                "message": "No ransomware indicators detected"
            }
        
        primary_family, primary_count = sorted_families[0]
        
        # Find the highest-scoring group for this family
        family_groups = [g for g in grouped_findings if g.get("family") == primary_family]
        
        max_score = 0
        if family_groups:
            max_score = max(g.get("combined_score", 0) for g in family_groups)
        
        # Generate detection verdict
        if max_score >= 0.85:
            confidence = "high"
            verdict = "confirmed"
        elif max_score >= 0.7:
            confidence = "medium"
            verdict = "likely"
        elif max_score >= 0.5:
            confidence = "low"
            verdict = "possible"
        else:
            confidence = "very low"
            verdict = "uncertain"
            
        return {
            "ransomware_detected": max_score >= 0.5,
            "primary_family": primary_family,
            "confidence": confidence,
            "confidence_score": max_score,
            "verdict": verdict,
            "detection_count": primary_count,
            "all_families": [family for family, _ in sorted_families],
            "message": f"{verdict.capitalize()} {primary_family} ransomware detection with {confidence} confidence"
        }
    
    def save_results(self, output_file: str) -> None:
        """
        Save integrated results to a JSON file.
        
        Args:
            output_file: Path to save results to
        """
        if not hasattr(self, 'integrated_results'):
            logger.warning("No integrated results to save")
            return
            
        try:
            with open(output_file, 'w') as f:
                json.dump(self.integrated_results, f, indent=2)
                logger.info(f"Results saved to {output_file}")
                
        except Exception as e:
            logger.error(f"Error saving results: {e}")
    
    def export_yara_rules(self, output_dir: str) -> Optional[str]:
        """
        Export YARA rules based on findings for future detection.
        
        Args:
            output_dir: Directory to save generated YARA rules
            
        Returns:
            Path to the generated YARA rules file, or None if generation failed
        """
        if not hasattr(self, 'integrated_results') or not self.integrated_results:
            logger.warning("No results available for YARA rule generation")
            return None
            
        try:
            # Ensure output directory exists
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                
            # Generate a filename based on the scan time
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(output_dir, f"memory_scan_{timestamp}.yar")
            
            # Check which findings can be converted to YARA rules
            rule_count = 0
            
            with open(output_file, 'w') as f:
                f.write("// Automatically generated YARA rules from memory scanning\n")
                f.write(f"// Generated at: {datetime.now().isoformat()}\n\n")
                
                # Generate rules from high-confidence findings
                for finding_group in self.integrated_results.get("integrated_findings", []):
                    if finding_group.get("combined_score", 0) >= 0.7:
                        # For finding groups
                        if finding_group.get("type") == "finding_group":
                            rule = self._generate_yara_rule_from_group(finding_group, rule_count)
                            if rule:
                                f.write(rule + "\n\n")
                                rule_count += 1
                        # For individual findings
                        elif finding_group.get("type") == "finding":
                            finding = finding_group.get("finding", {})
                            rule = self._generate_yara_rule_from_finding(finding, rule_count)
                            if rule:
                                f.write(rule + "\n\n")
                                rule_count += 1
            
            if rule_count == 0:
                logger.warning("No suitable findings for YARA rule generation")
                os.remove(output_file)  # Remove empty file
                return None
                
            logger.info(f"Generated {rule_count} YARA rules in {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Error generating YARA rules: {e}")
            return None
    
    def _generate_yara_rule_from_group(self, group: Dict[str, Any], rule_index: int) -> Optional[str]:
        """
        Generate a YARA rule from a finding group.
        
        Args:
            group: Finding group dictionary
            rule_index: Index for rule naming
            
        Returns:
            YARA rule string or None if generation failed
        """
        try:
            family = group.get("family", "Unknown")
            group_type = group.get("group_type", "unknown")
            
            # Generate rule name
            rule_name = f"Auto_{family}_{group_type}_{rule_index}"
            # Clean rule name (only alphanumeric and underscore allowed)
            rule_name = ''.join(c if c.isalnum() or c == '_' else '_' for c in rule_name)
            
            # Create rule header
            rule = f"rule {rule_name} {{\n"
            rule += "    meta:\n"
            rule += f"        description = \"Auto-generated rule for {family} ransomware\"\n"
            rule += f"        author = \"Memory Scanner Orchestrator\"\n"
            rule += f"        date = \"{datetime.now().strftime('%Y-%m-%d')}\"\n"
            rule += f"        confidence = \"{'High' if group.get('combined_score', 0) >= 0.8 else 'Medium'}\"\n"
            
            # Add family and scanner info
            rule += f"        family = \"{family}\"\n"
            rule += f"        scanners = \"{', '.join(group.get('scanners_involved', []))}\"\n"
            rule += "    strings:\n"
            
            # Extract strings/patterns from findings
            string_count = 0
            for finding in group.get("findings", []):
                # Extract potential YARA strings
                if "sample" in finding:
                    # Convert hex string to bytes
                    try:
                        sample_bytes = bytes.fromhex(finding.get("sample"))
                        if len(sample_bytes) > 4:  # Only use reasonably sized patterns
                            rule += f"        $s{string_count} = {{ {' '.join(f'{b:02x}' for b in sample_bytes)} }}\n"
                            string_count += 1
                    except Exception:
                        pass
                elif "data_hex" in finding:
                    try:
                        data_bytes = bytes.fromhex(finding.get("data_hex"))
                        if len(data_bytes) > 4:  # Only use reasonably sized patterns
                            rule += f"        $s{string_count} = {{ {' '.join(f'{b:02x}' for b in data_bytes)} }}\n"
                            string_count += 1
                    except Exception:
                        pass
                elif "pattern" in finding:
                    pattern = finding.get("pattern")
                    if isinstance(pattern, bytes) and len(pattern) > 4:
                        rule += f"        $s{string_count} = {{ {' '.join(f'{b:02x}' for b in pattern)} }}\n"
                        string_count += 1
                
                # Also look for text strings
                for key in ["text", "string_value"]:
                    if key in finding and isinstance(finding[key], str) and len(finding[key]) > 4:
                        # Escape special characters
                        text = finding[key].replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
                        rule += f"        $t{string_count} = \"{text}\"\n"
                        string_count += 1
            
            # Add condition
            if string_count == 0:
                return None  # No strings added, can't generate a useful rule
                
            if string_count == 1:
                rule += "    condition:\n        any of them\n}"
            else:
                # For multiple strings, require at least 2 for higher confidence
                rule += "    condition:\n        2 of them\n}"
                
            return rule
            
        except Exception as e:
            logger.error(f"Error generating YARA rule from group: {e}")
            return None
    
    def _generate_yara_rule_from_finding(self, finding: Dict[str, Any], rule_index: int) -> Optional[str]:
        """
        Generate a YARA rule from an individual finding.
        
        Args:
            finding: Finding dictionary
            rule_index: Index for rule naming
            
        Returns:
            YARA rule string or None if generation failed
        """
        try:
            finding_type = finding.get("type", "unknown")
            family = finding.get("family", "Unknown")
            name = finding.get("name", finding_type)
            
            # Generate rule name
            rule_name = f"Auto_{family}_{name}_{rule_index}"
            # Clean rule name (only alphanumeric and underscore allowed)
            rule_name = ''.join(c if c.isalnum() or c == '_' else '_' for c in rule_name)
            
            # Create rule header
            rule = f"rule {rule_name} {{\n"
            rule += "    meta:\n"
            rule += f"        description = \"Auto-generated rule for {finding_type}\"\n"
            rule += f"        author = \"Memory Scanner Orchestrator\"\n"
            rule += f"        date = \"{datetime.now().strftime('%Y-%m-%d')}\"\n"
            
            # Add finding details
            if "description" in finding:
                rule += f"        info = \"{finding['description']}\"\n"
            if family:
                rule += f"        family = \"{family}\"\n"
                
            rule += f"        confidence = \"{finding.get('confidence', 0.5):.2f}\"\n"
            rule += "    strings:\n"
            
            # Extract strings/patterns
            has_string = False
            
            # Try various fields that might contain useful patterns
            for field, prefix in [
                ("sample", "$s"),
                ("data_hex", "$d"),
                ("pattern", "$p"),
                ("key_hex", "$k"),
                ("marker", "$m"),
                ("context_hex", "$c")
            ]:
                if field in finding:
                    try:
                        data = finding[field]
                        if isinstance(data, str):
                            # Try to convert hex string to bytes
                            try:
                                data_bytes = bytes.fromhex(data)
                                if len(data_bytes) > 4:  # Only use reasonably sized patterns
                                    rule += f"        {prefix}0 = {{ {' '.join(f'{b:02x}' for b in data_bytes)} }}\n"
                                    has_string = True
                            except ValueError:
                                # Not a hex string, use as text
                                if len(data) > 4:
                                    # Escape special characters
                                    text = data.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
                                    rule += f"        {prefix}0 = \"{text}\"\n"
                                    has_string = True
                        elif isinstance(data, bytes) and len(data) > 4:
                            rule += f"        {prefix}0 = {{ {' '.join(f'{b:02x}' for b in data)} }}\n"
                            has_string = True
                    except Exception as e:
                        logger.debug(f"Error processing field {field}: {e}")
                    
                    # Only need one good string
                    if has_string:
                        break
            
            # Add condition
            if not has_string:
                return None  # No strings added, can't generate a useful rule
                
            rule += "    condition:\n        any of them\n}"
            return rule
            
        except Exception as e:
            logger.error(f"Error generating YARA rule from finding: {e}")
            return None
    
    def check_ransomware_family(self, family_name: str) -> Dict[str, Any]:
        """
        Check results for specific ransomware family indicators.
        
        Args:
            family_name: Name of the ransomware family to check for
            
        Returns:
            Dictionary with family-specific information
        """
        if not hasattr(self, 'integrated_results') or not self.integrated_results:
            return {
                "family": family_name,
                "detected": False,
                "confidence": 0,
                "message": "No scan results available"
            }
            
        # Normalize family name for comparison
        family_name_norm = family_name.lower()
        
        # Find all findings related to this family
        family_findings = []
        
        for group in self.integrated_results.get("integrated_findings", []):
            if group.get("type") == "finding_group":
                group_family = group.get("family", "").lower()
                if group_family == family_name_norm:
                    family_findings.append(group)
                    
                # Also check individual findings in the group
                for finding in group.get("findings", []):
                    finding_family = finding.get("family", "").lower()
                    if finding_family == family_name_norm:
                        family_findings.append(finding)
            elif group.get("type") == "finding":
                finding = group.get("finding", {})
                finding_family = finding.get("family", "").lower()
                if finding_family == family_name_norm:
                    family_findings.append(finding)
        
        # Calculate max confidence
        max_confidence = 0
        if family_findings:
            for finding in family_findings:
                if "combined_score" in finding:
                    max_confidence = max(max_confidence, finding["combined_score"])
                elif "confidence" in finding:
                    max_confidence = max(max_confidence, finding["confidence"])
        
        # Generate verdict based on confidence
        if max_confidence >= 0.85:
            confidence_str = "high"
            verdict = "confirmed"
        elif max_confidence >= 0.7:
            confidence_str = "medium"
            verdict = "likely"
        elif max_confidence >= 0.5:
            confidence_str = "low"
            verdict = "possible"
        else:
            confidence_str = "very low"
            verdict = "uncertain"
        
        # Create result
        return {
            "family": family_name,
            "detected": max_confidence >= 0.5,
            "confidence": confidence_str,
            "confidence_score": max_confidence,
            "findings_count": len(family_findings),
            "verdict": verdict,
            "message": f"{verdict.capitalize()} {family_name} ransomware detection with {confidence_str} confidence"
        }
    
    def extract_potential_keys(self) -> List[Dict[str, Any]]:
        """
        Extract all potential encryption keys from scan results.
        
        Returns:
            List of potential key findings
        """
        if not hasattr(self, 'integrated_results') or not self.integrated_results:
            return []
            
        keys = []
        
        # Look for key-related findings in all groups
        for group in self.integrated_results.get("integrated_findings", []):
            if group.get("type") == "finding_group":
                for finding in group.get("findings", []):
                    if self._is_key_finding(finding):
                        keys.append(self._normalize_key_finding(finding))
            elif group.get("type") == "finding":
                finding = group.get("finding", {})
                if self._is_key_finding(finding):
                    keys.append(self._normalize_key_finding(finding))
        
        # Sort by confidence
        keys.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        
        return keys
    
    def _is_key_finding(self, finding: Dict[str, Any]) -> bool:
        """
        Check if a finding is related to an encryption key.
        
        Args:
            finding: Finding dictionary
            
        Returns:
            True if finding is key-related, False otherwise
        """
        finding_type = finding.get("type", "").lower()
        name = finding.get("name", "").lower()
        description = finding.get("description", "").lower()
        
        key_related_types = ["key", "crypto_constant", "high_entropy"]
        key_related_terms = ["key", "schedule", "sbox", "encryption", "aes", "rsa", "chacha", "salsa"]
        
        # Check type
        if any(term in finding_type for term in key_related_types):
            return True
            
        # Check name and description
        if any(term in name for term in key_related_terms):
            return True
            
        if any(term in description for term in key_related_terms):
            return True
            
        return False
    
    def _normalize_key_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a key-related finding.
        
        Args:
            finding: Finding dictionary
            
        Returns:
            Normalized key finding
        """
        key_finding = {
            "type": "potential_key",
            "key_type": self._determine_key_type(finding),
            "confidence": finding.get("confidence", 0.5),
            "offset": finding.get("offset"),
            "size": finding.get("size"),
            "source_scanner": finding.get("scanner", "unknown"),
            "description": finding.get("description", "Unknown key data")
        }
        
        # Extract the key data if available
        for field in ["key_hex", "data_hex", "sample"]:
            if field in finding:
                key_finding["key_data"] = finding[field]
                break
        
        # Add algorithm info if available
        algorithm = finding.get("algorithm")
        if algorithm:
            key_finding["algorithm"] = algorithm
            
        return key_finding
    
    def _determine_key_type(self, finding: Dict[str, Any]) -> str:
        """
        Determine the type of encryption key.
        
        Args:
            finding: Finding dictionary
            
        Returns:
            Key type string
        """
        # Check for explicit algorithm/type
        algorithm = finding.get("algorithm", "").lower()
        name = finding.get("name", "").lower()
        description = finding.get("description", "").lower()
        
        # Try to determine key type
        if "aes" in algorithm or "aes" in name or "aes" in description:
            return "AES"
        elif "rsa" in algorithm or "rsa" in name or "rsa" in description:
            return "RSA"
        elif "chacha" in algorithm or "chacha" in name or "chacha" in description:
            return "ChaCha20"
        elif "salsa" in algorithm or "salsa" in name or "salsa" in description:
            return "Salsa20"
        elif "rc4" in algorithm or "rc4" in name or "rc4" in description:
            return "RC4"
        elif "des" in algorithm or "des" in name or "des" in description:
            return "DES"
        
        # Check key size (in bytes) if available
        size = finding.get("size")
        if size:
            if size == 16:
                return "AES-128"
            elif size == 24:
                return "AES-192"
            elif size == 32:
                return "AES-256"
            elif size >= 128:
                return "RSA"
        
        # Default
        return "Unknown"

def main():
    """Command line interface for the Memory Scanner Orchestrator."""
    parser = argparse.ArgumentParser(description="Memory Scanner Orchestrator for Ransomware Analysis")
    parser.add_argument("input", help="Memory dump file or process ID to scan")
    parser.add_argument("--pid", action="store_true", help="Input is a process ID instead of a file")
    parser.add_argument("--output", "-o", help="Output file for results (JSON)")
    parser.add_argument("--generate-yara", help="Generate YARA rules and save to specified directory")
    parser.add_argument("--check-family", help="Check for a specific ransomware family")
    parser.add_argument("--extract-keys", action="store_true", help="Extract potential encryption keys")
    parser.add_argument("--scanner-weights", help="Comma-separated list of scanner:weight pairs (e.g., 'yara:1.0,pattern:0.8')")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Create orchestrator
    orchestrator = MemoryScannerOrchestrator()
    
    # Set scanner weights if specified
    if args.scanner_weights:
        for pair in args.scanner_weights.split(','):
            if ':' in pair:
                scanner, weight = pair.split(':')
                try:
                    weight_value = float(weight)
                    orchestrator.set_scanner_weight(scanner, weight_value)
                except ValueError:
                    logger.error(f"Invalid weight value: {weight}")
    
    # Run scan
    if args.pid:
        try:
            pid = int(args.input)
            logger.info(f"Scanning process with PID: {pid}")
            results = orchestrator.scan_process(pid)
        except ValueError:
            logger.error("Invalid PID. Must be an integer.")
            return 1
    else:
        logger.info(f"Scanning file: {args.input}")
        results = orchestrator.scan_file(args.input)
    
    # Store integrated results
    orchestrator.integrated_results = results
    
    # Print summary
    summary = results.get("summary", {})
    logger.info(f"Scan complete. Found {summary.get('total_findings', 0)} findings.")
    
    # Print findings by type
    findings_by_type = summary.get("findings_by_type", {})
    for finding_type, count in findings_by_type.items():
        logger.info(f"  {finding_type}: {count}")
    
    # Print ransomware families if any
    findings_by_family = summary.get("findings_by_family", {})
    if findings_by_family:
        logger.info("\nRansomware families detected:")
        for family, count in sorted(findings_by_family.items(), key=lambda x: x[1], reverse=True):
            logger.info(f"  {family}: {count} matches")
    
    # Print detection summary if available
    detection_summary = results.get("detection_summary")
    if detection_summary:
        logger.info("\nDetection verdict:")
        logger.info(f"  {detection_summary.get('message', 'No verdict available')}")
    
    # Check specific family if requested
    if args.check_family:
        family_result = orchestrator.check_ransomware_family(args.check_family)
        logger.info(f"\nChecking for {args.check_family} ransomware:")
        logger.info(f"  {family_result.get('message')}")
        logger.info(f"  Findings: {family_result.get('findings_count', 0)}")
    
    # Extract keys if requested
    if args.extract_keys:
        keys = orchestrator.extract_potential_keys()
        logger.info(f"\nExtracted {len(keys)} potential encryption keys:")
        for i, key in enumerate(keys[:5]):  # Show top 5
            logger.info(f"  Key {i+1}: {key.get('key_type')} - Confidence: {key.get('confidence'):.2f}")
            if "key_data" in key:
                data_preview = key["key_data"]
                if len(data_preview) > 40:
                    data_preview = data_preview[:37] + "..."
                logger.info(f"    Data: {data_preview}")
    
    # Generate YARA rules if requested
    if args.generate_yara:
        yara_file = orchestrator.export_yara_rules(args.generate_yara)
        if yara_file:
            logger.info(f"\nGenerated YARA rules saved to: {yara_file}")
    
    # Save results if output file specified
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
            logger.info(f"\nDetailed results saved to {args.output}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())