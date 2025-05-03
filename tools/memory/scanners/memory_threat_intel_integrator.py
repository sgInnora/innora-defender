#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Memory Analysis Threat Intelligence Integrator

This module integrates memory analysis results with threat intelligence
to provide enhanced insights about ransomware families, tactics,
and potential decryption capabilities.
"""

import os
import sys
import logging
import json
import argparse
from typing import List, Dict, Any, Optional
from datetime import datetime
import importlib.util

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('MemThreatIntelIntegrator')

class MemoryThreatIntelIntegrator:
    """
    Integrates memory analysis results with threat intelligence for 
    enhanced ransomware analysis.
    """
    
    def __init__(self, ti_connector_path: Optional[str] = None):
        """
        Initialize the integrator.
        
        Args:
            ti_connector_path: Path to the threat intelligence connector module
        """
        self.ti_connector = None
        self.correlation_engine = None
        self.memory_scan_results = None
        
        # Try to import threat intelligence components
        try:
            # First, try to import from the provided path
            if ti_connector_path:
                self._import_ti_from_path(ti_connector_path)
            else:
                # Otherwise try to locate in standard paths
                self._import_ti_from_standard_locations()
        except ImportError as e:
            logger.warning(f"Could not import threat intelligence components: {e}")
    
    def _import_ti_from_path(self, path: str) -> None:
        """
        Import threat intelligence components from a specific path.
        
        Args:
            path: Path to the threat intelligence module
        """
        if not os.path.exists(path):
            raise ImportError(f"Threat intelligence module not found at: {path}")
            
        # Get directory and module name
        module_dir = os.path.dirname(path)
        module_name = os.path.basename(path).replace('.py', '')
        
        if module_dir not in sys.path:
            sys.path.append(module_dir)
            
        # Try to import the module
        try:
            ti_module = importlib.import_module(module_name)
            
            # Get connector and correlation engine classes
            if hasattr(ti_module, 'TIConnector'):
                self.ti_connector = ti_module.TIConnector()
                logger.info("Loaded TI connector from specified path")
                
            if hasattr(ti_module, 'CorrelationEngine'):
                self.correlation_engine = ti_module.CorrelationEngine()
                logger.info("Loaded correlation engine from specified path")
                
        except Exception as e:
            logger.error(f"Error importing threat intelligence module from {path}: {e}")
            raise ImportError(f"Failed to import threat intelligence components: {e}")
    
    def _import_ti_from_standard_locations(self) -> None:
        """
        Try to import threat intelligence components from standard locations.
        """
        # Try multiple possible locations for the TI components
        paths_to_try = [
            # Direct paths
            os.path.join(os.path.dirname(__file__), '..', '..', 'threat_intel', 'connectors', 'ti_connector.py'),
            os.path.join(os.path.dirname(__file__), '..', '..', 'threat_intel', 'correlation', 'correlation_engine.py'),
            # Local paths
            os.path.join(os.path.dirname(__file__), 'threat_intel', 'connectors', 'ti_connector.py'),
            os.path.join(os.path.dirname(__file__), 'threat_intel', 'correlation', 'correlation_engine.py'),
            # Parent directory paths
            os.path.join(os.path.dirname(os.path.dirname(__file__)), 'threat_intel', 'connectors', 'ti_connector.py'),
            os.path.join(os.path.dirname(os.path.dirname(__file__)), 'threat_intel', 'correlation', 'correlation_engine.py'),
            # Fixed path
            '/Users/anwu/Documents/code/company/Innora_dev/1211/threat_intel/connectors/ti_connector.py',
            '/Users/anwu/Documents/code/company/Innora_dev/1211/threat_intel/correlation/correlation_engine.py',
        ]
        
        for path in paths_to_try:
            try:
                if os.path.exists(path):
                    module_dir = os.path.dirname(path)
                    module_name = os.path.basename(path).replace('.py', '')
                    
                    if module_dir not in sys.path:
                        sys.path.append(module_dir)
                        
                    # Try to import the module
                    module = importlib.import_module(module_name)
                    
                    # Check for connector
                    if hasattr(module, 'TIConnector') and not self.ti_connector:
                        self.ti_connector = module.TIConnector()
                        logger.info(f"Loaded TI connector from {path}")
                        
                    # Check for correlation engine
                    if hasattr(module, 'CorrelationEngine') and not self.correlation_engine:
                        self.correlation_engine = module.CorrelationEngine()
                        logger.info(f"Loaded correlation engine from {path}")
                        
                    # If we have both, we can stop
                    if self.ti_connector and self.correlation_engine:
                        return
            except Exception as e:
                logger.debug(f"Could not import from {path}: {e}")
                
        # If we still don't have the components, create fallback implementations
        if not self.ti_connector:
            self.ti_connector = self._create_fallback_ti_connector()
            logger.warning("Using fallback TI connector implementation")
            
        if not self.correlation_engine:
            self.correlation_engine = self._create_fallback_correlation_engine()
            logger.warning("Using fallback correlation engine implementation")
    
    def _create_fallback_ti_connector(self) -> object:
        """
        Create a fallback threat intelligence connector.
        
        Returns:
            Simple TI connector object
        """
        # Simple class to provide basic TI functionality
        class FallbackTIConnector:
            def __init__(self):
                self.ransomware_data = self._load_builtin_ransomware_data()
                
            def _load_builtin_ransomware_data(self) -> Dict[str, Dict[str, Any]]:
                """Load built-in ransomware family data."""
                # Basic information about common ransomware families
                return {
                    "wannacry": {
                        "name": "WannaCry",
                        "aliases": ["WannaCrypt", "WCry", "WanaCrypt0r"],
                        "first_seen": "2017-05-12",
                        "encryption": {
                            "algorithms": ["RSA-2048", "AES-128-CBC"],
                            "key_format": "RSA public key embedding",
                            "file_marker": "WANACRY!"
                        },
                        "file_extensions": [".wncry", ".wcry", ".wncrypt"],
                        "ransom_note": ["@Please_Read_Me@.txt", "!Please Read Me!.txt"],
                        "known_vulnerabilities": ["MS17-010", "EternalBlue"],
                        "decryptors_available": True,
                        "decryptor_links": ["https://blog.avast.com/decrypted-wannacry-ransomware-works-offline"]
                    },
                    "ryuk": {
                        "name": "Ryuk",
                        "aliases": ["RyukReadMe"],
                        "first_seen": "2018-08-01",
                        "encryption": {
                            "algorithms": ["RSA-2048", "AES-256"],
                            "key_format": "RSA public key",
                            "file_marker": "HERMES"
                        },
                        "file_extensions": [".ryk", ".RYK"],
                        "ransom_note": ["RyukReadMe.txt"],
                        "known_vulnerabilities": ["RDP", "Phishing"],
                        "decryptors_available": False
                    },
                    "revil": {
                        "name": "REvil",
                        "aliases": ["Sodinokibi", "Sodin"],
                        "first_seen": "2019-04-01",
                        "encryption": {
                            "algorithms": ["Salsa20", "RSA-2048"],
                            "key_format": "Config with embedded public key",
                            "config_pattern": "{\"pk\":\""
                        },
                        "file_extensions": [".sodinokibi", ".sodin", ".revil", ".unknown"],
                        "ransom_note": ["[id]-readme.txt", "[random]-readme.txt"],
                        "known_vulnerabilities": ["RDP", "VPN", "Oracle WebLogic"],
                        "decryptors_available": False
                    },
                    "lockbit": {
                        "name": "LockBit",
                        "aliases": ["LockBit 2.0", "LockBit 3.0", "LockBit Black"],
                        "first_seen": "2019-09-01",
                        "encryption": {
                            "algorithms": ["AES-256", "RSA-4096"],
                            "key_format": "RSA public key",
                            "file_marker": "LOCK"
                        },
                        "file_extensions": [".lockbit", ".lock"],
                        "ransom_note": ["Restore-My-Files.txt"],
                        "known_vulnerabilities": ["Remote Desktop", "Phishing"],
                        "decryptors_available": False
                    },
                    "blackcat": {
                        "name": "BlackCat",
                        "aliases": ["ALPHV"],
                        "first_seen": "2021-11-01",
                        "encryption": {
                            "algorithms": ["AES-256", "ChaCha20", "RSA-2048"],
                            "key_format": "RSA public key and config",
                            "file_marker": "BlackCat"
                        },
                        "file_extensions": [".encrypted", ".encrypt"],
                        "ransom_note": ["RECOVER-[ID]-FILES.txt"],
                        "known_vulnerabilities": ["Remote Desktop", "VPN", "Phishing"],
                        "decryptors_available": False
                    },
                    "conti": {
                        "name": "Conti",
                        "aliases": ["ContiLeaks"],
                        "first_seen": "2020-02-01",
                        "encryption": {
                            "algorithms": ["AES-256", "RSA-4096"],
                            "key_format": "RSA public key",
                            "file_marker": "CONTI"
                        },
                        "file_extensions": [".conti"],
                        "ransom_note": ["CONTI_README.txt"],
                        "known_vulnerabilities": ["Remote Desktop", "VPN", "ProxyShell", "Exchange"],
                        "decryptors_available": False
                    },
                    "blackbasta": {
                        "name": "BlackBasta",
                        "aliases": ["Black Basta"],
                        "first_seen": "2022-04-01",
                        "encryption": {
                            "algorithms": ["ChaCha20", "RSA-4096"],
                            "key_format": "RSA public key",
                            "file_marker": "BLACK BASTA"
                        },
                        "file_extensions": [".basta"],
                        "ransom_note": ["readme.txt"],
                        "known_vulnerabilities": ["Remote Desktop", "VPN", "QakBot"],
                        "decryptors_available": False
                    }
                }
                
            def query_family(self, family_name: str) -> Dict[str, Any]:
                """
                Query information about a ransomware family.
                
                Args:
                    family_name: Name of the ransomware family
                    
                Returns:
                    Family information or empty dict if not found
                """
                # Normalize family name for lookup
                normalized_name = family_name.lower().replace(" ", "")
                
                # Direct lookup
                if normalized_name in self.ransomware_data:
                    return self.ransomware_data[normalized_name]
                
                # Try aliases
                for family_id, family_data in self.ransomware_data.items():
                    aliases = [alias.lower().replace(" ", "") for alias in family_data.get("aliases", [])]
                    if normalized_name in aliases:
                        return family_data
                
                # Not found
                return {}
                
            def query_ioc(self, ioc_type: str, ioc_value: str) -> List[Dict[str, Any]]:
                """
                Query threat intelligence for an IOC.
                
                Args:
                    ioc_type: Type of IOC (file_hash, domain, ip, etc.)
                    ioc_value: IOC value to query
                    
                Returns:
                    List of matches or empty list if not found
                """
                # In the fallback implementation, we don't have external
                # TI sources, so this will always return empty
                return []
                
            def is_available(self) -> bool:
                """Check if the connector is available."""
                return True
                
        return FallbackTIConnector()
    
    def _create_fallback_correlation_engine(self) -> object:
        """
        Create a fallback correlation engine.
        
        Returns:
            Simple correlation engine object
        """
        # Simple class to provide basic correlation functionality
        class FallbackCorrelationEngine:
            def __init__(self):
                pass
                
            def correlate_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
                """
                Correlate findings to identify patterns and relationships.
                
                Args:
                    findings: List of findings to correlate
                    
                Returns:
                    Correlation results
                """
                # Group findings by type and family
                grouped_by_type = {}
                grouped_by_family = {}
                
                for finding in findings:
                    # Group by type
                    finding_type = finding.get("type", "unknown")
                    if finding_type not in grouped_by_type:
                        grouped_by_type[finding_type] = []
                    grouped_by_type[finding_type].append(finding)
                    
                    # Group by family
                    family = finding.get("family")
                    if family:
                        if family not in grouped_by_family:
                            grouped_by_family[family] = []
                        grouped_by_family[family].append(finding)
                
                # Basic scoring for families
                family_scores = {}
                for family, family_findings in grouped_by_family.items():
                    # Sum of confidences, capped at 1.0
                    confidence_sum = sum(finding.get("confidence", 0.5) for finding in family_findings)
                    confidence_max = max(finding.get("confidence", 0.5) for finding in family_findings)
                    finding_count = len(family_findings)
                    
                    # Weight by number of findings and max confidence
                    score = min(1.0, (confidence_sum / (finding_count * 2)) + (confidence_max / 2))
                    family_scores[family] = score
                
                # Create correlation result
                correlation = {
                    "timestamp": datetime.now().isoformat(),
                    "finding_counts": {
                        "total": len(findings),
                        "by_type": {k: len(v) for k, v in grouped_by_type.items()}
                    },
                    "family_detection": {
                        k: {
                            "score": v,
                            "confidence": "high" if v >= 0.8 else "medium" if v >= 0.6 else "low",
                            "finding_count": len(grouped_by_family[k])
                        } for k, v in family_scores.items()
                    }
                }
                
                # Determine primary family if any
                if family_scores:
                    primary_family = max(family_scores.items(), key=lambda x: x[1])
                    correlation["primary_family"] = {
                        "name": primary_family[0],
                        "score": primary_family[1],
                        "confidence": "high" if primary_family[1] >= 0.8 else "medium" if primary_family[1] >= 0.6 else "low"
                    }
                
                return correlation
                
            def is_available(self) -> bool:
                """Check if the engine is available."""
                return True
                
        return FallbackCorrelationEngine()
    
    def load_memory_scan_results(self, results_file: str) -> bool:
        """
        Load memory scan results from a file.
        
        Args:
            results_file: Path to the JSON results file
            
        Returns:
            True if loaded successfully, False otherwise
        """
        try:
            if not os.path.exists(results_file):
                logger.error(f"Results file not found: {results_file}")
                return False
                
            with open(results_file, 'r') as f:
                self.memory_scan_results = json.load(f)
                
            logger.info(f"Loaded memory scan results from {results_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading memory scan results: {e}")
            return False
    
    def set_memory_scan_results(self, results: Dict[str, Any]) -> None:
        """
        Set memory scan results directly.
        
        Args:
            results: Memory scan results dictionary
        """
        self.memory_scan_results = results
        logger.info("Memory scan results set directly")
    
    def enrich_with_threat_intelligence(self) -> Dict[str, Any]:
        """
        Enrich memory scan results with threat intelligence data.
        
        Returns:
            Enriched results dictionary
        """
        if not self.memory_scan_results:
            logger.error("No memory scan results to enrich")
            return {}
            
        if not self.ti_connector or not self.ti_connector.is_available():
            logger.warning("Threat intelligence connector not available")
            return self.memory_scan_results
            
        enriched_results = dict(self.memory_scan_results)
        
        # Add threat intelligence section
        enriched_results["threat_intelligence"] = {
            "timestamp": datetime.now().isoformat(),
            "source": "Memory Threat Intel Integrator",
            "family_details": {},
            "iocs": [],
            "decryption_possibilities": {}
        }
        
        # Get detected families from the results
        detected_families = []
        
        # Check summary section for families
        summary = self.memory_scan_results.get("summary", {})
        findings_by_family = summary.get("findings_by_family", {})
        for family in findings_by_family.keys():
            if family not in detected_families:
                detected_families.append(family)
        
        # Also check detection summary if available
        detection_summary = self.memory_scan_results.get("detection_summary", {})
        primary_family = detection_summary.get("primary_family")
        if primary_family and primary_family not in detected_families:
            detected_families.append(primary_family)
            
        # Look through all findings
        integrated_findings = self.memory_scan_results.get("integrated_findings", [])
        for finding_group in integrated_findings:
            if finding_group.get("type") == "finding_group":
                group_family = finding_group.get("family")
                if group_family and group_family not in detected_families:
                    detected_families.append(group_family)
                    
                # Check individual findings
                for finding in finding_group.get("findings", []):
                    finding_family = finding.get("family")
                    if finding_family and finding_family not in detected_families:
                        detected_families.append(finding_family)
            elif finding_group.get("type") == "finding":
                finding = finding_group.get("finding", {})
                finding_family = finding.get("family")
                if finding_family and finding_family not in detected_families:
                    detected_families.append(finding_family)
        
        # Enrich with family details
        for family in detected_families:
            # Query the TI connector for family information
            family_info = self.ti_connector.query_family(family)
            
            if family_info:
                enriched_results["threat_intelligence"]["family_details"][family] = family_info
                
                # Check for decryption possibilities
                if family_info.get("decryptors_available"):
                    enriched_results["threat_intelligence"]["decryption_possibilities"][family] = {
                        "decryptors_available": True,
                        "links": family_info.get("decryptor_links", []),
                        "notes": "Decryption utilities are available for this ransomware family"
                    }
        
        # Extract IOCs from the findings and enrich them
        iocs = self._extract_iocs_from_findings(integrated_findings)
        
        # Enrich IOCs with TI data
        enriched_iocs = []
        for ioc in iocs:
            # Query TI for this IOC
            ioc_info = self.ti_connector.query_ioc(ioc["type"], ioc["value"])
            
            enriched_ioc = dict(ioc)
            if ioc_info:
                enriched_ioc["ti_data"] = ioc_info
                
            enriched_iocs.append(enriched_ioc)
            
        enriched_results["threat_intelligence"]["iocs"] = enriched_iocs
        
        # Check for potential decryption opportunities based on key findings
        self._assess_decryption_possibilities(enriched_results)
        
        return enriched_results
    
    def _extract_iocs_from_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extract IOCs from memory scan findings.
        
        Args:
            findings: List of finding groups or findings
            
        Returns:
            List of extracted IOCs
        """
        iocs = []
        
        for finding_group in findings:
            if finding_group.get("type") == "finding_group":
                group_findings = finding_group.get("findings", [])
                
                for finding in group_findings:
                    extracted = self._extract_ioc_from_finding(finding)
                    iocs.extend(extracted)
            elif finding_group.get("type") == "finding":
                finding = finding_group.get("finding", {})
                extracted = self._extract_ioc_from_finding(finding)
                iocs.extend(extracted)
        
        # Deduplicate IOCs
        unique_iocs = []
        seen_values = set()
        
        for ioc in iocs:
            value = ioc["value"]
            if value not in seen_values:
                unique_iocs.append(ioc)
                seen_values.add(value)
        
        return unique_iocs
    
    def _extract_ioc_from_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract IOCs from an individual finding.
        
        Args:
            finding: Finding dictionary
            
        Returns:
            List of extracted IOCs
        """
        iocs = []
        
        # Check for file hashes
        for hash_field in ["md5", "sha1", "sha256", "hash"]:
            if hash_field in finding and isinstance(finding[hash_field], str):
                iocs.append({
                    "type": "file_hash",
                    "hash_type": hash_field,
                    "value": finding[hash_field],
                    "description": finding.get("description", "Extracted from memory finding"),
                    "confidence": finding.get("confidence", 0.5),
                    "source": finding.get("scanner", "memory_scan")
                })
        
        # Check for domains
        if "domain" in finding:
            iocs.append({
                "type": "domain",
                "value": finding["domain"],
                "description": finding.get("description", "Extracted from memory finding"),
                "confidence": finding.get("confidence", 0.5),
                "source": finding.get("scanner", "memory_scan")
            })
        
        # Check for IP addresses
        if "ip" in finding:
            iocs.append({
                "type": "ip",
                "value": finding["ip"],
                "description": finding.get("description", "Extracted from memory finding"),
                "confidence": finding.get("confidence", 0.5),
                "source": finding.get("scanner", "memory_scan")
            })
        
        # Check for URLs
        if "url" in finding:
            iocs.append({
                "type": "url",
                "value": finding["url"],
                "description": finding.get("description", "Extracted from memory finding"),
                "confidence": finding.get("confidence", 0.5),
                "source": finding.get("scanner", "memory_scan")
            })
        
        # Check for filenames
        if "filename" in finding:
            iocs.append({
                "type": "filename",
                "value": finding["filename"],
                "description": finding.get("description", "Extracted from memory finding"),
                "confidence": finding.get("confidence", 0.5),
                "source": finding.get("scanner", "memory_scan")
            })
        
        # Check for encrypted file headers
        if finding.get("type") == "encrypted_file_header":
            if "marker" in finding:
                iocs.append({
                    "type": "file_marker",
                    "value": finding["marker"],
                    "family": finding.get("family", "unknown"),
                    "description": "Encrypted file header marker",
                    "confidence": finding.get("confidence", 0.5),
                    "source": finding.get("scanner", "memory_scan")
                })
        
        return iocs
    
    def _assess_decryption_possibilities(self, results: Dict[str, Any]) -> None:
        """
        Assess possible decryption opportunities based on key findings.
        Modifies the results dictionary in place.
        
        Args:
            results: Results dictionary to modify
        """
        # Check if there are potential keys in the scan results
        key_findings = []
        
        # Extract key findings
        integrated_findings = results.get("integrated_findings", [])
        for finding_group in integrated_findings:
            if finding_group.get("type") == "finding_group":
                for finding in finding_group.get("findings", []):
                    if self._is_key_finding(finding):
                        key_findings.append(finding)
            elif finding_group.get("type") == "finding":
                finding = finding_group.get("finding", {})
                if self._is_key_finding(finding):
                    key_findings.append(finding)
        
        # Check for encryption keys by algorithm
        keys_by_algorithm = {}
        
        for finding in key_findings:
            algorithm = self._determine_key_algorithm(finding)
            if algorithm:
                if algorithm not in keys_by_algorithm:
                    keys_by_algorithm[algorithm] = []
                keys_by_algorithm[algorithm].append(finding)
        
        # Add key assessment to the results
        if keys_by_algorithm:
            results["threat_intelligence"]["key_assessment"] = {
                "keys_found": True,
                "key_count": len(key_findings),
                "algorithms_found": list(keys_by_algorithm.keys()),
                "decryption_potential": self._evaluate_decryption_potential(keys_by_algorithm, results),
                "keys_by_algorithm": {
                    algorithm: {
                        "count": len(keys),
                        "max_confidence": max(key.get("confidence", 0.5) for key in keys),
                        "recommendations": self._get_key_recommendations(algorithm, keys)
                    }
                    for algorithm, keys in keys_by_algorithm.items()
                }
            }
        else:
            results["threat_intelligence"]["key_assessment"] = {
                "keys_found": False,
                "key_count": 0,
                "decryption_potential": "none",
                "recommendations": [
                    "No encryption keys identified in memory",
                    "Consider using additional memory scanning tools",
                    "Check for key files on disk that may contain encryption keys"
                ]
            }
    
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
    
    def _determine_key_algorithm(self, finding: Dict[str, Any]) -> Optional[str]:
        """
        Determine the algorithm of a potential encryption key.
        
        Args:
            finding: Finding dictionary
            
        Returns:
            Algorithm name or None if unknown
        """
        # Check explicit algorithm field
        if "algorithm" in finding:
            return finding["algorithm"]
            
        # Check name field
        name = finding.get("name", "").lower()
        description = finding.get("description", "").lower()
        
        # Check for algorithm names
        for algorithm in ["aes", "rsa", "chacha20", "salsa20", "rc4", "des"]:
            if algorithm in name or algorithm in description:
                return algorithm.upper()
                
        # Try to infer from size
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
                
        return None
    
    def _evaluate_decryption_potential(self, keys_by_algorithm: Dict[str, List[Dict[str, Any]]], 
                                      results: Dict[str, Any]) -> str:
        """
        Evaluate the potential for decryption based on found keys.
        
        Args:
            keys_by_algorithm: Dictionary mapping algorithms to key findings
            results: Full results dictionary
            
        Returns:
            Decryption potential assessment ("high", "medium", "low", "none")
        """
        # Check if we have symmetric encryption keys (AES, etc.)
        has_symmetric = any(alg.startswith(("AES", "CHACHA", "SALSA", "RC4", "DES")) 
                           for alg in keys_by_algorithm.keys())
                           
        # Check if we have asymmetric keys (RSA, etc.)
        has_asymmetric = any(alg.startswith("RSA") for alg in keys_by_algorithm.keys())
        
        # Get maximum key confidence
        max_confidence = 0
        for keys in keys_by_algorithm.values():
            for key in keys:
                max_confidence = max(max_confidence, key.get("confidence", 0.5))
        
        # Check if any ransomware families have decryptors available
        decryptors_available = False
        family_details = results.get("threat_intelligence", {}).get("family_details", {})
        for family_info in family_details.values():
            if family_info.get("decryptors_available"):
                decryptors_available = True
                break
        
        # Make the assessment
        if has_symmetric and max_confidence >= 0.8:
            return "high"
        elif (has_symmetric and max_confidence >= 0.6) or decryptors_available:
            return "medium"
        elif has_symmetric or has_asymmetric:
            return "low"
        else:
            return "none"
    
    def _get_key_recommendations(self, algorithm: str, keys: List[Dict[str, Any]]) -> List[str]:
        """
        Get recommendations for handling specific key types.
        
        Args:
            algorithm: Key algorithm
            keys: List of key findings for this algorithm
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Get highest confidence key
        max_confidence = max(key.get("confidence", 0.5) for key in keys)
        is_high_confidence = max_confidence >= 0.8
        
        # Algorithm-specific recommendations
        if algorithm.startswith("AES"):
            recommendations.append(f"Found potential {algorithm} encryption keys ({len(keys)} instances)")
            
            if is_high_confidence:
                recommendations.append("High confidence AES keys detected - extraction recommended")
                recommendations.append("Suggested action: Extract keys and use AES decryption tools")
                recommendations.append("Use file header analysis to determine encryption mode (CBC, CTR, etc.)")
            else:
                recommendations.append("Low confidence AES keys - validation required")
                recommendations.append("Use entropy analysis to confirm these are valid keys")
        
        elif algorithm.startswith("RSA"):
            recommendations.append(f"Found potential RSA key material ({len(keys)} instances)")
            
            if is_high_confidence:
                recommendations.append("High confidence RSA keys detected - extraction recommended")
                recommendations.append("Check if these are public or private keys - only private keys can be used for decryption")
                recommendations.append("Examine key format to determine if RSA PKCS#1 or X.509 format")
            else:
                recommendations.append("Low confidence RSA key material - validation required")
                recommendations.append("Check if complete private key components are present")
        
        elif algorithm.startswith(("CHACHA", "SALSA")):
            recommendations.append(f"Found potential {algorithm} keys ({len(keys)} instances)")
            
            if is_high_confidence:
                recommendations.append(f"High confidence {algorithm} keys detected - extraction recommended")
                recommendations.append(f"Look for nonce values near the key material for complete decryption")
                recommendations.append(f"Use specialized {algorithm} decryption tools")
            else:
                recommendations.append(f"Low confidence {algorithm} keys - validation required")
        
        elif algorithm.startswith("RC4"):
            recommendations.append(f"Found potential RC4 state tables ({len(keys)} instances)")
            
            if is_high_confidence:
                recommendations.append("High confidence RC4 state identified - extraction may be possible")
                recommendations.append("Extract the full 256-byte state table for decryption")
            else:
                recommendations.append("Low confidence RC4 state - validation required")
        
        else:
            recommendations.append(f"Found potential {algorithm} keys ({len(keys)} instances)")
            recommendations.append("Validate and extract keys for testing with decryption tools")
        
        # General recommendations
        recommendations.append("Extract keys to a file for testing with the decryption toolkit")
        recommendations.append("Test keys against encrypted files to validate decryption capability")
        
        return recommendations
    
    def analyze_families(self) -> Dict[str, Any]:
        """
        Perform deeper analysis of detected ransomware families.
        
        Returns:
            Analysis results
        """
        if not self.memory_scan_results:
            logger.error("No memory scan results to analyze")
            return {}
            
        if not self.correlation_engine or not self.correlation_engine.is_available():
            logger.warning("Correlation engine not available")
            return {}
            
        # Extract all findings from the scan results
        findings = []
        
        integrated_findings = self.memory_scan_results.get("integrated_findings", [])
        for finding_group in integrated_findings:
            if finding_group.get("type") == "finding_group":
                findings.extend(finding_group.get("findings", []))
            elif finding_group.get("type") == "finding":
                finding = finding_group.get("finding", {})
                if finding:
                    findings.append(finding)
        
        # Run correlation on the findings
        correlation_results = self.correlation_engine.correlate_findings(findings)
        
        # Get family details from threat intelligence
        family_details = {}
        
        if self.ti_connector and self.ti_connector.is_available():
            detected_families = correlation_results.get("family_detection", {}).keys()
            
            for family in detected_families:
                family_info = self.ti_connector.query_family(family)
                if family_info:
                    family_details[family] = family_info
        
        # Combine correlation and TI data
        analysis = {
            "timestamp": datetime.now().isoformat(),
            "correlation": correlation_results,
            "family_details": family_details,
            "findings_analyzed": len(findings)
        }
        
        # Add a summary of the findings
        analysis["summary"] = {
            "total_findings": len(findings),
            "primary_family": correlation_results.get("primary_family", {}).get("name", "Unknown"),
            "confidence": correlation_results.get("primary_family", {}).get("confidence", "low"),
            "known_families": list(correlation_results.get("family_detection", {}).keys()),
            "analysis_quality": "high" if len(findings) > 20 else "medium" if len(findings) > 5 else "low"
        }
        
        return analysis
    
    def generate_mitre_mapping(self) -> Dict[str, Any]:
        """
        Map memory scan findings to MITRE ATT&CK techniques.
        
        Returns:
            MITRE ATT&CK mapping
        """
        if not self.memory_scan_results:
            logger.error("No memory scan results to map")
            return {}
            
        # Map of ransomware behaviors to MITRE ATT&CK techniques
        mitre_mappings = {
            # Execution techniques
            "process": {
                "technique_id": "T1204",
                "technique_name": "User Execution",
                "tactic": "Execution"
            },
            "ransomware_process": {
                "technique_id": "T1204",
                "technique_name": "User Execution",
                "tactic": "Execution"
            },
            # Defense Evasion
            "encrypted_file_header": {
                "technique_id": "T1486",
                "technique_name": "Data Encrypted for Impact",
                "tactic": "Impact"
            },
            # Impact techniques
            "ransomware_pattern": {
                "technique_id": "T1486",
                "technique_name": "Data Encrypted for Impact",
                "tactic": "Impact"
            },
            "encrypted_file_marker": {
                "technique_id": "T1486",
                "technique_name": "Data Encrypted for Impact",
                "tactic": "Impact"
            },
            "ransom_note": {
                "technique_id": "T1486",
                "technique_name": "Data Encrypted for Impact",
                "tactic": "Impact"
            },
            # Credential Access
            "crypto_api": {
                "technique_id": "T1555",
                "technique_name": "Credentials from Password Stores",
                "tactic": "Credential Access"
            },
            # Command and Control
            "network_traffic": {
                "technique_id": "T1071",
                "technique_name": "Application Layer Protocol",
                "tactic": "Command and Control"
            },
            # Discovery
            "file_scan": {
                "technique_id": "T1083",
                "technique_name": "File and Directory Discovery",
                "tactic": "Discovery"
            },
            # Resource Development
            "crypto_constant": {
                "technique_id": "T1588.005",
                "technique_name": "Obtain Capabilities: Exploits",
                "tactic": "Resource Development"
            }
        }
        
        # Family-specific MITRE mappings
        family_mitre_mappings = {
            "WannaCry": [
                {
                    "technique_id": "T1210",
                    "technique_name": "Exploitation of Remote Services",
                    "tactic": "Lateral Movement",
                    "description": "WannaCry uses EternalBlue exploit (MS17-010) for lateral movement"
                }
            ],
            "Ryuk": [
                {
                    "technique_id": "T1489",
                    "technique_name": "Service Stop",
                    "tactic": "Impact",
                    "description": "Ryuk stops services to allow encryption of files"
                },
                {
                    "technique_id": "T1490",
                    "technique_name": "Inhibit System Recovery",
                    "tactic": "Impact",
                    "description": "Ryuk deletes shadow copies to prevent recovery"
                }
            ],
            "REvil": [
                {
                    "technique_id": "T1059.001",
                    "technique_name": "Command and Scripting Interpreter: PowerShell",
                    "tactic": "Execution",
                    "description": "REvil uses PowerShell for execution"
                }
            ],
            "LockBit": [
                {
                    "technique_id": "T1562.001",
                    "technique_name": "Impair Defenses: Disable or Modify Tools",
                    "tactic": "Defense Evasion",
                    "description": "LockBit disables security tools to evade detection"
                }
            ]
        }
        
        # Count technique occurrences
        technique_counts = {}
        technique_details = {}
        family_techniques = {}
        
        # Process all findings
        integrated_findings = self.memory_scan_results.get("integrated_findings", [])
        for finding_group in integrated_findings:
            if finding_group.get("type") == "finding_group":
                # Check for family-specific techniques
                group_family = finding_group.get("family")
                if group_family and group_family in family_mitre_mappings:
                    if group_family not in family_techniques:
                        family_techniques[group_family] = family_mitre_mappings[group_family]
                
                # Process individual findings
                for finding in finding_group.get("findings", []):
                    finding_type = finding.get("type", "unknown")
                    
                    # Map finding to technique
                    if finding_type in mitre_mappings:
                        technique = mitre_mappings[finding_type]
                        technique_id = technique["technique_id"]
                        
                        if technique_id not in technique_counts:
                            technique_counts[technique_id] = 0
                            technique_details[technique_id] = technique
                            
                        technique_counts[technique_id] += 1
                        
                    # Check for individual finding family
                    finding_family = finding.get("family")
                    if finding_family and finding_family in family_mitre_mappings:
                        if finding_family not in family_techniques:
                            family_techniques[finding_family] = family_mitre_mappings[finding_family]
            
            elif finding_group.get("type") == "finding":
                finding = finding_group.get("finding", {})
                finding_type = finding.get("type", "unknown")
                
                # Map finding to technique
                if finding_type in mitre_mappings:
                    technique = mitre_mappings[finding_type]
                    technique_id = technique["technique_id"]
                    
                    if technique_id not in technique_counts:
                        technique_counts[technique_id] = 0
                        technique_details[technique_id] = technique
                        
                    technique_counts[technique_id] += 1
                    
                # Check for finding family
                finding_family = finding.get("family")
                if finding_family and finding_family in family_mitre_mappings:
                    if finding_family not in family_techniques:
                        family_techniques[finding_family] = family_mitre_mappings[finding_family]
        
        # Create MITRE mapping result
        mapping = {
            "timestamp": datetime.now().isoformat(),
            "techniques": [
                {
                    "technique_id": technique_id,
                    "technique_name": technique_details[technique_id]["technique_name"],
                    "tactic": technique_details[technique_id]["tactic"],
                    "count": count,
                    "confidence": "high" if count >= 5 else "medium" if count >= 2 else "low"
                }
                for technique_id, count in technique_counts.items()
            ],
            "family_specific_techniques": [
                {
                    "family": family,
                    "techniques": techniques
                }
                for family, techniques in family_techniques.items()
            ]
        }
        
        # Sort techniques by count
        mapping["techniques"].sort(key=lambda x: x["count"], reverse=True)
        
        # Gather tactics
        tactics = set()
        for technique in mapping["techniques"]:
            tactics.add(technique["tactic"])
        
        for family_entry in mapping["family_specific_techniques"]:
            for technique in family_entry["techniques"]:
                tactics.add(technique["tactic"])
        
        mapping["tactics"] = sorted(list(tactics))
        
        # Add summary
        mapping["summary"] = {
            "techniques_count": len(mapping["techniques"]),
            "tactics_count": len(mapping["tactics"]),
            "primary_tactic": "Impact" if "Impact" in tactics else next(iter(tactics)) if tactics else "Unknown",
            "highest_confidence_technique": mapping["techniques"][0] if mapping["techniques"] else None
        }
        
        return mapping
    
    def generate_recovery_recommendations(self) -> Dict[str, Any]:
        """
        Generate recovery recommendations based on memory scan results.
        
        Returns:
            Recovery recommendations
        """
        if not self.memory_scan_results:
            logger.error("No memory scan results for recommendations")
            return {}
            
        # Check for family-specific recommendations
        detected_families = []
        family_details = {}
        
        # Extract family information
        summary = self.memory_scan_results.get("summary", {})
        findings_by_family = summary.get("findings_by_family", {})
        for family in findings_by_family.keys():
            if family not in detected_families:
                detected_families.append(family)
                
                # Get family details if available
                if self.ti_connector and self.ti_connector.is_available():
                    family_info = self.ti_connector.query_family(family)
                    if family_info:
                        family_details[family] = family_info
        
        # Detection summary
        detection_summary = self.memory_scan_results.get("detection_summary", {})
        primary_family = detection_summary.get("primary_family")
        if primary_family and primary_family not in detected_families:
            detected_families.append(primary_family)
            
            # Get family details if available
            if self.ti_connector and self.ti_connector.is_available():
                family_info = self.ti_connector.query_family(primary_family)
                if family_info:
                    family_details[primary_family] = family_info
        
        # Check for encryption keys
        has_keys = False
        key_count = 0
        key_algorithms = []
        max_key_confidence = 0
        
        # Look for key assessment if available
        ti_data = self.memory_scan_results.get("threat_intelligence", {})
        key_assessment = ti_data.get("key_assessment", {})
        
        if key_assessment:
            has_keys = key_assessment.get("keys_found", False)
            key_count = key_assessment.get("key_count", 0)
            key_algorithms = key_assessment.get("algorithms_found", [])
            
            # Check keys by algorithm
            keys_by_algorithm = key_assessment.get("keys_by_algorithm", {})
            for algorithm_data in keys_by_algorithm.values():
                max_key_confidence = max(max_key_confidence, algorithm_data.get("max_confidence", 0))
        else:
            # Manual check for keys
            integrated_findings = self.memory_scan_results.get("integrated_findings", [])
            for finding_group in integrated_findings:
                if finding_group.get("type") == "finding_group":
                    for finding in finding_group.get("findings", []):
                        if self._is_key_finding(finding):
                            has_keys = True
                            key_count += 1
                            
                            algorithm = self._determine_key_algorithm(finding)
                            if algorithm and algorithm not in key_algorithms:
                                key_algorithms.append(algorithm)
                                
                            max_key_confidence = max(max_key_confidence, finding.get("confidence", 0))
                elif finding_group.get("type") == "finding":
                    finding = finding_group.get("finding", {})
                    if self._is_key_finding(finding):
                        has_keys = True
                        key_count += 1
                        
                        algorithm = self._determine_key_algorithm(finding)
                        if algorithm and algorithm not in key_algorithms:
                            key_algorithms.append(algorithm)
                            
                        max_key_confidence = max(max_key_confidence, finding.get("confidence", 0))
        
        # Generate recommendations
        recommendations = {
            "timestamp": datetime.now().isoformat(),
            "ransomware_detected": len(detected_families) > 0,
            "decryption_possible": has_keys and max_key_confidence >= 0.7,
            "families": detected_families,
            "key_extraction": {
                "keys_found": has_keys,
                "key_count": key_count,
                "algorithms": key_algorithms,
                "max_confidence": max_key_confidence,
                "extraction_recommended": has_keys and max_key_confidence >= 0.6
            },
            "recommendations": []
        }
        
        # Set general recommendations
        if len(detected_families) == 0:
            recommendations["recommendations"] = [
                "No specific ransomware family detected. This may be a generic encryption process.",
                "Check for ransom notes or modified file extensions to identify the ransomware family.",
                "Consider additional memory analysis tools to identify the encryption process.",
                "Create backup copies of encrypted files before any recovery attempt."
            ]
        else:
            # Family-specific recommendations
            family_recs = []
            
            for family in detected_families:
                family_lower = family.lower()
                
                # Check for known decryptors
                has_decryptor = False
                decryptor_links = []
                
                family_info = family_details.get(family, {})
                if family_info:
                    has_decryptor = family_info.get("decryptors_available", False)
                    decryptor_links = family_info.get("decryptor_links", [])
                
                if has_decryptor:
                    family_recs.append(f"Decryptors are available for {family} ransomware")
                    for link in decryptor_links:
                        family_recs.append(f"Decryptor available at: {link}")
                
                # Family-specific action recommendations
                if "wannacry" in family_lower:
                    family_recs.append("WannaCry decryptors are available if the system was not rebooted after infection")
                    family_recs.append("Check for 00000000.eky and 00000000.dky files in Windows directories")
                    family_recs.append("Patch system with MS17-010 before reconnecting to network")
                    
                elif "ryuk" in family_lower:
                    family_recs.append("Ryuk uses RSA + AES encryption - difficult to decrypt without keys")
                    family_recs.append("Check for HERMES marker in encrypted files")
                    family_recs.append("Consider memory forensics to extract encryption keys")
                    
                elif "revil" in family_lower or "sodinokibi" in family_lower:
                    family_recs.append("REvil/Sodinokibi uses multiple encryption methods (Salsa20 and RSA)")
                    family_recs.append("Check for config structure in memory with public key")
                    family_recs.append("Look for ransom notes with [random]-readme.txt pattern")
                    
                elif "lockbit" in family_lower:
                    family_recs.append("LockBit uses AES + RSA encryption scheme")
                    family_recs.append("Multiple versions exist (1.0, 2.0, 3.0/Black) with different behaviors")
                    
                elif "blackcat" in family_lower or "alphv" in family_lower:
                    family_recs.append("BlackCat/ALPHV is a Rust-based ransomware with complex encryption")
                    family_recs.append("Uses ChaCha20 for file encryption and RSA for key protection")
                    
                elif "conti" in family_lower:
                    family_recs.append("Conti uses AES-256 for file encryption and RSA-4096 for key protection")
                    family_recs.append("Uses asynchronous encryption for speed - some partially encrypted files may be recoverable")
            
            # Add family recommendations if any
            if family_recs:
                recommendations["recommendations"].extend(family_recs)
            
            # General recommendations based on detected families
            recommendations["recommendations"].extend([
                f"Identified {len(detected_families)} ransomware {'family' if len(detected_families) == 1 else 'families'}: {', '.join(detected_families)}",
                "Create backup copies of encrypted files before any recovery attempt",
                "Do not reboot the system as encryption keys may still be in memory",
                "Use memory dumping tools to capture full memory for further analysis"
            ])
        
        # Add key-based recommendations
        if has_keys:
            key_confidence_str = "high" if max_key_confidence >= 0.8 else "medium" if max_key_confidence >= 0.6 else "low"
            recommendations["recommendations"].append(f"Found {key_count} potential encryption keys with {key_confidence_str} confidence")
            
            if max_key_confidence >= 0.7:
                recommendations["recommendations"].append("High confidence keys detected - extraction recommended for decryption attempt")
                recommendations["recommendations"].append("Use key extraction tools to extract keys from memory dump")
                recommendations["recommendations"].append("Test extracted keys against encrypted files to verify decryption capability")
            elif max_key_confidence >= 0.5:
                recommendations["recommendations"].append("Medium confidence keys detected - extraction may be useful for analysis")
                recommendations["recommendations"].append("Validation required before using keys for decryption attempts")
            else:
                recommendations["recommendations"].append("Low confidence keys detected - manual verification required")
                recommendations["recommendations"].append("Use additional memory analysis tools to improve key detection")
            
            # Algorithm-specific recommendations
            for algorithm in key_algorithms:
                if "aes" in algorithm.lower():
                    recommendations["recommendations"].append(f"For {algorithm} keys: Extract key and IV/nonce for decryption")
                elif "rsa" in algorithm.lower():
                    recommendations["recommendations"].append(f"For {algorithm} keys: Verify if private key components are available")
                elif "chacha" in algorithm.lower() or "salsa" in algorithm.lower():
                    recommendations["recommendations"].append(f"For {algorithm} keys: Look for 32-byte key and nonce values")
        else:
            recommendations["recommendations"].append("No encryption keys identified in memory")
            recommendations["recommendations"].append("Consider deeper memory analysis or file-based recovery techniques")
            recommendations["recommendations"].append("Check for known decryptors for the identified ransomware families")
        
        # General recommendations for all cases
        recommendations["recommendations"].extend([
            "Check for shadow copies and backup files that may have survived encryption",
            "Scan system for backdoors or persistent access mechanisms",
            "Create incident response documentation of all findings",
            "Perform root cause analysis to prevent future incidents"
        ])
        
        return recommendations
    
    def save_results(self, output_file: str) -> None:
        """
        Save enriched results to a JSON file.
        
        Args:
            output_file: Path to save results to
        """
        if not hasattr(self, 'enriched_results'):
            logger.warning("No enriched results to save")
            return
            
        try:
            with open(output_file, 'w') as f:
                json.dump(self.enriched_results, f, indent=2)
                logger.info(f"Enriched results saved to {output_file}")
                
        except Exception as e:
            logger.error(f"Error saving results: {e}")

def main():
    """Command line interface for the Memory Threat Intel Integrator."""
    parser = argparse.ArgumentParser(description="Memory Analysis Threat Intelligence Integrator")
    parser.add_argument("input", help="Memory scan results file (JSON)")
    parser.add_argument("--output", "-o", help="Output file for enriched results (JSON)")
    parser.add_argument("--ti-connector", help="Path to threat intelligence connector module")
    parser.add_argument("--mitre", action="store_true", help="Generate MITRE ATT&CK mapping")
    parser.add_argument("--family-analysis", action="store_true", help="Perform detailed family analysis")
    parser.add_argument("--recovery", action="store_true", help="Generate recovery recommendations")
    parser.add_argument("--all", action="store_true", help="Perform all analysis types")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Create integrator
    integrator = MemoryThreatIntelIntegrator(args.ti_connector)
    
    # Load scan results
    if not integrator.load_memory_scan_results(args.input):
        logger.error(f"Failed to load scan results from {args.input}")
        return 1
    
    # Enrich with threat intelligence
    enriched_results = integrator.enrich_with_threat_intelligence()
    integrator.enriched_results = enriched_results
    
    logger.info("Memory scan results enriched with threat intelligence")
    
    # Perform additional analysis as requested
    if args.all or args.mitre:
        mitre_mapping = integrator.generate_mitre_mapping()
        enriched_results["mitre_attack_mapping"] = mitre_mapping
        logger.info(f"Generated MITRE ATT&CK mapping with {len(mitre_mapping.get('techniques', []))} techniques")
    
    if args.all or args.family_analysis:
        family_analysis = integrator.analyze_families()
        enriched_results["family_analysis"] = family_analysis
        logger.info(f"Performed family analysis for {len(family_analysis.get('family_details', {})):d} families")
    
    if args.all or args.recovery:
        recovery_recommendations = integrator.generate_recovery_recommendations()
        enriched_results["recovery_recommendations"] = recovery_recommendations
        logger.info(f"Generated {len(recovery_recommendations.get('recommendations', []))} recovery recommendations")
    
    # Print summary
    ti_data = enriched_results.get("threat_intelligence", {})
    family_details = ti_data.get("family_details", {})
    decryption = ti_data.get("decryption_possibilities", {})
    key_assessment = ti_data.get("key_assessment", {})
    
    logger.info("\nIntegration Summary:")
    logger.info(f"Detected Families: {len(family_details)} ({', '.join(family_details.keys())})")
    logger.info(f"Decryption Possibilities: {len(decryption)} families have known decryptors")
    
    if key_assessment:
        logger.info(f"Key Assessment: {key_assessment.get('keys_found', False)}, {key_assessment.get('key_count', 0)} potential keys found")
        
        if key_assessment.get("algorithms_found"):
            logger.info(f"Key Algorithms: {', '.join(key_assessment.get('algorithms_found', []))}")
            
        if key_assessment.get("decryption_potential"):
            logger.info(f"Decryption Potential: {key_assessment.get('decryption_potential')}")
    
    # Save enriched results
    if args.output:
        integrator.save_results(args.output)
    elif not args.output:
        logger.warning("No output file specified. Results not saved.")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())