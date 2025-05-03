#!/usr/bin/env python3
"""
Enhanced Ransomware Family Detector

This module provides improved ransomware family detection capabilities:
- More comprehensive pattern matching for variant identification
- Hierarchical family classification
- Machine learning-based similarity detection
- Multi-feature correlation analysis
- Support for variant-specific indicators
- Integration with enhanced YARA rules
"""

import os
import re
import json
import logging
import difflib
import hashlib
import datetime
from typing import Dict, List, Set, Optional, Any, Tuple, Union
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('EnhancedFamilyDetector')

class RansomwareFamilyFeature:
    """Base class for ransomware family detection features"""
    
    def __init__(self, name: str, weight: float = 1.0):
        """
        Initialize the feature
        
        Args:
            name: Feature name
            weight: Feature weight for scoring
        """
        self.name = name
        self.weight = weight
    
    def extract(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract feature from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            Feature extraction results
        """
        raise NotImplementedError("Feature extraction method must be implemented by subclasses")
    
    def compare(self, sample_features: Dict[str, Any], family_features: Dict[str, Any]) -> float:
        """
        Compare sample features with family features
        
        Args:
            sample_features: Features extracted from sample
            family_features: Features for a ransomware family
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        raise NotImplementedError("Feature comparison method must be implemented by subclasses")


class StringPatternFeature(RansomwareFamilyFeature):
    """Feature based on string patterns found in ransomware samples"""
    
    def __init__(self, weight: float = 1.0):
        """
        Initialize the string pattern feature
        
        Args:
            weight: Feature weight for scoring
        """
        super().__init__("string_patterns", weight)
    
    def extract(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract string patterns from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            Dictionary containing extracted string patterns
        """
        results = {
            "ransom_note_content": [],
            "encryption_references": [],
            "payment_references": [],
            "file_markers": [],
            "command_patterns": [],
            "url_patterns": []
        }
        
        # Extract strings from analysis
        strings = sample_data.get("analysis", {}).get("strings", [])
        
        # Process strings
        for string in strings:
            # Skip very short strings
            if len(string) < 5:
                continue
            
            # Check for ransom note content
            if any(keyword in string.lower() for keyword in ["ransom", "encrypt", "decrypt", "bitcoin", "payment", "key", "recover", "files", "locked"]):
                results["ransom_note_content"].append(string)
            
            # Check for encryption references
            if any(keyword in string.lower() for keyword in ["aes", "rsa", "encrypt", "decrypt", "key", "cipher", "crypt"]):
                results["encryption_references"].append(string)
            
            # Check for payment references
            if any(keyword in string.lower() for keyword in ["bitcoin", "btc", "monero", "xmr", "payment", "wallet", "address", "pay", "usd", "eur"]):
                results["payment_references"].append(string)
            
            # Check for file markers
            if any(keyword in string.lower() for keyword in ["encrypted", "crypted", "locked", ".lock", ".crypt", ".encrypted"]):
                results["file_markers"].append(string)
            
            # Check for command patterns
            if any(keyword in string.lower() for keyword in ["cmd.exe", "powershell", "vssadmin", "bcdedit", "wbadmin", "wmic", "taskkill"]):
                results["command_patterns"].append(string)
            
            # Check for URL patterns
            if any(keyword in string.lower() for keyword in ["http://", "https://", ".onion", "tor", "i2p"]):
                results["url_patterns"].append(string)
        
        # Extract behavior data
        behaviors = sample_data.get("analysis", {}).get("behaviors", {})
        
        # Extract command lines from process behavior
        processes = behaviors.get("processes", [])
        for process in processes:
            if "command_line" in process:
                cmd = process["command_line"]
                if any(keyword in cmd.lower() for keyword in ["vssadmin", "bcdedit", "wbadmin", "wmic", "taskkill"]):
                    results["command_patterns"].append(cmd)
        
        # Extract file operations
        file_operations = behaviors.get("file_operations", [])
        for op in file_operations:
            if "path" in op:
                path = op["path"]
                filename = os.path.basename(path)
                
                # Check for ransom notes
                if any(pattern in filename.lower() for pattern in ["readme", "decrypt", "how_to", "recover", "restore"]):
                    results["ransom_note_content"].append(path)
                
                # Check for encrypted files
                ext = os.path.splitext(filename)[1].lower()
                if ext and ext not in ['.exe', '.dll', '.sys', '.bin', '.dat']:
                    results["file_markers"].append(ext)
        
        return results
    
    def compare(self, sample_features: Dict[str, Any], family_features: Dict[str, Any]) -> float:
        """
        Compare string patterns between sample and family
        
        Args:
            sample_features: Features extracted from sample
            family_features: Features for a ransomware family
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        score = 0.0
        max_score = 0.0
        
        # Compare each feature category
        categories = ["ransom_note_content", "encryption_references", "payment_references", 
                     "file_markers", "command_patterns", "url_patterns"]
        
        for category in categories:
            # Skip empty categories
            if not sample_features.get(category) or not family_features.get(category):
                continue
            
            max_score += 1.0
            
            # Calculate similarity for this category
            matches = 0
            for family_pattern in family_features[category]:
                for sample_pattern in sample_features[category]:
                    # Exact match
                    if family_pattern.lower() == sample_pattern.lower():
                        matches += 1
                        break
                    
                    # Partial match for longer strings
                    if len(family_pattern) > 10 and len(sample_pattern) > 10:
                        similarity = difflib.SequenceMatcher(None, family_pattern.lower(), sample_pattern.lower()).ratio()
                        if similarity > 0.7:  # High similarity threshold
                            matches += similarity
                            break
            
            # Calculate category score
            if len(family_features[category]) > 0:
                category_score = min(matches / len(family_features[category]), 1.0)
                score += category_score
        
        # Return normalized score
        return score / max_score if max_score > 0 else 0.0


class BehaviorFeature(RansomwareFamilyFeature):
    """Feature based on behavioral patterns observed in ransomware samples"""
    
    def __init__(self, weight: float = 1.2):
        """
        Initialize the behavior feature
        
        Args:
            weight: Feature weight for scoring
        """
        super().__init__("behavior_patterns", weight)
    
    def extract(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract behavioral patterns from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            Dictionary containing extracted behavioral patterns
        """
        results = {
            "file_operations": {},   # Types of file operations observed
            "registry_keys": [],     # Registry keys accessed
            "api_calls": {},         # API calls made by the sample
            "network_indicators": {},  # Network activity patterns
            "process_actions": [],   # Process-related actions
            "command_patterns": []   # Command execution patterns
        }
        
        # Extract behavior data
        behaviors = sample_data.get("analysis", {}).get("behaviors", {})
        
        # Process file operations
        file_ops = behaviors.get("file_operations", [])
        operations_count = {"read": 0, "write": 0, "delete": 0, "rename": 0}
        file_extensions = set()
        
        for op in file_ops:
            op_type = op.get("type", "unknown")
            if op_type in operations_count:
                operations_count[op_type] += 1
            
            if "path" in op:
                ext = os.path.splitext(op["path"])[1].lower()
                if ext:
                    file_extensions.add(ext)
        
        results["file_operations"] = {
            "operations_count": operations_count,
            "extensions_accessed": list(file_extensions),
            "total_operations": len(file_ops)
        }
        
        # Process registry operations
        registry = behaviors.get("registry", {})
        results["registry_keys"] = registry.get("keys_set", []) + registry.get("keys_deleted", [])
        
        # Process API calls
        api_calls = behaviors.get("api_calls", {})
        for category, calls in api_calls.items():
            results["api_calls"][category] = list(calls)
        
        # Process network activity
        network = behaviors.get("network", {})
        results["network_indicators"] = {
            "domains": network.get("domains", []),
            "ips": network.get("ips", []),
            "urls": network.get("urls", []),
            "protocols": network.get("protocols", [])
        }
        
        # Process process actions
        processes = behaviors.get("processes", [])
        for process in processes:
            if "name" in process and "command_line" in process:
                process_action = {
                    "name": process["name"],
                    "command_line": process["command_line"]
                }
                results["process_actions"].append(process_action)
                
                # Extract command patterns
                cmd = process["command_line"].lower()
                if any(keyword in cmd for keyword in ["vssadmin", "bcdedit", "wbadmin", "wmic", "taskkill", "shadowcopy"]):
                    results["command_patterns"].append(cmd)
        
        return results
    
    def compare(self, sample_features: Dict[str, Any], family_features: Dict[str, Any]) -> float:
        """
        Compare behavioral patterns between sample and family
        
        Args:
            sample_features: Features extracted from sample
            family_features: Features for a ransomware family
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        score = 0.0
        max_score = 0.0
        
        # Compare file operations
        if "file_operations" in sample_features and "file_operations" in family_features:
            max_score += 1.0
            
            sample_ops = sample_features["file_operations"]
            family_ops = family_features["file_operations"]
            
            # Compare total operations volume
            if "total_operations" in sample_ops and "total_operations" in family_ops:
                ratio = min(sample_ops["total_operations"] / max(family_ops["total_operations"], 1), 1.0)
                score += ratio * 0.5
            
            # Compare file extensions
            if "extensions_accessed" in sample_ops and "extensions_accessed" in family_ops:
                sample_exts = set(sample_ops["extensions_accessed"])
                family_exts = set(family_ops["extensions_accessed"])
                
                if family_exts:
                    intersection = sample_exts.intersection(family_exts)
                    ratio = len(intersection) / len(family_exts)
                    score += ratio * 0.5
        
        # Compare registry keys
        if "registry_keys" in sample_features and "registry_keys" in family_features:
            max_score += 1.0
            
            sample_keys = set(sample_features["registry_keys"])
            family_keys = set(family_features["registry_keys"])
            
            if family_keys:
                matches = 0
                for family_key in family_keys:
                    for sample_key in sample_keys:
                        if family_key.lower() in sample_key.lower() or sample_key.lower() in family_key.lower():
                            matches += 1
                            break
                
                ratio = matches / len(family_keys)
                score += ratio
        
        # Compare command patterns
        if "command_patterns" in sample_features and "command_patterns" in family_features:
            max_score += 1.0
            
            sample_cmds = sample_features["command_patterns"]
            family_cmds = family_features["command_patterns"]
            
            if family_cmds:
                matches = 0
                for family_cmd in family_cmds:
                    for sample_cmd in sample_cmds:
                        if family_cmd.lower() in sample_cmd.lower():
                            matches += 1
                            break
                
                ratio = min(matches / len(family_cmds), 1.0)
                score += ratio
        
        # Compare network indicators
        if "network_indicators" in sample_features and "network_indicators" in family_features:
            max_score += 1.0
            
            sample_net = sample_features["network_indicators"]
            family_net = family_features["network_indicators"]
            
            # Compare domains
            domain_score = 0.0
            if "domains" in sample_net and "domains" in family_net and family_net["domains"]:
                sample_domains = set(sample_net["domains"])
                family_domains = set(family_net["domains"])
                
                # Check for exact domain matches
                exact_matches = sample_domains.intersection(family_domains)
                if exact_matches:
                    domain_score = 0.7  # High score for exact domain match
                else:
                    # Check for partial domain matches (e.g., same TLD or similar patterns)
                    for family_domain in family_domains:
                        for sample_domain in sample_domains:
                            similarity = difflib.SequenceMatcher(None, family_domain, sample_domain).ratio()
                            if similarity > 0.7:
                                domain_score = max(domain_score, similarity * 0.5)
            
            # Compare IPs
            ip_score = 0.0
            if "ips" in sample_net and "ips" in family_net and family_net["ips"]:
                sample_ips = set(sample_net["ips"])
                family_ips = set(family_net["ips"])
                
                # Check for exact IP matches
                exact_matches = sample_ips.intersection(family_ips)
                if exact_matches:
                    ip_score = 0.7
                else:
                    # Check for IP subnet matches
                    for family_ip in family_ips:
                        fam_parts = family_ip.split('.')
                        for sample_ip in sample_ips:
                            sam_parts = sample_ip.split('.')
                            if len(fam_parts) >= 2 and len(sam_parts) >= 2:
                                # Check if first two octets match (same subnet)
                                if fam_parts[0] == sam_parts[0] and fam_parts[1] == sam_parts[1]:
                                    ip_score = max(ip_score, 0.4)
            
            # Combine network scores
            score += max(domain_score, ip_score)
        
        # Return normalized score
        return score / max_score if max_score > 0 else 0.0


class FileStructureFeature(RansomwareFamilyFeature):
    """Feature based on file structure and format patterns in ransomware samples"""
    
    def __init__(self, weight: float = 1.1):
        """
        Initialize the file structure feature
        
        Args:
            weight: Feature weight for scoring
        """
        super().__init__("file_structure", weight)
    
    def extract(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract file structure patterns from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            Dictionary containing extracted file structure patterns
        """
        results = {
            "file_type": sample_data.get("analysis", {}).get("file_type", "unknown"),
            "file_size": sample_data.get("size", 0),
            "pe_sections": [],
            "section_entropy": {},
            "imports": [],
            "exports": [],
            "resources": [],
            "file_header": {},
            "encryption_markers": []
        }
        
        # Extract static analysis data
        static = sample_data.get("analysis", {}).get("static", {})
        
        # Process PE sections
        sections = static.get("pe_sections", [])
        for section in sections:
            results["pe_sections"].append(section.get("name", ""))
            results["section_entropy"][section.get("name", "")] = section.get("entropy", 0)
        
        # Process imports
        imports = static.get("imports", {})
        for library, functions in imports.items():
            for function in functions:
                results["imports"].append(f"{library}.{function}")
        
        # Process exports
        results["exports"] = static.get("exports", [])
        
        # Process resources
        resources = static.get("resources", [])
        for resource in resources:
            if "name" in resource:
                results["resources"].append(resource["name"])
        
        # Process file header
        header = static.get("file_header", {})
        results["file_header"] = {
            "timestamp": header.get("timestamp", ""),
            "characteristics": header.get("characteristics", []),
            "machine_type": header.get("machine_type", "")
        }
        
        # Look for encryption markers
        strings = sample_data.get("analysis", {}).get("strings", [])
        for string in strings:
            if any(marker in string.lower() for marker in ["aes", "rsa", "encrypt", "decrypt", 
                                                          "salsa20", "chacha", "twofish", 
                                                          "blowfish", "serpent", "rc4"]):
                results["encryption_markers"].append(string)
        
        return results
    
    def compare(self, sample_features: Dict[str, Any], family_features: Dict[str, Any]) -> float:
        """
        Compare file structure patterns between sample and family
        
        Args:
            sample_features: Features extracted from sample
            family_features: Features for a ransomware family
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        score = 0.0
        max_score = 0.0
        
        # Compare file type
        if "file_type" in sample_features and "file_type" in family_features:
            max_score += 1.0
            if sample_features["file_type"] == family_features["file_type"]:
                score += 1.0
        
        # Compare PE sections
        if "pe_sections" in sample_features and "pe_sections" in family_features:
            max_score += 1.0
            
            sample_sections = set(sample_features["pe_sections"])
            family_sections = set(family_features["pe_sections"])
            
            if family_sections:
                intersection = sample_sections.intersection(family_sections)
                ratio = len(intersection) / len(family_sections)
                score += ratio
        
        # Compare section entropy
        if "section_entropy" in sample_features and "section_entropy" in family_features:
            max_score += 1.0
            
            sample_entropy = sample_features["section_entropy"]
            family_entropy = family_features["section_entropy"]
            
            # Check for common sections with similar entropy
            matches = 0
            for section, family_ent in family_entropy.items():
                if section in sample_entropy:
                    sample_ent = sample_entropy[section]
                    # If entropy values are within 0.5, consider it a match
                    if abs(family_ent - sample_ent) <= 0.5:
                        matches += 1
            
            if family_entropy:
                ratio = matches / len(family_entropy)
                score += ratio
        
        # Compare imports
        if "imports" in sample_features and "imports" in family_features:
            max_score += 1.0
            
            sample_imports = set(sample_features["imports"])
            family_imports = set(family_features["imports"])
            
            if family_imports:
                intersection = sample_imports.intersection(family_imports)
                ratio = len(intersection) / len(family_imports)
                score += ratio
        
        # Compare encryption markers
        if "encryption_markers" in sample_features and "encryption_markers" in family_features:
            max_score += 1.0
            
            sample_markers = sample_features["encryption_markers"]
            family_markers = family_features["encryption_markers"]
            
            if family_markers:
                matches = 0
                for family_marker in family_markers:
                    for sample_marker in sample_markers:
                        if family_marker.lower() in sample_marker.lower():
                            matches += 1
                            break
                
                ratio = min(matches / len(family_markers), 1.0)
                score += ratio
        
        # Return normalized score
        return score / max_score if max_score > 0 else 0.0


class NetworkIndicatorFeature(RansomwareFamilyFeature):
    """Feature based on network indicators observed in ransomware samples"""
    
    def __init__(self, weight: float = 0.9):
        """
        Initialize the network indicator feature
        
        Args:
            weight: Feature weight for scoring
        """
        super().__init__("network_indicators", weight)
    
    def extract(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract network indicators from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            Dictionary containing extracted network indicators
        """
        results = {
            "domains": [],
            "ips": [],
            "urls": [],
            "protocols": [],
            "ports": [],
            "traffic_patterns": [],
            "dns_requests": [],
            "http_requests": [],
            "c2_patterns": [],
            "tor_references": []
        }
        
        # Extract network behavior
        network = sample_data.get("analysis", {}).get("behaviors", {}).get("network", {})
        
        # Process domains
        results["domains"] = network.get("domains", [])
        
        # Process IPs
        results["ips"] = network.get("ips", [])
        
        # Process URLs
        results["urls"] = network.get("urls", [])
        
        # Process protocols
        results["protocols"] = network.get("protocols", [])
        
        # Process ports
        port_data = network.get("ports", [])
        results["ports"] = port_data
        
        # Process HTTP requests
        http_requests = network.get("http_requests", [])
        for request in http_requests:
            results["http_requests"].append({
                "method": request.get("method", ""),
                "url": request.get("url", ""),
                "headers": request.get("headers", {})
            })
        
        # Process DNS requests
        dns_requests = network.get("dns_requests", [])
        results["dns_requests"] = dns_requests
        
        # Check for TOR references
        strings = sample_data.get("analysis", {}).get("strings", [])
        for string in strings:
            if any(tor_ref in string.lower() for tor_ref in [".onion", "tor", "tor browser", "tor network", "anonymity"]):
                results["tor_references"].append(string)
        
        # Identify potential C2 patterns
        for domain in results["domains"]:
            # Look for algorithmically generated domains
            if len(domain) > 20 and re.match(r'^[a-z0-9]{20,}\.', domain):
                results["c2_patterns"].append({
                    "type": "dga_domain",
                    "value": domain
                })
        
        for url in results["urls"]:
            # Look for unusual URL paths
            if "/admin/" in url or "/panel/" in url or "/gate/" in url:
                results["c2_patterns"].append({
                    "type": "c2_path",
                    "value": url
                })
        
        return results
    
    def compare(self, sample_features: Dict[str, Any], family_features: Dict[str, Any]) -> float:
        """
        Compare network indicators between sample and family
        
        Args:
            sample_features: Features extracted from sample
            family_features: Features for a ransomware family
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        score = 0.0
        max_score = 0.0
        
        # Compare domains
        if "domains" in sample_features and "domains" in family_features:
            max_score += 1.0
            
            sample_domains = set(sample_features["domains"])
            family_domains = set(family_features["domains"])
            
            if family_domains:
                # Check for exact domain matches
                exact_matches = sample_domains.intersection(family_domains)
                if exact_matches:
                    score += 1.0
                else:
                    # Check for domain pattern matches
                    matches = 0
                    for family_domain in family_domains:
                        for sample_domain in sample_domains:
                            # Check for subdomain matches
                            if sample_domain.endswith(family_domain) or family_domain.endswith(sample_domain):
                                matches += 1
                                break
                            
                            # Check for similarity
                            similarity = difflib.SequenceMatcher(None, family_domain, sample_domain).ratio()
                            if similarity > 0.7:  # High similarity threshold
                                matches += similarity
                                break
                    
                    ratio = min(matches / len(family_domains), 1.0)
                    score += ratio
        
        # Compare IPs
        if "ips" in sample_features and "ips" in family_features:
            max_score += 1.0
            
            sample_ips = set(sample_features["ips"])
            family_ips = set(family_features["ips"])
            
            if family_ips:
                # Check for exact IP matches
                exact_matches = sample_ips.intersection(family_ips)
                if exact_matches:
                    score += 1.0
                else:
                    # Check for IP subnet matches
                    matches = 0
                    for family_ip in family_ips:
                        fam_parts = family_ip.split('.')
                        for sample_ip in sample_ips:
                            sam_parts = sample_ip.split('.')
                            if len(fam_parts) >= 2 and len(sam_parts) >= 2:
                                # Check if first two octets match (same subnet)
                                if fam_parts[0] == sam_parts[0] and fam_parts[1] == sam_parts[1]:
                                    matches += 1
                                    break
                    
                    ratio = min(matches / len(family_ips), 1.0)
                    score += ratio
        
        # Compare protocols and ports
        if "protocols" in sample_features and "protocols" in family_features:
            max_score += 1.0
            
            sample_protocols = set(sample_features["protocols"])
            family_protocols = set(family_features["protocols"])
            
            if family_protocols:
                intersection = sample_protocols.intersection(family_protocols)
                ratio = len(intersection) / len(family_protocols)
                score += ratio
        
        # Compare TOR references
        if "tor_references" in sample_features and "tor_references" in family_features:
            max_score += 1.0
            
            if sample_features["tor_references"] and family_features["tor_references"]:
                score += 1.0
        
        # Compare C2 patterns
        if "c2_patterns" in sample_features and "c2_patterns" in family_features:
            max_score += 1.0
            
            sample_c2_types = set(item["type"] for item in sample_features["c2_patterns"])
            family_c2_types = set(item["type"] for item in family_features["c2_patterns"])
            
            if family_c2_types:
                intersection = sample_c2_types.intersection(family_c2_types)
                ratio = len(intersection) / len(family_c2_types)
                score += ratio
        
        # Return normalized score
        return score / max_score if max_score > 0 else 0.0


class RansomwareExtensionFeature(RansomwareFamilyFeature):
    """Feature based on file extensions and naming patterns used by ransomware"""
    
    def __init__(self, weight: float = 1.3):
        """
        Initialize the extension feature
        
        Args:
            weight: Feature weight for scoring
        """
        super().__init__("ransomware_extensions", weight)
    
    def extract(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract file extension patterns from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            Dictionary containing extracted extension patterns
        """
        results = {
            "encrypted_extensions": [],
            "ransom_note_names": [],
            "file_renaming_patterns": [],
            "extension_append_mode": False,
            "email_references": []
        }
        
        # Extract file behaviors
        behaviors = sample_data.get("analysis", {}).get("behaviors", {})
        
        # Process file operations
        file_ops = behaviors.get("file_operations", [])
        created_files = []
        modified_files = []
        renamed_files = []
        
        for op in file_ops:
            op_type = op.get("type", "")
            if op_type == "write" and "path" in op:
                created_files.append(op["path"])
            elif op_type == "modify" and "path" in op:
                modified_files.append(op["path"])
            elif op_type == "rename" and "old_path" in op and "new_path" in op:
                renamed_files.append((op["old_path"], op["new_path"]))
        
        # Analyze created files for encrypted extensions
        for path in created_files:
            ext = os.path.splitext(path)[1].lower()
            if ext and ext not in ['.exe', '.dll', '.sys', '.bin', '.dat', '.tmp', '.log']:
                results["encrypted_extensions"].append(ext)
                
                # Check if the filename matches ransom note patterns
                filename = os.path.basename(path)
                if any(pattern in filename.lower() for pattern in ["readme", "decrypt", "how_to", "recover", "restore"]):
                    results["ransom_note_names"].append(filename)
        
        # Analyze renamed files for extension patterns
        for old_path, new_path in renamed_files:
            old_ext = os.path.splitext(old_path)[1].lower()
            new_ext = os.path.splitext(new_path)[1].lower()
            
            # If extension changed, record the new extension
            if old_ext != new_ext and new_ext:
                results["encrypted_extensions"].append(new_ext)
                
                # Check for extension append pattern (e.g., file.txt -> file.txt.encrypted)
                old_name = os.path.basename(old_path)
                new_name = os.path.basename(new_path)
                
                if new_name.startswith(old_name + "."):
                    results["extension_append_mode"] = True
                    append_ext = new_name[len(old_name):]
                    if append_ext not in results["encrypted_extensions"]:
                        results["encrypted_extensions"].append(append_ext)
                
                # Record file renaming pattern
                results["file_renaming_patterns"].append({
                    "old_name": os.path.basename(old_path),
                    "new_name": os.path.basename(new_path)
                })
        
        # Extract strings for email references (common in ransom notes)
        strings = sample_data.get("analysis", {}).get("strings", [])
        for string in strings:
            # Look for email addresses
            email_matches = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', string)
            for email in email_matches:
                if email not in results["email_references"]:
                    results["email_references"].append(email)
        
        # Remove duplicates
        results["encrypted_extensions"] = list(set(results["encrypted_extensions"]))
        results["ransom_note_names"] = list(set(results["ransom_note_names"]))
        
        return results
    
    def compare(self, sample_features: Dict[str, Any], family_features: Dict[str, Any]) -> float:
        """
        Compare extension patterns between sample and family
        
        Args:
            sample_features: Features extracted from sample
            family_features: Features for a ransomware family
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        score = 0.0
        max_score = 0.0
        
        # Compare encrypted extensions
        if "encrypted_extensions" in sample_features and "encrypted_extensions" in family_features:
            max_score += 1.0
            
            sample_exts = set(sample_features["encrypted_extensions"])
            family_exts = set(family_features["encrypted_extensions"])
            
            if family_exts:
                intersection = sample_exts.intersection(family_exts)
                ratio = len(intersection) / len(family_exts)
                score += ratio
        
        # Compare ransom note names
        if "ransom_note_names" in sample_features and "ransom_note_names" in family_features:
            max_score += 1.0
            
            matches = 0
            for family_note in family_features["ransom_note_names"]:
                for sample_note in sample_features["ransom_note_names"]:
                    if family_note.lower() in sample_note.lower() or sample_note.lower() in family_note.lower():
                        matches += 1
                        break
            
            if family_features["ransom_note_names"]:
                ratio = min(matches / len(family_features["ransom_note_names"]), 1.0)
                score += ratio
        
        # Compare extension append mode
        if "extension_append_mode" in sample_features and "extension_append_mode" in family_features:
            max_score += 1.0
            
            if sample_features["extension_append_mode"] == family_features["extension_append_mode"]:
                score += 1.0
        
        # Compare email references
        if "email_references" in sample_features and "email_references" in family_features:
            max_score += 1.0
            
            sample_emails = set(sample_features["email_references"])
            family_emails = set(family_features["email_references"])
            
            if family_emails:
                # Check for exact email matches
                intersection = sample_emails.intersection(family_emails)
                if intersection:
                    score += 1.0
                else:
                    # Check for email domain matches
                    sample_domains = set(email.split('@')[1] for email in sample_emails if '@' in email)
                    family_domains = set(email.split('@')[1] for email in family_emails if '@' in email)
                    
                    domain_intersection = sample_domains.intersection(family_domains)
                    if domain_intersection and family_domains:
                        ratio = len(domain_intersection) / len(family_domains)
                        score += ratio
        
        # Return normalized score
        return score / max_score if max_score > 0 else 0.0


class YaraRuleFeature(RansomwareFamilyFeature):
    """Feature based on YARA rule matching results"""
    
    def __init__(self, weight: float = 1.5, rules_dir: Optional[str] = None):
        """
        Initialize the YARA rule feature
        
        Args:
            weight: Feature weight for scoring
            rules_dir: Directory containing YARA rules (optional)
        """
        super().__init__("yara_rules", weight)
        self.rules_dir = rules_dir
        self.yara_rules = {}
        self._load_rules()
    
    def _load_rules(self) -> None:
        """Load YARA rules from the rules directory"""
        if not self.rules_dir or not os.path.exists(self.rules_dir):
            logger.warning("YARA rules directory not specified or not found")
            return
        
        try:
            # Attempt to import yara module
            import yara
            
            # Compile rules from directory
            rules_files = [os.path.join(self.rules_dir, f) for f in os.listdir(self.rules_dir) 
                          if f.endswith('.yar') or f.endswith('.yara')]
            
            for rule_file in rules_files:
                try:
                    namespace = os.path.basename(rule_file).split('.')[0]
                    rules = yara.compile(rule_file, namespace=namespace)
                    self.yara_rules[namespace] = rules
                    logger.info(f"Loaded YARA rules from {rule_file}")
                except Exception as e:
                    logger.error(f"Error compiling YARA rules from {rule_file}: {e}")
            
            logger.info(f"Loaded {len(self.yara_rules)} YARA rule sets")
            
        except ImportError:
            logger.warning("YARA module not available, YARA feature will not be used")
    
    def extract(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract YARA rule matches from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            Dictionary containing YARA rule match results
        """
        results = {
            "rule_matches": [],
            "family_matches": {}
        }
        
        # Check if YARA rule matches are already in the analysis data
        if "yara" in sample_data.get("analysis", {}):
            yara_data = sample_data["analysis"]["yara"]
            
            for match in yara_data:
                match_data = {
                    "rule": match.get("rule", ""),
                    "namespace": match.get("namespace", ""),
                    "tags": match.get("tags", []),
                    "meta": match.get("meta", {}),
                    "strings": match.get("strings", [])
                }
                
                results["rule_matches"].append(match_data)
                
                # Track family matches
                for tag in match.get("tags", []):
                    if "family:" in tag:
                        family = tag.split("family:")[1].strip()
                        if family not in results["family_matches"]:
                            results["family_matches"][family] = []
                        results["family_matches"][family].append(match.get("rule", ""))
                
                # Check meta for family info
                meta = match.get("meta", {})
                if "family" in meta:
                    family = meta["family"]
                    if family not in results["family_matches"]:
                        results["family_matches"][family] = []
                    results["family_matches"][family].append(match.get("rule", ""))
        
        # Perform YARA matching if we have loaded rules and sample path
        if self.yara_rules and "path" in sample_data:
            sample_path = sample_data["path"]
            
            if os.path.exists(sample_path):
                for namespace, rules in self.yara_rules.items():
                    try:
                        matches = rules.match(sample_path)
                        
                        for match in matches:
                            match_data = {
                                "rule": match.rule,
                                "namespace": namespace,
                                "tags": match.tags,
                                "meta": match.meta,
                                "strings": [(s[0], s[1], s[2].decode('utf-8', errors='replace')) 
                                           for s in match.strings]
                            }
                            
                            results["rule_matches"].append(match_data)
                            
                            # Track family matches
                            for tag in match.tags:
                                if "family:" in tag:
                                    family = tag.split("family:")[1].strip()
                                    if family not in results["family_matches"]:
                                        results["family_matches"][family] = []
                                    results["family_matches"][family].append(match.rule)
                            
                            # Check meta for family info
                            if hasattr(match, 'meta') and match.meta and "family" in match.meta:
                                family = match.meta["family"]
                                if family not in results["family_matches"]:
                                    results["family_matches"][family] = []
                                results["family_matches"][family].append(match.rule)
                                
                    except Exception as e:
                        logger.error(f"Error matching YARA rules from {namespace} on {sample_path}: {e}")
        
        return results
    
    def compare(self, sample_features: Dict[str, Any], family_features: Dict[str, Any]) -> float:
        """
        Compare YARA rule matches between sample and family
        
        Args:
            sample_features: Features extracted from sample
            family_features: Features for a ransomware family
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        score = 0.0
        max_score = 0.0
        
        # Check if family expects YARA matches
        if "family_matches" in family_features and family_features["family_matches"]:
            max_score += 1.0
            
            sample_families = set(sample_features.get("family_matches", {}).keys())
            family_families = set(family_features["family_matches"].keys())
            
            # Check for direct family matches
            intersection = sample_families.intersection(family_families)
            if intersection:
                # Direct family match is a strong indicator
                score += 1.0
        
        # Compare rule matches
        if "rule_matches" in sample_features and "rule_matches" in family_features:
            max_score += 1.0
            
            # Extract rule names from matches
            sample_rules = set(match["rule"] for match in sample_features["rule_matches"])
            family_rules = set(match["rule"] for match in family_features["rule_matches"])
            
            if family_rules:
                # Check for rule intersections
                intersection = sample_rules.intersection(family_rules)
                ratio = len(intersection) / len(family_rules)
                score += ratio
        
        # Return normalized score
        return score / max_score if max_score > 0 else 0.0


class EnhancedFamilyDetector:
    """Enhanced detector for ransomware families with variant support"""
    
    def __init__(self, families_dir: Optional[str] = None, yara_rules_dir: Optional[str] = None):
        """
        Initialize the enhanced family detector
        
        Args:
            families_dir: Directory containing family definition files
            yara_rules_dir: Directory containing YARA rules
        """
        # Set directories
        self.families_dir = families_dir
        if not families_dir:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.families_dir = os.path.join(base_dir, 'data', 'families')
        
        # Initialize features
        self.features = [
            StringPatternFeature(weight=1.0),
            BehaviorFeature(weight=1.2),
            FileStructureFeature(weight=1.1),
            NetworkIndicatorFeature(weight=0.9),
            RansomwareExtensionFeature(weight=1.3),
            YaraRuleFeature(weight=1.5, rules_dir=yara_rules_dir)
        ]
        
        # Load family data
        self.families = {}
        self.family_features = {}
        self.variant_mapping = {}
        self._load_families()
        
        logger.info(f"Enhanced Family Detector initialized with {len(self.families)} families and {len(self.features)} features")
    
    def _load_families(self) -> None:
        """Load family definitions from the families directory"""
        if not os.path.exists(self.families_dir):
            logger.warning(f"Families directory not found: {self.families_dir}")
            return
        
        # Load index file first if it exists
        index_file = os.path.join(self.families_dir, 'index.json')
        if os.path.exists(index_file):
            try:
                with open(index_file, 'r') as f:
                    index_data = json.load(f)
                
                # Process family aliases from index
                for family_info in index_data.get('families', []):
                    family_id = family_info.get('id', '').lower()
                    family_name = family_info.get('name', '').lower()
                    aliases = family_info.get('aliases', [])
                    
                    if family_id:
                        # Map all aliases to the canonical ID
                        for alias in aliases:
                            alias_lower = alias.lower()
                            self.variant_mapping[alias_lower] = family_id
                        
                        # Map the name to the ID as well
                        self.variant_mapping[family_name] = family_id
                
                logger.info(f"Loaded family index with {len(self.variant_mapping)} aliases")
                
            except Exception as e:
                logger.error(f"Error loading family index: {e}")
        
        # Load individual family definition files
        family_files = [f for f in os.listdir(self.families_dir) 
                       if f.endswith('.json') and f != 'index.json']
        
        for family_file in family_files:
            try:
                with open(os.path.join(self.families_dir, family_file), 'r') as f:
                    family_data = json.load(f)
                
                family_id = os.path.splitext(family_file)[0].lower()
                
                # Store family data
                self.families[family_id] = family_data
                
                # Extract aliases
                aliases = family_data.get('aliases', [])
                family_name = family_data.get('name', '').lower()
                
                # Map all aliases to the canonical ID
                for alias in aliases:
                    alias_lower = alias.lower()
                    self.variant_mapping[alias_lower] = family_id
                
                # Map the name to the ID as well if not already done
                if family_name not in self.variant_mapping:
                    self.variant_mapping[family_name] = family_id
                
                logger.info(f"Loaded family definition for {family_id} with {len(aliases)} aliases")
                
            except Exception as e:
                logger.error(f"Error loading family definition {family_file}: {e}")
        
        logger.info(f"Loaded {len(self.families)} family definitions with {len(self.variant_mapping)} total aliases")
    
    def normalize_family_name(self, family: str) -> str:
        """
        Normalize a family name to its canonical form
        
        Args:
            family: Family name or alias
            
        Returns:
            Canonical family ID
        """
        family_lower = family.lower()
        
        # Check direct match in variant mapping
        if family_lower in self.variant_mapping:
            return self.variant_mapping[family_lower]
        
        # Check for partial matches
        for alias, family_id in self.variant_mapping.items():
            if alias in family_lower or family_lower in alias:
                return family_id
        
        # If no match found, return the original (lowercase)
        return family_lower
    
    def extract_features(self, sample_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract all features from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            Dictionary of extracted features
        """
        features = {}
        
        for feature in self.features:
            try:
                feature_result = feature.extract(sample_data)
                features[feature.name] = feature_result
            except Exception as e:
                logger.error(f"Error extracting feature {feature.name}: {e}")
                features[feature.name] = {}
        
        return features
    
    def extract_family_features(self, family_id: str) -> Dict[str, Any]:
        """
        Extract expected features for a known family
        
        Args:
            family_id: Family ID
            
        Returns:
            Dictionary of expected features for the family
        """
        # Check if we already have cached features
        if family_id in self.family_features:
            return self.family_features[family_id]
        
        # Get family data
        family_data = self.families.get(family_id)
        if not family_data:
            logger.warning(f"Family {family_id} not found")
            return {}
        
        features = {}
        
        # Extract string patterns
        string_patterns = {
            "ransom_note_content": [],
            "encryption_references": [],
            "payment_references": [],
            "file_markers": [],
            "command_patterns": [],
            "url_patterns": []
        }
        
        # Get ransom note content
        ransom_note = family_data.get('technical_details', {}).get('ransom_note', {})
        string_patterns["ransom_note_content"] = ransom_note.get('content_markers', [])
        
        # Get encryption info
        encryption = family_data.get('technical_details', {}).get('encryption', {})
        if encryption:
            algorithm = encryption.get('algorithm', '')
            mode = encryption.get('mode', '')
            if algorithm:
                string_patterns["encryption_references"].append(algorithm)
            if mode:
                string_patterns["encryption_references"].append(mode)
        
        # Get file markers
        file_markers = family_data.get('technical_details', {}).get('file_markers', {})
        if file_markers:
            header = file_markers.get('header', '')
            footer = file_markers.get('footer', '')
            if header and header != "None":
                string_patterns["file_markers"].append(header)
            if footer and footer != "None":
                string_patterns["file_markers"].append(footer)
        
        # Get command patterns from execution behavior
        execution = family_data.get('technical_details', {}).get('execution_behavior', {})
        if execution:
            # Add persistence mechanism
            persistence = execution.get('persistence', '')
            if persistence and persistence != "None":
                string_patterns["command_patterns"].append(persistence)
            
            # Add privilege escalation techniques
            privilege_escalation = execution.get('privilege_escalation', '')
            if privilege_escalation and privilege_escalation != "None":
                string_patterns["command_patterns"].append(privilege_escalation)
            
            # Add lateral movement techniques
            lateral_movement = execution.get('lateral_movement', '')
            if lateral_movement and lateral_movement != "None":
                string_patterns["command_patterns"].append(lateral_movement)
        
        # Get URL patterns from network indicators
        network = family_data.get('technical_details', {}).get('network_indicators', {})
        if network:
            domains = network.get('c2_domains', [])
            tor = network.get('tor_addresses', [])
            string_patterns["url_patterns"].extend(domains)
            string_patterns["url_patterns"].extend(tor)
        
        features["string_patterns"] = string_patterns
        
        # Extract behavioral patterns
        behavior_patterns = {
            "file_operations": {
                "operations_count": {"read": 0, "write": 0, "delete": 0, "rename": 0},
                "extensions_accessed": [],
                "total_operations": 0
            },
            "registry_keys": [],
            "api_calls": {},
            "network_indicators": {
                "domains": network.get('c2_domains', []),
                "ips": [],
                "urls": network.get('tor_addresses', []),
                "protocols": []
            },
            "process_actions": [],
            "command_patterns": []
        }
        
        # Get file extensions
        extensions = family_data.get('technical_details', {}).get('extension', [])
        behavior_patterns["file_operations"]["extensions_accessed"] = extensions
        
        # Get execution behavior
        if execution:
            # Add anti-analysis techniques
            anti_analysis = execution.get('anti_analysis', [])
            for technique in anti_analysis:
                behavior_patterns["command_patterns"].append(technique)
        
        features["behavior_patterns"] = behavior_patterns
        
        # Extract ransomware extensions
        extension_features = {
            "encrypted_extensions": extensions,
            "ransom_note_names": ransom_note.get('filenames', []),
            "file_renaming_patterns": [],
            "extension_append_mode": any("." in ext for ext in extensions if ext.startswith('.')),
            "email_references": []
        }
        
        features["ransomware_extensions"] = extension_features
        
        # Extract YARA rule patterns
        yara_rules = {
            "rule_matches": [],
            "family_matches": {family_id: [f"{family_id}_ransomware"]}
        }
        
        # Get detection signatures
        signatures = family_data.get('detection_signatures', {})
        if signatures:
            yara_data = signatures.get('yara_rules', [])
            if yara_data and isinstance(yara_data, list) and len(yara_data) > 0:
                rule_name = f"{family_id}_ransomware"
                rule_strings = []
                
                # Extract pattern strings from the YARA rule content
                for line in yara_data:
                    if '$' in line and '=' in line:
                        rule_strings.append(line.strip())
                
                yara_rules["rule_matches"].append({
                    "rule": rule_name,
                    "namespace": "family_definitions",
                    "tags": [f"family:{family_id}", "ransomware"],
                    "meta": {"family": family_id},
                    "strings": rule_strings
                })
        
        features["yara_rules"] = yara_rules
        
        # Cache the features
        self.family_features[family_id] = features
        
        return features
    
    def compare_with_family(self, sample_features: Dict[str, Any], family_id: str) -> Dict[str, float]:
        """
        Compare sample features with a specific family
        
        Args:
            sample_features: Features extracted from sample
            family_id: Family ID to compare with
            
        Returns:
            Dictionary of feature scores
        """
        # Get family features
        family_features = self.extract_family_features(family_id)
        if not family_features:
            return {}
        
        scores = {}
        
        # Compare features
        for feature in self.features:
            if feature.name in sample_features and feature.name in family_features:
                try:
                    feature_score = feature.compare(sample_features[feature.name], family_features[feature.name])
                    scores[feature.name] = feature_score
                except Exception as e:
                    logger.error(f"Error comparing feature {feature.name} for family {family_id}: {e}")
                    scores[feature.name] = 0.0
            else:
                scores[feature.name] = 0.0
        
        return scores
    
    def calculate_family_score(self, feature_scores: Dict[str, float]) -> float:
        """
        Calculate overall family score from feature scores
        
        Args:
            feature_scores: Dictionary of feature scores
            
        Returns:
            Overall score (0.0 to 1.0)
        """
        total_weight = 0.0
        weighted_score = 0.0
        
        for feature in self.features:
            if feature.name in feature_scores:
                score = feature_scores[feature.name]
                weighted_score += score * feature.weight
                total_weight += feature.weight
        
        return weighted_score / total_weight if total_weight > 0 else 0.0
    
    def identify_family(self, sample_data: Dict[str, Any], min_score: float = 0.5) -> List[Dict[str, Any]]:
        """
        Identify the most likely ransomware family for a sample
        
        Args:
            sample_data: Sample analysis data
            min_score: Minimum score threshold for family identification
            
        Returns:
            List of identified families with scores, sorted by confidence
        """
        # Extract features from sample
        sample_features = self.extract_features(sample_data)
        
        results = []
        
        # Compare with each known family
        for family_id in self.families:
            try:
                # Compare features
                feature_scores = self.compare_with_family(sample_features, family_id)
                
                # Calculate overall score
                overall_score = self.calculate_family_score(feature_scores)
                
                # Add to results if score meets threshold
                if overall_score >= min_score:
                    family_name = self.families[family_id].get('name', family_id)
                    
                    result = {
                        "family_id": family_id,
                        "family_name": family_name,
                        "confidence": overall_score,
                        "feature_scores": feature_scores
                    }
                    
                    # Add additional family info
                    family_data = self.families[family_id]
                    result["aliases"] = family_data.get('aliases', [])
                    result["active"] = family_data.get('active', False)
                    result["first_seen"] = family_data.get('first_seen', 'unknown')
                    
                    # Check for variants
                    variant_info = self._identify_variant(sample_features, family_id, feature_scores)
                    if variant_info:
                        result["variant"] = variant_info
                    
                    results.append(result)
            except Exception as e:
                logger.error(f"Error identifying family {family_id}: {e}")
        
        # Sort by confidence
        results.sort(key=lambda x: x["confidence"], reverse=True)
        
        return results
    
    def _identify_variant(self, sample_features: Dict[str, Any], family_id: str, feature_scores: Dict[str, float]) -> Optional[Dict[str, Any]]:
        """
        Try to identify a specific variant of a ransomware family
        
        Args:
            sample_features: Features extracted from sample
            family_id: Family ID
            feature_scores: Feature scores for the family
            
        Returns:
            Variant information or None
        """
        # Get family data
        family_data = self.families.get(family_id)
        if not family_data:
            return None
        
        # Check for known variants in aliases
        aliases = family_data.get('aliases', [])
        if not aliases:
            return None
        
        # Look for distinct variant indicators
        # 1. Check for version numbers in string patterns
        string_patterns = sample_features.get('string_patterns', {})
        ransom_content = string_patterns.get('ransom_note_content', [])
        
        for alias in aliases:
            # Skip the main family name
            if alias.lower() == family_data.get('name', '').lower():
                continue
                
            # Check for alias in ransom note content
            for content in ransom_content:
                if alias.lower() in content.lower():
                    return {
                        "name": alias,
                        "confidence": 0.8,
                        "indicator": "ransom_note_content"
                    }
        
        # 2. Check for version-specific file extensions
        extensions = sample_features.get('ransomware_extensions', {}).get('encrypted_extensions', [])
        
        for alias in aliases:
            # Extract version part if present (e.g., "LockBit 2.0" -> "2.0")
            version_match = re.search(r'(\d+\.\d+)', alias)
            if version_match:
                version = version_match.group(1)
                
                # Check for version number in extensions
                for ext in extensions:
                    if version in ext:
                        return {
                            "name": alias,
                            "confidence": 0.7,
                            "indicator": "file_extension"
                        }
        
        # 3. Check YARA rule matches
        yara_features = sample_features.get('yara_rules', {})
        rule_matches = yara_features.get('rule_matches', [])
        
        for match in rule_matches:
            rule_name = match.get('rule', '').lower()
            meta = match.get('meta', {})
            
            # Check for variant info in YARA rule
            if "variant" in meta:
                variant = meta["variant"]
                # Verify if this variant matches one of our aliases
                for alias in aliases:
                    if variant.lower() in alias.lower() or alias.lower() in variant.lower():
                        return {
                            "name": alias,
                            "confidence": 0.9,
                            "indicator": "yara_match"
                        }
            
            # Check for variant info in rule name
            for alias in aliases:
                alias_words = alias.lower().split()
                if len(alias_words) > 1:  # Only check multi-word aliases (likely version numbers)
                    if all(word in rule_name for word in alias_words):
                        return {
                            "name": alias,
                            "confidence": 0.75,
                            "indicator": "yara_rule_name"
                        }
        
        # If no specific variant found, check for high string pattern match
        if 'string_patterns' in feature_scores and feature_scores['string_patterns'] > 0.7:
            # Use most recent alias as generic variant
            return {
                "name": aliases[0],  # Usually the most recent alias is first
                "confidence": 0.6,
                "indicator": "generic_match"
            }
        
        return None
    
    def add_family_definition(self, family_data: Dict[str, Any]) -> bool:
        """
        Add a new family definition
        
        Args:
            family_data: Family definition data
            
        Returns:
            True if family was added, False otherwise
        """
        # Validate required fields
        if 'name' not in family_data:
            logger.error("Family definition must include 'name' field")
            return False
        
        # Generate ID from name if not provided
        family_id = family_data.get('id', family_data['name'].lower().replace(' ', '_'))
        
        # Don't overwrite existing families
        if family_id in self.families:
            logger.warning(f"Family {family_id} already exists")
            return False
        
        try:
            # Save family definition
            self.families[family_id] = family_data
            
            # Update variant mapping
            family_name = family_data.get('name', '').lower()
            self.variant_mapping[family_name] = family_id
            
            # Add aliases
            for alias in family_data.get('aliases', []):
                alias_lower = alias.lower()
                self.variant_mapping[alias_lower] = family_id
            
            # Save to file
            output_file = os.path.join(self.families_dir, f"{family_id}.json")
            with open(output_file, 'w') as f:
                json.dump(family_data, f, indent=4)
            
            logger.info(f"Added new family definition: {family_id}")
            
            # Clear feature cache for this family
            if family_id in self.family_features:
                del self.family_features[family_id]
            
            return True
            
        except Exception as e:
            logger.error(f"Error adding family definition: {e}")
            return False
    
    def update_family_definition(self, family_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update an existing family definition
        
        Args:
            family_id: Family ID to update
            updates: Fields to update
            
        Returns:
            True if family was updated, False otherwise
        """
        if family_id not in self.families:
            logger.warning(f"Family {family_id} not found")
            return False
        
        try:
            # Update family data
            for key, value in updates.items():
                self.families[family_id][key] = value
            
            # Update aliases if changed
            if 'aliases' in updates:
                # Remove old aliases from mapping
                for alias, fid in list(self.variant_mapping.items()):
                    if fid == family_id and alias != family_id:
                        del self.variant_mapping[alias]
                
                # Add new aliases
                for alias in updates['aliases']:
                    alias_lower = alias.lower()
                    self.variant_mapping[alias_lower] = family_id
            
            # Update family name if changed
            if 'name' in updates:
                family_name = updates['name'].lower()
                self.variant_mapping[family_name] = family_id
            
            # Save to file
            output_file = os.path.join(self.families_dir, f"{family_id}.json")
            with open(output_file, 'w') as f:
                json.dump(self.families[family_id], f, indent=4)
            
            logger.info(f"Updated family definition: {family_id}")
            
            # Clear feature cache for this family
            if family_id in self.family_features:
                del self.family_features[family_id]
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating family definition: {e}")
            return False
    
    def update_index_file(self) -> bool:
        """
        Update the index file with current family information
        
        Returns:
            True if index was updated, False otherwise
        """
        try:
            # Create index data
            index_data = {
                "version": "2.1",
                "last_updated": datetime.datetime.now().isoformat(),
                "families_count": len(self.families),
                "families": []
            }
            
            # Add tags categories
            tags = {
                "active": [],
                "inactive": [],
                "has_decryptor": [],
                "no_decryptor": [],
                "by_sector": {},
                "encryption_algorithm": {},
                "notable_features": {}
            }
            
            # Add families to index
            for family_id, family_data in self.families.items():
                family_info = {
                    "id": family_id,
                    "name": family_data.get('name', family_id),
                    "aliases": family_data.get('aliases', []),
                    "first_seen": family_data.get('first_seen', 'unknown'),
                    "active": family_data.get('active', False),
                    "decryptors_available": "available_decryptors" in family_data,
                    "description": family_data.get('description', '')
                }
                
                index_data["families"].append(family_info)
                
                # Update tags
                if family_data.get('active', False):
                    tags["active"].append(family_id)
                else:
                    tags["inactive"].append(family_id)
                
                if "available_decryptors" in family_data:
                    tags["has_decryptor"].append(family_id)
                else:
                    tags["no_decryptor"].append(family_id)
                
                # Categorize by sector targeted
                for sector in family_data.get('sectors_targeted', []):
                    sector_key = sector.lower().replace(' ', '_')
                    if sector_key not in tags["by_sector"]:
                        tags["by_sector"][sector_key] = []
                    tags["by_sector"][sector_key].append(family_id)
                
                # Categorize by encryption algorithm
                enc_algo = family_data.get('technical_details', {}).get('encryption', {}).get('algorithm', '').lower()
                if enc_algo:
                    if enc_algo not in tags["encryption_algorithm"]:
                        tags["encryption_algorithm"][enc_algo] = []
                    tags["encryption_algorithm"][enc_algo].append(family_id)
                
                # Extract notable features
                execution = family_data.get('technical_details', {}).get('execution_behavior', {})
                
                if execution:
                    # Check for worm capabilities
                    lateral_movement = execution.get('lateral_movement', '')
                    if lateral_movement and "worm" in lateral_movement.lower():
                        if "worm_capabilities" not in tags["notable_features"]:
                            tags["notable_features"]["worm_capabilities"] = []
                        tags["notable_features"]["worm_capabilities"].append(family_id)
                    
                    # Check for multi-threading
                    if any("thread" in s.lower() for s in execution.get('anti_analysis', [])):
                        if "multi_threading" not in tags["notable_features"]:
                            tags["notable_features"]["multi_threading"] = []
                        tags["notable_features"]["multi_threading"].append(family_id)
            
            # Add tags to index
            index_data["tags"] = tags
            
            # Add decryption resources
            index_data["decryption_resources"] = {
                "no_more_ransom": "https://www.nomoreransom.org/",
                "emsisoft_ransomware_resources": "https://www.emsisoft.com/en/ransomware-decryption/",
                "kaspersky_nomoreransom": "https://noransom.kaspersky.com/",
                "europol_nomoreransom": "https://www.europol.europa.eu/partners-agreements/no-more-ransom"
            }
            
            # Save to file
            output_file = os.path.join(self.families_dir, "index.json")
            with open(output_file, 'w') as f:
                json.dump(index_data, f, indent=4)
            
            logger.info(f"Updated index file with {len(self.families)} families")
            return True
            
        except Exception as e:
            logger.error(f"Error updating index file: {e}")
            return False


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced Ransomware Family Detector")
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Identify command
    identify_parser = subparsers.add_parser('identify', help='Identify ransomware family')
    identify_parser.add_argument('--sample', required=True, help='Path to sample analysis JSON file')
    identify_parser.add_argument('--min-score', type=float, default=0.5, help='Minimum score threshold')
    identify_parser.add_argument('--output', help='Output file for results')
    
    # Add family command
    add_parser = subparsers.add_parser('add-family', help='Add a new family definition')
    add_parser.add_argument('--file', required=True, help='Path to family definition JSON file')
    
    # Update family command
    update_parser = subparsers.add_parser('update-family', help='Update a family definition')
    update_parser.add_argument('--id', required=True, help='Family ID to update')
    update_parser.add_argument('--file', required=True, help='Path to updated family definition JSON file')
    
    # List families command
    list_parser = subparsers.add_parser('list', help='List known families')
    list_parser.add_argument('--active', action='store_true', help='Show only active families')
    list_parser.add_argument('--details', action='store_true', help='Show detailed family information')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Create detector
    detector = EnhancedFamilyDetector()
    
    if args.command == 'identify':
        # Load sample data
        try:
            with open(args.sample, 'r') as f:
                sample_data = json.load(f)
            
            # Identify family
            results = detector.identify_family(sample_data, args.min_score)
            
            # Output results
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=4)
            else:
                print(json.dumps(results, indent=4))
            
            print(f"\nIdentified {len(results)} potential families")
            for i, result in enumerate(results):
                print(f"{i+1}. {result['family_name']} - Confidence: {result['confidence']:.2f}")
                if "variant" in result:
                    print(f"   Variant: {result['variant']['name']} (Confidence: {result['variant']['confidence']:.2f})")
            
        except Exception as e:
            print(f"Error identifying family: {e}")
            import traceback
            traceback.print_exc()
    
    elif args.command == 'add-family':
        # Load family definition
        try:
            with open(args.file, 'r') as f:
                family_data = json.load(f)
            
            # Add family
            if detector.add_family_definition(family_data):
                print(f"Added family: {family_data.get('name')}")
                
                # Update index
                detector.update_index_file()
            else:
                print("Failed to add family")
                
        except Exception as e:
            print(f"Error adding family: {e}")
    
    elif args.command == 'update-family':
        # Load family definition
        try:
            with open(args.file, 'r') as f:
                updates = json.load(f)
            
            # Update family
            if detector.update_family_definition(args.id, updates):
                print(f"Updated family: {args.id}")
                
                # Update index
                detector.update_index_file()
            else:
                print(f"Failed to update family: {args.id}")
                
        except Exception as e:
            print(f"Error updating family: {e}")
    
    elif args.command == 'list':
        # List families
        families = []
        for family_id, family_data in detector.families.items():
            if args.active and not family_data.get('active', False):
                continue
                
            family_info = {
                "id": family_id,
                "name": family_data.get('name', family_id),
                "aliases": family_data.get('aliases', []),
                "active": family_data.get('active', False),
                "first_seen": family_data.get('first_seen', 'unknown')
            }
            
            families.append(family_info)
        
        # Sort by name
        families.sort(key=lambda x: x["name"])
        
        # Print families
        print(f"Found {len(families)} families:")
        for i, family in enumerate(families):
            status = "Active" if family["active"] else "Inactive"
            print(f"{i+1}. {family['name']} ({family['id']}) - {status}, First seen: {family['first_seen']}")
            
            if args.details:
                aliases = family.get('aliases', [])
                if aliases:
                    print(f"   Aliases: {', '.join(aliases)}")
    
    else:
        parser.print_help()