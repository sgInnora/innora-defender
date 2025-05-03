#!/usr/bin/env python3
"""
Threat Intelligence Correlation Engine
Correlates sample analysis findings with threat intelligence data to identify ransomware families and techniques.
"""

import os
import json
import logging
import datetime
from typing import Dict, List, Any, Optional, Set, Tuple
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('correlation_engine')

class CorrelationEngine:
    """
    Correlates analysis findings with threat intelligence data
    to identify malware families and techniques
    """
    
    def __init__(self, ti_manager=None):
        self.ti_manager = ti_manager
        self.cache_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'cache')
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Load known ransomware indicators
        self.ransomware_indicators = self._load_ransomware_indicators()
        
    def _load_ransomware_indicators(self) -> Dict:
        """Load known ransomware indicators from the indicators file"""
        indicators_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'ransomware_indicators.json')
        
        # Default indicators if file doesn't exist yet
        default_indicators = {
            "file_extensions": [
                ".encrypted", ".locked", ".crypted", ".crypt", ".crypto", ".enc", ".ransomware", ".gdcb",
                ".wncry", ".wcry", ".wncrypt", ".wncryt", ".encrypted", ".locky", ".zepto", ".thor",
                ".aesir", ".zzzzz", ".cryptowall", ".ecc", ".ezz", ".exx", ".sage", ".cerber", ".cerber2",
                ".cerber3", ".crypt", ".crypz", ".cryp1", ".onion", ".breaking_bad", ".legion", ".magic", 
                ".xtbl", ".coded", ".ha3", ".toxcrypt", ".0x0", ".bleep", ".btc", ".ctb2", ".ctbl", 
                ".rmd", ".lesli", ".rdmk", ".cryptolocker", ".scl", ".code", ".razy", ".xrtn", 
                ".restorebakup", ".restorebackup"
            ],
            "process_names": [
                "cryptolocker", "winlocker", "lockbit", "ryuk", "wannacrypt", "wannacry", "petya", 
                "notpetya", "locky", "cryptxxx", "cerber", "sage", "spora", "gandcrab", "badrabbit", 
                "samsamcrypt", "dharma", "crysis", "wannadecryptor", "cryptodefense", "encryptor"
            ],
            "bitcoin_patterns": [
                "bitcoin", "btc", "wallet", "payment", "ransom", "decrypt", "key", "timer", "deadline",
                "unlock", "restore", "pay", "demand", "cryptocurrency", "monero", "xmr", "eth", "ethereum"
            ],
            "registry_keys": [
                "HKEY_CURRENT_USER\\Software\\Locky",
                "HKEY_CURRENT_USER\\Software\\CryptoLocker",
                "HKEY_CURRENT_USER\\Software\\Cerber",
                "HKEY_CURRENT_USER\\Software\\WannaCry",
                "HKEY_CURRENT_USER\\Software\\Petya",
                "HKEY_CURRENT_USER\\Software\\Ryuk"
            ],
            "encryption_related": [
                "AES", "RSA", "encrypt", "decrypt", "key", "public key", "private key", "cryptography",
                "encryptor", "decryptor", "encryption", "decryption", "aes-256", "rsa-2048"
            ],
            "known_ransom_notes": [
                "README.txt", "DECRYPT.txt", "HOW_TO_DECRYPT.txt", "HELP_DECRYPT.txt", 
                "YOUR_FILES.txt", "DECRYPT_INSTRUCTION.txt", "HOW_TO_UNLOCK.txt",
                "HELP_RESTORE.txt", "HOW_DECRYPT.txt", "RECOVERY_FILES.txt",
                "RECOVERY_FILE.txt", "RESTORE_FILES.txt", "HELP_RECOVER.txt",
                "HELP_YOURFILES.txt", "READ_ME_FOR_DECRYPT.txt"
            ],
            "encryption_file_markers": [
                "CRYPTED", "ENCRYPTED", "LOCKED", "LOCK", "ENCRYPTOR", "DECRYPTOR",
                "CIPHER", "RANSOM", "WNCRYPT"
            ]
        }
        
        try:
            if os.path.exists(indicators_file):
                with open(indicators_file, 'r') as f:
                    return json.load(f)
            else:
                # Create the file with default indicators
                with open(indicators_file, 'w') as f:
                    json.dump(default_indicators, f, indent=2)
                return default_indicators
        except Exception as e:
            logger.error(f"Error loading ransomware indicators: {e}")
            return default_indicators
    
    def _calculate_ransomware_probability(self, sample_data: Dict) -> float:
        """
        Calculate the probability that a sample is ransomware based on indicators
        
        Args:
            sample_data: Dictionary containing sample analysis data
            
        Returns:
            Probability from 0.0 to 1.0 that the sample is ransomware
        """
        score = 0.0
        max_score = 0.0
        
        # Check file extensions
        if "strings" in sample_data.get("analysis", {}):
            strings = sample_data["analysis"]["strings"]
            max_score += 1.0
            for ext in self.ransomware_indicators["file_extensions"]:
                if any(ext in s for s in strings):
                    score += 1.0
                    break
        
        # Check for bitcoin/payment related strings
        if "strings" in sample_data.get("analysis", {}):
            strings = sample_data["analysis"]["strings"]
            max_score += 1.0
            btc_matches = 0
            for pattern in self.ransomware_indicators["bitcoin_patterns"]:
                if any(pattern.lower() in s.lower() for s in strings):
                    btc_matches += 1
            if btc_matches >= 3:  # If at least 3 payment related terms are found
                score += 1.0
        
        # Check for encryption related strings
        if "strings" in sample_data.get("analysis", {}):
            strings = sample_data["analysis"]["strings"]
            max_score += 1.0
            encryption_matches = 0
            for pattern in self.ransomware_indicators["encryption_related"]:
                if any(pattern.lower() in s.lower() for s in strings):
                    encryption_matches += 1
            if encryption_matches >= 2:  # If at least 2 encryption related terms are found
                score += 1.0
        
        # Check for ransom note names
        if "files" in sample_data.get("analysis", {}):
            files = sample_data["analysis"]["files"]
            max_score += 1.0
            for note in self.ransomware_indicators["known_ransom_notes"]:
                if any(note.lower() in f.lower() for f in files):
                    score += 1.0
                    break
        
        # Check for file encryption activities (from behavioral analysis)
        if "behaviors" in sample_data.get("analysis", {}):
            behaviors = sample_data["analysis"]["behaviors"]
            
            # Check for mass file operations
            if "file_operations" in behaviors:
                file_ops = behaviors["file_operations"]
                file_extensions = set()
                for op in file_ops:
                    if "path" in op:
                        _, ext = os.path.splitext(op["path"])
                        if ext:
                            file_extensions.add(ext.lower())
                
                max_score += 1.0
                # If the sample touches files with many different extensions (typical for ransomware)
                if len(file_extensions) > 5:
                    score += 1.0
            
            # Check for encryption markers in created files
            if "created_files" in behaviors:
                created_files = behaviors["created_files"]
                max_score += 1.0
                for marker in self.ransomware_indicators["encryption_file_markers"]:
                    if any(marker.lower() in f.lower() for f in created_files):
                        score += 1.0
                        break
        
        # If we have threat intelligence data that classifies this as ransomware
        if "threat_intel" in sample_data:
            max_score += 2.0
            
            # Check VirusTotal classifications
            vt_data = sample_data.get("threat_intel", {}).get("virustotal", {})
            if vt_data and "detections" in vt_data:
                ransomware_detections = 0
                total_detections = len(vt_data["detections"])
                
                if total_detections > 0:
                    for av_name, detection in vt_data["detections"].items():
                        if any(kw in detection.lower() for kw in ["ransom", "crypt", "lock"]):
                            ransomware_detections += 1
                    
                    # If more than 30% of detections classify as ransomware
                    if ransomware_detections / total_detections > 0.3:
                        score += 1.0
            
            # Check AlienVault classifications
            av_data = sample_data.get("threat_intel", {}).get("alienvault", {})
            if av_data:
                # Check tags
                if "tags" in av_data:
                    if any(tag.lower() in ["ransomware", "crypter", "encryptor", "locker"] for tag in av_data["tags"]):
                        score += 0.5
                
                # Check pulses
                if "pulses" in av_data:
                    if any(any(kw in pulse.lower() for kw in ["ransom", "crypt", "lock"]) for pulse in av_data["pulses"]):
                        score += 0.5
                
                # Check malware families
                if "malware_families" in av_data:
                    for family in av_data["malware_families"]:
                        # Use threat intel to check if this family is ransomware
                        if any(kw in family.lower() for kw in ["ransom", "crypt", "lock"]):
                            score += 1.0
                            break
        
        # Calculate final probability
        if max_score > 0:
            return min(score / max_score, 1.0)
        return 0.0
    
    def _identify_ransomware_family(self, sample_data: Dict) -> List[Dict]:
        """
        Identify potential ransomware families based on analysis and threat intelligence
        
        Args:
            sample_data: Dictionary containing sample analysis data
            
        Returns:
            List of dictionaries containing identified families with confidence scores
        """
        families = []
        family_scores = {}
        
        # Check VirusTotal detections
        vt_data = sample_data.get("threat_intel", {}).get("virustotal", {})
        if vt_data and "detections" in vt_data:
            for av_name, detection in vt_data["detections"].items():
                if not detection:
                    continue
                    
                # Common patterns in AV detection strings:
                # "Ransom.FamilyName", "Trojan.Ransom.FamilyName", "FamilyName.Ransom"
                detection_lower = detection.lower()
                if any(kw in detection_lower for kw in ["ransom", "crypt", "lock"]):
                    # Extract family name
                    family_name = None
                    parts = detection_lower.split(".")
                    
                    # Try to identify the family name part
                    for i, part in enumerate(parts):
                        if i > 0 and parts[i-1] in ["ransom", "crypt", "lock"]:
                            family_name = part
                            break
                        elif i < len(parts) - 1 and parts[i+1] in ["ransom", "crypt", "lock"]:
                            family_name = part
                            break
                    
                    # If we couldn't find, just use the second part if it exists
                    if not family_name and len(parts) > 1:
                        family_name = parts[1]
                    
                    # Skip generic detections
                    if family_name in ["gen", "generic", "malware", "trojan", "virus"]:
                        continue
                    
                    if family_name:
                        if family_name in family_scores:
                            family_scores[family_name] += 1
                        else:
                            family_scores[family_name] = 1
        
        # Check AlienVault data
        av_data = sample_data.get("threat_intel", {}).get("alienvault", {})
        if av_data and "malware_families" in av_data:
            for family in av_data["malware_families"]:
                if family.lower() in family_scores:
                    family_scores[family.lower()] += 2  # Higher weight for AlienVault
                else:
                    family_scores[family.lower()] = 2
        
        # Get total detections for calculating confidence
        total_detections = 0
        if vt_data and "detections" in vt_data:
            total_detections += len(vt_data["detections"])
        
        # Convert scores to confidence levels
        for family, score in family_scores.items():
            confidence = min(score / (total_detections * 0.3 if total_detections > 0 else 1), 1.0)
            families.append({
                "name": family,
                "confidence": confidence,
                "score": score
            })
        
        # Sort by confidence
        families.sort(key=lambda x: x["confidence"], reverse=True)
        
        return families[:5]  # Return top 5 families
    
    def _extract_iocs_from_analysis(self, sample_data: Dict) -> Dict:
        """
        Extract indicators of compromise from the sample analysis
        
        Args:
            sample_data: Dictionary containing sample analysis data
            
        Returns:
            Dictionary containing extracted IOCs by type
        """
        iocs = {
            "hashes": [],
            "domains": [],
            "ips": [],
            "urls": [],
            "files": [],
            "registry_keys": []
        }
        
        # Extract file hashes
        if "sha256" in sample_data:
            iocs["hashes"].append({"type": "sha256", "value": sample_data["sha256"]})
        if "md5" in sample_data:
            iocs["hashes"].append({"type": "md5", "value": sample_data["md5"]})
        if "sha1" in sample_data:
            iocs["hashes"].append({"type": "sha1", "value": sample_data["sha1"]})
        
        # Extract domains, IPs, and URLs from network behavior
        if "behaviors" in sample_data.get("analysis", {}):
            behaviors = sample_data["analysis"]["behaviors"]
            
            if "network" in behaviors:
                network = behaviors["network"]
                
                # Extract domains
                if "domains" in network:
                    for domain in network["domains"]:
                        iocs["domains"].append({"value": domain})
                
                # Extract IPs
                if "ips" in network:
                    for ip in network["ips"]:
                        iocs["ips"].append({"value": ip})
                
                # Extract URLs
                if "urls" in network:
                    for url in network["urls"]:
                        iocs["urls"].append({"value": url})
            
            # Extract created files
            if "created_files" in behaviors:
                for file_path in behaviors["created_files"]:
                    if any(marker.lower() in file_path.lower() 
                           for marker in self.ransomware_indicators["encryption_file_markers"] + 
                                          self.ransomware_indicators["known_ransom_notes"]):
                        iocs["files"].append({"value": file_path, "type": "ransom_artifact"})
            
            # Extract registry keys
            if "registry" in behaviors:
                for key in behaviors["registry"].get("keys_set", []):
                    iocs["registry_keys"].append({"value": key})
        
        return iocs
    
    def correlate_sample(self, sample_data: Dict) -> Dict:
        """
        Correlate sample analysis data with threat intelligence
        
        Args:
            sample_data: Dictionary containing sample analysis data
            
        Returns:
            Dictionary containing correlation results, including ransomware classification,
            identified families, TTPs, and extracted IOCs
        """
        # Initialize result structure
        result = {
            "sample_id": sample_data.get("sha256", "unknown"),
            "analysis_timestamp": datetime.datetime.now().isoformat(),
            "is_ransomware": False,
            "ransomware_probability": 0.0,
            "identified_families": [],
            "ttps": [],
            "iocs": {},
            "threat_intel": {}
        }
        
        # If we already have threat intelligence data, use it
        if "threat_intel" in sample_data:
            result["threat_intel"] = sample_data["threat_intel"]
        # Otherwise, if we have a threat intelligence manager, enrich the sample
        elif self.ti_manager:
            enriched_data = self.ti_manager.enrich_sample(sample_data)
            result["threat_intel"] = enriched_data.get("threat_intel", {})
            # Update sample_data with the enriched data for further correlation
            sample_data = enriched_data
        
        # Calculate ransomware probability
        result["ransomware_probability"] = self._calculate_ransomware_probability(sample_data)
        result["is_ransomware"] = result["ransomware_probability"] > 0.6
        
        # Identify ransomware families
        if result["is_ransomware"]:
            result["identified_families"] = self._identify_ransomware_family(sample_data)
        
        # Extract TTPs from MITRE data
        mitre_data = sample_data.get("threat_intel", {}).get("mitre", {})
        if mitre_data and "techniques" in mitre_data:
            result["ttps"] = [
                {
                    "id": technique["id"],
                    "name": technique["name"],
                    "tactics": [tactic["name"] for tactic in technique.get("tactics", [])]
                }
                for technique in mitre_data["techniques"]
            ]
        
        # Extract IOCs
        result["iocs"] = self._extract_iocs_from_analysis(sample_data)
        
        # Add recommendations based on analysis
        result["recommendations"] = self._generate_recommendations(result)
        
        return result
    
    def _generate_recommendations(self, correlation_result: Dict) -> List[Dict]:
        """
        Generate recommendations based on the correlation results
        
        Args:
            correlation_result: Dictionary containing correlation results
            
        Returns:
            List of recommendation objects
        """
        recommendations = []
        
        # Ransomware-specific recommendations
        if correlation_result["is_ransomware"]:
            recommendations.append({
                "type": "isolation",
                "priority": "high",
                "description": "Isolate infected systems immediately to prevent further encryption"
            })
            
            recommendations.append({
                "type": "memory_forensics",
                "priority": "high",
                "description": "Capture memory dumps from infected systems to potentially extract encryption keys"
            })
            
            recommendations.append({
                "type": "backup_verification",
                "priority": "high",
                "description": "Verify backup integrity and test restoration procedures"
            })
            
            # Add family-specific recommendations if available
            if correlation_result["identified_families"]:
                top_family = correlation_result["identified_families"][0]["name"]
                recommendations.append({
                    "type": "family_specific",
                    "priority": "medium",
                    "description": f"Investigate potential decryptor for {top_family} ransomware",
                    "link": f"https://www.nomoreransom.org/en/decryption-tools.html"
                })
        
        # Network-based recommendations based on IOCs
        if correlation_result["iocs"].get("domains") or correlation_result["iocs"].get("ips"):
            recommendations.append({
                "type": "network_blocking",
                "priority": "medium",
                "description": "Block communication with identified C2 servers to prevent further infection and data exfiltration"
            })
        
        # MITRE ATT&CK-based recommendations
        if correlation_result["ttps"]:
            # Group TTPs by tactic
            tactics = {}
            for ttp in correlation_result["ttps"]:
                for tactic in ttp.get("tactics", []):
                    if tactic not in tactics:
                        tactics[tactic] = []
                    tactics[tactic].append(ttp)
            
            # Generate recommendations based on tactics
            for tactic, ttps in tactics.items():
                if tactic == "initial-access":
                    recommendations.append({
                        "type": "mitigation",
                        "priority": "high",
                        "description": "Strengthen email filtering and user awareness training to prevent initial infection",
                        "mitre_tactic": tactic
                    })
                elif tactic == "execution":
                    recommendations.append({
                        "type": "mitigation",
                        "priority": "high",
                        "description": "Implement application whitelisting and script blocking to prevent malicious code execution",
                        "mitre_tactic": tactic
                    })
                elif tactic == "persistence":
                    recommendations.append({
                        "type": "mitigation",
                        "priority": "medium",
                        "description": "Regularly audit scheduled tasks, startup items, and registry keys used for persistence",
                        "mitre_tactic": tactic
                    })
                elif tactic == "defense-evasion":
                    recommendations.append({
                        "type": "mitigation",
                        "priority": "medium",
                        "description": "Monitor for suspicious process behavior and unexpected system changes",
                        "mitre_tactic": tactic
                    })
                elif tactic == "credential-access":
                    recommendations.append({
                        "type": "mitigation",
                        "priority": "high",
                        "description": "Implement multi-factor authentication and limit credential caching",
                        "mitre_tactic": tactic
                    })
                elif tactic == "lateral-movement":
                    recommendations.append({
                        "type": "mitigation",
                        "priority": "high",
                        "description": "Segment networks and restrict lateral movement capabilities",
                        "mitre_tactic": tactic
                    })
                elif tactic == "command-and-control":
                    recommendations.append({
                        "type": "mitigation",
                        "priority": "high",
                        "description": "Implement network monitoring and DNS filtering to detect and block C2 traffic",
                        "mitre_tactic": tactic
                    })
                elif tactic == "impact":
                    recommendations.append({
                        "type": "mitigation",
                        "priority": "high",
                        "description": "Ensure regular backups and implement data recovery procedures",
                        "mitre_tactic": tactic
                    })
        
        return recommendations
    
    def correlate_multiple_samples(self, samples: List[Dict]) -> Dict:
        """
        Find patterns and correlations across multiple samples
        
        Args:
            samples: List of dictionaries containing sample data (with correlation results)
            
        Returns:
            Dictionary containing correlation findings across samples
        """
        result = {
            "analysis_timestamp": datetime.datetime.now().isoformat(),
            "samples_analyzed": len(samples),
            "common_families": [],
            "common_ttps": [],
            "common_iocs": {
                "domains": [],
                "ips": [],
                "urls": [],
                "files": [],
                "registry_keys": []
            },
            "cluster_analysis": [],
            "campaign_indicators": []
        }
        
        # Skip if we don't have enough samples
        if len(samples) < 2:
            return result
        
        # Collect all families, TTPs, and IOCs
        all_families = {}
        all_ttps = {}
        all_domains = {}
        all_ips = {}
        all_urls = {}
        
        for sample in samples:
            # Process families
            for family in sample.get("identified_families", []):
                family_name = family["name"]
                if family_name in all_families:
                    all_families[family_name]["count"] += 1
                    all_families[family_name]["confidence"] += family["confidence"]
                else:
                    all_families[family_name] = {
                        "name": family_name,
                        "count": 1,
                        "confidence": family["confidence"]
                    }
            
            # Process TTPs
            for ttp in sample.get("ttps", []):
                ttp_id = ttp["id"]
                if ttp_id in all_ttps:
                    all_ttps[ttp_id]["count"] += 1
                else:
                    all_ttps[ttp_id] = {
                        "id": ttp_id,
                        "name": ttp["name"],
                        "count": 1,
                        "tactics": ttp.get("tactics", [])
                    }
            
            # Process IOCs
            for domain in sample.get("iocs", {}).get("domains", []):
                domain_value = domain["value"]
                if domain_value in all_domains:
                    all_domains[domain_value]["count"] += 1
                else:
                    all_domains[domain_value] = {
                        "value": domain_value,
                        "count": 1
                    }
            
            for ip in sample.get("iocs", {}).get("ips", []):
                ip_value = ip["value"]
                if ip_value in all_ips:
                    all_ips[ip_value]["count"] += 1
                else:
                    all_ips[ip_value] = {
                        "value": ip_value,
                        "count": 1
                    }
            
            for url in sample.get("iocs", {}).get("urls", []):
                url_value = url["value"]
                if url_value in all_urls:
                    all_urls[url_value]["count"] += 1
                else:
                    all_urls[url_value] = {
                        "value": url_value,
                        "count": 1
                    }
        
        # Find common elements (appearing in at least 2 samples or 30% of samples, whichever is higher)
        min_sample_threshold = max(2, int(len(samples) * 0.3))
        
        # Common families
        for family_name, family_data in all_families.items():
            if family_data["count"] >= min_sample_threshold:
                result["common_families"].append({
                    "name": family_name,
                    "count": family_data["count"],
                    "confidence": family_data["confidence"] / family_data["count"]  # Average confidence
                })
        
        # Common TTPs
        for ttp_id, ttp_data in all_ttps.items():
            if ttp_data["count"] >= min_sample_threshold:
                result["common_ttps"].append({
                    "id": ttp_id,
                    "name": ttp_data["name"],
                    "count": ttp_data["count"],
                    "tactics": ttp_data["tactics"]
                })
        
        # Common IOCs
        for domain_value, domain_data in all_domains.items():
            if domain_data["count"] >= min_sample_threshold:
                result["common_iocs"]["domains"].append({
                    "value": domain_value,
                    "count": domain_data["count"]
                })
        
        for ip_value, ip_data in all_ips.items():
            if ip_data["count"] >= min_sample_threshold:
                result["common_iocs"]["ips"].append({
                    "value": ip_value,
                    "count": ip_data["count"]
                })
        
        for url_value, url_data in all_urls.items():
            if url_data["count"] >= min_sample_threshold:
                result["common_iocs"]["urls"].append({
                    "value": url_value,
                    "count": url_data["count"]
                })
        
        # Sort by count (descending)
        result["common_families"].sort(key=lambda x: x["count"], reverse=True)
        result["common_ttps"].sort(key=lambda x: x["count"], reverse=True)
        result["common_iocs"]["domains"].sort(key=lambda x: x["count"], reverse=True)
        result["common_iocs"]["ips"].sort(key=lambda x: x["count"], reverse=True)
        result["common_iocs"]["urls"].sort(key=lambda x: x["count"], reverse=True)
        
        # Determine if samples are likely part of the same campaign
        if result["common_families"] and (result["common_iocs"]["domains"] or result["common_iocs"]["ips"]):
            # Check time range of samples
            timestamps = []
            for sample in samples:
                if "analysis_timestamp" in sample:
                    try:
                        timestamps.append(datetime.datetime.fromisoformat(sample["analysis_timestamp"]))
                    except (ValueError, TypeError):
                        pass
            
            if timestamps:
                time_range = max(timestamps) - min(timestamps)
                time_range_days = time_range.total_seconds() / (60 * 60 * 24)
                
                # If samples span less than 30 days, check for common patterns
                if time_range_days < 30:
                    result["campaign_indicators"].append({
                        "name": f"{result['common_families'][0]['name']} campaign",
                        "confidence": 0.8 if time_range_days < 7 else 0.6,
                        "common_family": result["common_families"][0]["name"],
                        "timespan_days": round(time_range_days, 1),
                        "sample_count": len(samples),
                        "key_iocs": {
                            "domains": [ioc["value"] for ioc in result["common_iocs"]["domains"][:3]],
                            "ips": [ioc["value"] for ioc in result["common_iocs"]["ips"][:3]],
                        }
                    })
        
        return result


if __name__ == "__main__":
    # Example usage
    engine = CorrelationEngine()
    
    # Sample data (would normally come from analysis and threat intelligence)
    sample_data = {
        "sha256": "aaaaaaaaabbbbbbbbccccccccdddddddd",
        "name": "sample_ransomware.exe",
        "size": 1024000,
        "analysis": {
            "file_type": "PE32 executable",
            "strings": ["encrypt", "bitcoin", "payment", ".encrypted", "README.txt"],
            "behaviors": {
                "network": {
                    "domains": ["badguy.com", "payment.badguy.com"],
                    "ips": ["192.168.1.1", "8.8.8.8"],
                    "urls": ["https://badguy.com/payment"]
                },
                "created_files": [
                    "C:\\Users\\victim\\Desktop\\README.txt",
                    "C:\\Users\\victim\\Documents\\file.encrypted"
                ]
            }
        },
        "threat_intel": {
            "virustotal": {
                "detections": {
                    "Kaspersky": "Trojan-Ransom.Win32.Locky.a",
                    "Symantec": "Ransom.Locky",
                    "Microsoft": "Ransom:Win32/Locky.A"
                }
            },
            "alienvault": {
                "malware_families": ["Locky"],
                "tags": ["ransomware", "trojan"]
            },
            "mitre": {
                "techniques": [
                    {
                        "id": "T1486",
                        "name": "Data Encrypted for Impact",
                        "tactics": ["impact"]
                    },
                    {
                        "id": "T1489",
                        "name": "Service Stop",
                        "tactics": ["impact"]
                    }
                ]
            }
        }
    }
    
    # Correlate the sample
    result = engine.correlate_sample(sample_data)
    
    # Print the correlation result
    print(json.dumps(result, indent=2))