#!/usr/bin/env python3
"""
Threat Intelligence Connector
Interfaces with multiple external threat intelligence sources to retrieve data on known ransomware families.
"""

import os
import json
import requests
import time
import hashlib
import logging
from typing import Dict, List, Any, Optional, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('threat_intel_connector')

class ThreatIntelConnector:
    """Base connector class for threat intelligence platforms"""
    
    def __init__(self, api_key: str = None, api_url: str = None):
        self.api_key = api_key or os.environ.get('THREAT_INTEL_API_KEY')
        self.api_url = api_url
        self.cache_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'cache')
        os.makedirs(self.cache_dir, exist_ok=True)
        
    def _get_cache_path(self, query: str) -> str:
        """Generate a cache file path based on the query hash"""
        query_hash = hashlib.md5(query.encode()).hexdigest()
        return os.path.join(self.cache_dir, f"{query_hash}.json")
        
    def _check_cache(self, query: str, max_age: int = 86400) -> Optional[Dict]:
        """Check if we have a cached response for this query"""
        cache_path = self._get_cache_path(query)
        if os.path.exists(cache_path):
            cache_age = time.time() - os.path.getmtime(cache_path)
            if cache_age < max_age:
                try:
                    with open(cache_path, 'r') as f:
                        return json.load(f)
                except (json.JSONDecodeError, IOError) as e:
                    logger.warning(f"Cache read error: {e}")
        return None
        
    def _save_cache(self, query: str, data: Dict) -> None:
        """Save response to cache"""
        cache_path = self._get_cache_path(query)
        try:
            with open(cache_path, 'w') as f:
                json.dump(data, f)
        except IOError as e:
            logger.warning(f"Cache write error: {e}")
            
    def query(self, ioc: str, ioc_type: str) -> Dict:
        """
        Query the threat intelligence platform for information
        
        Args:
            ioc: Indicator of compromise (hash, domain, etc.)
            ioc_type: Type of IOC (sha256, domain, ip, etc.)
            
        Returns:
            Dictionary containing threat intelligence data
        """
        raise NotImplementedError("Subclasses must implement query method")
        
    def enrich_sample(self, sample_data: Dict) -> Dict:
        """
        Enrich sample data with threat intelligence
        
        Args:
            sample_data: Dictionary containing sample analysis data
            
        Returns:
            Enriched data with threat intelligence information
        """
        raise NotImplementedError("Subclasses must implement enrich_sample method")
        
    def get_ransomware_family_info(self, family_name: str) -> Dict:
        """
        Get information about a specific ransomware family
        
        Args:
            family_name: Name of the ransomware family
            
        Returns:
            Dictionary containing family information, tactics, techniques, etc.
        """
        raise NotImplementedError("Subclasses must implement get_ransomware_family_info method")


class VirusTotalConnector(ThreatIntelConnector):
    """Connector for VirusTotal API"""
    
    def __init__(self, api_key: str = None):
        super().__init__(api_key=api_key, api_url="https://www.virustotal.com/api/v3")
        
    def query(self, ioc: str, ioc_type: str) -> Dict:
        """Query VirusTotal API for information about an indicator"""
        cache_key = f"vt_{ioc_type}_{ioc}"
        cached = self._check_cache(cache_key)
        if cached:
            return cached
            
        if not self.api_key:
            return {"error": "No API key configured for VirusTotal"}
            
        endpoint = ""
        if ioc_type == "hash":
            endpoint = f"/files/{ioc}"
        elif ioc_type == "domain":
            endpoint = f"/domains/{ioc}"
        elif ioc_type == "ip":
            endpoint = f"/ip_addresses/{ioc}"
        elif ioc_type == "url":
            endpoint = f"/urls/{ioc}"
        else:
            return {"error": f"Unsupported IOC type: {ioc_type}"}
            
        headers = {"x-apikey": self.api_key}
        try:
            response = requests.get(f"{self.api_url}{endpoint}", headers=headers)
            if response.status_code == 200:
                data = response.json()
                self._save_cache(cache_key, data)
                return data
            else:
                return {
                    "error": "API request failed",
                    "status_code": response.status_code,
                    "message": response.text
                }
        except Exception as e:
            logger.error(f"Error querying VirusTotal: {e}")
            return {"error": str(e)}
            
    def enrich_sample(self, sample_data: Dict) -> Dict:
        """Enrich sample data with VirusTotal information"""
        if "sha256" not in sample_data:
            return sample_data
            
        vt_data = self.query(sample_data["sha256"], "hash")
        if "error" in vt_data:
            sample_data["threat_intel"] = {"virustotal": {"error": vt_data["error"]}}
            return sample_data
            
        # Extract relevant information
        try:
            data = vt_data.get("data", {})
            attributes = data.get("attributes", {})
            
            threat_data = {
                "virustotal": {
                    "detection_ratio": f"{attributes.get('last_analysis_stats', {}).get('malicious', 0)}/{sum(attributes.get('last_analysis_stats', {}).values())}",
                    "first_seen": attributes.get("first_submission_date"),
                    "last_seen": attributes.get("last_analysis_date"),
                    "reputation": attributes.get("reputation"),
                    "detections": {}
                }
            }
            
            # Extract AV detections
            for av_name, av_result in attributes.get("last_analysis_results", {}).items():
                if av_result.get("category") == "malicious":
                    threat_data["virustotal"]["detections"][av_name] = av_result.get("result")
            
            # Extract ransomware family names from detections
            family_names = set()
            for detection in threat_data["virustotal"]["detections"].values():
                if detection and isinstance(detection, str):
                    # Common patterns in ransomware names in detections
                    if any(kw in detection.lower() for kw in ["ransom", "crypt", "lock"]):
                        parts = detection.split(".")
                        if len(parts) > 1:
                            family_names.add(parts[1].strip())
                            
            if family_names:
                threat_data["virustotal"]["possible_families"] = list(family_names)
                
            sample_data["threat_intel"] = threat_data
            
        except Exception as e:
            logger.error(f"Error processing VirusTotal data: {e}")
            sample_data["threat_intel"] = {"virustotal": {"error": str(e)}}
            
        return sample_data
        
    def get_ransomware_family_info(self, family_name: str) -> Dict:
        """Get information about a ransomware family from VirusTotal"""
        cache_key = f"vt_family_{family_name}"
        cached = self._check_cache(cache_key)
        if cached:
            return cached
            
        # For ransomware family info, we'll search VT for samples of this family
        if not self.api_key:
            return {"error": "No API key configured for VirusTotal"}
            
        headers = {"x-apikey": self.api_key}
        query = f"tag:ransomware type:file p:{family_name}"
        
        try:
            response = requests.get(
                f"{self.api_url}/intelligence/search",
                headers=headers,
                params={"query": query, "limit": 10}
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Process and extract family information
                family_info = {
                    "name": family_name,
                    "sample_count": data.get("meta", {}).get("total_hits", 0),
                    "samples": []
                }
                
                for item in data.get("data", []):
                    sample = {
                        "sha256": item.get("id"),
                        "first_seen": item.get("attributes", {}).get("first_submission_date"),
                        "detection_ratio": f"{item.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)}/{sum(item.get('attributes', {}).get('last_analysis_stats', {}).values())}"
                    }
                    family_info["samples"].append(sample)
                
                self._save_cache(cache_key, family_info)
                return family_info
            else:
                return {
                    "error": "API request failed",
                    "status_code": response.status_code,
                    "message": response.text
                }
        except Exception as e:
            logger.error(f"Error searching VirusTotal for family info: {e}")
            return {"error": str(e)}


class AlienVaultOTXConnector(ThreatIntelConnector):
    """Connector for AlienVault OTX API"""
    
    def __init__(self, api_key: str = None):
        super().__init__(api_key=api_key, api_url="https://otx.alienvault.com/api/v1")
        
    def query(self, ioc: str, ioc_type: str) -> Dict:
        """Query AlienVault OTX API for information about an indicator"""
        cache_key = f"otx_{ioc_type}_{ioc}"
        cached = self._check_cache(cache_key)
        if cached:
            return cached
            
        if not self.api_key:
            return {"error": "No API key configured for AlienVault OTX"}
            
        endpoint = ""
        if ioc_type == "hash":
            endpoint = f"/indicators/file/{ioc}/general"
        elif ioc_type == "domain":
            endpoint = f"/indicators/domain/{ioc}/general"
        elif ioc_type == "ip":
            endpoint = f"/indicators/IPv4/{ioc}/general"
        elif ioc_type == "url":
            endpoint = f"/indicators/url/{ioc}/general"
        else:
            return {"error": f"Unsupported IOC type: {ioc_type}"}
            
        headers = {"X-OTX-API-KEY": self.api_key}
        try:
            response = requests.get(f"{self.api_url}{endpoint}", headers=headers)
            if response.status_code == 200:
                data = response.json()
                self._save_cache(cache_key, data)
                return data
            else:
                return {
                    "error": "API request failed",
                    "status_code": response.status_code,
                    "message": response.text
                }
        except Exception as e:
            logger.error(f"Error querying AlienVault OTX: {e}")
            return {"error": str(e)}
            
    def enrich_sample(self, sample_data: Dict) -> Dict:
        """Enrich sample data with AlienVault OTX information"""
        if "sha256" not in sample_data:
            return sample_data
            
        otx_data = self.query(sample_data["sha256"], "hash")
        if "error" in otx_data:
            if "threat_intel" not in sample_data:
                sample_data["threat_intel"] = {}
            sample_data["threat_intel"]["alienvault"] = {"error": otx_data["error"]}
            return sample_data
            
        # Extract relevant information
        try:
            threat_data = {
                "alienvault": {
                    "pulse_count": otx_data.get("pulse_info", {}).get("count", 0),
                    "malware_families": [],
                    "tags": [],
                    "references": []
                }
            }
            
            # Extract pulses information
            for pulse in otx_data.get("pulse_info", {}).get("pulses", []):
                if "name" in pulse and any(kw in pulse["name"].lower() for kw in ["ransom", "crypt", "lock"]):
                    threat_data["alienvault"]["pulses"] = threat_data["alienvault"].get("pulses", []) + [pulse["name"]]
                    
                # Extract tags
                threat_data["alienvault"]["tags"].extend(pulse.get("tags", []))
                
                # Extract references
                threat_data["alienvault"]["references"].extend(pulse.get("references", []))
                
                # Extract malware families
                if "malware_families" in pulse:
                    for family in pulse["malware_families"]:
                        if family.get("family_name"):
                            threat_data["alienvault"]["malware_families"].append(family.get("family_name"))
            
            # Remove duplicates
            threat_data["alienvault"]["tags"] = list(set(threat_data["alienvault"]["tags"]))
            threat_data["alienvault"]["references"] = list(set(threat_data["alienvault"]["references"]))
            threat_data["alienvault"]["malware_families"] = list(set(threat_data["alienvault"]["malware_families"]))
            
            if "threat_intel" not in sample_data:
                sample_data["threat_intel"] = {}
                
            sample_data["threat_intel"].update(threat_data)
            
        except Exception as e:
            logger.error(f"Error processing AlienVault OTX data: {e}")
            if "threat_intel" not in sample_data:
                sample_data["threat_intel"] = {}
            sample_data["threat_intel"]["alienvault"] = {"error": str(e)}
            
        return sample_data
        
    def get_ransomware_family_info(self, family_name: str) -> Dict:
        """Get information about a ransomware family from AlienVault OTX"""
        cache_key = f"otx_family_{family_name}"
        cached = self._check_cache(cache_key)
        if cached:
            return cached
            
        if not self.api_key:
            return {"error": "No API key configured for AlienVault OTX"}
            
        headers = {"X-OTX-API-KEY": self.api_key}
        try:
            # Search for pulses related to this ransomware family
            response = requests.get(
                f"{self.api_url}/search/pulses",
                headers=headers,
                params={"q": f"ransomware {family_name}", "limit": 20}
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Process and extract family information
                family_info = {
                    "name": family_name,
                    "pulse_count": data.get("count", 0),
                    "pulses": [],
                    "iocs": [],
                    "references": [],
                    "tags": []
                }
                
                for pulse in data.get("results", []):
                    pulse_info = {
                        "name": pulse.get("name"),
                        "author": pulse.get("author", {}).get("username"),
                        "created": pulse.get("created")
                    }
                    family_info["pulses"].append(pulse_info)
                    
                    # Collect IOCs
                    for indicator in pulse.get("indicators", []):
                        family_info["iocs"].append({
                            "type": indicator.get("type"),
                            "indicator": indicator.get("indicator")
                        })
                    
                    # Collect references
                    family_info["references"].extend(pulse.get("references", []))
                    
                    # Collect tags
                    family_info["tags"].extend(pulse.get("tags", []))
                
                # Remove duplicates
                family_info["references"] = list(set(family_info["references"]))
                family_info["tags"] = list(set(family_info["tags"]))
                
                self._save_cache(cache_key, family_info)
                return family_info
            else:
                return {
                    "error": "API request failed",
                    "status_code": response.status_code,
                    "message": response.text
                }
        except Exception as e:
            logger.error(f"Error searching AlienVault OTX for family info: {e}")
            return {"error": str(e)}


class MitreTTPConnector(ThreatIntelConnector):
    """Connector for MITRE ATT&CK Framework data"""
    
    def __init__(self):
        super().__init__(api_url="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
        self.techniques_by_id = {}
        self.techniques_by_name = {}
        self.tactics_by_id = {}
        self.tactics_by_name = {}
        self.groups_by_id = {}
        self.groups_by_name = {}
        self.software_by_id = {}
        self.software_by_name = {}
        self._load_mitre_data()
        
    def _load_mitre_data(self):
        """Load MITRE ATT&CK data"""
        cache_key = "mitre_enterprise_attack"
        cached = self._check_cache(cache_key, max_age=7 * 86400)  # Cache for 7 days
        
        if cached:
            mitre_data = cached
        else:
            try:
                response = requests.get(self.api_url)
                if response.status_code == 200:
                    mitre_data = response.json()
                    self._save_cache(cache_key, mitre_data)
                else:
                    logger.error(f"Failed to fetch MITRE ATT&CK data: {response.status_code}")
                    return
            except Exception as e:
                logger.error(f"Error loading MITRE ATT&CK data: {e}")
                return
        
        # Process the MITRE data
        try:
            for obj in mitre_data.get("objects", []):
                obj_type = obj.get("type")
                obj_id = obj.get("id")
                
                if not obj_id:
                    continue
                
                if obj_type == "attack-pattern":
                    # This is a technique
                    technique_id = next((ref.get("external_id") for ref in obj.get("external_references", []) 
                                        if ref.get("source_name") == "mitre-attack"), None)
                    if technique_id:
                        name = obj.get("name", "")
                        description = obj.get("description", "")
                        
                        technique_data = {
                            "id": technique_id,
                            "name": name,
                            "description": description,
                            "mitre_id": obj_id,
                            "tactics": []
                        }
                        
                        # Get tactics this technique belongs to
                        for phase in obj.get("kill_chain_phases", []):
                            if phase.get("kill_chain_name") == "mitre-attack":
                                technique_data["tactics"].append(phase.get("phase_name"))
                        
                        self.techniques_by_id[technique_id] = technique_data
                        self.techniques_by_name[name.lower()] = technique_data
                
                elif obj_type == "x-mitre-tactic":
                    # This is a tactic
                    tactic_id = next((ref.get("external_id") for ref in obj.get("external_references", []) 
                                    if ref.get("source_name") == "mitre-attack"), None)
                    if tactic_id:
                        name = obj.get("name", "")
                        description = obj.get("description", "")
                        shortname = obj.get("x_mitre_shortname", "")
                        
                        tactic_data = {
                            "id": tactic_id,
                            "name": name,
                            "description": description,
                            "shortname": shortname,
                            "mitre_id": obj_id
                        }
                        
                        self.tactics_by_id[tactic_id] = tactic_data
                        self.tactics_by_name[name.lower()] = tactic_data
                        if shortname:
                            self.tactics_by_name[shortname.lower()] = tactic_data
                
                elif obj_type == "intrusion-set":
                    # This is a group
                    group_id = next((ref.get("external_id") for ref in obj.get("external_references", []) 
                                   if ref.get("source_name") == "mitre-attack"), None)
                    if group_id:
                        name = obj.get("name", "")
                        description = obj.get("description", "")
                        
                        group_data = {
                            "id": group_id,
                            "name": name,
                            "description": description,
                            "mitre_id": obj_id,
                            "techniques": []
                        }
                        
                        self.groups_by_id[group_id] = group_data
                        self.groups_by_name[name.lower()] = group_data
                
                elif obj_type == "malware":
                    # This is software (malware)
                    software_id = next((ref.get("external_id") for ref in obj.get("external_references", []) 
                                      if ref.get("source_name") == "mitre-attack"), None)
                    if software_id:
                        name = obj.get("name", "")
                        description = obj.get("description", "")
                        
                        software_data = {
                            "id": software_id,
                            "name": name,
                            "description": description,
                            "mitre_id": obj_id,
                            "techniques": [],
                            "type": "malware"
                        }
                        
                        self.software_by_id[software_id] = software_data
                        self.software_by_name[name.lower()] = software_data
            
            # Process relationships to link techniques to groups and software
            for obj in mitre_data.get("objects", []):
                if obj.get("type") == "relationship":
                    rel_type = obj.get("relationship_type")
                    source_ref = obj.get("source_ref")
                    target_ref = obj.get("target_ref")
                    
                    if rel_type == "uses" and source_ref and target_ref:
                        # A group or software uses a technique
                        if source_ref in [group["mitre_id"] for group in self.groups_by_id.values()]:
                            # Group uses technique
                            for group in self.groups_by_id.values():
                                if group["mitre_id"] == source_ref:
                                    for technique in self.techniques_by_id.values():
                                        if technique["mitre_id"] == target_ref:
                                            group["techniques"].append(technique["id"])
                        
                        elif source_ref in [sw["mitre_id"] for sw in self.software_by_id.values()]:
                            # Software uses technique
                            for software in self.software_by_id.values():
                                if software["mitre_id"] == source_ref:
                                    for technique in self.techniques_by_id.values():
                                        if technique["mitre_id"] == target_ref:
                                            software["techniques"].append(technique["id"])
                    
        except Exception as e:
            logger.error(f"Error processing MITRE ATT&CK data: {e}")
        
    def query(self, ioc: str, ioc_type: str) -> Dict:
        """
        Query MITRE ATT&CK data for information. For MITRE, we don't query IOCs directly,
        but this method is included for API consistency.
        """
        return {"error": "MITRE connector doesn't support direct IOC queries"}
        
    def enrich_sample(self, sample_data: Dict) -> Dict:
        """Enrich sample data with MITRE ATT&CK TTPs information"""
        if "threat_intel" not in sample_data:
            return sample_data
            
        # Try to find ransomware family in the sample data
        family_name = None
        
        # Check VirusTotal data
        vt_data = sample_data.get("threat_intel", {}).get("virustotal", {})
        if vt_data and "possible_families" in vt_data and vt_data["possible_families"]:
            family_name = vt_data["possible_families"][0]
        
        # Check AlienVault data if no family found yet
        if not family_name:
            av_data = sample_data.get("threat_intel", {}).get("alienvault", {})
            if av_data and "malware_families" in av_data and av_data["malware_families"]:
                family_name = av_data["malware_families"][0]
        
        if not family_name:
            # No family name found, can't enrich with MITRE data
            return sample_data
            
        # Get MITRE information for this family
        mitre_info = self.get_ransomware_family_info(family_name)
        
        if "error" in mitre_info:
            if "mitre" not in sample_data["threat_intel"]:
                sample_data["threat_intel"]["mitre"] = {"error": mitre_info["error"]}
            return sample_data
            
        # Add MITRE data to the sample
        sample_data["threat_intel"]["mitre"] = mitre_info
        
        return sample_data
        
    def get_ransomware_family_info(self, family_name: str) -> Dict:
        """
        Get information about a ransomware family from MITRE ATT&CK
        
        For ransomware, we'll check if it exists as malware in the MITRE database,
        and return its associated techniques and tactics.
        """
        family_name_lower = family_name.lower()
        
        # First, try exact match
        if family_name_lower in self.software_by_name:
            software = self.software_by_name[family_name_lower]
        else:
            # Try partial match
            matches = []
            for name, sw in self.software_by_name.items():
                if sw["type"] == "malware" and (
                    family_name_lower in name or 
                    "ransomware" in name and any(part in name for part in family_name_lower.split())
                ):
                    matches.append(sw)
            
            if not matches:
                return {"error": f"No MITRE ATT&CK data found for {family_name}"}
                
            # Use the first match
            software = matches[0]
        
        # Get techniques used by this software
        techniques = []
        for technique_id in software["techniques"]:
            if technique_id in self.techniques_by_id:
                technique = self.techniques_by_id[technique_id]
                techniques.append({
                    "id": technique["id"],
                    "name": technique["name"],
                    "description": technique["description"],
                    "tactics": [
                        {
                            "id": self.tactics_by_name[tactic].get("id") if tactic in self.tactics_by_name else "",
                            "name": tactic
                        } for tactic in technique["tactics"]
                    ]
                })
        
        # Group techniques by tactic
        tactics = {}
        for technique in techniques:
            for tactic in technique["tactics"]:
                tactic_name = tactic["name"]
                if tactic_name not in tactics:
                    tactics[tactic_name] = {
                        "id": tactic["id"],
                        "name": tactic_name,
                        "techniques": []
                    }
                tactics[tactic_name]["techniques"].append({
                    "id": technique["id"],
                    "name": technique["name"]
                })
        
        return {
            "name": software["name"],
            "id": software["id"],
            "description": software["description"],
            "techniques": techniques,
            "tactics": list(tactics.values())
        }


class ThreatIntelManager:
    """
    Manages multiple threat intelligence connectors and aggregates their data
    """
    
    def __init__(self):
        self.connectors = {}
        self.cache_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'cache')
        os.makedirs(self.cache_dir, exist_ok=True)
        
    def add_connector(self, name: str, connector: ThreatIntelConnector) -> None:
        """Add a connector to the manager"""
        self.connectors[name] = connector
        
    def remove_connector(self, name: str) -> None:
        """Remove a connector from the manager"""
        if name in self.connectors:
            del self.connectors[name]
            
    def get_connector(self, name: str) -> Optional[ThreatIntelConnector]:
        """Get a specific connector by name"""
        return self.connectors.get(name)
        
    def enrich_sample(self, sample_data: Dict) -> Dict:
        """
        Enrich sample data with information from all available connectors
        
        Args:
            sample_data: Dictionary containing sample analysis data
            
        Returns:
            Enriched data with threat intelligence from all connectors
        """
        for name, connector in self.connectors.items():
            try:
                sample_data = connector.enrich_sample(sample_data)
            except Exception as e:
                logger.error(f"Error enriching sample with {name} connector: {e}")
                if "threat_intel" not in sample_data:
                    sample_data["threat_intel"] = {}
                if name not in sample_data["threat_intel"]:
                    sample_data["threat_intel"][name] = {}
                sample_data["threat_intel"][name]["error"] = str(e)
        
        return sample_data
        
    def get_family_info(self, family_name: str) -> Dict:
        """
        Get comprehensive information about a ransomware family from all connectors
        
        Args:
            family_name: Name of the ransomware family
            
        Returns:
            Dictionary containing aggregated family information
        """
        results = {"name": family_name, "sources": {}}
        
        for name, connector in self.connectors.items():
            try:
                family_info = connector.get_ransomware_family_info(family_name)
                results["sources"][name] = family_info
            except Exception as e:
                logger.error(f"Error getting family info from {name} connector: {e}")
                results["sources"][name] = {"error": str(e)}
        
        return results


def create_default_manager() -> ThreatIntelManager:
    """Create a threat intelligence manager with default connectors"""
    manager = ThreatIntelManager()
    
    # Add VirusTotal connector
    vt_key = os.environ.get('VIRUSTOTAL_API_KEY')
    if vt_key:
        manager.add_connector("virustotal", VirusTotalConnector(api_key=vt_key))
    else:
        logger.warning("No VirusTotal API key found in environment")
    
    # Add AlienVault OTX connector
    otx_key = os.environ.get('ALIENVAULT_OTX_API_KEY')
    if otx_key:
        manager.add_connector("alienvault", AlienVaultOTXConnector(api_key=otx_key))
    else:
        logger.warning("No AlienVault OTX API key found in environment")
    
    # Add MITRE connector (doesn't require API key)
    manager.add_connector("mitre", MitreTTPConnector())
    
    return manager


if __name__ == "__main__":
    # Example usage
    manager = create_default_manager()
    
    # Sample data (would normally come from analysis)
    sample_data = {
        "sha256": "aaaaaaaaabbbbbbbbccccccccdddddddd",
        "name": "sample_ransomware.exe",
        "size": 1024000,
        "analysis": {
            "file_type": "PE32 executable",
            "strings": ["encrypt", "bitcoin", "payment"]
        }
    }
    
    # Enrich the sample with threat intelligence
    enriched_data = manager.enrich_sample(sample_data)
    
    # Print the enriched data
    print(json.dumps(enriched_data, indent=2))