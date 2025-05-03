#!/usr/bin/env python3
"""
IOC Extractor Utility
Extracts and exports Indicators of Compromise (IOCs) from analysis data.
Supports multiple export formats including STIX, OpenIOC, CSV, and JSON.
"""

import os
import re
import csv
import json
import uuid
import logging
import datetime
import ipaddress
from typing import Dict, List, Any, Optional, Set, Tuple
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ioc_extractor')

class IOCExtractor:
    """Extracts and exports IOCs from analysis data"""
    
    def __init__(self, output_dir=None):
        """
        Initialize the IOC extractor
        
        Args:
            output_dir: Directory to store extracted IOCs
        """
        self.output_dir = output_dir or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), 'ioc_utils', 'output'
        )
        os.makedirs(self.output_dir, exist_ok=True)
    
    def _extract_domains(self, sample_data: Dict) -> List[Dict]:
        """
        Extract domain IOCs from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            List of domain IOCs
        """
        domains = []
        
        # Extract domains from network behavior
        network_domains = sample_data.get('analysis', {}).get('behaviors', {}).get('network', {}).get('domains', [])
        if network_domains:
            for domain in network_domains:
                if domain and self._is_valid_domain(domain):
                    domains.append({
                        "value": domain,
                        "type": "domain",
                        "context": "network_communication"
                    })
        
        # Extract domains from strings
        strings = sample_data.get('analysis', {}).get('strings', [])
        if strings:
            domain_pattern = r'(?:https?://)?(?:www\.)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
            for string in strings:
                matches = re.findall(domain_pattern, string)
                for match in matches:
                    domain = match.lower()
                    if self._is_valid_domain(domain) and domain not in [d['value'] for d in domains]:
                        domains.append({
                            "value": domain,
                            "type": "domain",
                            "context": "strings"
                        })
        
        return domains
    
    def _is_valid_domain(self, domain: str) -> bool:
        """
        Check if a domain is valid
        
        Args:
            domain: Domain to check
            
        Returns:
            True if domain is valid, False otherwise
        """
        # Basic validation
        if not domain or len(domain) < 4 or '.' not in domain:
            return False
        
        # Skip localhost and common test domains
        invalid_domains = ['localhost', 'example.com', 'test.com', 'domain.com']
        if domain in invalid_domains:
            return False
        
        # Skip IP addresses
        try:
            ipaddress.ip_address(domain)
            return False
        except ValueError:
            pass
        
        # Skip domains with invalid TLDs
        parts = domain.split('.')
        if len(parts) < 2:
            return False
            
        tld = parts[-1].lower()
        if len(tld) < 2 or not all(c.isalpha() for c in tld):
            return False
        
        return True
    
    def _extract_ips(self, sample_data: Dict) -> List[Dict]:
        """
        Extract IP address IOCs from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            List of IP address IOCs
        """
        ips = []
        
        # Extract IPs from network behavior
        network_ips = sample_data.get('analysis', {}).get('behaviors', {}).get('network', {}).get('ips', [])
        if network_ips:
            for ip in network_ips:
                if ip and self._is_valid_ip(ip):
                    ips.append({
                        "value": ip,
                        "type": "ip",
                        "context": "network_communication"
                    })
        
        # Extract IPs from strings
        strings = sample_data.get('analysis', {}).get('strings', [])
        if strings:
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            for string in strings:
                matches = re.findall(ip_pattern, string)
                for match in matches:
                    if self._is_valid_ip(match) and match not in [i['value'] for i in ips]:
                        ips.append({
                            "value": match,
                            "type": "ip",
                            "context": "strings"
                        })
        
        return ips
    
    def _is_valid_ip(self, ip: str) -> bool:
        """
        Check if an IP is valid and not internal/reserved
        
        Args:
            ip: IP to check
            
        Returns:
            True if IP is valid, False otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Skip private, loopback, link-local addresses
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
                return False
                
            # Skip common test IPs
            if str(ip_obj) in ['127.0.0.1', '0.0.0.0', '255.255.255.255', '8.8.8.8', '8.8.4.4']:
                return False
                
            return True
        except ValueError:
            return False
    
    def _extract_urls(self, sample_data: Dict) -> List[Dict]:
        """
        Extract URL IOCs from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            List of URL IOCs
        """
        urls = []
        
        # Extract URLs from network behavior
        network_urls = sample_data.get('analysis', {}).get('behaviors', {}).get('network', {}).get('urls', [])
        if network_urls:
            for url in network_urls:
                if url and self._is_valid_url(url):
                    urls.append({
                        "value": url,
                        "type": "url",
                        "context": "network_communication"
                    })
        
        # Extract URLs from strings
        strings = sample_data.get('analysis', {}).get('strings', [])
        if strings:
            url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*\??[-\w\+&@#/%=~_|!:,.;]*'
            for string in strings:
                matches = re.findall(url_pattern, string)
                for match in matches:
                    if self._is_valid_url(match) and match not in [u['value'] for u in urls]:
                        urls.append({
                            "value": match,
                            "type": "url",
                            "context": "strings"
                        })
        
        return urls
    
    def _is_valid_url(self, url: str) -> bool:
        """
        Check if a URL is valid
        
        Args:
            url: URL to check
            
        Returns:
            True if URL is valid, False otherwise
        """
        # Basic validation
        if not url or len(url) < 10 or not (url.startswith('http://') or url.startswith('https://')):
            return False
        
        # Skip common test URLs
        invalid_urls = [
            'http://localhost', 'https://localhost', 
            'http://example.com', 'https://example.com'
        ]
        if url in invalid_urls:
            return False
        
        # Attempt to extract domain and validate it
        try:
            # Simple extraction, will fail for some complex URLs
            domain_part = url.split('://', 1)[1].split('/', 1)[0]
            return self._is_valid_domain(domain_part)
        except:
            return False
    
    def _extract_file_hashes(self, sample_data: Dict) -> List[Dict]:
        """
        Extract file hash IOCs from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            List of file hash IOCs
        """
        hashes = []
        
        # Extract hashes from sample data
        for hash_type in ['md5', 'sha1', 'sha256']:
            if hash_type in sample_data:
                hashes.append({
                    "value": sample_data[hash_type],
                    "type": hash_type,
                    "context": "sample_hash"
                })
        
        # Extract hashes from analysis.dropped_files if it exists
        dropped_files = sample_data.get('analysis', {}).get('dropped_files', [])
        if dropped_files:
            for file in dropped_files:
                for hash_type in ['md5', 'sha1', 'sha256']:
                    if hash_type in file:
                        hashes.append({
                            "value": file[hash_type],
                            "type": hash_type,
                            "context": "dropped_file",
                            "file_name": file.get('name', 'unknown')
                        })
        
        return hashes
    
    def _extract_file_paths(self, sample_data: Dict) -> List[Dict]:
        """
        Extract file path IOCs from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            List of file path IOCs
        """
        file_paths = []
        
        # Extract created files
        created_files = sample_data.get('analysis', {}).get('behaviors', {}).get('created_files', [])
        if created_files:
            for file_path in created_files:
                file_paths.append({
                    "value": file_path,
                    "type": "file_path",
                    "context": "created_file"
                })
        
        # Extract file operations
        file_ops = sample_data.get('analysis', {}).get('behaviors', {}).get('file_operations', [])
        if file_ops:
            for op in file_ops:
                if 'path' in op:
                    file_paths.append({
                        "value": op['path'],
                        "type": "file_path",
                        "context": "file_operation",
                        "operation": op.get('type', 'unknown')
                    })
        
        # Extract interesting file paths from dropped files
        dropped_files = sample_data.get('analysis', {}).get('dropped_files', [])
        if dropped_files:
            for file in dropped_files:
                if 'path' in file:
                    file_paths.append({
                        "value": file['path'],
                        "type": "file_path",
                        "context": "dropped_file",
                        "name": file.get('name', 'unknown')
                    })
        
        return file_paths
    
    def _extract_registry_keys(self, sample_data: Dict) -> List[Dict]:
        """
        Extract registry key IOCs from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            List of registry key IOCs
        """
        registry_keys = []
        
        # Extract registry keys from registry behavior
        reg_keys = sample_data.get('analysis', {}).get('behaviors', {}).get('registry', {}).get('keys_set', [])
        if reg_keys:
            for key in reg_keys:
                registry_keys.append({
                    "value": key,
                    "type": "registry_key",
                    "context": "registry_modification"
                })
        
        return registry_keys
    
    def _extract_bitcoin_addresses(self, sample_data: Dict) -> List[Dict]:
        """
        Extract Bitcoin address IOCs from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            List of Bitcoin address IOCs
        """
        btc_addresses = []
        
        # Extract from strings
        strings = sample_data.get('analysis', {}).get('strings', [])
        if strings:
            # Bitcoin address pattern - simplified, not perfect
            btc_pattern = r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}'
            for string in strings:
                matches = re.findall(btc_pattern, string)
                for match in matches:
                    # Additional validation - a real implementation would use a proper validator
                    if len(match) >= 26 and len(match) <= 35 and match not in [a['value'] for a in btc_addresses]:
                        btc_addresses.append({
                            "value": match,
                            "type": "bitcoin_address",
                            "context": "strings"
                        })
        
        return btc_addresses
    
    def _extract_email_addresses(self, sample_data: Dict) -> List[Dict]:
        """
        Extract email address IOCs from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            List of email address IOCs
        """
        email_addresses = []
        
        # Extract from strings
        strings = sample_data.get('analysis', {}).get('strings', [])
        if strings:
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            for string in strings:
                matches = re.findall(email_pattern, string)
                for match in matches:
                    if match not in [e['value'] for e in email_addresses]:
                        email_addresses.append({
                            "value": match,
                            "type": "email",
                            "context": "strings"
                        })
        
        return email_addresses
    
    def _extract_mutex_names(self, sample_data: Dict) -> List[Dict]:
        """
        Extract mutex name IOCs from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            List of mutex name IOCs
        """
        mutex_names = []
        
        # Extract from behaviors
        mutexes = sample_data.get('analysis', {}).get('behaviors', {}).get('mutexes', [])
        if mutexes:
            for mutex in mutexes:
                mutex_names.append({
                    "value": mutex,
                    "type": "mutex",
                    "context": "created_mutex"
                })
        
        return mutex_names
    
    def extract_iocs(self, sample_data: Dict) -> Dict:
        """
        Extract all IOCs from sample data
        
        Args:
            sample_data: Sample analysis data
            
        Returns:
            Dictionary containing all extracted IOCs
        """
        # If this is a correlation result, check for pre-extracted IOCs
        if "iocs" in sample_data:
            existing_iocs = sample_data["iocs"]
            
            # Convert existing IOCs to our format
            converted_iocs = {}
            
            if "domains" in existing_iocs:
                converted_iocs["domains"] = [
                    {"value": d.get("value", d), "type": "domain", "context": "pre_extracted"}
                    for d in existing_iocs["domains"]
                ]
            
            if "ips" in existing_iocs:
                converted_iocs["ips"] = [
                    {"value": i.get("value", i), "type": "ip", "context": "pre_extracted"}
                    for i in existing_iocs["ips"]
                ]
            
            if "urls" in existing_iocs:
                converted_iocs["urls"] = [
                    {"value": u.get("value", u), "type": "url", "context": "pre_extracted"}
                    for u in existing_iocs["urls"]
                ]
            
            if "hashes" in existing_iocs:
                converted_iocs["file_hashes"] = [
                    {"value": h.get("value", h), "type": h.get("type", "hash"), "context": "pre_extracted"}
                    for h in existing_iocs["hashes"]
                ]
            
            if "files" in existing_iocs:
                converted_iocs["file_paths"] = [
                    {"value": f.get("value", f), "type": "file_path", "context": "pre_extracted"}
                    for f in existing_iocs["files"]
                ]
            
            if "registry_keys" in existing_iocs:
                converted_iocs["registry_keys"] = [
                    {"value": r.get("value", r), "type": "registry_key", "context": "pre_extracted"}
                    for r in existing_iocs["registry_keys"]
                ]
            
            # Extract additional IOCs that might not be in the pre-extracted data
            domains = self._extract_domains(sample_data)
            ips = self._extract_ips(sample_data)
            urls = self._extract_urls(sample_data)
            file_hashes = self._extract_file_hashes(sample_data)
            file_paths = self._extract_file_paths(sample_data)
            registry_keys = self._extract_registry_keys(sample_data)
            bitcoin_addresses = self._extract_bitcoin_addresses(sample_data)
            email_addresses = self._extract_email_addresses(sample_data)
            mutex_names = self._extract_mutex_names(sample_data)
            
            # Merge with existing IOCs
            converted_iocs["domains"] = list(self._merge_iocs(
                converted_iocs.get("domains", []), domains, key="value"))
            converted_iocs["ips"] = list(self._merge_iocs(
                converted_iocs.get("ips", []), ips, key="value"))
            converted_iocs["urls"] = list(self._merge_iocs(
                converted_iocs.get("urls", []), urls, key="value"))
            converted_iocs["file_hashes"] = list(self._merge_iocs(
                converted_iocs.get("file_hashes", []), file_hashes, key="value"))
            converted_iocs["file_paths"] = list(self._merge_iocs(
                converted_iocs.get("file_paths", []), file_paths, key="value"))
            converted_iocs["registry_keys"] = list(self._merge_iocs(
                converted_iocs.get("registry_keys", []), registry_keys, key="value"))
            converted_iocs["bitcoin_addresses"] = bitcoin_addresses
            converted_iocs["email_addresses"] = email_addresses
            converted_iocs["mutex_names"] = mutex_names
            
            return converted_iocs
        
        # Extract all IOC types
        domains = self._extract_domains(sample_data)
        ips = self._extract_ips(sample_data)
        urls = self._extract_urls(sample_data)
        file_hashes = self._extract_file_hashes(sample_data)
        file_paths = self._extract_file_paths(sample_data)
        registry_keys = self._extract_registry_keys(sample_data)
        bitcoin_addresses = self._extract_bitcoin_addresses(sample_data)
        email_addresses = self._extract_email_addresses(sample_data)
        mutex_names = self._extract_mutex_names(sample_data)
        
        # Combine all IOCs
        return {
            "domains": domains,
            "ips": ips,
            "urls": urls,
            "file_hashes": file_hashes,
            "file_paths": file_paths,
            "registry_keys": registry_keys,
            "bitcoin_addresses": bitcoin_addresses,
            "email_addresses": email_addresses,
            "mutex_names": mutex_names
        }
    
    def _merge_iocs(self, existing: List[Dict], new: List[Dict], key: str = "value") -> Set[Dict]:
        """
        Merge existing and new IOCs, avoiding duplicates
        
        Args:
            existing: List of existing IOCs
            new: List of new IOCs
            key: Key to use for deduplication
            
        Returns:
            Combined set of IOCs
        """
        # Convert dictionaries to tuple of items for hashability
        existing_set = {tuple(sorted(e.items())) for e in existing}
        new_set = {tuple(sorted(n.items())) for n in new}
        
        # Combine sets
        combined = existing_set.union(new_set)
        
        # Convert back to dictionaries
        return {dict(t) for t in combined}
    
    def export_iocs_json(self, iocs: Dict, output_file: str = None) -> str:
        """
        Export IOCs to JSON format
        
        Args:
            iocs: Dictionary of IOCs
            output_file: Output file path (optional)
            
        Returns:
            Path to the output file
        """
        if not output_file:
            timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
            output_file = os.path.join(self.output_dir, f"iocs_{timestamp}.json")
        
        with open(output_file, 'w') as f:
            json.dump(iocs, f, indent=2)
        
        logger.info(f"Exported IOCs to JSON: {output_file}")
        return output_file
    
    def export_iocs_csv(self, iocs: Dict, output_file: str = None) -> str:
        """
        Export IOCs to CSV format
        
        Args:
            iocs: Dictionary of IOCs
            output_file: Output file path (optional)
            
        Returns:
            Path to the output file
        """
        if not output_file:
            timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
            output_file = os.path.join(self.output_dir, f"iocs_{timestamp}.csv")
        
        # Prepare all IOCs for CSV
        all_iocs = []
        for ioc_type, ioc_list in iocs.items():
            for ioc in ioc_list:
                csv_ioc = {
                    "type": ioc_type,
                    "value": ioc["value"],
                    "context": ioc.get("context", "")
                }
                
                # Add any additional fields
                for key, value in ioc.items():
                    if key not in ["type", "value", "context"]:
                        csv_ioc[key] = value
                
                all_iocs.append(csv_ioc)
        
        # Write to CSV
        if all_iocs:
            # Get all possible fields
            fieldnames = set()
            for ioc in all_iocs:
                fieldnames.update(ioc.keys())
            
            fieldnames = sorted(list(fieldnames))
            
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(all_iocs)
        else:
            with open(output_file, 'w', newline='') as f:
                f.write("type,value,context\n")
        
        logger.info(f"Exported IOCs to CSV: {output_file}")
        return output_file
    
    def export_iocs_stix(self, iocs: Dict, sample_data: Dict = None, output_file: str = None) -> str:
        """
        Export IOCs to STIX format
        
        Args:
            iocs: Dictionary of IOCs
            sample_data: Sample analysis data (optional)
            output_file: Output file path (optional)
            
        Returns:
            Path to the output file
        """
        # Note: This is a simplified STIX 2.1 implementation
        # A real implementation would use the STIX libraries
        
        if not output_file:
            timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
            output_file = os.path.join(self.output_dir, f"iocs_{timestamp}.stix.json")
        
        # Create a STIX bundle
        stix_objects = []
        
        # Create identity for the producer
        identity_id = f"identity--{str(uuid.uuid4())}"
        identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": datetime.datetime.now().isoformat() + "Z",
            "modified": datetime.datetime.now().isoformat() + "Z",
            "name": "Threat Intel Analyzer",
            "identity_class": "system"
        }
        stix_objects.append(identity)
        
        # Create indicator objects for each IOC
        indicator_by_value = {}  # To avoid duplicates
        
        # Add each type of IOC
        for ioc_type, ioc_list in iocs.items():
            for ioc in ioc_list:
                ioc_value = ioc["value"]
                if ioc_value in indicator_by_value:
                    continue
                
                # Create appropriate pattern based on IOC type
                pattern = ""
                if ioc_type == "domains":
                    pattern = f"[domain-name:value = '{ioc_value}']"
                elif ioc_type == "ips":
                    pattern = f"[ipv4-addr:value = '{ioc_value}']"
                elif ioc_type == "urls":
                    pattern = f"[url:value = '{ioc_value}']"
                elif ioc_type == "file_hashes":
                    hash_type = ioc.get("type", "hash")
                    if hash_type == "md5":
                        pattern = f"[file:hashes.'MD5' = '{ioc_value}']"
                    elif hash_type == "sha1":
                        pattern = f"[file:hashes.'SHA-1' = '{ioc_value}']"
                    elif hash_type == "sha256":
                        pattern = f"[file:hashes.'SHA-256' = '{ioc_value}']"
                    else:
                        pattern = f"[file:hashes.'{hash_type.upper()}' = '{ioc_value}']"
                elif ioc_type == "file_paths":
                    pattern = f"[file:name = '{os.path.basename(ioc_value)}']"
                elif ioc_type == "registry_keys":
                    pattern = f"[windows-registry-key:key = '{ioc_value}']"
                elif ioc_type == "bitcoin_addresses":
                    pattern = f"[x-bitcoin-address:value = '{ioc_value}']"
                elif ioc_type == "email_addresses":
                    pattern = f"[email-addr:value = '{ioc_value}']"
                elif ioc_type == "mutex_names":
                    pattern = f"[mutex:name = '{ioc_value}']"
                
                if pattern:
                    indicator_id = f"indicator--{str(uuid.uuid4())}"
                    indicator = {
                        "type": "indicator",
                        "spec_version": "2.1",
                        "id": indicator_id,
                        "created": datetime.datetime.now().isoformat() + "Z",
                        "modified": datetime.datetime.now().isoformat() + "Z",
                        "name": f"{ioc_type.title()} - {ioc_value}",
                        "description": f"IOC extracted from ransomware sample",
                        "indicator_types": ["malicious-activity"],
                        "pattern": pattern,
                        "pattern_type": "stix",
                        "valid_from": datetime.datetime.now().isoformat() + "Z",
                        "created_by_ref": identity_id
                    }
                    
                    stix_objects.append(indicator)
                    indicator_by_value[ioc_value] = indicator_id
        
        # Create a malware object if we have sample data
        if sample_data:
            malware_id = f"malware--{str(uuid.uuid4())}"
            malware_name = "Unknown Malware"
            
            # Try to get malware family name
            if "identified_families" in sample_data and sample_data["identified_families"]:
                malware_name = sample_data["identified_families"][0]["name"].capitalize() + " Ransomware"
            
            malware = {
                "type": "malware",
                "spec_version": "2.1",
                "id": malware_id,
                "created": datetime.datetime.now().isoformat() + "Z",
                "modified": datetime.datetime.now().isoformat() + "Z",
                "name": malware_name,
                "is_family": True,
                "malware_types": ["ransomware"],
                "created_by_ref": identity_id
            }
            
            # Add description if available
            if "threat_intel" in sample_data and "mitre" in sample_data["threat_intel"]:
                mitre = sample_data["threat_intel"]["mitre"]
                if "description" in mitre:
                    malware["description"] = mitre["description"]
            
            stix_objects.append(malware)
            
            # Create relationships between malware and indicators
            for indicator_id in indicator_by_value.values():
                relationship_id = f"relationship--{str(uuid.uuid4())}"
                relationship = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": relationship_id,
                    "created": datetime.datetime.now().isoformat() + "Z",
                    "modified": datetime.datetime.now().isoformat() + "Z",
                    "relationship_type": "indicates",
                    "source_ref": indicator_id,
                    "target_ref": malware_id,
                    "created_by_ref": identity_id
                }
                stix_objects.append(relationship)
        
        # Create the STIX bundle
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{str(uuid.uuid4())}",
            "objects": stix_objects
        }
        
        # Write to file
        with open(output_file, 'w') as f:
            json.dump(stix_bundle, f, indent=2)
        
        logger.info(f"Exported IOCs to STIX: {output_file}")
        return output_file
    
    def export_iocs_openioc(self, iocs: Dict, sample_data: Dict = None, output_file: str = None) -> str:
        """
        Export IOCs to OpenIOC format
        
        Args:
            iocs: Dictionary of IOCs
            sample_data: Sample analysis data (optional)
            output_file: Output file path (optional)
            
        Returns:
            Path to the output file
        """
        # Note: This is a simplified OpenIOC implementation
        # A real implementation would use XML libraries
        
        if not output_file:
            timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
            output_file = os.path.join(self.output_dir, f"iocs_{timestamp}.ioc")
        
        # Get malware name if available
        malware_name = "Unknown Malware"
        if sample_data and "identified_families" in sample_data and sample_data["identified_families"]:
            malware_name = sample_data["identified_families"][0]["name"].capitalize() + " Ransomware"
        
        # Create OpenIOC framework
        ioc_id = str(uuid.uuid4())
        creation_date = datetime.datetime.now().isoformat()
        
        xml_content = f"""<?xml version="1.0" encoding="utf-8"?>
<ioc xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" id="{ioc_id}" last-modified="{creation_date}" xmlns="http://schemas.mandiant.com/2010/ioc">
  <short_description>{malware_name}</short_description>
  <description>IOCs extracted from ransomware sample</description>
  <authored_by>Threat Intel Analyzer</authored_by>
  <authored_date>{creation_date}</authored_date>
  <links />
  <definition>
    <Indicator operator="OR" id="{str(uuid.uuid4())}">
"""
        
        # Add each type of IOC
        for ioc_type, ioc_list in iocs.items():
            for ioc in ioc_list:
                ioc_value = ioc["value"]
                indicator_id = str(uuid.uuid4())
                
                # Create appropriate indicator based on IOC type
                if ioc_type == "domains":
                    xml_content += f"""      <IndicatorItem id="{indicator_id}" condition="is">
        <Context document="Network" search="Network/DNS" type="Network" />
        <Content type="string">{ioc_value}</Content>
      </IndicatorItem>
"""
                elif ioc_type == "ips":
                    xml_content += f"""      <IndicatorItem id="{indicator_id}" condition="is">
        <Context document="Network" search="Network/Connection/IP" type="IP" />
        <Content type="IP">{ioc_value}</Content>
      </IndicatorItem>
"""
                elif ioc_type == "urls":
                    xml_content += f"""      <IndicatorItem id="{indicator_id}" condition="is">
        <Context document="Network" search="Network/HTTP" type="URL" />
        <Content type="string">{ioc_value}</Content>
      </IndicatorItem>
"""
                elif ioc_type == "file_hashes":
                    hash_type = ioc.get("type", "hash")
                    if hash_type == "md5":
                        xml_content += f"""      <IndicatorItem id="{indicator_id}" condition="is">
        <Context document="FileItem" search="FileItem/Md5sum" type="md5" />
        <Content type="md5">{ioc_value}</Content>
      </IndicatorItem>
"""
                    elif hash_type == "sha1":
                        xml_content += f"""      <IndicatorItem id="{indicator_id}" condition="is">
        <Context document="FileItem" search="FileItem/Sha1sum" type="sha1" />
        <Content type="sha1">{ioc_value}</Content>
      </IndicatorItem>
"""
                    elif hash_type == "sha256":
                        xml_content += f"""      <IndicatorItem id="{indicator_id}" condition="is">
        <Context document="FileItem" search="FileItem/Sha256sum" type="sha256" />
        <Content type="sha256">{ioc_value}</Content>
      </IndicatorItem>
"""
                elif ioc_type == "file_paths":
                    file_name = os.path.basename(ioc_value)
                    xml_content += f"""      <IndicatorItem id="{indicator_id}" condition="is">
        <Context document="FileItem" search="FileItem/FileName" type="string" />
        <Content type="string">{file_name}</Content>
      </IndicatorItem>
"""
                elif ioc_type == "registry_keys":
                    xml_content += f"""      <IndicatorItem id="{indicator_id}" condition="is">
        <Context document="RegistryItem" search="RegistryItem/KeyPath" type="string" />
        <Content type="string">{ioc_value}</Content>
      </IndicatorItem>
"""
                elif ioc_type == "mutex_names":
                    xml_content += f"""      <IndicatorItem id="{indicator_id}" condition="is">
        <Context document="ProcessItem" search="ProcessItem/Mutex" type="string" />
        <Content type="string">{ioc_value}</Content>
      </IndicatorItem>
"""
        
        # Close the OpenIOC framework
        xml_content += """    </Indicator>
  </definition>
</ioc>"""
        
        # Write to file
        with open(output_file, 'w') as f:
            f.write(xml_content)
        
        logger.info(f"Exported IOCs to OpenIOC: {output_file}")
        return output_file
    
    def export_iocs_misp(self, iocs: Dict, sample_data: Dict = None, output_file: str = None) -> str:
        """
        Export IOCs to MISP format
        
        Args:
            iocs: Dictionary of IOCs
            sample_data: Sample analysis data (optional)
            output_file: Output file path (optional)
            
        Returns:
            Path to the output file
        """
        # Note: This is a simplified MISP implementation
        # A real implementation would use the PyMISP library
        
        if not output_file:
            timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
            output_file = os.path.join(self.output_dir, f"iocs_{timestamp}.misp.json")
        
        # Get malware name if available
        malware_name = "Unknown Malware"
        if sample_data and "identified_families" in sample_data and sample_data["identified_families"]:
            malware_name = sample_data["identified_families"][0]["name"].capitalize() + " Ransomware"
        
        # Create MISP event
        event_uuid = str(uuid.uuid4())
        creation_date = datetime.datetime.now().strftime('%Y-%m-%d')
        
        misp_event = {
            "Event": {
                "uuid": event_uuid,
                "info": f"{malware_name} IOCs",
                "date": creation_date,
                "threat_level_id": "2",
                "analysis": "2",
                "distribution": "0",
                "Attribute": []
            }
        }
        
        # Add each type of IOC as an attribute
        for ioc_type, ioc_list in iocs.items():
            for ioc in ioc_list:
                ioc_value = ioc["value"]
                attribute = {
                    "uuid": str(uuid.uuid4()),
                    "value": ioc_value,
                    "to_ids": True,
                    "distribution": "0"
                }
                
                # Set type based on IOC type
                if ioc_type == "domains":
                    attribute["type"] = "domain"
                    attribute["category"] = "Network activity"
                elif ioc_type == "ips":
                    attribute["type"] = "ip-dst"
                    attribute["category"] = "Network activity"
                elif ioc_type == "urls":
                    attribute["type"] = "url"
                    attribute["category"] = "Network activity"
                elif ioc_type == "file_hashes":
                    hash_type = ioc.get("type", "hash")
                    if hash_type == "md5":
                        attribute["type"] = "md5"
                    elif hash_type == "sha1":
                        attribute["type"] = "sha1"
                    elif hash_type == "sha256":
                        attribute["type"] = "sha256"
                    else:
                        attribute["type"] = "filename|" + hash_type
                    attribute["category"] = "Payload delivery"
                elif ioc_type == "file_paths":
                    attribute["type"] = "filename"
                    attribute["category"] = "Payload delivery"
                elif ioc_type == "registry_keys":
                    attribute["type"] = "regkey"
                    attribute["category"] = "Persistence mechanism"
                elif ioc_type == "bitcoin_addresses":
                    attribute["type"] = "btc"
                    attribute["category"] = "Financial fraud"
                elif ioc_type == "email_addresses":
                    attribute["type"] = "email"
                    attribute["category"] = "Network activity"
                elif ioc_type == "mutex_names":
                    attribute["type"] = "mutex"
                    attribute["category"] = "Artifacts dropped"
                else:
                    continue
                
                misp_event["Event"]["Attribute"].append(attribute)
        
        # Write to file
        with open(output_file, 'w') as f:
            json.dump(misp_event, f, indent=2)
        
        logger.info(f"Exported IOCs to MISP: {output_file}")
        return output_file
    
    def extract_and_export(self, sample_data: Dict, formats: List[str] = None) -> Dict:
        """
        Extract and export IOCs from sample data
        
        Args:
            sample_data: Sample analysis data
            formats: List of export formats (default: ["json", "csv"])
            
        Returns:
            Dictionary with paths to exported files
        """
        if formats is None:
            formats = ["json", "csv"]
        
        # Extract IOCs
        iocs = self.extract_iocs(sample_data)
        
        # Export to requested formats
        exported_files = {}
        
        for format_name in formats:
            if format_name.lower() == "json":
                exported_files["json"] = self.export_iocs_json(iocs)
            elif format_name.lower() == "csv":
                exported_files["csv"] = self.export_iocs_csv(iocs)
            elif format_name.lower() == "stix":
                exported_files["stix"] = self.export_iocs_stix(iocs, sample_data)
            elif format_name.lower() == "openioc":
                exported_files["openioc"] = self.export_iocs_openioc(iocs, sample_data)
            elif format_name.lower() == "misp":
                exported_files["misp"] = self.export_iocs_misp(iocs, sample_data)
        
        return exported_files


if __name__ == "__main__":
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description="Extract and export IOCs from sample analysis data")
    parser.add_argument('--file', '-f', help='Path to analysis JSON file')
    parser.add_argument('--output-dir', '-o', help='Output directory for exported IOCs')
    parser.add_argument('--formats', '-F', nargs='+', default=["json", "csv"],
                       help='Export formats (json, csv, stix, openioc, misp)')
    
    args = parser.parse_args()
    
    if not args.file:
        parser.print_help()
        sys.exit(1)
    
    extractor = IOCExtractor(output_dir=args.output_dir)
    
    try:
        with open(args.file, 'r') as f:
            sample_data = json.load(f)
        
        exported_files = extractor.extract_and_export(sample_data, formats=args.formats)
        
        print("Exported IOCs to the following files:")
        for format_name, file_path in exported_files.items():
            print(f"  {format_name.upper()}: {file_path}")
    except Exception as e:
        logger.error(f"Error extracting IOCs: {e}")
        sys.exit(1)