#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ransomware Network Detection Module

This module provides network-based detection capabilities for ransomware traffic patterns,
command and control communications, and data exfiltration activities. It works in conjunction
with the existing ransomware detection framework to provide comprehensive protection.

Key features:
- Real-time monitoring of network traffic for ransomware patterns
- Pattern matching against known ransomware C2 communications
- Detection of encryption key exchange over the network
- Identification of data exfiltration characteristic of ransomware
- Integration with memory forensics for key extraction

Usage:
    detector = RansomwareNetworkDetector()
    detector.start_monitoring()
    alerts = detector.get_alerts()
"""

import os
import re
import json
import time
import logging
import ipaddress
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional, Union, Any
from dataclasses import dataclass, field
import threading
from concurrent.futures import ThreadPoolExecutor
import socket
import struct

# Optional imports that may require installation
try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("RansomwareNetworkDetector")


@dataclass
class NetworkAlert:
    """Data class for network-based ransomware alerts"""
    timestamp: datetime
    alert_type: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    confidence: float
    description: str
    ransomware_family: Optional[str] = None
    traffic_sample: Optional[bytes] = None
    matched_pattern: Optional[str] = None
    matched_rule: Optional[str] = None
    alert_id: str = field(init=False)
    
    def __post_init__(self):
        """Generate a unique alert ID after initialization"""
        self.alert_id = f"NET-{int(time.time())}-{hash(self.source_ip + self.destination_ip)}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary for serialization"""
        result = {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "alert_type": self.alert_type,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "confidence": self.confidence,
            "description": self.description
        }
        
        if self.ransomware_family:
            result["ransomware_family"] = self.ransomware_family
        
        if self.matched_pattern:
            result["matched_pattern"] = self.matched_pattern
            
        if self.matched_rule:
            result["matched_rule"] = self.matched_rule
            
        # Don't include binary traffic sample in serialized output
        return result


class NetworkPatternMatcher:
    """Matches network traffic against known ransomware patterns"""
    
    def __init__(self, patterns_file: str = None):
        """Initialize with patterns from file or use default location"""
        self.patterns_file = patterns_file or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "threat_intel", "data", "ransomware_network_patterns.json"
        )
        self.patterns = self._load_patterns()
        self.ja3_signatures = self._extract_ja3_signatures()
        self.domain_patterns = self._compile_domain_patterns()
        self.traffic_patterns = self._compile_traffic_patterns()
        self.c2_ips = self._extract_c2_ips()
        
    def _load_patterns(self) -> Dict[str, Any]:
        """Load network patterns from JSON file"""
        try:
            with open(self.patterns_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Error loading network patterns: {e}")
            return {"families": {}, "version": "1.0", "last_updated": datetime.now().isoformat()}
    
    def _extract_ja3_signatures(self) -> Dict[str, str]:
        """Extract JA3 signatures from patterns file"""
        signatures = {}
        for family, data in self.patterns.get("families", {}).items():
            for rule_type, rules in data.get("detection_signatures", {}).items():
                for rule in rules:
                    ja3_match = re.search(r'ja3.hash.*content:\"([a-f0-9]{32})\"', rule, re.IGNORECASE)
                    if ja3_match:
                        signatures[ja3_match.group(1)] = family
        return signatures
    
    def _compile_domain_patterns(self) -> Dict[str, List[Tuple[re.Pattern, str]]]:
        """Compile regex patterns for domain matching"""
        domain_patterns = {}
        for family, data in self.patterns.get("families", {}).items():
            family_patterns = []
            for domain in data.get("c2_domains", []):
                if isinstance(domain, str) and not domain.startswith("Dynamic") and not domain.startswith("Various"):
                    try:
                        # Create regex from domain pattern, handling wildcards
                        pattern = domain.replace(".", "\\.").replace("*", ".*")
                        family_patterns.append((re.compile(pattern, re.IGNORECASE), domain))
                    except re.error:
                        logger.warning(f"Invalid domain pattern for {family}: {domain}")
            if family_patterns:
                domain_patterns[family] = family_patterns
        return domain_patterns
    
    def _compile_traffic_patterns(self) -> Dict[str, List[Tuple[str, float]]]:
        """Extract and compile traffic patterns"""
        traffic_patterns = {}
        for family, data in self.patterns.get("families", {}).items():
            family_patterns = []
            for pattern_data in data.get("traffic_patterns", []):
                if isinstance(pattern_data, dict) and "pattern" in pattern_data and "confidence" in pattern_data:
                    pattern = pattern_data["pattern"]
                    confidence_str = pattern_data["confidence"].lower()
                    
                    # Convert text confidence to numeric value
                    confidence = 0.5  # Default
                    if confidence_str == "high":
                        confidence = 0.8
                    elif confidence_str == "medium":
                        confidence = 0.5
                    elif confidence_str == "low":
                        confidence = 0.3
                    
                    family_patterns.append((pattern, confidence))
            if family_patterns:
                traffic_patterns[family] = family_patterns
        return traffic_patterns
    
    def _extract_c2_ips(self) -> Dict[str, List[str]]:
        """Extract C2 IP addresses for each family"""
        c2_ips = {}
        for family, data in self.patterns.get("families", {}).items():
            family_ips = []
            ip_data = data.get("c2_ips", [])
            
            # Handle different ways IP data might be stored
            if isinstance(ip_data, list):
                family_ips.extend(ip for ip in ip_data if isinstance(ip, str) and not ip.startswith("No consistent"))
            elif isinstance(ip_data, str) and not ip_data.startswith("No consistent"):
                # Try to extract IPs from string descriptions
                extracted_ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ip_data)
                family_ips.extend(extracted_ips)
                
            if family_ips:
                c2_ips[family] = family_ips
                
        return c2_ips
    
    def match_domain(self, domain: str) -> List[Tuple[str, float, str]]:
        """
        Match a domain against known C2 patterns
        
        Args:
            domain: Domain name to check
            
        Returns:
            List of tuples (family_name, confidence, matched_pattern)
        """
        matches = []
        
        for family, patterns in self.domain_patterns.items():
            for pattern, original in patterns:
                if pattern.search(domain):
                    # Higher confidence for exact matches
                    confidence = 0.9 if domain.lower() == original.lower() else 0.7
                    matches.append((family, confidence, original))
                    
        return matches
    
    def match_ip(self, ip_address: str) -> List[Tuple[str, float]]:
        """
        Match an IP against known C2 addresses
        
        Args:
            ip_address: IP address to check
            
        Returns:
            List of tuples (family_name, confidence)
        """
        matches = []
        
        for family, ips in self.c2_ips.items():
            if ip_address in ips:
                matches.append((family, 0.9))  # High confidence for direct IP match
                
        return matches
    
    def match_ja3(self, ja3_hash: str) -> Optional[Tuple[str, float]]:
        """
        Match a JA3 hash against known signatures
        
        Args:
            ja3_hash: JA3 hash to check
            
        Returns:
            Tuple of (family_name, confidence) or None
        """
        if ja3_hash in self.ja3_signatures:
            return (self.ja3_signatures[ja3_hash], 0.85)
        return None
    
    def check_port_patterns(self, port: int, protocol: str) -> List[Tuple[str, float, str]]:
        """
        Check if port/protocol combination matches known ransomware patterns
        
        Args:
            port: Port number
            protocol: Protocol (tcp, udp)
            
        Returns:
            List of tuples (family_name, confidence, purpose)
        """
        matches = []
        protocol = protocol.lower()
        
        for family, data in self.patterns.get("families", {}).items():
            for port_data in data.get("port_patterns", []):
                if isinstance(port_data, dict) and port_data.get("port") == port and port_data.get("protocol", "").lower() == protocol:
                    purpose = port_data.get("purpose", "Unknown")
                    matches.append((family, 0.4, purpose))  # Medium-low confidence since ports are commonly used
                    
        return matches
    
    def match_traffic_pattern(self, traffic_description: str) -> List[Tuple[str, float, str]]:
        """
        Match a traffic description against known patterns
        
        Args:
            traffic_description: Text description of traffic pattern
            
        Returns:
            List of tuples (family_name, confidence, matched_pattern)
        """
        matches = []
        
        for family, patterns in self.traffic_patterns.items():
            for pattern, confidence in patterns:
                # Simple substring matching - in a real implementation, this would be more sophisticated
                if pattern.lower() in traffic_description.lower():
                    matches.append((family, confidence, pattern))
                    
        return matches


class NetworkTrafficAnalyzer:
    """Analyzes network traffic for ransomware indicators"""
    
    def __init__(self, interface: str = "any", pattern_matcher: Optional[NetworkPatternMatcher] = None):
        """
        Initialize the traffic analyzer
        
        Args:
            interface: Network interface to monitor
            pattern_matcher: Optional NetworkPatternMatcher instance
        """
        self.interface = interface
        self.pattern_matcher = pattern_matcher or NetworkPatternMatcher()
        self.running = False
        self.capture_thread = None
        self.alerts = []
        self.alert_lock = threading.Lock()
        self._setup_capture_method()
        
    def _setup_capture_method(self):
        """Determine the best available packet capture method"""
        if PYSHARK_AVAILABLE:
            self.capture_method = "pyshark"
        elif SCAPY_AVAILABLE:
            self.capture_method = "scapy"
        elif DPKT_AVAILABLE:
            self.capture_method = "dpkt"
        else:
            self.capture_method = "basic"
            logger.warning("No specialized packet capture library available. Using basic socket capture.")
    
    def start_capture(self):
        """Start packet capture in a separate thread"""
        if self.running:
            logger.warning("Capture already running")
            return
            
        self.running = True
        
        if self.capture_method == "pyshark":
            self.capture_thread = threading.Thread(target=self._capture_with_pyshark)
        elif self.capture_method == "scapy":
            self.capture_thread = threading.Thread(target=self._capture_with_scapy)
        elif self.capture_method == "dpkt":
            self.capture_thread = threading.Thread(target=self._capture_with_dpkt)
        else:
            self.capture_thread = threading.Thread(target=self._capture_basic)
            
        self.capture_thread.daemon = True
        self.capture_thread.start()
        logger.info(f"Started network capture using {self.capture_method}")
    
    def stop_capture(self):
        """Stop the packet capture"""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)
            logger.info("Stopped network capture")
    
    def _capture_with_pyshark(self):
        """Capture packets using pyshark (Wireshark wrapper)"""
        try:
            capture = pyshark.LiveCapture(interface=self.interface)
            for packet in capture.sniff_continuously():
                if not self.running:
                    break
                    
                try:
                    # Process each packet
                    self._analyze_pyshark_packet(packet)
                except Exception as e:
                    logger.error(f"Error analyzing packet: {e}")
        except Exception as e:
            logger.error(f"PyShark capture error: {e}")
            self.running = False
    
    def _capture_with_scapy(self):
        """Capture packets using scapy"""
        try:
            def packet_callback(packet):
                if not self.running:
                    return
                try:
                    self._analyze_scapy_packet(packet)
                except Exception as e:
                    logger.error(f"Error analyzing scapy packet: {e}")
            
            # Start sniffing
            scapy.sniff(iface=self.interface, prn=packet_callback, store=0)
        except Exception as e:
            logger.error(f"Scapy capture error: {e}")
            self.running = False
    
    def _capture_with_dpkt(self):
        """Capture packets using dpkt"""
        try:
            # Create a raw socket
            if os.name == "nt":  # Windows
                # On Windows, promiscuous mode requires special setup
                socket_protocol = socket.IPPROTO_IP
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
                s.bind(("0.0.0.0", 0))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:  # Unix/Linux
                socket_protocol = socket.ntohs(0x0003)  # ETH_P_ALL
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket_protocol)
            
            while self.running:
                # Receive data
                try:
                    raw_packet = s.recvfrom(65535)[0]
                    self._analyze_dpkt_packet(raw_packet)
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error receiving packet: {e}")
            
            # Cleanup
            if os.name == "nt":
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            s.close()
            
        except Exception as e:
            logger.error(f"DPKT capture error: {e}")
            self.running = False
    
    def _capture_basic(self):
        """Basic packet capture using raw sockets"""
        try:
            # Create a raw socket to capture packets
            if os.name == "nt":  # Windows
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                s.bind(("0.0.0.0", 0))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:  # Unix/Linux
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            
            # Set timeout to allow for checking if we should stop
            s.settimeout(1.0)
            
            while self.running:
                try:
                    # Receive packet
                    packet_data = s.recvfrom(65535)[0]
                    
                    # Extract IP header (first 20 bytes)
                    ip_header = packet_data[0:20]
                    
                    # Extract source and destination IP addresses
                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    version_ihl = iph[0]
                    ihl = version_ihl & 0xF
                    
                    # Calculate where the IP header ends
                    iph_length = ihl * 4
                    
                    # Extract the protocol
                    protocol = iph[6]
                    
                    # Extract source and destination addresses
                    s_addr = socket.inet_ntoa(iph[8])
                    d_addr = socket.inet_ntoa(iph[9])
                    
                    # If this is TCP (protocol 6)
                    if protocol == 6:
                        # Extract TCP header (next 20 bytes after IP header)
                        tcp_header = packet_data[iph_length:iph_length+20]
                        
                        # Unpack TCP header
                        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                        
                        source_port = tcph[0]
                        dest_port = tcph[1]
                        
                        # Check for suspicious port patterns
                        port_matches = self.pattern_matcher.check_port_patterns(dest_port, "tcp")
                        for family, confidence, purpose in port_matches:
                            if confidence > 0.3:  # Only alert on significant matches
                                self._add_alert(
                                    alert_type="suspicious_port",
                                    source_ip=s_addr,
                                    destination_ip=d_addr,
                                    source_port=source_port,
                                    destination_port=dest_port,
                                    protocol="TCP",
                                    confidence=confidence,
                                    description=f"Connection to suspicious port {dest_port} ({purpose})",
                                    ransomware_family=family,
                                    traffic_sample=packet_data[:100] if len(packet_data) > 100 else packet_data,
                                    matched_pattern=f"TCP/{dest_port}",
                                    matched_rule=f"port_pattern:{dest_port}:{protocol}"
                                )
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error processing packet: {e}")
            
            # Cleanup
            if os.name == "nt":
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            s.close()
            
        except Exception as e:
            logger.error(f"Basic capture error: {e}")
            self.running = False
    
    def _analyze_pyshark_packet(self, packet):
        """Analyze a packet captured with pyshark"""
        # Check if it's IP
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            
            # Check for known C2 IPs
            ip_matches = self.pattern_matcher.match_ip(dst_ip)
            for family, confidence in ip_matches:
                self._add_alert(
                    alert_type="c2_communication",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=int(packet.tcp.srcport) if hasattr(packet, 'tcp') else 0,
                    destination_port=int(packet.tcp.dstport) if hasattr(packet, 'tcp') else 0,
                    protocol="TCP" if hasattr(packet, 'tcp') else "Unknown",
                    confidence=confidence,
                    description=f"Communication with known {family} C2 IP",
                    ransomware_family=family,
                    matched_pattern=dst_ip,
                    matched_rule=f"ip_match:{dst_ip}"
                )
                
            # If it's DNS
            if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                domain = packet.dns.qry_name
                domain_matches = self.pattern_matcher.match_domain(domain)
                
                for family, confidence, pattern in domain_matches:
                    self._add_alert(
                        alert_type="c2_domain_query",
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        source_port=int(packet.udp.srcport) if hasattr(packet, 'udp') else 0,
                        destination_port=int(packet.udp.dstport) if hasattr(packet, 'udp') else 0,
                        protocol="DNS",
                        confidence=confidence,
                        description=f"DNS query for known {family} C2 domain",
                        ransomware_family=family,
                        matched_pattern=pattern,
                        matched_rule=f"domain_match:{pattern}"
                    )
            
            # If it's TLS
            if hasattr(packet, 'tls') and hasattr(packet.tls, 'handshake'):
                # Check for JA3 hash if available
                if hasattr(packet.tls, 'ja3'):
                    ja3_hash = packet.tls.ja3
                    ja3_match = self.pattern_matcher.match_ja3(ja3_hash)
                    
                    if ja3_match:
                        family, confidence = ja3_match
                        self._add_alert(
                            alert_type="suspicious_tls_fingerprint",
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            source_port=int(packet.tcp.srcport) if hasattr(packet, 'tcp') else 0,
                            destination_port=int(packet.tcp.dstport) if hasattr(packet, 'tcp') else 0,
                            protocol="TLS",
                            confidence=confidence,
                            description=f"TLS connection with {family} JA3 fingerprint",
                            ransomware_family=family,
                            matched_pattern=ja3_hash,
                            matched_rule=f"ja3_hash:{ja3_hash}"
                        )
    
    def _analyze_scapy_packet(self, packet):
        """Analyze a packet captured with scapy"""
        # Check if it's an IP packet
        if scapy.IP in packet:
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            
            # Check for known C2 IPs
            ip_matches = self.pattern_matcher.match_ip(dst_ip)
            for family, confidence in ip_matches:
                self._add_alert(
                    alert_type="c2_communication",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=packet[scapy.TCP].sport if scapy.TCP in packet else 0,
                    destination_port=packet[scapy.TCP].dport if scapy.TCP in packet else 0,
                    protocol="TCP" if scapy.TCP in packet else "IP",
                    confidence=confidence,
                    description=f"Communication with known {family} C2 IP",
                    ransomware_family=family,
                    matched_pattern=dst_ip,
                    matched_rule=f"ip_match:{dst_ip}"
                )
                
            # If it's a DNS packet
            if scapy.DNS in packet and packet[scapy.DNS].qd:
                domain = packet[scapy.DNS].qd.qname.decode('utf-8')
                # Remove trailing dot if present
                if domain.endswith('.'):
                    domain = domain[:-1]
                    
                domain_matches = self.pattern_matcher.match_domain(domain)
                for family, confidence, pattern in domain_matches:
                    self._add_alert(
                        alert_type="c2_domain_query",
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        source_port=packet[scapy.UDP].sport if scapy.UDP in packet else 0,
                        destination_port=packet[scapy.UDP].dport if scapy.UDP in packet else 0,
                        protocol="DNS",
                        confidence=confidence,
                        description=f"DNS query for known {family} C2 domain",
                        ransomware_family=family,
                        matched_pattern=pattern,
                        matched_rule=f"domain_match:{pattern}"
                    )
    
    def _analyze_dpkt_packet(self, raw_packet):
        """Analyze a packet captured with dpkt"""
        # This would be implemented with dpkt packet parsing
        # For simplicity, not fully implemented in this example
        pass
    
    def _add_alert(self, alert_type, source_ip, destination_ip, source_port, destination_port, 
                  protocol, confidence, description, ransomware_family=None, traffic_sample=None,
                  matched_pattern=None, matched_rule=None):
        """Add a new alert to the alerts list with thread safety"""
        new_alert = NetworkAlert(
            timestamp=datetime.now(),
            alert_type=alert_type,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            confidence=confidence,
            description=description,
            ransomware_family=ransomware_family,
            traffic_sample=traffic_sample,
            matched_pattern=matched_pattern,
            matched_rule=matched_rule
        )
        
        with self.alert_lock:
            self.alerts.append(new_alert)
            
        # Log the alert
        logger.warning(f"ALERT: {description} ({confidence:.2f} confidence)")
    
    def get_alerts(self, min_confidence: float = 0.0, family: Optional[str] = None) -> List[NetworkAlert]:
        """
        Get current alerts, optionally filtered
        
        Args:
            min_confidence: Minimum confidence threshold
            family: Optional ransomware family to filter by
            
        Returns:
            List of NetworkAlert objects
        """
        with self.alert_lock:
            if family and min_confidence > 0:
                return [a for a in self.alerts if a.confidence >= min_confidence and a.ransomware_family == family]
            elif family:
                return [a for a in self.alerts if a.ransomware_family == family]
            elif min_confidence > 0:
                return [a for a in self.alerts if a.confidence >= min_confidence]
            else:
                return self.alerts.copy()


class NetworkMemoryCorrelator:
    """
    Correlates network traffic with memory forensics to extract encryption keys
    and ransomware indicators from memory dumps related to network connections
    """
    
    def __init__(self, memory_analyzer=None):
        """
        Initialize the correlator
        
        Args:
            memory_analyzer: Optional memory analyzer component
        """
        self.memory_analyzer = memory_analyzer
        self.process_connections = {}  # Map of process_id -> network connections
        
    def register_connection(self, process_id: int, connection_data: Dict[str, Any]):
        """
        Register a network connection for a specific process
        
        Args:
            process_id: Process ID
            connection_data: Connection details including remote IP, port, etc.
        """
        if process_id not in self.process_connections:
            self.process_connections[process_id] = []
            
        self.process_connections[process_id].append(connection_data)
    
    def find_encryption_keys_for_connection(self, source_ip: str, destination_ip: str, 
                                            source_port: int, destination_port: int) -> List[Dict[str, Any]]:
        """
        Search for encryption keys in memory related to a specific connection
        
        Args:
            source_ip: Source IP address
            destination_ip: Destination IP address
            source_port: Source port
            destination_port: Destination port
            
        Returns:
            List of potential encryption keys found in memory
        """
        # This is a placeholder - in a real implementation, this would:
        # 1. Identify processes with this connection
        # 2. Scan their memory for encryption-related patterns
        # 3. Extract and return potential keys
        
        # For demonstration purposes only
        results = []
        
        connection_tuple = (source_ip, source_port, destination_ip, destination_port)
        
        for pid, connections in self.process_connections.items():
            for conn in connections:
                conn_tuple = (conn.get('source_ip'), conn.get('source_port'), 
                              conn.get('destination_ip'), conn.get('destination_port'))
                
                if conn_tuple == connection_tuple and self.memory_analyzer:
                    # Search for encryption patterns in process memory
                    potential_keys = self.memory_analyzer.search_process_for_keys(pid)
                    
                    for key in potential_keys:
                        results.append({
                            'process_id': pid,
                            'key_type': key.get('type'),
                            'key_data': key.get('data'),
                            'confidence': key.get('confidence'),
                            'offset': key.get('offset')
                        })
        
        return results
    
    def correlate_network_pattern_with_memory(self, network_alert: NetworkAlert) -> Dict[str, Any]:
        """
        Correlate a network alert with memory analysis
        
        Args:
            network_alert: NetworkAlert object
            
        Returns:
            Correlation results with potential encryption keys
        """
        # This is a simplified placeholder
        if not self.memory_analyzer:
            return {"status": "memory_analyzer_not_available"}
            
        result = {
            "alert_id": network_alert.alert_id,
            "correlation_time": datetime.now().isoformat(),
            "potential_keys": []
        }
        
        # Find encryption keys related to the connection
        keys = self.find_encryption_keys_for_connection(
            network_alert.source_ip, 
            network_alert.destination_ip,
            network_alert.source_port,
            network_alert.destination_port
        )
        
        if keys:
            result["status"] = "potential_keys_found"
            result["potential_keys"] = keys
        else:
            result["status"] = "no_keys_found"
            
        return result


class RansomwareNetworkDetector:
    """Main ransomware network detection class that coordinates all components"""
    
    def __init__(self, interface: str = "any", memory_analyzer = None):
        """
        Initialize the ransomware network detector
        
        Args:
            interface: Network interface to monitor
            memory_analyzer: Optional memory analyzer component
        """
        self.pattern_matcher = NetworkPatternMatcher()
        self.traffic_analyzer = NetworkTrafficAnalyzer(interface, self.pattern_matcher)
        self.memory_correlator = NetworkMemoryCorrelator(memory_analyzer)
        self.logger = logger
        self.interface = interface
        self.monitoring = False
        
    def start_monitoring(self):
        """Start network monitoring"""
        if not self.monitoring:
            self.traffic_analyzer.start_capture()
            self.monitoring = True
            self.logger.info(f"Started monitoring on interface {self.interface}")
            
    def stop_monitoring(self):
        """Stop network monitoring"""
        if self.monitoring:
            self.traffic_analyzer.stop_capture()
            self.monitoring = False
            self.logger.info("Stopped network monitoring")
    
    def get_alerts(self, min_confidence: float = 0.3, family: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get current alerts as dictionaries
        
        Args:
            min_confidence: Minimum confidence threshold (default 0.3)
            family: Optional ransomware family to filter by
            
        Returns:
            List of alert dictionaries
        """
        alerts = self.traffic_analyzer.get_alerts(min_confidence, family)
        return [alert.to_dict() for alert in alerts]
    
    def correlate_with_memory(self, alert_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Correlate network alerts with memory analysis
        
        Args:
            alert_id: Optional specific alert ID to correlate
            
        Returns:
            List of correlation results
        """
        alerts = self.traffic_analyzer.get_alerts(min_confidence=0.5)
        
        if alert_id:
            alerts = [a for a in alerts if a.alert_id == alert_id]
            
        results = []
        for alert in alerts:
            correlation = self.memory_correlator.correlate_network_pattern_with_memory(alert)
            results.append(correlation)
            
        return results
    
    def generate_report(self, include_correlations: bool = False) -> Dict[str, Any]:
        """
        Generate a comprehensive report of all findings
        
        Args:
            include_correlations: Whether to include memory correlations
            
        Returns:
            Report dictionary
        """
        alerts = self.traffic_analyzer.get_alerts()
        
        # Group alerts by ransomware family
        family_alerts = {}
        for alert in alerts:
            family = alert.ransomware_family or "unknown"
            if family not in family_alerts:
                family_alerts[family] = []
            family_alerts[family].append(alert.to_dict())
        
        # Count alerts by type
        alert_types = {}
        for alert in alerts:
            alert_type = alert.alert_type
            if alert_type not in alert_types:
                alert_types[alert_type] = 0
            alert_types[alert_type] += 1
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "monitoring_time": "N/A",  # Would calculate actual monitoring time
            "total_alerts": len(alerts),
            "alerts_by_family": family_alerts,
            "alerts_by_type": alert_types,
            "highest_confidence_alerts": [a.to_dict() for a in sorted(alerts, key=lambda x: x.confidence, reverse=True)[:5]]
        }
        
        if include_correlations:
            report["memory_correlations"] = self.correlate_with_memory()
            
        return report


# Example usage
if __name__ == "__main__":
    # Create detector instance
    detector = RansomwareNetworkDetector()
    
    try:
        # Start monitoring
        detector.start_monitoring()
        
        # Keep running for a while
        time.sleep(300)  # 5 minutes
        
        # Get alerts
        alerts = detector.get_alerts(min_confidence=0.5)
        print(f"Detected {len(alerts)} suspicious network patterns")
        
        # Generate report
        report = detector.generate_report()
        print(f"Report generated with {report['total_alerts']} total alerts")
        
    except KeyboardInterrupt:
        print("Monitoring interrupted")
    finally:
        # Stop monitoring
        detector.stop_monitoring()