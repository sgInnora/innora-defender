# Ransomware Network Indicators Guide

This document provides a comprehensive guide to network-based indicators of compromise (IOCs) for major ransomware families. These indicators can be used to identify, detect, and respond to ransomware attacks through network traffic analysis.

## Table of Contents

1. [Introduction](#introduction)
2. [Types of Network Indicators](#types-of-network-indicators)
3. [Usage in Detection](#usage-in-detection)
4. [Ransomware Network Patterns](#ransomware-network-patterns)
5. [Encryption Key Exchange Patterns](#encryption-key-exchange-patterns)
6. [Detection Rules](#detection-rules)
7. [Reference Materials](#reference-materials)

## Introduction

Network-based indicators are critical for early detection of ransomware attacks, often allowing for identification before encryption begins. This document catalogs network indicators for major ransomware families and provides guidance on their application in security monitoring.

When a ransomware attack occurs, specific network patterns can be observed at different stages of the attack lifecycle:

1. **Initial Access**: Communication with command and control (C2) servers
2. **Lateral Movement**: Network scanning and exploitation activities
3. **Data Exfiltration**: Data transfer to attacker-controlled servers (double/triple extortion)
4. **Key Exchange**: Transmission of encryption keys or parameters
5. **Ransom Negotiation**: Communication with payment portals

By monitoring for these network patterns, security teams can detect and potentially disrupt ransomware attacks before encryption is complete.

## Types of Network Indicators

### C2 Communication Indicators

Command and Control (C2) indicators identify traffic between infected systems and attacker-controlled infrastructure:

1. **Domain Indicators**: Domain names used for C2 communication
2. **IP Indicators**: IP addresses of C2 servers
3. **URL Path Patterns**: Specific URL paths used in C2 requests
4. **Traffic Patterns**: Distinctive communication patterns
5. **TLS Fingerprints**: SSL/TLS client hello fingerprints (JA3 hashes)

### Lateral Movement Indicators

Lateral movement indicators identify attempts to spread within a network:

1. **SMB Traffic**: Unusual SMB traffic to multiple hosts
2. **RPC Calls**: Remote procedure calls to system services
3. **Administrative Protocols**: Use of WMI, PowerShell remoting, PsExec
4. **Credential Access**: LDAP queries, Kerberos ticket requests
5. **Port Scanning**: Rapid connection attempts to multiple hosts

### Data Exfiltration Indicators

Data exfiltration indicators identify attempts to steal data:

1. **Large Outbound Transfers**: Unusually large data transfers
2. **Compressed Archives**: Transfer of recently created archives
3. **Unusual Protocols**: Use of uncommon protocols for data transfer
4. **Encrypted Channels**: Data transfer over encrypted channels
5. **Exfiltration Staging**: Creation of temporary data staging areas

## Usage in Detection

### Detection Methods

1. **Signature-Based Detection**: Using specific patterns or IOCs
2. **Anomaly-Based Detection**: Identifying unusual network behavior
3. **Behavioral Analysis**: Recognizing patterns of malicious activity
4. **TLS Inspection**: Analyzing TLS handshakes without decryption
5. **Traffic Flow Analysis**: Examining patterns in network flows

### Detection Tools

These network indicators can be implemented in various security tools:

1. **Network IDS/IPS**: Suricata, Snort, Zeek (Bro)
2. **SIEM Systems**: Splunk, ELK Stack, QRadar
3. **NDR Solutions**: Darktrace, ExtraHop, Vectra
4. **Packet Analyzers**: Wireshark, tcpdump, NetworkMiner
5. **Threat Hunting Platforms**: Velociraptor, MISP, TheHive

## Ransomware Network Patterns

### WannaCry

WannaCry ransomware exhibited distinctive network patterns:

1. **C2 Domains**:
   - Primary killswitch domain: `www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`
   - Secondary C2: `xxlvbrloxvriy2c5.onion`

2. **Port Usage**:
   - TCP/445: SMB for EternalBlue exploitation
   - TCP/139: NetBIOS for lateral movement

3. **Traffic Patterns**:
   - SMB traffic with EternalBlue exploit signatures
   - DNS queries for the killswitch domain
   - No data exfiltration (simple ransomware)

4. **Detection Example**:
   ```
   alert tcp any any -> any 445 (msg:"WANNACRY SMB exploit"; 
   content:"|00 00 00 72 00 00 00 08 00 00 00 00|"; offset:0; depth:12; 
   classtype:trojan-activity; sid:1000001; rev:1;)
   ```

### REvil/Sodinokibi

REvil exhibited sophisticated network patterns:

1. **C2 Infrastructure**:
   - Dynamic domains, often using legitimate cloud services
   - Varied .onion addresses for payment portals

2. **Port Usage**:
   - TCP/443: HTTPS for C2 communication
   - UDP/0: Potential DNS tunneling

3. **Traffic Patterns**:
   - HTTPS POST requests with binary data to random subdomains
   - TLS with specific cipher preferences
   - DNS tunneling for C2 communication
   - Large outbound encrypted transfers to cloud storage

4. **Detection Example**:
   ```
   alert tls any any -> any any (msg:"Possible REvil C2 Communication Pattern"; 
   flow:established; tls.sni; content:!"."; content:".com"; endswith; 
   pcre:"/^[a-z0-9]{12,20}\.com$/i"; classtype:trojan-activity; sid:2024219; rev:1;)
   ```

### LockBit

LockBit employs advanced network techniques:

1. **C2 Infrastructure**:
   - Dynamic domains unique to each campaign
   - Multiple .onion leak sites

2. **Port Usage**:
   - TCP/443: HTTPS for C2 communication
   - TCP/445: SMB for lateral movement
   - TCP/135: RPC for discovery

3. **Traffic Patterns**:
   - Distinctive HTTPS traffic patterns
   - Aggressive lateral movement via SMB
   - Domain controller targeting
   - Abnormal RPC and LDAP queries
   - Data staging using .7z archives

4. **Detection Example**:
   ```
   alert smb any any -> any any (msg:"Potential LockBit Lateral Movement"; 
   flow:established; content:"|FF|SMB"; offset:4; depth:4; 
   pcre:"/\x01\x00\x00\x00.{20,30}\xff\xff\xff\xff/"; 
   classtype:trojan-activity; sid:2024220; rev:1;)
   ```

### BlackCat/ALPHV

BlackCat leverages a Rust-based architecture with distinctive patterns:

1. **C2 Infrastructure**:
   - Highly variable domains
   - Multiple .onion domains for leaks

2. **Port Usage**:
   - TCP/443: HTTPS communication
   - TCP/22: SSH/SCP for exfiltration
   - TCP/21: FTP for exfiltration

3. **Traffic Patterns**:
   - TLS with Rust-specific fingerprints
   - Unique JA3 hash: `51c64c77e60f3980eea90869b68c58a8`
   - Triple-staged exfiltration
   - ESXi-specific traffic for virtualization targeting

4. **Detection Example**:
   ```
   alert tls any any -> any any (msg:"Potential BlackCat TLS Fingerprint"; 
   flow:established; ja3.hash; content:"51c64c77e60f3980eea90869b68c58a8"; 
   classtype:trojan-activity; sid:2024222; rev:1;)
   ```

### Conti

Conti employed TrickBot-related infrastructure:

1. **C2 Infrastructure**:
   - Shared with TrickBot
   - .onion domains for leak sites

2. **Port Usage**:
   - TCP/443: HTTPS communication
   - TCP/445: SMB for lateral movement
   - TCP/4343: Alternative C2 channel

3. **Traffic Patterns**:
   - Distinctive HTTP User-Agent strings
   - BazarLoader-style C2 communication
   - Data staging with .zip/.rar archives
   - Irregular beaconing intervals

4. **Detection Example**:
   ```
   alert http any any -> any any (msg:"Potential Conti C2 HTTP Pattern"; 
   flow:established,to_server; http.method; content:"POST"; 
   http.uri; content:"/wp-content/plugins/"; 
   http.user_agent; pcre:"/Mozilla\/[4-5]\.0\s*\(Windows NT [6-9]\.[0-9]; Win[6-9][4-9]; \S+\)/"; 
   classtype:trojan-activity; sid:2024224; rev:1;)
   ```

## Encryption Key Exchange Patterns

Ransomware often exhibits specific patterns during encryption key exchange:

### Key Exchange Methods

1. **Direct Transmission**:
   - Keys transmitted directly from C2 to infected host
   - Usually small encrypted packets (<1KB)
   - Often occurs immediately before encryption begins

2. **DNS Tunneling**:
   - Keys encoded in DNS queries/responses
   - High-entropy subdomains in DNS queries
   - Abnormal DNS query volume and size

3. **Embedded Keys**:
   - Keys embedded in HTTP/HTTPS responses
   - Often Base64 or hex-encoded in HTTP headers or body
   - May be encrypted with a separate key

### Detection Challenges

Key exchange detection faces several challenges:

1. **Encryption**: Keys are often transmitted over encrypted channels
2. **Low Volume**: Key exchange involves minimal traffic
3. **Timing**: Brief exchange windows are easily missed
4. **Variation**: Exchange methods vary between ransomware families

### Detection Strategies

Effective detection strategies include:

1. **Temporal Correlation**: Identify network activity immediately preceding encryption
2. **Entropy Analysis**: Look for high-entropy data transfers
3. **Size Analysis**: Focus on anomalous small encrypted transfers
4. **Protocol Abuse**: Detect unusual use of standard protocols
5. **TLS Inspection**: Examine TLS handshake parameters without decryption

## Detection Rules

### Suricata Rules

```
# WannaCry SMB Exploitation
alert tcp any any -> any 445 (msg:"ET EXPLOIT WannaCry/WannaCrypt Ransomware MS17-010 SMB Exploit"; 
flow:established,to_server; content:"|00 00 00 72 00 00 00 08|"; depth:8; 
content:"|40 00 00 18 0c 00 00 00|"; distance:4; within:8; 
reference:url,github.com/rapidsec/wannasmile; classtype:trojan-activity; sid:2024217; rev:1;)

# REvil C2 Communication
alert tls any any -> any any (msg:"Possible REvil C2 Communication Pattern"; 
flow:established; tls.sni; content:!"."; content:".com"; endswith; 
pcre:"/^[a-z0-9]{12,20}\.com$/i"; classtype:trojan-activity; sid:2024219; rev:1;)

# LockBit Data Exfiltration
alert tcp any any -> any any (msg:"Potential LockBit Data Exfiltration"; 
flow:established,to_server; content:"POST"; http.method; content:"multipart/form-data"; http.header; 
content:".7z"; http.header; classtype:trojan-activity; sid:2024221; rev:1;)

# BlackCat TLS Fingerprint
alert tls any any -> any any (msg:"Potential BlackCat TLS Fingerprint"; 
flow:established; ja3.hash; content:"51c64c77e60f3980eea90869b68c58a8"; 
classtype:trojan-activity; sid:2024222; rev:1;)

# Conti C2 HTTP Pattern
alert http any any -> any any (msg:"Potential Conti C2 HTTP Pattern"; 
flow:established,to_server; http.method; content:"POST"; http.uri; content:"/wp-content/plugins/"; 
http.user_agent; pcre:"/Mozilla\/[4-5]\.0\s*\(Windows NT [6-9]\.[0-9]; Win[6-9][4-9]; \S+\)/"; 
classtype:trojan-activity; sid:2024224; rev:1;)

# Hive Data Exfiltration
alert http any any -> any any (msg:"Potential Hive Ransomware Data Exfiltration"; 
flow:established,to_server; http.method; content:"POST"; http.uri; content:"/home/"; 
http.header; content:"Content-Type: application/octet-stream"; content:"Content-Length:"; 
http.header; classtype:trojan-activity; sid:2024225; rev:1;)

# Generic Ransomware Key Exchange
alert tcp any any -> any any (msg:"Potential Ransomware Key Exchange"; 
flow:established,to_server; dsize:<1024; content:"POST"; http.method; 
content:"!DOCTYPE"; http.response_body; pcre:"/[A-Za-z0-9+\/=]{42,}|[A-Fa-f0-9]{64,}/"; 
classtype:trojan-activity; sid:2024226; rev:1;)
```

### Zeek Scripts

```zeek
# Conti C2 Detection
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) { 
    if (method == "POST" && /\/wp-content\/plugins\// in original_URI && 
        /Mozilla\/[4-5]\.0\s*\(Windows NT [6-9]\.[0-9]; Win[6-9][4-9]; \S+\)/ in c$http$user_agent) { 
        NOTICE([
            "$conn"] = c, 
            ["$note"] = HTTP::Potential_Conti_C2, 
            ["$msg"] = fmt("Potential Conti C2: %s %s", original_URI, c$http$user_agent)
        ]); 
    }
}

# LockBit Lateral Movement
event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool) { 
    if (hdr$command == 0x25 && /\x01\x00\x00\x00.{20,30}\xff\xff\xff\xff/ in c$service) { 
        NOTICE([
            "$conn"] = c, 
            ["$note"] = Conn::Possible_LockBit_Movement, 
            ["$msg"] = "Possible LockBit lateral movement detected"
        ]); 
    }
}

# BlackCat TLS Fingerprint
hook ssl_client_hello(c: connection, version: count, record_version: count, 
                     possible_ts: time, client_random: string, session_id: string, 
                     ciphers: index_vec, comp_methods: index_vec) &priority=10 { 
    if (md5(ja3_string(c$id, version, record_version, client_random, 
                      session_id, ciphers, comp_methods)) == "51c64c77e60f3980eea90869b68c58a8") { 
        NOTICE([
            "$conn"] = c, 
            ["$note"] = SSL::Potential_BlackCat_Client, 
            ["$msg"] = "Potential BlackCat client TLS fingerprint"
        ]); 
    }
}

# Ransomware DNS Tunneling
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    # Check for long, high-entropy subdomains (potential key material)
    local parts = split_string(query, /\./);
    for (i in parts) {
        if (|parts[i]| > 25) {
            # Calculate entropy
            local char_count: table[string] of count;
            for (j in parts[i]) {
                local char = parts[i][j];
                if (char !in char_count)
                    char_count[char] = 0;
                char_count[char] += 1;
            }
            
            local entropy = 0.0;
            for (char in char_count) {
                local p = char_count[char] / |parts[i]|;
                entropy += -p * log10(p) / log10(2);
            }
            
            if (entropy > 3.8) {
                NOTICE([
                    "$conn"] = c,
                    ["$note"] = DNS::Potential_Ransomware_Tunneling,
                    ["$msg"] = fmt("Potential DNS tunneling: high entropy subdomain in %s", query)
                ]);
            }
        }
    }
}
```

## Reference Materials

### MITRE ATT&CK Techniques

| Technique ID | Name | Description |
|--------------|------|-------------|
| T1071 | Application Layer Protocol | C2 communications using application layer protocols |
| T1571 | Non-Standard Port | Using non-standard ports for C2 communications |
| T1568 | Dynamic Resolution | Using dynamic DNS and fast flux to hide C2 |
| T1572 | Protocol Tunneling | Tunneling C2 traffic through standard protocols |
| T1573 | Encrypted Channel | Using encryption to hide C2 communications |
| T1041 | Exfiltration Over C2 Channel | Exfiltrating data over the C2 channel |
| T1567 | Exfiltration Over Web Service | Using web services for data exfiltration |
| T1048 | Exfiltration Over Alternative Protocol | Using uncommon protocols for exfiltration |

### Network Forensics Tools

1. **Wireshark**: Packet analysis and protocol decoding
2. **NetworkMiner**: Network forensic analysis tool
3. **Zeek (Bro)**: Network monitoring framework
4. **Suricata**: Network IDS/IPS and security monitoring
5. **RITA**: Real Intelligence Threat Analytics for network traffic
6. **Moloch**: Large-scale, full packet capture and search
7. **PcapXray**: Network forensics visualization tool

### Additional Resources

1. **Network-Based Detection Papers**:
   - "Network-Based Ransomware Detection and Categorization using Dynamic Local Scale Invariant Feature Transform" (2020)
   - "REDACT: Real-Time Detection of Ransomware Network Traffic" (2021)
   - "Detecting Ransomware with Network Traffic Analysis" (2022)

2. **Threat Intelligence Reports**:
   - CISA Alert AA21-265A: Conti Ransomware
   - CISA Alert AA22-040A: BlackCat/ALPHV Ransomware
   - CISA Alert AA22-321A: Hive Ransomware
   - FBI Flash Alert: LockBit 2.0 Ransomware

3. **Vendor Research**:
   - Mandiant: BlackCat Analysis in Rust
   - Sophos: LockBit 3.0 Technical Analysis
   - Microsoft: Conti Ransomware Network Traffic Analysis
   - Palo Alto Unit 42: REvil Network Indicators

---

© 2025 Innora-Sentinel安全团队 | All Rights Reserved | [https://innora.ai](https://innora.ai)