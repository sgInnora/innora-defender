#!/usr/bin/env python3
"""
Threat Intelligence Report Generator
Generates structured reports from threat intelligence correlation results.
"""

import os
import json
import datetime
import logging
from typing import Dict, List, Any, Optional
import markdown
import base64
import webbrowser
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('report_generator')

class ReportGenerator:
    """Generates reports from threat intelligence correlation results"""
    
    def __init__(self):
        self.reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports', 'generated')
        os.makedirs(self.reports_dir, exist_ok=True)
        
        self.templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
        os.makedirs(self.templates_dir, exist_ok=True)
        
        # Create default template if it doesn't exist
        self._create_default_templates()
        
    def _create_default_templates(self):
        """Create default report templates if they don't exist"""
        # Single sample report template
        single_template_path = os.path.join(self.templates_dir, 'single_sample_template.md')
        if not os.path.exists(single_template_path):
            with open(single_template_path, 'w') as f:
                f.write("""# Ransomware Analysis Report: {sample_id}

## Executive Summary

**Analysis Date:** {analysis_date}

**Ransomware Classification:** {is_ransomware_text}
**Confidence:** {ransomware_probability:.1%}

{executive_summary}

## Identified Ransomware Family

{family_info}

## Tactics, Techniques, and Procedures (TTPs)

{ttps_table}

## Indicators of Compromise (IOCs)

### File Hashes
{hash_list}

### Network Indicators
{network_indicators}

### File Artifacts
{file_artifacts}

## Threat Intelligence Sources

{threat_intel_sources}

## Recommendations

{recommendations}

---
Report generated: {generation_time}
""")
        
        # Multiple sample report template
        multi_template_path = os.path.join(self.templates_dir, 'multi_sample_template.md')
        if not os.path.exists(multi_template_path):
            with open(multi_template_path, 'w') as f:
                f.write("""# Ransomware Campaign Analysis Report

## Executive Summary

**Analysis Date:** {analysis_date}
**Samples Analyzed:** {sample_count}

{executive_summary}

## Common Ransomware Families

{family_info}

## Common Tactics, Techniques, and Procedures (TTPs)

{ttps_table}

## Common Indicators of Compromise (IOCs)

### Network Indicators
{network_indicators}

## Campaign Analysis

{campaign_analysis}

## Sample Details

{sample_details}

## Recommendations

{recommendations}

---
Report generated: {generation_time}
""")
    
    def _format_executive_summary(self, correlation_result: Dict) -> str:
        """Format the executive summary section of the report"""
        if correlation_result.get("is_ransomware", False):
            family_text = ""
            if correlation_result.get("identified_families", []):
                top_family = correlation_result["identified_families"][0]
                family_text = f"Analysis indicates this is likely **{top_family['name'].capitalize()} ransomware** with {top_family['confidence']:.1%} confidence."
            
            return f"""This sample has been identified as **ransomware** with {correlation_result['ransomware_probability']:.1%} confidence. {family_text}

The sample exhibits behavior consistent with data encryption malware, including encryption-related strings, ransom notes, and file encryption activities. Threat intelligence sources confirm this classification.

{len(correlation_result.get('ttps', []))} MITRE ATT&CK techniques were identified, primarily related to {', '.join(set(tactic for ttp in correlation_result.get('ttps', []) for tactic in ttp.get('tactics', []))[:3])}.
"""
        else:
            return f"""This sample has been analyzed but does not appear to be ransomware (confidence: {1 - correlation_result['ransomware_probability']:.1%}).

While the sample may be malicious, it lacks the typical indicators of ransomware such as encryption routines, ransom notes, or known ransomware family signatures.
"""
    
    def _format_family_info(self, correlation_result: Dict) -> str:
        """Format the ransomware family information section"""
        if not correlation_result.get("identified_families", []):
            return "No specific ransomware family was identified."
        
        result = ""
        for i, family in enumerate(correlation_result["identified_families"][:3]):
            if i == 0:
                result += f"### Primary Family: {family['name'].capitalize()}\n\n"
                result += f"**Confidence:** {family['confidence']:.1%}\n\n"
                
                # Add description if available in threat intel
                mitre_data = correlation_result.get("threat_intel", {}).get("mitre", {})
                if mitre_data and mitre_data.get("name", "").lower() == family["name"].lower():
                    result += f"{mitre_data.get('description', 'No description available.')}\n\n"
            else:
                result += f"### Alternative Classification: {family['name'].capitalize()}\n\n"
                result += f"**Confidence:** {family['confidence']:.1%}\n\n"
        
        return result
    
    def _format_ttps_table(self, correlation_result: Dict) -> str:
        """Format the TTPs table section"""
        ttps = correlation_result.get("ttps", [])
        if not ttps:
            return "No specific MITRE ATT&CK techniques were identified."
        
        result = "| Technique ID | Name | Tactics |\n"
        result += "|-------------|------|--------|\n"
        
        for ttp in ttps:
            tactics = ", ".join(ttp.get("tactics", []))
            result += f"| [{ttp['id']}](https://attack.mitre.org/techniques/{ttp['id'].replace('.', '/')}) | {ttp['name']} | {tactics} |\n"
        
        return result
    
    def _format_hash_list(self, correlation_result: Dict) -> str:
        """Format the hash list section"""
        hashes = correlation_result.get("iocs", {}).get("hashes", [])
        if not hashes:
            sample_id = correlation_result.get("sample_id", "")
            if sample_id and sample_id != "unknown":
                return f"SHA256: `{sample_id}`"
            return "No file hashes available."
        
        result = ""
        for hash_entry in hashes:
            result += f"**{hash_entry['type'].upper()}:** `{hash_entry['value']}`\n\n"
        
        return result
    
    def _format_network_indicators(self, correlation_result: Dict) -> str:
        """Format the network indicators section"""
        iocs = correlation_result.get("iocs", {})
        domains = iocs.get("domains", [])
        ips = iocs.get("ips", [])
        urls = iocs.get("urls", [])
        
        if not domains and not ips and not urls:
            return "No network indicators identified."
        
        result = ""
        
        if domains:
            result += "### Domains\n\n"
            for domain in domains:
                result += f"- `{domain['value']}`\n"
            result += "\n"
        
        if ips:
            result += "### IP Addresses\n\n"
            for ip in ips:
                result += f"- `{ip['value']}`\n"
            result += "\n"
        
        if urls:
            result += "### URLs\n\n"
            for url in urls:
                result += f"- `{url['value']}`\n"
            result += "\n"
        
        return result
    
    def _format_file_artifacts(self, correlation_result: Dict) -> str:
        """Format the file artifacts section"""
        files = correlation_result.get("iocs", {}).get("files", [])
        registry_keys = correlation_result.get("iocs", {}).get("registry_keys", [])
        
        if not files and not registry_keys:
            return "No specific file artifacts identified."
        
        result = ""
        
        if files:
            result += "### Files\n\n"
            for file in files:
                file_type = f" ({file.get('type', '')})" if file.get('type') else ""
                result += f"- `{file['value']}`{file_type}\n"
            result += "\n"
        
        if registry_keys:
            result += "### Registry Keys\n\n"
            for key in registry_keys:
                result += f"- `{key['value']}`\n"
            result += "\n"
        
        return result
    
    def _format_threat_intel_sources(self, correlation_result: Dict) -> str:
        """Format the threat intelligence sources section"""
        threat_intel = correlation_result.get("threat_intel", {})
        if not threat_intel:
            return "No threat intelligence data available."
        
        result = ""
        
        # VirusTotal information
        vt_data = threat_intel.get("virustotal", {})
        if vt_data and not "error" in vt_data:
            result += "### VirusTotal\n\n"
            
            if "detection_ratio" in vt_data:
                result += f"**Detection Ratio:** {vt_data['detection_ratio']}\n\n"
            
            if "detections" in vt_data:
                result += "**Top Detections:**\n\n"
                count = 0
                for av_name, detection in vt_data["detections"].items():
                    result += f"- {av_name}: `{detection}`\n"
                    count += 1
                    if count >= 5:
                        break
                result += "\n"
        
        # AlienVault information
        av_data = threat_intel.get("alienvault", {})
        if av_data and not "error" in av_data:
            result += "### AlienVault OTX\n\n"
            
            if "pulse_count" in av_data:
                result += f"**Pulse Count:** {av_data['pulse_count']}\n\n"
            
            if "tags" in av_data and av_data["tags"]:
                result += "**Tags:** " + ", ".join(f"`{tag}`" for tag in av_data["tags"][:10]) + "\n\n"
            
            if "malware_families" in av_data and av_data["malware_families"]:
                result += "**Malware Families:** " + ", ".join(av_data["malware_families"]) + "\n\n"
            
            if "references" in av_data and av_data["references"]:
                result += "**References:**\n\n"
                for reference in av_data["references"][:5]:
                    result += f"- [{reference}]({reference})\n"
                result += "\n"
        
        # MITRE information
        mitre_data = threat_intel.get("mitre", {})
        if mitre_data and not "error" in mitre_data and "tactics" in mitre_data:
            result += "### MITRE ATT&CK\n\n"
            
            result += "**Tactics:**\n\n"
            for tactic in mitre_data["tactics"]:
                result += f"- {tactic['name']} ({tactic['id']})\n"
            result += "\n"
        
        if not result:
            return "No detailed threat intelligence data available."
            
        return result
    
    def _format_recommendations(self, correlation_result: Dict) -> str:
        """Format the recommendations section"""
        recommendations = correlation_result.get("recommendations", [])
        if not recommendations:
            return "No specific recommendations available."
        
        result = ""
        
        # Group recommendations by priority
        high_priority = [rec for rec in recommendations if rec.get("priority") == "high"]
        medium_priority = [rec for rec in recommendations if rec.get("priority") == "medium"]
        low_priority = [rec for rec in recommendations if rec.get("priority") == "low"]
        
        if high_priority:
            result += "### High Priority\n\n"
            for rec in high_priority:
                result += f"- **{rec.get('type', 'Action').replace('_', ' ').title()}**: {rec['description']}"
                if "link" in rec:
                    result += f" [More Information]({rec['link']})"
                result += "\n"
            result += "\n"
        
        if medium_priority:
            result += "### Medium Priority\n\n"
            for rec in medium_priority:
                result += f"- **{rec.get('type', 'Action').replace('_', ' ').title()}**: {rec['description']}"
                if "link" in rec:
                    result += f" [More Information]({rec['link']})"
                result += "\n"
            result += "\n"
        
        if low_priority:
            result += "### Low Priority\n\n"
            for rec in low_priority:
                result += f"- **{rec.get('type', 'Action').replace('_', ' ').title()}**: {rec['description']}"
                if "link" in rec:
                    result += f" [More Information]({rec['link']})"
                result += "\n"
            result += "\n"
        
        return result
    
    def _format_campaign_analysis(self, multi_correlation_result: Dict) -> str:
        """Format the campaign analysis section for multi-sample reports"""
        campaign_indicators = multi_correlation_result.get("campaign_indicators", [])
        if not campaign_indicators:
            return "No campaign indicators identified. The analyzed samples do not appear to be related."
        
        result = ""
        for campaign in campaign_indicators:
            result += f"### {campaign['name']}\n\n"
            result += f"**Confidence:** {campaign['confidence']:.1%}\n\n"
            result += f"**Timespan:** {campaign['timespan_days']} days\n\n"
            result += f"**Samples:** {campaign['sample_count']}\n\n"
            
            result += "**Key Indicators:**\n\n"
            
            if "domains" in campaign.get("key_iocs", {}):
                result += "- Domains: " + ", ".join(f"`{domain}`" for domain in campaign["key_iocs"]["domains"]) + "\n"
            
            if "ips" in campaign.get("key_iocs", {}):
                result += "- IP Addresses: " + ", ".join(f"`{ip}`" for ip in campaign["key_iocs"]["ips"]) + "\n"
            
            result += "\n"
        
        return result
    
    def _format_sample_details(self, samples: List[Dict]) -> str:
        """Format the sample details section for multi-sample reports"""
        if not samples:
            return "No sample details available."
        
        result = ""
        for i, sample in enumerate(samples):
            if i >= 10:  # Limit to 10 samples for readability
                result += f"\n...{len(samples) - 10} more samples...\n"
                break
                
            result += f"### Sample {i+1}: {sample.get('sample_id', 'Unknown')}\n\n"
            
            if sample.get("is_ransomware", False):
                result += f"**Classification:** Ransomware (confidence: {sample['ransomware_probability']:.1%})\n\n"
                
                if sample.get("identified_families", []):
                    families = ", ".join(f"{family['name']} ({family['confidence']:.1%})" 
                                        for family in sample["identified_families"][:2])
                    result += f"**Families:** {families}\n\n"
                
                if sample.get("ttps", []):
                    techniques = ", ".join(f"{ttp['id']}" for ttp in sample["ttps"][:3])
                    result += f"**Techniques:** {techniques}\n\n"
            else:
                result += f"**Classification:** Not ransomware (confidence: {1 - sample['ransomware_probability']:.1%})\n\n"
            
            # Abbreviated IOCs
            iocs = sample.get("iocs", {})
            ioc_summary = []
            
            if "domains" in iocs and iocs["domains"]:
                ioc_summary.append(f"{len(iocs['domains'])} domains")
            
            if "ips" in iocs and iocs["ips"]:
                ioc_summary.append(f"{len(iocs['ips'])} IPs")
            
            if "files" in iocs and iocs["files"]:
                ioc_summary.append(f"{len(iocs['files'])} files")
            
            if ioc_summary:
                result += f"**IOCs:** {', '.join(ioc_summary)}\n\n"
            
            result += "---\n\n"
        
        return result
    
    def generate_single_sample_report(self, correlation_result: Dict) -> str:
        """
        Generate a report for a single sample
        
        Args:
            correlation_result: Dictionary containing correlation results
            
        Returns:
            Path to the generated report
        """
        # Make sure correlation_result has the correct structure
        sample_id = correlation_result.get("sample_id", f"unknown_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}")
        
        # Load the template
        template_path = os.path.join(self.templates_dir, 'single_sample_template.md')
        try:
            with open(template_path, 'r') as f:
                template = f.read()
        except Exception as e:
            logger.error(f"Error loading template: {e}")
            # Create a simple template
            template = "# Ransomware Analysis Report: {sample_id}\n\n## Executive Summary\n\n{executive_summary}\n\n## Recommendations\n\n{recommendations}"
        
        # Prepare template variables
        now = datetime.datetime.now()
        analysis_date = correlation_result.get("analysis_timestamp", now.isoformat())
        try:
            analysis_date = datetime.datetime.fromisoformat(analysis_date).strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            analysis_date = now.strftime('%Y-%m-%d %H:%M:%S')
        
        is_ransomware_text = "Ransomware" if correlation_result.get("is_ransomware", False) else "Not Ransomware"
        
        # Format report sections
        executive_summary = self._format_executive_summary(correlation_result)
        family_info = self._format_family_info(correlation_result)
        ttps_table = self._format_ttps_table(correlation_result)
        hash_list = self._format_hash_list(correlation_result)
        network_indicators = self._format_network_indicators(correlation_result)
        file_artifacts = self._format_file_artifacts(correlation_result)
        threat_intel_sources = self._format_threat_intel_sources(correlation_result)
        recommendations = self._format_recommendations(correlation_result)
        
        # Fill the template
        report_content = template.format(
            sample_id=sample_id,
            analysis_date=analysis_date,
            is_ransomware_text=is_ransomware_text,
            ransomware_probability=correlation_result.get("ransomware_probability", 0),
            executive_summary=executive_summary,
            family_info=family_info,
            ttps_table=ttps_table,
            hash_list=hash_list,
            network_indicators=network_indicators,
            file_artifacts=file_artifacts,
            threat_intel_sources=threat_intel_sources,
            recommendations=recommendations,
            generation_time=now.strftime('%Y-%m-%d %H:%M:%S')
        )
        
        # Save the report
        report_filename = f"report_{sample_id.replace(':', '_')}_{now.strftime('%Y%m%d%H%M%S')}.md"
        report_path = os.path.join(self.reports_dir, report_filename)
        
        try:
            with open(report_path, 'w') as f:
                f.write(report_content)
            logger.info(f"Report saved to {report_path}")
        except Exception as e:
            logger.error(f"Error saving report: {e}")
            return None
        
        return report_path
    
    def generate_multi_sample_report(self, multi_correlation_result: Dict, samples: List[Dict]) -> str:
        """
        Generate a report for multiple samples
        
        Args:
            multi_correlation_result: Dictionary containing multi-sample correlation results
            samples: List of dictionaries containing individual sample correlation results
            
        Returns:
            Path to the generated report
        """
        # Load the template
        template_path = os.path.join(self.templates_dir, 'multi_sample_template.md')
        try:
            with open(template_path, 'r') as f:
                template = f.read()
        except Exception as e:
            logger.error(f"Error loading template: {e}")
            # Create a simple template
            template = "# Ransomware Campaign Analysis Report\n\n## Executive Summary\n\n{executive_summary}\n\n## Campaign Analysis\n\n{campaign_analysis}\n\n## Recommendations\n\n{recommendations}"
        
        # Prepare template variables
        now = datetime.datetime.now()
        analysis_date = multi_correlation_result.get("analysis_timestamp", now.isoformat())
        try:
            analysis_date = datetime.datetime.fromisoformat(analysis_date).strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            analysis_date = now.strftime('%Y-%m-%d %H:%M:%S')
        
        # Create executive summary
        ransomware_samples = [s for s in samples if s.get("is_ransomware", False)]
        campaign_indicators = multi_correlation_result.get("campaign_indicators", [])
        
        executive_summary = f"""A total of **{len(samples)}** samples were analyzed, of which **{len(ransomware_samples)}** were identified as ransomware.

"""
        
        if campaign_indicators:
            campaign = campaign_indicators[0]
            executive_summary += f"""Analysis indicates these samples are likely part of a **{campaign['name']}** campaign with {campaign['confidence']:.1%} confidence. 
The campaign has been active for approximately {campaign['timespan_days']} days and uses common infrastructure across samples.

"""
        
        if multi_correlation_result.get("common_families", []):
            families = ", ".join(f"**{family['name']}**" for family in multi_correlation_result["common_families"][:3])
            executive_summary += f"Common ransomware families identified: {families}.\n\n"
        
        # Format report sections
        if multi_correlation_result.get("common_families", []):
            family_info = "| Family | Sample Count | Average Confidence |\n"
            family_info += "|--------|--------------|--------------------|\n"
            for family in multi_correlation_result["common_families"]:
                family_info += f"| {family['name']} | {family['count']} | {family['confidence']:.1%} |\n"
        else:
            family_info = "No common ransomware families identified across samples."
        
        if multi_correlation_result.get("common_ttps", []):
            ttps_table = "| Technique ID | Name | Sample Count | Tactics |\n"
            ttps_table += "|-------------|------|--------------|--------|\n"
            for ttp in multi_correlation_result["common_ttps"]:
                tactics = ", ".join(ttp.get("tactics", []))
                ttps_table += f"| [{ttp['id']}](https://attack.mitre.org/techniques/{ttp['id'].replace('.', '/')}) | {ttp['name']} | {ttp['count']} | {tactics} |\n"
        else:
            ttps_table = "No common TTPs identified across samples."
        
        network_indicators = "### Domains\n\n"
        common_domains = multi_correlation_result.get("common_iocs", {}).get("domains", [])
        if common_domains:
            network_indicators += "| Domain | Sample Count |\n"
            network_indicators += "|--------|-------------|\n"
            for domain in common_domains:
                network_indicators += f"| `{domain['value']}` | {domain['count']} |\n"
            network_indicators += "\n"
        else:
            network_indicators += "No common domains identified.\n\n"
        
        network_indicators += "### IP Addresses\n\n"
        common_ips = multi_correlation_result.get("common_iocs", {}).get("ips", [])
        if common_ips:
            network_indicators += "| IP Address | Sample Count |\n"
            network_indicators += "|------------|-------------|\n"
            for ip in common_ips:
                network_indicators += f"| `{ip['value']}` | {ip['count']} |\n"
            network_indicators += "\n"
        else:
            network_indicators += "No common IP addresses identified.\n\n"
        
        network_indicators += "### URLs\n\n"
        common_urls = multi_correlation_result.get("common_iocs", {}).get("urls", [])
        if common_urls:
            network_indicators += "| URL | Sample Count |\n"
            network_indicators += "|-----|-------------|\n"
            for url in common_urls:
                network_indicators += f"| `{url['value']}` | {url['count']} |\n"
            network_indicators += "\n"
        else:
            network_indicators += "No common URLs identified.\n\n"
        
        campaign_analysis = self._format_campaign_analysis(multi_correlation_result)
        sample_details = self._format_sample_details(samples)
        
        # Prepare recommendations based on campaign indicators
        recommendations = "## General Recommendations\n\n"
        
        if ransomware_samples:
            recommendations += """- **Isolate Infected Systems**: Immediately isolate any infected systems from the network to prevent lateral movement and further encryption.
- **Implement Network Blocks**: Block all identified C2 domains and IP addresses at the firewall and DNS level.
- **Enhance EDR Monitoring**: Configure EDR solutions to alert on the identified TTPs and IOCs.
- **Check Backups**: Verify the integrity of backups and ensure they are isolated from potentially infected networks.
- **Review Email Filters**: Update email security gateways to block similar phishing emails that may be part of this campaign.
"""
            
            if campaign_indicators:
                campaign = campaign_indicators[0]
                if campaign.get("common_family"):
                    recommendations += f"""
## {campaign['common_family'].capitalize()} Specific Recommendations

- **Check for Decryptors**: Investigate whether decryption tools are available for {campaign['common_family']} ransomware.
- **Review File Extension Blocks**: Configure systems to block execution of files with extensions associated with {campaign['common_family']}.
- **Monitor for Related Payloads**: Implement monitoring for dropper behavior associated with {campaign['common_family']}.
- **Analyze Initial Access**: Review how the ransomware gained initial access and implement specific controls.
"""
        else:
            recommendations += """- **Implement Network Blocks**: Block all identified suspicious domains and IP addresses at the firewall and DNS level.
- **Enhance EDR Monitoring**: Configure EDR solutions to alert on the identified TTPs and IOCs.
- **Review Security Controls**: Assess existing security controls against the identified techniques.
"""
        
        # Fill the template
        report_content = template.format(
            analysis_date=analysis_date,
            sample_count=len(samples),
            executive_summary=executive_summary,
            family_info=family_info,
            ttps_table=ttps_table,
            network_indicators=network_indicators,
            campaign_analysis=campaign_analysis,
            sample_details=sample_details,
            recommendations=recommendations,
            generation_time=now.strftime('%Y-%m-%d %H:%M:%S')
        )
        
        # Save the report
        report_filename = f"campaign_report_{now.strftime('%Y%m%d%H%M%S')}.md"
        report_path = os.path.join(self.reports_dir, report_filename)
        
        try:
            with open(report_path, 'w') as f:
                f.write(report_content)
            logger.info(f"Multi-sample report saved to {report_path}")
        except Exception as e:
            logger.error(f"Error saving multi-sample report: {e}")
            return None
        
        return report_path
    
    def generate_html_report(self, markdown_path: str) -> str:
        """
        Convert a Markdown report to HTML
        
        Args:
            markdown_path: Path to the Markdown report
            
        Returns:
            Path to the generated HTML report
        """
        if not markdown_path or not os.path.exists(markdown_path):
            logger.error(f"Markdown file not found: {markdown_path}")
            return None
        
        try:
            with open(markdown_path, 'r') as f:
                markdown_content = f.read()
                
            # Convert markdown to HTML
            html_content = markdown.markdown(markdown_content, extensions=['tables', 'fenced_code'])
            
            # Add HTML head with CSS for better styling
            html_document = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ransomware Analysis Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
        }}
        h1, h2, h3, h4 {{
            color: #2c3e50;
        }}
        h1 {{
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
            margin-top: 30px;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px 12px;
            text-align: left;
        }}
        th {{
            background-color: #f5f5f5;
        }}
        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        code {{
            background-color: #f8f8f8;
            padding: 2px 4px;
            border-radius: 3px;
            font-family: Consolas, Monaco, 'Andale Mono', monospace;
            font-size: 0.9em;
        }}
        a {{
            color: #3498db;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        hr {{
            border: none;
            border-top: 1px solid #eee;
            margin: 30px 0;
        }}
        .recommendations h3 {{
            color: #e74c3c;
        }}
    </style>
</head>
<body>
{html_content}
</body>
</html>
"""
            
            # Save the HTML report
            html_path = os.path.splitext(markdown_path)[0] + '.html'
            with open(html_path, 'w') as f:
                f.write(html_document)
                
            logger.info(f"HTML report saved to {html_path}")
            return html_path
            
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            return None
    
    def view_report(self, report_path: str) -> None:
        """
        Open a report for viewing
        
        Args:
            report_path: Path to the report (Markdown or HTML)
        """
        if not report_path or not os.path.exists(report_path):
            logger.error(f"Report file not found: {report_path}")
            return
        
        # If it's a Markdown file, convert to HTML first
        if report_path.endswith('.md'):
            html_path = self.generate_html_report(report_path)
            if html_path:
                report_path = html_path
            else:
                logger.error("Failed to convert Markdown to HTML")
                return
        
        # Open the report in the default browser
        try:
            webbrowser.open('file://' + os.path.abspath(report_path))
            logger.info(f"Opened report in browser: {report_path}")
        except Exception as e:
            logger.error(f"Error opening report: {e}")


if __name__ == "__main__":
    # Example usage
    generator = ReportGenerator()
    
    # Sample correlation result
    correlation_result = {
        "sample_id": "aaaaaaaaabbbbbbbbccccccccdddddddd",
        "analysis_timestamp": datetime.datetime.now().isoformat(),
        "is_ransomware": True,
        "ransomware_probability": 0.92,
        "identified_families": [
            {"name": "locky", "confidence": 0.85, "score": 5},
            {"name": "gandcrab", "confidence": 0.35, "score": 2}
        ],
        "ttps": [
            {"id": "T1486", "name": "Data Encrypted for Impact", "tactics": ["impact"]},
            {"id": "T1489", "name": "Service Stop", "tactics": ["impact"]}
        ],
        "iocs": {
            "hashes": [
                {"type": "sha256", "value": "aaaaaaaaabbbbbbbbccccccccdddddddd"},
                {"type": "md5", "value": "11111111222222223333333344444444"}
            ],
            "domains": [
                {"value": "badguy.com"},
                {"value": "payment.badguy.com"}
            ],
            "ips": [
                {"value": "192.168.1.1"},
                {"value": "8.8.8.8"}
            ],
            "urls": [
                {"value": "https://badguy.com/payment"}
            ],
            "files": [
                {"value": "C:\\Users\\victim\\Desktop\\README.txt", "type": "ransom_note"},
                {"value": "C:\\Users\\victim\\Documents\\file.encrypted", "type": "encrypted_file"}
            ]
        },
        "threat_intel": {
            "virustotal": {
                "detection_ratio": "45/68",
                "detections": {
                    "Kaspersky": "Trojan-Ransom.Win32.Locky.a",
                    "Symantec": "Ransom.Locky",
                    "Microsoft": "Ransom:Win32/Locky.A"
                }
            },
            "alienvault": {
                "pulse_count": 15,
                "malware_families": ["Locky"],
                "tags": ["ransomware", "trojan", "banking"],
                "references": [
                    "https://example.com/locky-analysis",
                    "https://example.com/ransomware-report"
                ]
            },
            "mitre": {
                "name": "locky",
                "description": "Locky is a ransomware that encrypts files with the .locky extension and demands payment for decryption.",
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
                ],
                "tactics": [
                    {"id": "TA0040", "name": "impact"}
                ]
            }
        },
        "recommendations": [
            {
                "type": "isolation",
                "priority": "high",
                "description": "Isolate infected systems immediately to prevent further encryption"
            },
            {
                "type": "memory_forensics",
                "priority": "high",
                "description": "Capture memory dumps from infected systems to potentially extract encryption keys"
            },
            {
                "type": "backup_verification",
                "priority": "high",
                "description": "Verify backup integrity and test restoration procedures"
            },
            {
                "type": "network_blocking",
                "priority": "medium",
                "description": "Block communication with identified C2 servers to prevent further infection and data exfiltration"
            },
            {
                "type": "mitigation",
                "priority": "medium",
                "description": "Implement network monitoring and DNS filtering to detect and block C2 traffic",
                "mitre_tactic": "command-and-control"
            }
        ]
    }
    
    # Generate a report
    report_path = generator.generate_single_sample_report(correlation_result)
    
    # View the report
    if report_path:
        generator.view_report(report_path)