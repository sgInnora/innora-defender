#!/usr/bin/env python3
"""
JIRA Integration Handler for Ransomware Detection

This module provides integration with JIRA for tracking ransomware variants.
"""

import os
import sys
import json
import logging
from typing import Dict, Any, Optional, List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('jira_handler')


class JiraHandler:
    """Handler for JIRA integration"""
    
    def __init__(self):
        """Initialize the JIRA handler"""
        # Load configuration from environment variables
        self.api_url = os.environ.get("JIRA_API_URL", "https://your-jira-instance.atlassian.net")
        self.api_key = os.environ.get("JIRA_API_KEY", "")
        self.project_key = os.environ.get("JIRA_PROJECT_KEY", "RANSOM")
        self.username = os.environ.get("JIRA_USERNAME", "")
        
        # Check if JIRA API is available
        self.is_available = bool(self.api_key and self.username)
        
        # Try to import JIRA library
        try:
            import jira
            self.jira_available = True
        except ImportError:
            self.jira_available = False
            logger.warning("JIRA library not installed, using placeholder functionality")
    
    def _get_jira_client(self):
        """
        Get JIRA client
        
        Returns:
            JIRA client instance or None
        """
        if not self.jira_available or not self.is_available:
            return None
        
        try:
            # Import here to avoid issues if library is not installed
            from jira import JIRA
            
            # Create client
            jira_client = JIRA(
                server=self.api_url,
                basic_auth=(self.username, self.api_key)
            )
            
            return jira_client
        except Exception as e:
            logger.error(f"Error creating JIRA client: {e}")
            return None
    
    def push_alert(self, alert_data: Dict[str, Any], report_file: str) -> str:
        """
        Push alert to JIRA
        
        Args:
            alert_data: Alert data
            report_file: Path to report file
            
        Returns:
            JIRA issue key
        """
        # Extract variant info
        variant_info = alert_data.get("variant_info", {})
        variant_name = variant_info.get("variant_name", "unknown")
        base_family = variant_info.get("base_family", "unknown")
        confidence = variant_info.get("confidence", 0)
        sample_id = variant_info.get("sample_id", "unknown")
        
        # Create issue summary and description
        summary = f"New Ransomware Variant Detected: {base_family}/{variant_name}"
        
        description = f"""
h2. Ransomware Variant Alert

*Base Family:* {base_family}
*Variant Name:* {variant_name}
*Confidence:* {confidence:.2f}
*Sample ID:* {sample_id}
*Severity:* {alert_data.get('severity', 'medium')}
*Detection Time:* {alert_data.get('timestamp', 'unknown')}

h3. Suggested Actions
"""
        
        # Add suggested actions
        for action in alert_data.get("suggested_actions", []):
            description += f"* {action}\n"
        
        # Check if we can create a real JIRA issue
        jira_client = self._get_jira_client()
        
        if jira_client:
            try:
                # Create issue fields
                issue_dict = {
                    'project': {'key': self.project_key},
                    'summary': summary,
                    'description': description,
                    'issuetype': {'name': 'Task'},
                    'priority': {'name': 'High' if alert_data.get('severity') == 'high' else 'Medium'},
                    'labels': ['ransomware', 'variant', base_family, variant_name]
                }
                
                # Create issue
                issue = jira_client.create_issue(fields=issue_dict)
                
                # Add attachment if report file exists
                if os.path.exists(report_file):
                    jira_client.add_attachment(issue=issue.key, attachment=report_file)
                
                logger.info(f"Created JIRA issue: {issue.key}")
                
                return issue.key
                
            except Exception as e:
                logger.error(f"Error creating JIRA issue: {e}")
        
        # Fallback to placeholder if JIRA API is not available
        logger.info(f"Would create JIRA issue: {summary}")
        
        return f"{self.project_key}-DEMO123"
    
    def push_update(self, update_data: Dict[str, Any], report_file: str) -> str:
        """
        Push update to JIRA
        
        Args:
            update_data: Update data
            report_file: Path to report file
            
        Returns:
            JIRA issue key
        """
        # Create issue summary and description
        summary = f"Ransomware Variant Definitions Updated: {update_data.get('variants_updated', 0)} variants"
        
        description = f"""
h2. Ransomware Variant Definition Update

*Variants Updated:* {update_data.get('variants_updated', 0)}
*Update Time:* {update_data.get('timestamp', 'unknown')}

h3. Updated Variants
"""
        
        # Add updated variants
        for variant_id, file_path in update_data.get("files", {}).items():
            description += f"* {variant_id}: {os.path.basename(file_path)}\n"
        
        # Check if we can create a real JIRA issue
        jira_client = self._get_jira_client()
        
        if jira_client:
            try:
                # Create issue fields
                issue_dict = {
                    'project': {'key': self.project_key},
                    'summary': summary,
                    'description': description,
                    'issuetype': {'name': 'Task'},
                    'priority': {'name': 'Medium'},
                    'labels': ['ransomware', 'definition-update']
                }
                
                # Create issue
                issue = jira_client.create_issue(fields=issue_dict)
                
                # Add attachment if report file exists
                if os.path.exists(report_file):
                    jira_client.add_attachment(issue=issue.key, attachment=report_file)
                
                logger.info(f"Created JIRA issue: {issue.key}")
                
                return issue.key
                
            except Exception as e:
                logger.error(f"Error creating JIRA issue: {e}")
        
        # Fallback to placeholder if JIRA API is not available
        logger.info(f"Would create JIRA issue: {summary}")
        
        return f"{self.project_key}-DEMO456"