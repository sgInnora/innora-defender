"""
Tracking Handler Modules Package

This package contains handlers for integrating with various tracking systems.
Each handler module should implement the BaseHandler interface for consistency.
"""

from typing import Dict, Any, Protocol, Optional, runtime_checkable


@runtime_checkable
class BaseHandler(Protocol):
    """Protocol for tracking system handlers"""
    
    def push_alert(self, alert_data: Dict[str, Any], report_file: str) -> str:
        """
        Push alert to tracking system
        
        Args:
            alert_data: Alert data
            report_file: Path to report file
            
        Returns:
            Status message or reference ID
        """
        ...
    
    def push_update(self, update_data: Dict[str, Any], report_file: str) -> str:
        """
        Push update to tracking system
        
        Args:
            update_data: Update data
            report_file: Path to report file
            
        Returns:
            Status message or reference ID
        """
        ...