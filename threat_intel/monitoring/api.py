#!/usr/bin/env python3
"""
Ransomware Detection API

This module provides a REST API for the real-time ransomware detection system.
"""

import os
import sys
import json
import logging
import datetime
from typing import Dict, Any, List, Optional, Tuple

# Add parent directory to path to import from threat_intel
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)
sys.path.append(parent_dir)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('detection_api')

# Global tracking integration instance
_integration = None

def get_integration():
    """Get or create tracking integration instance"""
    global _integration
    
    if _integration is None:
        from monitoring.tracking_integration import create_tracking_integration
        _integration = create_tracking_integration()
        
        # Start integration
        _integration.start()
        
        logger.info("Tracking integration created and started")
    
    return _integration

def submit_sample(sample_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Submit a sample for analysis
    
    Args:
        sample_data: Sample analysis data
        
    Returns:
        Response dictionary
    """
    integration = get_integration()
    
    try:
        # Submit sample
        result = integration.submit_sample(sample_data)
        
        if result:
            return {
                "status": "success",
                "message": "Sample submitted for analysis",
                "queue_size": integration.get_statistics().get("queue_size", 0)
            }
        else:
            return {
                "status": "error",
                "message": "Sample already processed or invalid",
                "queue_size": integration.get_statistics().get("queue_size", 0)
            }
    except Exception as e:
        logger.error(f"Error submitting sample: {e}")
        return {
            "status": "error",
            "message": f"Error submitting sample: {str(e)}"
        }

def get_detection_status() -> Dict[str, Any]:
    """
    Get current detection status
    
    Returns:
        Dictionary containing detection status
    """
    integration = get_integration()
    
    try:
        # Get statistics
        stats = integration.get_statistics()
        
        # Get recent alerts
        alerts = integration.get_recent_alerts(5)
        
        return {
            "status": "success",
            "uptime": stats.get("uptime_seconds", 0),
            "samples_processed": stats.get("samples_processed", 0),
            "families_detected": stats.get("families_detected", 0),
            "variants_detected": stats.get("variants_detected", 0),
            "new_variants_detected": stats.get("new_variants_detected", 0),
            "alerts_generated": stats.get("alerts_generated", 0),
            "queue_size": stats.get("queue_size", 0),
            "last_update": stats.get("last_update"),
            "recent_alerts": alerts
        }
    except Exception as e:
        logger.error(f"Error getting detection status: {e}")
        return {
            "status": "error",
            "message": f"Error getting detection status: {str(e)}"
        }

def get_family_details(family_name: str) -> Dict[str, Any]:
    """
    Get details about a ransomware family
    
    Args:
        family_name: Name of the ransomware family
        
    Returns:
        Dictionary containing family details
    """
    integration = get_integration()
    
    try:
        # Get family details
        family_info = integration.monitor.detection.refine_family_information(family_name)
        
        if not family_info:
            return {
                "status": "error",
                "message": f"Family '{family_name}' not found"
            }
        
        return {
            "status": "success",
            "family_name": family_name,
            "family_info": family_info
        }
    except Exception as e:
        logger.error(f"Error getting family details: {e}")
        return {
            "status": "error",
            "message": f"Error getting family details: {str(e)}"
        }

def get_variant_clusters(min_confidence: float = 0.7) -> Dict[str, Any]:
    """
    Get variant clusters
    
    Args:
        min_confidence: Minimum confidence threshold
        
    Returns:
        Dictionary containing variant clusters
    """
    integration = get_integration()
    
    try:
        # Get variant clusters
        if integration.monitor.detection.variant_detector:
            clusters = integration.monitor.detection.variant_detector.evaluate_clusters()
            
            # Filter by confidence
            filtered_clusters = [
                cluster for cluster in clusters
                if cluster.get("confidence", 0) >= min_confidence
            ]
            
            return {
                "status": "success",
                "total_clusters": len(clusters),
                "filtered_clusters": len(filtered_clusters),
                "min_confidence": min_confidence,
                "clusters": filtered_clusters
            }
        else:
            return {
                "status": "error",
                "message": "Variant detector not available"
            }
    except Exception as e:
        logger.error(f"Error getting variant clusters: {e}")
        return {
            "status": "error",
            "message": f"Error getting variant clusters: {str(e)}"
        }

def generate_variant_definition(cluster_id: str) -> Dict[str, Any]:
    """
    Generate variant definition
    
    Args:
        cluster_id: Cluster ID
        
    Returns:
        Dictionary containing variant definition
    """
    integration = get_integration()
    
    try:
        # Generate variant definition
        if integration.monitor.detection.variant_detector:
            definition = integration.monitor.detection.variant_detector.generate_variant_definition(cluster_id)
            
            if definition:
                return {
                    "status": "success",
                    "cluster_id": cluster_id,
                    "definition": definition
                }
            else:
                return {
                    "status": "error",
                    "message": f"Cluster '{cluster_id}' not found or definition generation failed"
                }
        else:
            return {
                "status": "error",
                "message": "Variant detector not available"
            }
    except Exception as e:
        logger.error(f"Error generating variant definition: {e}")
        return {
            "status": "error",
            "message": f"Error generating variant definition: {str(e)}"
        }

def save_variant_definitions() -> Dict[str, Any]:
    """
    Save variant definitions
    
    Returns:
        Dictionary containing save results
    """
    integration = get_integration()
    
    try:
        # Save variant definitions
        if integration.monitor.detection.variant_detector:
            saved_files = integration.monitor.detection.variant_detector.save_variant_definitions()
            
            return {
                "status": "success",
                "variants_saved": len(saved_files),
                "files": saved_files
            }
        else:
            return {
                "status": "error",
                "message": "Variant detector not available"
            }
    except Exception as e:
        logger.error(f"Error saving variant definitions: {e}")
        return {
            "status": "error",
            "message": f"Error saving variant definitions: {str(e)}"
        }

def update_tracking_systems() -> Dict[str, Any]:
    """
    Update tracking systems
    
    Returns:
        Dictionary containing update results
    """
    integration = get_integration()
    
    try:
        # Get valid variant clusters
        if integration.monitor.detection.variant_detector:
            valid_variants = integration.monitor.detection.variant_detector.evaluate_clusters()
            
            # Filter high-confidence variants
            high_confidence_variants = [
                variant for variant in valid_variants
                if variant.get("confidence", 0) >= integration.monitor.alert_threshold
            ]
            
            # Create update data
            update_data = {
                "timestamp": datetime.datetime.now().isoformat(),
                "variants_updated": len(high_confidence_variants),
                "files": {}
            }
            
            # Add file paths
            for variant in high_confidence_variants:
                cluster_id = variant.get("cluster_id")
                if cluster_id:
                    update_data["files"][cluster_id] = f"variant_{variant.get('variant_name', 'unknown')}"
            
            # Push update to tracking systems
            integration._handle_definition_update(update_data)
            
            return {
                "status": "success",
                "tracking_systems": list(integration.system_handlers.keys()),
                "variants_updated": len(high_confidence_variants),
                "update_data": update_data
            }
        else:
            return {
                "status": "error",
                "message": "Variant detector not available"
            }
    except Exception as e:
        logger.error(f"Error updating tracking systems: {e}")
        return {
            "status": "error",
            "message": f"Error updating tracking systems: {str(e)}"
        }

def perform_maintenance() -> Dict[str, Any]:
    """
    Perform maintenance tasks
    
    Returns:
        Dictionary containing maintenance results
    """
    integration = get_integration()
    
    try:
        # Perform maintenance
        integration.perform_maintenance()
        
        return {
            "status": "success",
            "message": "Maintenance completed successfully",
            "stats": integration.get_statistics()
        }
    except Exception as e:
        logger.error(f"Error performing maintenance: {e}")
        return {
            "status": "error",
            "message": f"Error performing maintenance: {str(e)}"
        }

def shutdown() -> Dict[str, Any]:
    """
    Shutdown the detection system
    
    Returns:
        Dictionary containing shutdown results
    """
    global _integration
    
    try:
        if _integration:
            # Stop integration
            _integration.stop()
            
            # Reset integration
            _integration = None
            
            return {
                "status": "success",
                "message": "Detection system shutdown successfully"
            }
        else:
            return {
                "status": "success",
                "message": "Detection system was not running"
            }
    except Exception as e:
        logger.error(f"Error shutting down detection system: {e}")
        return {
            "status": "error",
            "message": f"Error shutting down detection system: {str(e)}"
        }


# Example of how to set up a REST API (using Flask)
def create_flask_app():
    """Create Flask app for the detection API"""
    try:
        from flask import Flask, request, jsonify
        
        app = Flask(__name__)
        
        @app.route('/api/status', methods=['GET'])
        def api_status():
            return jsonify(get_detection_status())
        
        @app.route('/api/sample', methods=['POST'])
        def api_submit_sample():
            sample_data = request.json
            return jsonify(submit_sample(sample_data))
        
        @app.route('/api/family/<family_name>', methods=['GET'])
        def api_family_details(family_name):
            return jsonify(get_family_details(family_name))
        
        @app.route('/api/variants', methods=['GET'])
        def api_variant_clusters():
            min_confidence = float(request.args.get('min_confidence', 0.7))
            return jsonify(get_variant_clusters(min_confidence))
        
        @app.route('/api/variant/<cluster_id>', methods=['GET'])
        def api_variant_definition(cluster_id):
            return jsonify(generate_variant_definition(cluster_id))
        
        @app.route('/api/save', methods=['POST'])
        def api_save_definitions():
            return jsonify(save_variant_definitions())
        
        @app.route('/api/update', methods=['POST'])
        def api_update_tracking():
            return jsonify(update_tracking_systems())
        
        @app.route('/api/maintenance', methods=['POST'])
        def api_maintenance():
            return jsonify(perform_maintenance())
        
        @app.route('/api/shutdown', methods=['POST'])
        def api_shutdown():
            return jsonify(shutdown())
        
        return app
    except ImportError:
        logger.error("Flask not installed, cannot create API app")
        return None


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Ransomware Detection API")
    parser.add_argument('--host', default='127.0.0.1', help='API host')
    parser.add_argument('--port', type=int, default=5000, help='API port')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    # Create and run Flask app
    app = create_flask_app()
    
    if app:
        app.run(host=args.host, port=args.port, debug=args.debug)
    else:
        print("Could not create Flask app. Install Flask with 'pip install flask'.")
        sys.exit(1)