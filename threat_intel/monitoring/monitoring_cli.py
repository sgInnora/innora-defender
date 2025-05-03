#!/usr/bin/env python3
"""
Ransomware Detection Monitoring CLI

This script provides a command-line interface for the real-time ransomware detection 
and monitoring system.
"""

import os
import sys
import json
import time
import logging
import argparse
import datetime
from typing import Dict, Any, List, Optional

# Add parent directory to path to import from threat_intel
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)
sys.path.append(parent_dir)

from monitoring.tracking_integration import create_tracking_integration
from monitoring.api import (
    get_detection_status, 
    get_family_details,
    get_variant_clusters,
    generate_variant_definition,
    save_variant_definitions,
    update_tracking_systems,
    perform_maintenance,
    shutdown
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('monitoring_cli')


def start_monitor(args):
    """Start the monitoring system"""
    try:
        # Create tracking integration
        integration = create_tracking_integration(args.config)
        
        # Start integration
        integration.start()
        
        print(f"Monitoring system started.")
        print(f"Processing batch size: {integration.monitor.batch_size}")
        print(f"Update interval: {integration.monitor.update_interval} seconds")
        print(f"Tracking systems: {', '.join(integration.tracking_systems)}")
        
        # Return integration for other commands
        return integration
    except Exception as e:
        logger.error(f"Error starting monitoring system: {e}")
        return None


def stop_monitor(args):
    """Stop the monitoring system"""
    try:
        result = shutdown()
        
        if result["status"] == "success":
            print(f"Monitoring system stopped: {result['message']}")
        else:
            print(f"Error stopping monitoring system: {result['message']}")
    except Exception as e:
        logger.error(f"Error stopping monitoring system: {e}")


def show_status(args):
    """Show current status"""
    try:
        status = get_detection_status()
        
        if status["status"] == "success":
            print("\n=== Ransomware Detection Status ===")
            print(f"Uptime: {format_duration(status.get('uptime', 0))}")
            print(f"Samples processed: {status.get('samples_processed', 0)}")
            print(f"Families detected: {status.get('families_detected', 0)}")
            print(f"Variants detected: {status.get('variants_detected', 0)}")
            print(f"New variants detected: {status.get('new_variants_detected', 0)}")
            print(f"Alerts generated: {status.get('alerts_generated', 0)}")
            print(f"Current queue size: {status.get('queue_size', 0)}")
            
            if status.get('last_update'):
                last_update = datetime.datetime.fromisoformat(status['last_update'])
                now = datetime.datetime.now()
                elapsed = (now - last_update).total_seconds()
                print(f"Last update: {format_duration(elapsed)} ago")
            else:
                print("Last update: Never")
            
            if args.verbose and status.get('recent_alerts'):
                print("\n=== Recent Alerts ===")
                for alert in status.get('recent_alerts', []):
                    variant_info = alert.get('variant_info', {})
                    print(f"- {alert.get('timestamp', '')}: New variant detected: " +
                          f"{variant_info.get('base_family', 'unknown')}/{variant_info.get('variant_name', 'unknown')}" +
                          f" (confidence: {variant_info.get('confidence', 0):.2f})")
        else:
            print(f"Error getting status: {status.get('message', 'unknown error')}")
    except Exception as e:
        logger.error(f"Error showing status: {e}")


def list_families(args):
    """List ransomware families"""
    try:
        # Use tracking integration to get family names
        integration = create_tracking_integration(args.config)
        family_list = integration.monitor.detection.get_all_family_names()
        
        if not family_list:
            print("No ransomware families found.")
            return
        
        # Sort by variant status and name
        family_list.sort(key=lambda x: (not x.get('is_variant', False), x.get('name', '')))
        
        # Group by base family
        base_families = {}
        variants = {}
        
        for family in family_list:
            if family.get('is_variant', False):
                base = family.get('base_family', 'unknown')
                if base not in variants:
                    variants[base] = []
                variants[base].append(family)
            else:
                base_families[family.get('id', 'unknown')] = family
        
        # Print families and variants
        print("\n=== Ransomware Families ===")
        
        for family_id, family in sorted(base_families.items()):
            print(f"- {family.get('name', family_id)}")
            
            # Print aliases if available and verbose mode is enabled
            if args.verbose and family.get('aliases'):
                print(f"  Aliases: {', '.join(family.get('aliases', []))}")
            
            # Print variants
            if family_id in variants:
                for variant in variants[family_id]:
                    print(f"  └─ {variant.get('name', 'unknown')} " +
                          f"(confidence: {variant.get('confidence', 0):.2f})")
    except Exception as e:
        logger.error(f"Error listing families: {e}")


def show_family(args):
    """Show family details"""
    try:
        result = get_family_details(args.family)
        
        if result["status"] == "success":
            family_info = result["family_info"]
            
            print(f"\n=== Family: {family_info.get('name', args.family)} ===")
            
            if family_info.get('aliases'):
                print(f"Aliases: {', '.join(family_info.get('aliases', []))}")
            
            print(f"Active: {'Yes' if family_info.get('active', False) else 'No'}")
            print(f"First seen: {family_info.get('first_seen', 'unknown')}")
            
            if family_info.get('description'):
                print(f"\nDescription:")
                print(f"{family_info.get('description')}")
            
            # Print technical details if available
            if family_info.get('technical_details'):
                tech = family_info.get('technical_details', {})
                print(f"\nTechnical Details:")
                
                if tech.get('encryption'):
                    enc = tech.get('encryption', {})
                    print(f"  Encryption: {enc.get('algorithm', 'unknown')}")
                    if enc.get('key_length'):
                        print(f"  Key length: {enc.get('key_length')}")
                
                if tech.get('extensions'):
                    print(f"  File extensions: {', '.join(tech.get('extensions', []))}")
                
                if tech.get('ransom_note'):
                    note = tech.get('ransom_note', {})
                    if note.get('filenames'):
                        print(f"  Ransom note filenames: {', '.join(note.get('filenames', []))}")
            
            # Print decryptors if available
            if family_info.get('decryptors'):
                print(f"\nAvailable Decryptors:")
                for decryptor in family_info.get('decryptors', []):
                    print(f"  - {decryptor.get('name', 'unknown')}")
                    if decryptor.get('url'):
                        print(f"    URL: {decryptor.get('url')}")
            
            # Print known variants if available
            if family_info.get('known_variants'):
                print(f"\nKnown Variants:")
                for variant in family_info.get('known_variants', []):
                    print(f"  - {variant.get('name', 'unknown')}")
                    print(f"    Confidence: {variant.get('confidence', 0):.2f}")
                    print(f"    Samples: {variant.get('samples', 0)}")
                    if variant.get('first_seen'):
                        print(f"    First seen: {variant.get('first_seen', 'unknown')}")
            
            # Print distinctive features if this is a variant
            if family_info.get('is_variant', False) and family_info.get('distinctive_features'):
                print(f"\nDistinctive Features:")
                for feature in family_info.get('distinctive_features', []):
                    print(f"  - {feature.get('description', 'unknown')}")
        else:
            print(f"Error: {result.get('message', 'unknown error')}")
    except Exception as e:
        logger.error(f"Error showing family details: {e}")


def list_variants(args):
    """List variant clusters"""
    try:
        result = get_variant_clusters(args.min_confidence)
        
        if result["status"] == "success":
            clusters = result["clusters"]
            
            if not clusters:
                print("No variant clusters found.")
                return
            
            print(f"\n=== Variant Clusters ({len(clusters)}) ===")
            
            for cluster in clusters:
                print(f"- {cluster.get('variant_name', 'unknown')} (Base: {cluster.get('base_family', 'unknown')})")
                print(f"  Confidence: {cluster.get('confidence', 0):.2f}")
                print(f"  Samples: {cluster.get('samples', 0)}")
                print(f"  Cohesion: {cluster.get('cohesion', 0):.2f}")
                print(f"  Distinctive features: {cluster.get('distinctive_features_count', 0)}")
                
                if args.verbose:
                    print(f"  Cluster ID: {cluster.get('cluster_id', 'unknown')}")
                    print(f"  Relationship to base family: {cluster.get('relationship_score', 0):.2f}")
                
                print("")
        else:
            print(f"Error: {result.get('message', 'unknown error')}")
    except Exception as e:
        logger.error(f"Error listing variants: {e}")


def show_variant(args):
    """Show variant details"""
    try:
        result = generate_variant_definition(args.cluster_id)
        
        if result["status"] == "success":
            definition = result["definition"]
            
            print(f"\n=== Variant: {definition.get('name', 'unknown')} ===")
            print(f"Base family: {definition.get('base_family', 'unknown')}")
            
            if definition.get('aliases'):
                print(f"Aliases: {', '.join(definition.get('aliases', []))}")
            
            print(f"First seen: {definition.get('first_seen', 'unknown')}")
            print(f"Active: {'Yes' if definition.get('active', False) else 'No'}")
            
            if definition.get('description'):
                print(f"\nDescription:")
                print(f"{definition.get('description')}")
            
            # Print technical details if available
            if definition.get('technical_details'):
                tech = definition.get('technical_details', {})
                print(f"\nTechnical Details:")
                
                if tech.get('encryption'):
                    enc = tech.get('encryption', {})
                    print(f"  Encryption: {enc.get('algorithm', 'unknown')}")
                    if enc.get('key_length'):
                        print(f"  Key length: {enc.get('key_length')}")
                
                if tech.get('extension'):
                    print(f"  File extensions: {', '.join(tech.get('extension', []))}")
                
                if tech.get('ransom_note'):
                    note = tech.get('ransom_note', {})
                    if note.get('filenames'):
                        print(f"  Ransom note filenames: {', '.join(note.get('filenames', []))}")
            
            # Print detection signatures if available
            if definition.get('detection_signatures'):
                sigs = definition.get('detection_signatures', {})
                
                if sigs.get('yara_rules'):
                    print(f"\nYARA Rules:")
                    if isinstance(sigs.get('yara_rules'), list):
                        for i, rule in enumerate(sigs.get('yara_rules', [])[:5]):  # Show first 5 lines
                            print(f"  {rule}")
                        if len(sigs.get('yara_rules', [])) > 5:
                            print(f"  ... ({len(sigs.get('yara_rules', [])) - 5} more lines)")
                    else:
                        print(f"  {sigs.get('yara_rules')}")
            
            # Print distinctive features
            if definition.get('distinctive_features'):
                print(f"\nDistinctive Features:")
                for feature in definition.get('distinctive_features', []):
                    print(f"  - {feature.get('description', 'unknown')}")
        else:
            print(f"Error: {result.get('message', 'unknown error')}")
    except Exception as e:
        logger.error(f"Error showing variant details: {e}")


def save_definitions(args):
    """Save variant definitions"""
    try:
        result = save_variant_definitions()
        
        if result["status"] == "success":
            print(f"Saved {result.get('variants_saved', 0)} variant definitions.")
            
            if args.verbose and result.get('files'):
                print("\nSaved files:")
                for cluster_id, filepath in result.get('files', {}).items():
                    print(f"- {cluster_id}: {filepath}")
        else:
            print(f"Error: {result.get('message', 'unknown error')}")
    except Exception as e:
        logger.error(f"Error saving definitions: {e}")


def update_tracking(args):
    """Update tracking systems"""
    try:
        result = update_tracking_systems()
        
        if result["status"] == "success":
            print(f"Updated {result.get('variants_updated', 0)} variants in tracking systems.")
            print(f"Tracking systems: {', '.join(result.get('tracking_systems', []))}")
        else:
            print(f"Error: {result.get('message', 'unknown error')}")
    except Exception as e:
        logger.error(f"Error updating tracking systems: {e}")


def run_maintenance(args):
    """Run maintenance tasks"""
    try:
        result = perform_maintenance()
        
        if result["status"] == "success":
            print(f"Maintenance completed successfully.")
            
            # Show updated stats
            stats = result.get('stats', {})
            print(f"\nUpdated Statistics:")
            print(f"Samples processed: {stats.get('samples_processed', 0)}")
            print(f"Families detected: {stats.get('families_detected', 0)}")
            print(f"Variants detected: {stats.get('variants_detected', 0)}")
            print(f"New variants detected: {stats.get('new_variants_detected', 0)}")
            print(f"Alerts generated: {stats.get('alerts_generated', 0)}")
        else:
            print(f"Error: {result.get('message', 'unknown error')}")
    except Exception as e:
        logger.error(f"Error running maintenance: {e}")


def process_sample(args):
    """Process a single sample"""
    try:
        # Load sample data
        with open(args.sample, 'r') as f:
            sample_data = json.load(f)
        
        # Create tracking integration
        integration = create_tracking_integration(args.config)
        
        # Submit sample
        result = integration.submit_sample(sample_data)
        
        if result:
            print(f"Sample submitted for processing.")
            
            # Wait for processing if requested
            if args.wait:
                print(f"Waiting for processing to complete...")
                
                # Start integration
                integration.start()
                
                # Wait for specified time
                time.sleep(args.wait)
                
                # Force processing of batch
                integration.monitor._process_batch(force=True)
                
                # Show status
                stats = integration.get_statistics()
                print(f"\nProcessing completed:")
                print(f"Samples processed: {stats.get('samples_processed', 0)}")
                print(f"Queue size: {stats.get('queue_size', 0)}")
                
                # Stop integration
                integration.stop()
            
        else:
            print(f"Sample already processed or invalid.")
    except Exception as e:
        logger.error(f"Error processing sample: {e}")


def monitor_samples(args):
    """Monitor samples directory for new samples"""
    try:
        # Create tracking integration
        integration = create_tracking_integration(args.config)
        
        # Start integration
        integration.start()
        
        print(f"Monitoring directory: {args.directory}")
        print(f"Press Ctrl+C to stop...")
        
        # Track processed files
        processed_files = set()
        
        try:
            while True:
                # List JSON files in directory
                json_files = []
                for filename in os.listdir(args.directory):
                    if filename.endswith('.json') and not filename.startswith('.'):
                        filepath = os.path.join(args.directory, filename)
                        json_files.append(filepath)
                
                # Process new files
                new_files = [f for f in json_files if f not in processed_files]
                
                if new_files:
                    print(f"\nFound {len(new_files)} new files.")
                    
                    # Process each file
                    for filepath in new_files:
                        try:
                            # Load sample data
                            with open(filepath, 'r') as f:
                                sample_data = json.load(f)
                            
                            # Submit sample
                            result = integration.submit_sample(sample_data)
                            
                            if result:
                                print(f"Submitted: {os.path.basename(filepath)}")
                            else:
                                print(f"Already processed: {os.path.basename(filepath)}")
                            
                            # Mark as processed
                            processed_files.add(filepath)
                            
                        except Exception as e:
                            logger.error(f"Error processing file {filepath}: {e}")
                
                # Show current status periodically
                if args.verbose:
                    stats = integration.get_statistics()
                    print(f"\rSamples: {stats.get('samples_processed', 0)}, " +
                          f"Queue: {stats.get('queue_size', 0)}, " +
                          f"Variants: {stats.get('variants_detected', 0)}, " +
                          f"New: {stats.get('new_variants_detected', 0)}", end="")
                
                # Wait before checking again
                time.sleep(args.interval)
                
        except KeyboardInterrupt:
            print("\nStopping monitor...")
        finally:
            # Stop integration
            integration.stop()
            
            # Show final status
            stats = integration.get_statistics()
            print(f"\nFinal status:")
            print(f"Samples processed: {stats.get('samples_processed', 0)}")
            print(f"Families detected: {stats.get('families_detected', 0)}")
            print(f"Variants detected: {stats.get('variants_detected', 0)}")
            print(f"New variants detected: {stats.get('new_variants_detected', 0)}")
            print(f"Alerts generated: {stats.get('alerts_generated', 0)}")
    except Exception as e:
        logger.error(f"Error monitoring samples: {e}")


def run_server(args):
    """Run API server"""
    try:
        # Import API module
        from monitoring.api import create_flask_app
        
        # Create Flask app
        app = create_flask_app()
        
        if app:
            print(f"Starting API server on {args.host}:{args.port}...")
            print(f"Available endpoints:")
            print(f"  GET  /api/status - Get current detection status")
            print(f"  POST /api/sample - Submit a sample for analysis")
            print(f"  GET  /api/family/<family_name> - Get family details")
            print(f"  GET  /api/variants - Get variant clusters")
            print(f"  GET  /api/variant/<cluster_id> - Get variant definition")
            print(f"  POST /api/save - Save variant definitions")
            print(f"  POST /api/update - Update tracking systems")
            print(f"  POST /api/maintenance - Perform maintenance tasks")
            print(f"  POST /api/shutdown - Shutdown the detection system")
            
            # Run app
            app.run(host=args.host, port=args.port, debug=args.debug)
        else:
            print("Could not create Flask app. Install Flask with 'pip install flask'.")
    except ImportError:
        print("Flask not installed. Install Flask with 'pip install flask'.")
    except Exception as e:
        logger.error(f"Error running server: {e}")


def format_duration(seconds):
    """Format duration in seconds to a human-readable string"""
    if seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes, {int(seconds % 60)} seconds"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        minutes = int((seconds % 3600) / 60)
        return f"{hours} hours, {minutes} minutes"
    else:
        days = int(seconds / 86400)
        hours = int((seconds % 86400) / 3600)
        return f"{days} days, {hours} hours"


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Ransomware Detection Monitoring CLI")
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    
    # Create subparsers
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Start command
    start_parser = subparsers.add_parser('start', help='Start monitoring system')
    start_parser.set_defaults(func=start_monitor)
    
    # Stop command
    stop_parser = subparsers.add_parser('stop', help='Stop monitoring system')
    stop_parser.set_defaults(func=stop_monitor)
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show current status')
    status_parser.set_defaults(func=show_status)
    
    # Families command
    families_parser = subparsers.add_parser('families', help='List ransomware families')
    families_parser.set_defaults(func=list_families)
    
    # Family command
    family_parser = subparsers.add_parser('family', help='Show family details')
    family_parser.add_argument('family', help='Family name')
    family_parser.set_defaults(func=show_family)
    
    # Variants command
    variants_parser = subparsers.add_parser('variants', help='List variant clusters')
    variants_parser.add_argument('--min-confidence', type=float, default=0.7, help='Minimum confidence threshold')
    variants_parser.set_defaults(func=list_variants)
    
    # Variant command
    variant_parser = subparsers.add_parser('variant', help='Show variant details')
    variant_parser.add_argument('cluster_id', help='Cluster ID')
    variant_parser.set_defaults(func=show_variant)
    
    # Save command
    save_parser = subparsers.add_parser('save', help='Save variant definitions')
    save_parser.set_defaults(func=save_definitions)
    
    # Update command
    update_parser = subparsers.add_parser('update', help='Update tracking systems')
    update_parser.set_defaults(func=update_tracking)
    
    # Maintenance command
    maintenance_parser = subparsers.add_parser('maintenance', help='Run maintenance tasks')
    maintenance_parser.set_defaults(func=run_maintenance)
    
    # Process command
    process_parser = subparsers.add_parser('process', help='Process a single sample')
    process_parser.add_argument('sample', help='Path to sample analysis JSON file')
    process_parser.add_argument('--wait', type=int, help='Wait for processing to complete (seconds)')
    process_parser.set_defaults(func=process_sample)
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Monitor samples directory')
    monitor_parser.add_argument('directory', help='Directory containing sample analysis JSON files')
    monitor_parser.add_argument('--interval', type=int, default=5, help='Check interval in seconds')
    monitor_parser.set_defaults(func=monitor_samples)
    
    # Server command
    server_parser = subparsers.add_parser('server', help='Run API server')
    server_parser.add_argument('--host', default='127.0.0.1', help='Server host')
    server_parser.add_argument('--port', type=int, default=5000, help='Server port')
    server_parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    server_parser.set_defaults(func=run_server)
    
    # Parse arguments
    args = parser.parse_args()
    
    # Execute command
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()