#!/usr/bin/env python3
"""
Ransomware Variant Detection CLI

Command-line interface for the automatic ransomware variant detector.
"""

import os
import sys
import json
import time
import datetime
import argparse
import logging
from typing import Dict, List, Optional, Any

from .enhanced_family_detector import EnhancedFamilyDetector
from .auto_variant_detector import AutoVariantDetector, process_sample_batch

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('variant_cli')

# Global detector instances
enhanced_detector = None
variant_detector = None


def init_detectors(args):
    """
    Initialize detector instances
    
    Args:
        args: Command-line arguments
    """
    global enhanced_detector, variant_detector
    
    # Initialize enhanced detector
    families_dir = getattr(args, 'families_dir', None)
    yara_rules_dir = getattr(args, 'yara_rules_dir', None)
    
    enhanced_detector = EnhancedFamilyDetector(
        families_dir=families_dir,
        yara_rules_dir=yara_rules_dir
    )
    
    # Initialize variant detector
    clusters_dir = getattr(args, 'clusters_dir', None)
    similarity_threshold = getattr(args, 'similarity_threshold', 0.75)
    cohesion_threshold = getattr(args, 'cohesion_threshold', 0.7)
    min_samples = getattr(args, 'min_samples', 2)
    
    variant_detector = AutoVariantDetector(
        enhanced_detector=enhanced_detector,
        clusters_dir=clusters_dir,
        similarity_threshold=float(similarity_threshold),
        cohesion_threshold=float(cohesion_threshold),
        min_samples=int(min_samples)
    )


def process_sample(args):
    """
    Process a single sample for variant detection
    
    Args:
        args: Command-line arguments
    """
    # Load sample data
    try:
        with open(args.sample, 'r') as f:
            sample_data = json.load(f)
    except Exception as e:
        logger.error(f"Error loading sample data: {e}")
        sys.exit(1)
    
    # Process sample
    result = variant_detector.process_sample(sample_data)
    
    # Output result
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
    else:
        print(json.dumps(result, indent=2))
    
    # Print summary
    variant_detection = result.get("variant_detection", {})
    if variant_detection.get("is_variant", False):
        print(f"\nSample {result.get('sample_id', 'unknown')} identified as a variant:")
        print(f"Base Family: {variant_detection.get('base_family', 'unknown')}")
        print(f"Variant: {variant_detection.get('variant_name', 'unknown')}")
        print(f"Confidence: {variant_detection.get('confidence', 0.0):.2f}")
        print(f"Cluster ID: {variant_detection.get('cluster_id', 'unknown')}")
        print(f"New Variant: {'Yes' if variant_detection.get('is_new_variant', False) else 'No'}")
    else:
        print(f"\nSample {result.get('sample_id', 'unknown')} is not identified as a variant")


def process_directory(args):
    """
    Process all samples in a directory
    
    Args:
        args: Command-line arguments
    """
    # Check directory
    if not os.path.exists(args.directory) or not os.path.isdir(args.directory):
        logger.error(f"Directory not found: {args.directory}")
        sys.exit(1)
    
    # Load samples
    samples = []
    processed_files = 0
    start_time = time.time()
    
    for filename in os.listdir(args.directory):
        if filename.endswith('.json'):
            try:
                filepath = os.path.join(args.directory, filename)
                with open(filepath, 'r') as f:
                    sample_data = json.load(f)
                
                samples.append(sample_data)
                processed_files += 1
                
                # Process in batches if specified
                if args.batch_size and len(samples) >= int(args.batch_size):
                    print(f"Processing batch of {len(samples)} samples...")
                    process_sample_batch(variant_detector, samples)
                    samples = []
                    
                    # Save intermediate results if requested
                    if args.save_clusters:
                        save_clusters(args)
                    
                    if args.max_files and processed_files >= int(args.max_files):
                        break
            
            except Exception as e:
                logger.error(f"Error loading sample from {filename}: {e}")
    
    # Process remaining samples
    if samples:
        print(f"Processing final batch of {len(samples)} samples...")
        batch_result = process_sample_batch(variant_detector, samples)
        
        # Output final batch result if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(batch_result, f, indent=2)
    
    # Print summary
    elapsed_time = time.time() - start_time
    print(f"\nProcessed {processed_files} files in {elapsed_time:.2f} seconds")
    
    # Evaluate clusters
    valid_clusters = variant_detector.evaluate_clusters()
    print(f"Found {len(valid_clusters)} valid variant clusters")
    
    # Generate variant definitions if requested
    if args.generate_definitions:
        output_dir = args.output_dir or (enhanced_detector.families_dir if enhanced_detector else None)
        if output_dir:
            saved_files = variant_detector.save_variant_definitions(output_dir)
            print(f"Generated {len(saved_files)} variant definitions")
            for cluster_id, filepath in saved_files.items():
                print(f"- {cluster_id}: {filepath}")
        else:
            logger.error("No output directory specified for variant definitions")


def list_clusters(args):
    """
    List variant clusters
    
    Args:
        args: Command-line arguments
    """
    # Evaluate clusters
    clusters = variant_detector.evaluate_clusters()
    
    # Format results
    result = {
        "timestamp": datetime.datetime.now().isoformat(),
        "total_clusters": len(clusters),
        "clusters": clusters
    }
    
    # Output result
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
    else:
        print(json.dumps(result, indent=2))
    
    # Print summary
    print(f"\nFound {len(clusters)} valid variant clusters")
    
    for i, cluster in enumerate(clusters):
        print(f"\n{i+1}. {cluster['variant_name']} (Base: {cluster['base_family']})")
        print(f"   Samples: {cluster['samples']}")
        print(f"   Confidence: {cluster['confidence']:.2f}")
        print(f"   Cohesion: {cluster['cohesion']:.2f}")
        print(f"   Relationship to base family: {cluster['relationship_score']:.2f}")
        print(f"   Distinctive features: {cluster['distinctive_features_count']}")


def show_cluster(args):
    """
    Show details of a specific cluster
    
    Args:
        args: Command-line arguments
    """
    # Get cluster
    cluster_id = args.cluster
    
    if cluster_id not in variant_detector.clusters:
        logger.error(f"Cluster not found: {cluster_id}")
        sys.exit(1)
    
    cluster = variant_detector.clusters[cluster_id]
    
    # Generate family definition
    definition = variant_detector.generate_variant_definition(cluster_id)
    
    # Format result
    result = {
        "cluster_id": cluster_id,
        "cluster_info": cluster.to_dict(),
        "family_definition": definition
    }
    
    # Output result
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
    else:
        print(json.dumps(result, indent=2))
    
    # Print summary
    print(f"\nCluster: {cluster.variant_name} (Base: {cluster.base_family})")
    print(f"Samples: {len(cluster.samples)}")
    print(f"Creation Date: {cluster.creation_date}")
    print(f"Last Updated: {cluster.last_updated}")
    print(f"Confidence: {cluster.confidence_score:.2f}")
    print(f"Cohesion: {cluster.calculate_cohesion():.2f}")
    print(f"Relationship to base family: {cluster.relationship_score:.2f}")
    
    print("\nDistinctive Features:")
    for i, feature in enumerate(cluster.distinctive_features):
        print(f"{i+1}. {feature.get('description', 'Unknown feature')}")


def generate_definitions(args):
    """
    Generate variant definitions
    
    Args:
        args: Command-line arguments
    """
    # Get output directory
    output_dir = args.output_dir
    if not output_dir and enhanced_detector:
        output_dir = enhanced_detector.families_dir
    
    if not output_dir:
        logger.error("No output directory specified")
        sys.exit(1)
    
    # Generate definitions
    saved_files = variant_detector.save_variant_definitions(output_dir)
    
    # Format result
    result = {
        "timestamp": datetime.datetime.now().isoformat(),
        "total_definitions": len(saved_files),
        "files": saved_files
    }
    
    # Output result
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
    
    # Print summary
    print(f"\nGenerated {len(saved_files)} variant definitions to {output_dir}")
    for cluster_id, filepath in saved_files.items():
        print(f"- {cluster_id}: {os.path.basename(filepath)}")


def save_clusters(args):
    """
    Manually save all clusters to disk
    
    Args:
        args: Command-line arguments
    """
    saved_count = 0
    
    for cluster_id, cluster in variant_detector.clusters.items():
        try:
            variant_detector._save_cluster(cluster_id, cluster)
            saved_count += 1
        except Exception as e:
            logger.error(f"Error saving cluster {cluster_id}: {e}")
    
    print(f"Saved {saved_count} clusters to {variant_detector.clusters_dir}")


def clear_cache(args):
    """
    Clear the sample cache
    
    Args:
        args: Command-line arguments
    """
    variant_detector.clear_cache()
    print("Sample cache cleared")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Ransomware Variant Detection CLI')
    parser.add_argument('--families-dir', help='Directory containing family definitions')
    parser.add_argument('--yara-rules-dir', help='Directory containing YARA rules')
    parser.add_argument('--clusters-dir', help='Directory containing variant clusters')
    
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Process sample command
    process_parser = subparsers.add_parser('process', help='Process a sample')
    process_parser.add_argument('--sample', required=True, help='Path to sample analysis JSON file')
    process_parser.add_argument('--output', help='Output file for results')
    process_parser.add_argument('--similarity-threshold', type=float, default=0.75, help='Similarity threshold for matching')
    process_parser.add_argument('--cohesion-threshold', type=float, default=0.7, help='Cohesion threshold for clusters')
    process_parser.set_defaults(func=process_sample)
    
    # Process directory command
    dir_parser = subparsers.add_parser('process-dir', help='Process all samples in a directory')
    dir_parser.add_argument('--directory', required=True, help='Directory containing sample analysis JSON files')
    dir_parser.add_argument('--output', help='Output file for results')
    dir_parser.add_argument('--batch-size', type=int, default=10, help='Batch size for processing')
    dir_parser.add_argument('--max-files', type=int, help='Maximum number of files to process')
    dir_parser.add_argument('--save-clusters', action='store_true', help='Save clusters after each batch')
    dir_parser.add_argument('--generate-definitions', action='store_true', help='Generate variant definitions after processing')
    dir_parser.add_argument('--output-dir', help='Output directory for variant definitions')
    dir_parser.add_argument('--similarity-threshold', type=float, default=0.75, help='Similarity threshold for matching')
    dir_parser.add_argument('--cohesion-threshold', type=float, default=0.7, help='Cohesion threshold for clusters')
    dir_parser.add_argument('--min-samples', type=int, default=2, help='Minimum samples for a valid cluster')
    dir_parser.set_defaults(func=process_directory)
    
    # List clusters command
    list_parser = subparsers.add_parser('list', help='List variant clusters')
    list_parser.add_argument('--output', help='Output file for results')
    list_parser.set_defaults(func=list_clusters)
    
    # Show cluster command
    show_parser = subparsers.add_parser('show', help='Show details of a specific cluster')
    show_parser.add_argument('--cluster', required=True, help='Cluster ID')
    show_parser.add_argument('--output', help='Output file for results')
    show_parser.set_defaults(func=show_cluster)
    
    # Generate definitions command
    gen_parser = subparsers.add_parser('generate', help='Generate variant definitions')
    gen_parser.add_argument('--output-dir', help='Output directory for variant definitions')
    gen_parser.add_argument('--output', help='Output file for results')
    gen_parser.set_defaults(func=generate_definitions)
    
    # Save clusters command
    save_parser = subparsers.add_parser('save', help='Save all clusters to disk')
    save_parser.set_defaults(func=save_clusters)
    
    # Clear cache command
    cache_parser = subparsers.add_parser('clear-cache', help='Clear the sample cache')
    cache_parser.set_defaults(func=clear_cache)
    
    # Parse arguments
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        sys.exit(1)
    
    # Initialize detectors
    init_detectors(args)
    
    # Execute command
    args.func(args)


if __name__ == '__main__':
    main()