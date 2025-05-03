#!/usr/bin/env python3
"""
Ransomware Family Relationship Graph CLI

This script provides a command-line interface for generating
ransomware family relationship visualizations.
"""

import os
import sys
import json
import argparse
import logging
import webbrowser
from typing import Dict, Any, Optional

# Add parent directory to path to import from threat_intel
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)
sys.path.append(parent_dir)

from visualization.relationship_graph import create_relationship_graph
from family_detection.integration_with_variant import AdvancedFamilyDetectionIntegration

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('graph_cli')


def generate_graph(args):
    """
    Generate relationship graph
    
    Args:
        args: Command-line arguments
    """
    # Create graph generator
    graph_generator = create_relationship_graph(
        families_dir=args.families_dir,
        yara_rules_dir=args.yara_rules_dir,
        clusters_dir=args.clusters_dir,
        output_dir=args.output_dir,
        min_confidence=args.min_confidence
    )
    
    # Generate visualization
    if args.format == 'html':
        output_file = graph_generator.generate_html_visualization(args.output_file)
        
        # Open in browser if requested
        if args.open_browser:
            webbrowser.open('file://' + os.path.abspath(output_file))
    else:
        output_file = graph_generator.generate_json_data(args.output_file)
    
    print(f"\nGenerated {args.format.upper()} file: {output_file}")


def show_families(args):
    """
    Show available families and variants
    
    Args:
        args: Command-line arguments
    """
    # Create detection instance
    detection = AdvancedFamilyDetectionIntegration(
        families_dir=args.families_dir,
        yara_rules_dir=args.yara_rules_dir,
        clusters_dir=args.clusters_dir,
        auto_variant_detection=True
    )
    
    # Get families
    families = detection.get_all_family_names()
    
    # Group by base family
    base_families = {}
    variants = {}
    
    for family in families:
        if family.get('is_variant', False):
            base_family = family.get('base_family', 'unknown')
            if base_family not in variants:
                variants[base_family] = []
            variants[base_family].append(family)
        else:
            base_family = family.get('id', 'unknown')
            base_families[base_family] = family
    
    # Print families and variants
    print("\n=== Available Ransomware Families ===")
    print(f"Total families: {len(base_families)}")
    print(f"Total variants: {sum(len(v) for v in variants.values())}")
    print("")
    
    # Sort families by name
    sorted_families = sorted(base_families.items(), key=lambda x: x[1].get('name', '').lower())
    
    for family_id, family in sorted_families:
        family_name = family.get('name', family_id)
        aliases = family.get('aliases', [])
        alias_str = f" (aka {', '.join(aliases)})" if aliases else ""
        
        print(f"- {family_name}{alias_str}")
        
        # Print variants
        family_variants = variants.get(family_id, [])
        if family_variants and args.show_variants:
            # Sort variants by confidence
            family_variants.sort(key=lambda x: x.get('confidence', 0), reverse=True)
            
            for variant in family_variants:
                variant_name = variant.get('name', 'Unknown variant')
                confidence = variant.get('confidence', 0)
                
                # Skip low confidence variants if requested
                if confidence < args.min_confidence:
                    continue
                
                print(f"  • {variant_name} (confidence: {confidence:.2f})")
    
    print(f"\nTo generate a visual relationship graph, run:")
    print(f"python -m threat_intel.visualization.graph_cli generate")


def analyze_similarities(args):
    """
    Analyze and show similarities between variants
    
    Args:
        args: Command-line arguments
    """
    # Create graph generator
    graph_generator = create_relationship_graph(
        families_dir=args.families_dir,
        yara_rules_dir=args.yara_rules_dir,
        clusters_dir=args.clusters_dir,
        min_confidence=args.min_confidence
    )
    
    # Get graph data
    graph_data = graph_generator.generate_d3_graph()
    
    # Extract links that represent similarities
    similarity_links = [
        link for link in graph_data.get('links', [])
        if link.get('type') == 'similar_to'
    ]
    
    # Create a map of nodes
    nodes_map = {node['id']: node for node in graph_data.get('nodes', [])}
    
    # Sort links by similarity
    similarity_links.sort(key=lambda x: x.get('similarity', 0), reverse=True)
    
    print(f"\n=== Variant Similarity Analysis ===")
    print(f"Found {len(similarity_links)} similarity relationships\n")
    
    # Print top similarities
    for link in similarity_links[:args.limit]:
        source_node = nodes_map.get(link['source'], {})
        target_node = nodes_map.get(link['target'], {})
        
        source_name = source_node.get('full_name', 'Unknown')
        target_name = target_node.get('full_name', 'Unknown')
        similarity = link.get('similarity', 0)
        
        print(f"Similarity: {similarity:.2f}")
        print(f"  {source_name} <-> {target_name}")
        
        # Show base families if they differ
        source_family = source_node.get('base_family')
        target_family = target_node.get('base_family')
        
        if source_family and target_family and source_family != target_family:
            print(f"  Base families: {source_family} <-> {target_family}")
        
        print("")
    
    # Output to JSON if requested
    if args.output:
        output_data = {
            "similarities": [
                {
                    "source": nodes_map.get(link['source'], {}).get('full_name', 'Unknown'),
                    "target": nodes_map.get(link['target'], {}).get('full_name', 'Unknown'),
                    "source_family": nodes_map.get(link['source'], {}).get('base_family', 'Unknown'),
                    "target_family": nodes_map.get(link['target'], {}).get('base_family', 'Unknown'),
                    "similarity": link.get('similarity', 0)
                }
                for link in similarity_links
            ]
        }
        
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"Similarity data written to: {args.output}")


def analyze_variants(args):
    """
    Analyze a specific variant
    
    Args:
        args: Command-line arguments
    """
    # Create detection instance
    detection = AdvancedFamilyDetectionIntegration(
        families_dir=args.families_dir,
        yara_rules_dir=args.yara_rules_dir,
        clusters_dir=args.clusters_dir,
        auto_variant_detection=True
    )
    
    # Get variant information
    if args.variant_id:
        # Get variant by ID
        cluster_id = args.variant_id
        
        if not detection.variant_detector or cluster_id not in detection.variant_detector.clusters:
            print(f"Error: Variant with ID '{cluster_id}' not found")
            return
        
        cluster = detection.variant_detector.clusters[cluster_id]
        definition = detection.variant_detector.generate_variant_definition(cluster_id)
        
    elif args.variant_name:
        # Find variant by name
        families = detection.get_all_family_names()
        found = False
        
        for family in families:
            if family.get('is_variant', False) and family.get('name', '').lower() == args.variant_name.lower():
                found = True
                cluster_id = family.get('id')
                if not detection.variant_detector or cluster_id not in detection.variant_detector.clusters:
                    print(f"Error: Variant '{args.variant_name}' found but no cluster data available")
                    return
                
                cluster = detection.variant_detector.clusters[cluster_id]
                definition = detection.variant_detector.generate_variant_definition(cluster_id)
                break
        
        if not found:
            print(f"Error: Variant with name '{args.variant_name}' not found")
            return
    else:
        print("Error: Either --variant-id or --variant-name must be specified")
        return
    
    # Print variant information
    print(f"\n=== Variant Analysis: {cluster.variant_name} ===")
    print(f"Base family: {cluster.base_family}")
    print(f"Confidence score: {cluster.confidence_score:.2f}")
    print(f"Relationship to base family: {cluster.relationship_score:.2f}")
    print(f"Cohesion: {cluster.calculate_cohesion():.2f}")
    print(f"Number of samples: {len(cluster.samples)}")
    print(f"Created: {cluster.creation_date}")
    print(f"Last updated: {cluster.last_updated}")
    
    if cluster.distinctive_features:
        print("\nDistinctive Features:")
        for feature in cluster.distinctive_features:
            print(f"  - {feature.get('description', 'Unknown')}")
    
    # If definition includes detection signatures, print them
    if definition and 'detection_signatures' in definition:
        signatures = definition.get('detection_signatures', {})
        
        if 'yara_rules' in signatures and signatures['yara_rules']:
            print("\nYARA Rule:")
            rules = signatures['yara_rules']
            if isinstance(rules, list):
                # Print first few lines and last line of the rule
                max_lines = min(15, len(rules))
                for i in range(max_lines):
                    print(f"  {rules[i]}")
                if len(rules) > max_lines:
                    print(f"  ... ({len(rules) - max_lines} more lines)")
                    print(f"  {rules[-1]}")
            else:
                print(f"  {rules}")
    
    # Output to JSON if requested
    if args.output:
        # Prepare output data
        output_data = {
            "variant_id": cluster_id,
            "variant_name": cluster.variant_name,
            "base_family": cluster.base_family,
            "confidence_score": cluster.confidence_score,
            "relationship_score": cluster.relationship_score,
            "cohesion": cluster.calculate_cohesion(),
            "sample_count": len(cluster.samples),
            "creation_date": cluster.creation_date,
            "last_updated": cluster.last_updated,
            "distinctive_features": cluster.distinctive_features,
            "definition": definition
        }
        
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"\nVariant data written to: {args.output}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Ransomware Family Relationship Graph CLI")
    
    # Common arguments
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument('--families-dir', help='Directory containing family definitions')
    parent_parser.add_argument('--yara-rules-dir', help='Directory containing YARA rules')
    parent_parser.add_argument('--clusters-dir', help='Directory containing variant clusters')
    parent_parser.add_argument('--min-confidence', type=float, default=0.6, help='Minimum confidence threshold')
    
    # Subparsers
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Generate command
    generate_parser = subparsers.add_parser('generate', help='Generate relationship graph', parents=[parent_parser])
    generate_parser.add_argument('--output-dir', help='Directory for output files')
    generate_parser.add_argument('--output-file', help='Output file path')
    generate_parser.add_argument('--format', choices=['html', 'json'], default='html', help='Output format')
    generate_parser.add_argument('--open-browser', action='store_true', help='Open HTML file in browser')
    generate_parser.set_defaults(func=generate_graph)
    
    # List families command
    list_parser = subparsers.add_parser('list', help='List available families and variants', parents=[parent_parser])
    list_parser.add_argument('--show-variants', action='store_true', help='Show variants for each family')
    list_parser.set_defaults(func=show_families)
    
    # Analyze similarities command
    similarities_parser = subparsers.add_parser('similarities', help='Analyze similarities between variants', parents=[parent_parser])
    similarities_parser.add_argument('--limit', type=int, default=10, help='Maximum number of similarities to show')
    similarities_parser.add_argument('--output', help='Output file for JSON data')
    similarities_parser.set_defaults(func=analyze_similarities)
    
    # Analyze variant command
    variant_parser = subparsers.add_parser('variant', help='Analyze a specific variant', parents=[parent_parser])
    variant_group = variant_parser.add_mutually_exclusive_group(required=True)
    variant_group.add_argument('--variant-id', help='Variant cluster ID')
    variant_group.add_argument('--variant-name', help='Variant name')
    variant_parser.add_argument('--output', help='Output file for JSON data')
    variant_parser.set_defaults(func=analyze_variants)
    
    # Parse arguments
    args = parser.parse_args()
    
    # Execute command
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()