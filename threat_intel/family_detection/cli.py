#!/usr/bin/env python3
"""
Enhanced Ransomware Family Detection CLI

Command-line interface for the enhanced ransomware family detector.
"""

import os
import sys
import json
import argparse
import logging
import datetime
from typing import Dict, List, Any, Optional

from .enhanced_family_detector import EnhancedFamilyDetector
from .integration import get_family_detection_integration

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('family_detection_cli')

def identify_family(args):
    """
    Identify ransomware family for a sample
    
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
    
    # Get detector instance
    detector = EnhancedFamilyDetector(
        families_dir=args.families_dir,
        yara_rules_dir=args.yara_rules_dir
    )
    
    # Identify family
    results = detector.identify_family(sample_data, min_score=args.min_score)
    
    # Add timestamp
    output = {
        "timestamp": datetime.datetime.now().isoformat(),
        "sample": args.sample,
        "results": results
    }
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=4)
    else:
        print(json.dumps(output, indent=4))
    
    # Print summary
    print(f"\nIdentified {len(results)} potential families")
    for i, result in enumerate(results):
        print(f"{i+1}. {result['family_name']} - Confidence: {result['confidence']:.2f}")
        if "variant" in result:
            print(f"   Variant: {result['variant']['name']} (Confidence: {result['variant']['confidence']:.2f})")
            print(f"   Indicator: {result['variant']['indicator']}")
        
        # Print top features if detailed output requested
        if args.detailed and "feature_scores" in result:
            print(f"   Top features:")
            sorted_features = sorted(
                result["feature_scores"].items(), 
                key=lambda x: x[1], 
                reverse=True
            )
            for feature, score in sorted_features[:3]:
                print(f"     * {feature}: {score:.2f}")

def list_families(args):
    """
    List known ransomware families
    
    Args:
        args: Command-line arguments
    """
    # Get detector instance
    detector = EnhancedFamilyDetector(
        families_dir=args.families_dir,
        yara_rules_dir=args.yara_rules_dir
    )
    
    # Get families
    families = []
    for family_id, family_data in detector.families.items():
        if args.active and not family_data.get('active', False):
            continue
            
        family_info = {
            "id": family_id,
            "name": family_data.get('name', family_id),
            "aliases": family_data.get('aliases', []),
            "active": family_data.get('active', False),
            "first_seen": family_data.get('first_seen', 'unknown')
        }
        
        # Add variants if requested
        if args.show_variants:
            family_info["variants"] = []
            for alias in family_data.get('aliases', []):
                if alias.lower() != family_data.get('name', '').lower():
                    family_info["variants"].append(alias)
        
        families.append(family_info)
    
    # Sort by name or date
    if args.sort_by == 'date':
        # Convert date strings to comparable format
        def parse_date(date_str):
            try:
                if '-' in date_str:
                    return datetime.datetime.strptime(date_str, '%Y-%m')
                return datetime.datetime.strptime('1900-01', '%Y-%m')
            except:
                return datetime.datetime.strptime('1900-01', '%Y-%m')
        
        families.sort(key=lambda x: parse_date(x["first_seen"]), reverse=True)
    else:
        families.sort(key=lambda x: x["name"])
    
    # Print families
    if args.output:
        output = {
            "timestamp": datetime.datetime.now().isoformat(),
            "total": len(families),
            "families": families
        }
        
        with open(args.output, 'w') as f:
            json.dump(output, f, indent=4)
    
    print(f"Found {len(families)} families:")
    for i, family in enumerate(families):
        status = "Active" if family["active"] else "Inactive"
        print(f"{i+1}. {family['name']} ({family['id']}) - {status}, First seen: {family['first_seen']}")
        
        if args.detailed:
            description = detector.families[family['id']].get('description', '')
            if description:
                print(f"   Description: {description[:100]}..." if len(description) > 100 else f"   Description: {description}")
            
            technical = detector.families[family['id']].get('technical_details', {})
            encryption = technical.get('encryption', {})
            if encryption:
                algorithm = encryption.get('algorithm', 'Unknown')
                print(f"   Encryption: {algorithm}")
            
            extensions = technical.get('extension', [])
            if extensions:
                print(f"   Extensions: {', '.join(extensions[:5])}" + (" [...]" if len(extensions) > 5 else ""))
        
        if args.show_variants and family.get("variants"):
            print(f"   Variants: {', '.join(family['variants'])}")

def add_family(args):
    """
    Add a new family definition
    
    Args:
        args: Command-line arguments
    """
    # Get integration instance
    integration = get_family_detection_integration(
        families_dir=args.families_dir,
        yara_rules_dir=args.yara_rules_dir
    )
    
    # Load family data
    try:
        with open(args.file, 'r') as f:
            family_data = json.load(f)
    except Exception as e:
        logger.error(f"Error loading family data: {e}")
        sys.exit(1)
    
    # Validate family data
    required_fields = ['name', 'description', 'technical_details']
    for field in required_fields:
        if field not in family_data:
            logger.error(f"Missing required field: {field}")
            sys.exit(1)
    
    # Add family
    if integration.add_family_definition(family_data):
        print(f"Added family: {family_data.get('name')}")
    else:
        logger.error("Failed to add family")
        sys.exit(1)

def update_family(args):
    """
    Update an existing family definition
    
    Args:
        args: Command-line arguments
    """
    # Get integration instance
    integration = get_family_detection_integration(
        families_dir=args.families_dir,
        yara_rules_dir=args.yara_rules_dir
    )
    
    # Load update data
    try:
        with open(args.file, 'r') as f:
            updates = json.load(f)
    except Exception as e:
        logger.error(f"Error loading update data: {e}")
        sys.exit(1)
    
    # Update family
    if integration.update_family_definition(args.id, updates):
        print(f"Updated family: {args.id}")
    else:
        logger.error(f"Failed to update family: {args.id}")
        sys.exit(1)

def extract_features(args):
    """
    Extract features from a sample
    
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
    
    # Get integration instance
    integration = get_family_detection_integration(
        families_dir=args.families_dir,
        yara_rules_dir=args.yara_rules_dir
    )
    
    # Extract features
    features = integration.extract_sample_features(sample_data)
    
    # Output features
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(features, f, indent=4)
    else:
        print(json.dumps(features, indent=4))
    
    # Print summary
    print(f"\nExtracted features from {args.sample}:")
    for feature_name, feature_data in features.items():
        if isinstance(feature_data, dict):
            print(f"* {feature_name}: {len(feature_data)} properties")
        elif isinstance(feature_data, list):
            print(f"* {feature_name}: {len(feature_data)} items")
        else:
            print(f"* {feature_name}")

def compare_families(args):
    """
    Compare two ransomware families
    
    Args:
        args: Command-line arguments
    """
    # Get detector instance
    detector = EnhancedFamilyDetector(
        families_dir=args.families_dir,
        yara_rules_dir=args.yara_rules_dir
    )
    
    # Normalize family names
    family1 = detector.normalize_family_name(args.family1)
    family2 = detector.normalize_family_name(args.family2)
    
    # Get family data
    family1_data = detector.families.get(family1)
    family2_data = detector.families.get(family2)
    
    if not family1_data:
        logger.error(f"Family not found: {args.family1}")
        sys.exit(1)
    
    if not family2_data:
        logger.error(f"Family not found: {args.family2}")
        sys.exit(1)
    
    # Extract features
    family1_features = detector.extract_family_features(family1)
    family2_features = detector.extract_family_features(family2)
    
    # Compare features
    similarity_scores = {}
    for feature in detector.features:
        if feature.name in family1_features and feature.name in family2_features:
            try:
                score = feature.compare(family1_features[feature.name], family2_features[feature.name])
                similarity_scores[feature.name] = score
            except Exception as e:
                logger.error(f"Error comparing feature {feature.name}: {e}")
                similarity_scores[feature.name] = 0.0
    
    # Calculate overall similarity
    total_weight = sum(feature.weight for feature in detector.features if feature.name in similarity_scores)
    weighted_similarity = sum(score * next(f.weight for f in detector.features if f.name == name) 
                             for name, score in similarity_scores.items())
    
    overall_similarity = weighted_similarity / total_weight if total_weight > 0 else 0.0
    
    # Prepare result
    result = {
        "family1": {
            "id": family1,
            "name": family1_data.get('name', family1),
            "active": family1_data.get('active', False),
            "first_seen": family1_data.get('first_seen', 'unknown')
        },
        "family2": {
            "id": family2,
            "name": family2_data.get('name', family2),
            "active": family2_data.get('active', False),
            "first_seen": family2_data.get('first_seen', 'unknown')
        },
        "feature_similarities": similarity_scores,
        "overall_similarity": overall_similarity
    }
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=4)
    else:
        print(json.dumps(result, indent=4))
    
    # Print summary
    print(f"\nComparison of {family1_data.get('name', family1)} and {family2_data.get('name', family2)}:")
    print(f"Overall similarity: {overall_similarity:.2f} (0.0 to 1.0)")
    print("\nFeature similarities:")
    for feature, score in sorted(similarity_scores.items(), key=lambda x: x[1], reverse=True):
        print(f"* {feature}: {score:.2f}")
    
    # Interpretation
    if overall_similarity > 0.8:
        print("\nInterpretation: These families are very similar and may be related or derived from each other.")
    elif overall_similarity > 0.6:
        print("\nInterpretation: These families show significant similarities but also notable differences.")
    elif overall_similarity > 0.4:
        print("\nInterpretation: These families share some common characteristics but have distinct implementations.")
    else:
        print("\nInterpretation: These families are significantly different from each other.")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Enhanced Ransomware Family Detection CLI')
    parser.add_argument('--families-dir', help='Directory containing family definitions')
    parser.add_argument('--yara-rules-dir', help='Directory containing YARA rules')
    
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Identify command
    identify_parser = subparsers.add_parser('identify', help='Identify ransomware family')
    identify_parser.add_argument('--sample', required=True, help='Path to sample analysis JSON file')
    identify_parser.add_argument('--min-score', type=float, default=0.5, help='Minimum score threshold')
    identify_parser.add_argument('--output', help='Output file for results')
    identify_parser.add_argument('--detailed', action='store_true', help='Show detailed results')
    identify_parser.set_defaults(func=identify_family)
    
    # List families command
    list_parser = subparsers.add_parser('list', help='List known families')
    list_parser.add_argument('--active', action='store_true', help='Show only active families')
    list_parser.add_argument('--detailed', action='store_true', help='Show detailed family information')
    list_parser.add_argument('--show-variants', action='store_true', help='Show family variants')
    list_parser.add_argument('--sort-by', choices=['name', 'date'], default='name', 
                           help='Sort families by name or first seen date')
    list_parser.add_argument('--output', help='Output file for results')
    list_parser.set_defaults(func=list_families)
    
    # Add family command
    add_parser = subparsers.add_parser('add', help='Add a new family definition')
    add_parser.add_argument('--file', required=True, help='Path to family definition JSON file')
    add_parser.set_defaults(func=add_family)
    
    # Update family command
    update_parser = subparsers.add_parser('update', help='Update a family definition')
    update_parser.add_argument('--id', required=True, help='Family ID to update')
    update_parser.add_argument('--file', required=True, help='Path to updated family definition JSON file')
    update_parser.set_defaults(func=update_family)
    
    # Extract features command
    extract_parser = subparsers.add_parser('extract', help='Extract features from a sample')
    extract_parser.add_argument('--sample', required=True, help='Path to sample analysis JSON file')
    extract_parser.add_argument('--output', help='Output file for results')
    extract_parser.set_defaults(func=extract_features)
    
    # Compare families command
    compare_parser = subparsers.add_parser('compare', help='Compare two ransomware families')
    compare_parser.add_argument('--family1', required=True, help='First family name or ID')
    compare_parser.add_argument('--family2', required=True, help='Second family name or ID')
    compare_parser.add_argument('--output', help='Output file for results')
    compare_parser.set_defaults(func=compare_families)
    
    # Parse arguments
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        sys.exit(1)
    
    # Execute command
    args.func(args)

if __name__ == '__main__':
    main()