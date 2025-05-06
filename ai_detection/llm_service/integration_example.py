#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LLM Service Integration Example

This script demonstrates how to use the cost-optimized LLM service 
with the ransomware analyzer in the Innora-Defender project.
"""

import os
import sys
import json
import time
import logging
import argparse
from typing import Dict, Any, List, Optional

from ai_detection.llm_service.llm_provider_manager import llm_provider_manager
from ai_detection.llm_service.ransomware_analyzer import RansomwareAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Ransomware LLM Analyzer CLI")
    parser.add_argument("--sample", type=str, help="Path to the ransomware sample")
    parser.add_argument("--batch", type=str, help="Path to JSON file containing batch of samples")
    parser.add_argument("--output", type=str, help="Path to save output JSON results")
    parser.add_argument("--force-refresh", action="store_true", help="Force refresh analysis")
    parser.add_argument("--feature", type=str, default="F3", help="Feature ID for LLM routing")
    parser.add_argument("--stats", action="store_true", help="Show LLM usage statistics")
    parser.add_argument("--cost", action="store_true", help="Show cost report")
    parser.add_argument("--providers", action="store_true", help="Show available LLM providers")
    parser.add_argument("--vllm-priority", action="store_true", default=True, 
                        help="Prioritize vLLM for cost optimization")
    return parser.parse_args()

def load_sample_data(sample_path: str) -> Dict[str, Any]:
    """
    Load or generate sample data for a ransomware sample.
    
    Args:
        sample_path: Path to the ransomware sample
        
    Returns:
        Dictionary with sample data
    """
    # Check if there's a JSON metadata file next to the sample
    metadata_path = os.path.splitext(sample_path)[0] + ".json"
    
    if os.path.exists(metadata_path):
        with open(metadata_path, 'r') as f:
            return json.load(f)
    
    # If no metadata, generate some basic data
    import hashlib
    
    try:
        with open(sample_path, 'rb') as f:
            file_data = f.read()
            file_hash = hashlib.sha256(file_data).hexdigest()
            file_size = len(file_data)
    except Exception as e:
        logger.error(f"Error reading sample file: {e}")
        file_hash = "unknown"
        file_size = 0
    
    # Default to unknown data
    return {
        "family": "unknown",
        "confidence": 0.3,
        "sample_hash": file_hash,
        "key_features": [
            "File encryption capability",
            "Registry modifications",
            "Suspicious API calls"
        ],
        "technical_details": {
            "static_analysis": {
                "sha256": file_hash,
                "file_size": file_size,
                "file_type": os.path.splitext(sample_path)[1][1:].upper()
            }
        }
    }

def analyze_single_sample(args) -> Dict[str, Any]:
    """
    Analyze a single ransomware sample.
    
    Args:
        args: Command line arguments
        
    Returns:
        Analysis results
    """
    sample_path = args.sample
    if not os.path.exists(sample_path):
        logger.error(f"Sample file not found: {sample_path}")
        return {"error": f"Sample file not found: {sample_path}"}
    
    # Load or generate sample data
    sample_data = load_sample_data(sample_path)
    
    # Create analyzer
    analyzer = RansomwareAnalyzer(
        use_vllm_priority=args.vllm_priority
    )
    
    # Run analysis
    start_time = time.time()
    result = analyzer.analyze(
        sample_path=sample_path,
        upstream_results=sample_data,
        technical_details=sample_data.get("technical_details"),
        force_refresh=args.force_refresh,
        feature_id=args.feature
    )
    
    # Add timing information
    result["processing_time"] = time.time() - start_time
    
    return result

def analyze_batch_samples(args) -> List[Dict[str, Any]]:
    """
    Analyze a batch of ransomware samples.
    
    Args:
        args: Command line arguments
        
    Returns:
        List of analysis results
    """
    batch_path = args.batch
    if not os.path.exists(batch_path):
        logger.error(f"Batch file not found: {batch_path}")
        return [{"error": f"Batch file not found: {batch_path}"}]
    
    # Load batch data
    with open(batch_path, 'r') as f:
        batch_data = json.load(f)
    
    # Create analyzer
    analyzer = RansomwareAnalyzer(
        use_vllm_priority=args.vllm_priority
    )
    
    # Prepare sample data
    sample_paths = []
    upstream_results_list = []
    technical_details_list = []
    
    for sample in batch_data:
        sample_path = sample.get("sample_path")
        if not sample_path or not os.path.exists(sample_path):
            logger.error(f"Sample file not found: {sample_path}")
            continue
        
        sample_paths.append(sample_path)
        upstream_results_list.append(sample)
        technical_details_list.append(sample.get("technical_details"))
    
    # Run batch analysis
    start_time = time.time()
    results = analyzer.batch_analyze(
        sample_paths=sample_paths,
        upstream_results_list=upstream_results_list,
        technical_details_list=technical_details_list,
        force_refresh=args.force_refresh,
        feature_id=args.feature
    )
    
    # Add timing information
    total_time = time.time() - start_time
    for result in results:
        result["batch_processing_time"] = total_time
    
    return results

def show_llm_stats():
    """Display LLM usage statistics."""
    stats = llm_provider_manager.get_stats()
    
    print("\n===== LLM Usage Statistics =====")
    print(f"Total API calls: {sum(stats['calls'].values())}")
    
    print("\nCalls by provider:")
    for provider, calls in stats['calls'].items():
        success_rate = stats['success_rate'].get(provider, 0)
        print(f"  {provider}: {calls} calls ({success_rate:.1f}% success rate)")
    
    print("\nTokens by provider:")
    for provider, tokens in stats['tokens'].items():
        if tokens > 0:
            print(f"  {provider}: {tokens} tokens")
    
    print("\nCosts by provider:")
    for provider, cost in stats['costs'].items():
        if cost > 0:
            print(f"  {provider}: ${cost:.4f}")
    
    print("\nFeature calls:")
    for feature, calls in stats['feature_calls'].items():
        if calls > 0:
            print(f"  {feature}: {calls} calls")
    
    print("\nProvider health:")
    for provider, health in stats['provider_health'].items():
        status = "Healthy" if health else "Unhealthy"
        print(f"  {provider}: {status}")

def show_cost_report():
    """Display cost report."""
    providers_info = llm_provider_manager.get_providers_info()
    
    print("\n===== LLM Cost Report =====")
    
    total_cost = sum(provider["estimated_cost"] for provider in providers_info)
    print(f"Total estimated cost: ${total_cost:.6f}")
    
    print("\nCost breakdown by provider:")
    for provider in providers_info:
        if provider["calls"] > 0:
            print(f"  {provider['name']} ({provider['model']}): ${provider['estimated_cost']:.6f} "
                 f"({provider['tokens_used']} tokens, {provider['calls']} calls)")
    
    print("\nAverage cost per call:")
    for provider in providers_info:
        if provider["calls"] > 0:
            avg_cost = provider["estimated_cost"] / provider["calls"]
            print(f"  {provider['name']}: ${avg_cost:.6f} per call")
    
    print("\nCost efficiency:")
    for provider in providers_info:
        if provider["tokens_used"] > 0:
            efficiency = provider["estimated_cost"] / (provider["tokens_used"] / 1000)
            print(f"  {provider['name']}: ${efficiency:.6f} per 1K tokens")

def show_providers_info():
    """Display information about available LLM providers."""
    providers_info = llm_provider_manager.get_providers_info()
    feature_mapping = llm_provider_manager.get_feature_mapping()
    
    print("\n===== Available LLM Providers =====")
    for provider in providers_info:
        status = "✅ Healthy" if provider["healthy"] else "❌ Unhealthy"
        print(f"\n{provider['name']} ({provider['tier']} tier)")
        print(f"  Model: {provider['model']}")
        print(f"  Status: {status}")
        print(f"  Cost: ${provider['cost_per_1k_tokens']:.6f} per 1K tokens")
        print(f"  Priority: {provider['priority']}")
    
    print("\n===== Feature Routing Configuration =====")
    for feature_id, mapping in feature_mapping.items():
        print(f"{feature_id}: {mapping['description']}")
        print(f"  Primary: {mapping['primary']}")
        print(f"  Fallbacks: {', '.join(mapping['fallbacks'])}")

def main():
    """Main function."""
    args = parse_arguments()
    
    # Show statistics or information if requested
    if args.stats:
        show_llm_stats()
        return
    
    if args.cost:
        show_cost_report()
        return
    
    if args.providers:
        show_providers_info()
        return
    
    # Analyze sample(s)
    if args.sample:
        result = analyze_single_sample(args)
        
        # Print summary
        print(f"\nAnalysis of {os.path.basename(args.sample)}:")
        print(f"First-stage family: {result['first_stage_family']} ({result['first_stage_confidence']:.2f})")
        print(f"LLM family: {result['llm_family']}")
        print(f"LLM variant: {result['llm_variant']}")
        
        # Print analysis excerpt
        if 'analysis_text' in result:
            analysis_text = result['analysis_text']
            # Print first 5 lines
            lines = analysis_text.split('\n')
            print("\nAnalysis excerpt:")
            for line in lines[:5]:
                if line.strip():
                    print(f"  {line}")
            print("  ...")
        
        # Save output if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"\nFull analysis saved to {args.output}")
        
    elif args.batch:
        results = analyze_batch_samples(args)
        
        # Print summary
        print(f"\nAnalyzed {len(results)} samples:")
        
        for result in results:
            if 'error' in result:
                print(f"  Error: {result['error']}")
                continue
                
            print(f"  {result['sample_name']}: {result['llm_family']} ({result['llm_variant']})")
        
        # Save output if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nFull analysis saved to {args.output}")
    
    else:
        print("No sample or batch specified. Use --sample or --batch to specify input.")
        print("Use --help for more information.")

if __name__ == "__main__":
    main()