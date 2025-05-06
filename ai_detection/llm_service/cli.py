#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LLM Service CLI Tool

A command-line tool for managing and using the Innora-Defender LLM service.
This tool allows for direct interaction with LLM providers, analysis of
ransomware samples, and management of LLM service configuration.
"""

import os
import sys
import json
import time
import logging
import argparse
from typing import Dict, List, Any, Optional

from ai_detection.llm_service.llm_provider_manager import llm_provider_manager
from ai_detection.llm_service.ransomware_analyzer import RansomwareAnalyzer
from ai_detection.llm_service.config import load_config, save_user_config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Innora-Defender LLM Service CLI")
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze ransomware sample")
    analyze_parser.add_argument("--sample", type=str, required=True, help="Path to sample file")
    analyze_parser.add_argument("--output", type=str, help="Path to save analysis results")
    analyze_parser.add_argument("--feature", type=str, default="F3", help="Feature ID for routing (default: F3)")
    analyze_parser.add_argument("--force-refresh", action="store_true", help="Force refresh analysis")
    
    # batch command
    batch_parser = subparsers.add_parser("batch", help="Batch analyze multiple samples")
    batch_parser.add_argument("--input", type=str, required=True, help="Path to batch JSON file")
    batch_parser.add_argument("--output", type=str, help="Path to save analysis results")
    batch_parser.add_argument("--feature", type=str, default="F3", help="Feature ID for routing (default: F3)")
    batch_parser.add_argument("--force-refresh", action="store_true", help="Force refresh analysis")
    
    # chat command
    chat_parser = subparsers.add_parser("chat", help="Chat with LLM")
    chat_parser.add_argument("--feature", type=str, default="F4", help="Feature ID for routing (default: F4)")
    chat_parser.add_argument("--provider", type=str, help="Override provider")
    chat_parser.add_argument("--system", type=str, help="System prompt")
    
    # status command
    status_parser = subparsers.add_parser("status", help="Show LLM service status")
    status_parser.add_argument("--verbose", action="store_true", help="Show detailed status")
    
    # costs command
    costs_parser = subparsers.add_parser("costs", help="Show LLM service costs")
    
    # providers command
    providers_parser = subparsers.add_parser("providers", help="Show available LLM providers")
    
    # config command
    config_parser = subparsers.add_parser("config", help="Manage LLM service configuration")
    config_parser.add_argument("--show", action="store_true", help="Show current configuration")
    config_parser.add_argument("--save", action="store_true", help="Save current configuration")
    config_parser.add_argument("--reset", action="store_true", help="Reset to default configuration")
    config_parser.add_argument("--set", type=str, help="Set configuration key (format: key=value)")
    
    # parse args
    return parser.parse_args()

def format_json(data: Any) -> str:
    """Format JSON data for display."""
    return json.dumps(data, indent=2, sort_keys=True)

def analyze_command(args):
    """Execute analyze command."""
    sample_path = args.sample
    if not os.path.exists(sample_path):
        print(f"Error: Sample file not found: {sample_path}")
        return 1
    
    # Create analyzer
    analyzer = RansomwareAnalyzer()
    
    # Load or generate sample data
    print(f"Analyzing sample: {sample_path}")
    
    # Check if there's a JSON metadata file
    metadata_path = os.path.splitext(sample_path)[0] + ".json"
    if os.path.exists(metadata_path):
        with open(metadata_path, 'r') as f:
            sample_data = json.load(f)
        print(f"Using metadata from: {metadata_path}")
    else:
        print("No metadata file found, generating basic data")
        # Generate basic data
        import hashlib
        with open(sample_path, 'rb') as f:
            file_data = f.read()
            file_hash = hashlib.sha256(file_data).hexdigest()
            file_size = len(file_data)
        
        sample_data = {
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
    
    # Display results
    print("\n===== Analysis Results =====")
    print(f"First-stage family: {result['first_stage_family']} ({result['first_stage_confidence']:.2f})")
    print(f"LLM family: {result['llm_family']}")
    print(f"LLM variant: {result['llm_variant']}")
    print(f"Processing time: {result['processing_time']:.2f}s")
    
    # Print potential weaknesses if available
    if "potential_weaknesses" in result and result["potential_weaknesses"]:
        print("\nPotential weaknesses:")
        for weakness in result["potential_weaknesses"][:3]:  # Show top 3
            print(f"  - {weakness}")
    
    # Print recovery recommendations if available
    if "recovery_recommendations" in result and result["recovery_recommendations"]:
        print("\nRecovery recommendations:")
        for recommendation in result["recovery_recommendations"][:3]:  # Show top 3
            print(f"  - {recommendation}")
    
    # Print analysis excerpt
    if "analysis_text" in result:
        print("\nAnalysis excerpt:")
        # Show first 200 characters
        excerpt = result["analysis_text"][:200].replace("\n", " ")
        print(f"  {excerpt}...")
    
    # Save output if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"\nFull analysis saved to {args.output}")
    
    return 0

def batch_command(args):
    """Execute batch command."""
    batch_path = args.input
    if not os.path.exists(batch_path):
        print(f"Error: Batch file not found: {batch_path}")
        return 1
    
    # Load batch data
    with open(batch_path, 'r') as f:
        batch_data = json.load(f)
    
    # Create analyzer
    analyzer = RansomwareAnalyzer()
    
    # Prepare sample data
    sample_paths = []
    upstream_results_list = []
    technical_details_list = []
    
    for sample in batch_data:
        sample_path = sample.get("sample_path")
        if not sample_path or not os.path.exists(sample_path):
            print(f"Warning: Sample file not found: {sample_path}")
            continue
        
        sample_paths.append(sample_path)
        upstream_results_list.append(sample)
        technical_details_list.append(sample.get("technical_details"))
    
    # Run batch analysis
    print(f"Analyzing {len(sample_paths)} samples...")
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
    
    # Display results
    print(f"\n===== Batch Analysis Results ({len(results)} samples) =====")
    print(f"Total processing time: {total_time:.2f}s")
    print(f"Average time per sample: {total_time / len(results):.2f}s")
    
    # Show summary of results
    print("\nResults summary:")
    for result in results:
        if "error" in result:
            print(f"  {result.get('sample_name', 'Unknown')}: Error - {result['error']}")
        else:
            print(f"  {result['sample_name']}: {result['llm_family']} ({result['llm_variant']})")
    
    # Save output if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nFull analysis saved to {args.output}")
    
    return 0

def chat_command(args):
    """Execute chat command."""
    print("Starting chat session with LLM...")
    print("Type 'exit' or 'quit' to end the session.")
    
    # Prepare system prompt
    system_prompt = args.system or "You are a cybersecurity expert specializing in ransomware analysis."
    
    # Setup message history
    history = [{"role": "system", "content": system_prompt}]
    
    # Chat loop
    try:
        while True:
            # Get user input
            user_input = input("\nYou: ")
            
            # Check for exit command
            if user_input.lower() in ["exit", "quit"]:
                print("Ending chat session.")
                break
            
            # Add user message to history
            history.append({"role": "user", "content": user_input})
            
            # Call LLM
            if args.provider:
                response = llm_provider_manager.call(
                    messages=history,
                    provider_override=args.provider
                )
            else:
                response = llm_provider_manager.call_feature(
                    feature_id=args.feature,
                    messages=history
                )
            
            # Add assistant response to history
            history.append({"role": "assistant", "content": response})
            
            # Display response
            print(f"\nAssistant: {response}")
    
    except KeyboardInterrupt:
        print("\nChat session interrupted.")
    
    return 0

def status_command(args):
    """Execute status command."""
    stats = llm_provider_manager.get_stats()
    
    print("\n===== LLM Service Status =====")
    
    total_calls = sum(stats['calls'].values())
    total_tokens = sum(stats['tokens'].values())
    total_costs = sum(stats['costs'].values())
    
    print(f"Total API calls: {total_calls}")
    print(f"Total tokens used: {total_tokens}")
    print(f"Total estimated cost: ${total_costs:.6f}")
    
    # Calculate overall success rate
    total_failures = sum(stats['failures'].values())
    if total_calls > 0:
        success_rate = (total_calls - total_failures) / total_calls * 100
        print(f"Overall success rate: {success_rate:.1f}%")
    
    # Provider health
    print("\nProvider health:")
    for provider, health in stats['provider_health'].items():
        status = "✅ Healthy" if health else "❌ Unhealthy"
        print(f"  {provider}: {status}")
    
    # Detailed stats if requested
    if args.verbose:
        print("\nCalls by provider:")
        for provider, calls in stats['calls'].items():
            if calls > 0:
                success_rate = stats['success_rate'].get(provider, 0)
                avg_latency = stats['avg_latency'].get(provider, 0)
                print(f"  {provider}: {calls} calls, {success_rate:.1f}% success rate, {avg_latency:.2f}s avg latency")
        
        print("\nFeature calls:")
        for feature, calls in stats['feature_calls'].items():
            if calls > 0:
                print(f"  {feature}: {calls} calls")
    
    return 0

def costs_command(args):
    """Execute costs command."""
    providers_info = llm_provider_manager.get_providers_info()
    stats = llm_provider_manager.get_stats()
    
    print("\n===== LLM Service Costs =====")
    
    total_cost = sum(provider["estimated_cost"] for provider in providers_info)
    print(f"Total estimated cost: ${total_cost:.6f}")
    
    print("\nCost breakdown by provider:")
    for provider in providers_info:
        if provider["calls"] > 0:
            cost_percentage = (provider["estimated_cost"] / total_cost * 100) if total_cost > 0 else 0
            print(f"  {provider['name']} ({provider['model']}): ${provider['estimated_cost']:.6f} "
                 f"({cost_percentage:.1f}% of total)")
    
    print("\nToken usage by provider:")
    for provider in providers_info:
        if provider["tokens_used"] > 0:
            tokens_percentage = (provider["tokens_used"] / sum(p["tokens_used"] for p in providers_info) * 100) if sum(p["tokens_used"] for p in providers_info) > 0 else 0
            print(f"  {provider['name']}: {provider['tokens_used']} tokens ({tokens_percentage:.1f}% of total)")
    
    print("\nCost efficiency summary:")
    for provider in providers_info:
        if provider["tokens_used"] > 0:
            efficiency = provider["estimated_cost"] / (provider["tokens_used"] / 1000)
            print(f"  {provider['name']}: ${efficiency:.6f} per 1K tokens")
    
    # Calculate potential savings from using vLLM
    vllm_provider = next((p for p in providers_info if p["name"] == "vllm"), None)
    anthropic_provider = next((p for p in providers_info if p["name"] == "anthropic"), None)
    
    if vllm_provider and anthropic_provider and vllm_provider["tokens_used"] > 0:
        vllm_cost = vllm_provider["estimated_cost"]
        vllm_tokens = vllm_provider["tokens_used"]
        
        # Calculate what it would have cost with Claude
        equivalent_claude_cost = (vllm_tokens / 1000) * anthropic_provider["cost_per_1k_tokens"]
        savings = equivalent_claude_cost - vllm_cost
        savings_percentage = (savings / equivalent_claude_cost * 100) if equivalent_claude_cost > 0 else 0
        
        print(f"\nCost savings from using vLLM vs Claude: ${savings:.6f} ({savings_percentage:.1f}%)")
        print(f"  vLLM cost for {vllm_tokens} tokens: ${vllm_cost:.6f}")
        print(f"  Equivalent Claude cost: ${equivalent_claude_cost:.6f}")
    
    return 0

def providers_command(args):
    """Execute providers command."""
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
        
        # Show usage stats
        if provider["calls"] > 0:
            print(f"  Usage: {provider['calls']} calls, {provider['tokens_used']} tokens")
            print(f"  Estimated cost to date: ${provider['estimated_cost']:.6f}")
    
    print("\n===== Feature Routing Configuration =====")
    print("The following shows how different task types are routed to LLM providers:")
    
    for feature_id, mapping in feature_mapping.items():
        print(f"\n{feature_id}: {mapping['description']}")
        print(f"  Primary provider: {mapping['primary']}")
        print(f"  Fallback providers: {', '.join(mapping['fallbacks'])}")
        
        # Show usage if available
        feature_calls = llm_provider_manager.get_stats()['feature_calls'].get(feature_id, 0)
        if feature_calls > 0:
            print(f"  Usage: {feature_calls} calls")
    
    return 0

def config_command(args):
    """Execute config command."""
    # Load current config
    config = load_config()
    
    # Show config
    if args.show:
        print("\n===== LLM Service Configuration =====")
        print(format_json(config))
    
    # Set config key
    if args.set:
        if "=" not in args.set:
            print(f"Error: Invalid format. Use --set key=value")
            return 1
        
        key, value = args.set.split("=", 1)
        
        # Try to convert value to appropriate type
        try:
            # Try as JSON first
            value = json.loads(value)
        except json.JSONDecodeError:
            # If not JSON, try as number
            try:
                value = int(value)
            except ValueError:
                try:
                    value = float(value)
                except ValueError:
                    # Keep as string if not a number
                    pass
        
        # Set the key
        if "." in key:
            # Handle nested keys
            keys = key.split(".")
            target = config
            for k in keys[:-1]:
                if k not in target:
                    target[k] = {}
                target = target[k]
            target[keys[-1]] = value
        else:
            config[key] = value
        
        print(f"Set {key} = {value}")
    
    # Save config
    if args.save:
        save_user_config(config)
    
    # Reset config
    if args.reset:
        if os.path.exists(USER_CONFIG_PATH):
            os.remove(USER_CONFIG_PATH)
            print(f"Reset configuration to defaults")
        else:
            print(f"No user configuration found")
    
    return 0

def main():
    """Main function."""
    args = parse_args()
    
    # Execute command
    if args.command == "analyze":
        return analyze_command(args)
    elif args.command == "batch":
        return batch_command(args)
    elif args.command == "chat":
        return chat_command(args)
    elif args.command == "status":
        return status_command(args)
    elif args.command == "costs":
        return costs_command(args)
    elif args.command == "providers":
        return providers_command(args)
    elif args.command == "config":
        return config_command(args)
    else:
        print("No command specified. Use --help for available commands.")
        return 1

if __name__ == "__main__":
    sys.exit(main())