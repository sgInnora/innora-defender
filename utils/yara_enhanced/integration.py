#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced YARA Rule Generator Integration Module

This module provides integration between the enhanced YARA rule generator and the 
existing threat intelligence infrastructure. It allows the enhanced generator to
be used as a drop-in replacement for the existing YARA generators.
"""

import os
import sys
import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

# Add parent directory to path to allow importing relative modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(current_dir))
sys.path.insert(0, parent_dir)

# Import enhanced generator
from utils.yara_enhanced.enhanced_yara_generator import EnhancedYaraGenerator

# Try to import threat intelligence modules
try:
    from threat_intel.rules.yara_generator import YaraRuleGenerator
    from threat_intel.ioc_utils.ioc_extractor import IOCExtractor
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    THREAT_INTEL_AVAILABLE = False
    print("Warning: Threat intelligence modules not available")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('yara_integration')

class EnhancedYaraIntegration:
    """
    Integrates the enhanced YARA rule generator with the existing infrastructure
    """
    
    def __init__(self, output_dir: Optional[str] = None, 
                benign_samples_dir: Optional[str] = None,
                fallback_to_legacy: bool = True):
        """
        Initialize the integration
        
        Args:
            output_dir: Directory for generated rules
            benign_samples_dir: Directory containing benign samples for testing
            fallback_to_legacy: Whether to fall back to legacy generators if needed
        """
        # Set output directory
        self.output_dir = output_dir or os.path.join(
            os.path.dirname(__file__), 'output'
        )
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Set benign samples directory
        self.benign_samples_dir = benign_samples_dir
        
        # Create enhanced generator
        self.enhanced_generator = EnhancedYaraGenerator(
            output_dir=os.path.join(self.output_dir, 'enhanced'),
            legacy_mode=fallback_to_legacy,
            benign_samples_dir=benign_samples_dir
        )
        
        # Create legacy generator if available and fallback is enabled
        self.legacy_generator = None
        if THREAT_INTEL_AVAILABLE and fallback_to_legacy:
            self.legacy_generator = YaraRuleGenerator(
                rules_dir=os.path.join(self.output_dir, 'legacy')
            )
        
        logger.info("Enhanced YARA integration initialized")
    
    def generate_yara_rule(self, sample_data: Dict, correlation_result: Dict = None) -> str:
        """
        Generate a YARA rule from sample analysis data
        
        This method provides the same interface as the legacy YaraRuleGenerator
        for compatibility with existing code.
        
        Args:
            sample_data: Sample analysis data
            correlation_result: Optional correlation results
            
        Returns:
            Path to the generated YARA rule file
        """
        logger.info("Generating YARA rule using enhanced generator")
        
        try:
            # Extract file path if available
            file_path = None
            if 'file_path' in sample_data:
                file_path = sample_data['file_path']
            
            # Extract family information
            family = "unknown"
            if correlation_result and "identified_families" in correlation_result and correlation_result["identified_families"]:
                family = correlation_result["identified_families"][0]["name"]
            
            # If we have a file path, use it
            if file_path and os.path.exists(file_path):
                # Analyze the sample
                result = self.enhanced_generator.analyze_sample(
                    file_path=file_path,
                    family=family,
                    analysis_data=sample_data.get('analysis'),
                    generate_rule=True
                )
                
                if 'rule_path' in result:
                    return result['rule_path']
            
            # If we don't have a file path or the file doesn't exist, fall back to legacy generator
            if self.legacy_generator:
                logger.info("Falling back to legacy generator")
                return self.legacy_generator.generate_yara_rule(sample_data, correlation_result)
            else:
                logger.error("No file path available and no legacy generator to fall back to")
                return None
            
        except Exception as e:
            logger.error(f"Error generating YARA rule: {e}")
            
            # Fall back to legacy generator if available
            if self.legacy_generator:
                logger.info("Falling back to legacy generator due to error")
                return self.legacy_generator.generate_yara_rule(sample_data, correlation_result)
            
            raise
    
    def generate_family_rule(self, samples: List[Dict]) -> str:
        """
        Generate a YARA rule for a family based on multiple samples
        
        This method provides the same interface as the legacy YaraRuleGenerator
        for compatibility with existing code.
        
        Args:
            samples: List of sample correlation results
            
        Returns:
            Path to the generated YARA rule file
        """
        if not samples or len(samples) < 2:
            logger.warning("At least 2 samples are required to generate a family rule")
            return None
        
        logger.info(f"Generating family rule for {len(samples)} samples")
        
        try:
            # Extract family information
            family_counts = {}
            for sample in samples:
                if "identified_families" in sample and sample["identified_families"]:
                    family = sample["identified_families"][0]["name"]
                    family_counts[family] = family_counts.get(family, 0) + 1
            
            if not family_counts:
                logger.warning("No family information found in samples")
                if self.legacy_generator:
                    logger.info("Falling back to legacy generator")
                    return self.legacy_generator.generate_family_rule(samples)
                return None
            
            # Get most common family
            family_name = max(family_counts.items(), key=lambda x: x[1])[0]
            
            # Process each sample with the enhanced generator
            for sample in samples:
                # Extract file path if available
                file_path = None
                if 'file_path' in sample:
                    file_path = sample['file_path']
                elif 'sample' in sample and 'path' in sample['sample']:
                    file_path = sample['sample']['path']
                
                if file_path and os.path.exists(file_path):
                    # Analyze the sample
                    self.enhanced_generator.analyze_sample(
                        file_path=file_path,
                        family=family_name,
                        analysis_data=sample.get('analysis'),
                        generate_rule=False
                    )
            
            # Generate rule for the family
            rule = self.enhanced_generator.generate_rule_for_family(family_name)
            
            if rule:
                rule_path = os.path.join(self.enhanced_generator.output_dir, f"{rule.name}.yar")
                return rule_path
            
            # Fall back to legacy generator if needed
            if self.legacy_generator:
                logger.info("Falling back to legacy generator")
                return self.legacy_generator.generate_family_rule(samples)
            
            return None
            
        except Exception as e:
            logger.error(f"Error generating family rule: {e}")
            
            # Fall back to legacy generator if available
            if self.legacy_generator:
                logger.info("Falling back to legacy generator due to error")
                return self.legacy_generator.generate_family_rule(samples)
            
            raise

def main():
    """Command-line entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced YARA Integration")
    
    parser.add_argument('--file', '-f', help='Path to analysis JSON file')
    parser.add_argument('--directory', '-d', help='Path to directory with analysis JSON files')
    parser.add_argument('--output', '-o', help='Output directory for YARA rules')
    parser.add_argument('--benign', '-b', help='Directory containing benign samples for testing')
    parser.add_argument('--no-fallback', action='store_true', help='Disable fallback to legacy generator')
    
    args = parser.parse_args()
    
    if not args.file and not args.directory:
        parser.print_help()
        sys.exit(1)
    
    # Create integration
    integration = EnhancedYaraIntegration(
        output_dir=args.output,
        benign_samples_dir=args.benign,
        fallback_to_legacy=not args.no_fallback
    )
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                sample_data = json.load(f)
            
            rule_path = integration.generate_yara_rule(sample_data)
            print(f"Generated YARA rule: {rule_path}")
        except Exception as e:
            logger.error(f"Error generating rule from file: {e}")
            sys.exit(1)
    
    if args.directory:
        try:
            # Find all JSON files
            json_files = [os.path.join(args.directory, f) for f in os.listdir(args.directory) 
                        if f.endswith('.json') and os.path.isfile(os.path.join(args.directory, f))]
            
            if not json_files:
                logger.error(f"No JSON files found in {args.directory}")
                sys.exit(1)
            
            # Load samples
            samples = []
            for json_file in json_files:
                try:
                    with open(json_file, 'r') as f:
                        sample_data = json.load(f)
                    samples.append(sample_data)
                    # Generate individual rule
                    integration.generate_yara_rule(sample_data)
                except Exception as e:
                    logger.error(f"Error processing {json_file}: {e}")
            
            # Generate family rule if we have enough samples
            if len(samples) >= 2:
                family_rule = integration.generate_family_rule(samples)
                if family_rule:
                    print(f"Generated family YARA rule: {family_rule}")
            
            print(f"Generated {len(samples)} individual YARA rules")
        except Exception as e:
            logger.error(f"Error processing directory: {e}")
            sys.exit(1)

if __name__ == "__main__":
    sys.exit(main() or 0)