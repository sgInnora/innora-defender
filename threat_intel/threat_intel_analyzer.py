#!/usr/bin/env python3
"""
Threat Intelligence Analyzer
Main script that integrates all threat intelligence components to analyze ransomware samples.
"""

import os
import sys
import json
import logging
import argparse
import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import our modules
from threat_intel.connectors.ti_connector import create_default_manager
from threat_intel.correlation.correlation_engine import CorrelationEngine
from threat_intel.reports.report_generator import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(__file__), 'logs', 'threat_intel.log'), mode='a'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('threat_intel_analyzer')

# Create logs directory if it doesn't exist
os.makedirs(os.path.join(os.path.dirname(__file__), 'logs'), exist_ok=True)

class ThreatIntelAnalyzer:
    """
    Main class for integrating threat intelligence components
    to analyze ransomware samples
    """
    
    def __init__(self, api_keys: Dict[str, str] = None):
        """
        Initialize the analyzer
        
        Args:
            api_keys: Dictionary of API keys for threat intelligence services
        """
        # Set API keys in environment if provided
        if api_keys:
            for key_name, key_value in api_keys.items():
                os.environ[key_name] = key_value
        
        # Create components
        self.ti_manager = create_default_manager()
        self.correlation_engine = CorrelationEngine(ti_manager=self.ti_manager)
        self.report_generator = ReportGenerator()
    
    def analyze_sample(self, sample_data: Dict, generate_report: bool = True, view_report: bool = False) -> Dict:
        """
        Analyze a sample using threat intelligence
        
        Args:
            sample_data: Dictionary containing sample analysis data
            generate_report: Whether to generate a report
            view_report: Whether to view the generated report
            
        Returns:
            Dictionary containing correlation results
        """
        logger.info(f"Analyzing sample {sample_data.get('sha256', 'unknown')}")
        
        # Enrich the sample with threat intelligence if not already done
        if "threat_intel" not in sample_data and self.ti_manager:
            logger.info("Enriching sample with threat intelligence")
            sample_data = self.ti_manager.enrich_sample(sample_data)
        
        # Correlate the sample with threat intelligence
        logger.info("Correlating sample with threat intelligence")
        correlation_result = self.correlation_engine.correlate_sample(sample_data)
        
        # Generate report if requested
        if generate_report:
            logger.info("Generating report")
            report_path = self.report_generator.generate_single_sample_report(correlation_result)
            
            if report_path and view_report:
                logger.info("Opening report for viewing")
                self.report_generator.view_report(report_path)
            
            correlation_result["report_path"] = report_path
        
        return correlation_result
    
    def analyze_multiple_samples(self, samples: List[Dict], generate_report: bool = True, view_report: bool = False) -> Dict:
        """
        Analyze multiple samples and find correlations between them
        
        Args:
            samples: List of dictionaries containing sample data
            generate_report: Whether to generate a report
            view_report: Whether to view the generated report
            
        Returns:
            Dictionary containing correlation results across samples
        """
        logger.info(f"Analyzing {len(samples)} samples for correlations")
        
        # First, ensure all samples are correlated individually
        correlation_results = []
        for sample in samples:
            if "is_ransomware" not in sample:  # Not yet correlated
                correlation_result = self.correlation_engine.correlate_sample(sample)
                correlation_results.append(correlation_result)
            else:
                correlation_results.append(sample)
        
        # Correlate across samples
        logger.info("Finding correlations across samples")
        multi_correlation_result = self.correlation_engine.correlate_multiple_samples(correlation_results)
        
        # Generate report if requested
        if generate_report:
            logger.info("Generating multi-sample report")
            report_path = self.report_generator.generate_multi_sample_report(multi_correlation_result, correlation_results)
            
            if report_path and view_report:
                logger.info("Opening report for viewing")
                self.report_generator.view_report(report_path)
            
            multi_correlation_result["report_path"] = report_path
        
        return multi_correlation_result
    
    def analyze_file(self, file_path: str, generate_report: bool = True, view_report: bool = False) -> Dict:
        """
        Analyze a file using threat intelligence
        
        Args:
            file_path: Path to the file to analyze
            generate_report: Whether to generate a report
            view_report: Whether to view the generated report
            
        Returns:
            Dictionary containing correlation results
        """
        logger.info(f"Analyzing file {file_path}")
        
        # Read the file analysis if it's a JSON file
        if file_path.endswith('.json'):
            try:
                with open(file_path, 'r') as f:
                    sample_data = json.load(f)
                return self.analyze_sample(sample_data, generate_report, view_report)
            except Exception as e:
                logger.error(f"Error reading analysis file: {e}")
                return {"error": f"Error reading analysis file: {e}"}
        
        # For other file types, create a basic analysis
        # This would typically be handled by a separate analysis module
        
        # Get basic file information
        file_path = os.path.abspath(file_path)
        file_name = os.path.basename(file_path)
        
        try:
            file_size = os.path.getsize(file_path)
            file_created = datetime.datetime.fromtimestamp(os.path.getctime(file_path)).isoformat()
            file_modified = datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
        except Exception as e:
            logger.error(f"Error getting file information: {e}")
            return {"error": f"Error getting file information: {e}"}
        
        # Calculate hash (as a placeholder - in a real implementation, we'd calculate actual hashes)
        import hashlib
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                # Read the file in chunks to avoid loading large files into memory
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256_hash.update(chunk)
            file_hash = sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating file hash: {e}")
            file_hash = "unknown"
        
        # Create a basic sample data structure
        # In a real implementation, this would be much more comprehensive
        sample_data = {
            "sha256": file_hash,
            "name": file_name,
            "path": file_path,
            "size": file_size,
            "created": file_created,
            "modified": file_modified,
            "analysis": {
                "file_type": file_name.split('.')[-1] if '.' in file_name else "unknown"
            }
        }
        
        # Read some strings from the file (for text files)
        try:
            strings = []
            if os.path.getsize(file_path) < 10_000_000:  # Don't try to read very large files
                with open(file_path, 'rb') as f:
                    content = f.read()
                    
                    # Try to decode as text
                    try:
                        text_content = content.decode('utf-8', errors='ignore')
                        
                        # Extract strings (very simple approach)
                        import re
                        strings = [s for s in re.findall(r'[A-Za-z0-9_\-\.]{4,}', text_content) if len(s) < 100]
                        
                        # Limit the number of strings
                        strings = strings[:1000]
                        
                        sample_data["analysis"]["strings"] = strings
                    except:
                        pass
        except Exception as e:
            logger.error(f"Error reading file content: {e}")
        
        return self.analyze_sample(sample_data, generate_report, view_report)
    
    def analyze_directory(self, dir_path: str, generate_report: bool = True, view_report: bool = False) -> Dict:
        """
        Analyze all JSON files in a directory using threat intelligence
        
        Args:
            dir_path: Path to the directory containing analysis JSON files
            generate_report: Whether to generate a report
            view_report: Whether to view the generated report
            
        Returns:
            Dictionary containing correlation results across samples
        """
        logger.info(f"Analyzing directory {dir_path}")
        
        # Find all JSON files in the directory
        json_files = list(Path(dir_path).glob('*.json'))
        
        if not json_files:
            logger.warning(f"No JSON files found in {dir_path}")
            return {"error": f"No JSON files found in {dir_path}"}
        
        logger.info(f"Found {len(json_files)} JSON files")
        
        # Read and analyze each file
        samples = []
        for json_file in json_files:
            try:
                with open(json_file, 'r') as f:
                    sample_data = json.load(f)
                samples.append(sample_data)
            except Exception as e:
                logger.error(f"Error reading {json_file}: {e}")
        
        if not samples:
            logger.warning("No valid sample data found")
            return {"error": "No valid sample data found"}
        
        # Analyze the samples
        return self.analyze_multiple_samples(samples, generate_report, view_report)


def main():
    """Main function to handle command-line arguments"""
    parser = argparse.ArgumentParser(description='Threat Intelligence Analyzer for Ransomware')
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--file', '-f', help='Path to a file to analyze')
    input_group.add_argument('--analysis', '-a', help='Path to a JSON file containing analysis data')
    input_group.add_argument('--directory', '-d', help='Path to a directory containing analysis JSON files')
    
    # API keys
    parser.add_argument('--vt-key', help='VirusTotal API key')
    parser.add_argument('--otx-key', help='AlienVault OTX API key')
    
    # Report options
    parser.add_argument('--no-report', action='store_true', help='Do not generate a report')
    parser.add_argument('--view', action='store_true', help='View the generated report')
    
    # Output options
    parser.add_argument('--output', '-o', help='Path to save the correlation results as JSON')
    
    args = parser.parse_args()
    
    # Configure API keys
    api_keys = {}
    if args.vt_key:
        api_keys['VIRUSTOTAL_API_KEY'] = args.vt_key
    if args.otx_key:
        api_keys['ALIENVAULT_OTX_API_KEY'] = args.otx_key
    
    # Create analyzer
    analyzer = ThreatIntelAnalyzer(api_keys=api_keys)
    
    # Analyze based on input options
    result = None
    
    if args.file:
        result = analyzer.analyze_file(args.file, not args.no_report, args.view)
    elif args.analysis:
        try:
            with open(args.analysis, 'r') as f:
                sample_data = json.load(f)
            result = analyzer.analyze_sample(sample_data, not args.no_report, args.view)
        except Exception as e:
            logger.error(f"Error reading analysis file: {e}")
            return 1
    elif args.directory:
        result = analyzer.analyze_directory(args.directory, not args.no_report, args.view)
    
    # Save results if requested
    if args.output and result:
        try:
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2)
            logger.info(f"Results saved to {args.output}")
        except Exception as e:
            logger.error(f"Error saving results: {e}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())