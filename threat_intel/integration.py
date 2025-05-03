#!/usr/bin/env python3
"""
Threat Intelligence Integration Script
Integrates all threat intelligence components (connector, correlation, reporting, IOC extraction, YARA rules)
into a unified workflow.
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
from threat_intel.rules.yara_generator import YaraRuleGenerator
from threat_intel.ioc_utils.ioc_extractor import IOCExtractor
from threat_intel.threat_intel_analyzer import ThreatIntelAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(__file__), 'logs', 'integration.log'), mode='a'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('threat_intel_integration')

# Create logs directory if it doesn't exist
os.makedirs(os.path.join(os.path.dirname(__file__), 'logs'), exist_ok=True)

class ThreatIntelIntegration:
    """
    Integrates all threat intelligence components into a unified workflow
    """
    
    def __init__(self, api_keys: Dict[str, str] = None, output_dir: str = None):
        """
        Initialize the integration
        
        Args:
            api_keys: Dictionary of API keys for threat intelligence sources
            output_dir: Base directory for all outputs
        """
        # Set API keys in environment if provided
        if api_keys:
            for key_name, key_value in api_keys.items():
                os.environ[key_name] = key_value
        
        # Set output directory
        self.output_dir = output_dir or os.path.join(
            os.path.dirname(__file__), 'output'
        )
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Create subdirectories
        self.reports_dir = os.path.join(self.output_dir, 'reports')
        self.iocs_dir = os.path.join(self.output_dir, 'iocs')
        self.rules_dir = os.path.join(self.output_dir, 'rules')
        self.correlation_dir = os.path.join(self.output_dir, 'correlation')
        
        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(self.iocs_dir, exist_ok=True)
        os.makedirs(self.rules_dir, exist_ok=True)
        os.makedirs(self.correlation_dir, exist_ok=True)
        
        # Initialize components
        self.ti_manager = create_default_manager()
        self.correlation_engine = CorrelationEngine(ti_manager=self.ti_manager)
        self.report_generator = ReportGenerator()
        self.yara_generator = YaraRuleGenerator(rules_dir=self.rules_dir)
        self.ioc_extractor = IOCExtractor(output_dir=self.iocs_dir)
        self.analyzer = ThreatIntelAnalyzer(api_keys=api_keys)
    
    def process_sample(self, sample_data: Dict, 
                      generate_report: bool = True, 
                      generate_iocs: bool = True,
                      generate_yara: bool = True,
                      ioc_formats: List[str] = None,
                      view_report: bool = False) -> Dict:
        """
        Process a single sample with all components
        
        Args:
            sample_data: Sample analysis data
            generate_report: Whether to generate a report
            generate_iocs: Whether to extract and export IOCs
            generate_yara: Whether to generate YARA rules
            ioc_formats: List of IOC export formats
            view_report: Whether to view the generated report
            
        Returns:
            Dictionary containing all results
        """
        if ioc_formats is None:
            ioc_formats = ["json", "csv"]
        
        logger.info(f"Processing sample {sample_data.get('sha256', 'unknown')}")
        results = {}
        
        # Step 1: Enrich with threat intelligence if needed
        if "threat_intel" not in sample_data:
            logger.info("Enriching sample with threat intelligence")
            sample_data = self.ti_manager.enrich_sample(sample_data)
        
        # Step 2: Correlate the sample
        logger.info("Correlating sample with threat intelligence")
        correlation_result = self.correlation_engine.correlate_sample(sample_data)
        results["correlation"] = correlation_result
        
        # Save correlation result
        correlation_file = os.path.join(
            self.correlation_dir, 
            f"correlation_{sample_data.get('sha256', 'unknown')}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.json"
        )
        with open(correlation_file, 'w') as f:
            json.dump(correlation_result, f, indent=2)
        results["correlation_file"] = correlation_file
        
        # Step 3: Generate report if requested
        if generate_report:
            logger.info("Generating report")
            report_path = self.report_generator.generate_single_sample_report(correlation_result)
            results["report_path"] = report_path
            
            if view_report and report_path:
                logger.info("Opening report for viewing")
                self.report_generator.view_report(report_path)
        
        # Step 4: Extract and export IOCs if requested
        if generate_iocs:
            logger.info("Extracting and exporting IOCs")
            exported_files = self.ioc_extractor.extract_and_export(
                correlation_result, formats=ioc_formats
            )
            results["ioc_files"] = exported_files
        
        # Step 5: Generate YARA rules if requested
        if generate_yara:
            logger.info("Generating YARA rules")
            rule_path = self.yara_generator.generate_yara_rule(sample_data, correlation_result)
            results["yara_rule"] = rule_path
        
        return results
    
    def process_multiple_samples(self, samples: List[Dict],
                               generate_report: bool = True,
                               generate_iocs: bool = True,
                               generate_yara: bool = True,
                               ioc_formats: List[str] = None,
                               view_report: bool = False) -> Dict:
        """
        Process multiple samples with all components
        
        Args:
            samples: List of sample analysis data
            generate_report: Whether to generate a report
            generate_iocs: Whether to extract and export IOCs
            generate_yara: Whether to generate YARA rules
            ioc_formats: List of IOC export formats
            view_report: Whether to view the generated report
            
        Returns:
            Dictionary containing all results
        """
        if ioc_formats is None:
            ioc_formats = ["json", "csv"]
        
        logger.info(f"Processing {len(samples)} samples")
        results = {}
        
        # Step 1: Process each sample individually
        processed_samples = []
        for i, sample in enumerate(samples):
            logger.info(f"Processing sample {i+1}/{len(samples)}")
            
            # Enrich and correlate
            if "threat_intel" not in sample:
                sample = self.ti_manager.enrich_sample(sample)
            
            if "is_ransomware" not in sample:
                sample = self.correlation_engine.correlate_sample(sample)
            
            processed_samples.append(sample)
        
        # Step 2: Correlate across samples
        logger.info("Finding correlations across samples")
        multi_correlation_result = self.correlation_engine.correlate_multiple_samples(processed_samples)
        results["multi_correlation"] = multi_correlation_result
        
        # Save correlation result
        correlation_file = os.path.join(
            self.correlation_dir, 
            f"multi_correlation_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.json"
        )
        with open(correlation_file, 'w') as f:
            json.dump(multi_correlation_result, f, indent=2)
        results["correlation_file"] = correlation_file
        
        # Step 3: Generate multi-sample report if requested
        if generate_report:
            logger.info("Generating multi-sample report")
            report_path = self.report_generator.generate_multi_sample_report(
                multi_correlation_result, processed_samples
            )
            results["report_path"] = report_path
            
            if view_report and report_path:
                logger.info("Opening report for viewing")
                self.report_generator.view_report(report_path)
        
        # Step 4: Extract and export combined IOCs if requested
        if generate_iocs:
            logger.info("Extracting and exporting combined IOCs")
            # Merge IOCs from all samples
            all_iocs = {}
            for sample in processed_samples:
                iocs = self.ioc_extractor.extract_iocs(sample)
                for ioc_type, ioc_list in iocs.items():
                    if ioc_type not in all_iocs:
                        all_iocs[ioc_type] = []
                    all_iocs[ioc_type].extend(ioc_list)
            
            # Export combined IOCs
            exported_files = {}
            for format_name in ioc_formats:
                if format_name.lower() == "json":
                    exported_files["json"] = self.ioc_extractor.export_iocs_json(all_iocs)
                elif format_name.lower() == "csv":
                    exported_files["csv"] = self.ioc_extractor.export_iocs_csv(all_iocs)
                elif format_name.lower() == "stix":
                    exported_files["stix"] = self.ioc_extractor.export_iocs_stix(all_iocs)
                elif format_name.lower() == "openioc":
                    exported_files["openioc"] = self.ioc_extractor.export_iocs_openioc(all_iocs)
                elif format_name.lower() == "misp":
                    exported_files["misp"] = self.ioc_extractor.export_iocs_misp(all_iocs)
            
            results["ioc_files"] = exported_files
        
        # Step 5: Generate family YARA rule if requested
        if generate_yara:
            logger.info("Generating family YARA rule")
            rule_path = self.yara_generator.generate_family_rule(processed_samples)
            results["yara_rule"] = rule_path
        
        return results
    
    def process_file(self, file_path: str,
                   generate_report: bool = True,
                   generate_iocs: bool = True,
                   generate_yara: bool = True,
                   ioc_formats: List[str] = None,
                   view_report: bool = False) -> Dict:
        """
        Process a file using all components
        
        Args:
            file_path: Path to the file to analyze
            generate_report: Whether to generate a report
            generate_iocs: Whether to extract and export IOCs
            generate_yara: Whether to generate YARA rules
            ioc_formats: List of IOC export formats
            view_report: Whether to view the generated report
            
        Returns:
            Dictionary containing all results
        """
        logger.info(f"Processing file {file_path}")
        
        # Check if this is a JSON file with analysis data
        if file_path.endswith('.json'):
            try:
                with open(file_path, 'r') as f:
                    sample_data = json.load(f)
                return self.process_sample(
                    sample_data, 
                    generate_report, 
                    generate_iocs, 
                    generate_yara, 
                    ioc_formats, 
                    view_report
                )
            except json.JSONDecodeError:
                # Not a valid JSON file, treat as normal file
                pass
        
        # Use analyzer to get basic sample data
        result = self.analyzer.analyze_file(
            file_path, 
            generate_report=False,  # We'll handle reporting ourselves
            view_report=False
        )
        
        # Process the sample data
        return self.process_sample(
            result, 
            generate_report, 
            generate_iocs, 
            generate_yara, 
            ioc_formats, 
            view_report
        )
    
    def process_directory(self, dir_path: str,
                        generate_report: bool = True,
                        generate_iocs: bool = True,
                        generate_yara: bool = True,
                        ioc_formats: List[str] = None,
                        view_report: bool = False) -> Dict:
        """
        Process all JSON files in a directory
        
        Args:
            dir_path: Path to the directory to analyze
            generate_report: Whether to generate a report
            generate_iocs: Whether to extract and export IOCs
            generate_yara: Whether to generate YARA rules
            ioc_formats: List of IOC export formats
            view_report: Whether to view the generated report
            
        Returns:
            Dictionary containing all results
        """
        logger.info(f"Processing directory {dir_path}")
        
        # Find all JSON files in the directory
        json_files = list(Path(dir_path).glob('*.json'))
        
        if not json_files:
            logger.warning(f"No JSON files found in {dir_path}")
            return {"error": f"No JSON files found in {dir_path}"}
        
        logger.info(f"Found {len(json_files)} JSON files")
        
        # Read and process each file
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
        
        # Process the samples
        return self.process_multiple_samples(
            samples, 
            generate_report, 
            generate_iocs, 
            generate_yara, 
            ioc_formats, 
            view_report
        )


def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description="Threat Intelligence Integration")
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--file', '-f', help='Path to a file to analyze')
    input_group.add_argument('--analysis', '-a', help='Path to a JSON file containing analysis data')
    input_group.add_argument('--directory', '-d', help='Path to a directory containing analysis JSON files')
    
    # Output options
    parser.add_argument('--output-dir', '-o', help='Output directory for all results')
    
    # API keys
    parser.add_argument('--vt-key', help='VirusTotal API key')
    parser.add_argument('--otx-key', help='AlienVault OTX API key')
    
    # Feature flags
    parser.add_argument('--no-report', action='store_true', help='Do not generate reports')
    parser.add_argument('--no-iocs', action='store_true', help='Do not extract IOCs')
    parser.add_argument('--no-yara', action='store_true', help='Do not generate YARA rules')
    
    # IOC options
    parser.add_argument('--ioc-formats', nargs='+', default=["json", "csv"],
                       help='IOC export formats (json, csv, stix, openioc, misp)')
    
    # View options
    parser.add_argument('--view', action='store_true', help='View the generated report')
    
    args = parser.parse_args()
    
    # Configure API keys
    api_keys = {}
    if args.vt_key:
        api_keys['VIRUSTOTAL_API_KEY'] = args.vt_key
    if args.otx_key:
        api_keys['ALIENVAULT_OTX_API_KEY'] = args.otx_key
    
    # Create integration
    integration = ThreatIntelIntegration(api_keys=api_keys, output_dir=args.output_dir)
    
    # Process based on input options
    try:
        if args.file:
            result = integration.process_file(
                args.file,
                generate_report=not args.no_report,
                generate_iocs=not args.no_iocs,
                generate_yara=not args.no_yara,
                ioc_formats=args.ioc_formats,
                view_report=args.view
            )
        elif args.analysis:
            with open(args.analysis, 'r') as f:
                sample_data = json.load(f)
            result = integration.process_sample(
                sample_data,
                generate_report=not args.no_report,
                generate_iocs=not args.no_iocs,
                generate_yara=not args.no_yara,
                ioc_formats=args.ioc_formats,
                view_report=args.view
            )
        elif args.directory:
            result = integration.process_directory(
                args.directory,
                generate_report=not args.no_report,
                generate_iocs=not args.no_iocs,
                generate_yara=not args.no_yara,
                ioc_formats=args.ioc_formats,
                view_report=args.view
            )
        
        # Print summary of results
        print("\nProcessing completed successfully!")
        
        if "correlation_file" in result:
            print(f"Correlation results saved to: {result['correlation_file']}")
        
        if "report_path" in result:
            print(f"Report generated at: {result['report_path']}")
        
        if "ioc_files" in result:
            print("IOCs exported to:")
            for format_name, file_path in result["ioc_files"].items():
                print(f"  {format_name.upper()}: {file_path}")
        
        if "yara_rule" in result:
            print(f"YARA rule generated at: {result['yara_rule']}")
        
    except Exception as e:
        logger.error(f"Error in processing: {e}", exc_info=True)
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())