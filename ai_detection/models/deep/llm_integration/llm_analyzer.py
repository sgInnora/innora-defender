#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LLM Ransomware Analyzer

This module implements a ransomware analyzer using large language models (LLMs)
such as GPT for in-depth analysis of suspicious samples. It integrates with the
two-stage detection system, providing detailed insights for samples that require
deeper analysis beyond what specialized models can provide.
"""

import os
import sys
import json
import logging
import base64
import hashlib
import time
from typing import Dict, List, Any, Tuple, Optional, Union, Set
import tempfile
from datetime import datetime

import numpy as np
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


class LLMRansomwareAnalyzer:
    """
    Ransomware analyzer using large language models (LLMs)
    
    This class uses LLMs like GPT to perform in-depth analysis of suspicious
    ransomware samples, providing detailed explanations and insights about
    the sample's behavior, characteristics, and potential classification.
    """
    
    def __init__(
        self,
        api_type: str = "openai",
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        model_name: str = "gpt-4o",
        temperature: float = 0.0,
        max_tokens: int = 4096,
        cache_dir: str = "./llm_cache",
        system_prompt_template: Optional[str] = None,
        user_prompt_template: Optional[str] = None,
        use_cache: bool = True,
        request_timeout: int = 60,
        confidence_threshold: float = 0.5,
        verbose: bool = False
    ):
        """
        Initialize LLM analyzer
        
        Args:
            api_type: Type of API to use ('openai', 'anthropic', 'custom')
            api_key: API key for the LLM service
            api_base: Base URL for API requests
            model_name: Name of the LLM model to use
            temperature: Temperature parameter for generation
            max_tokens: Maximum number of tokens to generate
            cache_dir: Directory for caching results
            system_prompt_template: Template for system prompt
            user_prompt_template: Template for user prompt
            use_cache: Whether to use caching
            request_timeout: Timeout for API requests (seconds)
            confidence_threshold: Threshold for binary classification
            verbose: Whether to enable verbose logging
        """
        self.api_type = api_type
        self.api_key = api_key or os.environ.get(f"{api_type.upper()}_API_KEY")
        self.api_base = api_base
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.cache_dir = cache_dir
        self.use_cache = use_cache
        self.request_timeout = request_timeout
        self.confidence_threshold = confidence_threshold
        self.verbose = verbose
        
        # Ensure cache directory exists
        if use_cache:
            os.makedirs(cache_dir, exist_ok=True)
        
        # Set prompt templates
        self.system_prompt_template = system_prompt_template or self._get_default_system_prompt()
        self.user_prompt_template = user_prompt_template or self._get_default_user_prompt()
        
        # Initialize API client
        self._init_api_client()
    
    def _init_api_client(self):
        """Initialize API client based on api_type"""
        try:
            if self.api_type == "openai":
                import openai
                self.client = openai.OpenAI(
                    api_key=self.api_key,
                    base_url=self.api_base
                )
            elif self.api_type == "anthropic":
                import anthropic
                self.client = anthropic.Anthropic(
                    api_key=self.api_key,
                )
            else:
                logger.warning(f"Unknown API type: {self.api_type}, using custom implementation")
                self.client = None
        except ImportError as e:
            logger.warning(f"Failed to import {self.api_type} library: {str(e)}")
            logger.warning(f"Install with 'pip install {self.api_type}'")
            self.client = None
        except Exception as e:
            logger.error(f"Error initializing {self.api_type} client: {str(e)}")
            self.client = None
    
    def _get_default_system_prompt(self) -> str:
        """Get default system prompt template"""
        return """
You are a specialized AI security analyst focusing on ransomware detection and analysis. Your task is to analyze the provided information about a potentially suspicious binary sample and determine if it's ransomware. 

Approach this analysis methodically:

1. Review all the provided information carefully:
   - Features extracted by specialized models (CNN, LSTM)
   - Confidence scores from initial screening
   - Any API calls or behaviors observed
   - File characteristics and metadata
   - Patterns identified in the binary

2. Look for common ransomware indicators:
   - File encryption functionality
   - Registry/system modifications
   - Suspicious file access patterns
   - Communication with command and control servers
   - Deletion of backup files or shadow copies
   - Ransom notes or threatening messages
   - Presence of cryptographic primitives

3. Provide your analysis in the following structured format:
   - BRIEF SUMMARY: A 1-2 sentence overview of your findings
   - ANALYSIS: Detailed examination of the evidence and reasoning
   - INDICATORS: List specific indicators of malicious or benign behavior identified
   - CLASSIFICATION: Your final determination if this is ransomware (Yes/No/Uncertain)
   - CONFIDENCE: Your confidence level on a 0-1 scale (e.g., 0.8)
   - ATTRIBUTION: If possible, attribute to known ransomware family or techniques

Your analysis must be evidence-based, focusing only on the indicators present in the data provided. Be clear about what evidence supports your conclusions and where there is uncertainty.
"""
    
    def _get_default_user_prompt(self) -> str:
        """Get default user prompt template"""
        return """
# Sample Information

Binary hash: {binary_hash}
File path: {binary_path}

# Initial Screening Results

CNN confidence: {cnn_confidence}
LSTM confidence: {lstm_confidence}

# Features and Analysis Data

## CNN Features
{cnn_features}

## LSTM Features
{lstm_features}

## API Call Sequence (Sample)
{api_calls}

# Analysis Request

Based on the information above, perform a detailed analysis to determine if this is ransomware. Focus on identifying key indicators of ransomware behavior in the features and API calls. Provide your structured analysis following the format in your instructions.
"""
    
    def get_config(self) -> Dict[str, Any]:
        """
        Get configuration for serialization
        
        Returns:
            Dictionary with configuration
        """
        return {
            'api_type': self.api_type,
            'api_base': self.api_base,
            'model_name': self.model_name,
            'temperature': self.temperature,
            'max_tokens': self.max_tokens,
            'cache_dir': self.cache_dir,
            'system_prompt_template': self.system_prompt_template,
            'user_prompt_template': self.user_prompt_template,
            'use_cache': self.use_cache,
            'request_timeout': self.request_timeout,
            'confidence_threshold': self.confidence_threshold,
            'verbose': self.verbose
        }
    
    def _cache_key(self, data: Dict[str, Any]) -> str:
        """
        Generate cache key for data
        
        Args:
            data: Data to generate cache key for
            
        Returns:
            Cache key string
        """
        # Create a deterministic string representation
        data_str = json.dumps(data, sort_keys=True)
        
        # Generate hash
        return hashlib.md5(data_str.encode('utf-8')).hexdigest()
    
    def _load_from_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """
        Load result from cache
        
        Args:
            cache_key: Cache key
            
        Returns:
            Cached result or None if not found
        """
        if not self.use_cache:
            return None
        
        cache_path = os.path.join(self.cache_dir, f"{cache_key}.json")
        
        if os.path.exists(cache_path):
            try:
                with open(cache_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading from cache: {str(e)}")
        
        return None
    
    def _save_to_cache(self, cache_key: str, result: Dict[str, Any]):
        """
        Save result to cache
        
        Args:
            cache_key: Cache key
            result: Result to cache
        """
        if not self.use_cache:
            return
        
        cache_path = os.path.join(self.cache_dir, f"{cache_key}.json")
        
        try:
            with open(cache_path, 'w') as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving to cache: {str(e)}")
    
    def _prepare_api_call_summary(self, execution_logs: List[str], max_calls: int = 20) -> str:
        """
        Prepare summary of API calls from execution logs
        
        Args:
            execution_logs: List of paths to execution logs
            max_calls: Maximum number of API calls to include
            
        Returns:
            Summary string
        """
        if not execution_logs:
            return "No execution logs provided."
        
        # Try to load first log
        try:
            with open(execution_logs[0], 'r') as f:
                log_data = json.load(f)
            
            api_calls = []
            
            if isinstance(log_data, list):
                # Assuming a list of API call records
                for entry in log_data[:max_calls]:
                    if "api_name" in entry:
                        api_call = entry["api_name"]
                        if "params" in entry:
                            params = entry["params"]
                            api_call += f"({params})"
                        api_calls.append(api_call)
            elif isinstance(log_data, dict) and "api_calls" in log_data:
                # Assuming a dict with an "api_calls" key
                for entry in log_data["api_calls"][:max_calls]:
                    if "api_name" in entry:
                        api_call = entry["api_name"]
                        if "params" in entry:
                            params = entry["params"]
                            api_call += f"({params})"
                        api_calls.append(api_call)
            
            if not api_calls:
                return "No API calls found in execution logs."
            
            # If there are more calls than max_calls
            if len(api_calls) == max_calls and (
                (isinstance(log_data, list) and len(log_data) > max_calls) or
                (isinstance(log_data, dict) and "api_calls" in log_data and len(log_data["api_calls"]) > max_calls)
            ):
                api_calls.append("... (more calls omitted)")
            
            return "\n".join(api_calls)
            
        except Exception as e:
            logger.error(f"Error extracting API calls: {str(e)}")
            return f"Error extracting API calls: {str(e)}"
    
    def _prepare_prompt(self, data: Dict[str, Any]) -> Tuple[str, str]:
        """
        Prepare prompts for LLM
        
        Args:
            data: Analysis data
            
        Returns:
            Tuple of (system_prompt, user_prompt)
        """
        # Get binary hash
        binary_path = data.get('binary_path', '')
        binary_hash = "Unknown"
        
        if binary_path and os.path.exists(binary_path):
            try:
                with open(binary_path, 'rb') as f:
                    binary_hash = hashlib.md5(f.read()).hexdigest()
            except Exception as e:
                logger.error(f"Error computing binary hash: {str(e)}")
        
        # Get confidence scores
        stage1_confidences = data.get('stage1_confidences', {})
        cnn_confidence = stage1_confidences.get('cnn', 0.0)
        lstm_confidence = stage1_confidences.get('lstm', 0.0)
        
        # Get features
        stage1_features = data.get('stage1_features', {})
        cnn_features = stage1_features.get('cnn', {})
        lstm_features = stage1_features.get('lstm', {})
        
        # Format features for prompts
        cnn_features_str = json.dumps(cnn_features, indent=2)[:2000] if cnn_features else "No CNN features available."
        lstm_features_str = json.dumps(lstm_features, indent=2)[:2000] if lstm_features else "No LSTM features available."
        
        # Get API calls
        execution_logs = data.get('execution_logs', [])
        api_calls = self._prepare_api_call_summary(execution_logs)
        
        # Format user prompt
        user_prompt = self.user_prompt_template.format(
            binary_hash=binary_hash,
            binary_path=binary_path,
            cnn_confidence=cnn_confidence,
            lstm_confidence=lstm_confidence,
            cnn_features=cnn_features_str,
            lstm_features=lstm_features_str,
            api_calls=api_calls
        )
        
        return self.system_prompt_template, user_prompt
    
    def _call_llm_api(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        """
        Call LLM API
        
        Args:
            system_prompt: System prompt
            user_prompt: User prompt
            
        Returns:
            API response
        """
        if self.client is None:
            raise ValueError(f"LLM API client not initialized. Make sure to install the {self.api_type} library.")
        
        try:
            if self.api_type == "openai":
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    timeout=self.request_timeout
                )
                
                return {
                    'content': response.choices[0].message.content,
                    'prompt_tokens': response.usage.prompt_tokens,
                    'completion_tokens': response.usage.completion_tokens,
                    'total_tokens': response.usage.total_tokens,
                    'model': response.model
                }
                
            elif self.api_type == "anthropic":
                response = self.client.messages.create(
                    model=self.model_name,
                    system=system_prompt,
                    messages=[
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=self.temperature,
                    max_tokens=self.max_tokens
                )
                
                return {
                    'content': response.content[0].text,
                    'prompt_tokens': response.usage.input_tokens,
                    'completion_tokens': response.usage.output_tokens,
                    'total_tokens': response.usage.input_tokens + response.usage.output_tokens,
                    'model': response.model
                }
                
            else:
                raise ValueError(f"Unsupported API type: {self.api_type}")
                
        except Exception as e:
            logger.error(f"Error calling LLM API: {str(e)}")
            raise
    
    def _parse_llm_response(self, response_content: str) -> Dict[str, Any]:
        """
        Parse LLM response to extract structured information
        
        Args:
            response_content: LLM response content
            
        Returns:
            Dictionary with parsed results
        """
        # Default result
        result = {
            'is_ransomware': False,
            'confidence': 0.0,
            'summary': '',
            'analysis': '',
            'indicators': [],
            'classification': 'Uncertain',
            'attribution': 'Unknown'
        }
        
        # Extract sections
        sections = {
            'BRIEF SUMMARY': '',
            'ANALYSIS': '',
            'INDICATORS': '',
            'CLASSIFICATION': '',
            'CONFIDENCE': '',
            'ATTRIBUTION': ''
        }
        
        current_section = None
        section_content = []
        
        for line in response_content.split('\n'):
            line = line.strip()
            
            # Check if line is a section header
            for section in sections.keys():
                if line.upper().startswith(section) or line.upper().startswith('# ' + section):
                    if current_section:
                        sections[current_section] = '\n'.join(section_content).strip()
                    current_section = section
                    section_content = []
                    break
            else:
                if current_section:
                    section_content.append(line)
        
        # Add content from the last section
        if current_section:
            sections[current_section] = '\n'.join(section_content).strip()
        
        # Extract values
        result['summary'] = sections['BRIEF SUMMARY']
        result['analysis'] = sections['ANALYSIS']
        
        # Extract indicators as list
        indicators_text = sections['INDICATORS']
        indicators = []
        
        for line in indicators_text.split('\n'):
            line = line.strip()
            if line.startswith('-') or line.startswith('*'):
                indicators.append(line[1:].strip())
        
        result['indicators'] = indicators
        
        # Extract classification
        classification = sections['CLASSIFICATION'].upper()
        if 'YES' in classification or 'RANSOMWARE' in classification:
            result['is_ransomware'] = True
            result['classification'] = 'Ransomware'
        elif 'NO' in classification or 'BENIGN' in classification or 'NOT RANSOMWARE' in classification:
            result['is_ransomware'] = False
            result['classification'] = 'Benign'
        else:
            result['is_ransomware'] = False
            result['classification'] = 'Uncertain'
        
        # Extract confidence
        confidence_text = sections['CONFIDENCE']
        confidence = 0.0
        
        try:
            # Try to extract a number from the text
            import re
            confidence_matches = re.findall(r'0\.\d+|\d+%', confidence_text)
            
            if confidence_matches:
                confidence_str = confidence_matches[0]
                if '%' in confidence_str:
                    # Convert percentage to float
                    confidence = float(confidence_str.replace('%', '')) / 100
                else:
                    confidence = float(confidence_str)
        except Exception as e:
            logger.error(f"Error extracting confidence: {str(e)}")
        
        result['confidence'] = confidence
        
        # Extract attribution
        result['attribution'] = sections['ATTRIBUTION']
        
        # Determine is_ransomware based on confidence if uncertain
        if result['classification'] == 'Uncertain':
            result['is_ransomware'] = confidence >= self.confidence_threshold
        
        return result
    
    def analyze_sample(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze sample using LLM
        
        Args:
            data: Dictionary containing sample data, including:
                - binary_path: Path to binary sample
                - execution_logs: List of paths to execution logs
                - stage1_features: Features from stage 1
                - stage1_confidences: Confidence scores from stage 1
            
        Returns:
            Dictionary with analysis results
        """
        start_time = time.time()
        
        # Check if result is in cache
        cache_key = self._cache_key(data)
        cached_result = self._load_from_cache(cache_key)
        
        if cached_result:
            logger.info(f"Using cached result for {cache_key}")
            cached_result['from_cache'] = True
            return cached_result
        
        # Prepare prompts
        system_prompt, user_prompt = self._prepare_prompt(data)
        
        if self.verbose:
            logger.info(f"System prompt: {system_prompt}")
            logger.info(f"User prompt: {user_prompt}")
        
        # Call LLM API
        try:
            api_response = self._call_llm_api(system_prompt, user_prompt)
            
            # Parse response
            analysis_result = self._parse_llm_response(api_response['content'])
            
            # Add API response data
            analysis_result['llm_output'] = api_response['content']
            analysis_result['token_usage'] = {
                'prompt_tokens': api_response['prompt_tokens'],
                'completion_tokens': api_response['completion_tokens'],
                'total_tokens': api_response['total_tokens']
            }
            analysis_result['model'] = api_response['model']
            
            # Add metadata
            analysis_result['timestamp'] = datetime.now().isoformat()
            analysis_result['processing_time'] = time.time() - start_time
            
            # Cache result
            self._save_to_cache(cache_key, analysis_result)
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Error analyzing sample: {str(e)}")
            return {
                'is_ransomware': False,
                'confidence': 0.0,
                'error': str(e),
                'processing_time': time.time() - start_time
            }
    
    def process_batch(self, batch_data: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Process a batch of samples
        
        Args:
            batch_data: Dictionary mapping sample IDs to sample data
            
        Returns:
            Dictionary mapping sample IDs to analysis results
        """
        results = {}
        
        for sample_id, sample_data in batch_data.items():
            try:
                logger.info(f"Analyzing sample {sample_id}")
                results[sample_id] = self.analyze_sample(sample_data)
            except Exception as e:
                logger.error(f"Error processing sample {sample_id}: {str(e)}")
                results[sample_id] = {
                    'is_ransomware': False,
                    'confidence': 0.0,
                    'error': str(e)
                }
        
        return results