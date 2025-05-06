#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LLM Provider Manager 

This module implements a cost-optimized LLM provider manager for Innora-Defender,
prioritizing vLLM for better cost efficiency while maintaining performance.
It supports multiple LLM services including OpenAI, Anthropic, local vLLM deployments,
and Aliyun Qwen, with intelligent fallback mechanisms.
"""

import os
import re
import json
import time
import logging
import requests
import threading
from typing import Dict, Any, Optional, List, Union, Tuple
from dataclasses import dataclass
from pathlib import Path
import atexit

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Ransomware analysis task features to LLM mapping
FEATURE_CONFIG = {
    "F1": {"primary": "vllm", "fallbacks": ["qianwen_fast", "qianwen_detail"]},  # Basic sample analysis
    "F2": {"primary": "vllm", "fallbacks": ["qianwen_fast", "qianwen_detail"]},  # Simple behavior detection
    "F3": {"primary": "vllm", "fallbacks": ["qianwen_fast", "qianwen_detail"]},  # Static feature analysis
    "F4": {"primary": "vllm", "fallbacks": ["qianwen_fast", "qianwen_detail"]},  # Simple question answering
    "F5": {"primary": "vllm", "fallbacks": ["qianwen_fast", "qianwen_detail"]},  # Documentation generation
    "F6": {"primary": "vllm", "fallbacks": ["qianwen_fast", "qianwen_detail"]},  # Basic family attribution
    "F7": {"primary": "qianwen_detail", "fallbacks": ["anthropic", "openai"]},   # Advanced code analysis
    "F8": {"primary": "qianwen_detail", "fallbacks": ["anthropic", "openai"]},   # Deep technical analysis
    "F9": {"primary": "anthropic", "fallbacks": ["openai"]},                    # Complex attack chain analysis
    "F10": {"primary": "anthropic", "fallbacks": ["openai"]},                   # Vulnerability detection
    "F11": {"primary": "qianwen_detail", "fallbacks": ["anthropic", "openai"]}, # Advanced decryption workflows
    "F12": {"primary": "vllm", "fallbacks": ["qianwen_fast", "qianwen_detail"]}, # Test case generation
    "F13": {"primary": "vllm", "fallbacks": ["qianwen_fast", "qianwen_detail"]}, # Translation services
    "F14": {"primary": "vllm", "fallbacks": ["qianwen_fast", "qianwen_detail"]}, # Dependency analysis
    "F15": {"primary": "vllm", "fallbacks": ["qianwen_fast", "qianwen_detail"]}  # Error diagnosis
}

# Feature descriptions for better context and documentation
FEATURE_DESCRIPTIONS = {
    "F1": "Basic ransomware sample analysis",
    "F2": "Simple ransomware behavior detection",
    "F3": "Static feature analysis and classification",
    "F4": "Simple ransomware knowledge Q&A",
    "F5": "Ransomware analysis documentation",
    "F6": "Ransomware family attribution",
    "F7": "Advanced ransomware code analysis",
    "F8": "Deep technical analysis of complex payloads",
    "F9": "Complex ransomware attack chain analysis",
    "F10": "Encryption vulnerabilities detection",
    "F11": "Advanced ransomware decryption workflow",
    "F12": "Decryption test case generation",
    "F13": "Ransomware information translation",
    "F14": "Ransomware dependency analysis",
    "F15": "Encryption error diagnosis"
}

@dataclass
class LLMProvider:
    """Configuration for an LLM provider."""
    name: str
    api_key_env: str
    api_base: str
    default_model: str
    timeout: int = 60
    max_tokens: int = 4000
    temperature: float = 0.2
    retry_attempts: int = 3
    regions: List[str] = None
    tier: str = "standard"
    priority: int = 1  # Lower number = higher priority
    cost_per_1k_tokens: float = 0.0  # Cost per 1000 tokens
    
    def __post_init__(self):
        # Set default regions if not provided
        if self.regions is None:
            self.regions = ["global"]

class LLMProviderManager:
    """
    LLM Provider Manager optimized for cost-efficient ransomware analysis.
    Prioritizes vLLM deployments while supporting multiple provider fallbacks
    including OpenAI, Claude, and Qwen.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the LLM provider manager with the given configuration.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        
        # Default configuration
        default_config = {
            'enabled': True,
            'provider_priority': ['vllm', 'qianwen_fast', 'qianwen_detail', 'anthropic', 'openai'],
            'rate_limit': 10,  # Requests per minute
            'request_interval': 0.1,  # Seconds between requests
            'health_check_interval': 3600,  # Health check interval in seconds
            'cache_results': True,
            'cache_directory': os.path.expanduser('~/.innora/cache/llm'),
            'max_parallel_requests': 5,
            'default_region': 'global',
            'region_override_map': {},
            'use_regional_optimization': True,
            'auto_fallback': True,
            'detect_models': True,  # Auto-detect available vLLM models
            'feature_config': FEATURE_CONFIG,  # Feature-based routing config
            'cost_tracking': True,  # Track costs
            'performance_tracking': True,  # Track performance
            'usage_log_file': '/tmp/innora_llm_usage_log.jsonl',  # Usage log file
            'save_stats_on_exit': True  # Save stats on exit
        }
        
        # Update default config with provided config
        if config:
            for key, value in config.items():
                if key in default_config and isinstance(default_config[key], dict) and isinstance(value, dict):
                    default_config[key].update(value)
                else:
                    default_config[key] = value
        
        self.config = default_config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Initialize providers
        self.providers = self._initialize_providers()
        
        # Track provider health
        self.provider_health = {name: {"healthy": True, "last_check": time.time()} for name in self.providers}
        
        # Rate limiting
        self.request_times = {}
        self.request_lock = threading.RLock()
        
        # Performance and cost tracking
        self.stats = {
            'calls': {name: 0 for name in self.providers},
            'failures': {name: 0 for name in self.providers},
            'tokens': {name: 0 for name in self.providers},
            'latency': {name: [] for name in self.providers},
            'costs': {name: 0.0 for name in self.providers},
            'feature_calls': {feature_id: 0 for feature_id in FEATURE_CONFIG}
        }
        self.stats_lock = threading.RLock()
        
        # Create cache directory if needed
        if self.config.get('cache_results', True):
            Path(self.config['cache_directory']).mkdir(parents=True, exist_ok=True)
        
        # Start health check thread if enabled
        if self.config.get('health_check_interval', 0) > 0:
            self._start_health_check_thread()
            
        # Detect vLLM models if enabled
        if self.config.get('detect_models', True) and 'vllm' in self.providers:
            self._detect_vllm_models()
        
        # Register exit handler to save stats
        if self.config.get('save_stats_on_exit', True):
            atexit.register(self._save_stats)
    
    def _initialize_providers(self) -> Dict[str, LLMProvider]:
        """
        Initialize LLM provider configurations.
        
        Returns:
            Dictionary of provider configurations
        """
        providers = {}
        
        # OpenAI
        if os.environ.get('OPENAI_API_KEY'):
            providers['openai'] = LLMProvider(
                name="openai",
                api_key_env="OPENAI_API_KEY",
                api_base="https://api.openai.com/v1/chat/completions",
                default_model="gpt-4o-mini",
                regions=["global", "north-america", "europe", "asia", "oceania", "south-america", "africa"],
                tier="premium",
                priority=3,
                cost_per_1k_tokens=0.015  # GPT-4o-mini cost
            )
        
        # Anthropic/Claude
        if os.environ.get('CLAUDE_API_KEY'):
            providers['anthropic'] = LLMProvider(
                name="anthropic",
                api_key_env="CLAUDE_API_KEY",
                api_base="https://api.anthropic.com/v1/messages",
                default_model=os.environ.get('CLAUDE_MODEL', 'claude-3-7-sonnet-20250219'),
                regions=["global", "north-america", "europe", "asia", "oceania"],
                tier="premium",
                priority=2,
                cost_per_1k_tokens=0.03  # Claude cost
            )
        
        # Aliyun Qianwen (Fast)
        if os.environ.get('QIANWEN_API_KEY'):
            providers['qianwen_fast'] = LLMProvider(
                name="qianwen_fast",
                api_key_env="QIANWEN_API_KEY",
                api_base=os.environ.get('QIANWEN_API_BASE', 'https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation'),
                default_model=os.environ.get('QIANWEN_FAST_MODEL', 'qwen-plus'),
                regions=["global", "asia", "china"],
                tier="standard",
                priority=1,
                cost_per_1k_tokens=0.005  # Qwen cost
            )
            
            # Aliyun Qianwen (Detailed)
            providers['qianwen_detail'] = LLMProvider(
                name="qianwen_detail",
                api_key_env="QIANWEN_API_KEY",
                api_base=os.environ.get('QIANWEN_API_BASE', 'https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation'),
                default_model=os.environ.get('QIANWEN_DETAIL_MODEL', 'qwen-max'),
                regions=["global", "asia", "china"],
                tier="premium",
                priority=2,
                cost_per_1k_tokens=0.015  # Qwen detailed cost
            )
        
        # Self-hosted vLLM (RunPod or other deployment)
        if os.environ.get('RUNPOD_API_KEY') or os.environ.get('VLLM_API_BASE'):
            # Get API base URL from environment variables or config
            api_base = os.environ.get('VLLM_API_BASE') or os.environ.get('RUNPOD_ENDPOINT') or "http://localhost:8000"
            default_model = os.environ.get('VLLM_MODEL') or os.environ.get('RUNPOD_MODEL') or "/workspace/models/current"
            
            providers['vllm'] = LLMProvider(
                name="vllm",
                api_key_env="RUNPOD_API_KEY",
                api_base=api_base,
                default_model=default_model,
                timeout=180,  # Longer timeout for self-hosted models
                regions=["global", "asia", "russia", "china"],  # Regions where commercial APIs may be restricted
                tier="standard",
                priority=0,  # Highest priority - use vLLM when available
                cost_per_1k_tokens=0.0005  # vLLM cost (very low)
            )
        
        return providers
    
    def _detect_vllm_models(self) -> List[str]:
        """
        Detect available models on the vLLM endpoint.
        
        Returns:
            List of available model IDs
        """
        available_models = []
        
        if 'vllm' not in self.providers:
            return available_models
        
        provider = self.providers['vllm']
        api_base = provider.api_base
        
        # Try to get models from API
        try:
            models_url = f"{api_base.rstrip('/')}/v1/models"
            
            headers = {}
            if os.environ.get(provider.api_key_env):
                headers["Authorization"] = f"Bearer {os.environ.get(provider.api_key_env)}"
            
            response = requests.get(models_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and isinstance(data['data'], list):
                    for model in data['data']:
                        if 'id' in model:
                            available_models.append(model['id'])
                    
                    if available_models:
                        self.logger.info(f"Detected vLLM models: {', '.join(available_models)}")
                        
                        # Update default model if current default isn't available
                        if provider.default_model not in available_models and available_models:
                            provider.default_model = available_models[0]
                            self.logger.info(f"Updated default vLLM model to {provider.default_model}")
                        
                        return available_models
        except Exception as e:
            self.logger.warning(f"Error detecting vLLM models: {str(e)}")
        
        # If API method fails, try to test common model paths
        model_paths = [
            "/workspace/models/current",  # RunPod default
            "llama-3-8b-instruct",        # Llama 3 8B
            "mistral-7b-instruct",        # Mistral 7B
            "mixtral-8x7b-instruct",      # Mixtral 8x7B
            "gemma-7b-instruct",          # Google Gemma 7B
            "qwen2-7b-instruct"           # Qwen 2 7B
        ]
        
        # Test each model with a simple request
        for model_id in model_paths:
            try:
                self.logger.info(f"Testing vLLM model: {model_id}")
                
                headers = {"Content-Type": "application/json"}
                if os.environ.get(provider.api_key_env):
                    headers["Authorization"] = f"Bearer {os.environ.get(provider.api_key_env)}"
                
                chat_endpoint = f"{api_base.rstrip('/')}/v1/chat/completions"
                data = {
                    "model": model_id,
                    "messages": [
                        {"role": "user", "content": "Hello"}
                    ],
                    "max_tokens": 5
                }
                
                response = requests.post(chat_endpoint, headers=headers, json=data, timeout=10)
                
                if response.status_code == 200:
                    self.logger.info(f"Model {model_id} is available!")
                    available_models.append(model_id)
                    
                    # Update default model if current default isn't available
                    if provider.default_model not in available_models:
                        provider.default_model = model_id
                        self.logger.info(f"Updated default vLLM model to {model_id}")
                    
                    # Only need to find one working model
                    break
            except Exception as e:
                self.logger.debug(f"Model {model_id} test failed: {str(e)}")
        
        if not available_models:
            self.logger.warning("No vLLM models detected. Using configured default model.")
        
        return available_models
    
    def _start_health_check_thread(self) -> None:
        """Start a background thread for health checks."""
        def health_check_worker():
            while True:
                try:
                    for provider_name, provider in self.providers.items():
                        current_time = time.time()
                        last_check = self.provider_health[provider_name].get("last_check", 0)
                        
                        # Only check if interval has passed
                        if current_time - last_check >= self.config['health_check_interval']:
                            self._check_provider_health(provider_name)
                except Exception as e:
                    self.logger.error(f"Error in health check thread: {str(e)}")
                
                # Sleep until next check
                time.sleep(60)  # Check every minute if any providers need a health check
        
        thread = threading.Thread(target=health_check_worker, daemon=True)
        thread.start()
    
    def _check_provider_health(self, provider_name: str) -> bool:
        """
        Check the health of a provider.
        
        Args:
            provider_name: Name of the provider to check
            
        Returns:
            True if healthy, False otherwise
        """
        provider = self.providers.get(provider_name)
        if not provider:
            return False
        
        try:
            # Simple health check with minimal tokens
            result = self._call_provider(
                provider,
                [{"role": "user", "content": "Hello"}],
                max_tokens=5
            )
            
            healthy = bool(result)
            
            # Update health status
            self.provider_health[provider_name] = {
                "healthy": healthy,
                "last_check": time.time()
            }
            
            if not healthy:
                self.logger.warning(f"Provider {provider_name} is unhealthy")
            
            return healthy
        except Exception as e:
            self.logger.warning(f"Provider {provider_name} health check failed: {str(e)}")
            
            # Update health status
            self.provider_health[provider_name] = {
                "healthy": False,
                "last_check": time.time(),
                "error": str(e)
            }
            
            return False
    
    def get_optimal_provider(self, region: Optional[str] = None) -> LLMProvider:
        """
        Get the optimal provider for the given region.
        
        Args:
            region: Region code (e.g., 'north-america', 'asia') or None for default
            
        Returns:
            LLMProvider object
        """
        region = region or self.config['default_region']
        
        # Check region override map
        if region in self.config['region_override_map']:
            provider_name = self.config['region_override_map'][region]
            if provider_name in self.providers:
                return self.providers[provider_name]
        
        # Filter providers that support this region
        valid_providers = []
        for provider_name, provider in self.providers.items():
            # Check if provider is healthy and supports the region
            is_healthy = self.provider_health[provider_name].get("healthy", True)
            supports_region = "global" in provider.regions or region in provider.regions
            
            if is_healthy and supports_region:
                valid_providers.append(provider)
        
        # Sort by priority (lower is better)
        valid_providers.sort(key=lambda p: p.priority)
        
        if valid_providers:
            if valid_providers[0].name == 'vllm' and self.config.get('prioritize_vllm', True):
                self.logger.info(f"Using vLLM provider for region {region}")
                return valid_providers[0]
            return valid_providers[0]
        
        # If no valid providers, return first available as fallback
        if not self.providers:
            raise ValueError("No LLM providers configured")
        
        return next(iter(self.providers.values()))
    
    def call(self, 
            messages: List[Dict[str, str]], 
            region: Optional[str] = None,
            max_tokens: Optional[int] = None,
            temperature: Optional[float] = None,
            provider_override: Optional[str] = None) -> str:
        """
        Call LLM with automatic provider selection.
        
        Args:
            messages: List of message objects with role and content
            region: Optional region for provider selection
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            provider_override: Force use of specific provider
            
        Returns:
            Generated text response
        """
        if not self.config['enabled']:
            self.logger.warning("LLM service is disabled")
            return ""
        
        # Get optimal provider (or use override)
        provider = None
        if provider_override and provider_override in self.providers:
            provider = self.providers[provider_override]
        else:
            provider = self.get_optimal_provider(region)
        
        # Set parameters
        max_tokens = max_tokens or provider.max_tokens
        temperature = temperature if temperature is not None else provider.temperature
        
        # Apply rate limiting
        self._apply_rate_limit(provider.name)
        
        try:
            # Record start time (for latency statistics)
            start_time = time.time()
            
            # Call provider
            result = self._call_provider(
                provider,
                messages,
                max_tokens=max_tokens,
                temperature=temperature
            )
            
            # Calculate latency and update statistics
            latency = time.time() - start_time
            self._update_stats(provider.name, success=True, latency=latency)
            
            return result
        except Exception as e:
            self.logger.error(f"Error calling {provider.name}: {str(e)}")
            
            # Update statistics
            self._update_stats(provider.name, success=False)
            
            # Mark provider as unhealthy
            self.provider_health[provider.name] = {
                "healthy": False,
                "last_check": time.time(),
                "error": str(e)
            }
            
            # If auto-fallback is enabled and no override provider was specified
            if self.config['auto_fallback'] and not provider_override:
                # Get fallback providers excluding the failed one
                fallback_providers = [p for name, p in self.providers.items() if name != provider.name]
                
                # Sort by priority
                fallback_providers.sort(key=lambda p: p.priority)
                
                for fallback_provider in fallback_providers:
                    self.logger.info(f"Trying fallback provider: {fallback_provider.name}")
                    
                    try:
                        # Record start time
                        start_time = time.time()
                        
                        # Call fallback provider
                        result = self._call_provider(
                            fallback_provider,
                            messages,
                            max_tokens=max_tokens,
                            temperature=temperature
                        )
                        
                        # Calculate latency and update statistics
                        latency = time.time() - start_time
                        self._update_stats(fallback_provider.name, success=True, latency=latency, is_fallback=True)
                        
                        return result
                    except Exception as fallback_e:
                        self.logger.warning(f"Fallback provider {fallback_provider.name} failed: {str(fallback_e)}")
                        self._update_stats(fallback_provider.name, success=False, is_fallback=True)
            
            # If auto-fallback is disabled or all fallbacks failed
            self.logger.error("All LLM providers failed")
            return ""
    
    def call_feature(self,
                   feature_id: str,
                   messages: List[Dict[str, str]],
                   max_tokens: Optional[int] = None,
                   temperature: Optional[float] = None,
                   fallback: bool = True) -> str:
        """
        Call LLM based on feature routing.
        
        Args:
            feature_id: Feature ID from FEATURE_CONFIG
            messages: List of message objects with role and content
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            fallback: Whether to enable fallback to alternative providers
            
        Returns:
            Generated text response
        """
        if not self.config['enabled']:
            self.logger.warning("LLM service is disabled")
            return ""
        
        # Validate feature ID
        feature_config = self.config.get('feature_config', {})
        if feature_id not in feature_config:
            self.logger.warning(f"Unknown feature ID: {feature_id}, using default provider")
            return self.call(messages, max_tokens=max_tokens, temperature=temperature)
        
        # Get feature provider configuration
        config = feature_config[feature_id]
        primary = config.get("primary")
        fallbacks = config.get("fallbacks", [])
        
        # Update feature call count
        with self.stats_lock:
            self.stats['feature_calls'][feature_id] = self.stats['feature_calls'].get(feature_id, 0) + 1
        
        # Primary provider not configured or unavailable
        if not primary or primary not in self.providers:
            self.logger.warning(f"Primary provider for feature {feature_id} not configured or unavailable")
            return self.call(messages, max_tokens=max_tokens, temperature=temperature)
        
        # Call with specific provider
        try:
            return self.call(
                messages, 
                max_tokens=max_tokens, 
                temperature=temperature,
                provider_override=primary
            )
        except Exception as e:
            self.logger.error(f"Error calling primary provider {primary} for feature {feature_id}: {str(e)}")
            
            if not fallback:
                raise
            
            # Try fallback providers
            for provider_name in fallbacks:
                if provider_name not in self.providers:
                    continue
                    
                try:
                    self.logger.info(f"Trying fallback provider for feature {feature_id}: {provider_name}")
                    return self.call(
                        messages, 
                        max_tokens=max_tokens, 
                        temperature=temperature,
                        provider_override=provider_name
                    )
                except Exception as fallback_e:
                    self.logger.warning(f"Fallback provider {provider_name} failed: {str(fallback_e)}")
                    continue
            
            # All providers failed
            self.logger.error(f"All providers for feature {feature_id} failed")
            return ""
    
    def _call_provider(self, 
                      provider: LLMProvider, 
                      messages: List[Dict[str, str]],
                      max_tokens: int,
                      temperature: float = 0.2) -> str:
        """
        Call specific LLM provider.
        
        Args:
            provider: LLMProvider object
            messages: List of message objects with role and content
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            
        Returns:
            Generated text response
        """
        api_key = os.environ.get(provider.api_key_env, "")
        
        if provider.name == "anthropic":
            return self._call_anthropic(provider, messages, max_tokens, temperature, api_key)
        elif provider.name == "openai":
            return self._call_openai(provider, messages, max_tokens, temperature, api_key)
        elif provider.name == "qianwen_fast" or provider.name == "qianwen_detail":
            return self._call_qianwen(provider, messages, max_tokens, temperature, api_key)
        elif provider.name == "vllm":
            return self._call_vllm(provider, messages, max_tokens, temperature, api_key)
        else:
            raise ValueError(f"Unsupported provider: {provider.name}")
    
    def _call_anthropic(self, 
                       provider: LLMProvider, 
                       messages: List[Dict[str, str]],
                       max_tokens: int,
                       temperature: float,
                       api_key: str) -> str:
        """
        Call Anthropic Claude API.
        
        Args:
            provider: LLMProvider object
            messages: List of message objects
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            api_key: API key
            
        Returns:
            Generated text response
        """
        if not api_key:
            raise ValueError("Anthropic API key not configured")
        
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": os.environ.get("CLAUDE_API_VERSION", "2023-06-01")
        }
        
        data = {
            "model": provider.default_model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": messages
        }
        
        estimated_input_tokens = sum(len(msg.get("content", "")) for msg in messages) // 4
        
        for attempt in range(provider.retry_attempts):
            try:
                response = requests.post(
                    provider.api_base,
                    headers=headers,
                    json=data,
                    timeout=provider.timeout
                )
                
                response.raise_for_status()
                result = response.json()
                
                # Extract content from response
                if 'content' in result and len(result['content']) > 0:
                    content = result['content'][0]['text']
                    
                    # Update token usage statistics (estimated)
                    output_tokens = len(content) // 4
                    total_tokens = estimated_input_tokens + output_tokens
                    
                    with self.stats_lock:
                        self.stats['tokens'][provider.name] = self.stats['tokens'].get(provider.name, 0) + total_tokens
                        self.stats['costs'][provider.name] = self.stats['costs'].get(provider.name, 0) + (
                            total_tokens / 1000.0 * provider.cost_per_1k_tokens
                        )
                    
                    self._log_usage(provider.name, estimated_input_tokens, output_tokens, total_tokens)
                    
                    return content
                
                return ""
                
            except Exception as e:
                if attempt == provider.retry_attempts - 1:
                    raise
                self.logger.warning(f"Anthropic API call failed, retrying ({attempt+1}/{provider.retry_attempts}): {str(e)}")
                time.sleep(2 ** attempt)  # Exponential backoff
        
        return ""
    
    def _call_openai(self, 
                    provider: LLMProvider, 
                    messages: List[Dict[str, str]],
                    max_tokens: int,
                    temperature: float,
                    api_key: str) -> str:
        """
        Call OpenAI API.
        
        Args:
            provider: LLMProvider object
            messages: List of message objects
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            api_key: API key
            
        Returns:
            Generated text response
        """
        if not api_key:
            raise ValueError("OpenAI API key not configured")
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        
        # Ensure system message exists
        if not any(msg.get("role") == "system" for msg in messages):
            messages = [{"role": "system", "content": "You are a cybersecurity expert specializing in ransomware analysis."}] + messages
        
        data = {
            "model": provider.default_model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }
        
        estimated_input_tokens = sum(len(msg.get("content", "")) for msg in messages) // 4
        
        for attempt in range(provider.retry_attempts):
            try:
                response = requests.post(
                    provider.api_base,
                    headers=headers,
                    json=data,
                    timeout=provider.timeout
                )
                
                response.raise_for_status()
                result = response.json()
                
                # Extract content from response
                if 'choices' in result and len(result['choices']) > 0:
                    content = result['choices'][0]['message']['content']
                    
                    # Update token usage statistics (use actual numbers if available)
                    if 'usage' in result:
                        prompt_tokens = result['usage'].get('prompt_tokens', estimated_input_tokens)
                        completion_tokens = result['usage'].get('completion_tokens', len(content) // 4)
                        total_tokens = result['usage'].get('total_tokens', prompt_tokens + completion_tokens)
                    else:
                        # Estimate
                        output_tokens = len(content) // 4
                        total_tokens = estimated_input_tokens + output_tokens
                        prompt_tokens = estimated_input_tokens
                        completion_tokens = output_tokens
                    
                    with self.stats_lock:
                        self.stats['tokens'][provider.name] = self.stats['tokens'].get(provider.name, 0) + total_tokens
                        self.stats['costs'][provider.name] = self.stats['costs'].get(provider.name, 0) + (
                            total_tokens / 1000.0 * provider.cost_per_1k_tokens
                        )
                    
                    self._log_usage(provider.name, prompt_tokens, completion_tokens, total_tokens)
                    
                    return content
                
                return ""
                
            except Exception as e:
                if attempt == provider.retry_attempts - 1:
                    raise
                self.logger.warning(f"OpenAI API call failed, retrying ({attempt+1}/{provider.retry_attempts}): {str(e)}")
                time.sleep(2 ** attempt)  # Exponential backoff
        
        return ""
    
    def _call_qianwen(self, 
                     provider: LLMProvider, 
                     messages: List[Dict[str, str]],
                     max_tokens: int,
                     temperature: float,
                     api_key: str) -> str:
        """
        Call Aliyun Qianwen API.
        
        Args:
            provider: LLMProvider object
            messages: List of message objects
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            api_key: API key
            
        Returns:
            Generated text response
        """
        if not api_key:
            raise ValueError("Qianwen API key not configured")
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        
        # Use provider default model
        model = provider.default_model
        
        # Convert OpenAI format messages to Qianwen format
        formatted_messages = []
        
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            
            if role == "system":
                formatted_messages.append({
                    "role": "system",
                    "content": content
                })
            elif role == "user":
                formatted_messages.append({
                    "role": "user",
                    "content": content
                })
            elif role == "assistant":
                formatted_messages.append({
                    "role": "assistant",
                    "content": content
                })
        
        data = {
            "model": model,
            "input": {
                "messages": formatted_messages
            },
            "parameters": {
                "max_tokens": max_tokens,
                "temperature": temperature,
                "top_p": 0.8,
                "result_format": "text"
            }
        }
        
        estimated_input_tokens = sum(len(msg.get("content", "")) for msg in messages) // 4
        
        for attempt in range(provider.retry_attempts):
            try:
                response = requests.post(
                    provider.api_base,
                    headers=headers,
                    json=data,
                    timeout=provider.timeout
                )
                
                response.raise_for_status()
                result = response.json()
                
                # Extract content from response
                if 'output' in result and 'text' in result['output']:
                    content = result['output']['text']
                    
                    # Update token usage statistics
                    if 'usage' in result:
                        input_tokens = result['usage'].get('input_tokens', estimated_input_tokens)
                        output_tokens = result['usage'].get('output_tokens', len(content) // 4)
                        total_tokens = input_tokens + output_tokens
                    else:
                        # Estimate
                        output_tokens = len(content) // 4
                        total_tokens = estimated_input_tokens + output_tokens
                        input_tokens = estimated_input_tokens
                    
                    with self.stats_lock:
                        self.stats['tokens'][provider.name] = self.stats['tokens'].get(provider.name, 0) + total_tokens
                        self.stats['costs'][provider.name] = self.stats['costs'].get(provider.name, 0) + (
                            total_tokens / 1000.0 * provider.cost_per_1k_tokens
                        )
                    
                    self._log_usage(provider.name, input_tokens, output_tokens, total_tokens)
                    
                    return content
                
                return ""
                
            except Exception as e:
                if attempt == provider.retry_attempts - 1:
                    raise
                self.logger.warning(f"Qianwen API call failed, retrying ({attempt+1}/{provider.retry_attempts}): {str(e)}")
                time.sleep(2 ** attempt)  # Exponential backoff
        
        return ""
    
    def _call_vllm(self, 
                  provider: LLMProvider, 
                  messages: List[Dict[str, str]],
                  max_tokens: int,
                  temperature: float,
                  api_key: str) -> str:
        """
        Call vLLM API (OpenAI-compatible interface).
        
        Args:
            provider: LLMProvider object
            messages: List of message objects
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            api_key: API key (optional for some deployments)
            
        Returns:
            Generated text response
        """
        headers = {
            "Content-Type": "application/json"
        }
        
        # Add API key if available
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        
        # Ensure system message exists
        if not any(msg.get("role") == "system" for msg in messages):
            messages = [{"role": "system", "content": "You are a cybersecurity expert specializing in ransomware analysis."}] + messages
        
        data = {
            "model": provider.default_model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "top_p": 0.95
        }
        
        # vLLM deployments typically use an OpenAI-compatible endpoint
        api_url = f"{provider.api_base.rstrip('/')}/v1/chat/completions"
        
        estimated_input_tokens = sum(len(msg.get("content", "")) for msg in messages) // 4
        
        for attempt in range(provider.retry_attempts):
            try:
                response = requests.post(
                    api_url,
                    headers=headers,
                    json=data,
                    timeout=provider.timeout
                )
                
                response.raise_for_status()
                result = response.json()
                
                # Extract content from response (OpenAI format)
                if 'choices' in result and len(result['choices']) > 0:
                    content = result['choices'][0]['message']['content']
                    
                    # Clean up thinking tags common in some models (like Qwen)
                    content = self._clean_thinking_tags(content)
                    
                    # Update token usage statistics
                    if 'usage' in result:
                        prompt_tokens = result['usage'].get('prompt_tokens', estimated_input_tokens)
                        completion_tokens = result['usage'].get('completion_tokens', len(content) // 4)
                        total_tokens = result['usage'].get('total_tokens', prompt_tokens + completion_tokens)
                    else:
                        # Estimate
                        output_tokens = len(content) // 4
                        total_tokens = estimated_input_tokens + output_tokens
                        prompt_tokens = estimated_input_tokens
                        completion_tokens = output_tokens
                    
                    with self.stats_lock:
                        self.stats['tokens'][provider.name] = self.stats['tokens'].get(provider.name, 0) + total_tokens
                        self.stats['costs'][provider.name] = self.stats['costs'].get(provider.name, 0) + (
                            total_tokens / 1000.0 * provider.cost_per_1k_tokens
                        )
                    
                    self._log_usage(provider.name, prompt_tokens, completion_tokens, total_tokens)
                    
                    return content
                
                return ""
                
            except Exception as e:
                if attempt == provider.retry_attempts - 1:
                    raise
                self.logger.warning(f"vLLM API call failed, retrying ({attempt+1}/{provider.retry_attempts}): {str(e)}")
                time.sleep(2 ** attempt)  # Exponential backoff
        
        return ""
    
    def _clean_thinking_tags(self, content: str) -> str:
        """
        Clean thinking tags from model output.
        Some models like Qwen include <think>...</think> tags.
        
        Args:
            content: Original model output
            
        Returns:
            Cleaned content
        """
        # Remove <think>...</think> tags and their content
        cleaned = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL)
        
        # Remove any resulting empty lines
        cleaned = re.sub(r'\n\s*\n', '\n\n', cleaned)
        
        return cleaned
    
    def _apply_rate_limit(self, provider_name: str) -> None:
        """
        Apply rate limiting for API calls.
        
        Args:
            provider_name: Provider name
        """
        with self.request_lock:
            current_time = time.time()
            
            # Initialize request times for provider if not exists
            if provider_name not in self.request_times:
                self.request_times[provider_name] = []
            
            # Keep only requests from the last minute
            self.request_times[provider_name] = [
                t for t in self.request_times[provider_name] 
                if current_time - t < 60
            ]
            
            # Check if rate limit exceeded
            if len(self.request_times[provider_name]) >= self.config['rate_limit']:
                # Calculate sleep time to go below rate limit
                oldest_request = self.request_times[provider_name][0]
                sleep_time = 60 - (current_time - oldest_request) + 0.1
                
                if sleep_time > 0:
                    self.logger.info(f"Rate limit reached for {provider_name}, sleeping {sleep_time:.2f} seconds")
                    time.sleep(sleep_time)
                    
                    # Recalculate after sleep
                    current_time = time.time()
                    self.request_times[provider_name] = [
                        t for t in self.request_times[provider_name] 
                        if current_time - t < 60
                    ]
            
            # Add current request time
            self.request_times[provider_name].append(current_time)
            
            # Add small delay between requests
            time.sleep(self.config['request_interval'])
    
    def _update_stats(self, provider_name: str, success: bool, latency: float = 0.0, is_fallback: bool = False) -> None:
        """
        Update provider statistics.
        
        Args:
            provider_name: Provider name
            success: Whether the call was successful
            latency: Request latency in seconds
            is_fallback: Whether this was a fallback provider
        """
        if not self.config.get('performance_tracking', True):
            return
            
        with self.stats_lock:
            # Update call count
            self.stats['calls'][provider_name] = self.stats['calls'].get(provider_name, 0) + 1
            
            # If failed, update failure count
            if not success:
                self.stats['failures'][provider_name] = self.stats['failures'].get(provider_name, 0) + 1
            
            # If successful with latency, update latency statistics
            if success and latency > 0:
                self.stats['latency'][provider_name] = self.stats['latency'].get(provider_name, []) + [latency]
                
                # Keep only the most recent 100 latency measurements to save memory
                self.stats['latency'][provider_name] = self.stats['latency'][provider_name][-100:]
    
    def _log_usage(self, provider_name: str, input_tokens: int, output_tokens: int, total_tokens: int) -> None:
        """
        Log usage to the usage log file.
        
        Args:
            provider_name: Provider name
            input_tokens: Input token count
            output_tokens: Output token count
            total_tokens: Total token count
        """
        if not self.config.get('cost_tracking', True):
            return
            
        log_file = self.config.get('usage_log_file')
        if not log_file:
            return
            
        try:
            # Create usage log entry
            log_entry = {
                "timestamp": time.time(),
                "provider": provider_name,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": total_tokens,
                "estimated_cost": (total_tokens / 1000.0) * self.providers[provider_name].cost_per_1k_tokens
            }
            
            # Append to log file
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            self.logger.warning(f"Error logging usage: {str(e)}")
    
    def _save_stats(self) -> None:
        """Save statistics when program exits."""
        try:
            # Calculate average latency
            avg_latency = {}
            for provider_name, latencies in self.stats['latency'].items():
                if latencies:
                    avg_latency[provider_name] = sum(latencies) / len(latencies)
                else:
                    avg_latency[provider_name] = 0.0
            
            # Calculate success rate
            success_rate = {}
            for provider_name, calls in self.stats['calls'].items():
                failures = self.stats['failures'].get(provider_name, 0)
                if calls > 0:
                    success_rate[provider_name] = (calls - failures) / calls * 100.0
                else:
                    success_rate[provider_name] = 0.0
            
            # Create statistics summary
            summary = {
                "timestamp": time.time(),
                "date": time.strftime("%Y-%m-%d %H:%M:%S"),
                "calls": self.stats['calls'],
                "success_rate": success_rate,
                "avg_latency": avg_latency,
                "tokens": self.stats['tokens'],
                "costs": self.stats['costs'],
                "feature_calls": self.stats['feature_calls']
            }
            
            # Save to file
            stats_file = self.config.get('stats_file', '/tmp/innora_llm_stats.json')
            with open(stats_file, 'w') as f:
                json.dump(summary, f, indent=2)
                
            self.logger.info(f"Saved LLM usage statistics to {stats_file}")
        except Exception as e:
            self.logger.error(f"Error saving statistics: {str(e)}")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get current LLM usage statistics.
        
        Returns:
            Statistics dictionary
        """
        with self.stats_lock:
            # Calculate average latency
            avg_latency = {}
            for provider_name, latencies in self.stats['latency'].items():
                if latencies:
                    avg_latency[provider_name] = sum(latencies) / len(latencies)
                else:
                    avg_latency[provider_name] = 0.0
            
            # Calculate success rate
            success_rate = {}
            for provider_name, calls in self.stats['calls'].items():
                failures = self.stats['failures'].get(provider_name, 0)
                if calls > 0:
                    success_rate[provider_name] = (calls - failures) / calls * 100.0
                else:
                    success_rate[provider_name] = 0.0
            
            return {
                "calls": dict(self.stats['calls']),
                "failures": dict(self.stats['failures']),
                "success_rate": success_rate,
                "avg_latency": avg_latency,
                "tokens": dict(self.stats['tokens']),
                "costs": dict(self.stats['costs']),
                "feature_calls": dict(self.stats['feature_calls']),
                "provider_health": {name: health.get("healthy", False) 
                                   for name, health in self.provider_health.items()}
            }
    
    def get_providers_info(self) -> List[Dict[str, Any]]:
        """
        Get information about all providers.
        
        Returns:
            List of provider information
        """
        providers_info = []
        
        for name, provider in self.providers.items():
            health = self.provider_health.get(name, {"healthy": False, "last_check": 0})
            
            info = {
                "name": name,
                "model": provider.default_model,
                "tier": provider.tier,
                "priority": provider.priority,
                "cost_per_1k_tokens": provider.cost_per_1k_tokens,
                "healthy": health.get("healthy", False),
                "last_health_check": health.get("last_check", 0),
                "calls": self.stats['calls'].get(name, 0),
                "failures": self.stats['failures'].get(name, 0),
                "tokens_used": self.stats['tokens'].get(name, 0),
                "estimated_cost": self.stats['costs'].get(name, 0)
            }
            
            providers_info.append(info)
        
        # Sort by priority
        providers_info.sort(key=lambda p: p["priority"])
        
        return providers_info
    
    def clear_stats(self) -> None:
        """Clear usage statistics."""
        with self.stats_lock:
            for provider_name in self.providers:
                self.stats['calls'][provider_name] = 0
                self.stats['failures'][provider_name] = 0
                self.stats['tokens'][provider_name] = 0
                self.stats['latency'][provider_name] = []
                self.stats['costs'][provider_name] = 0.0
            
            for feature_id in FEATURE_CONFIG:
                self.stats['feature_calls'][feature_id] = 0
                
    def get_feature_mapping(self) -> Dict[str, Dict[str, Any]]:
        """
        Get the feature to LLM mapping.
        
        Returns:
            Feature mapping dictionary with descriptions
        """
        mapping = {}
        
        for feature_id, config in self.config.get('feature_config', {}).items():
            mapping[feature_id] = {
                "description": FEATURE_DESCRIPTIONS.get(feature_id, f"Feature {feature_id}"),
                "primary": config.get("primary"),
                "fallbacks": config.get("fallbacks", [])
            }
            
        return mapping

# Create global instance (singleton)
llm_provider_manager = LLMProviderManager()