"""
Innora-Defender LLM Service

This package provides LLM integration services for Innora-Defender with cost optimization.
It prioritizes vLLM for most tasks to reduce cost while maintaining analysis quality
and provides fallback mechanisms to higher-quality models when needed.

Key components:
- llm_provider_manager: Manages multiple LLM providers with cost-optimized routing
- RansomwareAnalyzer: LLM-based ransomware analysis with feature-based routing
"""

from ai_detection.llm_service.llm_provider_manager import llm_provider_manager
from ai_detection.llm_service.ransomware_analyzer import RansomwareAnalyzer

__all__ = ['llm_provider_manager', 'RansomwareAnalyzer']