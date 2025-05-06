# Innora-Defender LLM Service

A cost-optimized LLM integration service for Innora-Defender that prioritizes vLLM for better cost efficiency while maintaining high-quality analysis capabilities.

## Overview

The LLM Service is designed to provide Innora-Defender with intelligent analysis capabilities through large language models (LLMs), while optimizing for cost efficiency. The service features:

- **Multi-provider support**: OpenAI, Anthropic Claude, Aliyun Qianwen, and self-hosted vLLM
- **Cost optimization**: Prioritizes vLLM for most tasks to significantly reduce costs
- **Feature-based routing**: Routes different types of tasks to the most appropriate model
- **Automatic fallback**: If a preferred provider fails, automatically tries alternatives
- **Comprehensive caching**: Caches results to avoid redundant API calls
- **Health monitoring**: Tracks provider health and performance
- **Cost tracking**: Detailed cost and usage statistics

## Setup and Installation

### Prerequisites

- Python 3.8 or higher
- Access to at least one LLM provider (OpenAI, Claude, Qianwen, or vLLM)

### Environment Variables

Set up the following environment variables for your preferred LLM providers:

```bash
# OpenAI
export OPENAI_API_KEY="your-openai-api-key"

# Claude
export CLAUDE_API_KEY="your-claude-api-key"
export CLAUDE_MODEL="claude-3-7-sonnet-20250219"  # Optional, defaults to claude-3-7-sonnet

# Qianwen (Aliyun)
export QIANWEN_API_KEY="your-qianwen-api-key"
export QIANWEN_API_BASE="https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation"
export QIANWEN_FAST_MODEL="qwen-plus"
export QIANWEN_DETAIL_MODEL="qwen-max"

# vLLM (self-hosted)
export VLLM_API_BASE="http://localhost:11434/api"  # Your vLLM API endpoint
export VLLM_MODEL="llama-3-8b-instruct"  # Optional, will auto-detect if not specified
export RUNPOD_API_KEY="your-runpod-api-key"  # Optional for some deployments
```

## Usage Examples

### Basic Integration

```python
from ai_detection.llm_service import RansomwareAnalyzer

# Create analyzer
analyzer = RansomwareAnalyzer()

# Run analysis
result = analyzer.analyze(
    sample_path="/path/to/ransomware.exe",
    upstream_results={
        "family": "LockBit",
        "confidence": 0.85,
        "key_features": ["File encryption capability", "Registry modifications", "Suspicious API calls"]
    },
    technical_details={
        "static_analysis": {
            "sha256": "1234567890abcdef...",
            "file_size": 102400,
            "file_type": "EXE"
        }
    }
)

# Print results
print(f"First-stage family: {result['first_stage_family']}")
print(f"LLM family: {result['llm_family']}")
print(f"LLM variant: {result['llm_variant']}")
```

### Batch Analysis

```python
# Batch analyze multiple samples
results = analyzer.batch_analyze(
    sample_paths=["/path/to/sample1.exe", "/path/to/sample2.exe"],
    upstream_results_list=[
        {
            "family": "LockBit",
            "confidence": 0.85,
            "key_features": ["File encryption capability", "Registry modifications"]
        },
        {
            "family": "Ryuk",
            "confidence": 0.75,
            "key_features": ["Shadow copy deletion", "Ransom note creation"]
        }
    ]
)

# Process results
for result in results:
    print(f"{result['sample_name']}: {result['llm_family']} ({result['llm_variant']})")
```

### Direct LLM Interaction

```python
from ai_detection.llm_service import llm_provider_manager

# Use feature-based routing (best for tasks with specific requirements)
response = llm_provider_manager.call_feature(
    feature_id="F7",  # Advanced code analysis
    messages=[
        {"role": "system", "content": "You are a security analyst."},
        {"role": "user", "content": "What does this code do? [code]"}
    ]
)

# Or direct provider selection
response = llm_provider_manager.call(
    messages=[
        {"role": "system", "content": "You are a security analyst."},
        {"role": "user", "content": "What does this code do? [code]"}
    ],
    provider_override="anthropic"  # Force use of specific provider
)

print(response)
```

## Command-line Interface

The LLM Service includes a comprehensive CLI tool for easy interaction:

```bash
# Analyze a ransomware sample
python -m ai_detection.llm_service.cli analyze --sample /path/to/sample.exe --output results.json

# Batch analyze samples
python -m ai_detection.llm_service.cli batch --input batch.json --output results.json

# Interactive chat with LLM
python -m ai_detection.llm_service.cli chat --feature F4

# Check LLM service status
python -m ai_detection.llm_service.cli status --verbose

# View cost report
python -m ai_detection.llm_service.cli costs

# Show available providers
python -m ai_detection.llm_service.cli providers

# Manage configuration
python -m ai_detection.llm_service.cli config --show
```

## Feature Routing Configuration

The LLM Service uses feature-based routing to direct different types of tasks to the most appropriate LLM provider. The default routing is:

| Feature ID | Description | Primary Provider | Fallbacks |
|------------|-------------|-----------------|-----------|
| F1 | Basic ransomware sample analysis | vLLM | Qianwen Fast, Qianwen Detail |
| F2 | Simple ransomware behavior detection | vLLM | Qianwen Fast, Qianwen Detail |
| F3 | Static feature analysis and classification | vLLM | Qianwen Fast, Qianwen Detail |
| F4 | Simple ransomware knowledge Q&A | vLLM | Qianwen Fast, Qianwen Detail |
| F5 | Ransomware analysis documentation | vLLM | Qianwen Fast, Qianwen Detail |
| F6 | Ransomware family attribution | vLLM | Qianwen Fast, Qianwen Detail |
| F7 | Advanced ransomware code analysis | Qianwen Detail | Claude, OpenAI |
| F8 | Deep technical analysis of complex payloads | Qianwen Detail | Claude, OpenAI |
| F9 | Complex ransomware attack chain analysis | Claude | OpenAI |
| F10 | Encryption vulnerabilities detection | Claude | OpenAI |
| F11 | Advanced ransomware decryption workflow | Qianwen Detail | Claude, OpenAI |
| F12 | Decryption test case generation | vLLM | Qianwen Fast, Qianwen Detail |
| F13 | Ransomware information translation | vLLM | Qianwen Fast, Qianwen Detail |
| F14 | Ransomware dependency analysis | vLLM | Qianwen Fast, Qianwen Detail |
| F15 | Encryption error diagnosis | vLLM | Qianwen Fast, Qianwen Detail |

## Configuration

The LLM Service can be configured through:

1. Default configuration in `ai_detection/llm_service/config/default_config.json`
2. User configuration in `~/.innora/config/llm_config.json`
3. Environment variables
4. Code parameters

Key configuration options:

```json
{
  "enabled": true,
  "provider_priority": ["vllm", "qianwen_fast", "qianwen_detail", "anthropic", "openai"],
  "rate_limit": 10,
  "cache_results": true,
  "auto_fallback": true,
  "detect_models": true,
  "analyzer": {
    "cache_ttl": 86400,
    "max_tokens": 4000,
    "temperature": 0.3
  }
}
```

## Cost Optimization

The LLM Service is designed to significantly reduce costs while maintaining quality:

- **vLLM prioritization**: Uses self-hosted open-source models for most tasks
- **Targeted use of premium models**: Only uses expensive models for complex tasks
- **Comprehensive caching**: Avoids redundant API calls
- **Token optimization**: Carefully designs prompts to minimize token usage

Cost comparison (estimated per 1000 tokens):

| Provider | Cost per 1K Tokens | Relative Cost |
|----------|-------------------:|-------------:|
| vLLM | $0.0005 | 1x |
| Qianwen Fast | $0.005 | 10x |
| Qianwen Detail | $0.015 | 30x |
| OpenAI GPT-4o | $0.015 | 30x |
| Claude 3.7 Sonnet | $0.03 | 60x |

By routing 80-90% of tasks to vLLM, the service can reduce costs by up to 80-95% compared to using premium models exclusively.

## Performance Monitoring

The LLM Service includes comprehensive performance monitoring:

```python
# Get LLM usage statistics
stats = llm_provider_manager.get_stats()

# Get cost report
cost_report = analyzer.get_cost_report()

# Get analysis statistics
analysis_stats = analyzer.get_analysis_statistics()
```

## Extending the Service

The LLM Service is designed to be easily extended:

- Add new LLM providers by updating the `_initialize_providers` method
- Add new feature types by updating the `FEATURE_CONFIG` dictionary
- Customize prompt templates in the `RansomwareAnalyzer.PROMPT_TEMPLATES` dictionary

## Troubleshooting

Common issues and solutions:

- **Provider unavailable**: Ensure environment variables are set correctly and API keys are valid
- **vLLM not detected**: Check that your vLLM endpoint is accessible and configured correctly
- **Slow performance**: Enable caching and adjust rate limiting parameters
- **Rate limiting errors**: Decrease `rate_limit` or increase `request_interval`

For detailed logs, set the environment variable:

```bash
export LOG_LEVEL=DEBUG
```

## License

This project is licensed under the terms of the license included with Innora-Defender.