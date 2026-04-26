#!/usr/bin/env python3
"""
LLM Factory
Factory class for creating and managing different LLM clients
"""

from typing import Dict, List, Type
from llms.base_llm_client import BaseLLMClient
from llms.deepseek_client import DeepSeekClient
from llms.ollama_client import OllamaClient
from llms.openai_client import OpenAIClient
from llms.anthropic_client import AnthropicClient

# Import Cisco local client (optional)
try:
    from llms.cisco_local_client import CiscoFoundationLocalClient
    CISCO_AVAILABLE = True
except ImportError:
    CiscoFoundationLocalClient = None
    CISCO_AVAILABLE = False


class LLMFactory:
    """
    Factory class for creating LLM clients
    """
    
    PROVIDERS: Dict[str, Type[BaseLLMClient]] = {
        'deepseek': DeepSeekClient,
        'ollama': OllamaClient,
        'openai': OpenAIClient,
        'anthropic': AnthropicClient
    }
    
    if CISCO_AVAILABLE:
        PROVIDERS['cisco'] = CiscoFoundationLocalClient
    
    @classmethod
    def create_client(cls, provider: str, **kwargs) -> BaseLLMClient:
        """Create an LLM client for the specified provider"""
        provider = provider.lower()
        
        if provider not in cls.PROVIDERS:
            available = ", ".join(cls.PROVIDERS.keys())
            raise ValueError(f"Unsupported provider '{provider}'. Available: {available}")
        
        if provider == 'cisco' and 'api_key' in kwargs:
            kwargs.pop('api_key')
        
        return cls.PROVIDERS[provider](**kwargs)
    
    @classmethod
    def get_available_providers(cls) -> List[str]:
        """Get list of available LLM providers"""
        return list(cls.PROVIDERS.keys())
    
    @classmethod
    def get_provider_help(cls, provider: str) -> str:
        """Get help text for a specific provider"""
        help_text = {
            'deepseek': """
DeepSeek:
  --api-key-file <file>
  Models: deepseek-chat, deepseek-coder
  Website: https://platform.deepseek.com/
            """,
            'ollama': """
Ollama (local):
  --model <name>  (e.g., qwen2.5:7b, llama3:8b)
  Setup: https://ollama.ai/
            """,
            'openai': """
OpenAI:
  --api-key-file <file>
  Models: gpt-4, gpt-3.5-turbo
  Website: https://platform.openai.com/
            """,
            'anthropic': """
Anthropic:
  --api-key-file <file>
  Models: claude-sonnet-4-20250514, claude-3-opus-20240229
  Website: https://console.anthropic.com/
            """,
            'cisco': """
Cisco Foundation-Sec (local):
  --model <path>  (path to model)
  Specialized for cybersecurity analysis
            """
        }
        return help_text.get(provider.lower(), "No help available")
