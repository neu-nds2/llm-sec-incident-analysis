#!/usr/bin/env python3
"""
Base LLM Client Interface
Abstract base class for all LLM providers
"""

from abc import ABC, abstractmethod
from typing import Any, Dict

class BaseLLMClient(ABC):
    """
    Abstract base class for LLM clients
    All LLM provider implementations must inherit from this class
    """
    
    def __init__(self, **kwargs):
        """
        Initialize the LLM client with provider-specific configuration
        
        Args:
            **kwargs: Provider-specific configuration parameters
        """
        self.config = kwargs
    
    @abstractmethod
    def query(self, prompt: str, **kwargs) -> str:
        """
        Send query to LLM and return response
        
        Args:
            prompt: The prompt/question to send to the LLM
            **kwargs: Additional parameters (max_tokens, temperature, etc.)
            
        Returns:
            Response text from the LLM
        """
        pass
    
    @abstractmethod
    def test_connection(self) -> bool:
        """
        Test if the LLM connection works
        
        Returns:
            True if connection successful, False otherwise
        """
        pass
    
    def get_provider_name(self) -> str:
        """
        Get the name of the LLM provider
        
        Returns:
            Provider name (e.g., 'DeepSeek', 'Ollama', etc.)
        """
        return self.__class__.__name__.replace('Client', '')
    
    def get_config(self) -> Dict[str, Any]:
        """
        Get the current configuration
        
        Returns:
            Configuration dictionary
        """
        return self.config.copy()
    
    def update_config(self, **kwargs):
        """
        Update configuration parameters
        
        Args:
            **kwargs: New configuration parameters
        """
        self.config.update(kwargs)
