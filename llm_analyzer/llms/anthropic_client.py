#!/usr/bin/env python3
"""
Anthropic LLM Client
"""

import requests
from typing import Optional
from llms.base_llm_client import BaseLLMClient


class AnthropicClient(BaseLLMClient):
    """Anthropic Claude API client"""
    
    def __init__(self, api_key: str, base_url: str = "https://api.anthropic.com/v1/messages", **kwargs):
        super().__init__(api_key=api_key, base_url=base_url, **kwargs)
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {
            "x-api-key": api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01"
        }
        print(f"Anthropic client initialized (endpoint: {base_url})")
    
    def query(self, prompt: str, model: str = "claude-sonnet-4-20250514", 
              max_tokens: int = 4000, temperature: float = 0.1, **kwargs) -> str:
        payload = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}]
        }
        payload.update(kwargs)
        
        try:
            response = requests.post(self.base_url, headers=self.headers, json=payload, timeout=120)
            
            if response.status_code == 200:
                result = response.json()
                return result['content'][0]['text']
            elif response.status_code == 404:
                return f"Error: Model '{model}' not found"
            elif response.status_code == 401:
                return "Error: Invalid API key"
            elif response.status_code == 429:
                return "Error: Rate limit exceeded"
            else:
                return f"Error: {response.status_code} - {response.text}"
            
        except requests.exceptions.Timeout:
            return "Error: Request timeout"
        except requests.exceptions.RequestException as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Error: {e}"
    
    def test_connection(self) -> bool:
        print(f"Testing Anthropic connection...")
        response = self.query("Hello, respond with 'Connection successful'", max_tokens=50)
        
        success = "error" not in response.lower() and len(response) > 5
        
        if success:
            print("Anthropic API connection successful")
        else:
            print(f"Anthropic API connection failed: {response}")
        
        return success
