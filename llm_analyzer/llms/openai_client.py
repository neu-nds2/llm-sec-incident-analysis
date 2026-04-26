#!/usr/bin/env python3
"""
OpenAI LLM Client
"""

import requests
from typing import Optional
from llms.base_llm_client import BaseLLMClient


class OpenAIClient(BaseLLMClient):
    """OpenAI API client"""
    
    def __init__(self, api_key: str, base_url: str = "https://api.openai.com/v1/chat/completions", **kwargs):
        super().__init__(api_key=api_key, base_url=base_url, **kwargs)
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        print(f"OpenAI client initialized")
    
    def query(self, prompt: str, model: str = "gpt-3.5-turbo", 
              max_tokens: int = 4000, temperature: float = 0.1, **kwargs) -> str:
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature
        }
        payload.update(kwargs)
        
        try:
            response = requests.post(self.base_url, headers=self.headers, json=payload, timeout=120)
            response.raise_for_status()
            
            result = response.json()
            return result['choices'][0]['message']['content']
            
        except requests.exceptions.Timeout:
            return "Error: Request timeout"
        except requests.exceptions.RequestException as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Error: {e}"
    
    def test_connection(self) -> bool:
        response = self.query("Hello, respond with 'Connection successful'", max_tokens=50)
        
        success = "error" not in response.lower() and len(response) > 5
        
        if success:
            print("OpenAI API connection successful")
        else:
            print(f"OpenAI API connection failed: {response}")
        
        return success
