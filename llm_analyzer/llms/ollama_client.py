#!/usr/bin/env python3
"""
Ollama LLM Client
"""

import requests
from typing import Optional
from llms.base_llm_client import BaseLLMClient


class OllamaClient(BaseLLMClient):
    """Ollama local LLM client"""
    
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "qwen2.5:7b", 
                 num_ctx: int = 16384, **kwargs):
        super().__init__(base_url=base_url, model=model, num_ctx=num_ctx, **kwargs)
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.num_ctx = num_ctx  # Context window size
        self.chat_url = f"{self.base_url}/api/chat"
        self.generate_url = f"{self.base_url}/api/generate"
        self.tags_url = f"{self.base_url}/api/tags"
        print(f"Ollama client initialized (model: {model}, context: {num_ctx})")
    
    def query(self, prompt: str, max_tokens: int = 4000, temperature: float = 0.1, **kwargs) -> str:
        # Build options with context window
        options = {
            "temperature": temperature,
            "num_predict": max_tokens,
            "num_ctx": self.num_ctx  # Set context window size
        }
        if kwargs:
            options.update(kwargs)
        
        # Try chat format first
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "options": options
        }
        
        try:
            response = requests.post(self.chat_url, json=payload, timeout=300)
            if response.status_code == 200:
                result = response.json()
                return result.get('message', {}).get('content', "Error: No content")
        except:
            pass
        
        # Fallback to generate endpoint
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": options
        }
        
        try:
            response = requests.post(self.generate_url, json=payload, timeout=300)
            response.raise_for_status()
            result = response.json()
            return result.get('response', "Error: No response")
            
        except requests.exceptions.Timeout:
            return "Error: Request timeout"
        except requests.exceptions.ConnectionError:
            return f"Error: Cannot connect to Ollama at {self.base_url}"
        except Exception as e:
            return f"Error: {e}"
    
    def test_connection(self) -> bool:
        try:
            # Check if Ollama is running
            response = requests.get(self.tags_url, timeout=10)
            if response.status_code != 200:
                print(f"Ollama server not responding: {response.status_code}")
                return False
            
            # Check if model exists
            models = response.json().get('models', [])
            model_names = [m['name'] for m in models]
            
            model_found = any(
                self.model == name or 
                self.model in name or 
                name.startswith(self.model.split(':')[0])
                for name in model_names
            )
            
            if not model_found:
                print(f"Model '{self.model}' not found. Available: {', '.join(model_names[:5])}")
                print(f"Install with: ollama pull {self.model}")
                return False
            
            # Test query
            test_response = self.query("Hello, respond with 'OK'", max_tokens=20)
            success = "error" not in test_response.lower() and len(test_response) > 1
            
            if success:
                print(f"Ollama connection successful (model: {self.model}, ctx: {self.num_ctx})")
            else:
                print(f"Ollama test failed: {test_response}")
            
            return success
            
        except requests.exceptions.ConnectionError:
            print(f"Ollama not running. Start with: ollama serve")
            return False
        except Exception as e:
            print(f"Ollama connection error: {e}")
            return False
    
    def list_models(self) -> list:
        """Get available models"""
        try:
            response = requests.get(self.tags_url, timeout=10)
            if response.status_code == 200:
                return [m['name'] for m in response.json().get('models', [])]
            return []
        except:
            return []

