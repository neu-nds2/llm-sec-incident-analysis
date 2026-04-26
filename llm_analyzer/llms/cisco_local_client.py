#!/usr/bin/env python3
"""
Cisco Foundation-Sec Local Client
Runs Cisco's cybersecurity-specialized LLM locally via Hugging Face Transformers
"""

import os
import sys
from typing import Optional

from llms.base_llm_client import BaseLLMClient


class CiscoFoundationLocalClient(BaseLLMClient):
    """
    Local client for Cisco Foundation-Sec-8B models via Hugging Face Transformers
    
    Models:
    - fdtn-ai/Llama-3.1-FoundationAI-SecurityLLM-8B-Instruct (chat/instruct)
    - fdtn-ai/Llama-3.1-FoundationAI-SecurityLLM-8B-Reasoning (reasoning)
    """
    
    def __init__(self, 
                 model: str = "fdtn-ai/Llama-3.1-FoundationAI-SecurityLLM-8B-Instruct",
                 device: str = "auto",
                 load_in_8bit: bool = False,
                 load_in_4bit: bool = False,
                 torch_dtype: str = "float16",
                 force_cpu: bool = False,
                 num_ctx: int = 16384,
                 **kwargs):
        """
        Initialize Cisco Foundation-Sec local client
        
        Args:
            model: Model name on Hugging Face OR local path
            device: Device to use ('auto', 'cuda', 'cpu', 'mps')
            load_in_8bit: Use 8-bit quantization (saves memory)
            load_in_4bit: Use 4-bit quantization (saves more memory)
            torch_dtype: Torch dtype ('auto', 'float16', 'bfloat16')
            force_cpu: Force CPU usage (NOT recommended with GPU available)
            num_ctx: Context window size (default: 16384)
        """
        super().__init__(model=model, num_ctx=num_ctx, **kwargs)
        
        self.model_name = model
        self.model = None
        self.tokenizer = None
        self.device = None
        self.num_ctx = num_ctx
        
        print(f"Cisco Foundation-Sec Local Client")
        print(f"   Model: {model}")
        print(f"   Context window: {num_ctx}")
        
        if force_cpu:
            print(f"   Warning: force_cpu=True - using CPU (SLOW!)")
            self.device = "cpu"
        else:
            self.device = device
        
        self._load_model(load_in_8bit, load_in_4bit, torch_dtype, force_cpu)
    
    def _load_model(self, load_in_8bit: bool, load_in_4bit: bool, 
                    torch_dtype: str, force_cpu: bool):
        """Load the model from Hugging Face or local path"""
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
            
            print(f"Loading model: {self.model_name}")
            print(f"   This may take a few minutes on first run...")
            
            # Determine device
            if force_cpu:
                device_map = "cpu"
                print(f"   Forcing CPU (will be slow!)")
            elif torch.cuda.is_available():
                device_map = "auto"
                print(f"   Using CUDA GPU(s)")
                for i in range(torch.cuda.device_count()):
                    props = torch.cuda.get_device_properties(i)
                    print(f"      GPU {i}: {props.name} ({props.total_memory // 1024**3}GB)")
            else:
                device_map = "cpu"
                print(f"   No GPU found, using CPU (will be slow!)")
            
            # Determine torch dtype
            if torch_dtype == "float16":
                dtype = torch.float16
            elif torch_dtype == "bfloat16":
                dtype = torch.bfloat16
            elif torch_dtype == "auto":
                dtype = torch.float16 if torch.cuda.is_available() else torch.float32
            else:
                dtype = torch.float32
            
            print(f"   Dtype: {dtype}")
            
            # Quantization config
            quantization_config = None
            if load_in_4bit and not force_cpu:
                quantization_config = BitsAndBytesConfig(
                    load_in_4bit=True,
                    bnb_4bit_compute_dtype=dtype,
                    bnb_4bit_use_double_quant=True,
                    bnb_4bit_quant_type="nf4"
                )
                print(f"   Using 4-bit quantization")
            elif load_in_8bit and not force_cpu:
                quantization_config = BitsAndBytesConfig(load_in_8bit=True)
                print(f"   Using 8-bit quantization")
            else:
                print(f"   No quantization (full precision)")
            
            # Load tokenizer
            print(f"   Loading tokenizer...")
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_name,
                trust_remote_code=True
            )
            
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            
            # Load model
            print(f"   Loading model weights...")
            model_kwargs = {
                "torch_dtype": dtype,
                "device_map": device_map,
                "trust_remote_code": True,
            }
            
            if quantization_config:
                model_kwargs["quantization_config"] = quantization_config
            
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                **model_kwargs
            )
            
            if device_map == "auto" and torch.cuda.is_available():
                self.device = "cuda"
            else:
                self.device = "cpu"
            
            print(f"Model loaded successfully!")
            print(f"   Device: {self.device}")
            
            if torch.cuda.is_available():
                for i in range(torch.cuda.device_count()):
                    memory_used = torch.cuda.memory_allocated(i) / 1024**3
                    memory_total = torch.cuda.get_device_properties(i).total_memory / 1024**3
                    print(f"   GPU {i} Memory: {memory_used:.1f}GB / {memory_total:.1f}GB")
            
        except ImportError as e:
            print(f"Missing dependencies: {e}")
            print(f"   Install with: pip install transformers torch accelerate")
            raise
        except Exception as e:
            print(f"Error loading model: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    def query(self, prompt: str, max_tokens: int = 2048, temperature: float = 0.1, **kwargs) -> str:
        """Query the local model"""
        if self.model is None:
            return "Error: Model not loaded"
        
        try:
            import torch
            
            # Format as chat if it's an instruct/reasoning model
            if "Instruct" in self.model_name or "Reasoning" in self.model_name or "instruct" in self.model_name.lower():
                messages = [
                    {"role": "system", "content": "You are a cybersecurity expert assistant specialized in incident response, threat analysis, and security operations."},
                    {"role": "user", "content": prompt}
                ]
                
                if hasattr(self.tokenizer, 'apply_chat_template'):
                    formatted_prompt = self.tokenizer.apply_chat_template(
                        messages, 
                        tokenize=False, 
                        add_generation_prompt=True
                    )
                else:
                    formatted_prompt = f"### System:\nYou are a cybersecurity expert.\n\n### User:\n{prompt}\n\n### Assistant:\n"
            else:
                formatted_prompt = prompt
            
            # Tokenize input
            inputs = self.tokenizer(
                formatted_prompt, 
                return_tensors="pt",
                truncation=True,
                max_length=self.num_ctx - max_tokens  # Leave room for generation
            )
            
            input_length = inputs['input_ids'].shape[1]
            
            if self.device == "cuda":
                inputs = {k: v.cuda() for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=max_tokens,
                    max_length=self.num_ctx,  # Total context limit
                    temperature=temperature if temperature > 0 else 0.01,
                    do_sample=temperature > 0,
                    top_p=0.9,
                    repetition_penalty=1.1,
                    pad_token_id=self.tokenizer.eos_token_id,
                )
            
            # Extract only the NEW tokens (not the input)
            new_tokens = outputs[0][input_length:]
            response = self.tokenizer.decode(new_tokens, skip_special_tokens=True).strip()
            
            return response
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return f"Error: Generation failed - {e}"
    
    def test_connection(self) -> bool:
        """Test if the model is loaded and working"""
        if self.model is None:
            print("Model not loaded")
            return False
        
        print(f"Testing Cisco Foundation-Sec model on {self.device}...")
        test_prompt = "What is a SQL injection attack? Answer in one sentence."
        response = self.query(test_prompt, max_tokens=100)
        
        success = len(response) > 20 and "error" not in response.lower()
        
        if success:
            print(f"Cisco Foundation-Sec model working on {self.device}!")
            print(f"   Context window: {self.num_ctx}")
            print(f"   Test response: {response[:100]}...")
        else:
            print(f"Model test failed: {response}")
        
        return success
    
    def get_model_info(self) -> dict:
        """Get information about the loaded model"""
        info = {
            "model_name": self.model_name,
            "provider": "Cisco Foundation AI (Local)",
            "specialization": "Cybersecurity",
            "context_window": self.num_ctx,
            "capabilities": [
                "Threat analysis",
                "Incident response", 
                "Log analysis",
                "Vulnerability assessment",
                "Security reasoning"
            ]
        }
        
        if self.model is not None:
            try:
                import torch
                total_params = sum(p.numel() for p in self.model.parameters())
                info["parameters"] = f"{total_params / 1e9:.1f}B"
                
                if torch.cuda.is_available():
                    info["gpu_memory_gb"] = f"{torch.cuda.memory_allocated() / 1024**3:.1f}"
            except:
                pass
        
        return info

