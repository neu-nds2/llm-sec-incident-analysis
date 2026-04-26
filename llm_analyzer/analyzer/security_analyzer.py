#!/usr/bin/env python3
"""
Security Incident Analyzer
Simple, explicit configuration - no hidden defaults
"""

import os
import sys
from typing import List, Dict
from datetime import datetime

from analyzer.security_rag import SecurityRAG
from analyzer.prompt_templates import PromptTemplates
from llms.base_llm_client import BaseLLMClient
from llms.llm_factory import LLMFactory


class SecurityAnalyzer:
    """Security incident analyzer with explicit settings"""
    
    # Default settings (can be overridden)
    DEFAULT_SETTINGS = {
        'max_chunks': 7,           # Number of RAG chunks per question
        'max_tokens': 4000,        # Max response tokens
        'temperature': 0.1,        # LLM temperature
        'max_prompt_length': 60000, # Max prompt length in chars
    }
    
    def __init__(self, llm_client: BaseLLMClient, settings: Dict = None):
        self.rag = SecurityRAG()
        self.llm = llm_client
        self.network_context = ""
        
        # Use provided settings or defaults
        self.settings = {**self.DEFAULT_SETTINGS, **(settings or {})}
        
        print(f"{self.llm.get_provider_name()} analyzer initialized")
        print(f"   chunks={self.settings['max_chunks']}, tokens={self.settings['max_tokens']}, "
              f"temp={self.settings['temperature']}, max_prompt={self.settings['max_prompt_length']}")
    
    @classmethod
    def create(cls, provider: str, settings: Dict = None, **llm_config):
        """Create analyzer for a provider"""
        llm_client = LLMFactory.create_client(provider, **llm_config)
        return cls(llm_client, settings)
    
    def load_data(self, directory: str, cache_file: str = "cache/embeddings.pkl", 
                  rebuild_cache: bool = False) -> bool:
        """Load and index security documents"""
        print(f"Loading from: {directory}")
        
        chunks_loaded = self.rag.load_documents(directory)
        if chunks_loaded == 0:
            return False
        
        cache_dir = os.path.dirname(cache_file)
        if cache_dir and not os.path.exists(cache_dir):
            os.makedirs(cache_dir, exist_ok=True)
        
        success = self.rag.build_index(cache_file, force_rebuild=rebuild_cache)
        
        if success:
            stats = self.rag.get_stats()
            print(f"Indexed: {stats['total_chunks']} chunks from {stats['files']} files")
        
        return success
    
    def analyze_question(self, question: str, debug: bool = False):
        """Analyze a single question.

        Returns (answer_text, retrieved_filenames) so callers can record which
        chunks were available to the LLM, independent of which it cited.
        """
        chunks = self.rag.search(question, top_k=self.settings['max_chunks'])

        if not chunks:
            return "Not found in provided data", []

        retrieved = [meta['filename'] for _, _, meta in chunks]

        if debug:
            print(f"\nQuestion: {question}")
            print(f"   Retrieved {len(chunks)} chunks")
            for i, (text, score, meta) in enumerate(chunks, 1):
                print(f"   [{i}] {meta['filename']} (score: {score:.3f})")

        prompt = PromptTemplates.build_analysis_prompt(
            question, chunks, self.network_context,
            max_length=self.settings['max_prompt_length']
        )

        if debug:
            print(f"   Prompt length: {len(prompt)} chars")

        try:
            response = self.llm.query(
                prompt,
                max_tokens=self.settings['max_tokens'],
                temperature=self.settings['temperature']
            )
            return response.strip(), retrieved
        except Exception as e:
            return f"Error: {e}", retrieved
    
    def analyze(self, questions: List[str], debug: bool = False) -> str:
        """Analyze all questions and generate report"""
        import time
        
        start_time = time.time()
        
        print(f"\nAnalyzing {len(questions)} questions with {self.llm.get_provider_name()}")
        
        results = []
        for i, question in enumerate(questions, 1):
            print(f"[{i}/{len(questions)}] {question[:60]}...")
            answer, retrieved = self.analyze_question(question, debug=debug)
            retrieved_line = "RETRIEVED CHUNKS = [" + ", ".join(retrieved) + "]"
            results.append(f"**{i}. {question}**\n{answer}\n\n{retrieved_line}")
        
        # Generate summary
        print("Generating summary...")
        summary = self._generate_summary(results)
        
        duration = time.time() - start_time
        stats = self.rag.get_stats()
        
        report = f"""# SECURITY INCIDENT ANALYSIS

## FINDINGS

{chr(10).join(results)}

## SUMMARY

{summary}

## METADATA

- **Provider:** {self.llm.get_provider_name()}
- **Questions:** {len(questions)}
- **Data:** {stats['files']} files, {stats['total_chunks']} chunks
- **Settings:** chunks={self.settings['max_chunks']}, tokens={self.settings['max_tokens']}, temp={self.settings['temperature']}, max_prompt={self.settings['max_prompt_length']}
- **Duration:** {duration:.1f}s
- **Date:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
        
        print(f"Analysis complete in {duration:.1f}s")
        return report
    
    def _generate_summary(self, results: List[str]) -> str:
        """Generate summary of findings"""
        results_text = "\n".join(results)[:3000]
        
        prompt = f"""Summarize this security incident analysis in 3 sentences.
Focus on: attack type, key indicators, recommended actions.

{results_text}

Summary:"""
        
        try:
            return self.llm.query(prompt, max_tokens=300, temperature=0.1)
        except Exception as e:
            return f"Summary failed: {e}"
