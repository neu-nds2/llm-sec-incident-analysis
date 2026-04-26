#!/usr/bin/env python3
"""
No-RAG Security Analyzer
Sends raw logs directly to LLM without any retrieval system
For experiments comparing RAG vs full-context approaches
"""

import os
import sys
import json
import glob
import argparse
import re
import time
from datetime import datetime
from typing import List, Dict, Any, Optional

# Add parent directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from llms.llm_factory import LLMFactory


def load_questions(path: str) -> list:
    """Load questions from file (one per line, # = comment)"""
    with open(path, 'r') as f:
        lines = f.read().strip().split('\n')
        return [l.strip() for l in lines if l.strip() and not l.strip().startswith('#')]


def load_text(path: str) -> str:
    """Load text file"""
    with open(path, 'r') as f:
        return f.read().strip()


class NoRAGAnalyzer:
    """
    Simple analyzer that sends all logs directly to the LLM
    No embedding, no vector search, no retrieval - just raw context
    """
    
    # Approximate token limits per provider (conservative estimates)
    CONTEXT_LIMITS = {
        'anthropic': 180000,
        'openai': 25000,
        'deepseek': 115000,
        'ollama': 28000,
        'cisco': 6000,
    }
    
    CHARS_PER_TOKEN = 2.5
    
    def __init__(self, llm_client, max_tokens: Optional[int] = None, dump_prompt_dir: Optional[str] = None):
        self.llm = llm_client
        self.provider = llm_client.get_provider_name().lower()
        
        if max_tokens:
            self.max_context_tokens = max_tokens
        else:
            self.max_context_tokens = self.CONTEXT_LIMITS.get(self.provider, 8000)
        
        self.max_context_chars = int(self.max_context_tokens * self.CHARS_PER_TOKEN)
        
        self.logs = []
        self.log_stats = {}
        self.network_context = ""
        self.dump_prompt_dir = dump_prompt_dir
        
        if self.dump_prompt_dir:
            os.makedirs(self.dump_prompt_dir, exist_ok=True)
        
        print(f"No-RAG Analyzer initialized")
        print(f"   Provider: {self.provider}")
        print(f"   Max context: ~{self.max_context_tokens:,} tokens ({self.max_context_chars:,} chars)")
    
    def load_raw_logs(self, directory: str, file_pattern: str = "*_result.json") -> int:
        """Load raw logs from directory"""
        print(f"Loading logs from: {directory}")
        
        pattern = os.path.join(directory, "**", file_pattern)
        files = glob.glob(pattern, recursive=True)
        
        if not files:
            print(f"No files matching '{file_pattern}' found")
            return 0
        
        print(f"   Found {len(files)} files")
        
        all_logs = []
        files_processed = 0
        
        for file_path in sorted(files):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                if 'response' in data and 'hits' in data['response']:
                    hits = data['response']['hits'].get('hits', [])
                    for hit in hits:
                        log_entry = {
                            'file': os.path.basename(file_path),
                            'data': hit.get('_source', hit)
                        }
                        all_logs.append(log_entry)
                
                elif 'logs' in data:
                    for log in data['logs']:
                        log_entry = {
                            'file': os.path.basename(file_path),
                            'data': log.get('_source', log)
                        }
                        all_logs.append(log_entry)
                
                files_processed += 1
                
            except Exception as e:
                print(f"   Warning: Error reading {file_path}: {e}")
        
        self.logs = all_logs
        self.log_stats = {
            'total_logs': len(all_logs),
            'files_processed': files_processed,
            'directory': directory
        }
        
        print(f"   Loaded {len(all_logs):,} log entries from {files_processed} files")
        return len(all_logs)
    
    def load_network_context(self, context_file: str = None) -> str:
        """Load network context"""
        if context_file and os.path.exists(context_file):
            self.network_context = load_text(context_file)
            print(f"Network context loaded from {context_file}")
        else:
            self.network_context = ""
            print("No network context file provided")
        return self.network_context
    
    def _format_logs_for_prompt(self, max_chars: int) -> tuple:
        """Format logs for inclusion in prompt"""
        if not self.logs:
            return "No logs available.", 0
        
        formatted_logs = []
        current_chars = 0
        logs_included = 0
        
        for i, log in enumerate(self.logs):
            log_str = json.dumps(log['data'], separators=(',', ':'), default=str)
            entry = f"[{i+1}] {log_str}\n"
            
            if current_chars + len(entry) > max_chars:
                break
            
            formatted_logs.append(entry)
            current_chars += len(entry)
            logs_included += 1
        
        return ''.join(formatted_logs), logs_included
    
    def _build_prompt(self, question: str, logs_text: str, logs_included: int) -> str:
        """Build the analysis prompt"""
        network_info = ""
        if self.network_context:
            lines = self.network_context.split('\n')
            essential = [l.strip() for l in lines 
                        if l.strip() and not l.strip().startswith('#')
                        and any(k in l.lower() for k in ['range:', 'domain:', 'controller:', 'gateway:'])]
            network_info = '; '.join(essential[:4])
        
        prompt = f"""You are a cybersecurity analyst investigating a security incident.

TASK: Analyze the raw security logs below and answer this question:
{question}

INSTRUCTIONS:
- Search through ALL the logs provided
- Look for specific evidence: IP addresses, timestamps, hostnames, user accounts, domains
- If you find relevant information, cite the log entry number [N]
- If the information is not found in the logs, say "Not found in provided logs"
- Be specific and cite evidence

NETWORK CONTEXT: {network_info}

RAW SECURITY LOGS ({logs_included:,} entries from {self.log_stats.get('total_logs', 0):,} total):
{logs_text}

ANSWER:"""
        
        return prompt
    
    def analyze_question(self, question: str, debug: bool = False, 
                         max_retries: int = 5, retry_delay: int = 60) -> Dict[str, Any]:
        """Analyze a single question against all logs"""
        start_time = time.time()
        
        PROVIDER_TOKEN_LIMITS = {
            'anthropic': 200000,
            'openai': 25000,
            'deepseek': 128000,
            'ollama': 32000,
            'cisco': 8000,
        }
        provider_limit = PROVIDER_TOKEN_LIMITS.get(self.provider, 32000)
        
        logs_budget = self.max_context_chars - 2000
        logs_text, logs_included = self._format_logs_for_prompt(logs_budget)
        prompt = self._build_prompt(question, logs_text, logs_included)
        estimated_tokens = len(prompt) // 2
        
        if debug:
            print(f"\n   Question: {question}")
            print(f"   Logs included: {logs_included:,} / {len(self.logs):,}")
            print(f"   Prompt length: {len(prompt):,} chars (~{estimated_tokens:,} tokens)")
        
        # Pre-flight check
        if estimated_tokens > provider_limit:
            print(f"   Warning: Prompt too large (~{estimated_tokens:,} > {provider_limit:,} tokens)")
            print(f"   Auto-adjusting...")
            
            target_tokens = int(provider_limit * 0.85)
            target_chars = target_tokens * 2
            
            self.max_context_chars = target_chars
            self.max_context_tokens = target_tokens
            
            new_budget = target_chars - 2000
            logs_text, logs_included = self._format_logs_for_prompt(new_budget)
            prompt = self._build_prompt(question, logs_text, logs_included)
            estimated_tokens = len(prompt) // 2
            
            print(f"   Adjusted to {logs_included:,} logs (~{estimated_tokens:,} tokens)")
        
        # Save prompt if requested
        if self.dump_prompt_dir:
            safe_question = re.sub(r'[^\w\s-]', '', question)[:50].strip().replace(' ', '_')
            prompt_file = os.path.join(self.dump_prompt_dir, f"prompt_{safe_question}.txt")
            with open(prompt_file, 'w', encoding='utf-8') as f:
                f.write(f"=== QUESTION ===\n{question}\n\n")
                f.write(f"=== STATS ===\n")
                f.write(f"Logs included: {logs_included} / {len(self.logs)}\n")
                f.write(f"Prompt length: {len(prompt)} chars\n\n")
                f.write(f"=== FULL PROMPT ===\n{prompt}\n")
            print(f"   Prompt saved to: {prompt_file}")
        
        # Query LLM with retry logic
        last_error = None
        for attempt in range(max_retries):
            try:
                response = self.llm.query(prompt, max_tokens=1500, temperature=0.1)
                duration = time.time() - start_time
                
                response_lower = response.lower() if response else ""
                
                # Handle rate limit
                if 'rate limit' in response_lower or '429' in response_lower:
                    wait_time = retry_delay * (attempt + 1)
                    print(f"   Rate limited (attempt {attempt + 1}/{max_retries})")
                    if attempt < max_retries - 1:
                        print(f"   Waiting {wait_time}s...")
                        time.sleep(wait_time)
                        continue
                    else:
                        return {
                            'question': question,
                            'answer': f"Rate limit exceeded after {max_retries} retries",
                            'logs_analyzed': logs_included,
                            'total_logs': len(self.logs),
                            'prompt_chars': len(prompt),
                            'duration_seconds': duration,
                            'success': False
                        }
                
                # Success
                if debug:
                    print(f"   Response received ({duration:.1f}s)")
                
                return {
                    'question': question,
                    'answer': response.strip(),
                    'logs_analyzed': logs_included,
                    'total_logs': len(self.logs),
                    'prompt_chars': len(prompt),
                    'duration_seconds': duration,
                    'success': True
                }
                
            except Exception as e:
                last_error = str(e)
                if debug:
                    print(f"   Error: {last_error}")
                break
        
        duration = time.time() - start_time
        return {
            'question': question,
            'answer': f"Error: {last_error}",
            'logs_analyzed': logs_included,
            'total_logs': len(self.logs),
            'prompt_chars': len(prompt),
            'duration_seconds': duration,
            'success': False
        }
    
    def analyze_all_questions(self, questions: List[str], debug: bool = False, 
                               delay_seconds: int = 60) -> Dict[str, Any]:
        """Analyze all questions"""
        print(f"\nStarting No-RAG analysis")
        print(f"   Provider: {self.provider}")
        print(f"   Questions: {len(questions)}")
        print(f"   Total logs: {len(self.logs):,}")
        print(f"   Delay between questions: {delay_seconds}s")
        
        start_time = time.time()
        results = []
        
        for i, question in enumerate(questions, 1):
            print(f"\n[{i}/{len(questions)}] {question}")
            
            result = self.analyze_question(question, debug=debug)
            results.append(result)
            
            if result['success']:
                print(f"   Completed ({result['duration_seconds']:.1f}s)")
            else:
                print(f"   Failed: {result['answer'][:100]}")
            
            if i < len(questions):
                print(f"   Waiting {delay_seconds}s...")
                time.sleep(delay_seconds)
        
        total_duration = time.time() - start_time
        
        analysis = {
            'metadata': {
                'provider': self.provider,
                'model': self.llm.config.get('model', 'default'),
                'approach': 'no-rag-full-context',
                'total_logs_available': len(self.logs),
                'logs_analyzed_per_question': results[0]['logs_analyzed'] if results else 0,
                'max_context_tokens': self.max_context_tokens,
                'questions_count': len(questions),
                'total_duration_seconds': total_duration,
                'analysis_timestamp': datetime.now().isoformat(),
                'log_source': self.log_stats
            },
            'results': results
        }
        
        return analysis
    
    def generate_report(self, analysis: Dict[str, Any]) -> str:
        """Generate markdown report from analysis"""
        meta = analysis['metadata']
        results = analysis['results']
        
        findings = []
        for i, r in enumerate(results, 1):
            findings.append(f"**{i}. {r['question']}**\n\n{r['answer']}\n")
        
        report = f"""# SECURITY INCIDENT ANALYSIS (No-RAG Full Context)

## APPROACH

This analysis used the **No-RAG Full Context** approach:
- All available logs were sent directly to the LLM
- No vector search or retrieval system
- The LLM searched through raw logs to find answers

## FINDINGS

{chr(10).join(findings)}

## METADATA

- **Provider:** {meta['provider']}
- **Model:** {meta.get('model', 'default')}
- **Approach:** {meta['approach']}
- **Total Logs Available:** {meta['total_logs_available']:,}
- **Logs Analyzed Per Question:** {meta['logs_analyzed_per_question']:,}
- **Context Limit:** ~{meta['max_context_tokens']:,} tokens
- **Questions Processed:** {meta['questions_count']}
- **Total Duration:** {meta['total_duration_seconds']:.1f}s
- **Avg Time Per Question:** {meta['total_duration_seconds']/meta['questions_count']:.1f}s
- **Analysis Date:** {meta['analysis_timestamp']}

---
*Generated by No-RAG Security Analyzer*
"""
        return report


def main():
    parser = argparse.ArgumentParser(
        description="No-RAG Security Analyzer - Send raw logs directly to LLM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyzer/no_rag_analyzer.py ./raw_logs \\
      --provider anthropic --api-key-file keys/anthropic.txt \\
      --questions-file config/questions.txt \\
      --network-file config/network.txt
        """
    )
    
    parser.add_argument("directory", help="Directory containing log files")
    parser.add_argument("--provider", required=True, 
                        choices=['anthropic', 'openai', 'deepseek', 'ollama', 'cisco'])
    parser.add_argument("--model", help="Model name")
    parser.add_argument("--api-key", help="API key")
    parser.add_argument("--api-key-file", help="File containing API key")
    parser.add_argument("--questions-file", required=True, help="Questions file")
    parser.add_argument("--network-file", help="Network context file")
    parser.add_argument("--output", default="reports/no_rag_analysis.md", help="Output file")
    parser.add_argument("--max-tokens", type=int, help="Override context token limit")
    parser.add_argument("--no-limit", action="store_true", help="Send all logs (may error)")
    parser.add_argument("--delay", type=int, default=60, help="Seconds between questions")
    parser.add_argument("--dump-prompt", help="Save prompts to this directory")
    parser.add_argument("--debug", action="store_true", help="Show debug info")
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.directory):
        print(f"Directory not found: {args.directory}")
        sys.exit(1)
    
    if not os.path.exists(args.questions_file):
        print(f"Questions file not found: {args.questions_file}")
        sys.exit(1)
    
    # Build LLM config
    llm_config = {}
    
    if args.provider in ['anthropic', 'openai', 'deepseek']:
        if args.api_key:
            llm_config['api_key'] = args.api_key
        elif args.api_key_file:
            llm_config['api_key'] = load_text(args.api_key_file)
        else:
            print(f"{args.provider} requires --api-key or --api-key-file")
            sys.exit(1)
    
    if args.model:
        llm_config['model'] = args.model
    elif args.provider == 'ollama':
        print("ollama requires --model")
        sys.exit(1)
    
    # Create LLM client
    print(f"Initializing {args.provider}...")
    try:
        llm_client = LLMFactory.create_client(args.provider, **llm_config)
    except Exception as e:
        print(f"Failed to create LLM client: {e}")
        sys.exit(1)
    
    print(f"Testing connection...")
    if not llm_client.test_connection():
        print(f"Failed to connect to {args.provider}")
        sys.exit(1)
    
    # Create analyzer
    if args.no_limit:
        analyzer = NoRAGAnalyzer(llm_client, max_tokens=999999999, dump_prompt_dir=args.dump_prompt)
        print("Warning: No input limit - will send ALL logs")
    else:
        analyzer = NoRAGAnalyzer(llm_client, max_tokens=args.max_tokens, dump_prompt_dir=args.dump_prompt)
    
    # Load data
    log_count = analyzer.load_raw_logs(args.directory)
    if log_count == 0:
        print("No logs loaded")
        sys.exit(1)
    
    analyzer.load_network_context(args.network_file)
    
    # Load questions
    questions = load_questions(args.questions_file)
    print(f"Loaded {len(questions)} questions from {args.questions_file}")
    
    # Run analysis
    analysis = analyzer.analyze_all_questions(questions, debug=args.debug, delay_seconds=args.delay)
    
    # Save report
    report = analyzer.generate_report(analysis)
    
    output_dir = os.path.dirname(args.output)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    with open(args.output, 'w') as f:
        f.write(report)
    
    print(f"\nAnalysis complete!")
    print(f"Report saved to: {args.output}")
    
    meta = analysis['metadata']
    print(f"\nSummary:")
    print(f"   Logs analyzed: {meta['logs_analyzed_per_question']:,} / {meta['total_logs_available']:,}")
    print(f"   Questions: {meta['questions_count']}")
    print(f"   Total time: {meta['total_duration_seconds']:.1f}s")


if __name__ == "__main__":
    main()
