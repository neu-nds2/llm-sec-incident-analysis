#!/usr/bin/env python3
"""
Security Log Analyzer CLI
Simple, explicit configuration - no hidden provider-specific defaults
"""

import argparse
import sys
import os

from analyzer.security_analyzer import SecurityAnalyzer
from analyzer.security_rag import SecurityRAG
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


def main():
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer - Analyze logs with LLMs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Anthropic
  %(prog)s ./data --provider anthropic --api-key-file key.txt \\
      --questions-file questions.txt --network-file network.txt

  # Ollama (local) with extended context
  %(prog)s ./data --provider ollama --model qwen2.5:7b --num-ctx 32768 \\
      --questions-file questions.txt --network-file network.txt

  # Cisco Foundation (local) with extended context
  %(prog)s ./data --provider cisco --num-ctx 16384 \\
      --questions-file questions.txt --network-file network.txt

  # Build cache only
  %(prog)s ./data --build-cache-only
        """
    )
    
    # Data
    parser.add_argument("directory", nargs='?', help="Directory with *_result.json files")
    parser.add_argument("--build-cache-only", action="store_true", help="Build cache and exit")
    parser.add_argument("--cache", default="cache/embeddings.pkl", help="Cache file")
    parser.add_argument("--rebuild-cache", action="store_true", help="Force rebuild cache")
    
    # Provider
    parser.add_argument("--provider", choices=LLMFactory.get_available_providers())
    parser.add_argument("--model", help="Model name")
    parser.add_argument("--api-key", help="API key")
    parser.add_argument("--api-key-file", help="File with API key")
    
    # Local model context size (Ollama and Cisco)
    parser.add_argument("--num-ctx", type=int, default=16384, 
                        help="Context window size for local models (Ollama/Cisco, default: 16384)")
    
    # Required config files
    parser.add_argument("--questions-file", help="Questions file (required)")
    parser.add_argument("--network-file", help="Network context file (required)")
    
    # Analysis settings (explicit, same for all providers)
    parser.add_argument("--max-chunks", type=int, default=7, help="RAG chunks per question (default: 7)")
    parser.add_argument("--max-tokens", type=int, default=4000, help="Max response tokens (default: 4000)")
    parser.add_argument("--temperature", type=float, default=0.1, help="LLM temperature (default: 0.1)")
    parser.add_argument("--max-prompt", type=int, default=60000, help="Max prompt length (default: 60000)")
    
    # Output
    parser.add_argument("--output", default="analysis.md", help="Output file")
    parser.add_argument("--debug", action="store_true", help="Show debug info")
    
    args = parser.parse_args()
    
    # Validate directory
    if not args.directory:
        parser.print_help()
        sys.exit(1)
    
    if not os.path.isdir(args.directory):
        print(f"Directory not found: {args.directory}")
        sys.exit(1)
    
    # Build cache only mode
    if args.build_cache_only:
        cache_dir = os.path.dirname(args.cache)
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)
        
        rag = SecurityRAG()
        chunks = rag.load_documents(args.directory)
        
        if chunks == 0:
            print(f"No documents found")
            sys.exit(1)
        
        if rag.build_index(args.cache, force_rebuild=True):
            stats = rag.get_stats()
            print(f"Cache: {stats['total_chunks']} chunks, {stats['files']} files → {args.cache}")
        else:
            print("Cache build failed")
            sys.exit(1)
        return
    
    # Validate required args for analysis
    if not args.provider:
        print("--provider required")
        sys.exit(1)
    
    if not args.questions_file or not os.path.exists(args.questions_file):
        print(f"--questions-file required (file: {args.questions_file})")
        sys.exit(1)
    
    if not args.network_file or not os.path.exists(args.network_file):
        print(f"--network-file required (file: {args.network_file})")
        sys.exit(1)
    
    # Load config
    questions = load_questions(args.questions_file)
    network_context = load_text(args.network_file)
    print(f"{len(questions)} questions from {args.questions_file}")
    print(f"Network context from {args.network_file}")
    
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
    
    if args.provider == 'ollama' and not args.model:
        print("ollama requires --model")
        sys.exit(1)
    
    if args.model:
        llm_config['model'] = args.model
    
    # Local model context size (Ollama and Cisco)
    if args.provider in ['ollama', 'cisco']:
        llm_config['num_ctx'] = args.num_ctx
    
    # Analysis settings
    settings = {
        'max_chunks': args.max_chunks,
        'max_tokens': args.max_tokens,
        'temperature': args.temperature,
        'max_prompt_length': args.max_prompt,
    }
    
    # Run analysis
    try:
        analyzer = SecurityAnalyzer.create(args.provider, settings, **llm_config)
        analyzer.network_context = network_context
        
        print(f"Testing {args.provider}...")
        if not analyzer.llm.test_connection():
            print("Connection failed")
            sys.exit(1)
        
        if not analyzer.load_data(args.directory, args.cache, args.rebuild_cache):
            print("Failed to load data")
            sys.exit(1)
        
        report = analyzer.analyze(questions, debug=args.debug)
        
        # Save
        output_dir = os.path.dirname(args.output)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report)        
        
        print(f"Report saved: {args.output}")
        
    except KeyboardInterrupt:
        print("\nInterrupted")
        sys.exit(1)
    except Exception as e:
        print(f"{e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

