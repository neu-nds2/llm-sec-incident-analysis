#!/usr/bin/env python3
"""
Run LLM analysis across all providers and scenarios.

All scenarios use self-contained evaluation/<scenario>/ directories:
  config/questions.txt, config/answers.txt, config/network.txt
  es_results/          (query result JSON files)
  llm_reports/         (output)

Usage:
  python run_sweep.py                                    # full sweep (cloud)
  python run_sweep.py --providers anthropic deepseek     # subset
  python run_sweep.py --scenarios fake_auth iced_id      # subset
  python run_sweep.py --include-local                    # include Ollama/Cisco
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent       # final_release/
EVAL_DIR = ROOT / "evaluation"
ANALYZER = ROOT / "llm_analyzer"
KEYS = ANALYZER / "keys"   # Create this directory with your API key files

# --- Scenarios ---------------------------------------------------------------

SCENARIOS = [
    "fake_auth", "koi_stealer", "net_rat", "dirty_rat", "warmcookie",
    "lumma_stealer", "iced_id", "gozi", "qakbot", "redline_stlr",
    "dec21isc", "apr21isc", "may21isc", "burnincandle", "easy_123",
    "oct21isc", "jun21isc",
]

# --- Providers ---------------------------------------------------------------

CLOUD_PROVIDERS = {
    "anthropic":       ["anthropic", "--api-key-file", str(KEYS / "anthropic.txt")],
    "deepseek":        ["deepseek",  "--api-key-file", str(KEYS / "deepseek.txt")],
    "openai_gpt4":     ["openai",    "--model", "gpt-4",      "--api-key-file", str(KEYS / "openai.txt")],
    "openai_gpt4o":    ["openai",    "--model", "gpt-4o",     "--api-key-file", str(KEYS / "openai.txt")],
    "openai_gpt5mini": ["openai",    "--model", "gpt-5-mini", "--api-key-file", str(KEYS / "openai.txt")],
    "openai_gpt52":    ["openai",    "--model", "gpt-5.2",    "--api-key-file", str(KEYS / "openai.txt")],
}

LOCAL_PROVIDERS = {
    "ollama": ["ollama", "--model", "llama3.1:70b", "--num-ctx", "32768"],
    "cisco":  ["cisco",  "--model", os.path.expanduser("~/Foundation-Sec-8B-Reasoning/"), "--num-ctx", "16384"],
}


def _find_cache(scen_dir: Path, scenario: str) -> Path:
    """Find existing cache .pkl in the scenario's cache_embeddings/ dir,
    or return a default path for new cache creation."""
    cache_dir = scen_dir / "cache_embeddings"
    if cache_dir.exists():
        pkls = list(cache_dir.glob("*.pkl"))
        if pkls:
            return pkls[0]
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / f"{scenario}_embeddings.pkl"


def resolve_paths(scenario: str, max_chunks: int = 7):
    """Return paths dict for a scenario.

    Output dir includes k when k != 7 (the default) to avoid overwriting.
    """
    scen_dir = EVAL_DIR / scenario
    out_suffix = "llm_reports" if max_chunks == 7 else f"llm_reports_k{max_chunks}"
    return {
        "data_dir": scen_dir / "es_results",
        "net_file": scen_dir / "config" / "network.txt",
        "q_file":   scen_dir / "config" / "questions.txt",
        "cache":    _find_cache(scen_dir, scenario),
        "out_dir":  scen_dir / out_suffix,
    }


def run_analysis(scenario: str, label: str, provider_args: list, paths: dict):
    """Run analyze.py for one (scenario, provider) pair."""
    paths["out_dir"].mkdir(parents=True, exist_ok=True)
    out_file = paths["out_dir"] / f"{scenario}_{label}.md"

    cmd = [
        sys.executable, "analyze.py",
        str(paths["data_dir"]),
        "--provider", provider_args[0],
        *provider_args[1:],
        "--questions-file", str(paths["q_file"]),
        "--network-file",  str(paths["net_file"]),
        "--cache",         str(paths["cache"]),
        "--max-chunks",    str(paths["max_chunks"]),
        "--max-prompt",    str(paths["max_prompt"]),
        "--output",        str(out_file),
    ]

    print(f"=== {scenario} / {label} ===")
    result = subprocess.run(cmd, cwd=str(ANALYZER))
    return result.returncode


def main():
    parser = argparse.ArgumentParser(description="Sweep LLM providers across scenarios")
    parser.add_argument("--scenarios", nargs="+", default=SCENARIOS,
                        help="Scenarios to run (default: all)")
    parser.add_argument("--providers", nargs="+", default=None,
                        help="Provider labels to run (default: all cloud)")
    parser.add_argument("--include-local", action="store_true",
                        help="Include local providers (Ollama, Cisco)")
    parser.add_argument("--max-chunks", type=int, default=7,
                        help="Number of RAG chunks per question (default: 7)")
    parser.add_argument("--max-prompt", type=int, default=60000,
                        help="Max prompt length in chars (default: 60000)")
    args = parser.parse_args()

    # Build provider list
    providers = dict(CLOUD_PROVIDERS)
    if args.include_local:
        providers.update(LOCAL_PROVIDERS)

    if args.providers:
        providers = {k: v for k, v in providers.items() if k in args.providers}

    failed = 0
    total = 0

    for scenario in args.scenarios:
        if scenario not in SCENARIOS:
            print(f"SKIP: unknown scenario '{scenario}'")
            continue

        paths = resolve_paths(scenario, args.max_chunks)
        paths["max_chunks"] = args.max_chunks
        paths["max_prompt"] = args.max_prompt
        if not paths["data_dir"].is_dir():
            print(f"SKIP: {scenario} (no data at {paths['data_dir']})")
            continue

        for label, provider_args in providers.items():
            total += 1
            rc = run_analysis(scenario, label, provider_args, paths)
            if rc != 0:
                print(f"FAILED: {scenario} / {label} (rc={rc})")
                failed += 1

    print(f"\nSweep complete. {total - failed}/{total} succeeded. Failures: {failed}")


if __name__ == "__main__":
    main()
