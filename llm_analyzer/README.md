# LLM Analyzer

Analyze security logs using LLMs with RAG (Retrieval-Augmented Generation).

## Setup
> **Tip:** Use a virtual environment to avoid dependency conflicts.
```bash
pip install -r requirements.txt
```

## Quick Start

Pre-extracted query results and embedding caches are provided for 17
scenarios in `../evaluation/`. Run analysis on any scenario:

```bash
# Using Anthropic Claude
python analyze.py ../evaluation/fake_auth/es_results \
    --provider anthropic \
    --api-key-file keys/anthropic.txt \
    --questions-file ../evaluation/fake_auth/config/questions.txt \
    --network-file ../evaluation/fake_auth/config/network.txt \
    --cache ../evaluation/fake_auth/cache_embeddings/fake_auth_embeddings.pkl \
    --output ../evaluation/fake_auth/llm_reports/fake_auth_anthropic.md

# Or use an example script
bash scripts/run_analysis_anthropic.sh
```

## Usage

### 1. Build Embeddings Cache

Build a vector embeddings cache from Elasticsearch query results.
Uses the `all-mpnet-base-v2` sentence transformer model.

```bash
python analyze.py path/to/es_results \
    --build-cache-only \
    --cache path/to/cache.pkl
```

### 2. Run Analysis

```bash
python analyze.py path/to/es_results \
    --provider anthropic \
    --api-key-file keys/anthropic.txt \
    --questions-file path/to/questions.txt \
    --network-file path/to/network.txt \
    --cache path/to/cache.pkl \
    --output path/to/report.md
```

## Example Scripts

Complete example scripts are provided in `scripts/`:

| Script | Provider | Type |
|--------|----------|------|
| `run_analysis_anthropic.sh` | Anthropic Claude | Cloud API |
| `run_analysis_deepseek.sh` | DeepSeek | Cloud API |
| `run_analysis_openai.sh` | OpenAI GPT | Cloud API |
| `run_analysis_ollama.sh` | Ollama (Llama 3.1) | Local |
| `run_analysis_cisco.sh` | Cisco Foundation-Sec | Local |
| `run_raw_no_rag_anthropic.sh` | No-RAG baseline | Cloud API |

Edit the `SCENARIO` and `API_KEY_FILE` variables at the top of each
script before running.

## Required Files

### Questions File
One question per line. Lines starting with `#` are comments.

```text
What is the IP address of the infected host?
What suspicious domains were contacted?
What malware indicators are present?
```

### Network File
Network environment context for the scenario.

```text
LAN range: 10.1.17.0/24
Domain: company.local
Domain Controller: 10.1.17.2
Gateway: 10.1.17.1
```

### API Keys
Create a `keys/` directory with text files containing your API keys:
```
keys/anthropic.txt
keys/openai.txt
keys/deepseek.txt
```

## Providers

| Provider | Required Args |
|----------|---------------|
| `anthropic` | `--api-key-file` |
| `openai` | `--api-key-file`, `--model` |
| `deepseek` | `--api-key-file` |
| `ollama` | `--model` (requires `ollama serve` running) |
| `cisco` | `--model` (path to local model weights) |

## Settings

| Argument | Default | Description |
|----------|---------|-------------|
| `--max-chunks` | 7 | RAG chunks retrieved per question |
| `--max-tokens` | 4000 | Max LLM response tokens |
| `--temperature` | 0.1 | LLM temperature |
| `--max-prompt` | 60000 | Max prompt length in characters |
| `--cache` | `cache/embeddings.pkl` | Embeddings cache file |
| `--debug` | off | Show retrieved chunks and scores |
