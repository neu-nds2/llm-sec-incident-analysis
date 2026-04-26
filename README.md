# Retrieval-Augmented LLMs for Security Incident Analysis

Analyze security incidents from SIEM logs using Large Language Models
with RAG (Retrieval-Augmented Generation).

## Overview

The system extracts structured indicators from raw security logs via
Elasticsearch queries, embeds the results into a vector store, and
retrieves relevant chunks per forensic question for LLM analysis.

```
Elasticsearch/        log_extraction/        llm_analyzer/
Security Onion    -->  query_executor    -->  analyze.py
(SIEM logs)           (JSON results)         (Markdown report)
```

## Repository Structure

| Directory          | Description |
|--------------------|-------------|
| `llm_analyzer/`    | RAG-based LLM analysis pipeline |
| `log_extraction/`  | Elasticsearch query extraction tools |
| `evaluation/`      | 17 evaluation scenarios with data and results |
| `scoring/`         | Cross-scenario scoring and sweep tools |

## Evaluation Scenarios

We include pre-extracted query results, reference answers, and LLM
analysis reports for 17 malware-traffic scenarios from three
independent challenge sources:

**Malware-Traffic-Analysis.net exercises (8 scenarios):**
fake_auth, koi_stealer, net_rat, dirty_rat, warmcookie,
lumma_stealer, burnincandle, easy_123

**Palo Alto Unit 42 Wireshark Quizzes (4 scenarios):**
iced_id, gozi, qakbot, redline_stlr

**SANS Internet Storm Center forensic contests (5 scenarios):**
dec21isc, apr21isc, may21isc, oct21isc, jun21isc

Each scenario directory contains:

```
evaluation/<scenario>/
  config/              questions.txt, answers.txt, network.txt
  es_results/          Extracted query result JSON files
  cache_embeddings/    FAISS embedding cache (.pkl)
  llm_reports/         Generated LLM analysis reports (.md)
```

## Quick Start

### 1. Install dependencies
> **Tip:** Use a virtual environment to avoid dependency conflicts.
```bash
cd llm_analyzer
pip install -r requirements.txt
```

### 2. Run analysis on an existing scenario

```bash
cd llm_analyzer

# Using a cloud provider (create keys/ directory with your API key file)
python analyze.py ../evaluation/fake_auth/es_results \
    --provider anthropic \
    --api-key-file keys/anthropic.txt \
    --questions-file ../evaluation/fake_auth/config/questions.txt \
    --network-file ../evaluation/fake_auth/config/network.txt \
    --cache ../evaluation/fake_auth/cache_embeddings/fake_auth_embeddings.pkl \
    --output ../evaluation/fake_auth/llm_reports/fake_auth_anthropic.md

# Using a local model (Ollama)
python analyze.py ../evaluation/fake_auth/es_results \
    --provider ollama \
    --model llama3.1:70b \
    --questions-file ../evaluation/fake_auth/config/questions.txt \
    --network-file ../evaluation/fake_auth/config/network.txt \
    --cache ../evaluation/fake_auth/cache_embeddings/fake_auth_embeddings.pkl \
    --output ../evaluation/fake_auth/llm_reports/fake_auth_ollama.md
```

See `llm_analyzer/scripts/` for example scripts for each provider.

### 3. Run the full evaluation sweep

```bash
cd scoring

# All cloud providers x all scenarios
python run_sweep.py

# Specific providers/scenarios
python run_sweep.py --providers anthropic deepseek --scenarios fake_auth gozi
```

### 4. Score results against reference answers

```bash
cd scoring
python analyze_cross_source.py
# Produces per_answer.csv and summary.md
```

## Supported LLM Providers

| Provider | Type | Notes |
|----------|------|-------|
| Anthropic (Claude) | Cloud API | Highest recall in our evaluation |
| DeepSeek | Cloud API | Strong performance, cost-effective |
| OpenAI (GPT-4/4o/5-mini/5.2) | Cloud API | |
| Ollama (Llama 3.1) | Local | No API key needed |
| Cisco Foundation-Sec-8B | Local | Security-specialized |

## Extracting Logs from a New Scenario

To analyze a new PCAP/dataset (requires access to Security Onion):

1. Configure Elasticsearch credentials in `log_extraction/env.so`
   (see `env.so.example` for format)

2. Run query extraction:
```bash
cd log_extraction
python query_executor_with_time_range.py es_queries_malware \
    path/to/output_dir \
    --start-date 2024-07-29 --end-date 2024-07-31
```

3. Create the scenario config files (questions.txt, answers.txt,
   network.txt) in a config/ directory.

4. Run analysis as in Quick Start step 2.

## Key Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--max-chunks` | 7 | Number of RAG chunks retrieved per question |
| `--max-tokens` | 4000 | Max output tokens for LLM response |
| `--max-prompt` | 60000 | Max prompt length in characters |
| `--temperature` | 0.1 | LLM sampling temperature |

## Documentation

- [Log Extraction](log_extraction/README.md) - Elasticsearch queries
  and data extraction
- [LLM Analyzer](llm_analyzer/README.md) - Analysis pipeline setup
  and configuration

## Requirements

- Python 3.10+
- API key for cloud providers, or Ollama installed for local models
- For log extraction: access to Elasticsearch/Security Onion
