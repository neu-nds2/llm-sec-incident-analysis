# Retrieval-Augmented LLMs for Security Incident Analysis

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19895153.svg)](https://doi.org/10.5281/zenodo.19895153)

> **Paper:** Xavier Cadet, Aditya Vikram Singh, Harsh Mamania, Edward Koh, Alex Fitts, Dirk Van Bruggen, Simona Boboila, Peter Chin, and Alina Oprea.
> *Retrieval-Augmented LLMs for Security Incident Analysis.*
> ACM Conference on AI and Agentic Systems (CAIS), 2026.

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

**[Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/training-exercises.html) exercises (8 scenarios):**
fake_auth, koi_stealer, net_rat, dirty_rat, warmcookie,
lumma_stealer, burnincandle, easy_123

**[Palo Alto Unit 42](https://unit42.paloaltonetworks.com/category/cybersecurity-tutorials/) Wireshark Quizzes (4 scenarios):**
iced_id, gozi, qakbot, redline_stlr

**[SANS Internet Storm Center](https://isc.sans.edu/diary/28160) forensic contests (5 scenarios):**
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

Create and activate a virtual environment, then install pinned dependencies:

```bash
# macOS / Linux
python3.11 -m venv /path/to/venv
source /path/to/venv/bin/activate

# Windows (PowerShell)
py -3.11 -m venv C:\path\to\venv
C:\path\to\venv\Scripts\Activate.ps1

pip install -r llm_analyzer/requirements.txt
```

> **Python version.** Tested on Python 3.11 and 3.12. Python 3.13 and
> 3.14 are NOT supported — the pinned `numpy` and `faiss-cpu` wheels
> do not resolve on 3.13+.
>
> **Windows users.** Enable UTF-8 mode before running the scoring
> scripts, otherwise the report parser may fail on non-ASCII tokens:
> ```powershell
> $env:PYTHONUTF8=1
> ```

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

- Python 3.11 or 3.12 (3.13/3.14 not supported — see Quick Start)
- API key for cloud providers, or Ollama installed for local models (Llama 3.1:70b), or GPU with ≥16GB VRAM for Cisco Foundation-Sec-8B
- For log extraction: access to Elasticsearch/Security Onion

## Citation

If you use this artifact, please cite the associated paper:

```bibtex
@inproceedings{cadet2026ragllm,
  author    = {Cadet, Xavier and Singh, Aditya Vikram and Mamania, Harsh and
               Koh, Edward and Fitts, Alex and Van Bruggen, Dirk and
               Boboila, Simona and Chin, Peter and Oprea, Alina},
  title     = {Retrieval-Augmented {LLMs} for Security Incident Analysis},
  booktitle = {Proceedings of the ACM Conference on AI and Agentic Systems (CAIS)},
  year      = {2026},
  doi       = {10.5281/zenodo.19895153},

}
```
