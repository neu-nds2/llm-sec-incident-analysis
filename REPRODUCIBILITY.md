# Reproducing Paper Results

This document describes how to reproduce the evaluation results reported in
*Retrieval-Augmented LLMs for Security Incident Analysis* (CAIS 2026).

**No API keys or GPU required to verify the main results.** All pre-computed
LLM reports are included in the repository. Verification consists of
re-scoring those reports against reference answers using the provided scripts,
which runs in under a minute on any machine. Re-running LLM inference is
optional and documented separately below.

Published results are in [paper_results.md](paper_results.md).

---

## Environment Setup

### Supported Python versions

Tested on Python **3.11.1**, **3.12.1**, and **3.12.3**. Python 3.13 and 3.14
are **not supported**: the pinned `numpy` and `faiss-cpu` wheels resolve only
up to Python 3.12.

### Create a virtual environment (recommended)

The venv location is up to you — anywhere works as long as it's
activated before `pip install`.

```bash
# macOS / Linux
python3.11 -m venv /path/to/venv
source /path/to/venv/bin/activate

# Windows (PowerShell)
py -3.11 -m venv C:\path\to\venv
C:\path\to\venv\Scripts\Activate.ps1
```

### Install dependencies

```bash
pip install -r llm_analyzer/requirements.txt
```

All package versions are pinned in `requirements.txt` (numpy 1.26.4,
sentence-transformers 5.2.2, faiss-cpu 1.13.2, requests 2.32.4). Total
install footprint is ~870 MB.

### Platform-specific quirks

- **Windows.** Enable UTF-8 mode before running the scoring scripts:
  ```powershell
  $env:PYTHONUTF8=1
  ```
  Without this, the report parser may fail on non-ASCII tokens in LLM
  outputs.

---

## Verifying Results (no API keys needed)

### Recall across 17 scenarios × 8 providers (paper Table 1)

Pre-computed LLM reports are in `evaluation/<scenario>/llm_reports/` for all
17 scenarios and 8 providers. Re-score them against reference answers:

```bash
cd scoring && python analyze_cross_source.py
# Produces per_answer.csv and summary.md
```

Compare `summary.md` against `paper_results.md`.

### Retrieval window ablation (paper Table 3)

Pre-computed reports for k=1, 3, 5, 7, 14 are in
`evaluation/<scenario>/llm_reports_k{1,3,5,14}/` (k=7 is in `llm_reports/`).
Pre-computed scoring outputs are in `scoring/k_ablation/`. Re-score any k:

```bash
cd scoring
python analyze_cross_source.py --reports-dir llm_reports_k1 \
  --output-prefix k_ablation/k1_
# Repeat for k3, k5, k14
```

### RAG vs No-RAG baseline (paper Table 4)

Pre-computed No-RAG reports are in `evaluation/fake_auth/no_rag_reports/`.
Pre-computed RAG reports are in `evaluation/fake_auth/llm_reports/`.

These reports follow the same `FINAL ANSWER = [...]` schema as the RAG
reports, so the scoring script reproduces the numeric No-RAG recall column
automatically:

```bash
cd scoring
python analyze_cross_source.py --reports-dir no_rag_reports \
  --output-prefix no_rag_
# Produces no_rag_per_answer.csv and no_rag_summary.md
```

Compare the per-provider averages against the No-RAG column of paper Table 4
(Claude 50%, DeepSeek 50%, GPT-4/4o/5.2 38%, GPT-5-mini 38%). The
qualitative finding — No-RAG correctly identifies the victim host but
misses all attack infrastructure (malicious domains, C2 IPs, suspicious
certificates), while RAG recovers them — is also visible by inspecting the
two report sets.

### Cost and timing (paper Table 5)

Each LLM report records wall-clock duration in its METADATA section. The
script extracts timing statistics across all reports and computes USD cost
per analysis using Equation 1 from Section 6.5:

```bash
cd scoring && python cost_effectiveness.py
# Produces scoring/cost_effectiveness.md
```

The output includes both timing and the USD `Cost/Analysis` column. Cloud
provider prices are baked into the script (sourced from vendor
documentation as of early 2026) and match the prices listed in paper Table 5.

---

## Re-running LLM Inference (optional, requires API keys or GPU)

This section is optional. All pre-computed reports above are the exact outputs
used in the paper. Re-running allows you to generate fresh reports and verify
that the pipeline is functional end-to-end.

Note: LLM outputs are nondeterministic; results may vary by ±3% from the
pre-computed values.

### Hardware requirements

- Cloud providers (Anthropic, OpenAI, DeepSeek): any machine with internet access
- Llama 3.1:70b (via Ollama): GPU with ≥ 48GB VRAM
- Cisco Foundation-Sec-8B: GPU with ≥ 16GB VRAM (uncomment the torch /
  transformers / accelerate lines in `llm_analyzer/requirements.txt`)

### Running the pipeline

Set up API keys:

```bash
mkdir -p llm_analyzer/keys
echo "sk-..." > llm_analyzer/keys/anthropic.txt
```

Re-run analysis for any provider and scenario:

```bash
cd scoring
python run_sweep.py --providers anthropic --scenarios fake_auth
# ~2 min per scenario per provider
```

Then re-score:

```bash
python analyze_cross_source.py
```

### Re-running the No-RAG baseline

```bash
cd llm_analyzer && bash scripts/run_raw_no_rag_anthropic.sh
# ~5 min per provider
```
