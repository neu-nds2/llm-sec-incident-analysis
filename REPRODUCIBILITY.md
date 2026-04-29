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

## Verifying Results (no API keys needed)

### Requirements

- Python 3.10+
- `pip install -r llm_analyzer/requirements.txt`
- Any machine; < 1 min runtime

### Recall across 17 scenarios × 8 providers (Table 2)

Pre-computed LLM reports are in `evaluation/<scenario>/llm_reports/` for all
17 scenarios and 8 providers. Re-score them against reference answers:

```bash
cd scoring && python analyze_cross_source.py
# Produces per_answer.csv and summary.md
```

Compare `summary.md` against `paper_results.md`.

### Retrieval window ablation (Table 4)

Pre-computed reports for k=1, 3, 5, 7, 14 are in
`evaluation/<scenario>/llm_reports_k{1,3,5,14}/` (k=7 is in `llm_reports/`).
Pre-computed scoring outputs are in `scoring/k_ablation/`. Re-score any k:

```bash
cd scoring
python analyze_cross_source.py --reports-dir llm_reports_k1 \
  --output-prefix k_ablation/k1_
# Repeat for k3, k5, k14
```

### RAG vs No-RAG baseline (Table 5)

Pre-computed No-RAG reports are in `evaluation/fake_auth/no_rag_reports/`.
Pre-computed RAG reports are in `evaluation/fake_auth/llm_reports/`.
Inspect both sets to verify the claim: No-RAG correctly identifies the victim
host (IP, hostname, user) but misses all attack infrastructure (malicious
domains, C2 IPs, suspicious certificates), while RAG recovers them.

### Cost and timing (Table 3)

Each LLM report records wall-clock duration in its METADATA section.
Extract timing statistics across all reports:

```bash
cd scoring && python cost_effectiveness.py
# Produces scoring/cost_effectiveness.md
```

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
- Cisco Foundation-Sec-8B: GPU with ≥ 16GB VRAM (`pip install torch transformers bitsandbytes`)

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
