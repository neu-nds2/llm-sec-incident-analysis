# Paper Results

Published results from *Retrieval-Augmented LLMs for Security Incident
Analysis* (CAIS 2026). These are the reference tables for verifying
reproduction — see [REPRODUCIBILITY.md](REPRODUCIBILITY.md) for instructions.

## Table 1: Recall (%) by scenario and provider

| Scenario | Claude | DeepSeek | Ollama | Cisco | GPT-4 | GPT-4o | GPT-5m | GPT-5.2 |
|---|---|---|---|---|---|---|---|---|
| apr21isc | 92 | 79 | 79 | 71 | 85 | 85 | 85 | 85 |
| burnincandle | 100 | 93 | 84 | 77 | 70 | 70 | 70 | 70 |
| dec21isc | 100 | 100 | 94 | 81 | 75 | 75 | 75 | 75 |
| dirty_rat | 89 | 75 | 71 | 43 | 50 | 64 | 50 | 50 |
| easy_123 | 100 | 100 | 92 | 100 | 75 | 75 | 75 | 92 |
| fake_auth | 100 | 100 | 94 | 81 | 69 | 69 | 56 | 69 |
| gozi | 77 | 88 | 72 | 75 | 72 | 70 | 70 | 70 |
| iced_id | 94 | 91 | 88 | 75 | 50 | 50 | 38 | 50 |
| jun21isc | 98 | 80 | 70 | 38 | 54 | 60 | 54 | 54 |
| koi_stealer | 100 | 88 | 69 | 88 | 56 | 69 | 69 | 69 |
| lumma_stealer | 100 | 100 | 93 | 86 | 71 | 71 | 71 | 71 |
| may21isc | 86 | 86 | 79 | 79 | 79 | 79 | 64 | 64 |
| net_rat | 100 | 93 | 86 | 57 | 79 | 71 | 57 | 71 |
| oct21isc | 88 | 78 | 72 | 48 | 46 | 58 | 46 | 58 |
| qakbot | 90 | 78 | 84 | 69 | 69 | 62 | 69 | 62 |
| redline_stlr | 94 | 94 | 81 | 56 | 81 | 81 | 75 | 81 |
| warmcookie | 96 | 93 | 79 | 86 | 68 | 68 | 68 | 68 |
| **Average** | **94** | **89** | **81** | **71** | **67** | **69** | **64** | **68** |

## Table 3: Context-size ablation: Recall (%) by k

| Provider | k=1 | k=3 | k=5 | k=7 | k=14 |
|---|---|---|---|---|---|
| Claude | 39 | 72 | 86 | 94 | 94 |
| DeepSeek | 35 | 71 | 80 | 89 | 89 |
| Ollama | 40 | 68 | 78 | 81 | 78 |
| Cisco | 43 | 62 | 72 | 71 | 67 |
| GPT-4 | 46 | 60 | 64 | 67 | 66 |
| GPT-4o | 46 | 59 | 65 | 69 | 64 |
| GPT-5m | 44 | 62 | 65 | 64 | 66 |
| GPT-5.2 | 46 | 62 | 64 | 68 | 64 |

## Table 5: Cost-effectiveness — timing and USD per provider

| Provider | Recall | Avg time/scenario | Avg time/question | In ($/M) | Out ($/M) | Cost/Analysis |
|---|---|---|---|---|---|---|
| Claude Sonnet 4 | 94% | 100s | 13.1s | 3.00 | 15.00 | $0.12 |
| DeepSeek V3 | 89% | 110s | 14.4s | 0.28 | 0.42 | $0.0080 |
| GPT-4† | 67% | 18s | 2.4s | 3.00 | 12.00 | $0.11 |
| GPT-4o | 69% | 19s | 2.6s | 2.50 | 10.00 | $0.09 |
| GPT-5-mini | 64% | 18s | 2.4s | 0.25 | 2.00 | $0.01 |
| GPT-5.2 | 68% | 17s | 2.3s | 1.75 | 14.00 | $0.09 |
| Ollama 3.1:70b | 81% | 200s | 26.4s | – | – | $0* |
| Cisco 8B | 71% | 376s | 49.5s | – | – | $0* |

† GPT-4.1 pricing used; GPT-4 no longer published.
\* Local deployment; requires GPU infrastructure, cost not included.

Cost per analysis computed via Equation 1 (Section 6.5):
C = N_calls × (T_in/1e6 × P_in + T_out/1e6 × P_out), with N_calls=8,
T_in=3000, T_out=400.

## Table 4: RAG vs No-RAG baseline (fake_auth scenario, 8 questions)

The No-RAG baseline sends raw logs directly to the LLM without
embedding or retrieval. Each provider can only process as many logs
as fit in its context window. No-RAG finds the victim host (IP,
hostname, timestamp) but misses attack infrastructure (malicious
domains, C2 IPs, suspicious certificates).

| Provider | RAG (k=7) | No-RAG | Logs seen by LLM |
|---|---|---|---|
| Claude Sonnet 4 | 100% | 50% | 158 (4.3%) |
| DeepSeek V3 | 100% | 50% | 104 (2.8%) |
| GPT-4 | 69% | 38% | 22 (0.6%) |
| GPT-4o | 69% | 38% | 22 (0.6%) |
| GPT-5-mini | 56% | 38% | 22 (0.6%) |
| GPT-5.2 | 69% | 38% | 22 (0.6%) |

Pre-computed No-RAG reports in evaluation/fake_auth/no_rag_reports/.
