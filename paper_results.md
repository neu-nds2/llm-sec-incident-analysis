# Paper Results

These results will be included in the camera-ready version of the
paper. They extend the original submission (4 scenarios, 3 providers)
to 17 scenarios and 8 providers. See the artifact appendix for
instructions on how to reproduce each table.

## Recall (%) by scenario and provider

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

## Context-size ablation: Recall (%) by k

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

## Cost-effectiveness: timing per provider

| Provider | Type | Avg time/scenario | Avg time/question | Recall | Total time (17 scenarios) |
|---|---|---|---|---|---|
| Claude Sonnet 4 | Cloud | 100s | 13.1s | 94% | 1692s |
| DeepSeek V3 | Cloud | 110s | 14.4s | 89% | 1863s |
| GPT-4 | Cloud | 18s | 2.4s | 67% | 312s |
| GPT-4o | Cloud | 19s | 2.6s | 69% | 331s |
| GPT-5-mini | Cloud | 18s | 2.4s | 64% | 304s |
| GPT-5.2 | Cloud | 17s | 2.3s | 68% | 293s |
| Ollama 3.1:70b | Local | 200s | 26.4s | 81% | 3403s |
| Cisco 8B | Local | 376s | 49.5s | 71% | 6391s |

## RAG vs No-RAG baseline (fake_auth scenario, 8 questions)

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
