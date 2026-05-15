# Cost-Effectiveness Summary (paper Table 5)

| Provider | Type | Recall | Avg time/scenario | Avg time/question | In ($/M) | Out ($/M) | Cost/Analysis | Total time (17 scenarios) |
|---|---|---|---|---|---|---|---|---|
| Claude Sonnet 4 | Cloud | 94% | 100s | 13.1s | 3.00 | 15.00 | $0.12 | 1692s |
| DeepSeek V3 | Cloud | 89% | 110s | 14.4s | 0.28 | 0.42 | $0.0081 | 1863s |
| GPT-4 | Cloud | 67% | 18s | 2.4s | 3.00 | 12.00 | $0.11 | 312s |
| GPT-4o | Cloud | 69% | 19s | 2.6s | 2.50 | 10.00 | $0.09 | 331s |
| GPT-5-mini | Cloud | 64% | 18s | 2.4s | 0.25 | 2.00 | $0.01 | 304s |
| GPT-5.2 | Cloud | 68% | 17s | 2.3s | 1.75 | 14.00 | $0.09 | 293s |
| Ollama 3.1:70b | Local | 81% | 200s | 26.4s | – | – | $0* | 3403s |
| Cisco 8B | Local | 71% | 376s | 49.5s | – | – | $0* | 6391s |

Durations extracted from report metadata (evaluation/*/llm_reports/*.md).

Cost/Analysis computed via Equation 1 with N_calls=8, T_in=3000, T_out=400. \* Local deployment; requires GPU infrastructure, cost not included.
