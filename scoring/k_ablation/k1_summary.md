# Analysis Summary

- Reports parsed: **1032** rows
- Scored against reference answers: **1032**
- Mean recall: **42.4%**
- Correct (≥1 token matched): **476** (46.1%)

## Per-provider

| Provider | Scored | Recall | Correct |
|----------|--------|--------|---------|
| Cisco 8B | 129 | 42.6% | 61 |
| Claude Sonnet 4 | 129 | 38.9% | 56 |
| DeepSeek V3 | 129 | 35.4% | 51 |
| GPT-4 | 129 | 45.8% | 63 |
| GPT-4o | 129 | 45.8% | 63 |
| GPT-5-mini | 129 | 44.2% | 61 |
| GPT-5.2 | 129 | 45.8% | 63 |
| Ollama 3.1:70b | 129 | 40.4% | 58 |

## Per-scenario

| Scenario | Reports | Scored | Recall | Correct |
|----------|---------|--------|--------|---------|
| apr21isc | 64 | 64 | 54.7% | 39 |
| burnincandle | 56 | 56 | 57.6% | 38 |
| dec21isc | 64 | 64 | 23.4% | 15 |
| dirty_rat | 56 | 56 | 43.3% | 26 |
| easy_123 | 48 | 48 | 41.7% | 20 |
| fake_auth | 64 | 64 | 57.8% | 37 |
| gozi | 72 | 72 | 47.9% | 39 |
| iced_id | 64 | 64 | 24.2% | 19 |
| jun21isc | 64 | 64 | 23.7% | 17 |
| koi_stealer | 64 | 64 | 51.6% | 33 |
| lumma_stealer | 56 | 56 | 42.9% | 25 |
| may21isc | 56 | 56 | 38.4% | 22 |
| net_rat | 56 | 56 | 54.5% | 32 |
| oct21isc | 64 | 64 | 21.9% | 18 |
| qakbot | 64 | 64 | 53.9% | 35 |
| redline_stlr | 64 | 64 | 48.4% | 35 |
| warmcookie | 56 | 56 | 35.7% | 26 |

## Recall (%) by scenario and provider

| Scenario | Claude | DeepSeek | Ollama | Cisco | GPT-4 | GPT-4o | GPT-5m | GPT-5.2 |
|---|---|---|---|---|---|---|---|---|
| apr21isc | 44 | 56 | 56 | 56 | 56 | 56 | 56 | 56 |
| burnincandle | 52 | 66 | 54 | 54 | 59 | 59 | 59 | 59 |
| dec21isc | 25 | 12 | 25 | 25 | 25 | 25 | 25 | 25 |
| dirty_rat | 50 | 36 | 46 | 43 | 43 | 43 | 43 | 43 |
| easy_123 | 33 | 17 | 33 | 50 | 50 | 50 | 50 | 50 |
| fake_auth | 62 | 50 | 62 | 62 | 50 | 50 | 62 | 62 |
| gozi | 56 | 39 | 39 | 50 | 50 | 50 | 50 | 50 |
| iced_id | 38 | 19 | 19 | 19 | 31 | 31 | 19 | 19 |
| jun21isc | 27 | 21 | 21 | 21 | 25 | 25 | 25 | 25 |
| koi_stealer | 25 | 38 | 50 | 50 | 62 | 62 | 62 | 62 |
| lumma_stealer | 57 | 29 | 36 | 50 | 43 | 43 | 43 | 43 |
| may21isc | 29 | 29 | 29 | 50 | 43 | 43 | 43 | 43 |
| net_rat | 50 | 50 | 57 | 50 | 57 | 57 | 57 | 57 |
| oct21isc | 27 | 27 | 21 | 17 | 21 | 21 | 21 | 21 |
| qakbot | 38 | 38 | 50 | 56 | 62 | 62 | 62 | 62 |
| redline_stlr | 31 | 56 | 44 | 44 | 56 | 56 | 44 | 56 |
| warmcookie | 18 | 18 | 46 | 32 | 46 | 46 | 32 | 46 |
| **Average** | **39** | **35** | **40** | **43** | **46** | **46** | **44** | **46** |

