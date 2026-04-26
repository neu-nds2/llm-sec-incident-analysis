# Analysis Summary

- Reports parsed: **1032** rows
- Scored against reference answers: **1032**
- Mean recall: **73.4%**
- Correct (≥1 token matched): **835** (80.9%)

## Per-provider

| Provider | Scored | Recall | Correct |
|----------|--------|--------|---------|
| Cisco 8B | 129 | 67.3% | 96 |
| Claude Sonnet 4 | 129 | 94.1% | 127 |
| DeepSeek V3 | 129 | 89.0% | 123 |
| GPT-4 | 129 | 65.6% | 96 |
| GPT-4o | 129 | 63.7% | 92 |
| GPT-5-mini | 129 | 66.0% | 96 |
| GPT-5.2 | 129 | 63.7% | 92 |
| Ollama 3.1:70b | 129 | 78.0% | 113 |

## Per-scenario

| Scenario | Reports | Scored | Recall | Correct |
|----------|---------|--------|--------|---------|
| apr21isc | 64 | 64 | 81.0% | 60 |
| burnincandle | 56 | 56 | 77.1% | 51 |
| dec21isc | 64 | 64 | 83.6% | 55 |
| dirty_rat | 56 | 56 | 63.4% | 38 |
| easy_123 | 48 | 48 | 78.1% | 40 |
| fake_auth | 64 | 64 | 81.0% | 55 |
| gozi | 72 | 72 | 70.9% | 62 |
| iced_id | 64 | 64 | 62.1% | 47 |
| jun21isc | 64 | 64 | 29.4% | 23 |
| koi_stealer | 64 | 64 | 78.9% | 53 |
| lumma_stealer | 56 | 56 | 87.5% | 52 |
| may21isc | 56 | 56 | 76.8% | 45 |
| net_rat | 56 | 56 | 82.1% | 48 |
| oct21isc | 64 | 64 | 68.9% | 47 |
| qakbot | 64 | 64 | 75.8% | 55 |
| redline_stlr | 64 | 64 | 80.5% | 55 |
| warmcookie | 56 | 56 | 75.4% | 49 |

## Recall (%) by scenario and provider

| Scenario | Claude | DeepSeek | Ollama | Cisco | GPT-4 | GPT-4o | GPT-5m | GPT-5.2 |
|---|---|---|---|---|---|---|---|---|
| apr21isc | 96 | 92 | 67 | 60 | 83 | 83 | 83 | 83 |
| burnincandle | 98 | 96 | 62 | 80 | 70 | 70 | 70 | 70 |
| dec21isc | 100 | 100 | 94 | 69 | 81 | 75 | 75 | 75 |
| dirty_rat | 75 | 71 | 71 | 57 | 61 | 54 | 64 | 54 |
| easy_123 | 100 | 83 | 92 | 100 | 58 | 75 | 58 | 58 |
| fake_auth | 100 | 100 | 94 | 79 | 69 | 69 | 69 | 69 |
| gozi | 91 | 88 | 70 | 76 | 61 | 61 | 61 | 61 |
| iced_id | 88 | 88 | 78 | 56 | 50 | 38 | 50 | 50 |
| jun21isc | 94 | 70 | 72 | 0 | 0 | 0 | 0 | 0 |
| koi_stealer | 100 | 88 | 69 | 75 | 69 | 69 | 81 | 81 |
| lumma_stealer | 100 | 100 | 79 | 79 | 93 | 79 | 93 | 79 |
| may21isc | 86 | 86 | 79 | 64 | 79 | 71 | 79 | 71 |
| net_rat | 100 | 93 | 93 | 86 | 71 | 71 | 71 | 71 |
| oct21isc | 100 | 94 | 66 | 75 | 58 | 58 | 54 | 46 |
| qakbot | 84 | 90 | 74 | 84 | 69 | 69 | 69 | 69 |
| redline_stlr | 94 | 94 | 88 | 44 | 81 | 81 | 81 | 81 |
| warmcookie | 96 | 79 | 86 | 71 | 68 | 68 | 68 | 68 |
| **Average** | **94** | **89** | **78** | **67** | **66** | **64** | **66** | **64** |

