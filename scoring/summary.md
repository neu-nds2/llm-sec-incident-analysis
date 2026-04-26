# Analysis Summary

- Reports parsed: **1032** rows
- Scored against reference answers: **1032**
- Mean recall: **75.4%**
- Correct (≥1 token matched): **864** (83.7%)

## Per-provider

| Provider | Scored | Recall | Correct |
|----------|--------|--------|---------|
| Cisco 8B | 129 | 70.7% | 103 |
| Claude Sonnet 4 | 129 | 94.0% | 126 |
| DeepSeek V3 | 129 | 88.9% | 123 |
| GPT-4 | 129 | 67.4% | 99 |
| GPT-4o | 129 | 69.2% | 101 |
| GPT-5-mini | 129 | 64.1% | 94 |
| GPT-5.2 | 129 | 68.0% | 99 |
| Ollama 3.1:70b | 129 | 81.2% | 119 |

## Per-scenario

| Scenario | Reports | Scored | Recall | Correct |
|----------|---------|--------|--------|---------|
| apr21isc | 64 | 64 | 82.8% | 61 |
| burnincandle | 56 | 56 | 79.1% | 52 |
| dec21isc | 64 | 64 | 84.4% | 55 |
| dirty_rat | 56 | 56 | 61.6% | 38 |
| easy_123 | 48 | 48 | 88.5% | 45 |
| fake_auth | 64 | 64 | 79.7% | 54 |
| gozi | 72 | 72 | 74.1% | 65 |
| iced_id | 64 | 64 | 66.8% | 50 |
| jun21isc | 64 | 64 | 63.7% | 50 |
| koi_stealer | 64 | 64 | 75.8% | 51 |
| lumma_stealer | 56 | 56 | 83.0% | 52 |
| may21isc | 56 | 56 | 76.8% | 46 |
| net_rat | 56 | 56 | 76.8% | 45 |
| oct21isc | 64 | 64 | 61.7% | 44 |
| qakbot | 64 | 64 | 72.8% | 51 |
| redline_stlr | 64 | 64 | 80.5% | 55 |
| warmcookie | 56 | 56 | 78.1% | 50 |

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

