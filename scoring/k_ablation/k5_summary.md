# Analysis Summary

- Reports parsed: **1032** rows
- Scored against reference answers: **1032**
- Mean recall: **71.8%**
- Correct (≥1 token matched): **819** (79.4%)

## Per-provider

| Provider | Scored | Recall | Correct |
|----------|--------|--------|---------|
| Cisco 8B | 129 | 72.3% | 102 |
| Claude Sonnet 4 | 129 | 86.5% | 120 |
| DeepSeek V3 | 129 | 80.0% | 112 |
| GPT-4 | 129 | 64.0% | 92 |
| GPT-4o | 129 | 65.2% | 94 |
| GPT-5-mini | 129 | 64.8% | 93 |
| GPT-5.2 | 129 | 63.7% | 92 |
| Ollama 3.1:70b | 129 | 78.2% | 114 |

## Per-scenario

| Scenario | Reports | Scored | Recall | Correct |
|----------|---------|--------|--------|---------|
| apr21isc | 64 | 64 | 68.5% | 54 |
| burnincandle | 56 | 56 | 79.3% | 51 |
| dec21isc | 64 | 64 | 71.1% | 47 |
| dirty_rat | 56 | 56 | 66.1% | 40 |
| easy_123 | 48 | 48 | 90.6% | 46 |
| fake_auth | 64 | 64 | 71.1% | 47 |
| gozi | 72 | 72 | 75.9% | 65 |
| iced_id | 64 | 64 | 44.1% | 35 |
| jun21isc | 64 | 64 | 55.8% | 44 |
| koi_stealer | 64 | 64 | 85.2% | 57 |
| lumma_stealer | 56 | 56 | 88.4% | 53 |
| may21isc | 56 | 56 | 74.1% | 42 |
| net_rat | 56 | 56 | 83.0% | 48 |
| oct21isc | 64 | 64 | 51.4% | 38 |
| qakbot | 64 | 64 | 70.5% | 48 |
| redline_stlr | 64 | 64 | 83.6% | 57 |
| warmcookie | 56 | 56 | 70.5% | 47 |

## Recall (%) by scenario and provider

| Scenario | Claude | DeepSeek | Ollama | Cisco | GPT-4 | GPT-4o | GPT-5m | GPT-5.2 |
|---|---|---|---|---|---|---|---|---|
| apr21isc | 71 | 58 | 71 | 65 | 71 | 71 | 71 | 71 |
| burnincandle | 100 | 96 | 89 | 70 | 70 | 70 | 70 | 70 |
| dec21isc | 88 | 81 | 81 | 69 | 62 | 62 | 62 | 62 |
| dirty_rat | 82 | 86 | 75 | 71 | 43 | 64 | 57 | 50 |
| easy_123 | 100 | 83 | 92 | 100 | 92 | 92 | 92 | 75 |
| fake_auth | 96 | 96 | 90 | 62 | 62 | 50 | 62 | 50 |
| gozi | 88 | 88 | 83 | 61 | 72 | 72 | 72 | 72 |
| iced_id | 56 | 56 | 50 | 69 | 25 | 38 | 25 | 34 |
| jun21isc | 81 | 55 | 62 | 42 | 52 | 52 | 52 | 50 |
| koi_stealer | 100 | 88 | 81 | 88 | 81 | 81 | 81 | 81 |
| lumma_stealer | 100 | 100 | 93 | 93 | 79 | 86 | 79 | 79 |
| may21isc | 86 | 86 | 79 | 57 | 71 | 71 | 71 | 71 |
| net_rat | 100 | 93 | 93 | 93 | 71 | 71 | 71 | 71 |
| oct21isc | 67 | 54 | 49 | 57 | 46 | 46 | 46 | 46 |
| qakbot | 78 | 78 | 78 | 81 | 62 | 62 | 62 | 62 |
| redline_stlr | 94 | 94 | 94 | 75 | 81 | 75 | 81 | 75 |
| warmcookie | 93 | 75 | 79 | 89 | 54 | 54 | 54 | 68 |
| **Average** | **86** | **80** | **78** | **72** | **64** | **65** | **65** | **64** |

