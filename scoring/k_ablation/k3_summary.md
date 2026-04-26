# Analysis Summary

- Reports parsed: **1032** rows
- Scored against reference answers: **1032**
- Mean recall: **64.7%**
- Correct (≥1 token matched): **735** (71.2%)

## Per-provider

| Provider | Scored | Recall | Correct |
|----------|--------|--------|---------|
| Cisco 8B | 129 | 62.2% | 89 |
| Claude Sonnet 4 | 129 | 72.4% | 101 |
| DeepSeek V3 | 129 | 71.1% | 98 |
| GPT-4 | 129 | 60.1% | 86 |
| GPT-4o | 129 | 59.4% | 85 |
| GPT-5-mini | 129 | 62.1% | 89 |
| GPT-5.2 | 129 | 62.2% | 90 |
| Ollama 3.1:70b | 129 | 68.0% | 97 |

## Per-scenario

| Scenario | Reports | Scored | Recall | Correct |
|----------|---------|--------|--------|---------|
| apr21isc | 64 | 64 | 70.9% | 56 |
| burnincandle | 56 | 56 | 79.5% | 50 |
| dec21isc | 64 | 64 | 40.6% | 26 |
| dirty_rat | 56 | 56 | 55.4% | 34 |
| easy_123 | 48 | 48 | 76.0% | 39 |
| fake_auth | 64 | 64 | 62.5% | 41 |
| gozi | 72 | 72 | 69.6% | 60 |
| iced_id | 64 | 64 | 41.4% | 33 |
| jun21isc | 64 | 64 | 46.6% | 34 |
| koi_stealer | 64 | 64 | 90.6% | 60 |
| lumma_stealer | 56 | 56 | 65.2% | 38 |
| may21isc | 56 | 56 | 80.4% | 48 |
| net_rat | 56 | 56 | 75.0% | 44 |
| oct21isc | 64 | 64 | 54.0% | 42 |
| qakbot | 64 | 64 | 67.2% | 44 |
| redline_stlr | 64 | 64 | 74.2% | 48 |
| warmcookie | 56 | 56 | 55.4% | 38 |

## Recall (%) by scenario and provider

| Scenario | Claude | DeepSeek | Ollama | Cisco | GPT-4 | GPT-4o | GPT-5m | GPT-5.2 |
|---|---|---|---|---|---|---|---|---|
| apr21isc | 71 | 71 | 71 | 71 | 71 | 71 | 71 | 71 |
| burnincandle | 98 | 98 | 75 | 68 | 73 | 70 | 70 | 84 |
| dec21isc | 50 | 50 | 38 | 38 | 38 | 38 | 38 | 38 |
| dirty_rat | 43 | 57 | 57 | 46 | 57 | 61 | 61 | 61 |
| easy_123 | 83 | 83 | 75 | 75 | 75 | 75 | 67 | 75 |
| fake_auth | 71 | 71 | 71 | 50 | 50 | 62 | 62 | 62 |
| gozi | 77 | 77 | 72 | 72 | 61 | 55 | 72 | 72 |
| iced_id | 53 | 41 | 50 | 44 | 38 | 31 | 38 | 38 |
| jun21isc | 42 | 46 | 54 | 52 | 46 | 50 | 50 | 33 |
| koi_stealer | 100 | 88 | 94 | 88 | 94 | 75 | 94 | 94 |
| lumma_stealer | 71 | 86 | 71 | 64 | 57 | 43 | 71 | 57 |
| may21isc | 86 | 86 | 79 | 79 | 79 | 79 | 79 | 79 |
| net_rat | 86 | 79 | 71 | 71 | 71 | 79 | 71 | 71 |
| oct21isc | 73 | 60 | 54 | 49 | 42 | 51 | 51 | 51 |
| qakbot | 81 | 75 | 75 | 81 | 62 | 62 | 50 | 50 |
| redline_stlr | 88 | 88 | 88 | 69 | 62 | 62 | 62 | 75 |
| warmcookie | 61 | 61 | 64 | 43 | 54 | 54 | 54 | 54 |
| **Average** | **72** | **71** | **68** | **62** | **60** | **59** | **62** | **62** |

