# Analysis Summary

- Reports parsed: **48** rows
- Scored against reference answers: **48**
- Mean recall: **41.7%**
- Correct (≥1 token matched): **20** (41.7%)

## Per-provider

| Provider | Scored | Recall | Correct |
|----------|--------|--------|---------|
| Claude Sonnet 4 | 8 | 50.0% | 4 |
| DeepSeek V3 | 8 | 50.0% | 4 |
| GPT-4 | 8 | 37.5% | 3 |
| GPT-4o | 8 | 37.5% | 3 |
| GPT-5-mini | 8 | 37.5% | 3 |
| GPT-5.2 | 8 | 37.5% | 3 |

## Per-scenario

| Scenario | Reports | Scored | Recall | Correct |
|----------|---------|--------|--------|---------|
| fake_auth | 48 | 48 | 41.7% | 20 |

## Recall (%) by scenario and provider

| Scenario | Claude | DeepSeek | GPT-4 | GPT-4o | GPT-5m | GPT-5.2 |
|---|---|---|---|---|---|---|
| fake_auth | 50 | 50 | 38 | 38 | 38 | 38 |
| **Average** | **50** | **50** | **38** | **38** | **38** | **38** |

