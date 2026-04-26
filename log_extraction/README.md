# Log Extraction Module

Extract security logs from Elasticsearch (Security Onion / ELK Stack) for LLM analysis.

**Main tool:** `query_executor_with_time_range.py` runs Elasticsearch queries.  
**Alternative:** `raw_log_extractor.py` extracts unfiltered logs (for research comparisons).

## Setup

```bash
# Create env.so with credentials
cp env.so.example env.so
# Edit env.so with your credentials

# Install dependencies
pip install requests python-dotenv
```

## Query Executor

Run Elasticsearch queries with time range filtering.

```bash
# Test connection
python query_executor_with_time_range.py --env env.so --test

# Run queries
python query_executor_with_time_range.py queries/ output/ \
    --env env.so --start-date 2025-01-22 --end-date 2025-01-22
```

## Sample Results

Pre-extracted query results for 17 scenarios are included in
`../evaluation/<scenario>/es_results/`. See the top-level README for
the full list of scenarios and analysis instructions.

## Elasticsearch Queries

### Network & Endpoint Detection

| Query | Description |
|-------|-------------|
| `file_downloads.json` | Executable/script downloads (.exe, .msi, .ps1, .bat, .zip) |
| `suspicious_domains.json` | Non-whitelisted domain connections |
| `suricata_alerts.json` | IDS alerts: malware, trojans, high-severity |
| `suspicious_certificates.json` | Self-signed certs, IP-based CNs, short validity |
| `high_activity_external_dest.json` | Internal hosts with high external connections |
| `kerberos_clients.json` | Kerberos client accounts |
| `kerberos_hostnames.json` | Hostnames from Kerberos service tickets |
| `kerberos_full_services.json` | All Kerberos services requested |

### Active Directory Attack Reconstruction

| Query | Event Code | Description |
|-------|------------|-------------|
| `user_creation_event.json` | 4720 | New user account creation |
| `group_modification_event.json` | 4728/4732/4756 | User added to privileged group |
| `kerberos_auth_event.json` | 4768 | Kerberos TGT requests |
| `kerberos_service_event.json` | 4769 | Kerberos service ticket requests |
| `cert_request.json` | 4886 | Certificate requests |
| `cert_issued.json` | 4887 | Certificates issued |
| `cert_enum.json` | 4662 | Certificate enumeration |
| `service_installation_event.json` | 7045 | New service installed |
| `file_drops_event.json` | 11 | File created in suspicious locations |
| `powershell_injection_event.json` | 10 | PowerShell process injection |
| `reverse_tcp_on_8888.json` | — | Connections to port 8888 |

## Output

Results are saved as `*_result.json` files — input for the `llm_analyzer` module.

## SSH Tunnel

If Elasticsearch isn't directly accessible, use SSH tunneling:

```bash
# In a separate terminal
ssh user@security-onion-host -L 9200:localhost:9200 -N

# Then use localhost in env.so
ELASTICSEARCH_HOST=https://localhost:9200
```

---

## Raw Log Extractor (Alternative)

For research comparing filtered vs. unfiltered log analysis, you can extract raw logs without query filtering.

### Extract Raw Logs

```bash
python raw_log_extractor.py --env env.so \
    --start-date 2025-01-22 --end-date 2025-01-22 \
    -o raw_logs.json --max-logs 10000
```

### Convert to Analyzer Format

```bash
python raw_to_analyzer_format.py raw_logs.json output_dir/
```
