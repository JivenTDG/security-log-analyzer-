# security-log-analyzer-
## Project Overview

This tool analyzes CSV web-server logs and counts valid IP addresses found in the `src_ip` column. It flags a source IP as a **potential intrusion** when it appears more than once, which may help surface repeated activity for review. Repeated requests alone do not prove a brute-force attack; the tool does not currently evaluate login failures or attack-specific thresholds.

## Architecture / Flow

```text
Raw CSV Logs
    → CSV Parser (reads the src_ip column)
    → IP Validation and Per-Address Counting
    → Repeated Source IPs flagged when count > 1
    → JSON Report (alert.json)
```

## Deployment Instructions

The current script is `log_analyzer.py`, not `analyzer.py`. It creates `alert.json` beside the input CSV by default. I don’t have this project’s repository URL, so replace `<REPOSITORY_URL>` with the actual clone URL:

```powershell
git clone <REPOSITORY_URL>
cd <REPOSITORY_FOLDER>
python log_analyzer.py .\access.csv
```

To specify the JSON report path:

```powershell
python log_analyzer.py .\access.csv --output .\alerts.json
```

The example uses the current script and options; it does not run as `python analyzer.py` unless the script is renamed.

## Sample Output

With `--output .\alerts.json`, a source IP observed twice appears like this in the JSON file:

```json
{
  "source_ips": [
    {
      "address": "192.0.2.15",
      "version": 4,
      "count": 2,
      "potential_intrusion": true,
      "alert": "POTENTIAL INTRUSION"
    }
  ]
}
```
