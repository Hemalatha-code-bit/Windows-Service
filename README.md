# Windows Monitoring Agent

## Overview

This project monitors Windows processes and services to detect suspicious behavior, unauthorized processes, and potential security threats such as malware activity and persistence mechanisms.

## Features

* Parent-child process monitoring
* Startup service auditing
* Unauthorized process detection (whitelist/blacklist)
* Alert logging in JSON format

## Setup

```bash
pip install -r requirements.txt
python main.py
```

## Output

* `logs/monitoring.log` – readable logs
* `reports/report.json` – structured alert data

## Note

Logs and reports are generated dynamically and are not included in version control.
