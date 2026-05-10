# Python Security Log Analyzer

This project analyzes SSH authentication logs to detect repeated failed login attempts and identify suspicious IP addresses.

## Features

- Extracts IP addresses from failed login attempts
- Counts failed login attempts per IP
- Detects suspicious activity based on repeated failures
- Generates a CSV security report with risk classification and recommendations

## Files

- `security-log-analyzer.py` — main analysis script
- `sample.log` — sample SSH authentication log
- `report.csv` — generated security report

## Example output

The script identifies suspicious IP addresses and produces a CSV report with:

- IP address
- Failed attempts
- Risk level
- Recommendation
