# Threat Intelligence Aggregator Domains API Client

A lightweight Python client for querying domain threat intelligence and aggregating results. The package provides a programmatic `ThreatIntelligenceAggregatorClient` and a simple CLI utility for appending lookup results to CSV files.

## Features
- **Programmatic client**: `ThreatIntelligenceAggregatorClient` for domain lookups.
- **Well-defined API error type**: `APIError` for handling service errors.
- **CSV helper CLI**: `tia_domain_web_api.csv_lookup` to append `date_first_observed` to CSV rows.

## Quickstart (Python)

Here's a quick example of how to use the `ThreatIntelligenceAggregatorClient`:
```
from tia_domain_web_api import ThreatIntelligenceAggregatorClient, APIError

client = ThreatIntelligenceAggregatorClient()
try:
    info = client.get_domain_info("example.com")
    print(info.date_first_observed)
except APIError as e:
    # handle API-level errors (rate limits, invalid requests, etc.)
    print("API error:", e)
except Exception as e:
    # handle network or unexpected errors
    print("Unexpected error:", e)
```
## CSV CLI

A utility `tia_domain_web_api.csv_lookup` reads a CSV, looks up a domain in each row, and writes a new CSV with an appended column (default `date_first_observed`).

### Usage:

python -m tia_domain_web_api.csv_lookup input.csv --domain-col 2 --output out.csv

### Common options:
- `--domain-col, -c` : Zero-based column index for the domain (default `0`).
- `--output, -o` : Output CSV file path.
- `--no-header` : Specify the input CSV has no header row.
- `--field-name` : Name of the appended field (default `date_first_observed`).

## Error handling

- `APIError` indicates an error returned by the remote service. Catch this to differentiate service errors from local exceptions.
- Network errors and other unexpected exceptions should be handled separately.

## Contributing

Contributions are welcome.
