"""
Utility to read a CSV, look up a domain per-row, and write a new CSV with an appended
API-provided date_first_observed column.

Usage (module):
  from tia_domain_web_api.csv_lookup import process_csv
  process_csv("in.csv", "out.csv", domain_col=2)

Usage (CLI):
  python -m tia_domain_web_api.csv_lookup input.csv --domain-col 2 --output out.csv
"""
# note for the future: use tld extraction to cache and skip loookups that will have the same result
from typing import Optional
import csv
import argparse
import time
from datetime import datetime, date
from tia_domain_web_api import ThreatIntelligenceAggregatorClient, APIError


def process_csv(
    input_path: str,
    output_path: Optional[str] = None,
    domain_col: int = 0,
    has_header: bool = True,
    delimiter: str = ",",
    lookup_field_name: str = "date_first_observed",
    sleep_between_calls: float = 0.0, #sleep_between_calls is the number of seconds to sleep
) -> str:
    """
    Read input_path CSV, look up the domain located at column `domain_col` for each row,
    and write a new CSV with the same fields/values plus an appended column named
    `lookup_field_name` containing the API-provided date_first_observed value (ISO date YYYY-MM-DD)
    or blank if not available.

    Returns the path to the written output file.
    """
    if output_path is None:
        # default to input filename with suffix
        output_path = input_path.rsplit(".", 1)[0] + "_with_lookup.csv"

    client = ThreatIntelligenceAggregatorClient()

    with open(input_path, newline="", encoding="utf-8") as inf, open(
        output_path, "w", newline="", encoding="utf-8"
    ) as outf:
        reader = csv.reader(inf, delimiter=delimiter)
        writer = csv.writer(outf, delimiter=delimiter)

        try:
            first_row = next(reader)
        except StopIteration:
            # empty file -> write nothing and return
            return output_path

        # handle header
        if has_header:
            header = first_row
            header_out = header + [lookup_field_name]
            writer.writerow(header_out)
            start_rows = reader  # continue from remainder
        else:
            # no header: treat first_row as data row
            start_rows = (r for r in ([first_row] + list(reader)))  # include first_row

        # iterate rows
        for row in start_rows:
            # Ensure row has enough columns
            if domain_col < 0 or domain_col >= len(row):
                # append empty lookup value and continue
                writer.writerow(row + [""])
                continue

            domain = row[domain_col].strip()
            lookup_value = ""
            if domain:
                try:
                    info = client.get_domain_info(domain)
                    # Extract date_first_observed from API result, normalize to YYYY-MM-DD
                    date_val = getattr(info, "date_first_observed", None)
                    if date_val:
                        if isinstance(date_val, datetime):
                            lookup_value = date_val.date().isoformat()
                        elif isinstance(date_val, date):
                            lookup_value = date_val.isoformat()
                        else:
                            # fallback: string-formatted value
                            lookup_value = str(date_val)
                    else:
                        lookup_value = ""  # API returned no date
                except APIError:
                    # API returned a managed error; record blank (or choose "API_ERROR" if preferred)
                    lookup_value = ""
                except Exception:
                    # non-API errors shouldn't stop processing; mark as ERROR to inspect later
                    lookup_value = "ERROR"
            else:
                lookup_value = ""

            writer.writerow(row + [lookup_value])

            if sleep_between_calls:
                time.sleep(sleep_between_calls) # number of seconds

    return output_path


def _cli():
    parser = argparse.ArgumentParser(
        description="Append API date_first_observed to each row in a CSV (domain column index required)."
    )
    parser.add_argument("input", help="Input CSV file path")
    parser.add_argument(
        "--output", "-o", help="Output CSV file path (default: input_with_lookup.csv)"
    )
    parser.add_argument(
        "--domain-col",
        "-c",
        type=int,
        default=0,
        help="Zero-based integer index of the column containing the domain (default 0)",
    )
    parser.add_argument(
        "--no-header",
        dest="has_header",
        action="store_false",
        help="Specify if the input CSV has no header row",
    )
    parser.add_argument(
        "--delimiter",
        "-d",
        default=",",
        help="CSV delimiter (default ',')",
    )
    parser.add_argument(
        "--field-name",
        default="date_first_observed",
        help="Name of the appended field (default 'date_first_observed')",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.0,
        help="Seconds to sleep between API calls to avoid rate limits (default 0)",
    )

    args = parser.parse_args()
    out = process_csv(
        args.input,
        output_path=args.output,
        domain_col=args.domain_col,
        has_header=args.has_header,
        delimiter=args.delimiter,
        lookup_field_name=args.field_name,
        sleep_between_calls=args.sleep,
    )
    print("Wrote:", out)


if __name__ == "__main__":
    _cli()
