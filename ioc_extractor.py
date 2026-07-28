"""
ioc_extractor.py
Purpose : Extract Indicators of Compromise (IPs, file hashes, domains, URLs,
          and email addresses) from log files, reports, or arbitrary text.

Usage:
    python ioc_extractor.py <input_file> [--output iocs.csv] [--defang]

Output:
    A CSV with columns: type, value
"""

import argparse
import csv
import re
import sys
from pathlib import Path

PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
    ),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}\b"
    ),
    "url": re.compile(r"\bhttps?://[^\s\"'<>]+"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
}

# Common false positives to filter out of domain matches
DOMAIN_EXCLUDE_SUFFIXES = (".exe", ".dll", ".log", ".txt", ".sys", ".py")


def extract_iocs(text: str) -> dict:
    found = {ioc_type: set() for ioc_type in PATTERNS}

    for ioc_type, pattern in PATTERNS.items():
        for match in pattern.findall(text):
            found[ioc_type].add(match)

    # Hash patterns overlap (a sha1 substring can match inside a sha256, etc.)
    # so keep only the longest/most-specific classification per value.
    found["md5"] -= found["sha1"] | found["sha256"]
    found["sha1"] -= found["sha256"]

    # Drop domains that are actually filenames or already captured as part of a URL
    found["domain"] = {
        d for d in found["domain"]
        if not d.lower().endswith(DOMAIN_EXCLUDE_SUFFIXES)
    }

    return found


def defang(value: str, ioc_type: str) -> str:
    if ioc_type in ("ipv4", "domain", "url"):
        return value.replace(".", "[.]").replace("http", "hxxp")
    return value


def write_csv(found: dict, output_path: Path, should_defang: bool):
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "value"])
        for ioc_type, values in found.items():
            for value in sorted(values):
                out_value = defang(value, ioc_type) if should_defang else value
                writer.writerow([ioc_type, out_value])


def main():
    parser = argparse.ArgumentParser(description="Extract IOCs (IPs, hashes, domains, URLs, emails) from text.")
    parser.add_argument("input_file", type=Path, help="File to scan for IOCs")
    parser.add_argument("--output", type=Path, default=Path("iocs.csv"), help="Output CSV path")
    parser.add_argument("--defang", action="store_true", help="Defang IPs/domains/URLs in output (safer for reports)")
    args = parser.parse_args()

    if not args.input_file.is_file():
        print(f"ERROR: File not found: {args.input_file}")
        sys.exit(1)

    text = args.input_file.read_text(encoding="utf-8", errors="ignore")
    found = extract_iocs(text)
    write_csv(found, args.output, args.defang)

    total = sum(len(v) for v in found.values())
    print(f"Extracted {total} IOCs:")
    for ioc_type, values in found.items():
        print(f"  {ioc_type}: {len(values)}")
    print(f"Written to {args.output}")


if __name__ == "__main__":
    main()
