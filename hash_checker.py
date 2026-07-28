"""
hash_checker.py
Purpose : Check file hashes (MD5/SHA1/SHA256) against VirusTotal to see if
          they've been flagged as malicious.

Setup:
    pip install requests
    export VT_API_KEY="your_key_here"
    (free tier key: https://www.virustotal.com/gui/join-us)

Usage:
    python hash_checker.py hashes.txt [--output vt_report.csv]

    hashes.txt should contain one hash per line (MD5, SHA1, or SHA256).

Note:
    The VirusTotal public API has a rate limit of 4 requests/minute — this
    script paces requests accordingly.
"""

import argparse
import csv
import os
import sys
import time
from pathlib import Path

import requests

VT_URL_TEMPLATE = "https://www.virustotal.com/api/v3/files/{hash}"
REQUEST_DELAY_SECONDS = 16  # keeps us under the 4 req/min public API limit


def load_hashes(path: Path) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def check_hash(file_hash: str, api_key: str) -> dict:
    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(VT_URL_TEMPLATE.format(hash=file_hash), headers=headers, timeout=20)
    except requests.exceptions.RequestException as e:
        return {"hash": file_hash, "error": f"Request failed: {e}"}

    if resp.status_code == 401:
        return {"hash": file_hash, "error": "Authentication failed — check VT_API_KEY"}
    if resp.status_code == 404:
        return {"hash": file_hash, "error": "Not found in VirusTotal (unknown file)"}
    if resp.status_code == 429:
        return {"hash": file_hash, "error": "Rate limited by VirusTotal"}
    if resp.status_code != 200:
        return {"hash": file_hash, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}

    data = resp.json().get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    return {
        "hash": file_hash,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "type_description": data.get("type_description", ""),
        "meaningful_name": data.get("meaningful_name", ""),
        "error": "",
    }


def main():
    parser = argparse.ArgumentParser(description="Check file hashes against VirusTotal.")
    parser.add_argument("hash_list", type=Path, help="Text file with one hash per line")
    parser.add_argument("--output", type=Path, default=Path("vt_report.csv"))
    args = parser.parse_args()

    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        print("ERROR: Set the VT_API_KEY environment variable.")
        sys.exit(1)

    if not args.hash_list.is_file():
        print(f"ERROR: File not found: {args.hash_list}")
        sys.exit(1)

    hashes = load_hashes(args.hash_list)
    results = []

    for i, h in enumerate(hashes):
        result = check_hash(h, api_key)
        results.append(result)
        if result.get("error"):
            print(f"[!] {h}: {result['error']}")
        else:
            verdict = "MALICIOUS" if result["malicious"] > 0 else "clean"
            print(f"[{verdict:>9}] {h} (malicious={result['malicious']}, suspicious={result['suspicious']})")
        if i < len(hashes) - 1:
            time.sleep(REQUEST_DELAY_SECONDS)

    fieldnames = ["hash", "malicious", "suspicious", "harmless", "undetected",
                  "type_description", "meaningful_name", "error"]
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"\nReport written to {args.output}")


if __name__ == "__main__":
    main()
