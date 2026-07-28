"""
ip_reputation.py
Purpose : Check a list of IP addresses against a threat intelligence feed
          (AbuseIPDB) and flag ones with a high abuse confidence score.

Setup:
    pip install requests
    export ABUSEIPDB_API_KEY="your_key_here"
    (free tier key: https://www.abuseipdb.com/account/api)

Usage:
    python ip_reputation.py ips.txt [--output reputation_report.csv] [--threshold 50]

    ips.txt should contain one IP address per line.
"""

import argparse
import csv
import os
import sys
import time
from pathlib import Path

import requests

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def load_ips(path: Path) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def check_ip(ip: str, api_key: str) -> dict:
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        resp = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=15)
    except requests.exceptions.RequestException as e:
        return {"ip": ip, "error": f"Request failed: {e}"}

    if resp.status_code == 401:
        return {"ip": ip, "error": "Authentication failed — check ABUSEIPDB_API_KEY"}
    if resp.status_code == 429:
        return {"ip": ip, "error": "Rate limited by AbuseIPDB"}
    if resp.status_code != 200:
        return {"ip": ip, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}

    data = resp.json().get("data", {})
    return {
        "ip": ip,
        "abuseConfidenceScore": data.get("abuseConfidenceScore"),
        "countryCode": data.get("countryCode"),
        "isp": data.get("isp"),
        "totalReports": data.get("totalReports"),
        "lastReportedAt": data.get("lastReportedAt"),
        "error": "",
    }


def main():
    parser = argparse.ArgumentParser(description="Check IPs against AbuseIPDB threat feed.")
    parser.add_argument("ip_list", type=Path, help="Text file with one IP per line")
    parser.add_argument("--output", type=Path, default=Path("reputation_report.csv"))
    parser.add_argument("--threshold", type=int, default=50, help="Flag IPs at/above this abuse confidence score")
    args = parser.parse_args()

    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        print("ERROR: Set the ABUSEIPDB_API_KEY environment variable.")
        sys.exit(1)

    if not args.ip_list.is_file():
        print(f"ERROR: File not found: {args.ip_list}")
        sys.exit(1)

    ips = load_ips(args.ip_list)
    results = []
    flagged = []

    for ip in ips:
        result = check_ip(ip, api_key)
        results.append(result)
        if result.get("error"):
            print(f"[!] {ip}: {result['error']}")
        else:
            score = result["abuseConfidenceScore"]
            flag = " <-- FLAGGED" if score is not None and score >= args.threshold else ""
            if flag:
                flagged.append(ip)
            print(f"[{score:>3}] {ip} ({result['countryCode']}, {result['isp']}){flag}")
        time.sleep(1)  # stay well under free-tier rate limits

    fieldnames = ["ip", "abuseConfidenceScore", "countryCode", "isp", "totalReports", "lastReportedAt", "error"]
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"\n{len(flagged)} of {len(ips)} IPs flagged at threshold {args.threshold}.")
    print(f"Full report written to {args.output}")


if __name__ == "__main__":
    main()
