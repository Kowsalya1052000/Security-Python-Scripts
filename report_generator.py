"""
report_generator.py
Purpose : Auto-generate an incident response (IR) report in Markdown from
          structured findings — designed to consume the CSV outputs of
          ioc_extractor.py, ip_reputation.py, and hash_checker.py, but works
          with any similarly-shaped CSVs.

Usage:
    python report_generator.py \\
        --incident-name "Suspicious PowerShell Activity" \\
        --analyst "Kowsalya" \\
        --iocs iocs.csv \\
        --reputation reputation_report.csv \\
        --hashes vt_report.csv \\
        --output ir_report.md

Any of --iocs / --reputation / --hashes can be omitted if that data isn't
available for the case; the report simply skips that section.
"""

import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path


def read_csv_rows(path: Path) -> list:
    if not path or not path.is_file():
        return []
    with open(path, "r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def render_table(rows: list, columns: list) -> str:
    if not rows:
        return "_No data available._\n"
    header = "| " + " | ".join(columns) + " |"
    separator = "| " + " | ".join("---" for _ in columns) + " |"
    lines = [header, separator]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(c, "")) for c in columns) + " |")
    return "\n".join(lines) + "\n"


def build_report(incident_name: str, analyst: str, iocs: list, reputation: list, hashes: list) -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    flagged_ips = [r for r in reputation if r.get("abuseConfidenceScore") and int(r["abuseConfidenceScore"]) >= 50]
    malicious_hashes = [h for h in hashes if h.get("malicious") and int(h["malicious"]) > 0]

    sections = [
        f"# Incident Response Report: {incident_name}",
        "",
        f"**Analyst:** {analyst}  ",
        f"**Generated:** {generated_at}",
        "",
        "## Summary",
        "",
        f"- IOCs extracted: {len(iocs)}",
        f"- IPs checked against threat feed: {len(reputation)} ({len(flagged_ips)} flagged)",
        f"- File hashes checked: {len(hashes)} ({len(malicious_hashes)} flagged malicious)",
        "",
        "## Extracted Indicators of Compromise",
        "",
        render_table(iocs, ["type", "value"]) if iocs else "_No IOC data provided._\n",
        "## IP Reputation Findings",
        "",
        render_table(
            reputation,
            ["ip", "abuseConfidenceScore", "countryCode", "isp", "totalReports"],
        ) if reputation else "_No IP reputation data provided._\n",
        "## File Hash Findings (VirusTotal)",
        "",
        render_table(
            hashes,
            ["hash", "malicious", "suspicious", "type_description", "meaningful_name"],
        ) if hashes else "_No hash-check data provided._\n",
        "## Recommended Next Steps",
        "",
        "- [ ] Validate flagged IPs against firewall/proxy logs for lateral movement",
        "- [ ] Isolate hosts associated with malicious file hashes",
        "- [ ] Update detection rules (SIEM/EDR) with confirmed IOCs",
        "- [ ] Document root cause and timeline for post-incident review",
        "",
    ]
    return "\n".join(sections)


def main():
    parser = argparse.ArgumentParser(description="Generate an IR report from IOC/reputation/hash CSV data.")
    parser.add_argument("--incident-name", required=True, help="Short name/title for the incident")
    parser.add_argument("--analyst", required=True, help="Name of the analyst producing the report")
    parser.add_argument("--iocs", type=Path, default=None, help="CSV from ioc_extractor.py")
    parser.add_argument("--reputation", type=Path, default=None, help="CSV from ip_reputation.py")
    parser.add_argument("--hashes", type=Path, default=None, help="CSV from hash_checker.py")
    parser.add_argument("--output", type=Path, default=Path("ir_report.md"), help="Output Markdown file")
    args = parser.parse_args()

    iocs = read_csv_rows(args.iocs)
    reputation = read_csv_rows(args.reputation)
    hashes = read_csv_rows(args.hashes)

    report = build_report(args.incident_name, args.analyst, iocs, reputation, hashes)
    args.output.write_text(report, encoding="utf-8")

    print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
