"""
log_parser.py
Purpose : Parse Windows Event Logs (.evtx) into structured, searchable output.

Extracts common DFIR-relevant fields (EventID, TimeCreated, Computer, Channel,
Provider, and the rendered message) from .evtx files and writes them to CSV
for further triage in Excel, Splunk, or a SIEM.

Usage:
    python log_parser.py <path_to_evtx> [--output out.csv] [--event-id 4624 4625]

Requires:
    pip install python-evtx
"""

import argparse
import csv
import sys
from pathlib import Path

try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
except ImportError:
    print("ERROR: python-evtx is required. Install it with: pip install python-evtx")
    sys.exit(1)

import xml.etree.ElementTree as ET

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse_record_xml(xml_str: str) -> dict:
    """Pull the common fields out of a single EVTX record's XML."""
    root = ET.fromstring(xml_str)
    system = root.find("e:System", NS)

    def find_text(elem, path, attr=None):
        node = elem.find(path, NS) if elem is not None else None
        if node is None:
            return ""
        return node.get(attr) if attr else (node.text or "")

    event_id = find_text(system, "e:EventID")
    time_created = find_text(system, "e:TimeCreated", attr="SystemTime")
    computer = find_text(system, "e:Computer")
    channel = find_text(system, "e:Channel")
    provider = find_text(system, "e:Provider", attr="Name")

    # EventData fields (varies per event type — capture as key=value pairs)
    event_data = []
    data_node = root.find("e:EventData", NS)
    if data_node is not None:
        for d in data_node.findall("e:Data", NS):
            name = d.get("Name", "")
            value = d.text or ""
            event_data.append(f"{name}={value}")

    return {
        "EventID": event_id,
        "TimeCreated": time_created,
        "Computer": computer,
        "Channel": channel,
        "Provider": provider,
        "EventData": "; ".join(event_data),
    }


def parse_evtx(evtx_path: Path, event_id_filter=None):
    records = []
    with Evtx(str(evtx_path)) as log:
        for xml_str, record in evtx_file_xml_view(log):
            try:
                parsed = parse_record_xml(xml_str)
            except ET.ParseError:
                continue
            if event_id_filter and parsed["EventID"] not in event_id_filter:
                continue
            records.append(parsed)
    return records


def write_csv(records, output_path: Path):
    fieldnames = ["EventID", "TimeCreated", "Computer", "Channel", "Provider", "EventData"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)


def main():
    parser = argparse.ArgumentParser(description="Parse Windows Event Logs (.evtx) for DFIR triage.")
    parser.add_argument("evtx_path", type=Path, help="Path to the .evtx file")
    parser.add_argument("--output", type=Path, default=Path("parsed_events.csv"), help="Output CSV path")
    parser.add_argument("--event-id", nargs="*", default=None, help="Only include these Event IDs (e.g. 4624 4625)")
    args = parser.parse_args()

    if not args.evtx_path.is_file():
        print(f"ERROR: File not found: {args.evtx_path}")
        sys.exit(1)

    print(f"Parsing {args.evtx_path} ...")
    records = parse_evtx(args.evtx_path, event_id_filter=args.event_id)
    write_csv(records, args.output)
    print(f"Wrote {len(records)} records to {args.output}")


if __name__ == "__main__":
    main()
