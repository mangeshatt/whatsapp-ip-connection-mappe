import argparse
import csv
from pathlib import Path

import pyshark

"""
Very simple parser that reads a pcap/pcapng file and extracts:
- timestamp
- source IP
- destination IP

Later you can refine this with port filters and WhatsApp-specific heuristics.
"""

def parse_pcap(pcap_path: str, output_csv: str):
    cap = pyshark.FileCapture(pcap_path)
    rows = []

    print(f"[+] Parsing {pcap_path}")

    for pkt in cap:
        try:
            # Some packets may not have an IP layer
            if "IP" not in pkt:
                continue

            timestamp = pkt.sniff_time.isoformat()
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst

            rows.append({
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
            })
        except Exception as exc:
            # Skip malformed packets
            print(f"[!] Error parsing packet: {exc}")
            continue

    cap.close()

    Path(output_csv).parent.mkdir(parents=True, exist_ok=True)
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "src_ip", "dst_ip"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Wrote {len(rows)} rows to {output_csv}")


def main():
    parser = argparse.ArgumentParser(
        description="Parse pcap file and extract basic IP connection records."
    )
    parser.add_argument("--pcap", required=True, help="Input pcap/pcapng file path")
    parser.add_argument("--output", required=True, help="Output CSV file path")

    args = parser.parse_args()
    parse_pcap(args.pcap, args.output)


if __name__ == "__main__":
    main()
