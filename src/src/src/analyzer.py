import argparse
from datetime import datetime
from pathlib import Path

import pandas as pd

"""
Group IP traffic into simple sessions between peers and estimate duration.

This is a naive heuristic:
- A session key is (src_ip, dst_ip) normalized into a sorted tuple.
- Packets within a configurable idle timeout window are considered the same session.
"""

def analyze_connections(input_csv: str, output_csv: str, idle_timeout_sec: int = 60):
    print(f"[+] Loading {input_csv}")
    df = pd.read_csv(input_csv)

    if df.empty:
        print("[!] No rows found in input CSV")
        return

    # Parse timestamps
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Normalize peer pair so that src/dst ordering does not matter
    def normalize_pair(row):
        a, b = row["src_ip"], row["dst_ip"]
        return tuple(sorted([a, b]))

    df["peer_pair"] = df.apply(normalize_pair, axis=1)

    sessions = []

    for pair, group in df.groupby("peer_pair"):
        group = group.sort_values("timestamp")
        current_start = None
        last_time = None

        for ts in group["timestamp"]:
            if current_start is None:
                current_start = ts
                last_time = ts
                continue

            delta = (ts - last_time).total_seconds()

            if delta > idle_timeout_sec:
                sessions.append({
                    "peer_a": pair[0],
                    "peer_b": pair[1],
                    "start_time": current_start.isoformat(),
                    "end_time": last_time.isoformat(),
                    "duration_sec": (last_time - current_start).total_seconds(),
                })
                current_start = ts

            last_time = ts

        if current_start is not None and last_time is not None:
            sessions.append({
                "peer_a": pair[0],
                "peer_b": pair[1],
                "start_time": current_start.isoformat(),
                "end_time": last_time.isoformat(),
                "duration_sec": (last_time - current_start).total_seconds(),
            })

    out_df = pd.DataFrame(sessions)
    Path(output_csv).parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(output_csv, index=False)
    print(f"[+] Wrote {len(out_df)} sessions to {output_csv}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze IP connection records and estimate session durations between peers."
    )
    parser.add_argument("--input", required=True, help="Input CSV file from parser.py")
    parser.add_argument("--report", required=True, help="Output CSV file with sessions")
    parser.add_argument("--idle-timeout", type=int, default=60, help="Idle timeout in seconds between packets")

    args = parser.parse_args()
    analyze_connections(args.input, args.report, idle_timeout_sec=args.idle_timeout)


if __name__ == "__main__":
    main()
