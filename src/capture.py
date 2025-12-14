import argparse
import datetime
import pyshark

def capture_traffic(interface: str, output_file: str, duration: int | None, packet_count: int | None):
    """
    Capture network traffic on the given interface and save to a pcapng file.

    Note: This captures all traffic by default. Add capture_filter if you want BPF filters.
    """
    print(f"[+] Starting capture on {interface}")
    print(f"[+] Writing to {output_file}")

    capture = pyshark.LiveCapture(interface=interface, output_file=output_file)

    if duration is not None:
        print(f"[+] Capture duration: {duration} seconds")
        capture.sniff(timeout=duration)
    elif packet_count is not None:
        print(f"[+] Capture packet limit: {packet_count} packets")
        capture.sniff(packet_count=packet_count)
    else:
        print("[+] Capture until interrupted (Ctrl+C)")
        try:
            capture.sniff()
        except KeyboardInterrupt:
            print("[+] Capture interrupted by user")

    print("[+] Capture finished")


def main():
    parser = argparse.ArgumentParser(
        description="Capture network traffic to a pcapng file for later WhatsApp IP analysis."
    )
    parser.add_argument("--iface", required=True, help="Network interface to capture from (e.g. eth0, wlan0)")
    parser.add_argument("--output", default=None, help="Output pcapng file path")
    parser.add_argument("--duration", type=int, default=None, help="Capture duration in seconds")
    parser.add_argument("--packet-count", type=int, default=None, help="Number of packets to capture")

    args = parser.parse_args()

    if args.output is None:
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        args.output = f"data/raw/capture_{timestamp}.pcapng"

    capture_traffic(
        interface=args.iface,
        output_file=args.output,
        duration=args.duration,
        packet_count=args.packet_count,
    )

if __name__ == "__main__":
    main()
