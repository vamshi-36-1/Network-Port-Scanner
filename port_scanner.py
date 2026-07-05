#!/usr/bin/env python3
"""
Simple TCP Port Scanner
Usage:
    python3 port_scanner.py <host> [-p START-END] [-t THREADS] [--timeout SECONDS]

Examples:
    python3 port_scanner.py 192.168.1.1
    python3 port_scanner.py example.com -p 1-1000
    python3 port_scanner.py 10.0.0.5 -p 20-25,80,443,8000-8100 -t 200

Note: Only scan hosts/networks you own or have explicit permission to test.
Unauthorized scanning of systems you don't control may be illegal.
"""

import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# A few well-known ports for friendly labeling in results
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


def parse_ports(port_str):
    """Parse a port spec like '1-1000,8080,9000-9100' into a sorted list of ints."""
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            start, end = int(start), int(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def scan_port(host, port, timeout):
    """Attempt to connect to a single port. Returns (port, is_open, banner)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                banner = None
                try:
                    sock.settimeout(0.5)
                    data = sock.recv(64)
                    if data:
                        banner = data.decode(errors="replace").strip()
                except (socket.timeout, OSError):
                    pass
                return port, True, banner
            return port, False, None
    except socket.error:
        return port, False, None


def main():
    parser = argparse.ArgumentParser(description="Simple TCP port scanner")
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument("-p", "--ports", default="1-1024",
                         help="Ports to scan, e.g. '1-1000' or '22,80,443' (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                         help="Number of concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                         help="Per-port connection timeout in seconds (default: 1.0)")
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"Error: could not resolve host '{args.host}'")
        sys.exit(1)

    try:
        ports = parse_ports(args.ports)
    except ValueError:
        print(f"Error: invalid port specification '{args.ports}'")
        sys.exit(1)

    print(f"Scanning {args.host} ({ip}) — {len(ports)} ports, {args.threads} threads")
    print("-" * 60)

    start_time = time.time()
    open_ports = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, ip, port, args.timeout): port for port in ports}
        for future in as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                service = COMMON_PORTS.get(port, "unknown")
                line = f"Port {port:>5}/tcp  OPEN   ({service})"
                if banner:
                    line += f"  banner: {banner[:50]}"
                print(line)
                open_ports.append(port)

    elapsed = time.time() - start_time
    print("-" * 60)
    if open_ports:
        print(f"Found {len(open_ports)} open port(s): {sorted(open_ports)}")
    else:
        print("No open ports found.")
    print(f"Scan completed in {elapsed:.2f} seconds")


if __name__ == "__main__":
    main()
