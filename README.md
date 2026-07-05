# Network-Port-Scanner
A fast and lightweight network port scanner designed to identify open ports and detect active services on a target host.
# Port Scanner

A simple multithreaded TCP port scanner written in Python. Scans a target host over a given port range and reports which ports are open, along with a guessed service name and (if available) a banner grabbed from the service.

## ⚠️ Disclaimer

This tool is intended for use on hosts and networks you own or have explicit permission to test. Scanning systems without authorization may be illegal in your jurisdiction. Use responsibly.

## Requirements

- Python 3.6+
- No external dependencies (uses only the standard library)

## Usage

```bash
python3 port_scanner.py <host> [-p PORTS] [-t THREADS] [--timeout SECONDS]
```

### Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `host` | Target hostname or IP address | required |
| `-p`, `--ports` | Ports to scan, e.g. `1-1000` or `22,80,443` | `1-1024` |
| `-t`, `--threads` | Number of concurrent threads | `100` |
| `--timeout` | Per-port connection timeout (seconds) | `1.0` |

### Examples

```bash
# Scan common ports on localhost
python3 port_scanner.py 127.0.0.1

# Scan a custom port range
python3 port_scanner.py example.com -p 1-1000

# Scan specific ports with more threads
python3 port_scanner.py 192.168.1.10 -p 20-25,80,443,8000-8100 -t 200
```

## Example Output
Scanning 127.0.0.1 (127.0.0.1) — 1024 ports, 100 threads
Port    22/tcp  OPEN   (SSH)
Port    80/tcp  OPEN   (HTTP)
Found 2 open port(s): [22, 80]
Scan completed in 1.34 seconds

## License

MIT (or choose whatever license you prefer)
