# LanSentry

A lightweight, dependency-free TCP port and network scanner for
auditing devices and open services on your home network.

## ⚠️ Only scan networks you own or manage

Unauthorized scanning of networks you don't control can be illegal.
This tool is meant for your homelab, personal LAN, or systems you
have explicit permission to test.

## Features

- Scan a single host, hostname, or an entire CIDR subnet
  (e.g. `192.168.1.0/24`)
- Curated list of ~60 common/homelab-relevant ports (Plex, Home
  Assistant, Portainer, Proxmox, databases, remote access, etc.), or
  supply your own ports/ranges
- Multi-threaded for fast scans, with tunable concurrency and timeout
- Best-effort banner grabbing to help identify what's actually
  running on an open port
- Export results to JSON or CSV for record-keeping or diffing
  between scans
- Zero third-party dependencies — pure Python standard library

## Installation

### Requirements

- Python 3.7 or later

### 1. Get the files

```bash
git clone https://github.com/shaddy5635-ship-it/LanSentry.git
cd LanSentry
```

(Or just download `LanSentry.py` directly if you don't want to clone
a repo.)

### 2. (Optional) Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

LanSentry has no third-party dependencies, so this step is a no-op —
it's included for convention and for CI/tooling that expects a
`requirements.txt` to exist.

### 4. Verify it runs

```bash
python3 lansentry.py --help
```

## Usage

```bash
# Scan a single host for common/interesting ports
python3 lansentry.py -t 192.168.1.10

# Scan an entire subnet (this also acts as host discovery)
python3 lansentry.py -t 192.168.1.0/24

# Scan specific ports
python3 lansentry.py -t 192.168.1.10 -p 22,80,443,8080

# Scan a port range
python3 lansentry.py -t 192.168.1.10 -p 1-1024

# Tune speed vs. accuracy
python3 lansentry.py -t 192.168.1.0/24 --threads 200 --timeout 0.5

# Save results
python3 lansentry.py -t 192.168.1.0/24 -o results.json
python3 lansentry.py -t 192.168.1.0/24 -o results.csv
```

### CLI options

| Flag | Description | Default |
|---|---|---|
| `-t`, `--target` | Single IP, hostname, or CIDR range | *(required)* |
| `-p`, `--ports` | `common`, a comma list, or a range like `1-1024` | `common` |
| `--timeout` | Per-connection timeout in seconds | `1.0` |
| `--threads` | Concurrent worker threads | `100` |
| `-o`, `--output` | Save results to a `.json` or `.csv` file | *(none)* |

## How it works

1. **Parses your target** — a single IP, a hostname, or a CIDR block
   (e.g. `192.168.1.0/24` expands to every host in that subnet).
2. **Parses your port spec** — `common`, a comma list, or a range.
3. **Scans concurrently** with a thread pool, doing a TCP connect to
   each host:port pair.
4. **Grabs a banner** where possible — many services announce
   themselves right after connecting, which helps identify what's
   actually running on a port.
5. **Reports open ports** live as they're found, then prints a
   summary, and optionally writes JSON/CSV for later reference.

## Good homelab uses

- Periodically re-scan your LAN to catch devices/services you forgot
  were exposed (e.g. a container that published a port to `0.0.0.0`
  instead of `127.0.0.1`).
- Verify a firewall or VLAN change actually closed the ports you
  intended to close.
- Inventory what's listening on a new device before you trust it on
  your network.

## Limitations

- This is a TCP **connect** scan (not a raw SYN scan), so it doesn't
  need root privileges but is a bit more visible/slower than tools
  like `nmap -sS`.
- Host discovery is implicit: hosts with no open ports in your chosen
  port list will simply show zero results rather than being flagged
  as "down." True ICMP ping-sweep discovery differs by OS and
  typically needs elevated privileges — out of scope here to keep the
  tool dependency-free and cross-platform.
- UDP services (like some DNS/SNMP setups) won't show up — this tool
  only checks TCP.

## License

MIT — see [LICENSE](LICENSE) for details.
