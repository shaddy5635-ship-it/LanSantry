#!/usr/bin/env python3
"""
LanSentry — Homelab Network & Port Scanner
-------------------------------------------
A lightweight TCP connect-scan tool for auditing devices and open ports
on networks YOU own or have explicit permission to test (e.g. your
homelab or personal LAN).

Only scan networks you have permission to scan. Scanning networks
you don't own or manage may be illegal in your jurisdiction.

Usage examples:
    # Scan a single host, common ports
    python3 lansentry.py -t 192.168.1.10

    # Scan a whole subnet for common ports (also does host discovery)
    python3 lansentry.py -t 192.168.1.0/24

    # Scan specific ports on a host
    python3 lansentry.py -t 192.168.1.10 -p 22,80,443,8080

    # Scan a port range
    python3 lansentry.py -t 192.168.1.10 -p 1-1024

    # More threads / shorter timeout for a faster (but noisier) scan
    python3 lansentry.py -t 192.168.1.0/24 --threads 200 --timeout 0.5

    # Save results
    python3 lansentry.py -t 192.168.1.0/24 -o results.json
    python3 lansentry.py -t 192.168.1.0/24 -o results.csv
"""

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import socket
import sys
import time

# A reasonable "top ports" list covering common services on a home network
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 80: "http", 110: "pop3", 111: "rpcbind", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    514: "syslog", 515: "printer", 548: "afp", 587: "submission",
    631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1194: "openvpn", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 1883: "mqtt", 2049: "nfs", 2222: "ssh-alt",
    2375: "docker", 2376: "docker-tls", 27017: "mongodb",
    3000: "dev-http", 3128: "squid-proxy", 3306: "mysql",
    3389: "rdp", 5000: "upnp/dev-http", 5060: "sip", 5222: "xmpp",
    5353: "mdns", 5432: "postgresql", 5900: "vnc", 5901: "vnc-1",
    6379: "redis", 7000: "airplay", 8000: "http-alt", 8006: "proxmox",
    8080: "http-proxy", 8081: "http-alt2", 8096: "jellyfin",
    8123: "home-assistant", 8443: "https-alt", 8888: "http-alt3",
    9000: "portainer/dev", 9090: "prometheus/cockpit", 9100: "printer-jetdirect",
    9200: "elasticsearch", 27015: "srcds", 32400: "plex",
}


def parse_ports(port_spec):
    """Parse '22,80,443', '1-1024', or 'common' into a sorted list of ints."""
    if port_spec.lower() == "common":
        return sorted(COMMON_PORTS.keys())

    ports = set()
    for chunk in port_spec.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        elif chunk:
            ports.add(int(chunk))
    return sorted(p for p in ports if 0 < p <= 65535)


def parse_targets(target_spec):
    """Parse a single IP or CIDR range into a list of host strings."""
    try:
        network = ipaddress.ip_network(target_spec, strict=False)
        if network.num_addresses > 1:
            return [str(ip) for ip in network.hosts()]
        return [str(network.network_address)]
    except ValueError:
        # Not an IP/CIDR — assume it's a hostname
        return [target_spec]


def grab_banner(sock):
    """Best-effort banner grab; returns '' if nothing arrives quickly."""
    try:
        sock.settimeout(0.6)
        data = sock.recv(256)
        return data.decode(errors="replace").strip().replace("\r\n", " | ")
    except Exception:
        return ""


def scan_port(host, port, timeout):
    """Attempt a TCP connect to host:port. Returns a result dict or None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "unknown")
                banner = grab_banner(sock)
                return {
                    "host": host,
                    "port": port,
                    "service": service,
                    "banner": banner,
                }
    except (socket.gaierror, OSError):
        return None
    return None


def run_scan(hosts, ports, timeout, max_workers):
    open_results = []
    total = len(hosts) * len(ports)
    completed = 0
    last_print = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(scan_port, host, port, timeout): (host, port)
            for host in hosts
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            result = future.result()
            if result:
                open_results.append(result)
                print(f"  [OPEN] {result['host']:<15} {result['port']:>5}/tcp "
                      f"{result['service']:<15} {result['banner']}")
            now = time.time()
            if now - last_print > 1.5:
                sys.stderr.write(f"\r  scanned {completed}/{total} checks...")
                sys.stderr.flush()
                last_print = now

    sys.stderr.write(f"\r  scanned {completed}/{total} checks... done.\n")
    return sorted(open_results, key=lambda r: (r["host"], r["port"]))


def save_results(results, path):
    if path.lower().endswith(".json"):
        with open(path, "w") as f:
            json.dump(results, f, indent=2)
    elif path.lower().endswith(".csv"):
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["host", "port", "service", "banner"])
            writer.writeheader()
            writer.writerows(results)
    else:
        print(f"Unrecognized output extension for '{path}' — use .json or .csv")
        return
    print(f"\nResults saved to {path}")


def main():
    parser = argparse.ArgumentParser(
        description="LanSentry — homelab TCP port/network scanner. Only scan networks you own or manage.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-t", "--target", required=True,
                         help="Single IP, hostname, or CIDR range (e.g. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="common",
                         help="Ports: 'common' (default), '22,80,443', or a range '1-1024'")
    parser.add_argument("--timeout", type=float, default=1.0,
                         help="Per-connection timeout in seconds (default 1.0)")
    parser.add_argument("--threads", type=int, default=100,
                         help="Concurrent worker threads (default 100)")
    parser.add_argument("-o", "--output", help="Save results to a .json or .csv file")
    args = parser.parse_args()

    hosts = parse_targets(args.target)
    ports = parse_ports(args.ports)

    print(f"Scanning {len(hosts)} host(s) x {len(ports)} port(s) "
          f"= {len(hosts) * len(ports)} checks")
    print(f"(timeout={args.timeout}s, threads={args.threads})\n")

    start = time.time()
    results = run_scan(hosts, ports, args.timeout, args.threads)
    elapsed = time.time() - start

    print(f"\nFound {len(results)} open port(s) across {len(set(r['host'] for r in results))} "
          f"host(s) in {elapsed:.1f}s")

    if args.output:
        save_results(results, args.output)


if __name__ == "__main__":
    main()
