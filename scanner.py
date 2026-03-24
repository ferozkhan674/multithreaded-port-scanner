#!/usr/bin/env python3

import socket
import argparse
import threading
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Common ports & their service names ──────────────────────────────────────
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 119: "NNTP",
    123: "NTP", 135: "RPC", 137: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 587: "SMTP", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
    27017: "MongoDB",
}

print_lock = threading.Lock()


# ── Banner grabbing ──────────────────────────────────────────────────────────
def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """Try to grab a service banner from an open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            # Send a generic probe to trigger a response
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner.splitlines()[0] if banner else ""
    except Exception:
        return ""


# ── Single port scan ─────────────────────────────────────────────────────────
def scan_port(host: str, port: int, timeout: float, grab: bool) -> dict | None:
    """Return a result dict if the port is open, else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                service = COMMON_SERVICES.get(port, "")
                if not service:
                    try:
                        service = socket.getservbyport(port)
                    except OSError:
                        service = "unknown"
                banner = grab_banner(host, port) if grab else ""
                return {"port": port, "service": service, "banner": banner}
    except Exception:
        pass
    return None


# ── Host scanner ─────────────────────────────────────────────────────────────
def scan_host(host: str, ports: list[int], timeout: float,
              threads: int, grab: bool) -> list[dict]:
    """Scan all ports on a single host using a thread pool."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, host, p, timeout, grab): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return sorted(open_ports, key=lambda x: x["port"])


# ── Output helpers ───────────────────────────────────────────────────────────
def print_results(host: str, open_ports: list[dict], start_time: datetime) -> None:
    elapsed = (datetime.now() - start_time).total_seconds()
    with print_lock:
        print(f"\n{'─'*55}")
        print(f"  Host : {host}")
        print(f"  Time : {elapsed:.2f}s  |  Open ports: {len(open_ports)}")
        print(f"{'─'*55}")
        if open_ports:
            print(f"  {'PORT':<8} {'SERVICE':<16} BANNER")
            print(f"  {'----':<8} {'-------':<16} ------")
            for p in open_ports:
                banner_preview = (p["banner"][:40] + "…") if len(p["banner"]) > 40 else p["banner"]
                print(f"  {p['port']:<8} {p['service']:<16} {banner_preview}")
        else:
            print("  No open ports found.")
        print(f"{'─'*55}\n")


def save_results(filename: str, host: str, open_ports: list[dict]) -> None:
    with open(filename, "a") as f:
        f.write(f"\n[{datetime.now()}] Host: {host}\n")
        for p in open_ports:
            f.write(f"  {p['port']:<8} {p['service']:<16} {p['banner']}\n")
        f.write("\n")


# ── Port range parser ────────────────────────────────────────────────────────
def parse_ports(port_str: str) -> list[int]:
    """Parse '22,80,100-200' style port strings into a sorted list."""
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


# ── Resolve targets (supports CIDR) ─────────────────────────────────────────
def resolve_targets(target: str) -> list[str]:
    try:
        network = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return [target]  # single hostname or IP


# ── CLI entry point ──────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="🔍 Multi-threaded Python Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target IP, hostname, or CIDR (e.g. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Port range or list: '1-1024' or '22,80,443' (default: 1-1024)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("--threads", type=int, default=100,
                        help="Number of threads (default: 100)")
    parser.add_argument("--banner", action="store_true",
                        help="Attempt to grab service banners")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Save results to a file")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    targets = resolve_targets(args.target)

    print(f"\n{'='*55}")
    print(f"  🔍 Port Scanner — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Targets : {len(targets)} host(s)")
    print(f"  Ports   : {len(ports)} ({args.ports})")
    print(f"  Threads : {args.threads}  |  Timeout: {args.timeout}s")
    print(f"  Banners : {'yes' if args.banner else 'no'}")
    print(f"{'='*55}")

    for host in targets:
        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            print(f"  [!] Cannot resolve: {host}")
            continue

        start = datetime.now()
        open_ports = scan_host(ip, ports, args.timeout, args.threads, args.banner)
        print_results(ip, open_ports, start)

        if args.output:
            save_results(args.output, ip, open_ports)

    if args.output:
        print(f"  ✅ Results saved to: {args.output}\n")


if __name__ == "__main__":
    main()
