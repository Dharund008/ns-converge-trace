"""
ns-converge-trace — Unified NS propagation / DNS cutover convergence checker.

Checks a domain's NS delegation across 3 layers in a single pass:

  1. Registry layer        — auto-detects the TLD, queries the TLD's own
                              nameservers to see what NS the registry has
                              delegated (source of truth during a cutover).
  2. Authoritative layer   — queries each delegated NS hostname directly
                              (works for ANY provider — Cloudflare, Route53,
                              GoDaddy, etc. — nothing hardcoded).
  3. Public resolver layer — queries a configurable set of public resolvers
                              to see what the world currently sees.

Convergence is determined by comparing every layer's answer against the
registry's delegation (the definitive source of truth for "who SHOULD be
authoritative" during a cutover).

DNS ENGINE (hybrid, auto-selected):
  - Prefers the system `dig` binary when present on PATH. `dig` natively
    handles TCP-retry-on-truncation, EDNS0, and years of real-world edge
    cases — no reason to reinvent that when it's available.
  - Falls back to a built-in pure-Python DNS client (stdlib only: socket,
    struct) when `dig` is not installed (e.g. bare Windows, minimal
    containers). The fallback implements:
      * EDNS0 (requests a larger UDP payload to avoid truncation)
      * TCP fallback when the TC (truncated) flag is set in the response
      * Basic IDN label encoding (punycode) for non-ASCII domains
  - Force a specific engine with --engine dig | python (mainly for testing).

KNOWN LIMITATIONS:
  - TLD extraction is naive (last label only) — does not correctly handle
    two-part public suffixes like .co.uk or .com.au (would treat 'uk'/'au'
    as the TLD and query the wrong registry). Fine for .com/.io/.net/etc.
  - IPv6-only authoritative nameservers (AAAA-only glue) are not resolved.
    Virtually all major DNS providers publish IPv4 glue for their NS
    hostnames, so this is rare in practice — but if hit, this tool reports
    a clear resolution error rather than silently producing a wrong answer.

COMPATIBILITY: stdlib-only, no hard Python version floor — avoids
deprecated APIs so it keeps working across current and future 3.x releases.
"""

import argparse
import json
import os
import random
import shutil
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from ns_converge_trace import __version__

# --------------------------------------------------------------------------
# Resolver sets
# --------------------------------------------------------------------------

CORE_RESOLVERS = [
    ("8.8.8.8", "Google"),
    ("1.1.1.1", "Cloudflare"),
    ("9.9.9.9", "Quad9"),
    ("208.67.222.222", "OpenDNS"),
    ("4.2.2.2", "Lumen"),
]

EXTENDED_RESOLVERS = [
    ("64.6.64.6", "Verisign"),
    ("185.228.168.9", "CleanBrowsing"),
    ("94.140.14.14", "AdGuard"),
    ("8.26.56.26", "Comodo"),
    ("84.200.69.80", "DNS.WATCH"),
]

DNS_TIMEOUT = 5
DNS_PORT = 53

ROOT_SERVERS = [
    "198.41.0.4",     # a.root-servers.net
    "199.9.14.201",   # b.root-servers.net
    "192.33.4.12",    # c.root-servers.net
]

# Exit codes
EXIT_CONVERGED = 0
EXIT_PROPAGATING = 1
EXIT_UNKNOWN = 2

# Lazy-cached dig path — resolved on first use so dig installed after
# module import (e.g. during container bootstrap) is still picked up.
_dig_path_cache = None
_dig_path_resolved = False


def _get_dig_path():
    """Resolve dig path lazily (once per process)."""
    global _dig_path_cache, _dig_path_resolved
    if not _dig_path_resolved:
        _dig_path_cache = shutil.which("dig")
        _dig_path_resolved = True
    return _dig_path_cache


class C:
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


class NoColor:
    GREEN = YELLOW = RED = CYAN = BOLD = DIM = RESET = ""


# --------------------------------------------------------------------------
# DNS engine: dig backend
# --------------------------------------------------------------------------

def _dig_query(server, domain, rtype):
    """
    Shell out to `dig`. Relies on dig's own default behavior of retrying
    over TCP automatically if the response is truncated (TC flag) — this
    is standard `dig` behavior, not something we need to implement.
    `server` may be a hostname or an IP; dig resolves hostnames itself.

    Uses +noall +answer +authority rather than +short: a server that is
    not authoritative for `domain` (e.g. a root server asked "NS com")
    replies with a referral — the requested records land in the AUTHORITY
    section, not ANSWER — and +short only ever prints ANSWER, so it would
    silently report "no records" for a perfectly valid referral.

    Returns (sorted_values, error_or_None, min_ttl_or_None).
    """
    dig_path = _get_dig_path()
    if not dig_path:
        return [], "dig not found", None

    cmd = [
        dig_path, rtype, domain, f"@{server}",
        "+noall", "+answer", "+authority",
        f"+time={DNS_TIMEOUT}", "+tries=1",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=DNS_TIMEOUT + 3
        )
    except subprocess.TimeoutExpired:
        return [], "timeout", None
    except FileNotFoundError:
        return [], "dig not found", None

    if result.returncode != 0 and not result.stdout.strip():
        err = (result.stderr or "").strip() or f"dig exited {result.returncode}"
        return [], err, None

    values = []
    min_ttl = None
    rtype_upper = rtype.upper()
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        fields = line.split()
        # Resource record lines: NAME TTL CLASS TYPE RDATA...
        if len(fields) < 5 or fields[3].upper() != rtype_upper:
            continue
        values.append(fields[4].rstrip(".").lower())
        try:
            ttl = int(fields[1])
            if min_ttl is None or ttl < min_ttl:
                min_ttl = ttl
        except (ValueError, IndexError):
            pass

    return sorted(set(values)), None, min_ttl


# --------------------------------------------------------------------------
# DNS engine: pure-Python fallback (stdlib only)
# Implements EDNS0 + TCP-on-truncation + basic IDN handling.
# --------------------------------------------------------------------------

def _encode_label(label):
    """Encode a single DNS label, punycode-ing it if it contains non-ASCII
    characters (basic IDN support)."""
    try:
        label.encode("ascii")
        return label.encode("ascii")
    except UnicodeEncodeError:
        try:
            return label.encode("idna")
        except UnicodeError:
            return label.encode("ascii", "ignore")


def _encode_qname(domain):
    domain = domain.strip(".")
    out = b""
    for part in domain.split("."):
        if not part:
            continue
        enc = _encode_label(part)
        out += struct.pack("B", len(enc)) + enc
    return out + b"\x00"


def _build_query(domain, qtype, use_edns0=True):
    txid = random.randint(0, 0xFFFF)
    flags = 0x0100  # RD=1 (recursion desired) — required for public recursive resolvers
    qdcount = 1
    arcount = 1 if use_edns0 else 0
    header = struct.pack(">HHHHHH", txid, flags, qdcount, 0, 0, arcount)
    question = _encode_qname(domain) + struct.pack(">HH", qtype, 1)  # class IN

    packet = header + question
    if use_edns0:
        opt = struct.pack(">BHHIH", 0x00, 41, 4096, 0, 0)
        packet += opt
    return txid, packet


def _parse_name(data, offset):
    labels = []
    jumped = False
    original_offset = offset
    seen_offsets = set()
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset in seen_offsets:
                break
            seen_offsets.add(offset)
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", "ignore"))
        offset += length
    final_offset = original_offset if jumped else offset
    return ".".join(labels), final_offset


def _parse_response(data, txid, qtype):
    """Parse a DNS response. Returns (results, error, tc_flag, min_ttl)."""
    if len(data) < 12:
        return [], "malformed response", False, None
    resp_txid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    if resp_txid != txid:
        return [], "txid mismatch", False, None

    tc_flag = bool(flags & 0x0200)
    rcode = flags & 0x000F
    if rcode == 3:
        return [], "NXDOMAIN", tc_flag, None

    offset = 12
    for _ in range(qdcount):
        _, offset = _parse_name(data, offset)
        offset += 4

    results = []
    min_ttl = None
    for _ in range(ancount + nscount):
        if offset >= len(data):
            break
        _, offset = _parse_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata_start = offset
        if rtype == qtype:
            if qtype == 2:  # NS
                name, _ = _parse_name(data, rdata_start)
                if name:
                    results.append(name.rstrip("."))
                    if min_ttl is None or ttl < min_ttl:
                        min_ttl = ttl
            elif qtype == 1 and rdlength == 4:  # A
                ip = ".".join(str(b) for b in data[rdata_start:rdata_start + 4])
                results.append(ip)
                if min_ttl is None or ttl < min_ttl:
                    min_ttl = ttl
        offset += rdlength

    if rcode != 0 and not results:
        return [], f"rcode={rcode}", tc_flag, None
    return sorted(set(r.lower() for r in results)), None, tc_flag, min_ttl


def _query_udp(server_ip, packet, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(packet, (server_ip, DNS_PORT))
        data, _ = s.recvfrom(8192)
        return data, None
    except socket.timeout:
        return None, "timeout"
    except OSError as e:
        return None, f"socket error: {e}"
    finally:
        s.close()


def _query_tcp(server_ip, packet, timeout):
    """TCP DNS query: 2-byte length prefix + message, same prefix on response."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((server_ip, DNS_PORT))
        length_prefix = struct.pack(">H", len(packet))
        s.sendall(length_prefix + packet)

        resp_len_data = s.recv(2)
        if len(resp_len_data) < 2:
            return None, "incomplete TCP length prefix"
        resp_len = struct.unpack(">H", resp_len_data)[0]

        data = b""
        while len(data) < resp_len:
            chunk = s.recv(resp_len - len(data))
            if not chunk:
                break
            data += chunk
        return data, None
    except socket.timeout:
        return None, "TCP timeout"
    except OSError as e:
        return None, f"TCP socket error: {e}"
    finally:
        s.close()


def _python_query(server_ip, domain, qtype, timeout=DNS_TIMEOUT):
    """
    Pure-Python DNS query with EDNS0 + automatic TCP fallback on truncation.
    Returns (results_list, error_or_None, min_ttl_or_None).
    """
    txid, packet = _build_query(domain, qtype, use_edns0=True)
    data, err = _query_udp(server_ip, packet, timeout)
    if err:
        return [], err, None

    results, parse_err, tc_flag, min_ttl = _parse_response(data, txid, qtype)

    if tc_flag:
        tcp_data, tcp_err = _query_tcp(server_ip, packet, timeout)
        if tcp_err:
            if results:
                return results, f"partial (TCP retry failed: {tcp_err})", min_ttl
            return [], tcp_err, None
        tcp_results, tcp_parse_err, _, tcp_ttl = _parse_response(tcp_data, txid, qtype)
        if tcp_results:
            return tcp_results, None, tcp_ttl
        return results, parse_err, min_ttl

    return results, parse_err, min_ttl


def _is_ip_literal(s):
    try:
        socket.inet_aton(s)
        return True
    except OSError:
        return False


def _python_resolve_a(hostname, bootstrap_resolver="8.8.8.8"):
    """Resolve a hostname to an IPv4 address for the pure-Python engine."""
    if _is_ip_literal(hostname):
        return hostname, None
    ips, err, _ttl = _python_query(bootstrap_resolver, hostname, qtype=1)
    if ips:
        return ips[0], None
    try:
        return socket.gethostbyname(hostname), None
    except socket.gaierror as e:
        return None, str(e)


# --------------------------------------------------------------------------
# Unified engine dispatch
# --------------------------------------------------------------------------

def query_ns(server, domain, engine="auto"):
    """
    Query NS records for `domain` from `server` (hostname or IP).
    engine: "auto" (prefer dig, fallback python), "dig", or "python".
    Returns (ns_list, error_or_None, min_ttl_or_None).
    """
    use_dig = (engine == "dig") or (engine == "auto" and _get_dig_path())
    if use_dig:
        return _dig_query(server, domain, "NS")

    server_ip, resolve_err = _python_resolve_a(server)
    if not server_ip:
        return [], f"could not resolve server '{server}': {resolve_err}", None
    return _python_query(server_ip, domain, qtype=2)


# --------------------------------------------------------------------------
# Layered checks
# --------------------------------------------------------------------------

def get_tld(domain):
    """
    Best-effort TLD extraction (last label only).
    KNOWN LIMITATION: does not handle two-part public suffixes
    (e.g. .co.uk, .com.au) — see module docstring.
    """
    parts = domain.strip(".").split(".")
    return parts[-1] if len(parts) > 1 else domain


def get_registry_layer(domain, engine="auto"):
    tld = get_tld(domain)

    tld_ns_names = []
    for root_ip in ROOT_SERVERS:
        names, err, _ttl = query_ns(root_ip, tld, engine=engine)
        if names:
            tld_ns_names = names
            break
    if not tld_ns_names:
        return {
            "layer": "Registry",
            "source": f".{tld} registry (root lookup failed)",
            "ns_records": [],
            "min_ttl": None,
            "error": "could not resolve TLD nameservers from root servers",
        }

    for tld_ns_host in tld_ns_names:
        ns_list, err, min_ttl = query_ns(tld_ns_host, domain, engine=engine)
        if ns_list:
            return {
                "layer": "Registry",
                "source": f".{tld} registry ({tld_ns_host})",
                "ns_records": ns_list,
                "min_ttl": min_ttl,
                "error": None,
            }

    return {
        "layer": "Registry",
        "source": f".{tld} registry ({tld_ns_names[0]})",
        "ns_records": [],
        "min_ttl": None,
        "error": "no NS returned by any TLD server",
    }


def get_authoritative_layer(domain, delegated_ns_hosts, engine="auto"):
    rows = []
    if not delegated_ns_hosts:
        rows.append({
            "layer": "Authoritative",
            "source": "(no delegated NS hostnames — registry lookup empty)",
            "ns_records": [],
            "min_ttl": None,
            "error": "skipped",
        })
        return rows

    for ns_host in delegated_ns_hosts:
        ns_list, err, min_ttl = query_ns(ns_host, domain, engine=engine)
        rows.append({
            "layer": "Authoritative",
            "source": ns_host,
            "ns_records": ns_list,
            "min_ttl": min_ttl,
            "error": err if not ns_list else None,
        })
    return rows


def get_resolver_layer(domain, resolvers, engine="auto"):
    """Query all public resolvers in parallel using a thread pool."""
    rows = []

    def _query_one(ip, name):
        ns_list, err, min_ttl = query_ns(ip, domain, engine=engine)
        return {
            "layer": "Resolver",
            "source": f"{name} ({ip})",
            "ns_records": ns_list,
            "min_ttl": min_ttl,
            "error": err if not ns_list else None,
        }

    with ThreadPoolExecutor(max_workers=len(resolvers)) as pool:
        # Submit in order, keyed by index to preserve display order
        futures = {pool.submit(_query_one, ip, name): idx for idx, (ip, name) in enumerate(resolvers)}
        results_by_idx = {}
        for future in as_completed(futures):
            idx = futures[future]
            try:
                results_by_idx[idx] = future.result()
            except Exception as e:
                results_by_idx[idx] = {
                    "layer": "Resolver",
                    "source": resolvers[idx][1] + f" ({resolvers[idx][0]})",
                    "ns_records": [],
                    "min_ttl": None,
                    "error": str(e),
                }

    for idx in range(len(resolvers)):
        rows.append(results_by_idx[idx])

    return rows


def _format_ttl(seconds):
    """Format TTL seconds into a human-readable string."""
    if seconds is None:
        return ""
    if seconds >= 3600:
        h = seconds // 3600
        m = (seconds % 3600) // 60
        return f"{h}h{m}m" if m else f"{h}h"
    if seconds >= 60:
        m = seconds // 60
        s = seconds % 60
        return f"{m}m{s}s" if s else f"{m}m"
    return f"{seconds}s"


def check_domain(domain, resolvers, engine="auto"):
    registry = get_registry_layer(domain, engine=engine)
    baseline = registry["ns_records"]

    auth_rows = get_authoritative_layer(domain, baseline, engine=engine)
    resolver_rows = get_resolver_layer(domain, resolvers, engine=engine)
    all_rows = auth_rows + resolver_rows

    for row in all_rows:
        if row.get("error") == "skipped":
            row["status"] = "SKIPPED"
        elif row["error"] and not row["ns_records"]:
            row["status"] = "ERROR"
        elif not baseline:
            row["status"] = "UNKNOWN"
        elif row["ns_records"] == baseline:
            row["status"] = "CONVERGED"
        else:
            row["status"] = "DIVERGED"

    converged_count = sum(1 for r in all_rows if r["status"] == "CONVERGED")
    total_checked = sum(1 for r in all_rows if r["status"] != "SKIPPED")
    fully_converged = bool(baseline) and total_checked > 0 and converged_count == total_checked

    return {
        "domain": domain,
        "tld": get_tld(domain),
        "engine_used": "dig" if (engine == "dig" or (engine == "auto" and _get_dig_path())) else "python",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "registry": registry,
        "rows": all_rows,
        "baseline_ns": baseline,
        "fully_converged": fully_converged,
        "converged_count": converged_count,
        "total_checked": total_checked,
    }


# --------------------------------------------------------------------------
# Output rendering
# --------------------------------------------------------------------------

def _get_ns_col_width():
    """Derive NS RECORDS column width from terminal size."""
    try:
        cols = shutil.get_terminal_size((100, 24)).columns
    except (ValueError, OSError):
        cols = 100
    # Layout: LAYER(15) + SOURCE(32) + NS(dynamic) + TTL(10) + STATUS(12) + spacing
    # Reserve ~72 for fixed columns, give the rest to NS (min 30)
    ns_width = max(30, cols - 72)
    return ns_width


def status_color(status, c):
    return {
        "CONVERGED": c.GREEN,
        "DIVERGED": c.RED,
        "ERROR": c.YELLOW,
        "UNKNOWN": c.YELLOW,
        "SKIPPED": c.YELLOW,
    }.get(status, "")


def render_table(result, use_color=True):
    domain = result["domain"]
    lines = []
    c = C if use_color else NoColor()
    ns_width = _get_ns_col_width()

    lines.append(
        f"{c.BOLD}{c.CYAN}=== {domain} (.{result['tld']}) — engine: {result['engine_used']} — "
        f"checked {result['checked_at']} ==={c.RESET}"
    )

    reg = result["registry"]
    baseline_str = ", ".join(reg["ns_records"]) if reg["ns_records"] else f"(unavailable: {reg.get('error')})"
    ttl_note = f" [TTL {_format_ttl(reg.get('min_ttl'))}]" if reg.get("min_ttl") is not None else ""
    lines.append(f"{c.BOLD}Registry baseline{c.RESET} [{reg['source']}]: {baseline_str}{ttl_note}")
    lines.append("")

    header = f"{'LAYER':<15} {'SOURCE':<32} {'NS RECORDS':<{ns_width}} {'TTL':<10} {'STATUS'}"
    lines.append(header)
    lines.append("-" * len(header))

    for row in result["rows"]:
        if row["status"] == "SKIPPED":
            ns_str = row.get("error", "skipped")
        elif row["error"] and not row["ns_records"]:
            ns_str = f"(error: {row['error']})"
        else:
            ns_str = ", ".join(row["ns_records"]) if row["ns_records"] else "(empty)"
        truncated_at = ns_width - 3
        if len(ns_str) > truncated_at:
            ns_str = ns_str[:truncated_at] + "..."

        ttl_str = _format_ttl(row.get("min_ttl")) if row.get("min_ttl") is not None else ""
        color = status_color(row["status"], c)
        reset = c.RESET
        status_icon = {
            "CONVERGED": "PASS",
            "DIVERGED": "DIVERGED",
            "ERROR": "ERROR",
            "UNKNOWN": "N/A",
            "SKIPPED": "SKIPPED",
        }.get(row["status"], row["status"])

        lines.append(
            f"{row['layer']:<15} {row['source']:<32} {ns_str:<{ns_width}} {ttl_str:<10} {color}{status_icon}{reset}"
        )

    lines.append("")
    if not result["baseline_ns"]:
        lines.append(f"{c.YELLOW}Overall: UNKNOWN — could not establish registry baseline{c.RESET}")
    elif result["fully_converged"]:
        lines.append(f"{c.GREEN}{c.BOLD}Overall: CONVERGED — all {result['total_checked']} checks match registry delegation{c.RESET}")
    else:
        lines.append(
            f"{c.YELLOW}{c.BOLD}Overall: PROPAGATING — {result['converged_count']}/{result['total_checked']} checks converged{c.RESET}"
        )
    lines.append("")
    return "\n".join(lines)


def render_brief(result):
    """Single-line output: DOMAIN: STATUS"""
    if not result["baseline_ns"]:
        return f"{result['domain']}: UNKNOWN"
    elif result["fully_converged"]:
        return f"{result['domain']}: CONVERGED"
    else:
        return f"{result['domain']}: PROPAGATING ({result['converged_count']}/{result['total_checked']})"


def render_watch_diff(prev_rows, curr_rows, use_color=True):
    """Show what changed between two consecutive --watch attempts."""
    c = C if use_color else NoColor()
    changes = []
    prev_by_source = {r["source"]: r for r in prev_rows}
    for row in curr_rows:
        prev = prev_by_source.get(row["source"])
        if prev is None:
            continue
        old_status = prev["status"]
        new_status = row["status"]
        if old_status != new_status:
            color = c.GREEN if new_status == "CONVERGED" else c.YELLOW
            changes.append(
                f"  {color}↳ {row['source']}: {old_status} → {new_status}{c.RESET}"
            )
    if changes:
        return f"{c.DIM}[changes]{c.RESET}\n" + "\n".join(changes)
    return f"{c.DIM}[no changes since last check]{c.RESET}"


def parse_resolvers_arg(items):
    resolvers = []
    for item in items:
        if ":" in item:
            ip, name = item.split(":", 1)
        else:
            ip, name = item, item
        resolvers.append((ip, name))
    return resolvers


def _overall_status(result):
    """Return the exit code for a single domain check."""
    if not result["baseline_ns"]:
        return EXIT_UNKNOWN
    if result["fully_converged"]:
        return EXIT_CONVERGED
    return EXIT_PROPAGATING


def main():
    parser = argparse.ArgumentParser(
        prog="ns-converge-trace",
        description="ns-converge-trace — check NS propagation across registry, authoritative, and public resolver layers.",
    )
    parser.add_argument("domains", nargs="*", help="Domain(s) to check")
    parser.add_argument("-f", "--file", help="Path to a text file with one domain per line")
    parser.add_argument(
        "--watch", action="store_true",
        help="Poll repeatedly until fully converged. NOTE: when multiple "
             "domains are given, each domain is watched sequentially — the "
             "next domain's watch begins only after the previous one converges "
             "(or hits --max-attempts).",
    )
    parser.add_argument("--interval", type=int, default=30, help="Seconds between polls in --watch mode (default: 30)")
    parser.add_argument("--max-attempts", type=int, default=0, help="Max polling attempts in --watch mode (0 = unlimited)")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON instead of a table")
    parser.add_argument("--brief", action="store_true", help="One-line output per domain: DOMAIN: STATUS (for scripting)")
    parser.add_argument("--log", action="store_true", help="Also write a timestamped log file of this run")
    parser.add_argument("--log-path", help="Custom path for the log file")
    parser.add_argument("--resolvers", nargs="*", default=None, help="Custom resolver list as IP:Name pairs, e.g. 9.9.9.9:Quad9")
    parser.add_argument("--resolver-set", choices=["core", "full"], default="core",
                         help="core = 5 major resolvers (default), full = all 10")
    parser.add_argument("--engine", choices=["auto", "dig", "python"], default="auto",
                         help="DNS engine: auto (prefer dig, fallback to pure-Python), or force one explicitly")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in table output")
    parser.add_argument("--version", action="version", version=f"ns-converge-trace {__version__}")

    args = parser.parse_args()

    domains = list(args.domains)
    if args.file:
        with open(args.file) as f:
            domains.extend([l.strip() for l in f if l.strip() and not l.strip().startswith("#")])

    if not domains:
        parser.error("No domains provided. Pass domain(s) as arguments or use -f/--file.")

    if args.resolvers:
        resolvers = parse_resolvers_arg(args.resolvers)
    elif args.resolver_set == "full":
        resolvers = CORE_RESOLVERS + EXTENDED_RESOLVERS
    else:
        resolvers = CORE_RESOLVERS

    if args.engine == "dig" and not _get_dig_path():
        print("ERROR: --engine dig was forced, but `dig` was not found on PATH.", file=sys.stderr)
        sys.exit(1)

    # Respect NO_COLOR (https://no-color.org/) and --no-color flag
    use_color = not args.no_color and sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    log_lines = []
    worst_exit = EXIT_CONVERGED  # track worst status across all domains

    def log_and_print(text):
        print(text)
        if args.log:
            log_lines.append(text)

    for domain in domains:
        attempt = 0
        prev_rows = None
        while True:
            attempt += 1
            result = check_domain(domain, resolvers, engine=args.engine)

            # Track the worst exit code across all domains
            domain_status = _overall_status(result)
            if domain_status > worst_exit:
                worst_exit = domain_status

            if args.brief:
                log_and_print(render_brief(result))
            elif args.json:
                output = json.dumps(result, indent=2)
                log_and_print(output)
            else:
                if args.watch:
                    print(f"\n[Attempt {attempt}]")
                output = render_table(result, use_color=use_color)
                log_and_print(output)

                # Show diff from previous attempt in watch mode
                if args.watch and prev_rows is not None:
                    diff_text = render_watch_diff(prev_rows, result["rows"], use_color=use_color)
                    log_and_print(diff_text)

            prev_rows = result["rows"]

            if not args.watch:
                break
            if result["fully_converged"]:
                log_and_print(f">>> {domain}: fully converged after {attempt} attempt(s). Stopping watch.")
                break
            if args.max_attempts and attempt >= args.max_attempts:
                log_and_print(f">>> {domain}: max attempts ({args.max_attempts}) reached without full convergence.")
                break
            try:
                time.sleep(args.interval)
            except KeyboardInterrupt:
                log_and_print(f">>> {domain}: watch interrupted by user.")
                break

    if args.log and log_lines:
        if args.log_path:
            log_path = args.log_path
        else:
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            safe_name = domains[0].replace(".", "_") if len(domains) == 1 else "multi"
            log_path = f"ns-converge-trace-{safe_name}-{ts}.log"
        with open(log_path, "w") as f:
            f.write("\n".join(log_lines))
        print(f"\n[Log written to: {log_path}]")

    sys.exit(worst_exit)


if __name__ == "__main__":
    main()
