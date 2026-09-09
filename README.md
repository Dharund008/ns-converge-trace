# ns-converge-trace

Unified NS propagation / DNS cutover convergence checker.

Instead of running separate `dig` commands against the registry, the
authoritative provider, and multiple public resolvers, `ns-converge-trace`
checks all three layers for a domain in one pass and tells you whether NS
propagation has fully converged.

## What it checks

| Layer | What it verifies |
|---|---|
| **Registry** | Auto-detects the TLD, walks root servers → TLD servers, and asks the registry itself who this domain is delegated to. This is the source of truth during a cutover. |
| **Authoritative** | Queries each delegated NS hostname directly (from the registry layer). Works for any provider — Cloudflare, Route53, GoDaddy, etc. — nothing hardcoded. |
| **Resolver** | Queries a set of public DNS resolvers to see what the world currently sees. |

Every layer's answer is compared against the registry baseline. If all
layers agree, the domain is **CONVERGED**. If any layer disagrees, it's
**PROPAGATING** (still catching up) — and the table shows exactly which
layer/resolver is behind.

No API keys. No config files. No provider-specific hardcoding.

**Additional capabilities:**
- **TTL reporting** — every row shows the minimum TTL of cached NS records, so you know roughly when a stale answer will expire
- **Parallel resolver queries** — public resolvers are queried concurrently, so checking 5–10 resolvers takes the time of the slowest, not the sum
- **Watch mode diff** — in `--watch` mode, shows what changed since the previous poll instead of requiring you to re-read the full table

## Exit codes

| Code | Meaning |
|---|---|
| `0` | **CONVERGED** — all layers match the registry delegation |
| `1` | **PROPAGATING** — at least one layer hasn't caught up yet |
| `2` | **UNKNOWN** — couldn't establish the registry baseline |

When checking multiple domains, the exit code reflects the **worst** status
across all of them (UNKNOWN > PROPAGATING > CONVERGED).

## DNS engine

Prefers the system `dig` binary if available on PATH; falls back to a
built-in pure-Python DNS client (stdlib only, zero dependencies). Force
with `--engine dig` or `--engine python`.

## Installation

```bash
pip install .
```

This installs the `ns-converge-trace` command onto your PATH.

For local development (editable install, so code changes take effect immediately):

```bash
pip install -e .
```

No installation is required if `dig` is present — you can also run the
module directly without installing:

```bash
python3 -m ns_converge_trace.cli example.com
```

## Usage

```bash
# Single domain, one-shot check
ns-converge-trace example.com

# Multiple domains in one run
ns-converge-trace example.com example2.io example3.net

# From a list file (one domain per line, '#' lines ignored)
ns-converge-trace -f domains.txt

# Poll repeatedly until fully converged (checks every 30s by default)
ns-converge-trace example.com --watch

# Watch with a custom interval and a cap on attempts
ns-converge-trace example.com --watch --interval 15 --max-attempts 10

# Machine-readable JSON output
ns-converge-trace example.com --json

# One-line status for scripting (just "DOMAIN: STATUS")
ns-converge-trace example.com --brief

# Save a timestamped log file of the run (cutover evidence trail)
ns-converge-trace example.com --log
ns-converge-trace example.com --log --log-path my-cutover-evidence.log

# Use the extended resolver set (10 resolvers instead of the default 5)
ns-converge-trace example.com --resolver-set full

# Fully custom resolver list (overrides --resolver-set)
ns-converge-trace example.com --resolvers 9.9.9.9:Quad9 208.67.222.222:OpenDNS

# Force a specific DNS engine
ns-converge-trace example.com --engine dig
ns-converge-trace example.com --engine python

# Disable colored output (e.g. for piping to a file/CI log)
ns-converge-trace example.com --no-color

# Show version
ns-converge-trace --version
```

### All CLI flags

| Flag | Description |
|---|---|
| `domains` (positional) | One or more domains to check |
| `-f, --file PATH` | Read domains from a text file, one per line |
| `--watch` | Poll repeatedly until fully converged (or Ctrl+C). See note below on multi-domain behavior. |
| `--interval SECONDS` | Seconds between polls in `--watch` mode (default: 30) |
| `--max-attempts N` | Stop watch mode after N attempts (0 = unlimited, default) |
| `--json` | Output machine-readable JSON instead of a table |
| `--brief` | One-line output per domain — `DOMAIN: STATUS` — for scripting |
| `--log` | Write a timestamped log file of this run |
| `--log-path PATH` | Custom path/filename for the log file |
| `--resolvers IP:Name ...` | Custom resolver list, overrides `--resolver-set` |
| `--resolver-set {core,full}` | `core` (5 resolvers, default) or `full` (10 resolvers) |
| `--engine {auto,dig,python}` | DNS engine selection (default: `auto`) |
| `--no-color` | Disable ANSI colors in table output (also respects `NO_COLOR` env var) |
| `--version` | Print version and exit |

> **`--watch` with multiple domains:** Domains are watched **sequentially** —
> each domain's watch loop runs until that domain converges (or hits
> `--max-attempts`) before the next domain begins. If you need to watch
> multiple domains in parallel, run separate `ns-converge-trace --watch`
> instances in different terminal tabs or with `&` backgrounding.

## Known limitations

- **TLD extraction is naive** (last label only). It does not correctly
  handle two-part public suffixes like `.co.uk` or `.com.au` — it would
  treat `uk`/`au` as the TLD and query the wrong registry. Fine for
  `.com`, `.io`, `.net`, and other single-label TLDs.
- **IPv6-only authoritative nameservers are not resolved.** Virtually all
  major DNS providers (Cloudflare, Route53, etc.) publish IPv4 glue
  records for their NS hostnames, so this is rare in practice. If
  encountered, the tool reports a clear resolution error rather than
  silently producing a wrong answer.
- Resolver reachability depends on your network. Some resolvers may be
  blocked or unreachable from certain networks (corporate firewalls,
  restricted sandboxes, etc.) — this will show as an `ERROR` row rather
  than a false convergence result.
- **`--watch` with multiple domains is sequential**, not parallel. See the
  note under CLI flags above.

## Requirements

- Python 3.7+ (stdlib only, no third-party runtime dependencies)
- Optional: system `dig` binary (`bind-utils` on RHEL/CentOS, `dnsutils` on
  Debian/Ubuntu) — used automatically if present, otherwise the built-in
  Python DNS engine is used instead

## Resolver sets

### Core (default — 5 resolvers)

| Resolver | IP | Note |
|---|---|---|
| Google | `8.8.8.8` | Largest public DNS resolver |
| Cloudflare | `1.1.1.1` | Fast, privacy-focused, widely used |
| Quad9 | `9.9.9.9` | Security-focused (blocks known-malicious domains) |
| OpenDNS (Cisco) | `208.67.222.222` | Common in enterprise environments |
| Lumen (Level3) | `4.2.2.2` | Long-standing legacy/carrier-grade resolver |

### Extended (`--resolver-set full` — adds 5 more, 10 total)

| Resolver | IP | Note |
|---|---|---|
| Verisign | `64.6.64.6` | Registry-adjacent, often used in cutover validation |
| CleanBrowsing | `185.228.168.9` | Filtering-focused public resolver |
| AdGuard DNS | `94.140.14.14` | Increasingly common ad/tracker-blocking resolver |
| Comodo Secure DNS | `8.26.56.26` | Legacy but still checked in some environments |
| DNS.WATCH | `84.200.69.80` | Independent, no-logging resolver |

Use `--resolvers` to fully override either set with your own list, e.g.:

```bash
ns-converge-trace example.com --resolvers 1.1.1.1:Cloudflare 8.8.8.8:Google
```

## License

MIT
