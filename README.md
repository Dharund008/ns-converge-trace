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
layer/resolver is behind, including the **TTL** of cached records so you
know roughly how long until convergence.

No API keys. No config files. No provider-specific hardcoding.

## Exit codes

`ns-converge-trace` sets a meaningful exit code so it composes with scripts
and CI pipelines:

| Code | Meaning |
|---|---|
| `0` | **CONVERGED** — all layers match the registry delegation |
| `1` | **PROPAGATING** — at least one layer hasn't caught up yet |
| `2` | **UNKNOWN** — couldn't establish the registry baseline |

When checking multiple domains, the exit code reflects the **worst** status
across all of them (UNKNOWN > PROPAGATING > CONVERGED).

### Examples

```bash
# Gate a deploy on full convergence
ns-converge-trace example.com && kubectl rollout restart deployment/app

# Branch on status in a script
ns-converge-trace example.com
case $? in
  0) echo "Converged — safe to proceed" ;;
  1) echo "Still propagating — waiting" ;;
  2) echo "Couldn't establish baseline — investigate" ;;
esac

# CI pipeline step (non-zero fails the step)
- name: Verify NS cutover
  run: ns-converge-trace example.com
```

## DNS engine

`ns-converge-trace` auto-detects and prefers the system `dig` binary (from
`bind-utils` / `dnsutils`) if it's available on your `PATH` — `dig` already
handles TCP-retry-on-truncation, EDNS0, and years of real-world edge cases.

If `dig` is **not** installed (e.g. plain Windows, minimal containers), it
automatically falls back to a **built-in pure-Python DNS client** (stdlib
only — `socket` + `struct`, zero third-party dependencies) that implements:

- EDNS0 (requests a larger UDP payload to avoid truncation)
- Automatic TCP fallback when a response is truncated (TC flag)
- Basic IDN/punycode label encoding for non-ASCII domains

Either way, **no external Python packages are required** — this is a fully
standalone tool. Force a specific engine with `--engine dig` or `--engine python`
if needed (e.g. for testing).

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
| `--no-color` | Disable ANSI colors in table output |
| `--version` | Print version and exit |

> **`--watch` with multiple domains:** Domains are watched **sequentially** —
> each domain's watch loop runs until that domain converges (or hits
> `--max-attempts`) before the next domain begins. If you need to watch
> multiple domains in parallel, run separate `ns-converge-trace --watch`
> instances in different terminal tabs or with `&` backgrounding.

### Color behavior

ANSI colors are enabled automatically when stdout is a terminal. They are
disabled when:
- `--no-color` is passed, or
- The `NO_COLOR` environment variable is set (any value) — per the
  [no-color.org](https://no-color.org/) convention, or
- Output is piped or redirected to a file.

## Features

### TTL reporting

Every row in the output table shows the **minimum TTL** (time-to-live) of
the NS records returned by that source. During a cutover, this tells you
roughly how long until a stale-cached answer expires — the most common
follow-up question after "has it converged?" is "when will it converge?"

### Parallel resolver queries

Public resolver queries run **concurrently** (threaded), so checking 5–10
resolvers takes roughly the time of the slowest one, not the sum of all.

### Watch mode diff

In `--watch` mode, after the first poll, the tool shows a **diff** of what
changed since the previous attempt — so you see `Google: DIVERGED → PASS`
instead of having to re-read the full table each time.

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

## License

MIT
