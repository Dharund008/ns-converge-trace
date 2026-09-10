"""Unit tests for ns-converge-trace."""

import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch, MagicMock

from ns_converge_trace import __version__
from ns_converge_trace.cli import (
    _dig_query,
    _encode_qname,
    _format_ttl,
    _get_dig_path,
    _is_ip_literal,
    _overall_status,
    _parse_response,
    _build_query,
    check_domain,
    get_tld,
    parse_resolvers_arg,
    render_brief,
    render_watch_diff,
    query_ns,
    EXIT_CONVERGED,
    EXIT_PROPAGATING,
    EXIT_UNKNOWN,
    NoColor,
)


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

class TestVersion(unittest.TestCase):
    def test_version_is_string(self):
        self.assertIsInstance(__version__, str)

    def test_version_matches_cli(self):
        """--version should use the same string as __version__."""
        result = subprocess.run(
            [sys.executable, "-m", "ns_converge_trace.cli", "--version"],
            capture_output=True, text=True,
        )
        self.assertIn(__version__, result.stdout)


# ---------------------------------------------------------------------------
# TLD extraction
# ---------------------------------------------------------------------------

class TestGetTld(unittest.TestCase):
    def test_simple_com(self):
        self.assertEqual(get_tld("example.com"), "com")

    def test_subdomain(self):
        self.assertEqual(get_tld("www.sub.example.io"), "io")

    def test_trailing_dot(self):
        self.assertEqual(get_tld("example.net."), "net")

    def test_bare_tld(self):
        self.assertEqual(get_tld("com"), "com")


# ---------------------------------------------------------------------------
# IP literal detection
# ---------------------------------------------------------------------------

class TestIsIpLiteral(unittest.TestCase):
    def test_valid_ip(self):
        self.assertTrue(_is_ip_literal("8.8.8.8"))
        self.assertTrue(_is_ip_literal("192.168.1.1"))

    def test_not_ip(self):
        self.assertFalse(_is_ip_literal("example.com"))
        self.assertFalse(_is_ip_literal("not-an-ip"))


# ---------------------------------------------------------------------------
# TTL formatting
# ---------------------------------------------------------------------------

class TestFormatTtl(unittest.TestCase):
    def test_none(self):
        self.assertEqual(_format_ttl(None), "")

    def test_seconds(self):
        self.assertEqual(_format_ttl(45), "45s")

    def test_minutes(self):
        self.assertEqual(_format_ttl(120), "2m")

    def test_minutes_and_seconds(self):
        self.assertEqual(_format_ttl(125), "2m5s")

    def test_hours(self):
        self.assertEqual(_format_ttl(3600), "1h")
        self.assertEqual(_format_ttl(7200), "2h")

    def test_hours_and_minutes(self):
        self.assertEqual(_format_ttl(3660), "1h1m")

    def test_large_ttl(self):
        self.assertEqual(_format_ttl(172800), "48h")


# ---------------------------------------------------------------------------
# DNS qname encoding
# ---------------------------------------------------------------------------

class TestEncodeQname(unittest.TestCase):
    def test_simple(self):
        encoded = _encode_qname("example.com")
        # \x07example\x03com\x00
        self.assertEqual(encoded, b"\x07example\x03com\x00")

    def test_trailing_dot(self):
        self.assertEqual(_encode_qname("example.com."), b"\x07example\x03com\x00")


# ---------------------------------------------------------------------------
# dig output parsing
# ---------------------------------------------------------------------------

class TestDigQuery(unittest.TestCase):
    """Test _dig_query by mocking subprocess.run."""

    SAMPLE_DIG_OUTPUT = """\
example.com.		86400	IN	NS	ns1.example.com.
example.com.		86400	IN	NS	ns2.example.com.
"""

    SAMPLE_AUTHORITY_OUTPUT = """\
com.			172800	IN	NS	a.gtld-servers.net.
com.			172800	IN	NS	b.gtld-servers.net.
"""

    @patch("ns_converge_trace.cli._get_dig_path", return_value="/usr/bin/dig")
    @patch("subprocess.run")
    def test_parses_answer_section(self, mock_run, mock_dig):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=self.SAMPLE_DIG_OUTPUT,
            stderr="",
        )
        values, err, min_ttl = _dig_query("8.8.8.8", "example.com", "NS")
        self.assertIsNone(err)
        self.assertEqual(values, ["ns1.example.com", "ns2.example.com"])
        self.assertEqual(min_ttl, 86400)

    @patch("ns_converge_trace.cli._get_dig_path", return_value="/usr/bin/dig")
    @patch("subprocess.run")
    def test_parses_authority_section(self, mock_run, mock_dig):
        """Root server referrals land in AUTHORITY, not ANSWER."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=self.SAMPLE_AUTHORITY_OUTPUT,
            stderr="",
        )
        values, err, min_ttl = _dig_query("198.41.0.4", "com", "NS")
        self.assertIsNone(err)
        self.assertEqual(values, ["a.gtld-servers.net", "b.gtld-servers.net"])
        self.assertEqual(min_ttl, 172800)

    @patch("ns_converge_trace.cli._get_dig_path", return_value="/usr/bin/dig")
    @patch("subprocess.run")
    def test_filters_by_rtype(self, mock_run, mock_dig):
        """Only NS lines should be returned, not A or other types."""
        mixed_output = """\
example.com.		86400	IN	NS	ns1.example.com.
example.com.		300	IN	A	93.184.216.34
example.com.		86400	IN	NS	ns2.example.com.
"""
        mock_run.return_value = MagicMock(
            returncode=0, stdout=mixed_output, stderr="",
        )
        values, err, min_ttl = _dig_query("8.8.8.8", "example.com", "NS")
        self.assertIsNone(err)
        self.assertEqual(values, ["ns1.example.com", "ns2.example.com"])
        self.assertEqual(min_ttl, 86400)

    @patch("ns_converge_trace.cli._get_dig_path", return_value="/usr/bin/dig")
    @patch("subprocess.run")
    def test_empty_output(self, mock_run, mock_dig):
        """dig exits 0 with empty stdout (e.g. timeout) → should report error, not silent success."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="", stderr="",
        )
        values, err, min_ttl = _dig_query("8.8.8.8", "example.com", "NS")
        self.assertEqual(err, "no records in response")
        self.assertEqual(values, [])
        self.assertIsNone(min_ttl)

    @patch("ns_converge_trace.cli._get_dig_path", return_value="/usr/bin/dig")
    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="dig", timeout=8))
    def test_timeout(self, mock_run, mock_dig):
        values, err, min_ttl = _dig_query("8.8.8.8", "example.com", "NS")
        self.assertEqual(err, "timeout")
        self.assertEqual(values, [])

    @patch("ns_converge_trace.cli._get_dig_path", return_value=None)
    def test_no_dig(self, mock_dig):
        values, err, min_ttl = _dig_query("8.8.8.8", "example.com", "NS")
        self.assertEqual(err, "dig not found")


# ---------------------------------------------------------------------------
# Pure-Python DNS response parsing
# ---------------------------------------------------------------------------

class TestParseResponse(unittest.TestCase):
    def test_malformed(self):
        results, err, tc, ttl = _parse_response(b"\x00", 0x1234, 2)
        self.assertEqual(err, "malformed response")
        self.assertEqual(results, [])

    def test_txid_mismatch(self):
        # 12-byte header with a different txid
        header = b"\xAB\xCD" + b"\x00" * 10
        results, err, tc, ttl = _parse_response(header, 0x1234, 2)
        self.assertEqual(err, "txid mismatch")

    def _build_simple_response(self, txid, ns_names, rcode=0, tc=False):
        """Build a minimal DNS response with NS records in the authority section."""
        import struct as s
        flags = 0x8000 | rcode  # QR=1
        if tc:
            flags |= 0x0200
        ancount = 0
        nscount = len(ns_names)
        header = s.pack(">HHHHHH", txid, flags, 1, ancount, nscount, 0)

        # Question section: example.com IN NS
        question = b"\x07example\x03com\x00" + s.pack(">HH", 2, 1)

        # Authority section
        authority = b""
        for name in ns_names:
            # Owner name as pointer to question (offset 12)
            authority += b"\xc0\x0c"
            # Build the NS rdata
            rdata = b""
            for label in name.split("."):
                rdata += s.pack("B", len(label)) + label.encode()
            rdata += b"\x00"
            authority += s.pack(">HHIH", 2, 1, 3600, len(rdata))
            authority += rdata

        return header + question + authority

    def test_parses_ns_records(self):
        data = self._build_simple_response(
            0x1234, ["ns1.example.com", "ns2.example.com"]
        )
        results, err, tc, ttl = _parse_response(data, 0x1234, 2)
        self.assertIsNone(err)
        self.assertFalse(tc)
        self.assertIn("ns1.example.com", results)
        self.assertIn("ns2.example.com", results)
        self.assertEqual(ttl, 3600)

    def test_nxdomain(self):
        data = self._build_simple_response(0x1234, [], rcode=3)
        results, err, tc, ttl = _parse_response(data, 0x1234, 2)
        self.assertEqual(err, "NXDOMAIN")
        self.assertEqual(results, [])

    def test_tc_flag(self):
        data = self._build_simple_response(0x1234, ["ns1.example.com"], tc=True)
        results, err, tc, ttl = _parse_response(data, 0x1234, 2)
        self.assertTrue(tc)


# ---------------------------------------------------------------------------
# Resolver argument parsing
# ---------------------------------------------------------------------------

class TestParseResolversArg(unittest.TestCase):
    def test_ip_colon_name(self):
        result = parse_resolvers_arg(["9.9.9.9:Quad9", "1.1.1.1:Cloudflare"])
        self.assertEqual(result, [("9.9.9.9", "Quad9"), ("1.1.1.1", "Cloudflare")])

    def test_ip_only(self):
        result = parse_resolvers_arg(["8.8.8.8"])
        self.assertEqual(result, [("8.8.8.8", "8.8.8.8")])


# ---------------------------------------------------------------------------
# Exit code logic
# ---------------------------------------------------------------------------

class TestOverallStatus(unittest.TestCase):
    def test_converged(self):
        result = {"baseline_ns": ["ns1.example.com"], "fully_converged": True}
        self.assertEqual(_overall_status(result), EXIT_CONVERGED)

    def test_propagating(self):
        result = {"baseline_ns": ["ns1.example.com"], "fully_converged": False}
        self.assertEqual(_overall_status(result), EXIT_PROPAGATING)

    def test_unknown(self):
        result = {"baseline_ns": [], "fully_converged": False}
        self.assertEqual(_overall_status(result), EXIT_UNKNOWN)


# ---------------------------------------------------------------------------
# Brief rendering
# ---------------------------------------------------------------------------

class TestRenderBrief(unittest.TestCase):
    def test_converged(self):
        result = {
            "domain": "example.com",
            "baseline_ns": ["ns1.example.com"],
            "fully_converged": True,
            "converged_count": 7,
            "total_checked": 7,
        }
        self.assertEqual(render_brief(result), "example.com: CONVERGED")

    def test_propagating(self):
        result = {
            "domain": "example.com",
            "baseline_ns": ["ns1.example.com"],
            "fully_converged": False,
            "converged_count": 5,
            "total_checked": 7,
        }
        self.assertEqual(render_brief(result), "example.com: PROPAGATING (5/7)")

    def test_unknown(self):
        result = {
            "domain": "example.com",
            "baseline_ns": [],
            "fully_converged": False,
            "converged_count": 0,
            "total_checked": 0,
        }
        self.assertEqual(render_brief(result), "example.com: UNKNOWN")


# ---------------------------------------------------------------------------
# Watch diff rendering
# ---------------------------------------------------------------------------

class TestWatchDiff(unittest.TestCase):
    def test_shows_status_change(self):
        prev = [{"source": "Google (8.8.8.8)", "status": "DIVERGED"}]
        curr = [{"source": "Google (8.8.8.8)", "status": "CONVERGED"}]
        output = render_watch_diff(prev, curr, use_color=False)
        self.assertIn("DIVERGED → CONVERGED", output)

    def test_no_changes(self):
        rows = [{"source": "Google (8.8.8.8)", "status": "CONVERGED"}]
        output = render_watch_diff(rows, rows, use_color=False)
        self.assertIn("no changes", output)


# ---------------------------------------------------------------------------
# Integration: check_domain with mocked DNS
# ---------------------------------------------------------------------------

class TestCheckDomain(unittest.TestCase):
    @patch("ns_converge_trace.cli.query_ns")
    def test_fully_converged(self, mock_query):
        baseline = ["ns1.example.com", "ns2.example.com"]
        mock_query.return_value = (baseline, None, 86400)

        result = check_domain("example.com", [("8.8.8.8", "Google")])
        self.assertTrue(result["fully_converged"])
        self.assertEqual(result["baseline_ns"], baseline)
        self.assertEqual(result["converged_count"], result["total_checked"])

    @patch("ns_converge_trace.cli.query_ns")
    def test_diverged(self, mock_query):
        baseline = ["ns1.example.com", "ns2.example.com"]
        stale = ["old-ns1.example.com", "old-ns2.example.com"]

        def side_effect(server, domain, engine="auto"):
            # Registry and authoritative return new NS
            if server in ("198.41.0.4", "199.9.14.201", "192.33.4.12",
                          "ns1.example.com", "ns2.example.com"):
                return baseline, None, 86400
            # Resolver still has old cached data
            return stale, None, 3200

        mock_query.side_effect = side_effect
        result = check_domain("example.com", [("8.8.8.8", "Google")])
        self.assertFalse(result["fully_converged"])
        # Find the resolver row
        resolver_row = [r for r in result["rows"] if r["layer"] == "Resolver"][0]
        self.assertEqual(resolver_row["status"], "DIVERGED")

    @patch("ns_converge_trace.cli.query_ns")
    def test_unknown_baseline(self, mock_query):
        mock_query.return_value = ([], "timeout", None)
        result = check_domain("example.com", [("8.8.8.8", "Google")])
        self.assertFalse(result["fully_converged"])
        self.assertEqual(result["baseline_ns"], [])


if __name__ == "__main__":
    unittest.main()
