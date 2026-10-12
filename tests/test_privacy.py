"""Privacy guard: no real home-network details may be committed.

The repository is public. Test fixtures and docs use made-up values only, and this test keeps it
that way. Any hardware address, public IP address, email address or home-folder path in a
tracked file must be on the allowlists below (all of them fake, documentation-range, or public
infrastructure such as well-known DNS resolvers). Adding a new fixture with a real value fails here
first, so replace it with a fake one instead of extending the lists with real data.

A local, never-published denylist of the owner's real identifiers can be kept in
``private/denylist.txt`` (one term per line, case-insensitive substring match); when it exists,
no tracked file may contain any of its terms.
"""
import ipaddress
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = Path(__file__).resolve().parent.parent
SKIP_PREFIXES = ("private/", "laglens/web/vendor/")
SKIP_DIRS = {".git", "private", "sessions", "__pycache__", "vendor", "_build", "node_modules", ".claude"}

# Fake hardware addresses used by tests (Microsoft prefixes with made-up device parts, etc.).
ALLOWED_MACS = {
    "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", "00:11:22:33:44:66", "00:17:10:9a:76:a1",
    "01:23:45:67:89:ab", "28:16:a8:11:22:33", "28:16:a8:99:99:99", "7c:ed:8d:01:02:03", "7c:ed:8d:09:09:09",
    "7c:ed:8d:11:22:33", "7c:ed:8d:11:22:34", "7c:ed:8d:aa:bb:cc", "a8:a1:59:12:34:56",
}
# Public IPv4: well-known resolvers / service endpoints and obviously made-up test values.
ALLOWED_V4 = {
    "1.0.0.1", "1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "162.159.200.1", "216.239.35.0", "104.16.0.1",
    "20.190.190.130", "40.90.8.102", "40.90.8.103", "1.2.3.4", "5.6.7.8", "20.1.2.3", "20.9.9.9", "40.1.1.1",
    "73.1.2.3", "73.9.9.9",
}
ALLOWED_V4_NETS = [ipaddress.ip_network(n) for n in ("11.0.0.0/8",)]  # made-up "routers" in path fixtures
# Global IPv6: public resolvers and made-up prefixes (never a real home prefix).
ALLOWED_V6_NETS = [ipaddress.ip_network(n) for n in (
    "2001:db8::/32", "2601:abcd::/32", "2001:558:aaaa::/48", "2001:558:4000::/48", "2001:558:feed::/48",
    "2606:4700:4700::/48", "2001:4860:4860::/48", "2a01::/32")]
ALLOWED_V6 = {ipaddress.ip_address(a) for a in ("2601::1", "2601:1:2:3::10", "2001:558::1", "2606::1")}
ALLOWED_EMAIL_RX = re.compile(r"^[\w.+-]+@(example\.(com|org|net)|users\.noreply\.github\.com|anthropic\.com)$", re.I)
ALLOWED_HOMES = {"/Users/runner", "/home/runner", "/home/user", "/Users/you", "/home/you", "/home/deck"}

MAC_RX = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])")
V4_RX = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
V6_RX = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
EMAIL_RX = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
HOME_RX = re.compile(r"/(?:Users|home)/[A-Za-z0-9._-]+")


def tracked_files():
    """Files git tracks (falls back to a directory walk outside a git checkout)."""
    try:
        out = subprocess.run(["git", "ls-files"], cwd=str(ROOT), capture_output=True, text=True, timeout=30)
        if out.returncode == 0 and out.stdout.strip():
            return [f for f in out.stdout.splitlines() if not f.startswith(SKIP_PREFIXES) and (ROOT / f).is_file()]
    except (OSError, subprocess.SubprocessError):
        pass
    found = []
    for dirpath, dirnames, filenames in os.walk(str(ROOT)):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            rel = os.path.relpath(os.path.join(dirpath, name), str(ROOT)).replace(os.sep, "/")
            if not rel.startswith(SKIP_PREFIXES):
                found.append(rel)
    return found


def texts():
    for rel in tracked_files():
        try:
            yield rel, (ROOT / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary


def _mac_ok(mac):
    first = int(mac[:2], 16)
    return mac in ALLOWED_MACS or bool(first & 0x02)  # locally administered addresses are never a real NIC's


def _v4_ok(text):
    try:
        a = ipaddress.ip_address(text)
    except ValueError:
        return True
    if not a.is_global or a.is_multicast:
        return True
    return text in ALLOWED_V4 or any(a in n for n in ALLOWED_V4_NETS)


def _v6_ok(text):
    try:
        a = ipaddress.ip_address(text)
    except ValueError:
        return True
    if a.ipv4_mapped is not None or not (0x2000 <= int(a) >> 112 <= 0x3FFF):
        return True  # only global unicast (2000::/3) can identify a home
    return a in ALLOWED_V6 or any(a in n for n in ALLOWED_V6_NETS)


class PrivacyTests(unittest.TestCase):
    def collect(self, rx, ok, norm=lambda s: s):
        bad = {}
        for rel, s in texts():
            for m in rx.finditer(s):
                v = norm(m.group(0))
                if not ok(v):
                    bad.setdefault(v, set()).add(rel)
        return {k: sorted(v) for k, v in bad.items()}

    def test_hardware_addresses_are_fakes(self):
        bad = self.collect(MAC_RX, _mac_ok, lambda s: s.lower().replace("-", ":"))
        self.assertEqual(bad, {}, "real-looking hardware addresses; replace them with fake ones")

    def test_public_ipv4_addresses_are_known(self):
        self.assertEqual(self.collect(V4_RX, _v4_ok), {}, "public IPv4 addresses that are not on the allowlist")

    def test_global_ipv6_addresses_are_known(self):
        self.assertEqual(self.collect(V6_RX, _v6_ok), {}, "global IPv6 addresses outside the allowed prefixes")

    def test_no_email_addresses(self):
        self.assertEqual(self.collect(EMAIL_RX, lambda e: bool(ALLOWED_EMAIL_RX.match(e))), {}, "email addresses")

    def test_no_home_folder_paths(self):
        self.assertEqual(self.collect(HOME_RX, lambda h: h in ALLOWED_HOMES), {}, "paths into a real home folder")

    def test_private_denylist(self):
        path = ROOT / "private" / "denylist.txt"
        if not path.exists():
            self.skipTest("no private/denylist.txt (kept only on the owner's machine)")
        terms = [t.strip().lower() for t in path.read_text(encoding="utf-8").splitlines()
                 if t.strip() and not t.lstrip().startswith("#")]
        hits = {}
        for rel, s in texts():
            low = s.lower()
            for i, term in enumerate(terms):
                if term in low:
                    hits.setdefault("denylist line %d" % (i + 1), []).append(rel)
        self.assertEqual(hits, {}, "files contain a term from private/denylist.txt")

    def test_the_guard_itself_catches_real_looking_values(self):
        # built from parts so this file does not trip its own scan
        self.assertFalse(_mac_ok(":".join(["34", "12", "00", "00", "00", "01"])))
        self.assertTrue(_mac_ok("02:00:00:00:00:01"))
        self.assertFalse(_v4_ok(".".join(["96", "0", "0", "1"])))
        self.assertTrue(_v4_ok("10.0.0.1") and _v4_ok("1.1.1.1"))
        self.assertFalse(_v6_ok(":".join(["2601", "600", "1", "", "1"])))
        self.assertTrue(_v6_ok("2001:db8::1") and _v6_ok("fe80::1"))


if __name__ == "__main__":
    unittest.main()
