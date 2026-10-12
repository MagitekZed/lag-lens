"""Tests for laglens.targets: resolver filtering and the dns_gw choice."""
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens import targets  # noqa: E402
from laglens.config import DEFAULTS  # noqa: E402

ROUTE = {"gateway": "10.0.0.1", "iface": "en0", "gateway6": "fe80::1%en0", "iface6": "en0", "lan_ip": "10.0.0.35",
         "prefixlen": 24}


class FakePlatform:
    def __init__(self, resolvers):
        self._resolvers = list(resolvers)

    def resolvers(self):
        return list(self._resolvers)

    def default_route(self):
        return dict(ROUTE)


def no_resolver(name, family):
    return None


class MappedAnswerTests(unittest.TestCase):
    def test_is_ipv4_mapped(self):
        self.assertTrue(targets.is_ipv4_mapped("::ffff:40.90.8.102"))
        self.assertTrue(targets.is_ipv4_mapped("::ffff:2859:866"))
        self.assertFalse(targets.is_ipv4_mapped("2606:4700:4700::1111"))
        self.assertFalse(targets.is_ipv4_mapped("fe80::1%en0"))
        self.assertFalse(targets.is_ipv4_mapped("1.1.1.1"))
        self.assertFalse(targets.is_ipv4_mapped(None))
        self.assertFalse(targets.is_ipv4_mapped("not-an-ip"))

    def test_default_resolver_rejects_mapped_aaaa(self):
        answers = {
            (socket.AF_INET6, "profile.xboxlive.com"): [("::ffff:40.90.8.102",), ("::ffff:40.90.8.103",)],
            (socket.AF_INET6, "one.one.one.one"): [("::ffff:1.1.1.1",), ("2606:4700:4700::1111",)],
            (socket.AF_INET, "profile.xboxlive.com"): [("40.90.8.102",)],
        }

        def fake_getaddrinfo(name, port, family=0, kind=0, *a):
            rows = answers.get((family, name))
            if rows is None:
                raise socket.gaierror(8, "nodename nor servname provided")
            return [(family, kind, 6, "", (r[0], 0, 0, 0) if family == socket.AF_INET6 else (r[0], 0)) for r in rows]

        orig = socket.getaddrinfo
        socket.getaddrinfo = fake_getaddrinfo
        self.addCleanup(setattr, socket, "getaddrinfo", orig)
        self.assertIsNone(targets.default_resolver("profile.xboxlive.com", 6))  # mapped answers only
        self.assertEqual(targets.default_resolver("one.one.one.one", 6), "2606:4700:4700::1111")  # first real AAAA
        self.assertEqual(targets.default_resolver("profile.xboxlive.com", 4), "40.90.8.102")
        self.assertIsNone(targets.default_resolver("nope.invalid", 4))


class DnsGatewayTests(unittest.TestCase):
    def test_lan_resolver_prefers_gateway_then_lan_prefix(self):
        self.assertEqual(targets.lan_resolver(["100.100.100.100", "10.0.0.1"], ROUTE), "10.0.0.1")
        self.assertEqual(targets.lan_resolver(["100.100.100.100", "10.0.0.2", "10.0.0.1"], ROUTE), "10.0.0.2")
        self.assertIsNone(targets.lan_resolver(["100.100.100.100", "fd7a:115c::53"], ROUTE))
        self.assertIsNone(targets.lan_resolver([], ROUTE))
        # no prefix known: only an exact gateway match counts
        self.assertEqual(targets.lan_resolver(["10.0.0.9", "10.0.0.1"], {"gateway": "10.0.0.1"}), "10.0.0.1")
        self.assertIsNone(targets.lan_resolver(["10.0.0.9"], {"gateway": "10.0.0.1"}))
        self.assertIsNone(targets.lan_resolver(["junk", "10.0.0.9"], {"lan_ip": "bad", "prefixlen": 24}))

    def _dns_gw(self, resolvers, route=None):
        ts = targets.static_targets(DEFAULTS, FakePlatform(resolvers), resolver=no_resolver,
                                    route=route if route is not None else ROUTE)
        return next(t for t in ts if t.key == "dns_gw")

    def test_dns_gw_is_the_gateway_not_the_tailscale_resolver(self):
        t = self._dns_gw(["100.100.100.100", "10.0.0.1"])
        self.assertEqual((t.addr, t.enabled, t.label), ("10.0.0.1", True, "Gateway DNS 10.0.0.1"))
        # a LAN resolver that is not the gateway (a Pi-hole) is still the "gateway" side of the LAN
        t = self._dns_gw(["100.100.100.100", "10.0.0.5"])
        self.assertEqual(t.addr, "10.0.0.5")
        # only a foreign resolver listed: time the gateway itself
        t = self._dns_gw(["100.100.100.100"])
        self.assertEqual((t.addr, t.label), ("10.0.0.1", "Gateway DNS 10.0.0.1"))
        t = self._dns_gw([])
        self.assertEqual(t.addr, "10.0.0.1")

    def test_dns_gw_without_gateway_falls_back_to_the_system_resolver(self):
        route = {"gateway": None, "iface": None, "gateway6": None, "lan_ip": None, "prefixlen": None}
        t = self._dns_gw(["100.100.100.100"], route=route)
        self.assertEqual((t.addr, t.enabled, t.label), ("100.100.100.100", True, "System DNS 100.100.100.100"))
        t = self._dns_gw([], route=route)
        self.assertEqual((t.addr, t.enabled, t.reason), (None, False, "no resolver found"))


if __name__ == "__main__":
    unittest.main()
