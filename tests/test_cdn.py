"""Tests for laglens.probes.cdn with a fake HTTPSConnection: timings, samples, failures, cdn_slow."""
import argparse
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.probes import cdn as cdnmod  # noqa: E402
from laglens.probes.cdn import CdnProber  # noqa: E402
from laglens.state import F_ERROR, F_LOADTEST, F_LOST, KIND_CDN_CONNECT, KIND_CDN_TTFB, State, Target  # noqa: E402


# ---------------------------------------------------------------- fakes
class FakeClock:
    def __init__(self, mono=10.0, wall=1_700_000_000.0):
        self.mono = mono
        self.wall = wall

    def advance(self, s):
        self.mono += s
        self.wall += s


class FakeResponse:
    def __init__(self, conn, status, body, chunk_s):
        self.conn = conn
        self.status = status
        self.body = body
        self.chunk_s = chunk_s
        self.reads = []

    def read(self, n):
        self.reads.append(n)
        chunk, self.body = self.body[:n], self.body[n:]
        if chunk:
            self.conn.clock.advance(self.chunk_s * len(chunk) / (64 * 1024))
        return chunk


class FakeConn:
    def __init__(self, clock, spec):
        self.clock = clock
        self.spec = spec
        self.closed = False
        self.requests = []
        self.connected = False

    def connect(self):
        if self.spec.get("connect_exc"):
            raise self.spec["connect_exc"]
        self.clock.advance(self.spec.get("connect_s", 0.02))
        self.connected = True

    def request(self, method, path, headers=None, body=None):
        self.requests.append((method, path, headers or {}))

    def getresponse(self):
        if self.spec.get("response_exc"):
            raise self.spec["response_exc"]
        self.clock.advance(self.spec.get("ttfb_s", 0.05))
        return FakeResponse(self, self.spec.get("status", 200), self.spec.get("body", b"x" * (256 * 1024)),
                            self.spec.get("chunk_s", 0.01))

    def close(self):
        self.closed = True


class FakeFactory:
    def __init__(self, clock):
        self.clock = clock
        self.spec = {}
        self.conns = []
        self.calls = []

    def __call__(self, host, port, timeout=None):
        self.calls.append((host, port, timeout))
        c = FakeConn(self.clock, dict(self.spec))
        self.conns.append(c)
        return c


class FakeStore:
    def __init__(self):
        self.samples = []

    def append_sample(self, s):
        self.samples.append(s)


class FakeCtx:
    def __init__(self, wall, cfg=None):
        self.cfg = cfg if cfg is not None else {"cdn": {"enabled": True, "interval_s": 60, "urls": []}}
        self.args = argparse.Namespace()
        self.state = State(t0=wall, session_id="test")
        self.store = FakeStore()
        self.platform = None
        self.route = {}


def add_cdn(state, key, url, enabled=True):
    host = url.split("//", 1)[1].split("/", 1)[0]
    return state.add_target(Target(id=-1, key=key, role="cdn", addr=host, family=4, kind="cdn", label="CDN " + host,
                                   rate_hz=1 / 60.0, port=443, extra={"url": url}, enabled=enabled))


class CdnProberTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.ctx = FakeCtx(self.clock.wall)
        self.state = self.ctx.state
        self.t = add_cdn(self.state, "cdn_0", "https://speed.cloudflare.com/__down?bytes=262144")
        self.https = FakeFactory(self.clock)
        self.http = FakeFactory(self.clock)
        self.p = CdnProber(self.ctx, https_factory=self.https, http_factory=self.http,
                           clock=lambda: self.clock.mono, wall=lambda: self.clock.wall)

    def samples(self):
        return self.ctx.store.samples

    def test_good_fetch_timings_samples_and_latest(self):
        self.https.spec = {"connect_s": 0.020, "ttfb_s": 0.050, "chunk_s": 0.010}
        res = self.p.run_cycle()[0]
        self.assertEqual(self.https.calls, [("speed.cloudflare.com", 443, 10.0)])
        conn = self.https.conns[0]
        self.assertEqual(conn.requests[0][0], "GET")
        self.assertEqual(conn.requests[0][1], "/__down?bytes=262144")
        self.assertEqual(conn.requests[0][2]["Accept-Encoding"], "identity")
        self.assertTrue(conn.closed)
        self.assertAlmostEqual(res["connect_ms"], 20.0, places=3)
        self.assertAlmostEqual(res["ttfb_ms"], 70.0, places=3)  # connect + response wait
        self.assertEqual(res["bytes"], 256 * 1024)
        # 256 KB in 4 × 10 ms chunks = 2 Mbit / 0.04 s = 52.4288 Mb/s
        self.assertAlmostEqual(res["throughput_mbps"], 52.4288, places=2)
        self.assertEqual(res["status"], 200)
        self.assertEqual(res["phase"], "ok")
        self.assertEqual(len(self.samples()), 2)
        c, tt = self.samples()
        self.assertEqual((c.kind, tt.kind), (KIND_CDN_CONNECT, KIND_CDN_TTFB))
        self.assertEqual((c.target_id, tt.target_id), (self.t.id, self.t.id))
        self.assertEqual(c.value, 20000)
        self.assertEqual(tt.value, 70000)
        self.assertTrue(c.received and tt.received)
        self.assertEqual((c.seq, tt.seq), (1, 1))
        row = self.state.latest("cdn")["cdn_0"]
        self.assertEqual(row["status"], 200)
        self.assertAlmostEqual(row["ttfb_ms"], 70.0, places=3)
        self.assertAlmostEqual(row["throughput_mbps"], 52.4288, places=2)
        self.assertIn("t", row)
        self.assertEqual(len(self.state.raw_window(self.t.id, 0, self.clock.wall + 10)), 2)

    def test_reads_in_64k_chunks_and_stops_at_256k(self):
        self.https.spec = {"body": b"y" * (1024 * 1024)}
        self.p.run_cycle()
        conn = self.https.conns[0]
        self.assertTrue(conn.closed)
        res = self.state.latest("cdn")["cdn_0"]
        self.assertEqual(res["bytes"], 256 * 1024)

    def test_small_body_has_no_throughput(self):
        self.https.spec = {"status": 204, "body": b""}
        res = self.p.run_cycle()[0]
        self.assertEqual(res["status"], 204)
        self.assertIsNone(res["throughput_mbps"])
        self.assertEqual(res["bytes"], 0)
        self.assertTrue(all(s.received for s in self.samples()))

    def test_timeout_on_connect_marks_both_lost(self):
        self.https.spec = {"connect_exc": socket.timeout("timed out")}
        res = self.p.run_cycle()[0]
        self.assertEqual(res["error"], "timeout")
        self.assertEqual(res["phase"], "connect")
        c, tt = self.samples()
        self.assertTrue(c.flags & F_LOST and tt.flags & F_LOST)
        self.assertEqual((c.value, tt.value), (-1, -1))
        self.assertTrue(self.https.conns[0].closed)
        self.assertIsNone(self.state.latest("cdn")["cdn_0"]["connect_ms"])

    def test_error_after_connect_keeps_connect_sample(self):
        self.https.spec = {"connect_s": 0.015, "response_exc": OSError(54, "Connection reset by peer")}
        res = self.p.run_cycle()[0]
        self.assertEqual(res["phase"], "request")
        self.assertIn("Connection reset", res["error"])
        c, tt = self.samples()
        self.assertTrue(c.received)
        self.assertEqual(c.value, 15000)
        self.assertTrue(tt.flags & F_ERROR)
        self.assertEqual(tt.value, 54)

    def test_cdn_slow_note_only_after_two_slow_in_a_row(self):
        self.https.spec = {"ttfb_s": 1.5}
        self.p.run_cycle()
        self.assertEqual(self.state.drain_notes(), [])
        self.https.spec = {"ttfb_s": 0.05, "chunk_s": 0.2}  # 2.6 Mb/s
        self.p.run_cycle()
        notes = self.state.drain_notes()
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["type"], "cdn_slow")
        self.assertEqual(notes[0]["target"], self.t.id)
        self.assertEqual(notes[0]["severity"], 2)
        self.assertLess(notes[0]["peak"]["throughput_mbps"], 5.0)
        # a fast fetch resets the run
        self.https.spec = {"ttfb_s": 0.05, "chunk_s": 0.01}
        self.p.run_cycle()
        self.https.spec = {"ttfb_s": 1.5}
        self.p.run_cycle()
        self.assertEqual(self.state.drain_notes(), [])

    def test_failures_count_as_slow(self):
        self.https.spec = {"connect_exc": socket.timeout("timed out")}
        self.p.run_cycle()
        self.p.run_cycle()
        notes = self.state.drain_notes()
        self.assertEqual([n["type"] for n in notes], ["cdn_slow"])

    def test_http_scheme_uses_plain_connection(self):
        add_cdn(self.state, "cdn_1", "http://example.com/x")
        self.p.run_cycle()
        self.assertEqual(self.http.calls, [("example.com", 80, 10.0)])
        self.assertEqual(len(self.https.calls), 1)
        self.assertEqual(set(self.state.latest("cdn")), {"cdn_0", "cdn_1"})

    def test_disabled_target_skipped(self):
        add_cdn(self.state, "cdn_1", "https://www.gstatic.com/generate_204", enabled=False)
        out = self.p.run_cycle()
        self.assertEqual(len(out), 1)
        self.assertEqual(len(self.https.calls), 1)

    def test_loadtest_flag(self):
        self.state.loadtest["running"] = True
        self.p.run_cycle()
        self.assertTrue(all(s.flags & F_LOADTEST for s in self.samples()))

    def test_interval_from_config(self):
        ctx = FakeCtx(self.clock.wall, cfg={"cdn": {"interval_s": 120}})
        self.assertEqual(CdnProber(ctx).interval_s, 120.0)
        ctx = FakeCtx(self.clock.wall, cfg={"cdn": {"interval_s": "bogus"}})
        self.assertEqual(CdnProber(ctx).interval_s, cdnmod.DEFAULT_INTERVAL_S)
        ctx = FakeCtx(self.clock.wall, cfg={})
        self.assertEqual(CdnProber(ctx).interval_s, cdnmod.DEFAULT_INTERVAL_S)

    def test_start_and_stop_thread(self):
        p = CdnProber(self.ctx, https_factory=self.https, http_factory=self.http)
        p.start()
        self.assertTrue(p.thread.is_alive())
        self.state.stop_event.set()
        p.stop(timeout=3.0)
        self.assertFalse(p.thread.is_alive())
        self.assertEqual(self.state.collector("cdn")["status"], "ok")


if __name__ == "__main__":
    unittest.main()
