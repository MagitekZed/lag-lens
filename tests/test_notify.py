"""Tests for laglens.notify: configuration gating, confidence filter, batching, ntfy/webhook payloads, test()."""
import io
import json
import os
import sys
import unittest
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens import notify as n  # noqa: E402
from laglens.state import State  # noqa: E402


class FakeResp(io.BytesIO):
    def __init__(self, status=200):
        super().__init__(b"ok")
        self.status = status

    def getcode(self):
        return self.status


class FakeUrlopen:
    def __init__(self):
        self.calls = []
        self.fail = None

    def __call__(self, req, timeout=None):
        self.calls.append({"url": req.full_url, "data": req.data, "headers": dict(req.header_items()), "timeout": timeout, "method": req.get_method()})
        if self.fail is not None:
            raise self.fail
        return FakeResp()


class Ctx:
    def __init__(self, notify_cfg):
        self.cfg = {"notify": notify_cfg}
        self.state = State(cfg=self.cfg, session_id="20261011-190000")
        self.components = {}

    def component(self, name):
        return self.components.get(name)


class Clock:
    def __init__(self):
        self.t = 1_760_000_000.0
        self.m = 10.0


def make(**kw):
    c = {"ntfy_topic": "laglens-test", "webhook_url": None, "min_confidence": "medium", "batch_s": 120}
    c.update(kw)
    ctx = Ctx(c)
    clk = Clock()
    uo = FakeUrlopen()
    nt = n.Notifier(ctx, urlopen=uo, clock=lambda: clk.t, mono=lambda: clk.m)
    return ctx, clk, uo, nt


def episode(id="ep-000001", conf=0.8, dur=9.5, cls="docsis_access"):
    return {"id": id, "t0": 1_760_000_000.0, "t1": 1_760_000_000.0 + dur, "dur_s": dur, "class": cls, "confidence": conf,
            "evidence": ["Comcast hop 10.60.12.1: 38% loss", "1.1.1.1: 36% loss", "more"]}


class NotifyTests(unittest.TestCase):
    def test_not_configured(self):
        ctx, clk, uo, nt = make(ntfy_topic=None)
        nt.start()
        self.assertEqual(ctx.state.collector("notify")["reason"], "not configured")
        self.assertIsNone(nt.thread)
        self.assertEqual(nt.test()[0], False)
        nt.stop()

    def test_confidence_levels(self):
        self.assertEqual(n.confidence_level(0.9), "high")
        self.assertEqual(n.confidence_level(0.5), "medium")
        self.assertEqual(n.confidence_level(0.2), "low")
        self.assertEqual(n.confidence_level("high"), "high")
        self.assertEqual(n.confidence_level(None), "low")

    def test_batching_and_filter(self):
        ctx, clk, uo, nt = make()
        nt.start()
        self.assertEqual(ctx.state.collector("notify")["channels"], ["ntfy"])
        ctx.state.publish("episode_open", {"id": "ep-000001", "t0": clk.t, "class": "unknown", "confidence": 0.0})
        self.assertEqual(nt.pending(), 0)  # open with low confidence filtered at "medium"
        ctx.state.publish("episode_close", episode(conf=0.3))
        self.assertEqual(nt.pending(), 0)
        ctx.state.publish("episode_close", episode(dur=1.0))
        self.assertEqual(nt.pending(), 0)  # blip
        ctx.state.publish("episode_close", episode())
        ctx.state.publish("episode_close", episode(id="ep-000002", conf=0.55, cls="comcast_network"))
        ctx.state.publish("verdict", {"text": "Comcast side, probably", "confidence": "high"})
        ctx.state.publish("verdict", {"text": "Comcast side, probably", "confidence": "high"})  # unchanged → ignored
        self.assertEqual(nt.pending(), 3)
        self.assertFalse(nt.due())
        self.assertEqual(uo.calls, [])
        clk.m += 121
        self.assertTrue(nt.due())
        ok, msg = nt.flush()
        self.assertTrue(ok)
        self.assertEqual(len(uo.calls), 1)
        call = uo.calls[0]
        self.assertEqual(call["url"], "https://ntfy.sh/laglens-test")
        self.assertEqual(call["timeout"], 10.0)
        self.assertEqual(call["method"], "POST")
        self.assertEqual(call["headers"]["Title"], "Lag Lens: 3 events")
        body = call["data"].decode("utf-8")
        self.assertIn("ep-000001", body)
        self.assertIn("docsis_access", body)
        self.assertIn("Comcast hop 10.60.12.1", body)
        self.assertIn("Verdict: Comcast side", body)
        self.assertEqual(nt.pending(), 0)
        self.assertEqual(ctx.state.collector("notify")["sent"], 1)
        ctx.state.stop_event.set()
        nt.stop(1.0)

    def test_webhook_json_and_failure(self):
        ctx, clk, uo, nt = make(ntfy_topic=None, webhook_url="https://hooks.example/x", min_confidence="low")
        nt.start()
        ctx.state.publish("episode_open", {"id": "ep-000009", "t0": clk.t, "class": "unknown", "confidence": 0.0})
        clk.m += 200
        ok, msg = nt.flush()
        self.assertTrue(ok)
        call = uo.calls[0]
        self.assertEqual(call["headers"]["Content-type"], "application/json")
        payload = json.loads(call["data"].decode("utf-8"))
        self.assertEqual(payload["title"], "Lag Lens: episode open")
        self.assertEqual(payload["events"][0]["id"], "ep-000009")
        self.assertEqual(payload["session"], "20261011-190000")
        self.assertIn("Trouble started", payload["text"])
        uo.fail = urllib.error.HTTPError("https://hooks.example/x", 503, "down", {}, io.BytesIO(b""))
        ok, msg = nt.send("t", "x")
        self.assertFalse(ok)
        self.assertIn("HTTP 503", msg)
        self.assertEqual(ctx.state.collector("notify")["status"], "degraded")
        uo.fail = None
        self.assertTrue(nt.send("t", "x")[0])
        self.assertEqual(ctx.state.collector("notify")["status"], "ok")
        ctx.state.stop_event.set()
        nt.stop(1.0)

    def test_full_url_topic_and_test(self):
        ctx, clk, uo, nt = make(ntfy_topic="https://ntfy.example.org/mytopic", webhook_url="https://hooks.example/y")
        nt.start()
        ok, msg = nt.test()
        self.assertTrue(ok)
        self.assertEqual([c["url"] for c in uo.calls], ["https://ntfy.example.org/mytopic", "https://hooks.example/y"])
        self.assertIn("ntfy: HTTP 200", msg)
        self.assertIn("webhook: HTTP 200", msg)
        ctx.state.stop_event.set()
        nt.stop(1.0)

    def test_stop_flushes_pending(self):
        ctx, clk, uo, nt = make()
        nt.start()
        ctx.state.publish("episode_close", episode())
        ctx.state.stop_event.set()
        nt.stop(1.0)
        self.assertEqual(len(uo.calls), 1)
        ctx.state.publish("episode_close", episode())  # unsubscribed
        self.assertEqual(nt.pending(), 0)


if __name__ == "__main__":
    unittest.main()
