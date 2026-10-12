"""Tests for laglens.store: samples.bin round trip, torn records/lines, gzip, caps, resume."""
import gzip
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from laglens.state import KIND_ICMP, F_LOST, Sample, State  # noqa: E402
from laglens import store as storemod  # noqa: E402
from laglens.store import SAMPLE_SIZE, Store, new_session_id, pack_sample, unpack_sample  # noqa: E402


def cfg(**disk):
    d = {"session_cap_mb": 500, "total_cap_mb": 2048, "samples_cap_mb": 400, "min_free_mb": 500, "allow_prune": False}
    d.update(disk)
    return {"disk": d}


def samples(n=10, tid=3):
    return [Sample(ts_ms=1_760_000_000_000 + i * 250, target_id=tid, kind=KIND_ICMP, flags=F_LOST if i == 2 else 0, seq=i, value=-1 if i == 2 else 10_000 + i) for i in range(n)]


class FakeUsage:
    def __init__(self, free_mb):
        self.free = int(free_mb * 1024 * 1024)
        self.total = self.free * 2
        self.used = self.free


class StoreBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="laglens-store-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.stores = []

    def make(self, name="20261011-190000", resume=False, **kw):
        s = Store(self.tmp / name, cfg(), resume=resume, disk_usage=kw.pop("disk_usage", lambda p: FakeUsage(50_000)), **kw)
        self.stores.append(s)
        return s

    def tearDown(self):
        for s in self.stores:
            try:
                s.stop()
            except Exception:
                pass


class PackTests(unittest.TestCase):
    def test_record_size_and_round_trip(self):
        s = Sample(ts_ms=1_760_000_000_123, target_id=7, kind=4, flags=0x0302, seq=70000, value=-1)
        rec = pack_sample(s)
        self.assertEqual(len(rec), 20)
        self.assertEqual(SAMPLE_SIZE, 20)
        self.assertEqual(unpack_sample(rec), (1_760_000_000_123, 7, 4, 0x0302, 70000, -1))

    def test_value_clamped_to_int32(self):
        rec = pack_sample(Sample(ts_ms=1, target_id=1, kind=0, flags=0, seq=1, value=2 ** 40))
        self.assertEqual(unpack_sample(rec)[5], 0x7FFFFFFF)

    def test_session_id_format(self):
        self.assertRegex(new_session_id(1_760_223_600), r"^\d{8}-\d{6}$")


class WriteReadTests(StoreBase):
    def test_round_trip_and_filters(self):
        st = self.make()
        st.start()
        data = samples(10)
        for s in data:
            st.append_sample(s)
        st.flush()
        rows = st.read_samples()
        self.assertEqual(len(rows), 10)
        self.assertEqual(rows[2], (data[2].ts_ms, 3, 0, F_LOST, 2, -1))
        self.assertEqual(len(st.read_samples(t_from_ms=data[4].ts_ms, t_to_ms=data[7].ts_ms)), 3)
        self.assertEqual(st.read_samples(target_ids=[9]), [])
        self.assertEqual(len(st.read_samples(max_rows=4)), 4)
        self.assertTrue(st.last_read_truncated)
        self.assertEqual(len(list(st.iter_samples())), 10)

    def test_torn_trailing_record_is_skipped(self):
        st = self.make()
        st.start()
        for s in samples(3):
            st.append_sample(s)
        st.flush()
        st.stop()
        # inflate back and append 7 garbage bytes (a torn record)
        st2 = self.make(resume=True)
        with open(st2.path("samples.bin"), "ab") as fh:
            fh.write(b"\x01" * 7)
        self.assertEqual(len(st2.read_samples()), 3)

    def test_jsonl_round_trip_and_torn_line(self):
        st = self.make()
        st.start()
        st.append_json("events", {"id": "ev-000001", "type": "loss_burst"})
        st.append_json("events", {"id": "ev-000002", "type": "late_burst", "peak": {"n": 8}})
        st.flush()
        with open(st.path("events.jsonl"), "ab") as fh:
            fh.write(b'{"id":"ev-000003","typ')
        rows = st.read_json("events")
        self.assertEqual([r["id"] for r in rows], ["ev-000001", "ev-000002"])
        self.assertEqual(rows[1]["peak"]["n"], 8)
        self.assertEqual(st.read_json("missing"), [])
        with self.assertRaises(ValueError):
            st.append_json("bogus", {})

    def test_write_atomic_and_json_files(self):
        st = self.make()
        st.write_atomic("session.json", '{"a": 1}')
        st.write_atomic("session.json", b'{"a": 2}')
        self.assertEqual(st.read_file_json("session.json"), {"a": 2})
        self.assertEqual([p.name for p in st.dir.glob("session.json.tmp*")], [])
        st.write_json_atomic("targets.json", {"targets": [{"id": 0, "key": "gw4"}], "created": "x"})
        self.assertEqual(st.read_targets(), [{"id": 0, "key": "gw4"}])
        self.assertIsNone(st.read_file_json("nope.json"))
        st.write_atomic("marks/mk-1.json", "{}")
        self.assertTrue(st.path("marks/mk-1.json").exists())

    def test_gzip_on_stop_and_gz_readers(self):
        st = self.make()
        st.start()
        for s in samples(5):
            st.append_sample(s)
        st.append_json("host", {"t": 1, "host": {"load1": 0.5}})
        st.append_json("events", {"id": "ev-000001"})
        st.stop()
        self.assertTrue(st.path("samples.bin.gz").exists())
        self.assertFalse(st.path("samples.bin").exists())
        self.assertTrue(st.path("host.jsonl.gz").exists())
        self.assertTrue(st.path("events.jsonl").exists())  # only samples/host are compressed
        self.assertEqual(len(st.read_samples()), 5)
        self.assertEqual(st.read_json("host")[0]["host"]["load1"], 0.5)
        with gzip.open(st.path("samples.bin.gz"), "rb") as fh:
            self.assertEqual(len(fh.read()), 5 * SAMPLE_SIZE)
        st.stop()  # idempotent

    def test_stop_without_start_still_drains(self):
        st = self.make()
        st.append_json("events", {"id": "x"})
        st.stop()
        self.assertEqual(st.read_json("events"), [{"id": "x"}])


class ResumeTests(StoreBase):
    def test_resume_appends_after_gzip(self):
        st = self.make()
        st.start()
        for s in samples(4):
            st.append_sample(s)
        st.append_json("host", {"t": 1})
        st.write_json_atomic("targets.json", {"targets": [{"id": 0, "key": "gw4"}], "created": "x"})
        st.stop()
        st2 = self.make(resume=True)
        self.assertTrue(st2.path("samples.bin").exists())
        self.assertFalse(st2.path("samples.bin.gz").exists())
        st2.start()
        for s in samples(3, tid=5):
            st2.append_sample(s)
        st2.append_json("host", {"t": 2})
        st2.flush()
        rows = st2.read_samples()
        self.assertEqual(len(rows), 7)
        self.assertEqual([r[1] for r in rows], [3, 3, 3, 3, 5, 5, 5])
        self.assertEqual([r["t"] for r in st2.read_json("host")], [1, 2])
        self.assertEqual(st2.read_targets()[0]["key"], "gw4")
        st2.stop()
        self.assertEqual(len(st2.read_samples()), 7)

    def test_resume_realigns_torn_samples_bin(self):
        """Repro 1: a torn samples.bin (crash mid-record) must not misalign every later record."""
        st = self.make()
        st.start()
        for s in samples(3):
            st.append_sample(s)
        st.stop()
        st2 = self.make(resume=True)  # inflates samples.bin.gz back to samples.bin
        with open(st2.path("samples.bin"), "r+b") as fh:
            fh.truncate(3 * SAMPLE_SIZE - 7)  # OS crash / torn page mid-record
        self.stores.remove(st2)  # never stop()ped: st3 owns the directory from here
        st3 = self.make(resume=True)
        self.assertEqual(st3.path("samples.bin").stat().st_size, 2 * SAMPLE_SIZE)
        st3.start()
        for s in samples(3, tid=5):
            st3.append_sample(s)
        st3.flush()
        rows = st3.read_samples()
        self.assertEqual([r[1] for r in rows], [3, 3, 5, 5, 5])
        self.assertTrue(all(1_760_000_000_000 <= r[0] < 1_760_000_100_000 for r in rows), rows)

    def test_resume_realigns_torn_jsonl(self):
        """Repro 2: a torn last line must not swallow the first line appended after resume."""
        st = self.make()
        st.start()
        st.append_json("events", {"id": "ev-000001"})
        st.flush()
        with open(st.path("events.jsonl"), "ab") as fh:
            fh.write(b'{"id":"ev-000002","typ')
        st.stop()
        st2 = self.make(resume=True)
        self.assertTrue(st2.path("events.jsonl").read_bytes().endswith(b"}\n"))
        st2.start()
        st2.append_json("events", {"id": "ev-000003"})
        st2.append_json("events", {"id": "ev-000004"})
        st2.flush()
        self.assertEqual([r["id"] for r in st2.read_json("events")], ["ev-000001", "ev-000003", "ev-000004"])
        # a file that is nothing but a torn line is emptied, not glued onto
        (self.tmp / "20261011-190000" / "marks.jsonl").write_bytes(b'{"id":"mk-')
        st3 = self.make(resume=True)
        self.assertEqual(st3.path("marks.jsonl").stat().st_size, 0)

    def test_truncated_gz_keeps_the_readable_prefix(self):
        st = self.make()
        st.start()
        for s in samples(2000):
            st.append_sample(s)
        st.stop()
        gz = st.path("samples.bin.gz")
        data = gz.read_bytes()
        gz.write_bytes(data[: len(data) // 2])
        rows = st.read_samples()
        self.assertGreater(len(rows), 500, len(rows))
        self.assertLess(len(rows), 2000)
        self.assertEqual([r[4] for r in rows], list(range(len(rows))))  # whole records, in order
        # resume inflates the readable prefix atomically and no partial/temp file is left behind
        st2 = self.make(resume=True)
        self.assertFalse(gz.exists())
        self.assertEqual(st2.path("samples.bin").stat().st_size, len(rows) * SAMPLE_SIZE)
        self.assertEqual([p.name for p in st2.dir.glob("*.tmp")], [])
        # a zero-byte .gz reads as empty and inflates to an empty plain file
        st2.stop()  # gzips again; now replace the archive with an empty one
        self.assertFalse(st2.path("samples.bin").exists())
        gz.write_bytes(b"")
        self.assertEqual(st2.read_samples(), [])
        st3 = self.make(resume=True)
        self.assertTrue(st3.path("samples.bin").exists())
        self.assertFalse(gz.exists())

    def test_inflate_failure_leaves_no_partial_file(self):
        gz = self.tmp / "x" / "samples.bin.gz"
        gz.parent.mkdir()
        gz.write_bytes(b"\x1f\x8b\x08\x00garbage-not-deflate-data")
        self.assertFalse(storemod._inflate(gz, gz.with_name("samples.bin")))
        self.assertFalse(gz.with_name("samples.bin").exists())
        self.assertEqual([p.name for p in gz.parent.glob("*.tmp")], [])
        self.assertTrue(gz.exists())

    def test_resume_merges_plain_and_gz(self):
        st = self.make()
        st.start()
        for s in samples(3):
            st.append_sample(s)
        st.append_json("host", {"t": 1})
        st.stop()
        # a plain file next to the .gz (e.g. written by an older build after stop)
        with open(st.path("samples.bin"), "ab") as fh:
            fh.write(pack_sample(samples(1, tid=9)[0]))
        with open(st.path("host.jsonl"), "ab") as fh:
            fh.write(b'{"t":2}\n')
        with self.assertLogs("laglens.store", level="WARNING") as cm:
            st2 = self.make(resume=True)
        self.assertTrue(any("merging" in m for m in cm.output), cm.output)
        self.assertFalse(st2.path("samples.bin.gz").exists())
        self.assertEqual([r[1] for r in st2.read_samples()], [3, 3, 3, 9])
        self.assertEqual([r["t"] for r in st2.read_json("host")], [1, 2])

    def test_stop_is_a_hard_barrier(self):
        st = self.make()
        st.start()
        st.append_json("events", {"id": "ev-000001"})
        st.stop()
        st.append_json("events", {"id": "late"})
        st.append_sample(samples(1)[0])
        st.flush()
        self.assertEqual([r["id"] for r in st.read_json("events")], ["ev-000001"])
        self.assertFalse(st.path("samples.bin").exists())  # nothing re-opened next to samples.bin.gz
        self.assertEqual(st.read_samples(), [])

    def test_create_unique_ids_and_last(self):
        a = Store.create(self.tmp, cfg(), now=1_760_223_600, disk_usage=lambda p: FakeUsage(50_000))
        b = Store.create(self.tmp, cfg(), now=1_760_223_600, disk_usage=lambda p: FakeUsage(50_000))
        self.stores.extend([a, b])
        self.assertNotEqual(a.dir, b.dir)
        self.assertTrue(b.dir.name.startswith(a.dir.name))
        Store.write_last(self.tmp, "sessions/%s" % a.id)
        self.assertEqual(Store.read_last(self.tmp), "sessions/%s" % a.id)
        self.assertIsNone(Store.read_last(self.tmp / "nope"))


class TokenTests(StoreBase):
    def test_token_file(self):
        st = self.make()
        tok = st.ensure_token()
        self.assertGreaterEqual(len(tok), 24)
        self.assertEqual(st.token, tok)
        p = st.path("token")
        self.assertEqual(p.read_text().strip(), tok)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        st2 = self.make()
        self.assertEqual(st2.ensure_token(), tok)


class CapTests(StoreBase):
    def test_min_free_stops_all_writes(self):
        state = State(1.0, "s")
        st = self.make(state=state, disk_usage=lambda p: FakeUsage(100))
        self.assertFalse(st.writing)
        self.assertFalse(state.disk["writing"])
        self.assertIn("free space", state.disk["reason"])
        self.assertEqual(state.collector("store")["status"], "degraded")
        st.start()
        st.append_json("events", {"id": "dropped"})
        st.append_sample(samples(1)[0])
        st.flush()
        self.assertEqual(st.read_json("events"), [])
        self.assertEqual(st.read_samples(), [])

    def test_samples_cap_stops_only_samples(self):
        state = State(1.0, "s")
        st = Store(self.tmp / "s", {"disk": dict(cfg()["disk"], samples_cap_mb=0.00005)}, state=state,
                   disk_usage=lambda p: FakeUsage(50_000))
        self.stores.append(st)
        st.start()
        for s in samples(5):
            st.append_sample(s)
        st.flush()
        st.check_caps()
        self.assertFalse(st.samples_writing)
        self.assertTrue(st.writing)
        self.assertFalse(state.disk["samples_writing"])
        st.append_sample(samples(1)[0])
        st.append_json("rollups", {"t": 1})
        st.flush()
        self.assertEqual(len(st.read_samples()), 5)
        self.assertEqual(len(st.read_json("rollups")), 1)
        self.assertEqual(state.collector("store")["status"], "degraded")

    def test_session_cap(self):
        state = State(1.0, "s")
        st = Store(self.tmp / "s", {"disk": dict(cfg()["disk"], session_cap_mb=0.0001)}, state=state,
                   disk_usage=lambda p: FakeUsage(50_000))
        self.stores.append(st)
        st.write_atomic("report.html", "x" * 2000)
        st.check_caps()
        self.assertFalse(st.writing)
        self.assertIn("cap", state.disk["reason"])

    def test_write_failure_latches_until_retry_window(self):
        clock = {"t": 100.0}
        state = State(1.0, "s")
        st = self.make(state=state, clock=lambda: clock["t"])
        st.append_json("events", {"id": "x"})
        st.stop()  # closes the files; now make the directory unwritable for the next append
        st2 = self.make(name="20261011-190001", state=state, clock=lambda: clock["t"])
        # feed the writer internals directly with a file handle that fails
        class Boom:
            def write(self, b):
                raise OSError(28, "No space left on device")

            def flush(self):
                pass

            def close(self):
                pass

            def fileno(self):
                raise OSError("closed")

        st2._files["events.jsonl"] = Boom()
        st2._handle(("events.jsonl", b"{}\n"))
        self.assertFalse(st2.writing)
        self.assertIn("No space left", state.disk["reason"])
        self.assertEqual(state.collector("store")["status"], "degraded")
        clock["t"] += 5
        st2.check_caps()  # the periodic cap check must not flap it back to ok
        self.assertFalse(st2.writing)
        self.assertIn("No space left", st2.disk["reason"])
        self.assertEqual(state.collector("store")["status"], "degraded")
        clock["t"] += storemod.WRITE_RETRY_S
        st2.check_caps()  # one retry is allowed after the window
        self.assertTrue(st2.writing)
        st2._files.pop("events.jsonl")
        st2._handle(("events.jsonl", b'{"id":"ok"}\n'))  # a successful write keeps it cleared
        self.assertTrue(st2.writing)
        self.assertEqual(state.collector("store")["status"], "ok")

    def test_dir_size_is_cached_between_full_walks(self):
        clock = {"t": 0.0}
        st = self.make(clock=lambda: clock["t"])
        st.write_atomic("report.html", "x" * (2 * 1024 * 1024))
        walks = {"n": 0}
        orig_walk = os.walk

        def counting_walk(*a, **k):
            walks["n"] += 1
            return orig_walk(*a, **k)

        os.walk = counting_walk
        self.addCleanup(setattr, os, "walk", orig_walk)
        clock["t"] += 5
        st.check_caps()
        clock["t"] += 5
        st.check_caps()
        self.assertEqual(walks["n"], 0)  # within FULL_WALK_S: no walk, cache only
        self.assertGreaterEqual(st.disk["session_mb"], 2.0)  # write_atomic fed the cache
        clock["t"] += storemod.FULL_WALK_S
        st.check_caps()
        self.assertEqual(walks["n"], 1)

    def test_ok_when_disk_usage_fails(self):
        def boom(p):
            raise OSError("no statvfs")

        state = State(1.0, "s")
        st = self.make(state=state, disk_usage=boom)
        self.assertTrue(st.writing)
        self.assertIsNone(state.disk["free_mb"])
        self.assertEqual(state.collector("store")["status"], "ok")


if __name__ == "__main__":
    unittest.main()
