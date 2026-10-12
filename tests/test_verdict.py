"""Session verdict, headline and Tell-Comcast block (SPEC §7.7, §8.3): tally, sentences, marks rule, comcast text."""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from helpers_detection import BEYOND_GW, T0, Session, make_cfg, make_ticker, ntp_row, run_episode  # noqa: E402
from laglens.engine import verdict as vm  # noqa: E402
from laglens.state import KIND_ICMP, Episode, Event, Mark, Target  # noqa: E402


def ep(eid, t0, dur, cls, conf=0.8, relevant=True, subclass=None, docsis=None, direction="n/a", evidence=None):
    return Episode(id=eid, t0=t0, t1=t0 + dur, dur_s=dur, cls=cls, subclass=subclass, confidence=conf,
                   comcast_relevant=relevant, docsis=docsis, direction=direction, evidence=list(evidence or []))


class TallyTests(unittest.TestCase):
    def setUp(self):
        self.s = Session(with_store=False)
        self.addCleanup(self.s.close)
        st = self.s.state
        st.episodes.extend([
            ep("ep-1", T0 + 100, 10, "docsis_access"),
            ep("ep-2", T0 + 300, 10, "docsis_access"),
            ep("ep-3", T0 + 500, 10, "docsis_access"),
            ep("ep-4", T0 + 700, 10, "internet", conf=0.5),
            ep("ep-5", T0 + 900, 10, "docsis_access", relevant=False),      # host-tagged: full tally only
            ep("ep-6", T0 + 1000, 1.0, "docsis_access"),                    # blip: never counted
            ep("ep-7", T0 + 1100, 60, "xb7_cpu", conf=0.6),                 # informational: excluded
            ep("ep-8", T0 + 1200, 60, "loadtest", conf=1.0),                # self-inflicted: excluded
            Episode(id="", t0=T0 + 1300),                                   # unregistered: ignored
        ])

    def test_counted_episodes_and_tally(self):
        s = self.s
        now = T0 + 2000
        counted = vm.counted_episodes(s.state, now)
        self.assertEqual([e.id for e in counted], ["ep-1", "ep-2", "ep-3", "ep-4", "ep-5", "ep-7", "ep-8"])
        full, comcast = vm.tally(counted, now)
        self.assertEqual(set(full), {"docsis_access", "internet"})
        self.assertAlmostEqual(full["docsis_access"]["weight"], 4 * 10 * 0.8)
        self.assertEqual(full["docsis_access"]["episodes"], 4)
        self.assertAlmostEqual(full["internet"]["weight"], 5.0)
        self.assertAlmostEqual(comcast["docsis_access"]["weight"], 3 * 10 * 0.8)  # ep-5 not comcast_relevant
        top = vm.top_list(full)
        self.assertEqual(top[0]["class"], "docsis_access")
        self.assertAlmostEqual(top[0]["share"], round(32 / 37.0, 2))
        self.assertEqual(top[0]["episodes"], 4)
        self.assertEqual(top[0]["seconds"], 40.0)
        self.assertEqual(vm.headline_class(top), "docsis_access")
        self.assertEqual(vm.headline_class([]), "none")
        self.assertEqual(vm.headline_class([{"class": "a", "share": 0.55}, {"class": "b", "share": 0.45}]), "mixed")

    def test_open_episode_counts_to_now(self):
        st = self.s.state
        st.episodes.append(Episode(id="ep-9", t0=T0 + 1500, cls="internet", confidence=0.5))
        full, _ = vm.tally(vm.counted_episodes(st, T0 + 1510), T0 + 1510)
        self.assertAlmostEqual(full["internet"]["seconds"], 20.0)  # ep-4 (10 s) + the open one (10 s so far)


class SentenceTests(unittest.TestCase):
    def setUp(self):
        self.s = Session(with_store=False)
        self.addCleanup(self.s.close)

    def test_what_sentence_with_numbers(self):
        st = self.s.state
        now = T0 + 2 * 3600 + 5 * 60
        self.assertIn("showed no trouble episodes longer than 1.5 s.", vm.sentence_what(st, [], now))
        st.blips = 3
        st.episodes.append(ep("ep-7", T0 + 1100, 60, "xb7_cpu", conf=0.6))
        text = vm.sentence_what(st, vm.counted_episodes(st, now), now)
        self.assertIn("(3 sub-1.5 s blips; 1 informational episode: XB7 CPU, not a path fault)", text)
        st.blips = 0
        eps = [ep("ep-%d" % i, T0 + 100 * i, 10, "docsis_access") for i in range(1, 5)]
        self.assertEqual(vm.sentence_what(st, eps, now),
                         "Over 2 h 5 m your connection dropped packets in 4 short bursts totalling 40 s.")
        # latency-dominated episodes "slowed down"; ≥ 30 s ones are "episodes"
        st.events.append(Event(id="ev-1", t0=T0, t1=T0 + 1, type="latency_spike", target=0, severity=3))
        long_ep = ep("ep-9", T0 + 900, 45, "upload_saturation")
        long_ep.events = ["ev-1"]
        self.assertEqual(vm.sentence_what(st, [long_ep], now),
                         "Over 2 h 5 m your connection slowed down in 1 episode totalling 45 s.")

    def test_where_sentence_hedging_and_docsis_detail(self):
        eps = [ep("ep-%d" % i, T0 + 100 * i, 10, "docsis_access",
                  docsis={"events": [{"type": "docsis_t3", "t": T0 + 100 * i + 2}]} if i <= 4 else None) for i in range(1, 7)]
        eps.append(ep("ep-7", T0 + 900, 10, "internet", conf=0.5))
        top = vm.top_list(vm.tally(eps, T0 + 2000)[0])
        s = vm.sentence_where("docsis_access", "high", eps, top, T0 + 2000)
        self.assertEqual(s, "In 6 of them your XB7 kept answering but everything past it went silent at the same moment, "
                            "and the modem logged 4 T3 timeouts, which points at the cable line or Comcast's equipment "
                            "rather than anything in your home.")
        self.assertIn("which may point at the cable line", vm.sentence_where("docsis_access", "low", eps[:6], top, T0 + 2000))
        self.assertIn("which suggests the cable line", vm.sentence_where("docsis_access", "medium", eps[:6], top, T0 + 2000))
        self.assertTrue(vm.sentence_where("docsis_access", "medium", eps[:6], top, T0 + 2000).startswith("In all 6"))
        self.assertTrue(vm.sentence_where("docsis_access", "medium", eps[:1], top, T0 + 2000).startswith("In it your XB7"))
        self.assertIn("slowed down at the same moment", vm.sentence_where("docsis_access", "high", eps, top, T0 + 2000, loss_dominant=False))
        mixed = vm.sentence_where("mixed", "low", eps, [{"class": "docsis_access", "share": 0.55}, {"class": "internet", "share": 0.45}], T0)
        self.assertIn("split between the cable line / Comcast access network (55%) and the wider internet (45%)", mixed)
        self.assertEqual(vm.sentence_where("none", "low", [], [], T0), "There is nothing to point at yet.")
        for cls in ("comcast_network", "xb7_gateway", "xbox_lan", "probe_link", "probe_wifi", "probe_host", "upload_saturation",
                    "ipv6_only", "ipv4_only", "internet", "single_destination", "dns", "cdn", "unknown"):
            text = vm.sentence_where(cls, "medium", [ep("e", T0, 5, cls)], [{"class": cls, "share": 1.0}], T0 + 100)
            self.assertTrue(text.startswith("In it"), text)
            self.assertTrue(text.endswith("."), text)

    def test_marks_sentence_and_fifty_percent_rule(self):
        st = self.s.state
        self.assertEqual(vm.sentence_marks(st)[0], "You have not pressed 'Lag happened' yet, so there is nothing to line up.")
        for i in range(6):
            st.marks.append(Mark(id="mk-%d" % i, t_pressed=T0 + i, offset_s=0, t_est=T0 + i, episode="ep-1" if i < 5 else None))
        text, total, linked = vm.sentence_marks(st)
        self.assertEqual((total, linked), (6, 5))
        self.assertEqual(text, "5 of your 6 'Lag happened' presses line up with these bursts; 1 showed nothing, "
                               "which is likely the game server.")
        for m in st.marks[1:]:
            m.episode = None
        text, total, linked = vm.sentence_marks(st)
        self.assertEqual((total, linked), (6, 1))
        self.assertIn("1 of your 6 'Lag happened' presses line up", text)
        self.assertIn("The probe could not see most of your lag presses: suspect the Xbox's own cable/port, the game servers, "
                      "or run a second probe (peer mode).", text)
        st.marks[0].episode = None
        self.assertTrue(vm.sentence_marks(st)[0].startswith("None of your 6 'Lag happened' presses showed anything"))
        for m in st.marks:
            m.episode = "ep-1"
        self.assertTrue(vm.sentence_marks(st)[0].startswith("All 6 of your 'Lag happened' presses line up"))
        self.assertNotIn("peer mode", vm.sentence_marks(st)[0])

    def test_persistent_findings(self):
        st = self.s.state
        st.host = {"speed": 100, "duplex": "half", "v6": True}
        st.xbox = {"ip": "10.0.0.23", "state": "awake", "source": None, "link_mbps": 100}
        st.set_latest("igd", {"status": "Connected", "mappings": [{"proto": "UDP", "ext": 3074, "int": "10.0.0.23:3074", "desc": "Xbox"}]})
        st.set_latest("docsis", {"ds_snr_min": 36.4, "us_pwr_max": 44.0, "uncorr_delta": 12})
        st.add_row5("docsis", {"t": int(T0) + 5, "docsis": {"uncorr_delta": 800}})
        st.events.append(Event(id="ev-1", t0=T0 + 5, t1=T0 + 5, type="docsis_reboot", target=None, severity=4))
        out = vm.persistent_findings(self.s.ctx, [], T0 + 100)
        self.assertIn("Probe link: 100 Mb/s half (slow or half duplex: worth fixing).", out)
        self.assertIn("Xbox link: 100 Mb/s (expected 1000).", out)
        self.assertIn("IPv6: available.", out)
        self.assertIn("NAT: UPnP works (1 Xbox mapping).", out)
        self.assertIn("DOCSIS: min DS SNR 36.4 dB, max US power 44.0 dBmV, uncorrectables +800 this session.", out)
        self.assertIn("XB7 reboot/reset count: 1.", out)
        # evening concentration needs ≥ 3 h of session
        eve = time.mktime(time.localtime(T0)[:3] + (20, 0, 0, 0, 0, -1))
        if eve < T0:  # in time zones where T0 is already past 20:00 local, use the next evening
            eve += 86400
        eps = [ep("ep-%d" % i, eve + 60 * i, 20, "docsis_access") for i in range(5)]
        out = vm.persistent_findings(self.s.ctx, eps, eve + 4 * 3600)
        self.assertTrue(any(line.startswith("Trouble concentrates in the evening (19:00–23:00): 100%") for line in out), out)

    def test_fmt_helpers(self):
        self.assertEqual([vm.fmt_duration(x) for x in (42, 61, 3600 * 6 + 12 * 60 + 30)], ["42 s", "1 m", "6 h 12 m"])
        self.assertEqual([vm.fmt_seconds(x) for x in (2.6, 41.4, 125)], ["2.6 s", "41 s", "2 m"])
        self.assertEqual(vm.truncate_prefix("2601:abcd:1234:5678::/64"), "2601:abcd:1234::/64 (truncated)")
        self.assertEqual(vm.truncate_prefix("2601:abcd:1234::/64 (truncated)"), "2601:abcd:1234::/64 (truncated)")
        self.assertIsNone(vm.truncate_prefix(None))


class ComputeVerdictTests(unittest.TestCase):
    def setUp(self):
        self.s = Session()
        self.addCleanup(self.s.close)

    def test_shape_text_and_next_steps(self):
        s = self.s
        st = s.state
        for i in range(1, 5):
            st.episodes.append(ep("ep-%d" % i, T0 + 100 * i, 10, "docsis_access", conf=0.86, subclass="t3_signature",
                                  direction="upstream", docsis={"events": [{"type": "docsis_t3", "t": T0 + 100 * i + 2}]}))
        st.episodes.append(ep("ep-5", T0 + 600, 10, "docsis_access", conf=0.8, relevant=False))
        for i in range(6):
            st.marks.append(Mark(id="mk-%d" % i, t_pressed=T0 + i, offset_s=0, t_est=T0 + i, episode="ep-1" if i < 5 else None))
        now = T0 + 6 * 3600 + 12 * 60
        v = vm.compute_verdict(s.ctx, now=now)
        self.assertIs(st.verdict, v)
        self.assertEqual(set(v), {"text", "confidence", "top", "comcast", "next", "marks"})
        self.assertEqual(v["confidence"], "high")
        self.assertEqual(v["top"][0]["class"], "docsis_access")
        self.assertEqual(v["top"][0]["episodes"], 5)
        self.assertEqual(v["marks"], {"total": 6, "linked": 5})
        self.assertTrue(v["text"].startswith("Over 6 h 12 m your connection dropped packets in 5 short bursts totalling 50 s. "
                                             "In all 5 your XB7 kept answering but everything past it went silent at the same moment, "
                                             "and the modem logged 4 T3 timeouts, which points at the cable line"), v["text"])
        self.assertIn("5 of your 6 'Lag happened' presses line up with these bursts; 1 showed nothing", v["text"])
        self.assertEqual(len(v["next"]), 3)
        for step in v["next"]:
            self.assertEqual(set(step), {"try", "confirm_if", "refute_if"})
        self.assertIn("Call Comcast with the attached evidence", v["next"][0]["try"])
        self.assertIn("Lag Lens evidence for Comcast", v["comcast"])
        self.assertIn("Episodes (local time; only those not explained by equipment in this home): 4", v["comcast"])
        self.assertTrue((s.store.dir / "comcast_evidence.txt").exists())
        self.assertEqual((s.store.dir / "comcast_evidence.txt").read_text(encoding="utf-8"), v["comcast"])
        self.assertEqual(st.snapshot()["verdict"], v)

    def test_empty_session_and_mixed(self):
        s = self.s
        v = vm.compute_verdict(s.ctx, now=T0 + 120)
        self.assertEqual((v["confidence"], v["top"], v["next"]), ("low", [], []))
        self.assertIn("showed no trouble episodes longer than 1.5 s", v["text"])
        self.assertIn("There is nothing to point at yet.", v["text"])
        self.assertIn("no Comcast-side episode recorded yet", v["comcast"])
        s.state.episodes.append(ep("ep-1", T0 + 10, 10, "docsis_access", conf=0.7))
        s.state.episodes.append(ep("ep-2", T0 + 50, 10, "xbox_lan", conf=0.7))
        v = vm.compute_verdict(s.ctx, now=T0 + 120)
        self.assertEqual([t["class"] for t in v["top"]], ["docsis_access", "xbox_lan"])
        self.assertEqual(v["top"][0]["share"], 0.5)
        self.assertIn("The evidence is split between the cable line / Comcast access network (50%) and the Xbox LAN cable/port (50%)", v["text"])
        self.assertEqual(v["next"][0]["try"], vm.NEXT_STEPS["mixed"][0]["try"])

    def test_verdict_never_raises(self):
        s = self.s
        s.state.episodes.append(ep("ep-1", T0 + 10, 10, "docsis_access"))
        s.state.events = None  # type: ignore[assignment]  # breaks _loss_dominant
        v = vm.compute_verdict(s.ctx, now=T0 + 120)
        self.assertTrue(v["text"].startswith("Verdict unavailable"))
        self.assertEqual(v["confidence"], "low")


class ComcastTextTests(unittest.TestCase):
    def setUp(self):
        self.s = Session()
        self.addCleanup(self.s.close)

    def test_structure_and_relevance_filter(self):
        s = self.s
        st = s.state
        st.host = {"hostname": "mac", "iface": "en0", "speed": 1000, "duplex": "full", "gateway": "10.0.0.1", "wifi": True}
        st.set_latest("wan", {"ext_ip": "73.1.2.3", "ext_ip6": "2601:abcd:1234:5678::9", "prefix6": "2601:abcd:1234:5678::/64", "t": T0})
        st.set_latest("docsis", {"fw": "3.5p7", "ds_snr_min": 36.4, "us_pwr_max": 44.0, "uncorr_delta": 5, "log_clock_offset_s": -3, "t": T0})
        st.add_row5("docsis", {"t": int(T0) + 5, "docsis": {"uncorr_delta": 812}})
        st.events.append(Event(id="ev-1", t0=T0 + 50, t1=T0 + 50, type="docsis_t3", target=None, severity=3))
        st.events.append(Event(id="ev-2", t0=T0 + 60, t1=T0 + 60, type="docsis_t4", target=None, severity=3))
        st.episodes.append(ep("ep-1", T0 + 48, 9.5, "docsis_access", subclass="t3_signature", direction="upstream",
                              docsis={"events": [{"type": "docsis_t3", "t": T0 + 50}]},
                              evidence=["gateway 10.0.0.1: 0% loss, +1 ms", "Comcast hop 10.60.12.1: 38% loss, +2 ms",
                                        "1.1.1.1: 36% loss, +0 ms"]))
        st.episodes.append(ep("ep-2", T0 + 200, 5, "probe_wifi", relevant=False))
        st.episodes.append(ep("ep-3", T0 + 300, 5, "xb7_cpu"))
        text = vm.comcast_text(s.ctx, now=T0 + 400)
        lines = text.splitlines()
        self.assertTrue(lines[0].startswith("Lag Lens evidence for Comcast — session 20261011-190000 ("))
        self.assertEqual(lines[1], "Gateway: XB7 10.0.0.1 firmware 3.5p7 | WAN IP: 73.1.2.3 | IPv6 prefix: 2601:abcd:1234::/64 (truncated) "
                                   "| Probe host: mac (en0 1000 Mb/s full (Wi-Fi))")
        self.assertIn("Episodes (local time; only those not explained by equipment in this home): 1", text)
        header = [ln for ln in lines if ln.startswith("time ")][0]
        for col in ("dur", "class", "gw loss", "Comcast hop", "internet", "direction", "DOCSIS"):
            self.assertIn(col, header)
        row = [ln for ln in lines if "docsis_access/t3_signature" in ln][0]
        self.assertIn(time.strftime("%H:%M:%S", time.localtime(T0 + 48)), row)
        self.assertIn("9.5 s", row)
        self.assertIn("upstream", row)
        self.assertIn("T3 (+2 s)", row)
        self.assertIn("0%", row)   # gateway loss from the evidence line (no raw samples)
        self.assertIn("38%", row)
        self.assertIn("36%", row)
        self.assertNotIn("probe_wifi", text)
        self.assertNotIn("xb7_cpu", text)
        self.assertIn("DOCSIS snapshot: min DS SNR 36.4 dB, max US power 44.0 dBmV, Σ uncorrectables +812, T3 ×1, T4 ×1, reboots 0", text)
        self.assertIn("XB7 log clock offset: -3 s", text)
        self.assertTrue(lines[-1].startswith("Request: in these 1 episode (9.5 s in total) the gateway answered normally"))
        self.assertEqual((s.store.dir / "comcast_evidence.txt").read_text(encoding="utf-8"), text)
        # write=False leaves the file alone
        (s.store.dir / "comcast_evidence.txt").unlink()
        vm.comcast_text(s.ctx, now=T0 + 400, write=False)
        self.assertFalse((s.store.dir / "comcast_evidence.txt").exists())

    def test_without_docsis_or_wan(self):
        text = vm.comcast_text(self.s.ctx, now=T0 + 400)
        self.assertIn("Gateway: XB7 10.0.0.1 | WAN IP: unknown | IPv6 prefix: n/a", text)
        self.assertIn("DOCSIS snapshot: not collected (XB7 login not configured)", text)
        self.assertIn("Request: no Comcast-side episode recorded yet", text)

    def test_loss_columns_from_raw_samples(self):
        s = self.s
        s.stream(T0 + 40, T0 + 50, lost=lambda k, t: k in BEYOND_GW and T0 + 42 <= t < T0 + 47)
        s.state.episodes.append(ep("ep-1", T0 + 42, 5, "docsis_access"))
        text = vm.comcast_text(s.ctx, now=T0 + 100)
        row = [ln for ln in text.splitlines() if "docsis_access" in ln][0]
        cols = row.split()
        # time dur(2 tokens) class gw hop internet direction docsis
        self.assertEqual(cols[4], "0%")
        self.assertGreaterEqual(int(cols[5].rstrip("%")), 90)  # 2 Hz hop: 10 of 11 samples in the window
        self.assertGreaterEqual(int(cols[6].rstrip("%")), 90)

    def test_ipv6_evidence_lines_and_an_ipv6_only_comcast_hop(self):
        # an older episode (no raw samples left) is read back from its evidence lines, whose IPv6 labels contain
        # colons; on this line the first Comcast hop answers only over IPv6
        s = Session(keys=("gw4", "inet4_cf", "inet4_g", "inet6_cf", "inet6_g"))
        self.addCleanup(s.close)
        s.state.add_target(Target(id=-1, key="isp_hop6", role="isp_hop", addr="2001:558:aaaa:cccc::3", family=6,
                                  kind=KIND_ICMP, label="isp_hop6", rate_hz=2.0))
        s.state.episodes.append(ep("ep-1", T0 + 40, 5, "upstream_delay", direction="upstream", evidence=[
            "gateway 10.0.0.1: 0% loss, +0 ms", "Comcast hop 2001:558:aaaa:cccc::3: 4% loss, +23 ms",
            "1.1.1.1: 0% loss, +22 ms", "8.8.8.8: 0% loss, +22 ms",
            "2606:4700:4700::1111: 2% loss, +11 ms", "2001:4860:4860::8888: 6% loss, +12 ms"]))
        text = vm.comcast_text(s.ctx, now=T0 + 100, write=False)
        row = [ln for ln in text.splitlines() if "upstream_delay" in ln][0]
        self.assertEqual(row.split()[4:7], ["0%", "4%", "2%"])  # gw, Comcast hop (IPv6), internet mean


class HeadlineTests(unittest.TestCase):
    def setUp(self):
        self.s = Session(cfg=make_cfg(warmup_s=60))
        self.addCleanup(self.s.close)

    def test_warmup_no_sign_and_classes(self):
        s = self.s
        h = vm.headline(s.ctx, now=T0 + 10)
        self.assertEqual(h["answer"], "unknown")
        self.assertEqual(h["text"], "Can't tell yet")
        self.assertIn("Learning your normal", h["action"])
        self.assertEqual(vm.headline(s.ctx, now=T0 + 100), {"answer": "no_sign", "text": "No sign of it yet", "action": "Keep running"})
        s.state.episodes.append(Episode(id="ep-0", t0=T0 + 90, cls="unknown", confidence=0.3))  # open, < 1.5 s so far
        self.assertEqual(vm.headline(s.ctx, now=T0 + 91)["action"], "Trouble in progress — classifying")
        s.state.episodes.pop()
        s.state.episodes.append(ep("ep-1", T0 + 100, 10, "docsis_access", conf=0.9))
        s.state.verdict = dict(s.state.verdict, confidence="high")
        h = vm.headline(s.ctx, now=T0 + 200)
        self.assertEqual((h["answer"], h["text"]), ("yes_comcast", "Yes — Comcast side (cable line)"))
        self.assertEqual(h["action"], vm.NEXT_STEPS["docsis_access"][0]["try"])
        s.state.verdict = dict(s.state.verdict, confidence="medium")
        self.assertEqual(vm.headline(s.ctx, now=T0 + 200)["text"], "Probably yes — Comcast side (cable line)")
        s.state.episodes[-1].cls = "xbox_lan"
        self.assertEqual(vm.headline(s.ctx, now=T0 + 200)["text"], "Probably yes — your home (Xbox cable/port)")
        s.state.episodes[-1].cls = "internet"
        h = vm.headline(s.ctx, now=T0 + 200)
        self.assertEqual((h["answer"], h["text"]), ("no_sign", "Probably not your home or Comcast — the wider internet"))
        s.state.episodes[-1].cls = "ipv6_only"
        self.assertEqual(vm.headline(s.ctx, now=T0 + 200)["text"], "Can't tell yet — IPv6 only")
        s.state.episodes.append(ep("ep-2", T0 + 150, 10, "xbox_lan", conf=0.9))
        h = vm.headline(s.ctx, now=T0 + 200)
        self.assertEqual(h["answer"], "unknown")
        self.assertTrue(h["text"].startswith("Can't tell yet — split between"))

    def test_end_to_end_through_the_ticker(self):
        s = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s.close)
        s.state.set_latest("ntp", ntp_row())
        tk = make_ticker(s)
        eps = run_episode(s, tk.tick, baseline_s=40, lost_keys=BEYOND_GW, fault_s=2.5)
        self.assertEqual(eps[0].cls, "docsis_access")
        v = s.state.verdict
        self.assertEqual(v["top"][0]["class"], "docsis_access")
        self.assertIn("1 short burst totalling 2.", v["text"])
        self.assertIn("upstream", v["comcast"])
        self.assertEqual(s.state.headline["answer"], "yes_comcast")
        self.assertIn("verdict", s.published_names())
        self.assertTrue((s.store.dir / "comcast_evidence.txt").exists())


if __name__ == "__main__":
    unittest.main()
