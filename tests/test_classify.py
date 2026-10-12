"""Classification fixtures: one synthetic episode per SPEC §7.6 class through State → Detector → classify.

Each fixture asserts class, subclass, confidence band, the ``alt`` runner-up
and evidence substrings. ``nat_stateful`` (rule 12) is not in v1.
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from helpers_detection import (  # noqa: E402
    BEYOND_GW,
    ICMP_KEYS,
    INTERNET,
    T0,
    Session,
    feed,
    make_cfg,
    ntp_row,
    run_episode,
)
from laglens.engine import classify as cm  # noqa: E402
from laglens.engine.detector import Detector  # noqa: E402
from laglens.state import Episode  # noqa: E402


def local_at(hour: int, base: float = T0) -> float:
    """A wall time on ``base``'s local date at ``hour:00``, on the 5 s grid."""
    lt = time.localtime(base)
    t = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, hour, 0, 0, 0, 0, -1))
    return float(int(t) // 5 * 5)


class ClassifyBase(unittest.TestCase):
    t_start = T0

    def setUp(self):
        self.s = Session(t0=self.t_start, cfg=make_cfg(warmup_s=30))
        self.addCleanup(self.s.close)
        self.det = Detector(self.s.ctx)

    def episode(self, **kw) -> Episode:
        kw.setdefault("baseline_s", 40)
        eps = run_episode(self.s, self.det.step, **kw)
        self.assertEqual(len(eps), 1, "expected exactly one closed episode, got %r" % [e.to_dict(brief=True) for e in eps])
        return eps[0]

    def assertEvidence(self, ep: Episode, *needles: str):
        for needle in needles:
            self.assertTrue(any(needle in line for line in ep.evidence), "%r not in evidence %r" % (needle, ep.evidence))

    def assertBand(self, ep: Episode, band: str):
        self.assertEqual(cm.confidence_band(ep.confidence), band, "confidence %.2f is not %s" % (ep.confidence, band))

    def note_at(self, rel_s: float, type_: str, **peak):
        """``per_second`` hook raising one note ``rel_s`` seconds after the fault start."""
        s = self.s

        def per(t):
            if int(t) == int(s.fault_t0 + rel_s):
                s.state.raise_note(type_, t=t, severity=peak.pop("severity", 2), note=peak.pop("note", type_), **peak)
        return per


class HelperTests(unittest.TestCase):
    def test_confidence_band_and_floor(self):
        self.assertEqual([cm.confidence_band(x) for x in (0.49, 0.5, 0.74, 0.75)], ["low", "medium", "medium", "high"])
        self.assertEqual(cm.floor_for("gateway", 0.5), 10.0)
        self.assertEqual(cm.floor_for("xbox", 3.0), 15.0)
        self.assertEqual(cm.floor_for("isp_hop"), 25.0)
        self.assertEqual(cm.floor_for("anycast"), 30.0)

    def test_ntp_direction_reads_the_aux_probes_row(self):
        direction, share, dtheta = cm._ntp_direction([ntp_row("upstream", 0.81, d_offset=25.0, d_rtt=60.0)])
        self.assertEqual((direction, share, dtheta), ("upstream", 0.81, 25.0))
        # top-level direction/share without per-server detail
        self.assertEqual(cm._ntp_direction([{"direction": "downstream", "share": 0.1, "t": 1}])[:2], ("downstream", 0.1))
        # a row without a baseline yet is not a measurement
        self.assertEqual(cm._ntp_direction([{"cf": {"share": None, "direction": "n/a"}, "direction": "n/a", "share": None}]),
                         ("n/a", None, None))
        # the row with the larger RTT shift wins
        rows = [ntp_row("symmetric", 0.5, d_offset=0.0, d_rtt=10.0), ntp_row("upstream", 0.9, d_offset=30.0, d_rtt=70.0)]
        self.assertEqual(cm._ntp_direction(rows)[0], "upstream")
        self.assertEqual(cm._ntp_direction([])[0], "n/a")
        # per-server shares only: combined by mean, mixed when they disagree
        self.assertEqual(cm._ntp_direction([{"cf": {"share": 0.9}, "g": {"share": 0.2}}])[0], "mixed")
        self.assertEqual(cm._ntp_direction([{"cf": {"share": 0.8}, "g": {"share": 0.75}}])[0], "upstream")

    def test_classify_never_raises(self):
        s = Session()
        self.addCleanup(s.close)
        ep = Episode(id="ep-x", t0=T0 + 10, t1=T0 + 12)

        class Broken:
            cfg = None

            @property
            def state(self):
                raise RuntimeError("boom")

        cm.classify(ep, Broken())
        self.assertEqual(ep.cls, "unknown")
        self.assertTrue(ep.evidence[0].startswith("classification failed"))


class RuleFixtureTests(ClassifyBase):
    def test_1_probe_host(self):
        s = self.s

        def per(t):
            stalled = s.fault_t0 - 1 <= t <= s.fault_t1 + 1
            s.state.set_latest("host", {"late_ms_max": 300 if stalled else 2, "loop_gap_ms": 400 if stalled else 3,
                                        "stall": stalled, "t": t + 0.5})

        ep = self.episode(lost_keys=INTERNET, fault_s=4, per_second=per)
        self.assertEqual((ep.cls, ep.subclass), ("probe_host", None))
        self.assertBand(ep, "medium")  # 0.9 − 0.2 single signal
        self.assertEqual(ep.host_tags, ["host_stall"])
        self.assertFalse(ep.comcast_relevant)
        self.assertEvidence(ep, "probe host stalled or paused for 100% of the episode", "host tags: host_stall",
                            "single signal")
        self.assertEqual(ep.alt["class"], "internet")
        self.assertIn("outranked by probe_host", ep.alt["why_rejected"])

    def test_2_probe_wifi(self):
        self.s.state.host = {"wifi": True, "iface": "en0"}
        ep = self.episode(lost_keys=INTERNET, fault_s=4, per_second=self.note_at(0, "wifi_drop", note="RSSI -55 -> -80"))
        self.assertEqual(ep.cls, "probe_wifi")
        self.assertBand(ep, "high")  # 0.8: wifi event + host on Wi-Fi
        self.assertEqual(ep.host_tags, ["wifi_drop"])
        self.assertFalse(ep.comcast_relevant)
        self.assertEvidence(ep, "Wi-Fi drop/roam on the probe host coincided with the episode")
        # wired host: the same event does not exonerate
        s2 = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s2.close)
        s2.state.host = {"wifi": False}

        def per(t):
            if int(t) == int(s2.fault_t0):
                s2.state.raise_note("wifi_roam", t=t, severity=2)
        eps = run_episode(s2, Detector(s2.ctx).step, baseline_s=40, lost_keys=INTERNET, fault_s=4, per_second=per)
        self.assertEqual(eps[0].cls, "internet")
        self.assertEqual(eps[0].host_tags, ["wifi_roam"])  # still tagged (§7.3), just not the class

    def test_2b_probe_wifi_latency_without_a_wifi_event(self):
        """Wi-Fi host: the gateway itself slows together with everything beyond it (no RSSI note)."""
        self.s.state.host = {"wifi": True, "iface": "en0"}
        ep = self.episode(slow_keys=["gw4"] + list(INTERNET), slow_ms=60, fault_s=6)
        self.assertEqual(ep.cls, "probe_wifi")
        self.assertEqual(ep.subclass, "wifi_latency")
        self.assertBand(ep, "medium")
        self.assertIn("wifi_latency", ep.host_tags)
        self.assertFalse(ep.comcast_relevant)
        self.assertEvidence(ep, "probe host is on Wi-Fi and the gateway itself slowed", "wire this computer to the XB7")

    def test_2c_probe_wifi_loss_variant_and_wired_host_unchanged(self):
        self.s.state.host = {"wifi": True, "iface": "en0"}
        ep = self.episode(lost_keys=["gw4"] + list(INTERNET), fault_s=4)
        self.assertEqual((ep.cls, ep.subclass), ("probe_wifi", "wifi_loss"))
        self.assertFalse(ep.comcast_relevant)
        # the same pattern on a wired host is NOT attributed to Wi-Fi
        s2 = Session(t0=self.t_start, cfg=make_cfg(warmup_s=30))
        self.addCleanup(s2.close)
        s2.state.host = {"wifi": False, "iface": "enp3s0"}
        det2 = Detector(s2.ctx)
        eps = run_episode(s2, det2.step, baseline_s=40, slow_keys=["gw4"] + list(INTERNET), slow_ms=60, fault_s=6)
        self.assertEqual(len(eps), 1)
        self.assertNotEqual(eps[0].cls, "probe_wifi")

    def test_3_loadtest(self):
        f0 = self.t_start + 40
        ep = self.episode(lost_keys=INTERNET, fault_s=4, loadtest=(f0 - 5, f0 + 30))
        self.assertEqual(ep.cls, "loadtest")
        self.assertBand(ep, "high")
        self.assertEqual(ep.confidence, 0.95)  # capped
        self.assertEvidence(ep, "inside a load-test window (self-inflicted)")
        self.assertEqual(ep.alt["class"], "internet")

    def test_4_probe_link(self):
        ep = self.episode(lost_keys=ICMP_KEYS, fault_s=4, per_second=self.note_at(0, "link_flap", severity=3, note="carrier down"))
        self.assertEqual(ep.cls, "probe_link")
        self.assertBand(ep, "high")
        self.assertEqual(ep.host_tags, ["link_flap"])
        self.assertFalse(ep.comcast_relevant)
        self.assertEvidence(ep, "link flap / interface errors on the probe host", "gateway and Xbox lost packets together")
        self.assertEqual(ep.alt["class"], "xb7_gateway")
        # gateway + Xbox lost without a link event: still probe_link, single signal
        s2 = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s2.close)
        eps = run_episode(s2, Detector(s2.ctx).step, baseline_s=40, lost_keys=ICMP_KEYS, fault_s=4)
        self.assertEqual(eps[0].cls, "probe_link")
        self.assertBand(eps[0], "medium")
        self.assertTrue(eps[0].comcast_relevant)

    def test_5_xbox_lan(self):
        ep = self.episode(lost_keys=["xbox"], fault_s=4)
        self.assertEqual(ep.cls, "xbox_lan")
        self.assertBand(ep, "medium")
        self.assertEqual(ep.confidence, 0.7)
        self.assertEqual(ep.xbox_state, "awake")
        self.assertEvidence(ep, "only the Xbox was affected: Xbox 10.0.0.23", "% loss")
        self.assertEqual(ep.alt["class"], "comcast_network")
        s2 = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s2.close)
        s2.state.xbox = {"ip": "10.0.0.23", "state": "awake", "source": "udp5050", "link_mbps": 100}
        eps = run_episode(s2, Detector(s2.ctx).step, baseline_s=40, lost_keys=["xbox"], fault_s=4)
        self.assertEqual((eps[0].cls, eps[0].confidence, eps[0].xbox_state), ("xbox_lan", 0.9, "awake"))
        self.assertBand(eps[0], "high")
        self.assertTrue(any("100 Mb/s" in line for line in eps[0].evidence))
        # an asleep Xbox never opens an episode at all
        s3 = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s3.close)
        s3.state.xbox = {"ip": "10.0.0.23", "state": "asleep", "source": None, "link_mbps": None}
        self.assertEqual(run_episode(s3, Detector(s3.ctx).step, baseline_s=40, lost_keys=["xbox"], fault_s=4), [])

    def test_5b_silent_console_not_yet_seen_awake_is_not_a_fault(self):
        """At start-up the console's state is unknown (it may be in standby): its silence opens no episode."""
        self.s.state.xbox = {"ip": "10.0.0.23", "state": "unknown", "source": None, "link_mbps": None}
        eps = run_episode(self.s, self.det.step, baseline_s=40, lost_keys=["xbox"], fault_s=6)
        self.assertEqual(eps, [])
        self.s.state.xbox = {"ip": "10.0.0.23", "state": "asleep", "source": "icmp", "link_mbps": None}
        eps = run_episode(self.s, self.det.step, baseline_s=40, lost_keys=["xbox"], fault_s=6)
        self.assertEqual(eps, [])

    def test_6_xb7_cpu_info(self):
        ep = self.episode(slow_keys=["gw4"], slow_ms=40, fault_s=6)
        self.assertEqual(ep.cls, "xb7_cpu")
        self.assertBand(ep, "medium")
        self.assertIn("xb7_cpu", cm.INFO_CLASSES)
        self.assertTrue(ep.xb7_cpu_only)
        self.assertEvidence(ep, "gateway latency rose", "without loss", "everything beyond the gateway stayed clean",
                            "XB7 CPU busy, not a path fault")
        self.assertEqual(ep.alt["class"], "xbox_lan")

    def test_7_xb7_gateway(self):
        keys = [k for k in ICMP_KEYS if k != "xbox"]
        ep = self.episode(lost_keys=keys, fault_s=6)
        self.assertEqual(ep.cls, "xb7_gateway")
        self.assertBand(ep, "medium")
        self.assertEqual(ep.confidence, 0.6)
        self.assertEqual(ep.locus["shallowest"], "gw4")
        self.assertEvidence(ep, "gateway lost packets: gateway 10.0.0.1", "everything beyond it lost too", "loss locus: gateway")
        self.assertEqual(ep.alt["class"], "docsis_access")  # the best near miss: everything but the gateway condition
        self.assertIn("gateway not clean", ep.alt["why_rejected"])
        s2 = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s2.close)

        def per(t):
            if int(t) == int(s2.fault_t0 + 2):
                s2.state.raise_note("docsis_reboot", t=t, severity=4, note="XB7 uptime decreased", uptime_s=12)
        eps = run_episode(s2, Detector(s2.ctx).step, baseline_s=40, lost_keys=keys, fault_s=6, per_second=per)
        self.assertEqual((eps[0].cls, eps[0].confidence), ("xb7_gateway", 0.9))
        self.assertBand(eps[0], "high")
        self.assertTrue(any("corroborated by docsis_reboot" in line for line in eps[0].evidence))

    def test_8_docsis_access_t3_signature(self):
        s = self.s
        s.state.set_latest("ntp", ntp_row("upstream", 0.81))
        ep = self.episode(lost_keys=BEYOND_GW, fault_s=2.5, quiet_s=25,
                          per_second=self.note_at(12, "docsis_t3", severity=3, note="XB7 log: 2026-10-11 21:14:03 T3 time-out"))
        self.assertEqual((ep.cls, ep.subclass), ("docsis_access", "t3_signature"))
        self.assertEqual(ep.confidence, 0.95)
        self.assertBand(ep, "high")
        self.assertEqual(ep.direction, "upstream")
        self.assertEqual(ep.locus["shallowest"], "isp_hop4")
        self.assertGreaterEqual(ep.locus["cond"]["isp_hop4|inet4_cf"], 0.9)
        self.assertEqual(ep.locus["cond"]["gw4|inet4_cf"], 0.0)
        self.assertTrue(ep.comcast_relevant)
        self.assertEvidence(ep, "gateway 10.0.0.1: 0% loss", "Comcast hop 10.60.12.1:", "loss locus: Comcast hop 10.60.12.1",
                            "gateway 0%", "NTP direction: upstream (share 0.81)", "XB7 log: T3 time-out at", "(+12 s)",
                            "IPv4 and IPv6 targets agree", "T3 signature")
        # nearest miss: the upload-direction rule, rejected for the loss and the modem's DOCSIS events
        self.assertEqual(ep.alt["class"], "upstream_delay")
        self.assertIn("DOCSIS events", ep.alt["why_rejected"])
        self.assertEqual([d["type"] for d in ep.docsis["events"]], ["docsis_t3"])

    def test_8_docsis_access_plain_and_rf_plant(self):
        ep = self.episode(lost_keys=BEYOND_GW, fault_s=8)
        self.assertEqual((ep.cls, ep.subclass), ("docsis_access", None))  # 8 s: too long for the T3 signature
        self.assertEqual(ep.confidence, 0.75)  # 0.6 + 0.15 v4/v6 agree
        self.assertBand(ep, "high")
        s2 = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s2.close)

        def per(t):
            if int(t) == int(s2.fault_t0 + 20):
                s2.state.raise_note("docsis_uncorr", t=t, severity=3, note="uncorrectable codewords +812 since last poll",
                                    uncorr_delta=812, per_channel={"18": 812, "19": 3})
        eps = run_episode(s2, Detector(s2.ctx).step, baseline_s=40, lost_keys=BEYOND_GW, fault_s=8, quiet_s=30, per_second=per)
        ep2 = eps[0]
        self.assertEqual((ep2.cls, ep2.subclass), ("docsis_access", "rf_plant"))
        self.assertEqual(ep2.confidence, 0.9)  # + docsis correlation
        self.assertTrue(any("uncorrectables +812 on DS ch 18" in line for line in ep2.evidence), ep2.evidence)
        self.assertTrue(any("uncorrectable burst at" in line for line in ep2.evidence), ep2.evidence)

    def test_8_docsis_access_congestion_in_the_evening(self):
        s = Session(t0=local_at(20), cfg=make_cfg(warmup_s=30))
        self.addCleanup(s.close)
        # a long baseline: the rolling 10 min p50 must not absorb the 130 s rise (SPEC §7.1 keeps it rolling)
        eps = run_episode(s, Detector(s.ctx).step, baseline_s=200, slow_keys=BEYOND_GW, slow_ms=60, fault_s=130, quiet_s=15)
        self.assertEqual(len(eps), 1)
        ep = eps[0]
        self.assertEqual((ep.cls, ep.subclass), ("docsis_access", "congestion"))
        self.assertTrue(any("congestion signature" in line for line in ep.evidence), ep.evidence)
        self.assertEqual(ep.alt["class"], "upload_saturation")
        self.assertIn("no upload evidence", ep.alt["why_rejected"])
        # the same rise at 10:00 is not congestion
        s2 = Session(t0=local_at(10), cfg=make_cfg(warmup_s=30))
        self.addCleanup(s2.close)
        eps2 = run_episode(s2, Detector(s2.ctx).step, baseline_s=200, slow_keys=BEYOND_GW, slow_ms=60, fault_s=130, quiet_s=15)
        self.assertEqual((eps2[0].cls, eps2[0].subclass), ("docsis_access", None))

    def test_9_comcast_network(self):
        ep = self.episode(lost_keys=["mid_hop4"] + list(INTERNET), fault_s=4)
        self.assertEqual(ep.cls, "comcast_network")
        self.assertBand(ep, "medium")
        self.assertEqual(ep.locus["shallowest"], "mid_hop4")
        self.assertEvidence(ep, "mid-path hop affected while gateway and Comcast hop stayed clean", "loss locus: mid-path hop 11.0.5.1")
        self.assertEqual(ep.alt["class"], "docsis_access")
        self.assertIn("Comcast hop not affected", ep.alt["why_rejected"])

    def test_10_upload_saturation_by_other_device(self):
        self.s.state.set_latest("igd", {"tx_mbps": 22.0, "rx_mbps": 1.0, "trusted": True, "uptime_s": 1000, "t": T0})
        ep = self.episode(slow_keys=BEYOND_GW, slow_ms=80, fault_s=12)
        self.assertEqual((ep.cls, ep.subclass), ("upload_saturation", "by_other_device"))
        self.assertEqual(ep.confidence, 0.85)
        self.assertBand(ep, "high")
        self.assertEvidence(ep, "uniform latency inflation on every target past the gateway", "WAN tx 22.0 Mb/s of 25 (88%, trusted IGD counters)")
        self.assertEqual(ep.wan, {"tx_mbps_max": 22.0, "rx_mbps_max": 1.0, "trusted": True})
        self.assertEqual(ep.alt["class"], "docsis_access")
        self.assertIn("upload_saturation", ep.alt["why_rejected"])

    def test_10_upload_saturation_by_this_host_and_inferred(self):
        self.s.state.set_latest("iface", {"tx_mbps": 20.0, "rx_mbps": 0.5, "t": T0})
        ep = self.episode(slow_keys=BEYOND_GW, slow_ms=80, fault_s=12)
        self.assertEqual((ep.cls, ep.subclass, ep.confidence), ("upload_saturation", "by_this_host", 0.85))
        self.assertEvidence(ep, "host tx 20.0 Mb/s of 25 (80%)")
        s2 = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s2.close)
        s2.state.set_latest("ntp", ntp_row("upstream", 0.85, d_offset=25.0, d_rtt=60.0))
        eps = run_episode(s2, Detector(s2.ctx).step, baseline_s=40, slow_keys=BEYOND_GW, slow_ms=80, fault_s=12)
        ep2 = eps[0]
        # no measurable household upload: a home upload and Comcast's upstream cannot be told apart
        self.assertEqual((ep2.cls, ep2.subclass), ("upstream_delay", None))
        self.assertBand(ep2, "medium")
        self.assertEqual(ep2.direction, "upstream")
        self.assertEvidence(ep2, "upload direction", "household upload is not measurable")
        # untrusted WAN counters are not upload evidence
        s3 = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s3.close)
        s3.state.set_latest("igd", {"tx_mbps": 22.0, "rx_mbps": 1.0, "trusted": False, "uptime_s": 1000, "t": T0})
        eps3 = run_episode(s3, Detector(s3.ctx).step, baseline_s=40, slow_keys=BEYOND_GW, slow_ms=80, fault_s=12)
        self.assertEqual(eps3[0].cls, "docsis_access")
        self.assertTrue(any("WAN tx 22.0 Mb/s of 25 (untrusted)" in line for line in eps3[0].evidence))

    def test_11_ipv6_only_and_ipv4_only(self):
        ep = self.episode(lost_keys=["inet6_cf", "inet6_g"], fault_s=4,
                          per_second=self.note_at(-20, "v6_gw_stale", severity=2, note="neighbour STALE"))
        self.assertEqual((ep.cls, ep.confidence), ("ipv6_only", 0.7))
        self.assertBand(ep, "medium")
        self.assertEvidence(ep, "only IPv6 targets affected", "IPv4 twins clean", "IPv6 health event v6_gw_stale")
        self.assertEqual(ep.alt["class"], "comcast_network")
        s2 = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s2.close)
        eps = run_episode(s2, Detector(s2.ctx).step, baseline_s=40, lost_keys=["inet4_cf", "inet4_g"], fault_s=4)
        ep2 = eps[0]
        self.assertEqual((ep2.cls, ep2.confidence), ("ipv4_only", 0.7))
        self.assertBand(ep2, "medium")
        self.assertTrue(any("only IPv4 targets affected" in line for line in ep2.evidence))

    def test_13_internet(self):
        ep = self.episode(lost_keys=INTERNET, fault_s=4)
        self.assertEqual(ep.cls, "internet")
        self.assertEqual(ep.confidence, 0.5)
        self.assertBand(ep, "medium")
        self.assertEqual(ep.locus["shallowest"], "internet")
        self.assertEvidence(ep, "only the internet targets were affected", "hops clean", "loss locus: internet only")
        self.assertEqual(ep.alt["class"], "comcast_network")
        self.assertIn("mid-path hop not affected", ep.alt["why_rejected"])

    def test_14_single_destination(self):
        ep = self.episode(lost_keys=["inet4_g"], fault_s=4)
        self.assertEqual(ep.cls, "single_destination")
        self.assertEqual(ep.confidence, 0.2)  # 0.4 − 0.2 single signal
        self.assertBand(ep, "low")
        self.assertEvidence(ep, "exactly one destination affected: 8.8.8.8", "likely not your problem")
        self.assertEqual(ep.alt["class"], "ipv4_only")
        self.assertIn("single destination?", ep.alt["why_rejected"])

    def test_15_hop_rate_limit_info(self):
        s = self.s
        f0 = T0 + 40
        feed(s, self.det.step, T0, f0 + 20, lost=lambda k, ts: k == "isp_hop4" and f0 <= ts < f0 + 6)
        self.assertEqual(s.episodes(), [])  # an uncorroborated hop symptom never opens an episode
        ep = Episode(id="ep-manual", t0=f0, t1=f0 + 6, dur_s=6.0, targets=[s.ids["isp_hop4"]])
        cm.classify(ep, s.ctx, now=f0 + 20)
        self.assertEqual(ep.cls, "hop_rate_limit")
        self.assertEqual(ep.confidence, 0.9)
        self.assertBand(ep, "high")
        self.assertIn("hop_rate_limit", cm.INFO_CLASSES)
        self.assertTrue(any("rate-limiting its own replies" in line for line in ep.evidence), ep.evidence)
        self.assertEqual(ep.alt["class"], "docsis_access")

    def test_16_dns(self):
        s = self.s

        def per(t):
            rel = int(t - T0)
            if rel % 3 == 0:
                s.emit("dns_gw", t + 0.1, lost=s.fault_t0 <= t < s.fault_t1)

        ep = self.episode(fault_s=12, per_second=per)
        self.assertEqual(ep.cls, "dns")
        self.assertEqual(ep.confidence, 0.5)
        self.assertBand(ep, "medium")
        self.assertEvidence(ep, "only DNS probes were affected: dns_gw", "dns_gw: 100% loss, no replies")
        self.assertEqual(ep.targets, [s.ids["dns_gw"]])

    def test_17_cdn(self):
        s = self.s
        s.add_target("cdn_cf", "cdn", "104.16.0.1", kind="cdn", rate_hz=1 / 60.0, p50_ms=300.0)
        from laglens.state import KIND_CDN_TTFB

        def per(t):
            rel = int(t - T0)
            if rel % 5 == 0:
                s.emit("cdn_cf", t + 0.3, rtt_ms=1500.0 if s.fault_t0 <= t < s.fault_t1 else 300.0, kind=KIND_CDN_TTFB)

        ep = self.episode(fault_s=12, per_second=per)
        self.assertEqual(ep.cls, "cdn")
        self.assertBand(ep, "low")  # 0.5 − 0.2
        self.assertEvidence(ep, "only CDN fetches were slow: cdn_cf")

    def test_18_unknown(self):
        ep = self.episode(lost_keys=["gw4", "inet4_cf"], fault_s=4)
        self.assertEqual(ep.cls, "unknown")
        self.assertEqual(ep.confidence, 0.3)
        self.assertBand(ep, "low")
        self.assertEvidence(ep, "no rule matched the pattern")
        self.assertEqual(ep.alt["class"], "ipv4_only")
        self.assertIn("single destination?", ep.alt["why_rejected"])


class EpisodeFieldTests(ClassifyBase):
    def test_fields_filled_on_every_episode(self):
        s = self.s
        s.state.set_activity("bf6")
        s.state.xbox = {"ip": "10.0.0.23", "state": "awake", "source": "udp5050", "link_mbps": None}
        ep = self.episode(lost_keys=BEYOND_GW, fault_s=3)
        d = ep.to_dict()
        for key in ("class", "subclass", "confidence", "evidence", "alt", "locus", "direction", "xbox_state", "activity",
                    "host_tags", "comcast_relevant", "onset_order", "size_loss_ratio", "xb7_cpu_only", "wan", "marks"):
            self.assertIn(key, d)
        self.assertEqual((d["activity"], d["xbox_state"], d["direction"]), ("bf6", "awake", "n/a"))
        self.assertEqual(d["onset_order"][0], "isp_hop4")
        self.assertEqual(set(d["onset_order"]), set(BEYOND_GW))
        self.assertEqual(d["size_loss_ratio"], {})
        self.assertFalse(d["xb7_cpu_only"])
        self.assertEqual(set(d["locus"]), {"shallowest", "cond", "slots", "excluded"})
        self.assertEqual(s.state.matrix["locus_counts"], {"isp_hop4": 1})
        self.assertGreaterEqual(s.state.matrix["pairs"]["isp_hop4|inet4_cf"], 0.9)
        brief = ep.to_dict(brief=True)
        self.assertNotIn("sweep", brief)
        self.assertNotIn("docsis", brief)


if __name__ == "__main__":
    unittest.main()


class XboxAddressSwitchTests(unittest.TestCase):
    def test_previous_address_silence_does_not_open_an_xbox_episode(self):
        """Lost samples sent before the Xbox address switch belong to the old address, not this console."""
        s = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s.close)
        det = Detector(s.ctx)
        switch_at = s.clock.t + 40 + 4 + 0.001  # right after the (old-address) silence ends
        s.state.xbox = dict(s.state.xbox, since=switch_at)
        self.assertEqual(run_episode(s, det.step, baseline_s=40, lost_keys=["xbox"], fault_s=4), [])

    def test_the_same_silence_after_the_switch_is_still_caught(self):
        s = Session(cfg=make_cfg(warmup_s=30))
        self.addCleanup(s.close)
        det = Detector(s.ctx)
        s.state.xbox = dict(s.state.xbox, since=s.clock.t + 1)
        eps = run_episode(s, det.step, baseline_s=40, lost_keys=["xbox"], fault_s=4)
        self.assertEqual([e.cls for e in eps], ["xbox_lan"])



class UpstreamAttributionTests(unittest.TestCase):
    """Upload-direction delay past the modem, with and without a verified household-upload witness."""

    def run_one(self, igd=None, keys=None):
        s = Session(cfg=make_cfg(warmup_s=30), keys=keys)
        self.addCleanup(s.close)
        s.state.set_latest("ntp", ntp_row("upstream", 0.9, d_offset=30.0, d_rtt=70.0))
        if igd is not None:
            s.state.set_latest("igd", igd)
        slow = [k for k in BEYOND_GW if keys is None or k in keys] + (["isp_hop6"] if keys and "isp_hop6" in keys else [])
        eps = run_episode(s, Detector(s.ctx).step, baseline_s=40, slow_keys=slow, slow_ms=90, fault_s=10)
        self.assertEqual(len(eps), 1, [e.to_dict(brief=True) for e in eps])
        return eps[0]

    def test_unverified_witness_names_both_causes(self):
        ep = self.run_one()
        self.assertEqual(ep.cls, "upstream_delay")
        self.assertTrue(ep.comcast_relevant)

    def test_verified_low_household_upload_points_at_comcast_upstream(self):
        ep = self.run_one(igd={"tx_mbps": 0.4, "rx_mbps": None, "trusted": True, "uptime_s": 1000, "t": T0})
        self.assertEqual((ep.cls, ep.subclass), ("docsis_access", "upstream"))
        self.assertTrue(any("household upload was low (0.4 of 25 Mb/s" in line for line in ep.evidence), ep.evidence)

    def test_verified_high_household_upload_is_saturation(self):
        ep = self.run_one(igd={"tx_mbps": 22.0, "rx_mbps": None, "trusted": True, "uptime_s": 1000, "t": T0})
        self.assertEqual((ep.cls, ep.subclass), ("upload_saturation", "by_other_device"))

    def test_ipv6_comcast_hop_stands_in_when_the_ipv4_hop_is_not_probed(self):
        from helpers_detection import LADDER as L
        keys = [row[0] for row in L if row[0] != "isp_hop4"] + ["isp_hop6"]
        s = Session(cfg=make_cfg(warmup_s=30), keys=[k for k in keys if k != "isp_hop6"])
        self.addCleanup(s.close)
        hop6 = s.add_target("isp_hop6", "isp_hop", "2001:558:aaaa:bbbb::2", family=6, rate_hz=2.0, p50_ms=12.0)
        self.assertIsNotNone(hop6)
        s.state.set_latest("ntp", ntp_row("upstream", 0.9, d_offset=30.0, d_rtt=70.0))
        slow = ["isp_hop6", "mid_hop4"] + list(INTERNET)
        eps = run_episode(s, Detector(s.ctx).step, baseline_s=40, slow_keys=slow, slow_ms=90, fault_s=10)
        self.assertEqual([e.cls for e in eps], ["upstream_delay"])
        self.assertTrue(any("Comcast hop" in line or "isp_hop6" in line for line in eps[0].evidence), eps[0].evidence)
