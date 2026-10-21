"""Session verdict, Tell-Comcast block and the dashboard headline (SPEC_FULL §7.7, §8.3).

* :func:`compute_verdict` tallies Σ(duration × confidence) per class over the
  episodes of at least 1.5 s (informational classes ``xb7_cpu`` and
  ``hop_rate_limit`` and ``loadtest`` artefacts excluded), honours
  ``comcast_relevant`` for the Comcast-side tally, picks the headline class
  (≥ 60 % share, else *mixed*), renders the three plain-English sentences
  with hedging by confidence, appends the persistent findings, the marks
  rule and the "what to try next" table, stores the result in
  ``state.verdict`` (the §10.2 ``verdict`` shape) and returns it.
* :func:`comcast_text` renders the Tell-Comcast block from the
  ``comcast_relevant`` episodes and writes it atomically to
  ``comcast_evidence.txt``.
* :func:`headline` answers "Is it my network?" for the top bar.
"""
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from laglens.engine.classify import COMCAST_HOP_KEYS, confidence_band, label_of
from laglens.state import Episode, State

log = logging.getLogger("laglens.verdict")

MIN_EPISODE_S = 1.5
INFO_CLASSES = frozenset({"xb7_cpu", "hop_rate_limit"})
EXCLUDED_FROM_TALLY = INFO_CLASSES | frozenset({"loadtest"})
COMCAST_CLASSES = frozenset({"docsis_access", "comcast_network", "xb7_gateway"})
HOME_CLASSES = frozenset({"probe_host", "probe_wifi", "probe_link", "xbox_lan", "upload_saturation",
                          "plex_server", "plex_player", "home_lan"})
INTERNET_CLASSES = frozenset({"internet", "single_destination", "cdn", "dns"})
HEADLINE_SHARE = 0.6
CLASS_LABELS: Dict[str, str] = {
    "probe_host": "this computer (probe host)",
    "probe_wifi": "this computer's Wi-Fi",
    "loadtest": "load test",
    "probe_link": "this computer's network link",
    "xbox_lan": "the Xbox LAN cable/port",
    "plex_server": "the Plex server",
    "plex_player": "the Plex player",
    "home_lan": "the home network between the Plex server and the player",
    "xb7_cpu": "XB7 CPU (informational)",
    "xb7_gateway": "the XB7 gateway",
    "docsis_access": "the cable line / Comcast access network",
    "comcast_network": "Comcast's network",
    "upload_saturation": "upload saturation",
    "upstream_delay": "upload delay past the modem (a home upload or Comcast's upstream)",
    "ipv6_only": "IPv6 only",
    "ipv4_only": "IPv4 only",
    "internet": "the wider internet",
    "single_destination": "a single destination",
    "hop_rate_limit": "hop rate limiting (informational)",
    "dns": "DNS",
    "cdn": "CDN fetches",
    "unknown": "unclear",
    "mixed": "mixed",
}
#: SPEC §7.7 "what to try next": ≤ 3 experiments per top class with confirm/refute conditions.
NEXT_STEPS: Dict[str, List[dict]] = {
    "docsis_access": [
        {"try": "Call Comcast with the attached evidence; ask for upstream SNR/power at the CMTS and node utilization 19:00–23:00",
         "confirm_if": "they find a plant issue, or the episodes stop after their fix",
         "refute_if": "CMTS-side levels are nominal and the episodes continue unchanged"},
        {"try": "Check every coax connector and splitter indoors; remove unused splitters, hand-tighten the F-connectors",
         "confirm_if": "US power drops and the T3/uncorrectable counts stop growing",
         "refute_if": "levels and episode rate stay the same"},
        {"try": "Run one more 24 h session and compare the episode rate by hour of day",
         "confirm_if": "episodes concentrate 19:00–23:00 (node congestion) or follow modem log lines",
         "refute_if": "episodes are uniform in time with no DOCSIS correlation"},
    ],
    "comcast_network": [
        {"try": "Call Comcast with the Tell-Comcast block; point at the mid-path hop that loses packets while the first hop is clean",
         "confirm_if": "they acknowledge a routing/core issue or the loss moves/clears",
         "refute_if": "the mid-path hop is merely rate-limiting (deeper targets were actually clean)"},
        {"try": "Run a session with the path rediscovered every 30 min and watch for route changes",
         "confirm_if": "episodes coincide with route changes",
         "refute_if": "the path is stable through the episodes"},
    ],
    "xb7_gateway": [
        {"try": "Power-cycle the XB7 once and run 24 h; note the DOCSIS/IGD uptime in the panel",
         "confirm_if": "uptime resets line up with the outages (spontaneous reboots)",
         "refute_if": "uptime is continuous through the outages"},
        {"try": "Ask Comcast to swap the XB7 or put it in bridge mode behind your own router",
         "confirm_if": "the gateway-lost outages stop",
         "refute_if": "the same pattern continues with the new gateway"},
    ],
    "xbox_lan": [
        {"try": "Swap the Xbox cable and XB7 port; run `start.sh --porttest` on the old cable",
         "confirm_if": "Xbox loss stops with the new cable/port",
         "refute_if": "the Xbox still drops while the XB7 and internet stay clean"},
        {"try": "Check the Xbox's negotiated link speed in its network settings",
         "confirm_if": "it shows 100 Mb/s or half duplex",
         "refute_if": "it shows 1 Gb/s full duplex"},
    ],
    "plex_server": [
        {"try": "Open the Plex dashboard while it stutters: a Transcode under 1.0x speed, high CPU or a background task "
                "(library scan, thumbnails, intro/credit detection) means the server PC cannot keep up",
         "confirm_if": "the stutters line up with transcoding, CPU peaks or a task; Direct Play or scheduling the tasks overnight stops them",
         "refute_if": "Direct Play, low CPU and no tasks, yet the server still drops off the network"},
        {"try": "On the server PC: turn off sleep and the network adapter's power saving / Energy-Efficient Ethernet, "
                "and swap its Ethernet cable or switch port",
         "confirm_if": "the drop-outs stop",
         "refute_if": "they continue with a new cable and power saving off"},
        {"try": "Check the drive the media is on: an external or sleeping disk takes seconds to spin up",
         "confirm_if": "the stutters line up with the disk waking (first seconds of a title, after pauses)",
         "refute_if": "they happen mid-playback with the disk awake"},
    ],
    "plex_player": [
        {"try": "Swap the player's Ethernet cable and router/switch port; check it negotiates 1 Gb/s",
         "confirm_if": "its drop-outs stop with the new cable/port",
         "refute_if": "the player still drops while the server and router stay clean"},
        {"try": "Play the same title on another player",
         "confirm_if": "the other player plays it smoothly",
         "refute_if": "the other player stutters at the same moments"},
    ],
    "home_lan": [
        {"try": "Plug the Plex server and the player straight into the router (skip any extra switch) and replay",
         "confirm_if": "the stutters stop: the switch or a shared cable is at fault",
         "refute_if": "both still drop together while plugged into the router"},
    ],
    "probe_link": [
        {"try": "Move the probe host to a different XB7 port / cable (or wired instead of Wi-Fi)",
         "confirm_if": "link flaps and interface errors stop",
         "refute_if": "the same flaps appear on the new port"},
    ],
    "probe_wifi": [
        {"try": "Run the probe on a wired connection, or move it closer to the access point",
         "confirm_if": "episodes stop when wired",
         "refute_if": "episodes continue when wired"},
    ],
    "probe_host": [
        {"try": "Close CPU-heavy apps on the probe host (or stop Game Mode) and rerun",
         "confirm_if": "host_stall events disappear and so do the episodes",
         "refute_if": "episodes continue without host stalls"},
    ],
    "upload_saturation": [
        {"try": "Run 2 h idle overnight; if clean, enable QoS/SQM or schedule backups",
         "confirm_if": "the idle run is clean and the latency rise returns with uploads",
         "refute_if": "the idle run shows the same latency inflation"},
        {"try": "Find the uploader: check the IGD WAN tx line vs this host's tx line during an episode",
         "confirm_if": "WAN tx is high while host tx is low (another device)",
         "refute_if": "WAN tx stays below 70% of the upstream rate"},
    ],
    "upstream_delay": [
        {"try": "Look for an upload at home when it happens: Xbox clip/screenshot auto-upload (Settings > Preferences > "
                "Capture & share), cloud photo or backup apps, cameras; pause it and play again",
         "confirm_if": "the episodes stop while that upload is off",
         "refute_if": "the episodes continue with nothing uploading at home"},
        {"try": "Run the load test once while nobody is playing (bash start.sh --loadtest)",
         "confirm_if": "grade D or F: any upload at home can add this much delay; schedule uploads or enable QoS",
         "refute_if": "grade A or B: home uploads cannot add this much delay; take the report to Comcast"},
        {"try": "If neither: call Comcast with the report; ask about upstream noise and utilization on your node",
         "confirm_if": "they find an upstream issue, or the episodes stop after their fix",
         "refute_if": "their upstream checks are clean and the episodes continue"},
    ],
    "ipv6_only": [
        {"try": "Run 2 h with IPv6 disabled on the XB7",
         "confirm_if": "the lag presses stop while IPv4 keeps working",
         "refute_if": "episodes continue on IPv4 alone"},
    ],
    "ipv4_only": [
        {"try": "Compare IPv4 and IPv6 routes with a rediscovery; note where the v4 path diverges",
         "confirm_if": "the v4-only hop keeps losing packets while v6 is clean",
         "refute_if": "both families start failing together"},
    ],
    "internet": [
        {"try": "Keep running; compare against a second session on another day",
         "confirm_if": "loss stays confined to the final internet targets with clean hops",
         "refute_if": "the Comcast hop starts showing the same loss"},
    ],
    "single_destination": [
        {"try": "Nothing on your side; keep monitoring and watch whether other destinations join",
         "confirm_if": "only one destination ever misbehaves",
         "refute_if": "several destinations start failing at the same moments"},
    ],
    "dns": [
        {"try": "Switch the resolver (e.g. 1.1.1.1 instead of the gateway) and rerun",
         "confirm_if": "DNS symptoms stop with the other resolver",
         "refute_if": "both resolvers fail at the same moments"},
    ],
    "cdn": [
        {"try": "Keep monitoring; CDN slowness alone rarely explains game lag",
         "confirm_if": "CDN TTFB spikes line up with your marks",
         "refute_if": "marks happen without CDN symptoms"},
    ],
    "mixed": [
        {"try": "Keep running another 12–24 h so one class dominates",
         "confirm_if": "one class reaches 60% of the tally",
         "refute_if": "the split persists (two independent problems)"},
    ],
    "unknown": [
        {"try": "Keep running; press 'Lag happened' every time you feel it so marks can be lined up",
         "confirm_if": "episodes start matching your presses",
         "refute_if": "presses keep showing nothing on any target"},
    ],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def fmt_duration(seconds: float) -> str:
    """``6 h 12 m`` / ``14 m`` / ``42 s``."""
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return "%d s" % int(round(seconds))
    minutes = int(seconds // 60)
    if minutes < 60:
        return "%d m" % minutes
    return "%d h %d m" % (minutes // 60, minutes % 60)


def fmt_seconds(seconds: float) -> str:
    if seconds < 60:
        return ("%.1f s" % seconds) if seconds < 10 else ("%d s" % int(round(seconds)))
    return fmt_duration(seconds)


def local_hms(t: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(t))


def local_date(t: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t))


def _hedge(band: str) -> str:
    return {"high": "points at", "medium": "suggests", "low": "may point at"}.get(band, "suggests")


def counted_episodes(state: State, now: float) -> List[Episode]:
    """Registered episodes ≥ 1.5 s that count in the verdict (open ones use ``now``)."""
    with state.lock:
        episodes = list(state.episodes)
    out: List[Episode] = []
    for ep in episodes:
        if not ep.id:
            continue
        t1 = ep.t1 if ep.t1 is not None else now
        if t1 - ep.t0 < MIN_EPISODE_S:
            continue
        out.append(ep)
    return out


def tally(episodes: List[Episode], now: float) -> Tuple[Dict[str, dict], Dict[str, dict]]:
    """Per-class ``{"weight","episodes","seconds","conf_sum"}`` for all episodes and the Comcast-side subset."""
    full: Dict[str, dict] = {}
    comcast: Dict[str, dict] = {}
    for ep in episodes:
        if ep.cls in EXCLUDED_FROM_TALLY:
            continue
        dur = (ep.t1 if ep.t1 is not None else now) - ep.t0
        w = dur * max(0.0, float(ep.confidence))
        for dst, ok in ((full, True), (comcast, bool(ep.comcast_relevant))):
            if not ok:
                continue
            row = dst.setdefault(ep.cls, {"weight": 0.0, "episodes": 0, "seconds": 0.0, "conf_sum": 0.0})
            row["weight"] += w
            row["episodes"] += 1
            row["seconds"] += dur
            row["conf_sum"] += float(ep.confidence)
    return full, comcast


def top_list(t: Dict[str, dict]) -> List[dict]:
    total = sum(r["weight"] for r in t.values()) or 0.0
    rows = []
    for cls, r in sorted(t.items(), key=lambda kv: -kv[1]["weight"]):
        rows.append({"class": cls, "share": round(r["weight"] / total, 2) if total > 0 else 0.0,
                     "episodes": r["episodes"], "seconds": round(r["seconds"], 1)})
    return rows


def headline_class(top: List[dict]) -> str:
    if not top:
        return "none"
    if top[0]["share"] >= HEADLINE_SHARE:
        return top[0]["class"]
    return "mixed"


# ---------------------------------------------------------------------------
# Text
# ---------------------------------------------------------------------------
def _loss_dominant(episodes: List[Episode], state: State) -> bool:
    with state.lock:
        by_id = {e.id: e for e in state.events}
    loss = other = 0
    for ep in episodes:
        for eid in ep.events:
            e = by_id.get(eid)
            if e is None:
                continue
            if e.type in ("loss_burst", "tcp_timeout", "dns_fail"):
                loss += 1
            elif e.type in ("latency_spike", "jitter", "late_burst", "tcp_slow", "dns_slow"):
                other += 1
    return loss >= other


def sentence_what(state: State, episodes: List[Episode], now: float) -> str:
    elapsed = fmt_duration(now - state.t0)
    counted = [e for e in episodes if e.cls not in EXCLUDED_FROM_TALLY]
    n = len(counted)
    if n == 0:
        blips = int(getattr(state, "blips", 0) or 0)
        info = [e for e in episodes if e.cls in INFO_CLASSES]
        parts = []
        if blips:
            parts.append("%d sub-1.5 s blip%s" % (blips, "" if blips == 1 else "s"))
        if info:
            parts.append("%d informational episode%s: %s, not a path fault" % (
                len(info), "" if len(info) == 1 else "s", ", ".join(sorted({CLASS_LABELS.get(e.cls, e.cls).replace(" (informational)", "") for e in info}))))
        tail = " (%s)" % "; ".join(parts) if parts else ""
        return "Over %s your connection showed no trouble episodes longer than 1.5 s%s." % (elapsed, tail)
    total = sum(((e.t1 if e.t1 is not None else now) - e.t0) for e in counted)
    verb = "dropped packets" if _loss_dominant(counted, state) else "slowed down"
    longest = max(((e.t1 if e.t1 is not None else now) - e.t0) for e in counted)
    kind = "short bursts" if longest < 30 else "episodes"
    if n == 1:
        kind = "short burst" if longest < 30 else "episode"
    return "Over %s your connection %s in %d %s totalling %s." % (elapsed, verb, n, kind, fmt_seconds(total))


# "xb7_gateway" when the gateway is a router of the user's own (the XB7 in bridge mode behind it)
ROUTER_GATEWAY_STEPS = [
    {"try": "Power-cycle your router once and run 24 h; check its uptime or log for reboots",
     "confirm_if": "router reboots line up with the outages",
     "refute_if": "the router stays up through the outages"},
    {"try": "Update the router's firmware, or swap in another router for a session",
     "confirm_if": "the gateway-lost outages stop",
     "refute_if": "the same pattern continues with the other router"},
]


def next_steps(cls: str, state: Optional[State] = None) -> List[dict]:
    """The experiments for ``cls``, with the gateway named for this network."""
    if cls == "none":
        return []
    if cls == "xb7_gateway" and state is not None and not state.gateway_is_modem():
        return [dict(s) for s in ROUTER_GATEWAY_STEPS]
    steps = NEXT_STEPS.get(cls) or NEXT_STEPS["unknown"]
    if state is None:
        return [dict(s) for s in steps]
    return [{k: state.gw_text(v) if isinstance(v, str) else v for k, v in s.items()} for s in steps]

def sentence_where(cls: str, band: str, episodes: List[Episode], top: List[dict], now: float,
                   loss_dominant: bool = True) -> str:
    hedge = _hedge(band)
    k = sum(1 for e in episodes if e.cls == cls)
    n = len([e for e in episodes if e.cls not in EXCLUDED_FROM_TALLY])
    of = "In %d of them" % k if k < n else ("In all %d" % n if n > 1 else "In it")
    if cls == "none":
        return "There is nothing to point at yet."
    if cls == "mixed":
        a, b = top[0], top[1] if len(top) > 1 else {"class": "unknown", "share": 0.0}
        return ("The evidence is split between %s (%d%%) and %s (%d%%), so no single place %s clearly yet."
                % (CLASS_LABELS.get(a["class"], a["class"]), int(round(a["share"] * 100)),
                   CLASS_LABELS.get(b["class"], b["class"]), int(round(b["share"] * 100)), "stands out"))
    docsis_lines = 0
    t3 = 0
    for e in episodes:
        if e.cls != cls or not isinstance(e.docsis, dict):
            continue
        evs = e.docsis.get("events") or []
        docsis_lines += len(evs)
        t3 += sum(1 for d in evs if isinstance(d, dict) and d.get("type") == "docsis_t3")
    if cls == "docsis_access":
        extra = ", and the modem logged %d T3 timeout%s" % (t3, "" if t3 == 1 else "s") if t3 else (
            ", and the modem log shows %d related line%s" % (docsis_lines, "" if docsis_lines == 1 else "s") if docsis_lines else "")
        what = "went silent" if loss_dominant else "slowed down"
        return ("%s your XB7 kept answering but everything past it %s at the same moment%s, which %s the cable line "
                "or Comcast's equipment rather than anything in your home." % (of, what, extra, hedge))
    if cls == "comcast_network":
        return ("%s your XB7 and the first Comcast hop answered normally while the hop beyond them and the internet targets "
                "suffered together, which %s Comcast's network past your neighbourhood." % (of, hedge))
    if cls == "xb7_gateway":
        return ("%s your XB7 itself stopped answering and everything past it went with it, which %s the gateway "
                "(a reset or reboot) rather than the line." % (of, hedge))
    if cls == "xbox_lan":
        return ("%s only the Xbox stopped answering while the XB7 and the internet were fine, which %s the Xbox's cable, "
                "port or the console itself." % (of, hedge))
    if cls == "plex_server":
        return ("%s only the Plex server stopped answering or slowed down while the router and the player were fine, which "
                "%s the server PC itself (busy, asleep or its network connection)." % (of, hedge))
    if cls == "plex_player":
        return ("%s only the Plex player stopped answering while the router and the server were fine, which %s the player's "
                "cable, port or the device itself." % (of, hedge))
    if cls == "home_lan":
        return ("%s the Plex server and the player dropped together while the router answered normally, which %s the "
                "cabling or switch they share." % (of, hedge))
    if cls == "probe_link":
        return ("%s this computer's own link flapped or lost the gateway and the Xbox together, which %s this computer's "
                "connection, not the internet." % (of, hedge))
    if cls == "probe_wifi":
        return "%s this computer's Wi-Fi dropped or roamed at the same moment, which %s the probe host's Wi-Fi." % (of, hedge)
    if cls == "probe_host":
        return ("%s this computer stalled so the probe itself was late, which %s the probe host, not the network." % (of, hedge))
    if cls == "upload_saturation":
        subs = [e.subclass for e in episodes if e.cls == cls and e.subclass]
        who = {"by_this_host": "from this computer", "by_other_device": "from another device on your LAN",
               "inferred": "inferred from the upstream direction"}.get(subs[0] if subs else "", "")
        return ("%s every target past the gateway slowed down together while uploads ran high%s, which %s upload saturation "
                "(bufferbloat) of your upstream link." % (of, (" " + who) if who else "", hedge))
    if cls == "upstream_delay":
        return ("%s your XB7 answered normally while everything past the modem slowed down in the upload direction, which %s "
                "a full upload queue: either a device at home uploading (a game clip, a backup) or Comcast's upstream. This "
                "gateway cannot report household upload, so the two cannot be told apart from here." % (of, hedge))
    if cls in ("ipv6_only", "ipv4_only"):
        fam, other = ("IPv6", "IPv4") if cls == "ipv6_only" else ("IPv4", "IPv6")
        return ("%s only the %s targets suffered while their %s twins were fine, which %s an %s-specific problem on the XB7 or "
                "Comcast's side." % (of, fam, other, hedge, fam))
    if cls == "internet":
        return ("%s your XB7 and the Comcast hops were fine while the internet targets suffered, which %s the wider internet, "
                "not your home or Comcast's access network." % (of, hedge))
    if cls == "single_destination":
        return "%s exactly one destination suffered while everything else was fine, which is likely not your problem." % of
    if cls == "dns":
        return "%s only DNS lookups failed or were slow while the paths were clean, which %s the resolver." % (of, hedge)
    if cls == "cdn":
        return "%s only CDN fetches were slow while the paths were clean, which %s the CDN, not your connection." % (of, hedge)
    return "%s the evidence did not point clearly at one place." % of


def sentence_marks(state: State) -> Tuple[str, int, int]:
    with state.lock:
        marks = list(state.marks)
    total = len(marks)
    linked = sum(1 for m in marks if m.episode)
    if total == 0:
        return "You have not pressed 'Lag happened' yet, so there is nothing to line up.", 0, 0
    unlinked = total - linked
    if unlinked == 0:
        s = "All %d of your 'Lag happened' press%s line up with these bursts." % (total, "es" if total != 1 else "")
    elif linked == 0:
        s = "None of your %d 'Lag happened' press%s showed anything on any target, which is likely the game server." % (
            total, "es" if total != 1 else "")
    else:
        s = ("%d of your %d 'Lag happened' presses line up with these bursts; %d showed nothing, which is likely the game server."
             % (linked, total, unlinked))
    if linked / float(total) < 0.5:
        s += (" The probe could not see most of your lag presses: suspect the Xbox's own cable/port, the game servers, "
              "or run a second probe (peer mode).")
    return s, total, linked


def plex_finding(state: State, plex: dict) -> str:
    """One sentence on what the Plex server reported this session (buffering, transcoding, CPU, tasks)."""
    if not plex.get("token_set"):
        return ("Plex: server status is off (no Plex token), so transcoding, CPU and buffering are not visible; "
                "only the server's and players' network answers are watched.")
    with state.lock:
        evs = [e for e in state.events if e.type.startswith("plex_")]
    n = {k: sum(1 for e in evs if e.type == k) for k in ("plex_buffering", "plex_transcode_slow", "plex_cpu_high", "plex_offline", "plex_remote")}
    parts = []
    parts.append("%d buffering moment%s reported by the server" % (n["plex_buffering"], "" if n["plex_buffering"] == 1 else "s")
                 if n["plex_buffering"] else "no buffering reported by the server")
    if n["plex_transcode_slow"]:
        speeds = [e.peak.get("speed") for e in evs if e.type == "plex_transcode_slow" and isinstance(e.peak.get("speed"), (int, float))]
        parts.append("the server fell behind transcoding %d time%s%s" % (
            n["plex_transcode_slow"], "" if n["plex_transcode_slow"] == 1 else "s",
            " (slowest %.1fx real time)" % min(speeds) if speeds else ""))
    if n["plex_cpu_high"]:
        cpus = [e.peak.get("cpu") for e in evs if e.type == "plex_cpu_high" and isinstance(e.peak.get("cpu"), (int, float))]
        parts.append("server CPU went over 90%%%s" % (" (peak %d%%)" % int(round(max(cpus))) if cpus else ""))
    tasks = sorted({str(e.peak.get("task")) for e in evs if e.type == "plex_activity" and e.peak.get("task")})
    if tasks:
        parts.append("background tasks ran: %s" % ", ".join(tasks[:4]))
    if n["plex_offline"]:
        parts.append("the server stopped answering %d time%s" % (n["plex_offline"], "" if n["plex_offline"] == 1 else "s"))
    if n["plex_remote"]:
        parts.append("%d stream%s left the home network (remote or relayed)" % (n["plex_remote"], "" if n["plex_remote"] == 1 else "s"))
    decisions = sorted({str(s.get("decision")) for s in plex.get("sessions") or [] if s.get("decision")})
    if decisions:
        parts.append("now playing as %s" % " and ".join(decisions))
    return "Plex: %s." % "; ".join(parts)


def persistent_findings(ctx: Any, episodes: List[Episode], now: float) -> List[str]:
    """Link speed/duplex, Xbox link, IPv6, DOCSIS levels, reboots, activity split, hour-of-day concentration."""
    state: State = ctx.state
    out: List[str] = []
    host = dict(state.host)
    iface = state.latest("iface") or {}
    speed = iface.get("speed", host.get("speed"))
    duplex = iface.get("duplex", host.get("duplex"))
    if speed:
        line = "Probe link: %s Mb/s %s" % (speed, duplex or "")
        if (isinstance(speed, (int, float)) and speed < 1000) or (duplex and str(duplex).lower().startswith("half")):
            line += " (slow or half duplex: worth fixing)"
        out.append(line.strip() + ".")
    with state.lock:
        downs = [e for e in state.events if e.type == "link_down"]
    if downs:
        secs = sum(max(0.0, (e.t1 if e.t1 is not None else now) - e.t0) for e in downs)
        out.append("This computer's own network link was down %d time%s (%s in all); nothing was measured then and "
                   "no episode was counted." % (len(downs), "" if len(downs) == 1 else "s", fmt_duration(secs)))
    xbox_link = state.xbox.get("link_mbps")
    if xbox_link:
        out.append("Xbox link: %s Mb/s%s." % (xbox_link, " (expected 1000)" if xbox_link < 1000 else ""))
    inet6 = [t for t in state.targets_list() if t.key.startswith("inet6") and t.enabled]
    if inet6:
        with state.lock:
            replies = sum(max(0, state.totals[t.id].sent - state.totals[t.id].lost - state.totals[t.id].err)
                          for t in inet6 if t.id in state.totals)
        v6 = host.get("v6")
        if replies > 0 or v6 is not None:
            ok = replies > 0 or bool(v6)
            out.append("IPv6: %s." % ("available" if ok else "not available (IPv4 only)"))
    igd = state.latest("igd") or {}
    maps = igd.get("mappings")
    if isinstance(maps, list):
        xbox_maps = [m for m in maps if isinstance(m, dict) and "xbox" in str(m.get("desc", "")).lower()]
        out.append("NAT: UPnP %s%s." % ("works" if igd.get("status") else "status unknown",
                                        " (%d Xbox mapping%s)" % (len(xbox_maps), "" if len(xbox_maps) == 1 else "s") if xbox_maps else ""))
    docsis = state.latest("docsis") or {}
    if docsis:
        parts = []
        if docsis.get("ds_snr_min") is not None:
            parts.append("min DS SNR %.1f dB" % float(docsis["ds_snr_min"]))
        if docsis.get("us_pwr_max") is not None:
            parts.append("max US power %.1f dBmV" % float(docsis["us_pwr_max"]))
        uncorr = sum(int(r.get("docsis", {}).get("uncorr_delta") or 0) for r in state.rows5("docsis", state.t0, now)
                     if isinstance(r.get("docsis"), dict))
        if uncorr or docsis.get("uncorr_delta") is not None:
            parts.append("uncorrectables +%d this session" % uncorr)
        if parts:
            out.append("DOCSIS: %s." % ", ".join(parts))
    with state.lock:
        reboots = sum(1 for e in state.events if e.type in ("docsis_reboot", "xb7_reset"))
    if reboots:
        out.append(state.gw_text("XB7 reboot/reset count: %d." % reboots))
    plex = state.latest("plex")
    if plex:
        out.append(plex_finding(state, plex))
    # per-activity split
    try:
        from laglens.engine import rollup as rollupmod
        acts = sorted({t.get("activity") for t in state.tags if t.get("activity")})
        if len(acts) >= 2 or (acts and acts != ["idle"]):
            parts = []
            for a in acts:
                st = rollupmod.stats(state, "session", activity=a, now=now)
                losses = [v.get("loss_pct") for k, v in st["targets"].items()
                          if v.get("loss_pct") is not None and state.target_by_id(int(k)) is not None
                          and state.target_by_id(int(k)).key.startswith("inet")]
                if losses:
                    parts.append("%s %.1f%%" % (a, sum(losses) / len(losses)))
            if len(parts) >= 2:
                out.append("Loss by activity: %s." % " vs ".join(parts))
    except Exception:  # noqa: BLE001
        log.debug("activity split failed", exc_info=True)
    # hour-of-day concentration (in-session)
    if now - state.t0 >= 3 * 3600 and episodes:
        per_hour: Dict[int, float] = {}
        total = 0.0
        for e in episodes:
            if e.cls in EXCLUDED_FROM_TALLY:
                continue
            dur = (e.t1 if e.t1 is not None else now) - e.t0
            h = time.localtime(e.t0).tm_hour
            per_hour[h] = per_hour.get(h, 0.0) + dur
            total += dur
        if total > 0:
            evening = sum(v for h, v in per_hour.items() if 19 <= h <= 22)
            share = evening / total
            if share >= 0.6:
                out.append("Trouble concentrates in the evening (19:00–23:00): %d%% of episode time." % int(round(share * 100)))
            elif share <= 0.1 and per_hour:
                top_h = max(per_hour.items(), key=lambda kv: kv[1])[0]
                out.append("Trouble is not an evening pattern (peak hour %02d:00)." % top_h)
    return out


def compute_verdict(ctx: Any, now: Optional[float] = None) -> dict:
    """Build the verdict (§10.2 shape), store it in ``state.verdict`` and return it."""
    state: State = ctx.state
    now = state.now() if now is None else now
    try:
        episodes = counted_episodes(state, now)
        full, comcast_tally = tally(episodes, now)
        top = top_list(full)
        cls = headline_class(top)
        if cls in ("none", "mixed"):
            confs = [e.confidence for e in episodes if e.cls not in EXCLUDED_FROM_TALLY]
        else:
            confs = [e.confidence for e in episodes if e.cls == cls]
        mean_conf = (sum(confs) / len(confs)) if confs else 0.0
        band = confidence_band(mean_conf) if episodes else "low"
        s1 = sentence_what(state, episodes, now)
        s2 = state.gw_text(sentence_where(cls, band, episodes, top, now,
                                          loss_dominant=_loss_dominant([e for e in episodes if e.cls == cls] or episodes, state)))
        s3, total_marks, linked_marks = sentence_marks(state)
        findings = persistent_findings(ctx, episodes, now)
        text = " ".join([s1, s2, s3] + findings)
        nxt = next_steps(cls, state)[:3]
        comcast = comcast_text(ctx, now=now, episodes=episodes)
        verdict = {
            "text": text,
            "confidence": band,
            "top": top,
            "comcast": comcast,
            "next": nxt,
            "marks": {"total": total_marks, "linked": linked_marks},
        }
    except Exception as exc:  # noqa: BLE001 - the verdict must never break the ticker
        log.exception("verdict failed")
        verdict = {"text": "Verdict unavailable: %s" % exc, "confidence": "low", "top": [], "comcast": "", "next": [],
                   "marks": {"total": len(state.marks), "linked": sum(1 for m in state.marks if m.episode)}}
    with state.lock:
        state.verdict = verdict
    return verdict


# ---------------------------------------------------------------------------
# Tell-Comcast block
# ---------------------------------------------------------------------------
def truncate_prefix(prefix: Optional[str]) -> Optional[str]:
    """``2601:abcd:1234:5678::/64`` → ``2601:abcd:1234::/64 (truncated)``."""
    if not prefix or not isinstance(prefix, str):
        return None
    if "(truncated)" in prefix:
        return prefix
    addr = prefix.split("/")[0]
    groups = addr.split("::")[0].split(":")
    kept = ":".join(groups[:3])
    return "%s::/64 (truncated)" % kept if kept else prefix


_EVIDENCE_LOSS_RX = re.compile(r"\s*(\d+(?:\.\d+)?)% loss")


def _loss_pct_for(state: State, ep: Episode, key: str, now: float) -> Optional[float]:
    t = state.target(key)
    if t is None:
        return None
    t1 = ep.t1 if ep.t1 is not None else now
    samples = [s for s in state.raw_window(t.id, ep.t0, t1 + 0.25) if not s.late]
    if not samples:
        # fall back to the stored evidence line ("<label>: 12% loss, +3 ms"); the label itself may be an
        # IPv6 address, so the number is read after the label, never after the first colon
        label = label_of(t) + ":"
        for line in ep.evidence:
            if line.startswith(label):
                m = _EVIDENCE_LOSS_RX.match(line[len(label):])
                return float(m.group(1)) if m else None
        return None
    return 100.0 * sum(1 for s in samples if s.lost) / len(samples)


def _docsis_corr(ep: Episode) -> str:
    if not isinstance(ep.docsis, dict):
        return "-"
    evs = ep.docsis.get("events") or []
    names = []
    for d in evs:
        if not isinstance(d, dict):
            continue
        typ = str(d.get("type", "")).replace("docsis_", "").upper()
        off = d.get("t")
        if isinstance(off, (int, float)):
            names.append("%s (%+d s)" % (typ, int(round(off - ep.t0))))
        else:
            names.append(typ)
    return ", ".join(names) if names else "-"


def comcast_text(ctx: Any, now: Optional[float] = None, episodes: Optional[List[Episode]] = None, write: bool = True) -> str:
    """Render the Tell-Comcast block (§7.7) and write ``comcast_evidence.txt`` atomically."""
    state: State = ctx.state
    now = state.now() if now is None else now
    try:
        eps = episodes if episodes is not None else counted_episodes(state, now)
        is_modem = state.gateway_is_modem()
        # only episodes that point past the modem: not the home's equipment (incl. a router of the user's own),
        # not one far-away destination, not unclassified
        comcast_side = set(COMCAST_CLASSES) | {"upstream_delay"}
        if not is_modem:
            comcast_side.discard("xb7_gateway")
        counted = [e for e in eps if e.cls not in EXCLUDED_FROM_TALLY]
        relevant = [e for e in counted if e.comcast_relevant and e.cls in comcast_side]
        host = dict(state.host)
        docsis = state.latest("docsis") or {}
        wan = state.latest("wan") or {}
        igd = state.latest("igd") or {}
        gw = host.get("gateway") or (state.target("gw4").addr if state.target("gw4") else None) or "?"
        fw = docsis.get("fw") or docsis.get("firmware")
        model = docsis.get("model") or "XB7"
        if docsis.get("hw_model") and docsis.get("hw_model") != model:
            model = "%s (%s)" % (model, docsis["hw_model"])
        wan_ip = wan.get("ext_ip") or igd.get("ext_ip") or "unknown"
        prefix = truncate_prefix(wan.get("v6_prefix") or wan.get("prefix6") or host.get("v6_prefix") or host.get("prefix6")) or "n/a"
        link = "%s" % (host.get("iface") or "?")
        if host.get("speed"):
            link += " %s Mb/s %s" % (host.get("speed"), host.get("duplex") or "")
        if host.get("wifi"):
            link += " (Wi-Fi)"
        lines: List[str] = []
        lines.append("Lag Lens evidence for Comcast — session %s (%s → %s local)" % (
            state.session_id or "?", local_date(state.t0), local_date(now)))
        if is_modem:
            gw_desc = "Gateway: %s %s%s" % (model, gw, (" firmware %s" % fw) if fw else "")
        else:
            router = igd.get("model")
            gw_desc = "Router (customer-owned): %s%s | Modem: %s in bridge mode%s" % (
                gw, (" %s" % router) if router else "", model, (" firmware %s" % fw) if fw else "")
        lines.append("%s | WAN IP: %s | IPv6 prefix: %s | Probe host: %s (%s)" % (
            gw_desc, wan_ip, prefix, host.get("hostname") or "?", link.strip()))
        lines.append("")
        lines.append("Episodes pointing at Comcast's side (local time): %d" % len(relevant))
        left_out = len(counted) - len(relevant)
        if left_out:
            lines.append("(%d other episode%s left out: this home's equipment, a single far-away destination, or unclear)"
                         % (left_out, "" if left_out == 1 else "s"))
        lines.append("%-9s %-8s %-26s %-8s %-12s %-9s %-10s %s" % (
            "time", "dur", "class", "gw loss", "Comcast hop", "internet", "direction", "DOCSIS"))
        total_s = 0.0
        any_loss = False  # did any relevant episode lose packets past the gateway (vs. latency only)?
        for e in relevant[-200:]:
            t1 = e.t1 if e.t1 is not None else now
            dur = t1 - e.t0
            total_s += dur
            gw_loss = _loss_pct_for(state, e, "gw4", now)
            # the first Comcast hop as probed: IPv4 when it answers, else IPv6 (as the classifier picks it)
            hop_loss = next((v for v in (_loss_pct_for(state, e, k, now) for k in COMCAST_HOP_KEYS) if v is not None), None)
            inet = [v for v in (_loss_pct_for(state, e, k, now) for k in ("inet4_cf", "inet4_g", "inet6_cf", "inet6_g"))
                    if v is not None]
            inet_loss = (sum(inet) / len(inet)) if inet else None
            if (hop_loss or 0) > 0 or (inet_loss or 0) > 0:
                any_loss = True
            cls = e.cls + ("/" + e.subclass if e.subclass else "")
            lines.append("%-9s %-8s %-26s %-8s %-12s %-9s %-10s %s" % (
                local_hms(e.t0), fmt_seconds(dur), cls[:26],
                "n/a" if gw_loss is None else "%d%%" % int(round(gw_loss)),
                "n/a" if hop_loss is None else "%d%%" % int(round(hop_loss)),
                "n/a" if inet_loss is None else "%d%%" % int(round(inet_loss)),
                e.direction or "n/a", _docsis_corr(e)))
        lines.append("")
        with state.lock:
            events = list(state.events)
        t3 = sum(1 for ev in events if ev.type == "docsis_t3")
        t4 = sum(1 for ev in events if ev.type == "docsis_t4")
        reboots = sum(1 for ev in events if ev.type in ("docsis_reboot", "xb7_reset"))
        if docsis:
            uncorr = sum(int(r.get("docsis", {}).get("uncorr_delta") or 0) for r in state.rows5("docsis", state.t0, now)
                         if isinstance(r.get("docsis"), dict))
            snr = docsis.get("ds_snr_min")
            usp = docsis.get("us_pwr_max")
            # T3/T4 come from the modem's event log; firmware that hides it from the admin login shows none,
            # which must not read as "no timeouts"
            log_hidden = docsis.get("log_lines_seen") == 0
            timeouts = ("T3/T4 not visible (the modem hides its event log from the customer login)" if log_hidden
                        else "T3 ×%d, T4 ×%d" % (t3, t4))
            lines.append("DOCSIS snapshot: min DS SNR %s, max US power %s, Σ uncorrectables +%d, %s, reboots %d" % (
                ("%.1f dB" % float(snr)) if snr is not None else "n/a",
                ("%.1f dBmV" % float(usp)) if usp is not None else "n/a", uncorr, timeouts, reboots))
            off = docsis.get("log_clock_offset_s")
            if isinstance(off, (int, float)) and not isinstance(off, bool) and not log_hidden:
                lines.append(state.gw_text("XB7 log clock offset: %+d s (log timestamps vs this computer)" % int(round(off))))
        else:
            lines.append("DOCSIS snapshot: not collected (gateway login not configured)")
        lines.append("")
        if relevant:
            what = ("slowed down or dropped packets at the same moments" if any_loss
                    else "slowed down at the same moments (latency rose, no packets were lost)")
            up = sum(1 for e in relevant if e.direction == "upstream")
            direction = (" The extra delay was in the upload direction in %d of them." % up) if up * 2 > len(relevant) else ""
            lines.append("Request: in these %d episode%s (%s in total) the %s answered normally while the first Comcast hop "
                         "and the internet targets %s.%s Please check the upstream SNR/power at "
                         "the CMTS for this modem, its T3 timeouts and the node utilization 19:00–23:00." % (
                             len(relevant), "" if len(relevant) == 1 else "s", fmt_seconds(total_s),
                             "gateway" if is_modem else "customer router and the modem", what, direction))
        else:
            lines.append("Request: no Comcast-side episode recorded yet; keep this file for reference.")
        text = "\n".join(lines) + "\n"
    except Exception as exc:  # noqa: BLE001
        log.exception("comcast text failed")
        text = "Tell-Comcast block unavailable: %s\n" % exc
    if write:
        store = getattr(ctx, "store", None)
        if store is not None:
            try:
                store.write_atomic("comcast_evidence.txt", text)
            except Exception:  # noqa: BLE001
                log.exception("cannot write comcast_evidence.txt")
    return text


# ---------------------------------------------------------------------------
# Headline
# ---------------------------------------------------------------------------
def headline(ctx: Any, now: Optional[float] = None) -> dict:
    """``{"answer": yes_comcast|yes_home|no_sign|unknown, "text", "action"}`` for the top bar."""
    out = _headline(ctx, now)
    state: State = ctx.state
    try:
        return dict(out, text=state.gw_text(out.get("text") or ""), action=state.gw_text(out.get("action") or ""))
    except Exception:  # noqa: BLE001
        return out


def _headline(ctx: Any, now: Optional[float] = None) -> dict:
    state: State = ctx.state
    now = state.now() if now is None else now
    cfg = getattr(ctx, "cfg", None) or {}
    warmup = float(cfg.get("warmup_s", 60) or 0)
    elapsed = now - state.t0
    try:
        episodes = counted_episodes(state, now)
        full, _ = tally(episodes, now)
        top = top_list(full)
        cls = headline_class(top)
        if cls == "none":
            if elapsed < warmup:
                return {"answer": "unknown", "text": "Can't tell yet",
                        "action": "Learning your normal — %d s to go" % int(max(0, warmup - elapsed))}
            open_eps = [e for e in state.open_episodes() if e.id]
            if open_eps:
                return {"answer": "unknown", "text": "Can't tell yet", "action": "Trouble in progress — classifying"}
            return {"answer": "no_sign", "text": "No sign of it yet", "action": "Keep running"}
        band = state.verdict.get("confidence", "low") if isinstance(state.verdict, dict) else "low"
        qual = {"high": "Yes", "medium": "Probably yes", "low": "Possibly"}.get(band, "Probably yes")
        nxt = next_steps(cls, state)
        action = nxt[0]["try"] if nxt else "Keep running"
        if cls == "xb7_gateway" and not state.gateway_is_modem():
            return {"answer": "yes_home", "text": "%s — your home (your router)" % qual, "action": action}
        if cls in COMCAST_CLASSES:
            where = {"docsis_access": "Comcast side (cable line)", "comcast_network": "Comcast side (network)",
                     "xb7_gateway": "Comcast side (XB7 gateway)"}[cls]
            return {"answer": "yes_comcast", "text": "%s — %s" % (qual, where), "action": action}
        if cls in HOME_CLASSES:
            where = {"xbox_lan": "Xbox cable/port", "probe_link": "this computer's link", "probe_wifi": "this computer's Wi-Fi",
                     "probe_host": "this computer", "upload_saturation": "upload saturation at home",
                     "plex_server": "the Plex server", "plex_player": "the Plex player",
                     "home_lan": "the network between the Plex server and the player"}[cls]
            return {"answer": "yes_home", "text": "%s — your home (%s)" % (qual, where), "action": action}
        if cls == "upstream_delay":
            return {"answer": "unknown", "text": "%s — upload delay past your modem (a home upload or Comcast's upstream)" % qual,
                    "action": action}
        if cls in INTERNET_CLASSES:
            return {"answer": "no_sign", "text": "Probably not your home or Comcast — %s" % CLASS_LABELS.get(cls, cls),
                    "action": action}
        if cls == "mixed":
            a = top[0]["class"] if top else "unknown"
            b = top[1]["class"] if len(top) > 1 else "unknown"
            return {"answer": "unknown", "text": "Can't tell yet — split between %s and %s" % (
                CLASS_LABELS.get(a, a), CLASS_LABELS.get(b, b)), "action": action}
        return {"answer": "unknown", "text": "Can't tell yet — %s" % CLASS_LABELS.get(cls, cls), "action": action}
    except Exception:  # noqa: BLE001
        log.exception("headline failed")
        return {"answer": "unknown", "text": "Can't tell yet", "action": ""}


__all__ = ["compute_verdict", "comcast_text", "headline", "tally", "top_list", "headline_class", "counted_episodes",
           "fmt_duration", "fmt_seconds", "truncate_prefix", "NEXT_STEPS", "CLASS_LABELS", "COMCAST_CLASSES",
           "HOME_CLASSES", "INTERNET_CLASSES", "EXCLUDED_FROM_TALLY", "INFO_CLASSES", "MIN_EPISODE_S", "persistent_findings",
           "sentence_what", "sentence_where", "sentence_marks"]
