# Lag Lens v1 — Interfaces (skeleton contract)

Everything below is implemented in the skeleton and is what the other modules
(probes, detection, server, report, collectors) import. Signatures are copied
from the code; `docs/BUILD_PLAN.md` remains the authority for behaviour. Python
3.9 syntax only (`typing.Optional`, no `match`, no `X | Y`).

Package layout that exists today:

```
run.py start.sh config.example.json VERSION LICENSE CHANGELOG.md README.md
laglens/__init__.py version.py config.py log.py supervisor.py state.py store.py
        targets.py cli.py app.py
        engine/__init__.py engine/rollup.py
        platform/__init__.py platform/base.py platform/linux.py platform/darwin.py
tests/ (unittest; fixtures/linux, fixtures/darwin, fixtures/xb7)
```

Run the tests: `python3 -I -m unittest discover -s tests -v` (every test file
inserts the repo root into `sys.path`, so `-I` works).

---

## 1. `laglens.state` — shared in-memory state

### Constants

```python
KIND_ICMP = 0; KIND_ICMP_BIG = 1; KIND_TRAIN = 2; KIND_TTL = 3; KIND_NTP = 4
KIND_STUN = 5; KIND_DNS = 6; KIND_TCP = 7; KIND_CDN_CONNECT = 8; KIND_CDN_TTFB = 9
KIND_NAMES: Dict[int, str]

F_LOST = 1; F_LATE = 2; F_ERROR = 4; F_STALL = 8; F_LOADTEST = 16; F_FALLBACK = 32; F_XBOX_ASLEEP = 64
F_EXTRA_SHIFT = 8; F_EXTRA_MASK = 0xFF00        # bits 8–15: DNS rcode / TTL / train index
extra_of(flags: int) -> int
with_extra(flags: int, extra: int) -> int

ON_GRID_KINDS = frozenset({KIND_ICMP, KIND_ICMP_BIG})   # samples that feed the 250 ms slot matrix
SLOT_MS = 250; SLOT_GRID_MS = 5000; RAW_RING_S = 900; RING1_LEN = 7200; RING5_LEN = 17280
MAX_TARGET_ID = 255; MATRIX_MAX_ID = 31

STATUS_STARTING, STATUS_WARMUP, STATUS_OK, STATUS_TROUBLE, STATUS_RECENT,
STATUS_LOADTEST, STATUS_GAP, STATUS_DEGRADED, STATUS_STOPPED      # pill vocabulary (SPEC §8.2)
LATEST_KINDS = ("iface","host","wifi","wan","docsis","igd","xbox","ntp","dns")
ROW5_KINDS   = ("iface","host","wifi","wan","ntp","docsis","xbox","slots")
```

### Dataclasses

```python
@dataclass
class Target:
    id: int; key: str; role: str; addr: Optional[str]; family: int   # family 4 or 6; addr None = unresolved
    kind: str                       # 'icmp' | 'dns' | 'tcp' | 'ntp' | 'cdn'
    label: str; rate_hz: float = 4.0; backend: str = 'socket'       # 'socket' | 'pingbin'
    mode: str = 'direct'            # 'direct' | 'ttl_expiry'
    enabled: bool = True; reason: Optional[str] = None
    port: int = 0; extra: dict = {}                                 # e.g. {'name':..., 'url':...}
    to_dict() -> dict ; Target.from_dict(d) -> Target ; on_grid -> bool

@dataclass
class Sample:
    ts_ms: int; target_id: int; kind: int; flags: int; seq: int; value: int; slot: int = 0
    lost / late / error / received -> bool ; rtt_ms -> Optional[float] ; to_row() -> [ts_ms,id,kind,flags,value]

@dataclass
class Event:
    id: str; t0: float; t1: Optional[float]; type: str; target: Optional[int]; severity: int
    peak: dict = {}; episode: Optional[str] = None; stall: bool = False; source: str = 'auto'; note: str = ''
    to_dict() -> dict

@dataclass
class Episode:     # SPEC §6.5; the JSON key "class" is the attribute `cls`
    id: str; t0: float; t1: Optional[float] = None; dur_s: Optional[float] = None
    targets: List[int]; events: List[str]; cls: str = 'unknown'; subclass: Optional[str] = None
    confidence: float = 0.0; evidence: List[str]; alt: Optional[dict]; locus: Optional[dict]
    direction: str = 'n/a'; xbox_state: str = 'unknown'; activity: str = 'idle'
    host_tags: List[str]; comcast_relevant: bool = True; sweep: Optional[dict]; docsis: Optional[dict]
    marks: List[str]; onset_order: List[str]; size_loss_ratio: Dict[str, float]
    wan: Optional[dict]; xb7_cpu_only: bool = False
    open -> bool ; to_dict(brief=False) -> dict   # brief drops sweep/docsis (for /api/state) ; Episode.from_dict(d)

@dataclass
class Mark:
    id: str; t_pressed: float; offset_s: float; t_est: float; activity: str = 'idle'; note: str = ''
    source: str = 'dashboard'; episode: Optional[str] = None; assessment: Optional[str] = None
    snapshot: Optional[str] = None       # 'marks/<id>.json'
    to_dict() -> dict

@dataclass
class Rollup:      # ms floats; None when nothing was received
    t: int; id: int; n: int; lost: int; late: int; err: int
    min: Optional[float]; p50: Optional[float]; p95: Optional[float]; max: Optional[float]
    jit: Optional[float]; stall: int; big_n: int = 0; big_lost: int = 0
    to_row() -> dict (the rollups.jsonl probe row) ; loss_pct -> Optional[float] ; received -> int
    merge(other: Rollup) -> None   # fold a later rollup of the same (t, id) in: counts exact, min/max exact,
                                   # p50/p95/jit weighted by received count (approximate)
```

Accounting rules in `State.add_sample`: a `F_LATE` sample is a second record
for a seq that was already recorded as lost; it counts in `late` only (not in
`n`, not in percentiles). `n = lost + err + received`.

Slot grid: `Sample.slot` counts 250 ms slots from `State.slot_origin_ms`,
which is `t0` rounded **down to the 5 s grid** (`SLOT_GRID_MS`), not from
`t0_ms` itself. A wall-aligned 5 s window `[t, t+5)` therefore covers exactly
slots `slot_for(t*1000) .. +19`, so the `slots` row of `rollups.jsonl` has
no sub-slot phase offset against the probe rows of the same window. Slot 0
starts at most 5 s before `t0`.

### `State`

```python
class State:
    def __init__(self, t0: Optional[float] = None, session_id: str = "", cfg: Optional[dict] = None)
    lock: threading.RLock ; t0: float ; t0_ms: int ; slot_origin_ms: int ; session_id: str ; cfg: dict ; label ; resumed_count ; version
    targets: Dict[int, Target] ; by_key: Dict[str, Target] ; totals: Dict[int, TargetTotals] ; sample_count: int
    events: List[Event] ; episodes: List[Episode] ; marks: List[Mark] ; tags: List[dict]
    activity: dict ; verdict: dict ; doctor: List[dict] ; path: dict ; loadtest: dict ; disk: dict
    host: dict ; xbox: dict ; update: dict ; matrix: dict ; w5m: Dict[int, dict] ; port: Optional[int]
    stop_event: threading.Event ; stop_reason: str ; status: str ; pill: str ; headline: dict ; health: dict
    sse_clients: int

    # time / slots
    now() -> float ; elapsed(now=None) -> float
    slot_for(ts_ms: int) -> int ; slot_time(slot: int) -> float     # relative to slot_origin_ms (5 s-aligned t0)

    # targets
    add_target(t: Target) -> Target          # id < 0 or clashing id → next free id; publishes 'target'
    next_target_id() -> int ; target(key) -> Optional[Target] ; target_by_id(tid) -> Optional[Target]
    targets_list() -> List[Target]           # id order
    set_target_state(key, enabled=None, reason=<unset>, **fields) -> None   # publishes 'target'
        # only the arguments passed change: omitting `reason` leaves it untouched (a re-resolver that
        # passes only addr=... cannot wipe 'cannot resolve'); pass reason=None to clear it explicitly

    # samples / rings
    add_sample(s: Sample) -> None            # raw ring 15 min, 1 s accumulators, slot bitmasks, session totals
    raw_window(target_id, t_from, t_to) -> List[Sample]        # t in unix s, oldest first
    raw_all(t_from, t_to, target_ids=None) -> List[Sample]     # sorted by ts_ms
    last_sample(target_id, received_only=True) -> Optional[Sample]
    take_accumulators(before_sec: int) -> Dict[int, Dict[int, SecondAcc]]   # pops seconds < before_sec
    pending_seconds() -> List[int]
    slots(slot_from: int, count: int, late=False) -> List[int]  # u32 bitmasks of target ids lost/late
    prune_slots(before_slot: int) -> None
    add_rollup(res: int, r: Rollup) -> None                     # res 1 (2 h) or 5 (24 h); keeps the ring time-ordered;
                                                                # a rollup for an existing (t, id) is MERGED (Rollup.merge),
                                                                # never appended as a duplicate row
    rollups(res, t_from, t_to, target_ids=None) -> Dict[int, List[Rollup]]   # O(window), not O(ring): scans
                                                                             # back from the tail and stops at t_from
    last_rollup(res, target_id) -> Optional[Rollup]
    add_row5(kind: str, row: dict) -> None ; rows5(kind, t_from, t_to) -> List[dict]   # 5 s collector rows

    # registry / latest
    set_collector(name, status, reason=None, **kv) -> None     # status ok|degraded|disabled; publishes 'collector' on change
    collectors() -> Dict[str, dict] ; collector(name) -> Optional[dict]
    latest(kind) -> Optional[dict] ; set_latest(kind, row: dict) -> None

    # notes (producers -> detector; see §10.1)
    raise_note(type, t=None, target=None, severity=1, note='', **peak) -> dict   # queued; `t` defaults to now()
    drain_notes() -> List[dict]              # the detector empties the queue once per second

    # detection-engine additions (additive, no API body changes)
    clock: Callable[[], float]               # behind now(); tests inject a fake (`state.clock = lambda: t`)
    blips: int                               # episodes shorter than 1.5 s (SPEC §7.4), counted, never stored
    matrix_acc: dict                         # running sums behind matrix["pairs"] ({"both": {..}, "b_lost": {..}})

    # events / episodes / marks / activity
    next_event_id() -> 'ev-000001' ; next_episode_id() -> 'ep-000001' ; next_mark_id() -> 'mk-1'
    seed_ids(events=0, episodes=0, marks=0) -> None            # resume: continue numbering
    add_event(ev) -> Event (publishes 'event') ; add_episode(ep) -> Episode (publishes 'episode_open')
    episode(id) -> Optional[Episode] ; open_episodes() -> List[Episode]
    add_mark(m) -> Mark (publishes 'mark') ; mark(id) -> Optional[Mark]
    set_activity(activity, source='dashboard', label=None) -> dict (publishes 'activity'; closes the previous tag)
    activity_spans(activity) -> List[Tuple[float, float]]

    # status / snapshot
    set_status(status, pill=None, headline=None) -> None
    snapshot() -> dict                        # GET /api/state body (SPEC §10.2 minus deferred keys) + "activities": cfg list
    tick_payload(now=None) -> dict            # SSE 'tick' body (SPEC §10.3)

    # pub/sub
    subscribe(cb: Callable[[str, Any], None]) -> unsubscribe_fn ; unsubscribe(cb)
    publish(name: str, obj) -> None           # fan-out outside the lock; listener errors swallowed
    request_stop(reason='api', publish=True) -> None   # sets stop_event, stop_reason; publishes 'stopping'
                                                        # (publish=False from a signal handler: app.shutdown publishes once)
```

Published names: `target`, `collector`, `event`, `episode_open`, `mark`,
`activity`, `stopping`. The ticker/detector publish `tick`, `rollup5`,
`episode_update`, `episode_close`, `verdict`, `loadtest`, `docsis` themselves
with `state.publish(name, obj)`; the SSE server subscribes and forwards.

---

## 2. `laglens.engine.rollup`

```python
percentile(sorted_values: Sequence[float], p: float) -> Optional[float]   # == statistics.quantiles(method='inclusive')
jitter(rtts: Sequence[float]) -> Optional[float]                           # mean |rtt_i − rtt_{i−1}|, None if < 2
rollup_from_acc(t: int, tid: int, acc: SecondAcc) -> Rollup
close_second(state: State, t: int) -> List[Rollup]        # closes every accumulated second < t; stores them in the 1 s ring
rollup_from_samples(t: int, tid: int, samples: Iterable[Sample]) -> Rollup
close_window5(state: State, t: int) -> List[dict]         # rows for rollups.jsonl: probe rows, the 'slots' row
                                                          # {"t","slots":[u32×20],"late_slots":[u32×20]}, collector rows
                                                          # {"t","<kind>":{...}} from state.latest(kind); fills the 5 s rings
longest_outage(samples, rate_hz) -> float                  # seconds
window_stats(samples: Sequence[Sample], rate_hz=4.0) -> dict   # sent,lost,late,err,loss_pct,late_pct,min,p50,p95,p99,max,
                                                               # jitter,longest_outage_s,big_loss_ratio
stats(state, window='session'|'1h'|'5m', activity='all', now=None) -> dict   # GET /api/stats body
w5m_for(state, now=None) -> Dict[int, dict]               # refreshes state.w5m (p50,p95,loss_pct,late_pct,jitter)
WINDOW5_S = 5 ; SLOTS_PER_WINDOW = 20
```

```python
WINDOW5_LAG_S = 10                                          # == late_window_ms
second_close_lag_s(cfg=None, timeout_ms=None) -> int       # ceil(timeout_ms/1000) + 1  (3 with the 2000 ms default)
```

Ticker contract (implemented in `engine/ticker.py`, see §11). Samples are keyed
by SEND time but a probe's verdict is only known at send + `timeout_ms`
(lost) or up to send + `late_window_ms` (late reply), so **the ticker lags
wall time**. Once per second at `t = int(now)`:

1. `close_second(state, t - second_close_lag_s(cfg))` — closes every
   accumulated second older than the lag (every probe sent in it has its
   lost/received verdict). A sample that still lands in an already-closed
   second (a late reply) is closed on a later call and `State.add_rollup`
   merges it into the existing 1 s rollup, so the 1 s ring never holds two
   rows for one `(t, id)`.
2. when `t % 5 == 0`: rows = `close_window5(state, t - WINDOW5_LAG_S)`
   (the window `[t-10, t-5)`, every lost and late verdict in) →
   `store.append_json('rollups', row)` for each → `state.publish('rollup5', rows)`.
3. detector/episodes/classify, every 30 s verdict, `w5m_for(state)`,
   `state.publish('tick', state.tick_payload())`.

`close_final()` at shutdown closes everything still pending (`close_second(state, now + 1)`
and the last window) before `store.flush()` and the final report.
`Ticker.replay(samples)` drives the same pipeline from stored samples for the offline
`--report DIR` rebuild (§11.6).

---

## 3. `laglens.store.Store`

```python
SAMPLE_STRUCT = struct.Struct('<QBBHIi'); SAMPLE_SIZE = 20   # (ts_ms, target_id, kind, flags, seq, value)
JSONL_NAMES = {'rollups','events','episodes','marks','tags','path','xb7','igd','host','loadtests','docs'}
pack_sample(s: Sample) -> bytes ; unpack_sample(rec: bytes) -> tuple ; new_session_id(now=None) -> 'YYYYMMDD-HHMMSS'
TOKEN_FILE = 'token' ; LAST_FILE = '.last' ; PID_FILE = 'laglens.pid'

class Store:
    def __init__(self, session_dir, cfg: dict, resume: bool = False, state=None, disk_usage=None, clock=time.monotonic)
    Store.create(sessions_root, cfg, now=None, **kw) -> Store     # new unique local-time session dir
    dir: Path ; id: str ; state ; samples_writing: bool ; writing: bool ; disk: dict ; last_read_truncated: bool
    path(name) -> Path
    ensure_token() -> str ; token -> str                            # 0600, secrets.token_urlsafe(24)
    start() -> None ; stop(timeout=15.0) -> None                    # stop drains, closes, gzips samples.bin + host.jsonl;
                                                                    # a HARD BARRIER: appends after stop() are logged and dropped
    append_sample(s: Sample) -> None                                # dropped while samples_writing/writing is False
    append_json(name, obj: dict) -> None                            # name ∈ JSONL_NAMES; ValueError otherwise
    write_atomic(name, data: Union[bytes, str]) -> Path             # tmp + os.replace; subdirs allowed ('marks/mk-1.json')
    write_json_atomic(name, obj, indent=1) -> Path
    flush() -> None                                                 # blocks until queued writes hit the OS
    read_samples(t_from_ms=None, t_to_ms=None, target_ids=None, max_rows=50000) -> List[tuple]   # .bin or .bin.gz, torn tail skipped;
                                                                    # a truncated .gz yields every whole record before the cut
    iter_samples() -> Iterable[Sample]
    read_json(name) -> List[dict]                                   # .jsonl or .jsonl.gz, torn last line skipped
    read_file_json(name) -> Optional[Any] ; read_targets() -> Optional[List[dict]]
    check_caps() -> dict                                            # samples_cap_mb / session_cap_mb / min_free_mb → state.disk + 'store' collector
    sizes() -> Dict[str, int]
    Store.write_last(sessions_root, session_dir) ; Store.read_last(sessions_root) -> Optional[str]
```

Writer thread: flush every 1 s, `fsync` every 5 s on `samples.bin` and
`events.jsonl`, caps re-checked every 5 s (the session-dir size comes from a
cache: a full walk every `FULL_WALK_S` = 60 s, otherwise only the writer's
open files are re-stat'ed). A failed write latches `writing=False` with its
reason for `WRITE_RETRY_S` = 30 s (the cap check does not flap it back),
then one retry is allowed.

`resume=True` first inflates `samples.bin.gz`/`host.jsonl.gz` atomically
(`.inflate.tmp` + `os.replace`; a truncated archive inflates to its readable
prefix, a failure leaves no partial file; a plain file that exists next to
the `.gz` is merged after it with a warning) and then **realigns** the files:
`samples.bin` is truncated to a multiple of `SAMPLE_SIZE` and every `*.jsonl`
ending in a torn line is cut back to its last newline, so appends after a
crash never glue onto torn bytes.

`write_atomic` is not subject to the caps. `ReportBuilder` must check
`store.writing` before building `report.html` (every 30 s) so a full disk is
not written to; `session.json` at shutdown is small and always written.

`events.jsonl` and `episodes.jsonl` hold **one row per open/update/close** of
the same id (the detector re-appends an event or episode when it changes);
readers (`--report`, export, the sessions index) must dedupe by `id`, keeping
the last row.

---

## 4. `laglens.platform`

```python
get_platform(name: Optional[str] = None, **kw) -> Platform   # LinuxPlatform | DarwinPlatform | Platform (generic)
is_private(addr: Optional[str]) -> bool                      # RFC1918/link-local/loopback/CGNAT (token source check)

class Platform:   # every method never raises; None/{}/[] on failure
    name: str  # 'linux' | 'darwin' | 'generic'
    def __init__(self, runner=None, reader=None, exists=None, env=None, which=None)   # injectable for tests
    missing: set ; capabilities: Dict[str, bool] ; last_error: Dict[str, str]
    run_rc(argv, timeout=5.0) -> Optional[Tuple[int, str, str]] ; run(argv, timeout=5.0) -> Optional[str]  # stdout if rc 0
    read(path) -> Optional[str] ; read_stripped(path) ; exists(path) -> bool ; which(name) -> Optional[str] ; env(key, default='')
    hostname() -> str ; lan_ip(probe_addr='10.0.0.1') -> Optional[str] ; load_avg() -> Optional[Tuple[float,float,float]]
    terminal_app_name() -> str ; os_info() -> dict ; binaries(names) -> Dict[str, Optional[str]]
    default_route() -> {'gateway','iface','gateway6','iface6','lan_ip','prefixlen'}     # (+ 'expires6' on Linux)
    route_to(addr) -> {'iface','src'}
    iface_stats(iface) -> {rx_bytes,tx_bytes,rx_packets,tx_packets,rx_errors,tx_errors,rx_dropped,tx_dropped,crc,collisions,multicast}  # None where unavailable
    link_info(iface) -> {'speed','duplex','carrier','carrier_changes','operstate','wireless': bool}   # (+ 'media' on macOS)
    neighbors() -> List[{'ip','mac','iface','state'}]            # v4 + v6; mac None when incomplete
    wifi_info(iface) -> Optional[{'rssi','noise','chan','bssid','ssid','rate_mbps'}]  # extra keys: freq/quality (Linux), phy/connected (macOS)
    resolvers() -> List[str]
    vpn_routes(addr='1.1.1.1') -> {'via_tunnel': bool, 'iface'}
    keepawake_cmd(pid) -> Optional[List[str]]
    on_battery() -> Optional[bool] ; is_game_mode() -> bool ; firewall_info() -> dict ; dhcp_lease(iface) -> dict
```

Runner fake contract: `runner(argv: list, timeout: float) -> (rc, stdout, stderr)`;
raise `FileNotFoundError` for a missing binary (cached once in `missing`),
`subprocess.TimeoutExpired` for a timeout. `reader(path) -> Optional[str]`,
`exists(path) -> bool`. Commands used: see `platform/linux.py` /
`platform/darwin.py` and the fixtures under `tests/fixtures/`.

---

## 5. `laglens.config`

```python
DEFAULTS: dict                                   # SPEC §11.1 with BUILD_PLAN §3.6 changes (config.example.json is identical)
load_config(path=None, overrides=None) -> dict   # deep-merge; unknown keys → WARN+drop; bad values → default; rate_hz/hop_rate_hz clamped 1–5
                                                 # overrides may be dotted ('targets.xbox_ip'); result has '_warnings': List[str]
redact(cfg) -> dict                              # keys containing password/secret/token → '***'
has_secret(cfg) -> bool ; public(cfg) -> dict (redacted, no '_' keys) ; protect_file(path) -> bool (chmod 600)
ensure_config_file(path) -> Path                 # copy config.example.json (or defaults) on first run; chmod 600 if a secret is set
save_values(path, {"targets.xbox_ip": ip, ...}) -> bool   # persist dotted keys into the user's config.json: re-reads the file
                                                 # as written (not the merged defaults), sets the keys, writes `.tmp` + os.replace,
                                                 # keeps 0600 when a secret is present or the file already was private; an
                                                 # unreadable/non-object file is left alone (False). Used by POST /api/xbox.
deep_merge(base, over) -> dict ; expand_dotted(overrides) -> dict ; iter_keys(d) -> Iterable[str]
```

## 6. `laglens.log`

```python
setup_logging(session_dir=None, verbose=False, secrets=None) -> logging.Logger   # stderr + RotatingFileHandler log.txt 5 MB × 3
get_logger(name='') -> logging.Logger          # 'laglens' or 'laglens.<name>'
```
Use `logging.getLogger('laglens.<module>')` in modules; the package installs a
`NullHandler` so nothing prints until `setup_logging` runs.

## 7. `laglens.supervisor` — how a module registers a thread

```python
supervised(name, fn, state, stop_event, engine=False, max_failures=10, window_s=600.0,
           backoff_min=1.0, backoff_max=60.0, clock=time.monotonic, sleep=None) -> 'ok' | 'disabled'
start_thread(name, fn, state, stop_event=None, engine=False, daemon=True, **kw) -> threading.Thread
```

`fn` takes no arguments and should loop until `state.stop_event.is_set()`.
Exceptions are caught and logged; the body restarts after 1, 2, 4 … 60 s;
status is kept in the registry (`state.set_collector(name, 'ok'|'degraded'|'disabled', reason=...)`).
A non-engine body failing 10× in 10 min is disabled with a reason; `engine=True`
is always restarted. A body that **returns before stop was requested** ends
supervision with the registry entry set to `degraded` / `thread exited early`
(a dead thread must be visible); returning after `stop_event` is set keeps `ok`.
Typical use:

```python
class HostCollector:
    def __init__(self, ctx): self.ctx = ctx
    def start(self): self.thread = start_thread('host', self._loop, self.ctx.state)
    def stop(self, timeout=2.0): self.thread.join(timeout)
    def _loop(self):
        st = self.ctx.state
        while not st.stop_event.wait(1.0):
            row = {...}
            st.set_latest('iface', row)                 # picked up by close_window5 every 5 s
            self.ctx.store.append_json('host', {...})   # 1 Hz full-rate row
```

## 8. `laglens.targets`

```python
build_targets(cfg, platform, state, store=None, resume_targets=None, resolver=None, route=None) -> List[Target]
static_targets(cfg, platform, resolver=None, route=None) -> List[Target]   # ids provisional (-1), stable order
save_targets(state, store) -> None            # rewrite targets.json (call after state.add_target for xbox/hops)
targets_document(state) -> dict ; resolve_many(items, resolver=None, timeout=5.0) -> dict
default_resolver(name, family) -> Optional[str]   # family 6 skips IPv4-mapped answers (::ffff:a.b.c.d): a name without AAAA
                                                  # stays unresolved → tcp_*6 disabled with reason 'cannot resolve'
lan_resolver(resolvers, route) -> Optional[str]   # first IPv4 resolver that is the gateway or inside route lan_ip/prefixlen
is_ipv4_mapped(addr) -> bool
RATE_DNS = 1/3 ; RATE_TCP = 0.5 ; RATE_NTP = 0.2 ; RATE_CDN = 1/60
```

`dns_gw` = `lan_resolver(platform.resolvers(), route)` → else the gateway
address → else (no gateway) the first IPv4 system resolver labelled
"System DNS …" (a VPN/MagicDNS resolver such as Tailscale's `100.100.100.100`
is never preferred over the home gateway). The doctor's "gateway" DNS check
uses the same rule.

Static key order: `gw4, gw6, inet4_cf, inet4_g, inet6_cf, inet6_g, dns_gw,
dns_cf4, tcp_cf4, tcp_cf6, tcp_gw, tcp_xbl_auth4/6, tcp_xbl_profile4/6,
tcp_live4/6, tcp_game_N, ntp_cf, ntp_g, cdn_N`. Unresolvable names keep
`addr=None`, `enabled=False`, `reason='cannot resolve'` (re-resolve every
300 s in the TCP prober and call `state.set_target_state`). `xbox`,
`isp_hop4`, `mid_hop4`, `isp_hop6` are added later with
`state.add_target(Target(id=-1, ...))` + `save_targets`.

## 9. `laglens.cli` / `laglens.app`

```python
cli.build_parser() -> ArgumentParser ; cli.parse_args(argv=None) ; cli.main(argv=None) -> int
cli.EXIT_OK = 0 ; EXIT_ERROR = 1 ; EXIT_NOT_IMPLEMENTED = 2 ; EXIT_INTERRUPTED = 130

app.ROOT: Path ; app.COMPONENTS: List[(name, module, attr, 'class'|'func')]   # start order:
    # engine, tracer, tcp, dns, ntp, cdn, host, wifi, wan, xbox, docsis, igd, ticker, report, http, keepawake, notify
app.cmd_run / cmd_doctor / cmd_selftest / cmd_report / cmd_export / cmd_index / cmd_loadtest / cmd_docsis_dump / cmd_update / cmd_stop(args) -> int
app.load_app_config(args, create=True) -> dict ; app.config_path(args) -> Path
app.run(cfg, args, sessions_root=None, platform=None, resolver=None, stop_after=None, install_signals=True, components=None,
        quiet=False, terminal_marks=False, update_check=False) -> int     # cmd_run passes terminal_marks/update_check=True
app.LAST_RUN: dict        # {"stop_reason", "session_id", "session_dir"} of the run that just returned
app.STOP_REASON_ROTATE = "rotate"   # session reached cfg.rotate_hours: cmd_run starts a fresh session in the same process
app.shutdown(ctx, pidfile=None, grace_s=STOP_GRACE_S) -> int ; app.startup_box(ctx) -> str ; app.doctor_lines(checks) -> List[str]
app.session_document(ctx, stopped=None) -> dict ; app.write_session_json(ctx, stopped=None) ; app.truncate_v6_prefix(prefix)
app.TerminalMarks(ctx, stream=sys.stdin, out=print)   # Enter = "Lag happened" (source 'terminal'); one daemon reader per process,
                                                       # started only when stdin is a TTY; .press(note) -> Mark
app.STOP_GRACE_S = 4.0   # shutdown budget: engine 2 s, the rest split between the other components, writer ≥ 1 s

class AppContext:    # passed to every component constructor
    cfg: dict ; args: Namespace ; state: State ; store: Store ; platform: Platform ; root: Path ; sessions_root: Path
    log ; components: Dict[str, Any] ; port: int ; started_at: float ; route: dict ; urls: List[str]
    config_file: Path          # the config.json of this run (POST /api/xbox persists targets.xbox_ip into it)
    terminal_marks: Optional[TerminalMarks]
    token -> str ; component(name) -> Optional[Any] ; wants(name) -> bool
```

`run()` in order: platform → Store → State → targets → `doctor.fast(ctx)` (its
OK/WARN/FAIL lines go into the startup box, `state.doctor`, `doctor.json`) →
`MarkService` (in `ctx.components["marks"]`, shared by the server, the
terminal and `GET /mark`) → `COMPONENTS` in the order above → LAN URLs →
terminal reader (TTY only) → startup box (version, session, dashboard + phone
URLs, gateway, doctor lines, running/not-running chips) →
`updater.check_async(ctx)` (when `cfg.update_check`) → browser (`open` /
`xdg-open`, unless `--no-browser`, `open_browser: false`, SSH, or no
display) → main loop (`session.json` every 30 s; rotation when the session is
older than `cfg.rotate_hours`, `stop_reason = "rotate"`).

Module entry points the app looks for (implement these names):

| component | module.attr | protocol |
|---|---|---|
| engine | `laglens.engine.scheduler.Engine(ctx)` | `.start()`, `.stop(timeout)`; stopped first at shutdown |
| tracer | `laglens.probes.path.Tracer(ctx)` | start/stop |
| tcp / dns / ntp / cdn | `laglens.probes.tcp.TcpProber`, `probes.dns.DnsProber`, `probes.ntp.NtpProber`, `probes.cdn.CdnProber` | start/stop |
| host / wifi / wan / xbox / docsis / igd | `laglens.collectors.<name>.<Name>Collector(ctx)` | start/stop; docsis only with a password and not `--no-docsis`; igd not with `--no-igd` |
| ticker | `laglens.engine.ticker.Ticker(ctx)` | start/stop, optional `.close_final()` |
| report | `laglens.report.build.ReportBuilder(ctx)` | start/stop, `.build(final=True)`; `rebuild(dir, cfg)` for `--report` |
| http | `laglens.server.http.serve(ctx)` → object with `.stop(timeout)` | |
| keepawake | `laglens.keepawake.KeepAwake(ctx)` | start/stop (stopped last) |
| notify | `laglens.notify.Notifier(ctx)` | start/stop; only when ntfy/webhook configured |
| doctor | `laglens.doctor.run_cli(cfg, platform, no_net=False) -> int`, `fast(ctx)` (before the engine starts), `selftest(run_tests=False) -> int` | |
| update check | `laglens.updater.check_async(ctx)` once after the components start (sets `state.update`; `GET /api/version` returns it as `update`) | |
| export / index / loadtest / docsis-dump / update | `report.export.export_cli(dir, pack, cfg)`, `report.sessions.rebuild_index(root)`, `loadtest.run_cli(cfg)`, `collectors.docsis.dump_cli(cfg)`, `updater.run_cli(check_only, root)` | each returns an int |

A missing module is logged as "component not available yet" and its registry
entry is `disabled` with reason `not available yet`. A module that *exists*
but whose own imports fail is not "missing": the error is logged with its
traceback and the entry is `disabled` with reason `import failed: ...`. A
constructor exception disables it with the error text. `POST /api/stop`
should call `ctx.state.request_stop('api')`.

Shutdown order (`app.shutdown`): `stopping` published once → engine
`stop(2.0)` → other components `stop(timeout)` in reverse start order →
ticker `close_final()` → `store.flush()` (so a ReportBuilder reading
`rollups.jsonl`/`events.jsonl` sees every queued row) → `report.build(final=True)`
(reads the still-plain `samples.bin`) → `comcast_evidence.txt` ensured
(`engine.verdict.comcast_text(ctx)` when neither the verdict nor the builder
wrote it) → `store.stop()` (gzip) → `session.json` (with `stop_reason`,
truncated `v6_prefix`, `summary.verdict/health/headline/matrix`) →
`report.sessions.rebuild_index(sessions_root)` (the static `sessions/index.html`)
→ keepawake → pidfile. The first SIGINT/SIGTERM only sets `stop_event`
(no subscriber callbacks run in the handler); only SIGINTs count toward the
forced exit (third Ctrl-C, ≥ 1 s after the first → `os._exit(130)`).

`stop_reason` values: `sigint`, `sigterm`, `api` (`POST /api/stop`, also
`--stop` which sends SIGTERM → `sigterm`), `rotate`, `test`.

Session files written by the skeleton: `targets.json`, `session.json`
(start, every 30 s, final), `token` (0600), `log.txt`, `events.jsonl`
(`monitor_gap` on resume, `peak={"reason": "monitor restarted"}`; the file
row is exactly `Event.to_dict()`), `sessions/.last`, `sessions/laglens.pid`.
On resume a malformed `targets.json` entry (id not an int in 0..255, no key)
or `session.json` (`started`/`resumed_count` not numeric) degrades with a
warning instead of aborting the run.

---

## 10. Cross-module contracts for the feature modules (authoritative)

### 10.1 Who creates what

- **Samples**: every probe emits `Sample` objects with `ctx.state.add_sample(s)` followed by
  `ctx.store.append_sample(s)` (same order, every sample, including lost/late/error ones).
  `ts_ms` is the wall-clock send time; `slot = state.slot_for(ts_ms)` for on-grid ICMP kinds, 0 otherwise.
  Flags: set `F_LOADTEST` when `state.loadtest.get('running')`, `F_XBOX_ASLEEP` on the xbox target's
  samples when `state.xbox.get('state') == 'asleep'`, `F_FALLBACK` on ping-binary samples, `F_STALL` is set by
  the engine when its own send lateness > 50 ms or loop gap > 200 ms in that second.
- **Events**: ONLY `laglens.engine.detector` creates `Event` objects (`state.add_event` + `store.append_json('events', ev.to_dict())`).
  Every other module reports discrete occurrences with `state.raise_note(type, t=None, target=None, severity=1, note='', **peak)`;
  the detector calls `state.drain_notes()` once per second and converts each note into an Event
  (dedupe/rate-limit per type, attach to open episodes within ±5 s, docsis within ±60 s as correlation).
  Note types producers may raise: `route_change, path_anomaly, link_flap, iface_errors, wifi_drop, wifi_roam, self_load,
  wan_saturated, wan_ip_change, v6_prefix_change, docsis_t3, docsis_t4, docsis_drw, docsis_ranging, docsis_uncorr,
  docsis_power_snr, docsis_partial, docsis_reboot, xb7_reset, vpn_route, dhcp_renew, clock_jump, collector_error,
  loadtest_phase, probe_error, monitor_gap, nat_mapping_change, cdn_slow, dns_fail, tcp_timeout`.
- **Latest rows**: collectors publish their newest reading with `state.set_latest(kind, row)` (kinds:
  `iface, host, wifi, wan, docsis, igd, xbox, ntp, dns, cdn, path`); `close_window5` copies the kinds in
  `ROW5_KINDS` into `rollups.jsonl` every 5 s. Full-rate rows go to `store.append_json(<name>, row)`.
- **Threads**: every component is `Cls(ctx)` with `.start()` / `.stop(timeout)`; loops run via
  `laglens.supervisor.start_thread(name, fn, ctx.state)` and stop when `ctx.state.stop_event` is set.

### 10.2 Method names other modules call (implement exactly these)

| module | class / function | used by |
|---|---|---|
| `engine.scheduler` | `Engine(ctx)`; `.start()`, `.stop(timeout)`; `.stats() -> dict` (pps, lateness) | app |
| `probes.path` | `Tracer(ctx)`; `.rediscover() -> bool` (async; False if already running), `.sweep(reason: str) -> bool` (async, rate-limited 1/60 s), `.current() -> dict` (= `GET /api/path` body: `{"v4":[hops],"v6":[hops],"roles":{...},"discovered_at","changes","history":[...],"method"}`); keeps `state.path` updated; adds `isp_hop4/mid_hop4/isp_hop6` targets via `state.add_target` + `targets.save_targets` | server, detector |
| `probes.tcp` / `probes.dns` / `probes.ntp` / `probes.cdn` | `TcpProber(ctx)`, `DnsProber(ctx)`, `NtpProber(ctx)`, `CdnProber(ctx)` start/stop | app |
| `collectors.xbox` | `XboxCollector(ctx)`; sets `state.xbox = {'ip','state':'unknown|awake|asleep','source','link_mbps','candidates':[{ip,mac,oui_match}]}`; `.set_ip(ip) -> bool` (from `/setup`: switches the target in place, `cfg` in memory; the server then persists `targets.xbox_ip` with `config.save_values(ctx.config_file, …)`) | server |
| `engine.ticker` | `Ticker(ctx, clock=None, wait=None)`; `.start()`, `.stop(timeout)`, `.tick(t, now=None)`, `.close_final()`, `.replay(samples, final=True) -> int` | app, report |
| `engine.detector` | `Detector(ctx)`; `.step(t: int)` called by the ticker each second; `.finalize(t=None)`, `.open_episode() -> Optional[Episode]`, `.baseline(tid)`, `.stats()`, `.verdict_due` | ticker |
| `engine.classify` | `classify(episode, ctx, now=None) -> None` (fills cls/subclass/confidence/evidence/alt/locus/direction/host_tags/comcast_relevant/onset_order/size_loss_ratio/xb7_cpu_only/wan, accumulates `state.matrix` on close); `compute_matrix(state, t0, t1) -> dict`; `confidence_band(conf) -> 'low'|'medium'|'high'` | detector, report |
| `engine.verdict` | `compute_verdict(ctx, now=None) -> dict` (stores in `state.verdict`, writes `comcast_evidence.txt`), `comcast_text(ctx, now=None, episodes=None, write=True) -> str`, `headline(ctx, now=None) -> dict` | ticker, server, report |
| `engine.marks` | `MarkService(ctx)`; `.create(offset_s=0.0, activity=None, note='', source='dashboard', t_pressed=None, replay=False) -> Mark` (writes `marks.jsonl`, assessment text, links an episode, schedules `marks/<id>.json` snapshot after 30 s); `.snapshot(mark_id) -> Optional[dict]`; `.stop(timeout)` | server |
| `engine.health` | `refresh(state, now=None, session=True) -> {"now", "session"}` (the ticker calls it every 5 s); `window_health`, `session_health`, `score` | ticker, report |
| `engine.rollup` | `stats(state, window, activity)` (exists) | server, report |
| `server.series` | `build_series(ctx_or_state, store, t_from, t_to, res, target_ids=None) -> dict` (= `GET /api/series` body; RAM rings first, `rollups.jsonl` for older ranges) | server, report |
| `server.http` | `serve(ctx) -> server` with `.stop(timeout)`; sets `state.port` | app |
| `collectors.docsis` | `DocsisCollector(ctx)`; `.refresh() -> bool`, `.recent(n=20) -> dict` (= `GET /api/docsis` body); `dump_cli(cfg) -> int` | server, app |
| `collectors.igd` | `IgdCollector(ctx)`; `.status() -> dict` (= `GET /api/igd` body) | server |
| `loadtest` | `LoadTest(ctx)`; `.start(force=False) -> dict` (raises `LoadTestBusy`/`EpisodeOpen` exceptions defined in the module), `.stop()`, `.status() -> dict` (= `GET /api/loadtest` body); keeps `state.loadtest` updated; `run_cli(cfg) -> int` | server, app |
| `notify` | `Notifier(ctx)`; `.test() -> Tuple[bool, str]`; subscribes to `episode_open/episode_close` via `state.subscribe` | server |
| `keepawake` | `KeepAwake(ctx)` start/stop; sets collector `keepawake` with `method` | app |
| `doctor` | `run_cli(cfg, platform, no_net=False) -> int`, `fast(ctx) -> List[dict]` (sets `state.doctor`, writes `doctor.json`), `selftest() -> int` | app, server |
| `updater` | `run_cli(check_only: bool, root: Path) -> int`, `check_async(ctx)` (sets `state.update`) | app |
| `report.build` | `ReportBuilder(ctx)` start/stop, `.build(final=False) -> Optional[Path]`, `rebuild(session_dir: Path, cfg: dict) -> Path` (offline: re-runs rollups+detection from `samples.bin` when `--report`) | app, server |
| `report.export` | `build_zip(session_dir, pack='full', raw=True, cfg=None) -> bytes`, `export_cli(session_dir, pack, cfg) -> int` | server, app |
| `report.sessions` | `list_sessions(root) -> List[dict]` (= `GET /api/sessions` rows), `session_summary(dir) -> dict`, `rebuild_index(root) -> int` (writes `sessions/index.html`) | server, app |

Missing components are tolerated everywhere: the server returns `503 {"error":"<name> not available","code":"unavailable"}`
when `ctx.component(name)` is None; the report shows "not collected".

### 10.3 Report data blob (`report.html` ⇄ `app.js` static mode)

`laglens/web/report_template.html` is an HTML shell with the placeholders `{{TITLE}}`, `{{STYLE}}` (style.css),
`{{UPLOT_CSS}}`, `{{UPLOT_JS}}`, `{{COMMON_JS}}`, `{{APP_JS}}` and `{{DATA_JSON}}` inside
`<script id="laglens-data" type="application/json">…</script>` (the builder escapes `</` as `<\/`).
`app.js` starts in static mode when `document.getElementById('laglens-data')` exists and renders from that blob
instead of talking to the API. Privacy (`report.build.scrub`, `report.export._scrub_text`, SPEC §9.1 checklist):
secrets → `***`, MACs → `xx:xx:xx:xx:xx:xx`, `v6_prefix`/`prefix6` → three groups + ` (truncated)`, and the EUI-64
interface id of any IPv6 literal (`…:211:22ff:fe33:4455`, the XB7's global address on the v6 path — a MAC in
disguise) → `xxxx:xxff:fexx:xxxx`; the WAN addresses themselves (v4 `ext_ip`, v6 `ext_ip6`) stay.
The blob (built by `report/build.py`) is:

```
{"version", "generated_at", "static": true,
 "session": <session.json document>, "targets": [Target.to_dict()...],
 "state": <GET /api/state body at build time>, "stats": <GET /api/stats?window=session body>,
 "stats_1h": <same for the last hour>,
 "series": <GET /api/series body, res 5, whole session>,
 "events": [...], "episodes": [...full Episode.to_dict() incl. sweep/docsis...], "marks": [...], "tags": [...],
 "raw_slices": {"<episode-or-mark id>": {"from_ms","to_ms","rows":[[ts_ms,id,kind,flags,value_us],...]}}  # ±90 s, ≤ 60 slices
 "path": <GET /api/path body>, "docsis": <GET /api/docsis body or null>, "igd": <GET /api/igd body or null>,
 "loadtests": [...], "doctor": [...], "collectors": {...}, "config": <redacted cfg>,
 "verdict": {...}, "comcast_text": "...", "activity_stats": {"<activity>": <stats targets dict>},
 "hour_heatmap": [{"hour":0,"loss_pct":..,"p95":..,"episodes":..}, ...24],
 "methodology": [ "...strings..." ]}
```

---

## 11. Detection engine (`laglens/engine/{detector,classify,verdict,marks,ticker,health}.py`)

Behaviour follows SPEC_FULL §7, §8.2, §8.4 and BUILD_PLAN §4; this section records the
contract details the other modules rely on. Unit tests: `tests/test_detector*.py`,
`test_classify.py`, `test_matrix.py`, `test_verdict.py`, `test_marks.py`, `test_ticker*.py`,
`test_state_ext.py`; the reusable smoke harness is `tests/helpers_detection.py`
(`Session`, `make_ticker`, `feed`, `run_episode`, `fault`, `ntp_row`: synthetic sample streams
through `State → Ticker/Detector` under a fake clock, with fake tracer/DOCSIS components).

### 11.1 Detector (`Detector(ctx)`, `.step(t)`)

- Runs `second_close_lag_s(cfg)` seconds (3 with the 2000 ms timeout) behind wall time (the
  *edge*) so every sample it looks at has its lost/late verdict. Event and episode times are
  sample (send) times, never tick times.
- Stages per tick, each guarded (one failing stage never stops the others; `detector.errors`
  counts): notes → baselines (every 5 s, rolling 10 min p50/MAD/p95 + baseline jitter; the
  session p50 every 60 s) → symptoms per enabled target → `host_stall` → hop corroboration →
  `xb7_reset` → event closing → episodes.
- Symptoms and their end rules are the SPEC §7.2 table. Loss events fire after 15 s, latency
  and jitter after `cfg.warmup_s` **and** ≥ 20 baseline samples. `F_STALL` and `F_LOADTEST`
  samples never make a latency spike or jitter (they still count for loss). Ping-binary targets
  get +1 on the consecutive counts and +1 interval on the windows.
- Notes → events: `SEVERITY_BY_NOTE` fixes the severity per type; the same `(type, target)`
  within `RATE_LIMIT_BY_NOTE` (default 5 s) is folded into the previous event (`peak.count`).
  `probe_error`, `dns_fail`, `tcp_timeout` and `cdn_slow` notes share one per-target limiter with
  the detector's own sample-derived rule (`NOTE_SHARED_LIMITS`: 60/30/30/120 s), so a probe that
  raises its own note and the detector never produce the symptom twice. `peak.gap_s|dur_s`
  gives a note a span; `peak.source` becomes `Event.source`.
- Attachment: events within ±5 s of an episode span become members (`Episode.events`);
  `docsis_*` events within ±60 s become correlations in `Episode.docsis = {"events": [...],
  "log_lines": [...]}` (pre/post uncorrectables are **not** filled by the detector, see
  `docs/notes/detection.md`). A closed episode is reclassified and re-written when a host-tag or
  DOCSIS event arrives late.
- Hop symptoms (`isp_hop`, `mid_hop` roles) are opened at severity 1 with `peak.base_severity`
  and `peak.corroborated=False`; they are upgraded (and re-published) when a deeper target shows
  a severity ≥ 2 symptom in the same or the next 250 ms slot (two deeper targets when
  `target.extra["rate_limit_suspected"]`). Uncorroborated hop symptoms never open an episode.
- Episodes: open on a severity ≥ 2 symptom on a non-hop target (or a corroborated hop), join
  while the gap since the last symptom is < 5 s, **register** (id, `state.add_episode` →
  `episode_open`, `episodes.jsonl` row, tracer sweep, DOCSIS refresh, mark linking) once the
  symptom span reaches 1.5 s, re-classify + `episode_update` every 10 s or when dirty, close
  after 10 s of quiet (`episode_close`, `dur_s`, `state.matrix` accumulated), split at 10 min,
  and collapse into one `subclass="unstable_period"` episode (60 s quiet rule) when more than
  30 episodes opened in 10 min. Shorter spans are blips: `state.blips += 1`, members get
  `peak.blip = True`, nothing is published or stored as an episode.
- Load tests: symptoms during `state.loadtest.running` (or on `F_LOADTEST` samples) carry
  `peak.loadtest = True`; an episode made of them is classified `loadtest` (rule 3) and opens
  **without** tracer sweep / DOCSIS refresh. `verdict` and `health` exclude it.
- `xb7_reset` (severity 4, target gw4): internet targets all dark ≥ 15 s while gw4 answers, or
  gw4 dark ≥ 20 s then recovery, corroborated within 60 s by `link_flap`, `route_change`,
  `wan_ip_change`, `docsis_reboot` or an IGD/DOCSIS `uptime_s` drop in the latest rows.
- Side effects on open go through `ctx.component("tracer").sweep("episode")` and
  `ctx.component("docsis").refresh()` (both optional, both guarded); the IGD latest row seeds
  `Episode.wan`. Marks within ±60 s of the span are linked on register and on close.
- `finalize(t)` closes open events and the open episode (shutdown / replay).

### 11.2 Classification (`classify(episode, ctx, now=None)`)

Rules run in SPEC §7.6 order (rule 12 `nat_stateful` omitted); first full match wins.
Features come from the raw ring (episode window vs the 10 min before it), the slot bitmasks
(matrix + locus, `MATRIX_MAX_ID` ids, off-grid targets excluded and named in the sentence), the
`ntp` 5 s rows + latest row (`direction`/`share`, per-server `d_offset`/`d_rtt`), `iface` /
`igd` / `wan` rows (host tx, trusted WAN tx), `state.host["wifi"]`, `state.xbox`, the
`state.loadtest` window and the events within ±60 s. Two refinements over the letter of the
table: rule 8 (`docsis_access`) yields to rule 10 when the episode is the upload-saturation
pattern (uniform inflation, no loss, upload evidence), and rule 11 (`ipv4_only`/`ipv6_only`)
needs the *family* affected (≥ 2 of its targets, or all it has) so one lost anycast is rule 14.
Confidence = base + boosts, −0.2 with a single independent signal, capped at 0.95, banded by
`confidence_band`. `alt` = the best near miss among the other rules (`{"class",
"why_rejected"}`; a later full match says "outranked by …"). `comcast_relevant = not
host_tags` (§7.3). Informational classes: `INFO_CLASSES = {xb7_cpu, hop_rate_limit}`.

### 11.3 Verdict (`compute_verdict`, `comcast_text`, `headline`)

`state.verdict = {"text", "confidence", "top": [{"class","share","episodes","seconds"}],
"comcast", "next": [{"try","confirm_if","refute_if"}] (≤ 3), "marks": {"total","linked"}}`.
Tally = Σ(duration × confidence) over registered episodes ≥ 1.5 s, excluding `loadtest`,
`xb7_cpu`, `hop_rate_limit`; the Comcast-side tally and the Tell-Comcast block honour
`comcast_relevant`. Text = three sentences (what/how often with numbers, where and why with
hedging by band, how the marks line up incl. the < 50 % rule) + persistent findings.
`comcast_text` writes `comcast_evidence.txt` (`write=False` to skip) with a header
(gateway/firmware, WAN IP, truncated v6 prefix, probe host/link), the local-time episode table
(time, dur, class/subclass, gw / Comcast hop / internet loss, direction, DOCSIS correlation),
the DOCSIS snapshot line, the XB7 log clock offset and the request sentence. `headline` →
`{"answer": yes_comcast|yes_home|no_sign|unknown, "text", "action"}`.

### 11.4 Marks (`MarkService`)

`create()` → `t_est = (t_pressed or now) − offset_s`; assessment over `[t_est−10 s, t_est+2 s]`
in the §8.4 sentence styles (`NULL_ASSESSMENT` when nothing is abnormal); nearest episode within
±60 s linked (episode row re-appended, `episode_update` published); `marks.jsonl` row; a
`mark` note (severity 1 timeline event); `marks/<id>.json` written by a daemon thread after
`snapshot_delay_s` (30 s) with raw rows `[ts_ms,id,kind,flags,value]` for `t_est−120 … +30 s`,
the 1 s rollups and the iface/wan/wifi/dns/docsis 5 s rows; `mark.snapshot` set and `mark`
re-published. `snapshot(id)` returns `None` until written.

### 11.5 Ticker and health

Stages per second (each guarded): monitor gap (tick > 2 s late → `monitor_gap` note, `GAP`
pill for 30 s) → `close_second` → pending 5 s windows (`rollups.jsonl` rows, `rollup5`) →
`Detector.step` → verdict (every 30 s, on episode close, published as `verdict` on change) →
`w5m_for` → health (every 5 s; session score every 30 s) → status/pill/headline
(`LOADTEST` > `GAP` > `TROUBLE` > `RECENT` (10 min) > `WARMUP` > `DEGRADED` > `OK`; a
degraded/disabled collector whose reason is not a configuration choice adds a
`\nDegraded: name (reason)` sub-line) → `publish("tick", state.tick_payload())`.
`health.refresh` computes the §7.8 score over the reference set (four internet anycasts +
direct `isp_hop4`) excluding `F_STALL`/`F_LOADTEST` samples; `state.health = {"now", "session"}`.

### 11.6 Offline rebuild

`Ticker(ctx).replay(samples)` (samples from `store.read_samples()` or `iter_samples()`, time
ordered; `ctx.store` may be `None`) ticks every wall second from the sample timestamps, so
`--report DIR` gets the same rollups, events, episodes, verdict and health as the live run
(DOCSIS/host notes are not replayed; `events.jsonl` on disk keeps them).
