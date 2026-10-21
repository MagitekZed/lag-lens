"""Configuration: defaults, loading with validation, redaction, first-run copy.

The key set and defaults follow SPEC_FULL §11.1 with the v1 changes from
BUILD_PLAN §3.6 (no ``trains``/``big_packets``/``pmtu``/``pulse``/``peer_url``/
``path.calibrate``; XB7 ``.jst`` pages first; ``docsis.login_paths``;
``hop_rate_hz`` 2).  Unknown keys are logged as warnings and dropped, invalid
values fall back to the default with a warning, ``rate_hz`` is clamped to 1–5.
"""
import copy
import json
import logging
import os
import stat
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

log = logging.getLogger("laglens.config")

DEFAULTS: Dict[str, Any] = {
    "port": 8787,
    "bind": "0.0.0.0",
    "rate_hz": 4,
    "hop_rate_hz": 2,
    "timeout_ms": 2000,
    "late_window_ms": 10000,
    "targets": {
        "v4": ["1.1.1.1", "8.8.8.8"],
        "v6": ["2606:4700:4700::1111", "2001:4860:4860::8888"],
        "xbox_ip": None,
        "xbox_discovery": True,
        "ntp": ["time.cloudflare.com", "time.google.com"],
        "stun": ["stun.cloudflare.com:3478", "stun.l.google.com:19302"],
        "tcp_names": ["xsts.auth.xboxlive.com", "profile.xboxlive.com", "login.live.com"],
        "game_endpoints": [],
        "dns_names": ["xboxlive.com", "hbomax.com", "cloudflare.com"],
    },
    "cdn": {
        "enabled": True,
        "interval_s": 60,
        "urls": [
            "https://speed.cloudflare.com/__down?bytes=262144",
            "https://www.gstatic.com/generate_204",
        ],
    },
    "path": {"discover_interval_s": 1800, "max_ttl": 12, "sweep_on_episode": True},
    "link": {"up_mbps": 25, "down_mbps": 1000},
    "docsis": {
        "url": "http://10.0.0.1",
        "username": "admin",
        "password": None,
        "interval_s": 60,
        "pages": [
            "/network_setup.jst",
            "/connection_status.jst",
            "/troubleshooting_logs.jst",
            "/at_a_glance.jst",
            "/hardware.jst",
            "/network_setup.jsp",
            "/connection_status.jsp",
            "/troubleshooting_logs.jsp",
        ],
        "login_paths": ["/check.jst", "/check.jsp"],
        "save_raw": True,
    },
    "igd": {
        "enabled": True,
        "verify_upload": True,
        "counter_interval_s": 2,
        "status_interval_s": 30,
        "mappings_interval_s": 300,
    },
    "wifi": {"enabled": "auto", "interval_s": 5},
    # Plex mode: watch the Plex server and its players on the home network while the "Now:" activity is
    # Plex. ``token`` is the X-Plex-Token (a secret, like docsis.password); ``players`` are extra player
    # addresses ("ip" or "ip=name").
    "plex": {"server": None, "token": None, "players": [], "interval_s": 5},
    "notify": {
        "ntfy_topic": None,
        "webhook_url": None,
        "min_confidence": "medium",
        "batch_s": 120,
    },
    "loadtest": {
        "enabled": True,
        "phase_s": 20,
        "threads": 4,
        "nightly": False,
        "nightly_at": "04:00",
    },
    "disk": {
        "session_cap_mb": 500,
        "total_cap_mb": 2048,
        "samples_cap_mb": 400,
        "min_free_mb": 500,
        "allow_prune": False,
    },
    "rotate_hours": 24,
    "warmup_s": 60,
    "activities": ["idle", "bf6", "rocket_league", "hbo_max", "plex", "other"],
    "update_check": True,
    "open_browser": True,
    "label": None,
}

#: Keys whose default is ``None`` and which accept a string.
_OPTIONAL_STR_KEYS = {
    "targets.xbox_ip",
    "docsis.password",
    "notify.ntfy_topic",
    "notify.webhook_url",
    "plex.server",
    "plex.token",
    "label",
}

#: Keys that accept either a bool or the string "auto".
_AUTO_BOOL_KEYS = {"wifi.enabled"}

#: Key names whose values are secrets (redacted wherever config is shown).
SECRET_KEY_NAMES = ("password", "secret", "token")

#: Numeric clamps: dotted key -> (min, max).
_CLAMPS: Dict[str, Tuple[float, float]] = {
    "rate_hz": (1, 5),
    "hop_rate_hz": (1, 5),
    "port": (1, 65535),
    "timeout_ms": (100, 60000),
    "late_window_ms": (1000, 120000),
    "warmup_s": (0, 3600),
    "rotate_hours": (1, 24 * 30),
}

ConfigDict = Dict[str, Any]


def deep_merge(base: ConfigDict, over: ConfigDict) -> ConfigDict:
    """Return a new dict with ``over`` merged into ``base`` recursively.

    Dict values are merged key by key; any other value in ``over`` replaces the
    one in ``base``. Neither input is modified.
    """
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def expand_dotted(overrides: Optional[Dict[str, Any]]) -> ConfigDict:
    """Turn ``{"docsis.password": "x", "port": 1}`` into a nested dict."""
    out: ConfigDict = {}
    if not overrides:
        return out
    for key, value in overrides.items():
        parts = key.split(".")
        cur = out
        for p in parts[:-1]:
            nxt = cur.get(p)
            if not isinstance(nxt, dict):
                nxt = {}
                cur[p] = nxt
            cur = nxt
        cur[parts[-1]] = value
    return out


def _walk_unknown(user: ConfigDict, defaults: ConfigDict, prefix: str = "") -> List[str]:
    """List dotted keys present in ``user`` but absent from ``defaults``."""
    unknown: List[str] = []
    for k, v in user.items():
        dotted = prefix + k
        if k not in defaults:
            unknown.append(dotted)
            continue
        if isinstance(defaults[k], dict):
            if isinstance(v, dict):
                unknown.extend(_walk_unknown(v, defaults[k], dotted + "."))
    return unknown


def _drop_unknown(user: ConfigDict, defaults: ConfigDict) -> ConfigDict:
    out: ConfigDict = {}
    for k, v in user.items():
        if k not in defaults:
            continue
        if isinstance(defaults[k], dict) and isinstance(v, dict):
            out[k] = _drop_unknown(v, defaults[k])
        else:
            out[k] = v
    return out


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _validate(cfg: ConfigDict, defaults: ConfigDict, warnings: List[str], prefix: str = "") -> None:
    """Replace values whose type does not match the default (in place)."""
    for k, dflt in defaults.items():
        dotted = prefix + k
        if k not in cfg:
            cfg[k] = copy.deepcopy(dflt)
            continue
        v = cfg[k]
        if isinstance(dflt, dict):
            if not isinstance(v, dict):
                warnings.append("%s: expected an object, using defaults" % dotted)
                cfg[k] = copy.deepcopy(dflt)
            else:
                _validate(v, dflt, warnings, dotted + ".")
            continue
        ok = True
        if dotted in _AUTO_BOOL_KEYS:
            ok = isinstance(v, bool) or v == "auto"
        elif dotted in _OPTIONAL_STR_KEYS:
            ok = v is None or isinstance(v, str)
        elif isinstance(dflt, bool):
            ok = isinstance(v, bool)
        elif _is_number(dflt):
            ok = _is_number(v)
        elif isinstance(dflt, str):
            ok = isinstance(v, str)
        elif isinstance(dflt, list):
            ok = isinstance(v, list)
        if not ok:
            warnings.append("%s: invalid value %r, using default %r" % (dotted, v, dflt))
            cfg[k] = copy.deepcopy(dflt)
            continue
        clamp = _CLAMPS.get(dotted)
        if clamp is not None and _is_number(v):
            lo, hi = clamp
            if v < lo or v > hi:
                nv = min(max(v, lo), hi)
                warnings.append("%s: %r clamped to %r" % (dotted, v, nv))
                cfg[k] = nv


def load_config(
    path: Optional[Union[str, Path]] = None,
    overrides: Optional[Dict[str, Any]] = None,
) -> ConfigDict:
    """Load ``config.json`` (if present) merged over :data:`DEFAULTS`.

    ``overrides`` (CLI flags) are applied last; keys may be dotted
    (``"targets.xbox_ip"``) or nested dicts. Unknown keys are warned about and
    dropped; invalid values revert to the default; ``rate_hz`` and
    ``hop_rate_hz`` are clamped to 1–5. A missing or unreadable file yields the
    defaults. Never raises on bad input.
    """
    warnings: List[str] = []
    user: ConfigDict = {}
    if path is not None:
        p = Path(path)
        if p.exists():
            try:
                with open(p, "r", encoding="utf-8") as fh:
                    loaded = json.load(fh)
                if isinstance(loaded, dict):
                    user = loaded
                else:
                    warnings.append("%s: top level is not an object; ignoring file" % p)
            except (OSError, ValueError) as exc:
                warnings.append("%s: cannot read config (%s); using defaults" % (p, exc))
    ov = expand_dotted(overrides) if overrides else {}
    merged_user = deep_merge(user, ov) if ov else user
    for key in _walk_unknown(merged_user, DEFAULTS):
        warnings.append("unknown config key %r ignored" % key)
    cfg = deep_merge(DEFAULTS, _drop_unknown(merged_user, DEFAULTS))
    _validate(cfg, DEFAULTS, warnings)
    for w in warnings:
        log.warning("config: %s", w)
    cfg["_warnings"] = warnings  # informational; not a config key
    return cfg


def _redact_value(key: str, value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _redact_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(key, v) for v in value]
    lk = key.lower()
    if any(s in lk for s in SECRET_KEY_NAMES) and value not in (None, ""):
        return "***"
    return value


def redact(cfg: ConfigDict) -> ConfigDict:
    """Return a deep copy of ``cfg`` with every secret replaced by ``"***"``.

    Secrets are values of keys whose name contains ``password``, ``secret`` or
    ``token`` (at any depth). ``None``/empty values are left as-is so a report
    can show that no password was configured.
    """
    return {k: _redact_value(k, v) for k, v in copy.deepcopy(cfg).items()}


def has_secret(cfg: ConfigDict) -> bool:
    """True when the config contains a non-empty secret value."""
    def walk(key: str, value: Any) -> bool:
        if isinstance(value, dict):
            return any(walk(k, v) for k, v in value.items())
        if isinstance(value, list):
            return any(walk(key, v) for v in value)
        lk = key.lower()
        return any(s in lk for s in SECRET_KEY_NAMES) and value not in (None, "")
    return any(walk(k, v) for k, v in cfg.items())


def _example_path(path: Path) -> Optional[Path]:
    """Locate ``config.example.json``: next to the target, then the repo root."""
    candidates = [
        path.parent / "config.example.json",
        Path(__file__).resolve().parent.parent / "config.example.json",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def ensure_config_file(path: Union[str, Path]) -> Path:
    """Create ``config.json`` from ``config.example.json`` on first run.

    When no example file can be found, the defaults are written instead. If the
    resulting file holds a secret (for example ``docsis.password``) its mode is
    set to ``0600``. Returns the config path. Failures are logged, not raised.
    """
    p = Path(path)
    if not p.exists():
        example = _example_path(p)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            if example is not None:
                p.write_bytes(example.read_bytes())
                log.info("config: created %s from %s", p, example.name)
            else:
                with open(p, "w", encoding="utf-8") as fh:
                    json.dump(DEFAULTS, fh, indent=2)
                    fh.write("\n")
                log.info("config: created %s with defaults", p)
        except OSError as exc:
            log.warning("config: cannot create %s: %s", p, exc)
            return p
    try:
        with open(p, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and has_secret(data):
            protect_file(p)
    except (OSError, ValueError):
        pass
    return p


def protect_file(path: Union[str, Path]) -> bool:
    """``chmod 600`` the file; returns True on success (no-op on Windows)."""
    try:
        os.chmod(str(path), stat.S_IRUSR | stat.S_IWUSR)
        return True
    except OSError as exc:
        log.warning("config: cannot chmod 600 %s: %s", path, exc)
        return False


def public(cfg: ConfigDict) -> ConfigDict:
    """Redacted config without internal (``_``-prefixed) keys, for reports."""
    return {k: v for k, v in redact(cfg).items() if not k.startswith("_")}


def save_values(path: Union[str, Path], values: Dict[str, Any]) -> bool:
    """Persist dotted keys (``{"targets.xbox_ip": "10.0.0.23"}``) into the config file.

    The file is re-read as the user wrote it (not the merged defaults), the
    keys are set, and the result is written atomically (``.tmp`` +
    ``os.replace``). A missing file starts from :data:`DEFAULTS`; an
    unreadable one is left alone (``False``) so a hand-edited file is never
    clobbered. The mode is kept at ``0600`` when the file holds a secret or
    already was ``0600``. Returns ``True`` when the file was written.
    """
    p = Path(path)
    data: ConfigDict
    was_private = False
    if p.exists():
        try:
            with open(p, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            was_private = stat.S_IMODE(p.stat().st_mode) & 0o077 == 0
        except (OSError, ValueError) as exc:
            log.warning("config: not saving %s: cannot read %s (%s)", ", ".join(values), p, exc)
            return False
        if not isinstance(loaded, dict):
            log.warning("config: not saving %s: %s is not a JSON object", ", ".join(values), p)
            return False
        data = loaded
    else:
        data = copy.deepcopy(DEFAULTS)
    for key, value in values.items():
        parts = key.split(".")
        cur = data
        for part in parts[:-1]:
            nxt = cur.get(part)
            if not isinstance(nxt, dict):
                nxt = {}
                cur[part] = nxt
            cur = nxt
        cur[parts[-1]] = value
    tmp = p.with_name(p.name + ".tmp")
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
        if was_private or has_secret(data):
            protect_file(tmp)
        os.replace(str(tmp), str(p))
    except OSError as exc:
        log.warning("config: cannot write %s: %s", p, exc)
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        return False
    log.info("config: saved %s to %s", ", ".join("%s=%r" % kv for kv in values.items()), p.name)
    return True


def iter_keys(d: ConfigDict, prefix: str = "") -> Iterable[str]:
    """Yield every dotted key in ``d`` (helper for docs/tests)."""
    for k, v in d.items():
        if isinstance(v, dict):
            for sub in iter_keys(v, prefix + k + "."):
                yield sub
        else:
            yield prefix + k


__all__ = [
    "DEFAULTS",
    "deep_merge",
    "expand_dotted",
    "load_config",
    "redact",
    "has_secret",
    "ensure_config_file",
    "protect_file",
    "public",
    "save_values",
    "iter_keys",
]
