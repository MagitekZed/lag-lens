"""Session storage: directory layout, writer thread, binary samples, JSONL.

One :class:`Store` per session directory (``sessions/<YYYYMMDD-HHMMSS>/``).
All appends go through a single writer thread fed by a queue (flush every
1 s, ``fsync`` every 5 s on ``samples.bin`` and ``events.jsonl``); atomic
files (``session.json``, ``targets.json``, ``report.html``) are written
directly with temp + ``os.replace``.

Readers tolerate a torn trailing record/line, and a truncated ``.gz``
yields every whole record that could be decompressed before the cut.
``samples.bin`` and ``host.jsonl`` are gzipped on :meth:`Store.stop`; the
readers handle both forms and ``--resume`` inflates them again so appends
continue. On resume the files are **realigned** first: ``samples.bin`` is
truncated to a whole number of records and a ``.jsonl`` ending in a torn
line is cut back to its last newline, so new appends never glue onto torn
bytes. :meth:`Store.stop` is a hard barrier: later appends are dropped.

Disk caps (``cfg['disk']``): ``samples_cap_mb`` stops sample writes (JSONL
continues); ``session_cap_mb`` and ``min_free_mb`` stop all writes. The
current situation is mirrored into ``state.disk`` and the ``store``
collector status.
"""
import gzip
import json
import logging
import os
import queue
import secrets
import shutil
import stat
import struct
import threading
import time
import zlib
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

from laglens.state import Sample

log = logging.getLogger("laglens.store")

SAMPLE_STRUCT = struct.Struct("<QBBHIi")
SAMPLE_SIZE = SAMPLE_STRUCT.size  # 20
assert SAMPLE_SIZE == 20

JSONL_NAMES = frozenset(
    {"rollups", "events", "episodes", "marks", "tags", "path", "xb7", "igd", "host", "loadtests", "docs"}
)
GZIP_ON_STOP = ("samples.bin", "host.jsonl")
FSYNC_FILES = ("samples.bin", "events.jsonl")
FLUSH_S = 1.0
FSYNC_S = 5.0
#: A full ``os.walk`` of the session dir for the size cap runs this often; in
#: between only the files the writer touched are re-stat'ed.
FULL_WALK_S = 60.0
#: After a failed write all writing stays off (reason kept) for this long,
#: then one retry is allowed; a success clears the latch, a failure re-latches.
WRITE_RETRY_S = 30.0
GZ_READ_CHUNK = 64 * 1024
TOKEN_FILE = "token"
LAST_FILE = ".last"
PID_FILE = "laglens.pid"

_STOP = object()


def pack_sample(s: Sample) -> bytes:
    """Pack a :class:`Sample` into the 20-byte ``samples.bin`` record."""
    value = s.value
    if value > 0x7FFFFFFF:
        value = 0x7FFFFFFF
    elif value < -0x80000000:
        value = -0x80000000
    return SAMPLE_STRUCT.pack(
        int(s.ts_ms) & 0xFFFFFFFFFFFFFFFF,
        int(s.target_id) & 0xFF,
        int(s.kind) & 0xFF,
        int(s.flags) & 0xFFFF,
        int(s.seq) & 0xFFFFFFFF,
        value,
    )


def unpack_sample(rec: bytes) -> Tuple[int, int, int, int, int, int]:
    """``(ts_ms, target_id, kind, flags, seq, value)`` from a 20-byte record."""
    return SAMPLE_STRUCT.unpack(rec)


def new_session_id(now: Optional[float] = None) -> str:
    """Local-time session id ``YYYYMMDD-HHMMSS``."""
    dt = datetime.fromtimestamp(time.time() if now is None else now)
    return dt.strftime("%Y%m%d-%H%M%S")


def _iter_gz_chunks(path: Path) -> Iterable[bytes]:
    """Yield decompressed chunks of a gzip file, tolerating a truncated tail.

    Uses ``zlib.decompressobj`` on the raw bytes instead of ``gzip.open`` so
    a file cut mid-stream (crash during ``stop()``) yields everything that
    was decodable before the cut instead of raising ``EOFError`` on the first
    read and losing it all. Corrupt (not merely short) data raises
    ``zlib.error``; multi-member gzip files are handled.
    """
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    with open(path, "rb") as fh:
        while True:
            raw = fh.read(GZ_READ_CHUNK)
            if not raw:
                break
            out = d.decompress(raw)
            if out:
                yield out
            while d.eof and d.unused_data:  # next gzip member
                rest = d.unused_data
                d = zlib.decompressobj(16 + zlib.MAX_WBITS)
                out = d.decompress(rest)
                if out:
                    yield out
    tail = d.flush()
    if tail:
        yield tail


def _iter_chunks(path: Path) -> Optional[Iterable[bytes]]:
    """Chunks of ``path`` or ``path.gz`` (plain first); ``None`` if neither exists."""
    if path.exists():
        def plain() -> Iterable[bytes]:
            with open(path, "rb") as fh:
                while True:
                    chunk = fh.read(GZ_READ_CHUNK)
                    if not chunk:
                        return
                    yield chunk
        return plain()
    gz = path.with_name(path.name + ".gz")
    if gz.exists():
        return _iter_gz_chunks(gz)
    return None


def _inflate(gz: Path, dst: Path, append_existing: bool = False) -> bool:
    """Decompress ``gz`` to ``dst`` atomically (``dst.tmp`` + ``os.replace``) and remove ``gz``.

    With ``append_existing`` the current contents of ``dst`` (a plain file
    that exists next to the ``.gz``, e.g. appends made after ``stop()``) are
    appended after the inflated data, so nothing is orphaned. A truncated
    ``.gz`` inflates to what was decodable; a failure leaves no partial
    ``dst`` behind.
    """
    tmp = dst.with_name(dst.name + ".inflate.tmp")
    try:
        with open(tmp, "wb") as out:
            for chunk in _iter_gz_chunks(gz):
                out.write(chunk)
            if append_existing and dst.exists():
                with open(dst, "rb") as old:
                    shutil.copyfileobj(old, out, 1024 * 1024)
            out.flush()
            try:
                os.fsync(out.fileno())
            except OSError:
                pass
        os.replace(tmp, dst)
        gz.unlink()
        return True
    except (OSError, EOFError, zlib.error) as exc:
        log.warning("cannot inflate %s: %s", gz, exc)
        try:
            tmp.unlink()
        except OSError:
            pass
        return False


def _realign_session_files(session_dir: Path) -> List[str]:
    """Cut torn tails so appends after a crash start on a record/line boundary.

    ``samples.bin`` is truncated to a multiple of ``SAMPLE_SIZE``; every
    ``*.jsonl`` whose last byte is not a newline is truncated back to its last
    newline (the torn line was unreadable anyway). Returns the names fixed.
    """
    fixed: List[str] = []
    p = session_dir / "samples.bin"
    try:
        if p.exists():
            size = p.stat().st_size
            if size % SAMPLE_SIZE:
                with open(p, "r+b") as fh:
                    fh.truncate(size - size % SAMPLE_SIZE)
                fixed.append(p.name)
    except OSError as exc:
        log.warning("cannot realign %s: %s", p, exc)
    for p in sorted(session_dir.glob("*.jsonl")):
        try:
            size = p.stat().st_size
            if size == 0:
                continue
            with open(p, "r+b") as fh:
                fh.seek(size - 1)
                if fh.read(1) == b"\n":
                    continue
                # walk back to the previous newline
                keep = 0
                pos = size
                while pos > 0:
                    step = min(4096, pos)
                    pos -= step
                    fh.seek(pos)
                    buf = fh.read(step)
                    idx = buf.rfind(b"\n")
                    if idx >= 0:
                        keep = pos + idx + 1
                        break
                fh.truncate(keep)
            fixed.append(p.name)
        except OSError as exc:
            log.warning("cannot realign %s: %s", p, exc)
    if fixed:
        log.warning("resume: torn tail removed from %s", ", ".join(fixed))
    return fixed


def _compress(src: Path) -> bool:
    """Gzip ``src`` to ``src.gz`` and remove ``src`` on success."""
    dst = src.with_name(src.name + ".gz")
    tmp = src.with_name(src.name + ".gz.tmp")
    try:
        with open(src, "rb") as f, gzip.open(tmp, "wb", compresslevel=6) as g:
            shutil.copyfileobj(f, g, 1024 * 1024)
        os.replace(tmp, dst)
        src.unlink()
        return True
    except OSError as exc:
        log.warning("cannot gzip %s: %s", src, exc)
        try:
            tmp.unlink()
        except OSError:
            pass
        return False


class Store:
    """Session directory writer/reader (BUILD_PLAN §3.2)."""

    def __init__(
        self,
        session_dir: Union[str, Path],
        cfg: dict,
        resume: bool = False,
        state: Optional[Any] = None,
        disk_usage: Optional[Callable[[str], Any]] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.dir = Path(session_dir)
        self.id = self.dir.name
        self.cfg = cfg or {}
        self.resume = resume
        self.state = state
        self._disk_usage = disk_usage or shutil.disk_usage
        self._clock = clock
        disk = self.cfg.get("disk", {}) if isinstance(self.cfg, dict) else {}
        self.samples_cap_mb = float(disk.get("samples_cap_mb", 400))
        self.session_cap_mb = float(disk.get("session_cap_mb", 500))
        self.min_free_mb = float(disk.get("min_free_mb", 500))

        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "marks").mkdir(exist_ok=True)
        (self.dir / "xb7_raw").mkdir(exist_ok=True)
        if resume:
            for name in GZIP_ON_STOP:
                gz = self.dir / (name + ".gz")
                plain = self.dir / name
                if gz.exists():
                    if plain.exists():
                        log.warning("resume: both %s and %s exist; merging (.gz first, then plain)", gz.name, name)
                    _inflate(gz, plain, append_existing=True)
            _realign_session_files(self.dir)

        self._q: "queue.Queue[Any]" = queue.Queue()
        self._thread: Optional[threading.Thread] = None
        self._files: Dict[str, Any] = {}
        self._lock = threading.Lock()
        self._started = False
        self._stopped = False
        self.samples_writing = True
        self.writing = True
        self.disk: Dict[str, Any] = {
            "free_mb": None,
            "session_mb": 0,
            "samples_mb": 0,
            "writing": True,
            "samples_writing": True,
            "reason": None,
        }
        self.last_read_truncated = False
        self._token: Optional[str] = None
        #: Latched by a failed write (cleared by the next successful one);
        #: ``check_caps`` keeps ``writing=False`` while it is set.
        self._write_failed: Optional[str] = None
        self._write_failed_at: float = 0.0
        self._size_cache: Dict[str, int] = {}
        self._last_walk: Optional[float] = None
        self.check_caps()

    # ----------------------------------------------------------- creation
    @classmethod
    def create(cls, sessions_root: Union[str, Path], cfg: dict, now: Optional[float] = None, **kw) -> "Store":
        """Create a new session directory under ``sessions_root`` (unique id)."""
        root = Path(sessions_root)
        root.mkdir(parents=True, exist_ok=True)
        base = new_session_id(now)
        sid = base
        n = 1
        while (root / sid).exists():
            sid = "%s-%d" % (base, n)
            n += 1
        return cls(root / sid, cfg, resume=False, **kw)

    def path(self, name: str) -> Path:
        """Absolute path of a file inside the session directory."""
        return self.dir / name

    # --------------------------------------------------------------- token
    def ensure_token(self) -> str:
        """Create ``token`` (0600, ``secrets.token_urlsafe``) if absent; return it."""
        if self._token:
            return self._token
        p = self.dir / TOKEN_FILE
        try:
            if p.exists():
                tok = p.read_text(encoding="utf-8").strip()
                if tok:
                    self._token = tok
                    try:
                        os.chmod(str(p), stat.S_IRUSR | stat.S_IWUSR)
                    except OSError:
                        pass
                    return tok
            tok = secrets.token_urlsafe(24)
            fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(tok + "\n")
            os.chmod(str(p), stat.S_IRUSR | stat.S_IWUSR)
            self._token = tok
            return tok
        except OSError as exc:
            log.warning("cannot create token file: %s", exc)
            self._token = secrets.token_urlsafe(24)
            return self._token

    @property
    def token(self) -> str:
        return self.ensure_token()

    # ------------------------------------------------------------- writing
    def start(self) -> None:
        """Start the writer thread (idempotent)."""
        with self._lock:
            if self._started:
                return
            self._started = True
            self._stopped = False
        self._thread = threading.Thread(target=self._writer, name="writer", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 15.0) -> None:
        """Drain the queue, close files, gzip ``samples.bin`` and ``host.jsonl``."""
        with self._lock:
            if self._stopped:
                return
            self._stopped = True
        if self._started and self._thread is not None:
            self._q.put(_STOP)
            self._thread.join(timeout)
        else:
            self._drain()
        self._close_all()
        for name in GZIP_ON_STOP:
            p = self.dir / name
            if p.exists() and p.stat().st_size > 0:
                _compress(p)
            elif p.exists():
                try:
                    p.unlink()
                except OSError:
                    pass

    def append_sample(self, s: Sample) -> None:
        """Queue a sample for ``samples.bin`` (dropped while sample writing is capped or after ``stop()``)."""
        if self._stopped:
            log.debug("append_sample after stop() dropped")
            return
        if not self.samples_writing or not self.writing:
            return
        self._q.put(("samples.bin", pack_sample(s)))

    def append_json(self, name: str, obj: dict) -> None:
        """Queue one JSON object as a line of ``<name>.jsonl`` (dropped after ``stop()``)."""
        if name not in JSONL_NAMES:
            raise ValueError("unknown JSONL file %r" % name)
        if self._stopped:
            log.warning("append_json(%s) after stop() dropped", name)
            return
        if not self.writing:
            return
        line = json.dumps(obj, separators=(",", ":"), ensure_ascii=False, default=_json_default) + "\n"
        self._q.put((name + ".jsonl", line.encode("utf-8")))

    def write_atomic(self, name: str, data: Union[bytes, str]) -> Path:
        """Write ``name`` via temp file + ``os.replace`` (subdirectories allowed)."""
        p = self.dir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".tmp-%d" % threading.get_ident())
        if isinstance(data, str):
            data = data.encode("utf-8")
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        os.replace(tmp, p)
        try:
            self._size_cache[os.path.relpath(str(p), str(self.dir))] = len(data)
        except ValueError:
            pass
        return p

    def write_json_atomic(self, name: str, obj: Any, indent: Optional[int] = 1) -> Path:
        return self.write_atomic(name, json.dumps(obj, indent=indent, ensure_ascii=False, default=_json_default) + "\n")

    def flush(self) -> None:
        """Block until everything queued so far has reached the OS buffers."""
        if self._started and not self._stopped and self._thread is not None and self._thread.is_alive():
            done = threading.Event()
            self._q.put(("__flush__", done))
            done.wait(5.0)
        else:
            self._drain()
            for fh in self._files.values():
                try:
                    fh.flush()
                except OSError:
                    pass

    # ----------------------------------------------------- writer internals
    def _fh(self, name: str):
        fh = self._files.get(name)
        if fh is None:
            fh = open(self.dir / name, "ab")
            self._files[name] = fh
        return fh

    def _handle(self, item: Any) -> None:
        name, payload = item
        if name == "__flush__":
            for fh in self._files.values():
                try:
                    fh.flush()
                except OSError:
                    pass
            payload.set()
            return
        if name == "samples.bin" and not self.samples_writing:
            return
        if not self.writing:
            return
        try:
            self._fh(name).write(payload)
            if self._write_failed is not None:
                log.info("write to %s succeeded again; resuming", name)
                self._write_failed = None
                self.check_caps()
        except OSError as exc:
            if self._write_failed is None:
                log.error("write to %s failed: %s (writing paused, retry in %ds)", name, exc, int(WRITE_RETRY_S))
            self._write_failed = "write failed: %s" % exc
            self._write_failed_at = self._clock()
            self._set_writing(False, self._write_failed)

    def _drain(self) -> None:
        while True:
            try:
                item = self._q.get_nowait()
            except queue.Empty:
                return
            if item is _STOP:
                continue
            self._handle(item)

    def _flush_all(self) -> None:
        for fh in self._files.values():
            try:
                fh.flush()
            except OSError:
                pass

    def _fsync_some(self) -> None:
        for name in FSYNC_FILES:
            fh = self._files.get(name)
            if fh is not None:
                try:
                    fh.flush()
                    os.fsync(fh.fileno())
                except OSError:
                    pass

    def _close_all(self) -> None:
        self._flush_all()
        for fh in self._files.values():
            try:
                fh.close()
            except OSError:
                pass
        self._files.clear()

    def _writer(self) -> None:
        last_flush = self._clock()
        last_fsync = last_flush
        while True:
            try:
                item = self._q.get(timeout=0.25)
            except queue.Empty:
                item = None
            if item is _STOP:
                self._drain()
                self._flush_all()
                self._fsync_some()
                return
            if item is not None:
                try:
                    self._handle(item)
                except Exception:  # noqa: BLE001 - the writer must survive
                    log.exception("writer error")
            now = self._clock()
            if now - last_flush >= FLUSH_S:
                self._flush_all()
                last_flush = now
            if now - last_fsync >= FSYNC_S:
                self._fsync_some()
                try:
                    self.check_caps()
                except Exception:  # noqa: BLE001
                    log.exception("cap check failed")
                last_fsync = now

    # ----------------------------------------------------------------- caps
    def _dir_size_mb(self) -> float:
        """Session directory size from a cache: full walk every ``FULL_WALK_S``,
        otherwise only the files the writer has open (and ``write_atomic``
        targets) are re-measured, so ``xb7_raw/`` with thousands of pages is
        not walked every 5 s on the writer thread."""
        now = self._clock()
        if self._last_walk is None or now - self._last_walk >= FULL_WALK_S:
            cache: Dict[str, int] = {}
            for root, _dirs, files in os.walk(self.dir):
                for f in files:
                    p = os.path.join(root, f)
                    try:
                        cache[os.path.relpath(p, str(self.dir))] = os.path.getsize(p)
                    except OSError:
                        pass
            self._size_cache = cache
            self._last_walk = now
        else:
            for name, fh in list(self._files.items()):
                try:
                    self._size_cache[name] = os.fstat(fh.fileno()).st_size
                except (OSError, ValueError):
                    pass
        return sum(self._size_cache.values()) / (1024.0 * 1024.0)

    def _set_writing(self, writing: bool, reason: Optional[str]) -> None:
        self.writing = writing
        self.disk["writing"] = writing
        if reason:
            self.disk["reason"] = reason
        if self.state is not None:
            try:
                with self.state.lock:
                    self.state.disk = dict(self.disk)
                self.state.set_collector("store", "ok" if (writing and self.samples_writing) else "degraded", reason=reason)
            except Exception:  # noqa: BLE001
                log.exception("cannot update state.disk")

    def check_caps(self) -> Dict[str, Any]:
        """Measure disk usage, apply the caps, update ``state.disk``; returns ``self.disk``."""
        try:
            free_mb = self._disk_usage(str(self.dir)).free / (1024.0 * 1024.0)
        except (OSError, AttributeError):
            free_mb = None
        samples_mb = 0.0
        p = self.dir / "samples.bin"
        try:
            if p.exists():
                samples_mb = p.stat().st_size / (1024.0 * 1024.0)
        except OSError:
            pass
        session_mb = self._dir_size_mb()
        self.disk["free_mb"] = None if free_mb is None else round(free_mb, 1)
        self.disk["samples_mb"] = round(samples_mb, 1)
        self.disk["session_mb"] = round(session_mb, 1)
        reason = None
        writing = True
        samples_writing = True
        if self._write_failed is not None and self._clock() - self._write_failed_at >= WRITE_RETRY_S:
            log.info("store: retrying writes after %s", self._write_failed)
            self._write_failed = None
        if self._write_failed is not None:
            writing = False
            reason = self._write_failed
        elif free_mb is not None and free_mb < self.min_free_mb:
            writing = False
            reason = "free space below %d MB (%d MB free): writing stopped" % (self.min_free_mb, free_mb)
        elif session_mb >= self.session_cap_mb:
            writing = False
            reason = "session directory reached %d MB cap: writing stopped" % self.session_cap_mb
        if samples_mb >= self.samples_cap_mb:
            samples_writing = False
            if reason is None:
                reason = "samples.bin reached %d MB cap: raw samples no longer written" % self.samples_cap_mb
        changed = (writing != self.writing) or (samples_writing != self.samples_writing)
        self.writing = writing
        self.samples_writing = samples_writing
        self.disk["writing"] = writing
        self.disk["samples_writing"] = samples_writing
        self.disk["reason"] = reason
        if self.state is not None:
            try:
                with self.state.lock:
                    self.state.disk = dict(self.disk)
                if changed or reason:
                    status = "ok" if (writing and samples_writing) else "degraded"
                    self.state.set_collector("store", status, reason=reason)
                elif self.state.collector("store") is None:
                    self.state.set_collector("store", "ok")
            except Exception:  # noqa: BLE001
                log.exception("cannot update state.disk")
        if changed and reason:
            log.warning("store: %s", reason)
        return dict(self.disk)

    # -------------------------------------------------------------- reading
    def read_samples(
        self,
        t_from_ms: Optional[int] = None,
        t_to_ms: Optional[int] = None,
        target_ids: Optional[Iterable[int]] = None,
        max_rows: int = 50000,
    ) -> List[Tuple[int, int, int, int, int, int]]:
        """Read ``samples.bin[.gz]`` as ``(ts_ms, id, kind, flags, seq, value)`` tuples.

        Filters by time (``t_from_ms <= ts < t_to_ms``) and target ids; stops
        after ``max_rows`` and sets :attr:`last_read_truncated`. A torn
        trailing record is ignored.
        """
        self.last_read_truncated = False
        chunks = _iter_chunks(self.dir / "samples.bin")
        if chunks is None:
            return []
        ids = set(target_ids) if target_ids is not None else None
        out: List[Tuple[int, int, int, int, int, int]] = []
        carry = b""
        try:
            for chunk in chunks:
                buf = carry + chunk
                usable = len(buf) - (len(buf) % SAMPLE_SIZE)
                for off in range(0, usable, SAMPLE_SIZE):
                    rec = SAMPLE_STRUCT.unpack_from(buf, off)
                    ts = rec[0]
                    if t_from_ms is not None and ts < t_from_ms:
                        continue
                    if t_to_ms is not None and ts >= t_to_ms:
                        continue
                    if ids is not None and rec[1] not in ids:
                        continue
                    if len(out) >= max_rows:
                        self.last_read_truncated = True
                        return out
                    out.append(rec)
                carry = buf[usable:]
        except (OSError, EOFError, zlib.error) as exc:
            log.warning("samples.bin read stopped early: %s", exc)
        return out

    def iter_samples(self) -> Iterable[Sample]:
        """Yield every record of ``samples.bin[.gz]`` as a :class:`Sample`."""
        for ts, tid, kind, flags, seq, value in self.read_samples(max_rows=1 << 62):
            yield Sample(ts_ms=ts, target_id=tid, kind=kind, flags=flags, seq=seq, value=value)

    def read_json(self, name: str) -> List[dict]:
        """Read ``<name>.jsonl[.gz]``; skips a torn trailing line (and logs other bad lines)."""
        fname = name if name.endswith(".jsonl") else name + ".jsonl"
        chunks = _iter_chunks(self.dir / fname)
        if chunks is None:
            return []
        out: List[dict] = []
        parts: List[bytes] = []
        try:
            for chunk in chunks:
                parts.append(chunk)
        except (OSError, EOFError, zlib.error) as exc:
            log.warning("%s read stopped early: %s", fname, exc)
        data = b"".join(parts)
        lines = data.split(b"\n")
        for i, raw in enumerate(lines):
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                if i >= len(lines) - 2:
                    log.debug("%s: torn trailing line skipped", fname)
                else:
                    log.warning("%s: bad line %d skipped", fname, i + 1)
                continue
            if isinstance(obj, dict):
                out.append(obj)
        return out

    def read_file_json(self, name: str) -> Optional[Any]:
        """Parse a single JSON file (``session.json``, ``targets.json``, ...)."""
        p = self.dir / name
        try:
            with open(p, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def read_targets(self) -> Optional[List[dict]]:
        """The ``targets`` list of ``targets.json`` or ``None``."""
        data = self.read_file_json("targets.json")
        if isinstance(data, dict) and isinstance(data.get("targets"), list):
            return data["targets"]
        return None

    # ---------------------------------------------------------- bookkeeping
    @staticmethod
    def write_last(sessions_root: Union[str, Path], session_dir: Union[str, Path]) -> None:
        """Record ``session_dir`` in ``sessions/.last`` for ``start.sh --resume``."""
        root = Path(sessions_root)
        try:
            root.mkdir(parents=True, exist_ok=True)
            tmp = root / (LAST_FILE + ".tmp")
            tmp.write_text(str(session_dir) + "\n", encoding="utf-8")
            os.replace(tmp, root / LAST_FILE)
        except OSError as exc:
            log.warning("cannot write %s: %s", root / LAST_FILE, exc)

    @staticmethod
    def read_last(sessions_root: Union[str, Path]) -> Optional[str]:
        try:
            v = (Path(sessions_root) / LAST_FILE).read_text(encoding="utf-8").strip()
            return v or None
        except OSError:
            return None

    def sizes(self) -> Dict[str, int]:
        """Byte sizes of the files in the session directory (for reports)."""
        out: Dict[str, int] = {}
        for root, _dirs, files in os.walk(self.dir):
            for f in files:
                p = os.path.join(root, f)
                try:
                    out[os.path.relpath(p, str(self.dir))] = os.path.getsize(p)
                except OSError:
                    pass
        return out


def _json_default(o: Any) -> Any:
    """Serialise dataclasses/sets/Paths that end up in JSONL rows."""
    if hasattr(o, "to_dict"):
        return o.to_dict()
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    if isinstance(o, Path):
        return str(o)
    if isinstance(o, bytes):
        return o.decode("utf-8", "replace")
    raise TypeError("not JSON serialisable: %r" % type(o))


__all__ = [
    "Store", "SAMPLE_STRUCT", "SAMPLE_SIZE", "JSONL_NAMES", "pack_sample", "unpack_sample",
    "new_session_id", "TOKEN_FILE", "LAST_FILE", "PID_FILE",
]
