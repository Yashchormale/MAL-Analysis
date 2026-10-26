"""Shared helpers for MAL v4: escaping, entropy, rate limiting, caching."""

from __future__ import annotations

import datetime as dt
import hashlib
import html
import ipaddress
import json
import math
import os
import re
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path


class Raw(str):
    """A string that is already safe HTML (will not be escaped again)."""

    __slots__ = ()


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def esc(value) -> str:
    return html.escape(str(value), quote=True)


def fmt_size(n) -> str:
    try:
        x = float(n)
    except (TypeError, ValueError):
        return str(n)
    for unit in ("B", "KB", "MB", "GB"):
        if x < 1024 or unit == "GB":
            return f"{x:.2f} {unit}" if unit != "B" else f"{int(x)} B"
        x /= 1024
    return f"{n} B"


def unique_keep_order(items):
    seen = set()
    out = []
    for x in items:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def clamp(v, lo=0, hi=100):
    return max(lo, min(hi, v))


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def block_entropy(data: bytes, blocks: int = 96) -> list:
    """Entropy of `blocks` equal slices of the file (for the entropy map)."""
    if not data:
        return []
    blocks = max(1, min(blocks, len(data)))
    step = max(1, len(data) // blocks)
    out = []
    for i in range(0, len(data), step):
        chunk = data[i:i + step]
        if chunk:
            out.append(round(entropy(chunk), 3))
        if len(out) >= blocks:
            break
    return out


def epoch_to_iso(v):
    try:
        if v in (None, "", 0):
            return None
        return dt.datetime.fromtimestamp(int(v), dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OverflowError, OSError, TypeError):
        return None


def defang(value: str) -> str:
    """Make an IOC safe to paste in tickets/chat (hxxp, [.] and [@])."""
    s = str(value)
    s = re.sub(r"^http", "hxxp", s, flags=re.I)
    s = re.sub(r"^ftp://", "fxp://", s, flags=re.I)
    s = s.replace(".", "[.]").replace("@", "[@]")
    return s


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def clean_text(s, limit: int = 300) -> str:
    s = _CTRL.sub(".", str(s))
    return s if len(s) <= limit else s[:limit] + "..."


def safe_stem(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)[:80] or "sample"


def trunc(s, n: int = 120) -> str:
    s = str(s)
    return s if len(s) <= n else s[: n - 3] + "..."


def redact(text, secrets) -> str:
    """Remove API keys from any message before it is logged or reported."""
    out = str(text)
    for s in secrets:
        if s and len(s) >= 6:
            out = out.replace(s, "***REDACTED***")
    return out


class RateLimiter:
    """Thread-safe slot scheduler: at most `per_minute` calls per minute."""

    def __init__(self, per_minute: int, notify=None):
        self.interval = 60.0 / per_minute if per_minute and per_minute > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0
        self.notify = notify

    def wait(self, label: str = "") -> float:
        if not self.interval:
            return 0.0
        with self._lock:
            now = time.monotonic()
            delay = max(0.0, self._next - now)
            self._next = max(now, self._next) + self.interval
        if delay > 0:
            if self.notify and delay >= 3:
                self.notify(f"{label} rate limit: waiting {delay:.0f}s")
            time.sleep(delay)
        return delay


class DiskCache:
    """Tiny JSON cache so repeated lookups do not burn API quota."""

    def __init__(self, directory: str, ttl_hours: float, enabled: bool = True):
        self.dir = Path(directory)
        self.ttl = float(ttl_hours) * 3600
        self.enabled = enabled and self.ttl > 0
        if self.enabled:
            try:
                self.dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                self.enabled = False

    def _path(self, key: str) -> Path:
        return self.dir / (hashlib.sha256(key.encode()).hexdigest() + ".json")

    def get(self, key: str):
        if not self.enabled:
            return None
        p = self._path(key)
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            if time.time() - raw.get("ts", 0) <= self.ttl:
                return raw.get("value")
        except (OSError, ValueError):
            pass
        return None

    def set(self, key: str, value) -> None:
        if not self.enabled:
            return
        try:
            fd, tmp = tempfile.mkstemp(dir=str(self.dir), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"ts": time.time(), "value": value}, f, default=str)
            os.replace(tmp, self._path(key))
        except OSError:
            pass


def finding(fid: str, title: str, detail: str, weight: int, category: str,
            attack=None, source: str = "static") -> dict:
    """Uniform structure used by every format analyzer so scoring stays generic."""
    return {
        "id": fid,
        "title": title,
        "detail": clean_text(detail, 400),
        "weight": int(weight),
        "category": category,
        "attack": list(attack) if attack else None,
        "source": source,
    }
