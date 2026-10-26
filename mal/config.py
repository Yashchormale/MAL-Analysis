"""Configuration: dependency-free .env loader + typed settings.

Precedence (highest first):  CLI flag  >  real environment variable  >  .env file
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

PLACEHOLDER_HINTS = ("your_", "your-", "xxxx", "changeme", "paste_", "<", "insert")


def parse_env_text(text: str) -> dict:
    """Parse KEY=VALUE lines. Supports comments, `export`, and quoted values."""
    out = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if not key or not key.replace("_", "").isalnum():
            continue
        if val[:1] in ("'", '"') and val.endswith(val[:1]) and len(val) >= 2:
            val = val[1:-1]
        else:
            # strip inline comment (only for unquoted values)
            if " #" in val:
                val = val.split(" #", 1)[0].rstrip()
        out[key] = val
    return out


def find_env_file(explicit: str | None = None) -> Path | None:
    candidates = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    candidates.append(Path.cwd() / ".env")
    candidates.append(Path(__file__).resolve().parent.parent / ".env")
    for c in candidates:
        try:
            if c.is_file():
                return c
        except OSError:
            continue
    return None


def load_env_file(path: Path | None) -> dict:
    if not path:
        return {}
    try:
        return parse_env_text(path.read_text(encoding="utf-8-sig"))
    except OSError:
        return {}


def env_permission_warning(path: Path | None) -> str | None:
    """Warn if the .env file is readable by other users (POSIX only)."""
    if not path or os.name != "posix":
        return None
    try:
        mode = path.stat().st_mode
        if mode & (stat.S_IRGRP | stat.S_IROTH):
            return (f"{path} is readable by other users. Protect your API keys: "
                    f"chmod 600 {path}")
    except OSError:
        pass
    return None


def _clean_key(value: str | None) -> str:
    v = (value or "").strip()
    if not v:
        return ""
    low = v.lower()
    if any(h in low for h in PLACEHOLDER_HINTS):
        return ""
    return v


def _to_int(v, default):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def _to_bool(v, default=False):
    if v is None or str(v).strip() == "":
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "on", "y"}


@dataclass
class Settings:
    vt_api_key: str = ""
    abusech_auth_key: str = ""        # MalwareBazaar + URLhaus + ThreatFox (one abuse.ch key)
    otx_api_key: str = ""
    abuseipdb_api_key: str = ""
    hybrid_analysis_api_key: str = ""

    vt_rate_limit_per_min: int = 4    # free key = 4/min. Premium: raise or set 0 (unlimited)
    vt_depth: str = "standard"        # basic | standard | full
    http_timeout: int = 20
    verify_ssl: bool = True
    user_agent: str = "MAL-v4 defensive-analysis (+hash-lookup-only)"
    cache_dir: str = ".mal_cache"
    cache_ttl_hours: float = 24
    enrich_limit: int = 5
    max_file_mb: int = 100
    output_dir: str = "reports"
    auto_intel: bool = False
    env_file: str | None = None
    warnings: list = field(default_factory=list)

    def secrets(self) -> list:
        return [self.vt_api_key, self.abusech_auth_key, self.otx_api_key,
                self.abuseipdb_api_key, self.hybrid_analysis_api_key]

    def key_status(self) -> dict:
        return {
            "VirusTotal": bool(self.vt_api_key),
            "abuse.ch (MalwareBazaar/URLhaus/ThreatFox)": bool(self.abusech_auth_key),
            "AlienVault OTX": bool(self.otx_api_key),
            "AbuseIPDB": bool(self.abuseipdb_api_key),
            "Hybrid Analysis": bool(self.hybrid_analysis_api_key),
        }


def load_settings(env_path: str | None = None, overrides: dict | None = None) -> Settings:
    overrides = overrides or {}
    path = find_env_file(env_path)
    file_vars = load_env_file(path)

    def get(*names, default=None):
        for n in names:                      # real environment wins over .env
            if os.environ.get(n):
                return os.environ[n]
        for n in names:
            if file_vars.get(n):
                return file_vars[n]
        return default

    s = Settings(
        vt_api_key=_clean_key(get("VT_API_KEY", "VIRUSTOTAL_API_KEY")),
        abusech_auth_key=_clean_key(get("ABUSECH_AUTH_KEY", "ABUSE_CH_API_KEY",
                                        "MALWAREBAZAAR_API_KEY", "URLHAUS_AUTH_KEY",
                                        "THREATFOX_AUTH_KEY")),
        otx_api_key=_clean_key(get("OTX_API_KEY", "ALIENVAULT_OTX_API_KEY")),
        abuseipdb_api_key=_clean_key(get("ABUSEIPDB_API_KEY")),
        hybrid_analysis_api_key=_clean_key(get("HYBRID_ANALYSIS_API_KEY", "HA_API_KEY")),
        vt_rate_limit_per_min=_to_int(get("VT_RATE_LIMIT_PER_MIN"), 4),
        vt_depth=(get("VT_DEPTH", default="standard") or "standard").lower(),
        http_timeout=_to_int(get("MAL_HTTP_TIMEOUT"), 20),
        verify_ssl=_to_bool(get("MAL_VERIFY_SSL"), True),
        cache_dir=get("MAL_CACHE_DIR", default=".mal_cache"),
        cache_ttl_hours=float(_to_int(get("MAL_CACHE_TTL_HOURS"), 24)),
        enrich_limit=_to_int(get("MAL_ENRICH_LIMIT"), 5),
        max_file_mb=_to_int(get("MAL_MAX_FILE_MB"), 100),
        output_dir=get("MAL_OUTPUT_DIR", default="reports"),
        auto_intel=_to_bool(get("MAL_AUTO_INTEL"), False),
        env_file=str(path) if path else None,
    )

    for k, v in overrides.items():
        if v is not None and hasattr(s, k):
            setattr(s, k, v)

    if s.vt_depth not in {"basic", "standard", "full"}:
        s.warnings.append(f"VT_DEPTH '{s.vt_depth}' invalid; using 'standard'.")
        s.vt_depth = "standard"
    if not s.verify_ssl:
        s.warnings.append("MAL_VERIFY_SSL is disabled: TLS certificates are NOT being verified.")
    w = env_permission_warning(path)
    if w:
        s.warnings.append(w)
    return s
