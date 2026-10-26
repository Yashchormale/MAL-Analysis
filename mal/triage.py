"""Static triage: hashing, type detection, strings, IOCs, safe deobfuscation.

Nothing in this module executes, imports, or evaluates sample content.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import ipaddress
import re
import struct
import zipfile
import zlib
from pathlib import Path

from . import rules as R
from .utils import (clean_text, entropy, finding, fmt_size, unique_keep_order)

try:
    import ppdeep
except ImportError:  # optional
    ppdeep = None
try:
    import tlsh
except ImportError:  # optional
    tlsh = None
try:
    import pefile
except ImportError:  # optional
    pefile = None

MAX_STRINGS_SCAN = 200_000       # strings kept for analysis
MAX_TEXT_SCAN = 20 * 1024 * 1024  # bytes of string-text fed to regex engines
MAX_IOCS_PER_TYPE = 500
XOR_SCAN_LIMIT = 16 * 1024 * 1024
INFLATE_LIMIT = 16 * 1024 * 1024


# ----------------------------------------------------------------------------
# Loading & hashing
# ----------------------------------------------------------------------------

def load_sample(path: Path, max_mb: int):
    size = path.stat().st_size
    limit = max_mb * 1024 * 1024
    if size == 0:
        raise ValueError("File is empty (0 bytes).")
    if size > limit:
        raise ValueError(f"File is {fmt_size(size)}, above the {max_mb} MB static-analysis limit "
                         f"(raise MAL_MAX_FILE_MB to allow).")
    data = path.read_bytes()          # one read; everything else works on these bytes
    hashes = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha3_256": hashlib.sha3_256(data).hexdigest(),
    }
    return data, hashes


def fuzzy_hashes(data: bytes) -> dict:
    out = {"ssdeep": None, "tlsh": None}
    if ppdeep is not None and len(data) <= 32 * 1024 * 1024:
        try:
            out["ssdeep"] = ppdeep.hash(data)
        except Exception:
            pass
    if tlsh is not None and len(data) >= 50:
        try:
            h = tlsh.hash(data)
            out["tlsh"] = h if h and h != "TNULL" else None
        except Exception:
            pass
    return out


# ----------------------------------------------------------------------------
# File type detection
# ----------------------------------------------------------------------------

def _zip_names(data: bytes):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            return z.namelist()
    except Exception:
        return None


def detect_type(data: bytes, path: Path) -> dict:
    """Return {'type': human string, 'kind': machine key}."""
    head = data[:64]
    ext = path.suffix.lower()

    def out(t, k):
        return {"type": t, "kind": k}

    if head.startswith(b"MZ"):
        return out("PE / Windows executable", "pe")
    if head.startswith(b"\x7fELF"):
        return out("ELF / Linux executable", "elf")
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return out("Mach-O / macOS executable", "macho")
    if head[:4] == b"\xca\xfe\xba\xbe":
        n = struct.unpack(">I", head[4:8])[0]
        return out("Mach-O universal binary", "macho") if n < 20 else out("Java class file", "jar")
    if b"%PDF" in data[:1024]:
        return out("PDF document", "pdf")
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        names = _zip_names(data) or []
        low = [n.lower() for n in names]
        if "[content_types].xml" in low:
            if any(n.startswith("word/") for n in low):
                app = "Word"
            elif any(n.startswith("xl/") for n in low):
                app = "Excel"
            elif any(n.startswith("ppt/") for n in low):
                app = "PowerPoint"
            else:
                app = "Office"
            macro = any(n.endswith("vbaproject.bin") for n in low)
            return out(f"Microsoft {app} document (OOXML{', macro-enabled' if macro else ''})", "ooxml")
        if "androidmanifest.xml" in low:
            return out("Android package (APK)", "apk")
        if "meta-inf/manifest.mf" in low:
            return out("Java archive (JAR)", "jar")
        return out("ZIP archive", "zip")
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return out("OLE2 compound file (legacy Office / MSI)", "ole")
    if head.startswith(b"{\\rt"):
        return out("RTF document", "rtf")
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return out("7-Zip archive", "archive")
    if head.startswith(b"Rar!\x1a\x07"):
        return out("RAR archive", "archive")
    if head.startswith(b"\x1f\x8b"):
        return out("GZIP archive", "archive")
    if head.startswith(b"BZh"):
        return out("BZIP2 archive", "archive")
    if head.startswith(b"\xfd7zXZ\x00"):
        return out("XZ archive", "archive")
    if head.startswith(b"MSCF"):
        return out("Microsoft Cabinet (CAB)", "archive")
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return out("ISO 9660 disk image", "archive")
    if len(data) > 262 and data[257:262] == b"ustar":
        return out("TAR archive", "archive")
    if head[:4] == b"L\x00\x00\x00" and head[4:20] == bytes.fromhex("0114020000000000c000000000000046"):
        return out("Windows shortcut (LNK)", "lnk")
    if head.startswith(b"\x89PNG"):
        return out("PNG image", "image")
    if head.startswith(b"\xff\xd8\xff"):
        return out("JPEG image", "image")
    if head.startswith(b"GIF8"):
        return out("GIF image", "image")

    text = data[:1024 * 1024].decode("utf-8", errors="ignore").lower()
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = data[:1024 * 1024].decode("utf-16", errors="ignore").lower()

    if "<hta:application" in text or ext == ".hta":
        return out("HTML Application (HTA)", "script")
    if text.startswith("#!"):
        first = text.split("\n", 1)[0]
        if "python" in first:
            return out("Python script", "script")
        if "php" in first:
            return out("PHP script", "script")
        return out("Shell script", "script")
    if text.lstrip().startswith("<?php") or ext == ".php":
        return out("PHP script", "script")
    if ext in {".ps1", ".psm1", ".psd1"} or re.search(r"\b(?:invoke-expression|write-host|\$env:|new-object)\b", text):
        return out("PowerShell script", "script")
    if ext in {".vbs", ".vbe", ".vba", ".bas"} or "wscript.shell" in text or re.search(r"(?m)^\s*dim\s+\w+", text):
        return out("VBScript / VBA", "script")
    if ext in {".js", ".jse"}:
        return out("JavaScript", "script")
    if ext in {".wsf", ".sct"}:
        return out("Windows Script File / scriptlet", "script")
    if ext in {".bat", ".cmd"} or re.search(r"(?m)^@echo off", text):
        return out("Windows batch script", "script")
    if ext == ".reg" or text.startswith("windows registry editor"):
        return out("Windows registry script", "script")
    if ext == ".py" or re.search(r"(?m)^\s*(import|from)\s+[A-Za-z_]", text):
        return out("Python script", "script")
    if ext in {".sh", ".bash"}:
        return out("Shell script", "script")
    if ext == ".url" or text.startswith("[internetshortcut]"):
        return out("Internet shortcut (URL)", "script")
    if ext in {".html", ".htm"} or "<html" in text:
        return out("HTML document", "html")
    if text.strip():
        return out("Text / script-like file", "text")
    return out("Unknown / binary data", "unknown")


def analyze_name(path: Path, kind: str) -> list:
    """Filename masquerading checks (RTLO, double extension, extension/content mismatch)."""
    name = path.name
    findings = []
    if "\u202e" in name:
        findings.append(finding("rtlo", "Right-to-Left Override in filename",
                                f"Filename contains U+202E: {name!r}", 10, "evasion",
                                ("T1036.002", "Masquerading: Right-to-Left Override", R.EVAS)))
    if R.DOUBLE_EXT_RE.search(name):
        findings.append(finding("double_ext", "Double file extension",
                                f"{name} imitates a document/image but ends in an executable extension",
                                8, "evasion",
                                ("T1036.007", "Masquerading: Double File Extension", R.EVAS)))
    expected = R.EXPECTED_KINDS.get(path.suffix.lower())
    strong = {"pe", "elf", "script", "lnk", "ooxml", "ole", "pdf", "rtf", "zip", "archive"}
    if expected and kind in strong and kind not in expected:
        weight = 12 if kind in {"pe", "elf", "script", "lnk"} else 6
        findings.append(finding("ext_mismatch", "File extension does not match content",
                                f"Extension '{path.suffix}' but content is '{kind}'",
                                weight, "evasion",
                                ("T1036.008", "Masquerading: Masquerade File Type", R.EVAS)))
    return findings


# ----------------------------------------------------------------------------
# Strings
# ----------------------------------------------------------------------------

ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")


def extract_strings(data: bytes) -> list:
    out = []
    seen = set()
    for m in ASCII_RE.finditer(data):
        s = m.group().decode("ascii", errors="ignore")
        if s not in seen:
            seen.add(s)
            out.append(s)
            if len(out) >= MAX_STRINGS_SCAN:
                return out
    for m in UTF16_RE.finditer(data):
        s = m.group().decode("utf-16le", errors="ignore")
        if s not in seen:
            seen.add(s)
            out.append(s)
            if len(out) >= MAX_STRINGS_SCAN:
                break
    return out


def strings_to_text(strings) -> str:
    """Join strings for regex scanning, capped so huge binaries stay tractable."""
    text = "\n".join(strings)
    if len(text) > MAX_TEXT_SCAN:
        text = text[:MAX_TEXT_SCAN]
    return text


# ----------------------------------------------------------------------------
# IOC extraction
# ----------------------------------------------------------------------------

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\\^`{}|]{4,}", re.I)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
EMAIL_RE = re.compile(R.EMAIL_RE_PATTERN)
WIN_PATH_RE = re.compile(r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]{1,100}\\){0,12}[^\\/:*?\"<>|\r\n]{0,100}")
ENV_PATH_RE = re.compile(
    r"%(?:appdata|localappdata|temp|tmp|programdata|userprofile|windir|systemroot|public)%\\[^\r\n\"'<>|]{1,200}",
    re.I)
REGISTRY_RE = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS)\\[^\r\n\"']{1,250}",
    re.I)
MUTEX_RE = re.compile(r"\b(?:Global|Local)\\[A-Za-z0-9_.{}\-]{5,80}")
PIPE_RE = re.compile(r"\\\\\.\\pipe\\[A-Za-z0-9_.\-]{3,60}", re.I)
PDB_RE = re.compile(r"[A-Za-z]:\\[^\r\n\"'<>|]{3,200}\.pdb\b", re.I)
BTC_RE = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
XMR_RE = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
TG_TOKEN_RE = re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")
HASH_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})(?![0-9a-fA-F])")
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _valid_base58check(addr: str) -> bool:
    n = 0
    for ch in addr:
        i = _B58.find(ch)
        if i < 0:
            return False
        n = n * 58 + i
    try:
        raw = n.to_bytes(25, "big")
    except OverflowError:
        return False
    return hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]


def _clean(x: str) -> str:
    return x.rstrip(".,;:)]}>'\"")


def _benign_domain(d: str) -> bool:
    return any(d == s or d.endswith("." + s) for s in R.BENIGN_DOMAIN_SUFFIXES)


def extract_iocs(text: str) -> dict:
    urls_all = [u for u in unique_keep_order(_clean(x) for x in URL_RE.findall(text)) if len(u) >= 10]
    urls, suppressed_urls = [], []
    for u in urls_all:
        host = u.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].split("@")[-1].lower()
        (suppressed_urls if _benign_domain(host) else urls).append(u)

    ips = []
    for ip in IP_RE.findall(text):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.is_loopback or a.is_unspecified or a.is_multicast or ip == "255.255.255.255":
            continue
        ips.append(ip)
    ips = unique_keep_order(ips)

    domains, suppressed = [], []
    for m in DOMAIN_RE.findall(text):
        labels = m.split(".")
        tld = labels[-1].lower()
        if tld not in R.COMMON_TLDS:
            continue
        if len(labels) >= 2 and all(l[:1].isupper() for l in labels):
            continue                                   # .NET namespace like System.Net.Http
        d = m.lower().rstrip(".")
        if d.split(".")[0] in {"system", "microsoft", "windows", "mono", "mscorlib"}:
            continue
        if _benign_domain(d):
            suppressed.append(d)
        else:
            domains.append(d)
    domains = unique_keep_order(domains)

    emails = unique_keep_order(
        e.lower() for e in EMAIL_RE.findall(text)
        if e.rsplit(".", 1)[-1].lower() in R.COMMON_TLDS and not _benign_domain(e.split("@", 1)[1].lower()))

    crypto = []
    for a in unique_keep_order(BTC_RE.findall(text)):
        if a.startswith("bc1") or _valid_base58check(a):
            crypto.append("BTC:" + a)
    crypto += ["ETH:" + a for a in unique_keep_order(ETH_RE.findall(text))]
    crypto += ["XMR:" + a for a in unique_keep_order(XMR_RE.findall(text))]
    crypto += ["TELEGRAM_TOKEN:" + a for a in unique_keep_order(TG_TOKEN_RE.findall(text))]

    paths = unique_keep_order(_clean(x) for x in WIN_PATH_RE.findall(text))
    paths += unique_keep_order(_clean(x) for x in ENV_PATH_RE.findall(text))

    out = {
        "urls": urls,
        "domains": domains,
        "ips": ips,
        "emails": emails,
        "file_paths": unique_keep_order(paths),
        "registry": unique_keep_order(_clean(x) for x in REGISTRY_RE.findall(text)),
        "mutexes": unique_keep_order(MUTEX_RE.findall(text)),
        "pipes": unique_keep_order(PIPE_RE.findall(text)),
        "pdb_paths": unique_keep_order(PDB_RE.findall(text)),
        "crypto": unique_keep_order(crypto),
        "hashes": unique_keep_order(h.lower() for h in HASH_RE.findall(text)),
    }
    out = {k: v[:MAX_IOCS_PER_TYPE] for k, v in out.items()}
    out["_suppressed_benign"] = unique_keep_order(suppressed + suppressed_urls)[:50]
    return out


def build_ioc_set(static_text: str, decoded: list) -> tuple:
    """Merge IOCs from raw strings and decoded layers. Returns (iocs, origin_map)."""
    base = extract_iocs(static_text)
    origin = {}
    for t, vals in base.items():
        if t.startswith("_"):
            continue
        for v in vals:
            origin[(t, v)] = "static"
    for method, text in decoded:
        extra = extract_iocs(text)
        for t, vals in extra.items():
            if t.startswith("_"):
                continue
            for v in vals:
                if v not in base[t]:
                    base[t].append(v)
                    origin[(t, v)] = f"decoded:{method}"
    for t in list(base):
        if not t.startswith("_"):
            base[t] = base[t][:MAX_IOCS_PER_TYPE]
    return base, origin


# ----------------------------------------------------------------------------
# Safe deobfuscation (decode only; nothing is ever executed)
# ----------------------------------------------------------------------------

B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){40,}(?![0-9A-Fa-f])")
PS_ENC_RE = re.compile(r"\s-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{20,})", re.I)
CHARCODE_RE = re.compile(
    r"((?:(?:\[char\]\s*\(?\s*\d{2,3}\s*\)?|chr[wb]?\s*\(\s*\d{2,3}\s*\))\s*[+&,;]?\s*){4,})", re.I)
CONCAT_RE = re.compile(r"""(['"])([^'"\r\n]{0,200})\1\s*[+&]\s*(['"])([^'"\r\n]{0,200})\3""")


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    ok = sum(1 for c in b[:4096] if c in (9, 10, 13) or 32 <= c <= 126)
    return ok / min(len(b), 4096)


def _inflate(b: bytes):
    try:
        d = zlib.decompressobj(wbits=47)          # auto-detect zlib / gzip
        out = d.decompress(b, INFLATE_LIMIT)
        return out if out else None
    except Exception:
        return None


def _classify(b: bytes):
    """Return (kind, text_or_None)."""
    if b[:2] == b"MZ":
        return "pe", None
    if b[:4] == b"\x7fELF":
        return "elf", None
    if b[:4] == b"PK\x03\x04":
        return "zip", None
    if b[:2] in (b"\x78\x9c", b"\x78\xda", b"\x78\x01") or b[:2] == b"\x1f\x8b":
        return "compressed", None
    if len(b) >= 8 and b[1::2][:2048].count(0) >= 0.8 * len(b[1::2][:2048]):
        try:
            t = b.decode("utf-16le", errors="ignore")
            if t and _printable_ratio(t.encode("utf-8", "ignore")) > 0.9:
                return "text", t
        except Exception:
            pass
    if _printable_ratio(b) >= 0.92 and len(b) >= 8:
        return "text", b.decode("utf-8", errors="ignore")
    return "binary", None


def describe_pe_at(data: bytes, off: int, origin: str = "embedded") -> dict:
    chunk = data[off: off + 64 * 1024 * 1024]
    info = {"offset": off, "origin": origin, "size": None, "sha256": None,
            "arch": None, "timestamp": None, "sections": None, "is_dll": None}
    size = len(chunk)
    if pefile is not None:
        try:
            pe = pefile.PE(data=chunk, fast_load=True)
            ends = [s.PointerToRawData + s.SizeOfRawData for s in pe.sections]
            if ends:
                size = min(len(chunk), max(ends))
            info["arch"] = {0x10B: "x86", 0x20B: "x64"}.get(pe.OPTIONAL_HEADER.Magic, "unknown")
            info["timestamp"] = int(pe.FILE_HEADER.TimeDateStamp)
            info["sections"] = [s.Name.rstrip(b"\x00").decode("ascii", "replace") for s in pe.sections][:12]
            info["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
            pe.close()
        except Exception:
            pass
    info["size"] = size
    info["sha256"] = hashlib.sha256(chunk[:size]).hexdigest()
    info["_bytes"] = chunk[:size]             # stripped before JSON export
    return info


def find_embedded_pe(data: bytes, skip_header: bool, origin: str = "embedded") -> list:
    hits = []
    pos = data.find(b"MZ", 1 if skip_header else 0)
    checks = 0
    while pos != -1 and len(hits) < 20 and checks < 200_000:
        checks += 1
        if pos + 0x40 <= len(data):
            e_lfanew = struct.unpack_from("<I", data, pos + 0x3C)[0]
            if 0x40 <= e_lfanew <= 0x400 and data[pos + e_lfanew: pos + e_lfanew + 4] == b"PE\x00\x00":
                hits.append(describe_pe_at(data, pos, origin))
        pos = data.find(b"MZ", pos + 2)
    return hits


_XOR_MARKERS = [(b"http://", "url"), (b"https://", "url"),
                (b"This program cannot be run in DOS mode", "pe")]


def xor_scan(data: bytes) -> dict:
    """Detect single-byte-XOR-encoded URLs and PE payloads (key 0x20 skipped: case-flip noise)."""
    window = data[:XOR_SCAN_LIMIT]
    hits, pes = [], []
    for key in range(1, 256):
        if key == 0x20:
            continue
        for marker, kind in _XOR_MARKERS:
            needle = bytes(b ^ key for b in marker)
            pos = window.find(needle)
            if pos < 0:
                continue
            if kind == "url":
                raw_run = window[pos: pos + 300]
                nul = raw_run.find(b"\x00")                 # strings are NUL-terminated: stop there
                if nul >= 0:
                    raw_run = raw_run[:nul]
                dec = bytes(b ^ key for b in raw_run)
                end = 0
                while end < len(dec) and 0x21 <= dec[end] <= 0x7E:
                    end += 1
                hits.append({"kind": "url", "key": f"0x{key:02x}", "offset": pos,
                             "value": dec[:end].decode("ascii", "ignore")})
            else:
                start = pos - 0x4E
                if start >= 0 and window[start] ^ key == 0x4D and window[start + 1] ^ key == 0x5A:
                    decoded = bytes(b ^ key for b in data[start: start + 32 * 1024 * 1024])
                    d = describe_pe_at(decoded, 0, f"xor:0x{key:02x}")
                    d["offset"] = start
                    d["key"] = f"0x{key:02x}"
                    pes.append(d)
                    hits.append({"kind": "pe", "key": f"0x{key:02x}", "offset": start,
                                 "value": f"XOR-encoded PE ({d['size']} bytes)"})
    return {"hits": hits[:40], "pe": pes[:5], "truncated": len(data) > XOR_SCAN_LIMIT}


def collapse_concat(text: str):
    """Rebuild 'ht'+'tp://' style split strings. Returns list of reconstructed lines."""
    new = text
    for _ in range(6):
        nxt = CONCAT_RE.sub(lambda m: f"'{m.group(2)}{m.group(4)}'", new)
        if nxt == new:
            break
        new = nxt
    if new == text:
        return []
    old_lines = set(text.splitlines())
    return [l for l in new.splitlines() if l not in old_lines and len(l) >= 8][:300]


def deobfuscate(data: bytes, strings: list, kind: str, deep: bool = True) -> dict:
    """Decode (never run) common obfuscation. Returns layers + text for IOC/rule rescans."""
    text = strings_to_text(strings)
    layers, decoded_texts, carved = [], [], []
    seen = set()

    def record(method, enc_len, raw, depth):
        sha = hashlib.sha256(raw).hexdigest()
        if sha in seen or len(layers) >= 60:
            return None
        seen.add(sha)
        k, t = _classify(raw)
        if k == "compressed":
            inflated = _inflate(raw)
            if inflated:
                inner = record(method + "+inflate", len(raw), inflated, depth + 1)
                if inner:
                    scan_text(inner, depth + 2)
        layer = {"method": method, "depth": depth, "encoded_len": enc_len,
                 "decoded_len": len(raw), "kind": k, "sha256": sha,
                 "entropy": round(entropy(raw[:65536]), 3),
                 "preview": clean_text(t[:300] if t else raw[:48].hex(" "), 300)}
        layers.append(layer)
        if k == "pe":
            d = describe_pe_at(raw, 0, f"decoded:{method}")
            carved.append(d)
            layer["note"] = f"decoded payload is a PE ({d['size']} bytes, sha256 {d['sha256'][:16]}...)"
        if t:
            decoded_texts.append((method, t))
        return t

    def scan_text(t: str, depth: int):
        if depth > 2:
            return
        # PowerShell -EncodedCommand (UTF-16LE base64)
        for m in PS_ENC_RE.findall(t)[:20]:
            try:
                raw = base64.b64decode(m + "=" * (-len(m) % 4), validate=True)
            except (binascii.Error, ValueError):
                continue
            sub = record("powershell_encodedcommand", len(m), raw, depth)
            if sub:
                scan_text(sub, depth + 1)
        # generic base64
        cands = unique_keep_order(B64_RE.findall(t))
        cands = [c for c in cands if len(set(c)) >= 12][:150]
        for c in cands:
            try:
                raw = base64.b64decode(c + "=" * (-len(c) % 4), validate=True)
            except (binascii.Error, ValueError):
                continue
            if len(raw) < 12:
                continue
            sub = record("base64", len(c), raw, depth)
            if sub:
                scan_text(sub, depth + 1)
        # long hex blobs
        for h in unique_keep_order(HEX_RE.findall(t))[:40]:
            try:
                raw = bytes.fromhex(h)
            except ValueError:
                continue
            sub = record("hex", len(h), raw, depth)
            if sub:
                scan_text(sub, depth + 1)
        # [char]/chr() arrays
        for m in CHARCODE_RE.findall(t)[:30]:
            nums = [int(n) for n in re.findall(r"\d{2,3}", m)]
            s = "".join(chr(n) for n in nums if n in (9, 10, 13) or 32 <= n <= 126)
            if len(s) >= 6 and s not in seen:
                seen.add(s)
                layers.append({"method": "charcode", "depth": depth, "encoded_len": len(m),
                               "decoded_len": len(s), "kind": "text", "sha256": hashlib.sha256(s.encode()).hexdigest(),
                               "entropy": 0.0, "preview": clean_text(s, 300)})
                decoded_texts.append(("charcode", s))

    if kind in {"script", "html", "text", "ooxml", "ole", "rtf", "pdf", "lnk", "unknown"} or len(text) < 5_000_000:
        scan_text(text, 0)

    concat_lines = collapse_concat(text) if kind in {"script", "html", "text"} else []
    if concat_lines:
        joined = "\n".join(concat_lines)
        layers.append({"method": "string_concat", "depth": 0, "encoded_len": len(joined),
                       "decoded_len": len(joined), "kind": "text",
                       "sha256": hashlib.sha256(joined.encode()).hexdigest(), "entropy": 0.0,
                       "preview": clean_text(joined, 300)})
        decoded_texts.append(("string_concat", joined))

    embedded = find_embedded_pe(data, skip_header=(kind == "pe")) if deep else []
    xor = xor_scan(data) if deep else {"hits": [], "pe": [], "truncated": False}
    for x in xor["hits"]:
        if x["kind"] == "url":
            decoded_texts.append(("xor", x["value"]))
    return {"layers": layers, "decoded_texts": decoded_texts, "carved_pe": carved,
            "embedded_pe": embedded, "xor": xor}
