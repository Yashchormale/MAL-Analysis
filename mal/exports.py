"""Export helpers: IOC CSV, STIX 2.1 bundle, auto-generated YARA rule."""

from __future__ import annotations

import csv
import datetime as dt
import io
import re
import uuid


_NS = uuid.UUID("6f1c3d52-0b6e-4a53-9f4a-0a4d7e8b1c11")


def ioc_rows(report: dict) -> list:
    rows = []
    origin = report.get("ioc_origin", {})
    for t, vals in report.get("iocs", {}).items():
        if t.startswith("_"):
            continue
        for v in vals:
            rows.append((t, v, origin.get(f"{t}|{v}", "static")))
    intel = report.get("intel") or {}
    vt = (intel.get("providers") or {}).get("vt") or {}
    rel = vt.get("relationships") or {}
    for kind, t in (("contacted_domains", "domains"), ("contacted_ips", "ips"), ("contacted_urls", "urls")):
        for it in (rel.get(kind) or {}).get("items", []):
            rows.append((t, it.get("value"), "intel:virustotal-sandbox"))
    for it in (vt.get("behaviour") or {}).get("dns_lookups", []) if vt else []:
        rows.append(("domains", it.split(" -> ")[0], "intel:virustotal-sandbox"))
    tf = (intel.get("providers") or {}).get("threatfox") or {}
    for r in tf.get("iocs", []) or []:
        rows.append(("c2_ioc", r.get("ioc"), "intel:threatfox"))
    seen, out = set(), []
    for r in rows:
        if r[1] and (r[0], r[1]) not in seen:
            seen.add((r[0], r[1]))
            out.append(r)
    return out


def iocs_csv(report: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "value", "origin", "sample_sha256", "risk_level"])
    s = report.get("sample", {}).get("sha256", "")
    lvl = report.get("risk", {}).get("level", "")
    for t, v, o in ioc_rows(report):
        v = str(v)
        if v[:1] in "=+-@":                   # neutralize spreadsheet formula injection
            v = "'" + v
        w.writerow([t, v, o, s, lvl])
    return buf.getvalue()


def stix_bundle(report: dict) -> dict:
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    sample = report.get("sample", {})
    conf = int(report.get("risk", {}).get("score", 0))
    objs = []

    def ind(name, pattern, labels):
        oid = "indicator--" + str(uuid.uuid5(_NS, pattern))
        objs.append({"type": "indicator", "spec_version": "2.1", "id": oid, "created": now, "modified": now,
                     "name": name, "pattern": pattern, "pattern_type": "stix", "valid_from": now,
                     "indicator_types": ["malicious-activity"], "labels": labels, "confidence": conf})

    def q(v):
        return str(v).replace("\\", "\\\\").replace("'", "\\'")

    for algo, key in (("SHA-256", "sha256"), ("SHA-1", "sha1"), ("MD5", "md5")):
        if sample.get(key):
            ind(f"{sample.get('name', 'sample')} ({algo})", f"[file:hashes.'{algo}' = '{q(sample[key])}']",
                ["mal-v4", "file-hash"])
    ptype = {"domains": "domain-name:value", "ips": "ipv4-addr:value", "urls": "url:value",
             "emails": "email-addr:value"}
    if report.get("risk", {}).get("score", 0) >= 25:        # avoid publishing IOCs from clean-looking files
        for t, v, o in ioc_rows(report):
            if t in ptype:
                ind(f"{t[:-1]} {v}", f"[{ptype[t]} = '{q(v)}']", ["mal-v4", o])
    return {"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": objs}


_COMMON = re.compile(
    r"^(?:[\w.-]+\.dll|kernel32|user32|msvcr?t?\d*|this program|runtime error|microsoft|windows|"
    r"__\w+|\.?text|\.?data|\.?rdata|\.?rsrc|\.?reloc|[0-9a-f-]{32,40}|(?:[A-Za-z]:)?\\windows\\system32)$", re.I)
_KEYWORDS = re.compile(
    r"powershell|cmd\.exe|http|\\\\|\.exe|\.onion|regsvr|rundll|mshta|schtasks|cmdline|payload|inject|"
    r"decrypt|ransom|beacon|stager|shellcode|download|mutex|pipe|token|passw|wallet|stratum|user-agent",
    re.I)


def generate_yara(report: dict, strings: list, data_len: int) -> str:
    sample = report.get("sample", {})
    cands = []
    for s in strings:
        if not (8 <= len(s) <= 90) or _COMMON.match(s) or not s.isprintable():
            continue
        if len(set(s)) < 5:
            continue
        score = 0
        if _KEYWORDS.search(s):
            score += 3
        if re.search(r"\d", s) and re.search(r"[A-Za-z]", s):
            score += 1
        if len(s) >= 14:
            score += 1
        if "\\" in s or "/" in s:
            score += 1
        cands.append((score, s))
    cands.sort(key=lambda x: (-x[0], -len(x[1])))
    picked, seen = [], set()
    for _sc, s in cands:
        if s.lower() not in seen:
            seen.add(s.lower())
            picked.append(s)
        if len(picked) >= 12:
            break
    sha = sample.get("sha256", "0" * 64)
    kind = sample.get("kind", "")
    cond = []
    if kind == "pe":
        cond.append("uint16(0) == 0x5A4D")
    elif kind == "elf":
        cond.append("uint32(0) == 0x464C457F")
    cond.append(f"filesize < {max(16, int(data_len * 1.5 / 1024) + 1)}KB")
    if picked:
        need = min(len(picked), max(3, int(len(picked) * 0.6)))
        cond.append(f"{need} of ($s*)")
    lines = [f"rule MAL_{sha[:12]}", "{", "    meta:",
             '        description = "Auto-generated by MAL v4 from static strings - REVIEW AND TEST BEFORE DEPLOYING"',
             f'        sha256 = "{sha}"',
             f'        date = "{dt.date.today().isoformat()}"',
             f'        risk = "{report.get("risk", {}).get("level", "")}"']
    imp = (report.get("pe") or {}).get("imphash")
    if imp:
        lines.append(f'        imphash = "{imp}"   // can be used with: import "pe" ... pe.imphash() == "{imp}"')
    if picked:
        lines.append("    strings:")
        for i, s in enumerate(picked):
            esc = s.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'        $s{i} = "{esc}" ascii wide')
    lines += ["    condition:", "        " + " and ".join(cond), "}", ""]
    return "\n".join(lines)
