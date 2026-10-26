"""Capability detection, ATT&CK mapping and the transparent, capped risk engine."""

from __future__ import annotations

import re

from . import rules as R
from .utils import clamp, clean_text, trunc

STRONG_INDICATORS = {"reverse_shell", "mimikatz", "c2_framework", "combo_ransomware", "combo_injection",
                     "php_webshell", "vss_delete", "combo_dropper", "minidump", "sam_dump"}
_COMPILED = {r[0]: re.compile(r[1], re.I) for r in R.CAPABILITY_RULES}


def detect_capabilities(static_text: str, decoded_texts: list, import_names: list) -> list:
    """Run every rule once. A rule scores once; counts are evidence only."""
    imports_text = "\n".join(import_names or [])
    decoded_joined = "\n".join(t for _, t in decoded_texts)
    caps = []
    for rid, _pat, title, category, weight, attack in R.CAPABILITY_RULES:
        rx = _COMPILED[rid]
        sources, count, example = [], 0, None
        for label, text in (("strings", static_text), ("imports", imports_text), ("decoded", decoded_joined)):
            if not text:
                continue
            n = 0
            for m in rx.finditer(text):
                n += 1
                if example is None:
                    example = clean_text(m.group(0).strip(), 90)
                if n >= 50:
                    break
            if n:
                sources.append(label)
                count += n
        if sources:
            caps.append({"id": rid, "title": title, "category": category, "weight": weight,
                         "attack": list(attack) if attack else None, "count": count,
                         "sources": sources, "example": example})
    return caps


def evaluate_combos(caps: list) -> list:
    ids = {c["id"] for c in caps}
    out = []
    for cid, required, any_of, min_any, title, bonus, category, attack in R.COMBO_RULES:
        if not required <= ids:
            continue
        hit = sorted(any_of & ids)
        if len(hit) < min_any:
            continue
        out.append({"id": cid, "title": title, "category": category, "weight": bonus,
                    "attack": list(attack) if attack else None,
                    "evidence": ", ".join(sorted(required) + hit)})
    return out


def build_attack(caps, combos, findings, intel_summary) -> list:
    found = {}

    def add(attack, evidence, source):
        if not attack:
            return
        tid, name, tactic = attack[0], attack[1], attack[2]
        e = found.setdefault(tid, {"technique_id": tid, "name": name, "tactic": tactic,
                                   "evidence": [], "sources": []})
        if evidence not in e["evidence"]:
            e["evidence"].append(evidence)
        if source not in e["sources"]:
            e["sources"].append(source)

    for c in caps:
        add(c["attack"], c["title"], "static")
    for c in combos:
        add(c["attack"], c["title"], "static")
    for f in findings:
        add(f.get("attack"), f["title"], "static")
    for t in (intel_summary or {}).get("observed_techniques", []):
        tid = t.get("id")
        if not tid:
            continue
        known = R.ATTACK_NAMES.get(tid)
        name = t.get("name") or (known[0] if known else t.get("description") or "(reported by sandbox)")
        tactic = t.get("tactic") or (known[1] if known else "Other")
        add((tid, trunc(name, 100), tactic), t.get("description") or "observed behaviour", t["source"])
    return sorted(found.values(), key=lambda x: (R.TACTIC_ORDER.index(x["tactic"])
                                                  if x["tactic"] in R.TACTIC_ORDER else 99, x["technique_id"]))


def calculate_risk(caps, combos, findings, iocs, yara_result, intel) -> dict:
    cats = {k: 0 for k in R.CATEGORY_CAPS}
    reasons = []

    def add(cat, indicator, points, evidence, source="static"):
        if points <= 0:
            return
        cats[cat] = cats.get(cat, 0) + points
        reasons.append({"category": cat, "indicator": indicator, "points": points,
                        "evidence": evidence, "source": source})

    for c in caps:
        if c["weight"] > 0:
            src = "+".join(c["sources"])
            add(c["category"], c["id"], c["weight"],
                f"{c['title']} (x{c['count']}, via {src}; e.g. {c['example']!r})",
                "decoded" if c["sources"] == ["decoded"] else "static")
    for c in combos:
        add(c["category"], c["id"], c["weight"], f"{c['title']} [{c['evidence']}]")
    for f in findings:
        add(f["category"], f["id"], f["weight"], f"{f['title']}: {f['detail']}", f.get("source", "static"))

    ioc_n = sum(len(v) for k, v in iocs.items() if not k.startswith("_") and k != "hashes")
    net_n = len(iocs.get("urls", [])) * 3 + len(iocs.get("domains", [])) * 2 + len(iocs.get("ips", [])) * 2
    if net_n:
        add("network", "network_ioc", min(8, net_n),
            f"{len(iocs['urls'])} URL(s), {len(iocs['domains'])} domain(s), {len(iocs['ips'])} IP(s)")
    if ioc_n:
        add("ioc", "embedded_iocs", min(6, ioc_n), f"{ioc_n} extracted indicator(s)")

    if yara_result.get("matches"):
        add("reputation", "yara_match", min(18, 6 * len(yara_result["matches"])),
            ", ".join(m["rule"] for m in yara_result["matches"][:6]))

    # ---- external reputation (kept in its own capped category) ----
    summ = (intel or {}).get("summary") or {}
    provs = (intel or {}).get("providers") or {}
    rep = 0
    vt_det = summ.get("vt_malicious", 0) + summ.get("vt_suspicious", 0) * 0.5
    if vt_det:
        p = min(30, int(6 + 2 * vt_det))
        rep += p
        reasons.append({"category": "reputation", "indicator": "virustotal", "points": p,
                        "evidence": f"{summ.get('vt_malicious', 0)} malicious + {summ.get('vt_suspicious', 0)} "
                                    f"suspicious of {summ.get('vt_total', 0)} engines", "source": "intel"})
    for pn, label, pts in (("mb", "MalwareBazaar listing", 10), ("threatfox", "ThreatFox IOC link", 8),
                           ("urlhaus", "URLhaus malware-distribution link", 8)):
        if provs.get(pn, {}).get("status") == "ok":
            rep += pts
            reasons.append({"category": "reputation", "indicator": pn, "points": pts,
                            "evidence": label, "source": "intel"})
    hv = summ.get("ha_verdict") or ""
    if "malicious" in hv or "suspicious" in hv:
        p = 10 if "malicious" in hv else 5
        rep += p
        reasons.append({"category": "reputation", "indicator": "hybrid_analysis", "points": p,
                        "evidence": f"verdict '{hv}', threat score {summ.get('ha_threat_score')}", "source": "intel"})
    if provs.get("otx", {}).get("status") == "ok" and provs["otx"].get("pulse_count", 0):
        p = min(5, provs["otx"]["pulse_count"])
        rep += p
        reasons.append({"category": "reputation", "indicator": "otx", "points": p,
                        "evidence": f"{provs['otx']['pulse_count']} threat-intel pulse(s)", "source": "intel"})
    cats["reputation"] += rep
    if summ.get("network_flagged"):
        add("network", "flagged_infrastructure", min(8, 4 * summ["network_flagged"]),
            f"{summ['network_flagged']} contacted/embedded host(s) flagged by intel", "intel")

    capped = {k: min(v, R.CATEGORY_CAPS[k]) for k, v in cats.items()}
    score = int(clamp(sum(capped.values())))

    # Known-bad floor: strong external consensus should not be diluted by weak static evidence.
    floor = None
    if summ.get("vt_malicious", 0) >= 25:
        floor = 75
    elif summ.get("vt_malicious", 0) >= 10 or "mb" in summ.get("hits", []) or "threatfox" in summ.get("hits", []) \
            or "malicious" in (summ.get("ha_verdict") or ""):
        floor = 60
    if floor and score < floor:
        reasons.append({"category": "reputation", "indicator": "reputation_floor", "points": floor - score,
                        "evidence": f"Strong external consensus raises score to at least {floor}",
                        "source": "intel"})
        score = floor

    strong_ids = {c["id"] for c in caps} | {c["id"] for c in combos}
    strong = sorted(strong_ids & STRONG_INDICATORS)
    if strong and score < 50:
        reasons.append({"category": "execution", "indicator": "high_confidence_floor", "points": 50 - score,
                        "evidence": "Strongly malicious indicator(s): " + ", ".join(strong), "source": "static"})
        score = 50

    level = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
    diversity = sum(1 for k, v in capped.items() if v > 0 and k not in ("ioc",))
    static_pts = sum(v for k, v in capped.items() if k != "reputation")
    confidence = "HIGH" if diversity >= 4 else "MEDIUM" if diversity >= 2 else "LOW"
    if summ.get("verdict") == "malicious" and static_pts >= 20:
        confidence = "HIGH"                         # static + external agree
    elif summ.get("verdict") == "malicious" and confidence == "LOW":
        confidence = "MEDIUM"
    return {"score": score, "level": level, "confidence": confidence, "categories": capped,
            "reasons": sorted(reasons, key=lambda r: -r["points"]),
            "verdict_note": ("Score = sum of capped category totals (max 100). Each indicator counts once; "
                             "repetition is shown as evidence only.")}
