"""Threat-intelligence enrichment.

Privacy model
  * Hash lookups send ONLY the file hash. The sample itself is never uploaded.
  * IOC enrichment (domains/IPs found inside the sample) is a separate opt-in (--enrich).
  * API keys are read from .env / environment, sent only in request headers, and
    redacted from every log line and report.

Every provider returns a dict with a `status`:
    ok | not_found | no_key | error | rate_limited | restricted
"""

from __future__ import annotations

import concurrent.futures as cf
import threading
import time
from collections import Counter

from .utils import (DiskCache, RateLimiter, clean_text, epoch_to_iso, is_public_ip,
                    redact, unique_keep_order)

try:
    import requests
except ImportError:
    requests = None

PROVIDER_LABELS = {
    "vt": "VirusTotal", "mb": "MalwareBazaar", "urlhaus": "URLhaus", "threatfox": "ThreatFox",
    "otx": "AlienVault OTX", "ha": "Hybrid Analysis", "abuseipdb": "AbuseIPDB",
}
HASH_PROVIDERS = ["vt", "mb", "urlhaus", "threatfox", "otx", "ha"]
NETWORK_PROVIDERS = ["vt", "otx", "abuseipdb", "urlhaus", "threatfox"]
ALIASES = {
    "virustotal": ["vt"], "vt": ["vt"], "malwarebazaar": ["mb"], "mb": ["mb"], "bazaar": ["mb"],
    "urlhaus": ["urlhaus"], "threatfox": ["threatfox"], "tf": ["threatfox"],
    "abusech": ["mb", "urlhaus", "threatfox"], "abuse.ch": ["mb", "urlhaus", "threatfox"],
    "otx": ["otx"], "alienvault": ["otx"], "ha": ["ha"], "hybrid": ["ha"], "hybridanalysis": ["ha"],
    "abuseipdb": ["abuseipdb"], "abuseip": ["abuseipdb"],
}


class IntelError(Exception):
    pass


def parse_provider_list(spec) -> list | None:
    """'vt,otx' -> ['vt','otx'].  None / 'all' -> None (means: every provider with a key)."""
    if spec is None:
        return None
    out = []
    for tok in str(spec).lower().replace(" ", "").split(","):
        if not tok or tok == "all":
            return None
        if tok not in ALIASES:
            raise ValueError(f"Unknown intel provider '{tok}'. Valid: vt, mb, urlhaus, threatfox, "
                             f"otx, ha, abuseipdb, abusech, all")
        out += ALIASES[tok]
    return unique_keep_order(out)


def _s(x, n=200) -> str:
    """Compact, safe string for arbitrary JSON values coming back from third parties."""
    if isinstance(x, dict):
        x = ", ".join(f"{k}={v}" for k, v in list(x.items())[:6])
    elif isinstance(x, (list, tuple)):
        x = ", ".join(str(i) for i in x[:6])
    return clean_text(x, n)


def _int(x, default=0) -> int:
    try:
        return int(x)
    except (TypeError, ValueError):
        return default


def _res(provider, status, **kw) -> dict:
    d = {"provider": provider, "label": PROVIDER_LABELS.get(provider, provider), "status": status}
    d.update(kw)
    return d


# ----------------------------------------------------------------------------
# HTTP wrapper
# ----------------------------------------------------------------------------

class Http:
    def __init__(self, settings):
        self.s = settings
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": settings.user_agent, "Accept": "application/json"})

    def request(self, method, url, headers=None, params=None, data=None, json_body=None):
        last = None
        for attempt in range(3):
            try:
                r = self.session.request(method, url, headers=headers, params=params, data=data,
                                         json=json_body, timeout=self.s.http_timeout,
                                         verify=self.s.verify_ssl)
            except requests.RequestException as e:
                last = redact(str(e), self.s.secrets())
                time.sleep(1.5 * (attempt + 1))
                continue
            if r.status_code == 429 and attempt < 2:
                try:
                    wait = min(int(r.headers.get("Retry-After", "5")), 30)
                except ValueError:
                    wait = 5
                time.sleep(wait)
                continue
            if r.status_code >= 500 and attempt < 2:
                time.sleep(2 * (attempt + 1))
                continue
            try:
                js = r.json()
            except ValueError:
                js = None
            return r.status_code, js, r.text[:300]
        raise IntelError(last or "request failed")


def _http_status(provider, code, text=""):
    if code == 401:
        return _res(provider, "error", error="API key rejected (HTTP 401). Check your .env file.")
    if code == 403:
        return _res(provider, "restricted",
                    error="HTTP 403: key lacks permission for this endpoint (often a free-tier limit).")
    if code == 429:
        return _res(provider, "rate_limited", error="Rate limit / quota reached (HTTP 429).")
    if code == 404:
        return _res(provider, "not_found")
    return _res(provider, "error", error=f"HTTP {code}: {clean_text(text, 160)}")


# ----------------------------------------------------------------------------
# VirusTotal
# ----------------------------------------------------------------------------

class VirusTotal:
    name = "vt"
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, eng):
        self.eng = eng
        self.s = eng.settings
        self.limiter = RateLimiter(self.s.vt_rate_limit_per_min, notify=eng.log)

    # -- transport ---------------------------------------------------------
    def get(self, path, params=None):
        key = f"vt|{path}|{sorted((params or {}).items())}"
        hit = self.eng.cache_get(key)
        if hit:
            return hit["status"], hit["json"], True
        self.limiter.wait("VirusTotal")
        code, js, txt = self.eng.http.request("GET", self.BASE + path,
                                              headers={"x-apikey": self.s.vt_api_key}, params=params)
        if code == 200:
            self.eng.cache.set(key, {"status": code, "json": js})
        return code, js, False

    def _rel(self, sha, rel, limit=40):
        code, js, _ = self.get(f"/files/{sha}/{rel}", {"limit": limit})
        if code == 200 and isinstance(js, dict):
            return {"status": "ok", "items": js.get("data") or [],
                    "count": (js.get("meta") or {}).get("count")}
        if code == 404:
            return {"status": "ok", "items": [], "count": 0}
        if code == 403:
            return {"status": "restricted", "items": [], "count": None}
        if code == 429:
            return {"status": "rate_limited", "items": [], "count": None}
        return {"status": "error", "items": [], "count": None}

    # -- hash lookup -------------------------------------------------------
    def hash_lookup(self, hashes):
        sha = hashes.get("sha256") or hashes.get("sha1") or hashes.get("md5")
        self.eng.log(f"VirusTotal: file report for {sha[:16]}...")
        code, js, cached = self.get(f"/files/{sha}")
        if code != 200 or not isinstance(js, dict):
            return _http_status("vt", code)
        attrs = (js.get("data") or {}).get("attributes") or {}
        fid = (js.get("data") or {}).get("id") or sha
        res = self.parse_file(attrs, fid)
        res["from_cache"] = cached
        depth = self.s.vt_depth
        res["depth"] = depth
        res["calls_note"] = {"basic": "1 API call", "standard": "~5 API calls", "full": "~8 API calls"}[depth]

        if depth in ("standard", "full"):
            self.eng.log("VirusTotal: sandbox behaviour summary...")
            code, bjs, _ = self.get(f"/files/{fid}/behaviour_summary")
            if code == 200 and isinstance(bjs, dict):
                res["behaviour"] = self.parse_behaviour(bjs.get("data") or {})
            elif code in (403, 429):
                res["behaviour"] = {"status": "restricted" if code == 403 else "rate_limited"}
            else:
                res["behaviour"] = {"status": "none"}
            self.eng.log("VirusTotal: contacted hosts / dropped files...")
            res["relationships"] = {
                "contacted_domains": self._parse_rel("contacted_domains", self._rel(fid, "contacted_domains")),
                "contacted_ips": self._parse_rel("contacted_ips", self._rel(fid, "contacted_ips")),
                "dropped_files": self._parse_rel("dropped_files", self._rel(fid, "dropped_files")),
            }
        if depth == "full":
            self.eng.log("VirusTotal: contacted URLs, MITRE tree, comments...")
            res["relationships"]["contacted_urls"] = self._parse_rel(
                "contacted_urls", self._rel(fid, "contacted_urls"))
            code, mjs, _ = self.get(f"/files/{fid}/behaviour_mitre_trees")
            if code == 200 and isinstance(mjs, dict):
                res["mitre"] = self.parse_mitre(mjs.get("data") or {})
            code, cjs, _ = self.get(f"/files/{fid}/comments", {"limit": 10})
            if code == 200 and isinstance(cjs, dict):
                res["comments"] = self.parse_comments(cjs.get("data") or [])
        return res

    # -- parsers (defensive: every field may be missing or a different type) --
    def parse_file(self, a, sha):
        stats = a.get("last_analysis_stats") or {}
        mal, sus = _int(stats.get("malicious")), _int(stats.get("suspicious"))
        har, und = _int(stats.get("harmless")), _int(stats.get("undetected"))
        total = mal + sus + har + und
        flagged = []
        for eng_name, r in (a.get("last_analysis_results") or {}).items():
            if isinstance(r, dict) and r.get("category") in ("malicious", "suspicious"):
                flagged.append({"engine": eng_name, "category": r.get("category"),
                                "result": _s(r.get("result") or "", 120),
                                "method": r.get("method") or ""})
        flagged.sort(key=lambda x: (x["category"] != "malicious", x["engine"].lower()))

        ptc = a.get("popular_threat_classification") or {}
        categories = [{"value": _s(x.get("value"), 60), "count": _int(x.get("count"))}
                      for x in (ptc.get("popular_threat_category") or []) if isinstance(x, dict)][:6]
        families = [{"value": _s(x.get("value"), 60), "count": _int(x.get("count"))}
                    for x in (ptc.get("popular_threat_name") or []) if isinstance(x, dict)][:8]

        sandboxes = []
        for sb, v in (a.get("sandbox_verdicts") or {}).items():
            if isinstance(v, dict):
                sandboxes.append({"sandbox": sb, "category": v.get("category"),
                                  "confidence": v.get("confidence"),
                                  "classification": [_s(x, 40) for x in (v.get("malware_classification") or [])][:5],
                                  "names": [_s(x, 40) for x in (v.get("malware_names") or [])][:5]})

        yara = [{"rule": _s(y.get("rule_name"), 80), "ruleset": _s(y.get("ruleset_name"), 80),
                 "author": _s(y.get("author"), 60), "source": _s(y.get("source"), 100)}
                for y in (a.get("crowdsourced_yara_results") or []) if isinstance(y, dict)][:25]
        sigma = [{"title": _s(x.get("rule_title"), 100), "level": x.get("rule_level"),
                  "source": _s(x.get("rule_source"), 60)}
                 for x in (a.get("sigma_analysis_results") or []) if isinstance(x, dict)][:20]
        ids = [{"msg": _s(x.get("rule_msg"), 120), "severity": x.get("alert_severity"),
                "category": _s(x.get("rule_category"), 60), "source": _s(x.get("rule_source"), 40)}
               for x in (a.get("crowdsourced_ids_results") or []) if isinstance(x, dict)][:20]

        sig = a.get("signature_info") or {}
        signature = {}
        if isinstance(sig, dict) and sig:
            for k in ("verified", "product", "description", "copyright", "original name",
                      "internal name", "file version", "signing date", "signers"):
                if sig.get(k):
                    signature[k] = _s(sig[k], 160)
            names = [_s(d.get("name"), 80) for d in (sig.get("signers details") or []) if isinstance(d, dict)]
            if names:
                signature["signer_chain"] = names[:6]

        code_insight = []
        for x in (a.get("crowdsourced_ai_results") or []):
            if isinstance(x, dict):
                txt = x.get("analysis") or x.get("summary") or x.get("verdict")
                if txt:
                    code_insight.append(_s(txt, 1500))
        votes = a.get("total_votes") or {}
        pe_info = a.get("pe_info") or {}
        trid = [f"{_s(t.get('file_type'), 40)} ({t.get('probability')}%)"
                for t in (a.get("trid") or []) if isinstance(t, dict)][:3]
        packers = [f"{k}: {_s(v, 40)}" for k, v in (a.get("packers") or {}).items()][:6]

        return {
            "provider": "vt", "label": "VirusTotal", "status": "ok", "sha256": a.get("sha256") or sha,
            "malicious": mal, "suspicious": sus, "harmless": har, "undetected": und,
            "timeout": _int(stats.get("timeout")),
            "unsupported": _int(stats.get("type-unsupported")),
            "total_engines": total,
            "detection_ratio": round((mal + sus) / total * 100, 2) if total else 0.0,
            "reputation": a.get("reputation"),
            "votes": {"harmless": _int(votes.get("harmless")), "malicious": _int(votes.get("malicious"))},
            "meaningful_name": _s(a.get("meaningful_name") or "", 120),
            "names": [_s(n, 100) for n in (a.get("names") or [])][:12],
            "type_description": a.get("type_description"), "type_tag": a.get("type_tag"),
            "size": a.get("size"), "tags": [_s(t, 40) for t in (a.get("tags") or [])][:30],
            "capabilities": [_s(t, 60) for t in (a.get("capabilities_tags") or [])][:20],
            "first_submission": epoch_to_iso(a.get("first_submission_date")),
            "last_submission": epoch_to_iso(a.get("last_submission_date")),
            "last_analysis": epoch_to_iso(a.get("last_analysis_date")),
            "creation_date": epoch_to_iso(a.get("creation_date")),
            "times_submitted": a.get("times_submitted"), "unique_sources": a.get("unique_sources"),
            "threat_label": _s(ptc.get("suggested_threat_label") or "", 80),
            "threat_categories": categories, "threat_families": families,
            "flagged_engines": flagged[:150],
            "sandbox_verdicts": sandboxes, "crowdsourced_yara": yara, "sigma": sigma,
            "sigma_stats": a.get("sigma_analysis_stats") or {}, "ids": ids,
            "signature": signature, "code_insight": code_insight[:2],
            "hashes": {"md5": a.get("md5"), "sha1": a.get("sha1"), "sha256": a.get("sha256"),
                       "ssdeep": a.get("ssdeep"), "tlsh": a.get("tlsh"), "vhash": a.get("vhash"),
                       "authentihash": a.get("authentihash"), "imphash": pe_info.get("imphash")},
            "trid": trid, "packers": packers,
            "permalink": f"https://www.virustotal.com/gui/file/{a.get('sha256') or sha}",
        }

    def parse_behaviour(self, d):
        def lst(key, n=25, fmt=None):
            out = []
            for x in (d.get(key) or [])[:n]:
                out.append(fmt(x) if fmt and isinstance(x, dict) else _s(x, 220))
            return out
        dns = lst("dns_lookups", fmt=lambda x: f"{_s(x.get('hostname'), 100)} -> "
                                                f"{_s(x.get('resolved_ips') or '', 80)}")
        ip_tr = lst("ip_traffic", fmt=lambda x: f"{x.get('destination_ip')}:{x.get('destination_port')} "
                                                f"/{x.get('transport_layer_protocol', '')}")
        http = lst("http_conversations", fmt=lambda x: f"{x.get('request_method', '')} {_s(x.get('url'), 160)} "
                                                       f"[{x.get('response_status_code', '')}]")
        reg = lst("registry_keys_set", fmt=lambda x: f"{_s(x.get('key'), 160)} = {_s(x.get('value') or '', 60)}")
        mitre = []
        for m in (d.get("mitre_attack_techniques") or [])[:40]:
            if isinstance(m, dict) and m.get("id"):
                mitre.append({"id": m.get("id"), "severity": m.get("severity"),
                              "description": _s(m.get("signature_description"), 160)})
        return {
            "status": "ok",
            "processes_created": lst("processes_created"),
            "command_executions": lst("command_executions"),
            "files_written": lst("files_written"),
            "files_dropped": lst("files_dropped", fmt=lambda x: _s(x.get("path") or x, 160)),
            "files_deleted": lst("files_deleted", 15),
            "registry_keys_set": reg,
            "registry_keys_deleted": lst("registry_keys_deleted", 10),
            "mutexes_created": lst("mutexes_created", 20),
            "services_started": lst("services_started", 10),
            "modules_loaded": lst("modules_loaded", 15),
            "dns_lookups": dns, "ip_traffic": ip_tr, "http_conversations": http,
            "mitre_attack_techniques": mitre,
            "tags": [_s(t, 40) for t in (d.get("tags") or [])][:25],
            "verdicts": [_s(t, 40) for t in (d.get("verdicts") or [])][:6],
            "verdict_labels": [_s(t, 40) for t in (d.get("verdict_labels") or [])][:8],
            "calls_highlighted": lst("calls_highlighted", 15),
            "text_highlighted": lst("text_highlighted", 10),
        }

    def parse_mitre(self, data):
        out = []
        for sandbox, v in (data or {}).items():
            if not isinstance(v, dict):
                continue
            for tac in v.get("tactics") or []:
                for tech in tac.get("techniques") or []:
                    out.append({"sandbox": _s(sandbox, 40), "tactic": _s(tac.get("name"), 60),
                                "technique_id": _s(tech.get("id"), 20),
                                "technique": _s(tech.get("name"), 100),
                                "severity": tech.get("severity"),
                                "signatures": [_s(s.get("description"), 140)
                                               for s in (tech.get("signatures") or [])[:3]
                                               if isinstance(s, dict)]})
        return out[:80]

    def parse_comments(self, data):
        out = []
        for c in data[:10]:
            at = (c or {}).get("attributes") or {}
            if at.get("text"):
                out.append({"date": epoch_to_iso(at.get("date")), "text": _s(at["text"], 400)})
        return out

    def _parse_rel(self, kind, rel):
        items = []
        for it in rel.get("items") or []:
            at = (it or {}).get("attributes") or {}
            st = at.get("last_analysis_stats") or {}
            mal = _int(st.get("malicious")) + _int(st.get("suspicious"))
            if kind in ("contacted_domains", "contacted_ips"):
                items.append({"value": it.get("id"), "malicious": mal, "reputation": at.get("reputation"),
                              "country": at.get("country"), "owner": _s(at.get("as_owner") or "", 60)})
            elif kind == "contacted_urls":
                items.append({"value": _s(at.get("url") or it.get("id"), 200), "malicious": mal,
                              "reputation": at.get("reputation")})
            elif kind == "dropped_files":
                items.append({"value": it.get("id"), "name": _s(at.get("meaningful_name") or "", 80),
                              "type": at.get("type_description"), "size": at.get("size"), "malicious": mal})
        return {"status": rel.get("status"), "count": rel.get("count"), "items": items[:40]}

    # -- network enrichment --------------------------------------------------
    def ip_lookup(self, ip):
        code, js, _ = self.get(f"/ip_addresses/{ip}")
        if code != 200 or not isinstance(js, dict):
            return _http_status("vt", code)
        a = (js.get("data") or {}).get("attributes") or {}
        st = a.get("last_analysis_stats") or {}
        return _res("vt", "ok", malicious=_int(st.get("malicious")), suspicious=_int(st.get("suspicious")),
                    total=sum(_int(st.get(k)) for k in ("malicious", "suspicious", "harmless", "undetected")),
                    reputation=a.get("reputation"), country=a.get("country"),
                    owner=_s(a.get("as_owner") or "", 80), asn=a.get("asn"),
                    tags=[_s(t, 30) for t in (a.get("tags") or [])][:8])

    def domain_lookup(self, d):
        code, js, _ = self.get(f"/domains/{d}")
        if code != 200 or not isinstance(js, dict):
            return _http_status("vt", code)
        a = (js.get("data") or {}).get("attributes") or {}
        st = a.get("last_analysis_stats") or {}
        cats = sorted({_s(v, 30) for v in (a.get("categories") or {}).values()})[:6]
        return _res("vt", "ok", malicious=_int(st.get("malicious")), suspicious=_int(st.get("suspicious")),
                    total=sum(_int(st.get(k)) for k in ("malicious", "suspicious", "harmless", "undetected")),
                    reputation=a.get("reputation"), registrar=_s(a.get("registrar") or "", 60),
                    created=epoch_to_iso(a.get("creation_date")), categories=cats,
                    tags=[_s(t, 30) for t in (a.get("tags") or [])][:8])


# ----------------------------------------------------------------------------
# abuse.ch family
# ----------------------------------------------------------------------------

class MalwareBazaar:
    name = "mb"
    URL = "https://mb-api.abuse.ch/api/v1/"

    def __init__(self, eng):
        self.eng, self.s = eng, eng.settings

    def hash_lookup(self, hashes):
        h = hashes.get("sha256") or hashes.get("md5") or hashes.get("sha1")
        code, js, _ = self.eng.http.request("POST", self.URL, headers={"Auth-Key": self.s.abusech_auth_key},
                                            data={"query": "get_info", "hash": h})
        if code != 200 or not isinstance(js, dict):
            return _http_status("mb", code)
        qs = js.get("query_status")
        if qs in ("hash_not_found", "no_results"):
            return _res("mb", "not_found")
        if qs != "ok" or not js.get("data"):
            return _res("mb", "error", error=f"query_status={qs}")
        d = js["data"][0]
        vendors = d.get("vendor_intel") or {}
        vi = []
        for vname, v in vendors.items():
            if isinstance(v, dict):
                vi.append(f"{vname}: " + _s(v.get("verdict") or v.get("threat_name") or v.get("malware_family")
                                            or v.get("detection") or v, 100))
            elif isinstance(v, list) and v:
                first = v[0] if isinstance(v[0], dict) else {"x": v[0]}
                vi.append(f"{vname}: " + _s(first.get("verdict") or first.get("detection") or first, 100))
        intel = d.get("intelligence") or {}
        return _res("mb", "ok", signature=_s(d.get("signature") or "", 60),
                    file_name=_s(d.get("file_name") or "", 100), file_type=d.get("file_type"),
                    mime=d.get("file_type_mime"), size=d.get("file_size"),
                    first_seen=d.get("first_seen"), last_seen=d.get("last_seen"),
                    reporter=_s(d.get("reporter") or "", 40), country=d.get("origin_country"),
                    delivery_method=_s(d.get("delivery_method") or "", 40),
                    tags=[_s(t, 40) for t in (d.get("tags") or [])][:20],
                    clamav=[_s(c, 60) for c in (intel.get("clamav") or [])][:5],
                    downloads=intel.get("downloads"), uploads=intel.get("uploads"),
                    yara=[{"rule": _s(y.get("rule_name"), 80), "author": _s(y.get("author"), 40)}
                          for y in (d.get("yara_rules") or []) if isinstance(y, dict)][:15],
                    vendor_intel=vi[:15],
                    hashes={"imphash": d.get("imphash"), "tlsh": d.get("tlsh"), "ssdeep": d.get("ssdeep")},
                    permalink=f"https://bazaar.abuse.ch/sample/{d.get('sha256_hash') or h}/")


class URLhaus:
    name = "urlhaus"
    BASE = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self, eng):
        self.eng, self.s = eng, eng.settings

    def _post(self, path, data):
        return self.eng.http.request("POST", self.BASE + path,
                                     headers={"Auth-Key": self.s.abusech_auth_key}, data=data)

    def hash_lookup(self, hashes):
        field, val = (("sha256_hash", hashes["sha256"]) if hashes.get("sha256")
                      else ("md5_hash", hashes.get("md5")))
        code, js, _ = self._post("/payload/", {field: val})
        if code != 200 or not isinstance(js, dict):
            return _http_status("urlhaus", code)
        if js.get("query_status") != "ok":
            return _res("urlhaus", "not_found")
        urls = [{"url": _s(u.get("url"), 200), "status": u.get("url_status"), "filename": _s(u.get("filename") or "", 60),
                 "first_seen": u.get("firstseen")} for u in (js.get("urls") or []) if isinstance(u, dict)]
        vt = js.get("virustotal") or {}
        return _res("urlhaus", "ok", signature=_s(js.get("signature") or "", 60), file_type=js.get("file_type"),
                    first_seen=js.get("firstseen"), last_seen=js.get("lastseen"),
                    url_count=_int(js.get("url_count")), distribution_urls=urls[:20],
                    vt_percent=vt.get("percent") if isinstance(vt, dict) else None,
                    permalink=js.get("urlhaus_download") or "https://urlhaus.abuse.ch/")

    def host_lookup(self, host):
        code, js, _ = self._post("/host/", {"host": host})
        if code != 200 or not isinstance(js, dict):
            return _http_status("urlhaus", code)
        if js.get("query_status") != "ok":
            return _res("urlhaus", "not_found")
        urls = js.get("urls") or []
        online = sum(1 for u in urls if isinstance(u, dict) and u.get("url_status") == "online")
        return _res("urlhaus", "ok", url_count=_int(js.get("url_count")), online=online,
                    blacklists=js.get("blacklists") or {}, first_seen=js.get("firstseen"),
                    threats=sorted({_s(u.get("threat"), 30) for u in urls if isinstance(u, dict) and u.get("threat")})[:5])

    ip_lookup = host_lookup
    domain_lookup = host_lookup


class ThreatFox:
    name = "threatfox"
    URL = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(self, eng):
        self.eng, self.s = eng, eng.settings

    def _q(self, body):
        return self.eng.http.request("POST", self.URL, headers={"Auth-Key": self.s.abusech_auth_key},
                                     json_body=body)

    @staticmethod
    def _rows(js):
        data = js.get("data") if isinstance(js, dict) else None
        if not isinstance(data, list):
            return []
        return [{"ioc": _s(x.get("ioc"), 200), "type": x.get("ioc_type"), "threat_type": x.get("threat_type"),
                 "malware": _s(x.get("malware_printable") or x.get("malware") or "", 60),
                 "confidence": x.get("confidence_level"), "first_seen": x.get("first_seen"),
                 "tags": [_s(t, 30) for t in (x.get("tags") or [])][:6]}
                for x in data if isinstance(x, dict)][:30]

    def hash_lookup(self, hashes):
        h = hashes.get("sha256") or hashes.get("md5")
        code, js, _ = self._q({"query": "search_hash", "hash": h})
        if code == 200 and isinstance(js, dict) and js.get("query_status") == "ok":
            rows = self._rows(js)
        else:
            if code in (401, 403, 429):
                return _http_status("threatfox", code)
            code, js, _ = self._q({"query": "search_ioc", "search_term": h, "exact_match": True})
            if code != 200 or not isinstance(js, dict):
                return _http_status("threatfox", code)
            rows = self._rows(js) if js.get("query_status") == "ok" else []
        if not rows:
            return _res("threatfox", "not_found")
        return _res("threatfox", "ok", iocs=rows,
                    malware=unique_keep_order(r["malware"] for r in rows if r["malware"])[:6],
                    permalink="https://threatfox.abuse.ch/browse/")

    def _ioc(self, term):
        code, js, _ = self._q({"query": "search_ioc", "search_term": term, "exact_match": False})
        if code != 200 or not isinstance(js, dict):
            return _http_status("threatfox", code)
        rows = self._rows(js) if js.get("query_status") == "ok" else []
        if not rows:
            return _res("threatfox", "not_found")
        return _res("threatfox", "ok", iocs=rows[:5], malware=unique_keep_order(
            r["malware"] for r in rows if r["malware"])[:4])

    ip_lookup = _ioc
    domain_lookup = _ioc


# ----------------------------------------------------------------------------
# AlienVault OTX
# ----------------------------------------------------------------------------

class OTX:
    name = "otx"
    BASE = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(self, eng):
        self.eng, self.s = eng, eng.settings

    def _general(self, kind, value):
        code, js, _ = self.eng.http.request("GET", f"{self.BASE}/{kind}/{value}/general",
                                            headers={"X-OTX-API-KEY": self.s.otx_api_key})
        if code != 200 or not isinstance(js, dict):
            return None, _http_status("otx", code)
        return js, None

    @staticmethod
    def _pulses(js):
        info = js.get("pulse_info") or {}
        pulses, fams, attack, tags = [], [], [], []
        for p in (info.get("pulses") or [])[:50]:
            if not isinstance(p, dict):
                continue
            pulses.append({"name": _s(p.get("name"), 110), "author": _s(p.get("author_name"), 40),
                           "modified": _s(p.get("modified"), 20), "adversary": _s(p.get("adversary") or "", 40)})
            for f in p.get("malware_families") or []:
                fams.append(_s(f.get("display_name") or f.get("id") if isinstance(f, dict) else f, 50))
            for t in p.get("attack_ids") or []:
                if isinstance(t, dict) and t.get("id"):
                    attack.append({"id": t["id"], "name": _s(t.get("name") or t.get("display_name") or "", 80)})
            tags += [_s(t, 30) for t in (p.get("tags") or [])]
        fam_rank = [k for k, _ in Counter(f for f in fams if f).most_common(8)]
        tag_rank = [k for k, _ in Counter(tags).most_common(12)]
        seen, atk = set(), []
        for a in attack:
            if a["id"] not in seen:
                seen.add(a["id"])
                atk.append(a)
        return _int(info.get("count")), pulses[:12], fam_rank, atk[:25], tag_rank

    def hash_lookup(self, hashes):
        h = hashes.get("sha256") or hashes.get("sha1") or hashes.get("md5")
        js, err = self._general("file", h)
        if err:
            return err
        count, pulses, fams, atk, tags = self._pulses(js)
        return _res("otx", "ok" if count else "not_found", pulse_count=count, pulses=pulses,
                    families=fams, attack_ids=atk, tags=tags,
                    permalink=f"https://otx.alienvault.com/indicator/file/{h}")

    def ip_lookup(self, ip):
        js, err = self._general("IPv4", ip)
        if err:
            return err
        count, pulses, fams, atk, tags = self._pulses(js)
        return _res("otx", "ok", pulse_count=count, pulses=pulses[:5], families=fams[:4],
                    reputation=js.get("reputation"), country=js.get("country_name"), asn=js.get("asn"))

    def domain_lookup(self, d):
        js, err = self._general("domain", d)
        if err:
            return err
        count, pulses, fams, atk, tags = self._pulses(js)
        return _res("otx", "ok", pulse_count=count, pulses=pulses[:5], families=fams[:4])


# ----------------------------------------------------------------------------
# Hybrid Analysis
# ----------------------------------------------------------------------------

class HybridAnalysis:
    name = "ha"
    BASE = "https://www.hybrid-analysis.com/api/v2"

    def __init__(self, eng):
        self.eng, self.s = eng, eng.settings

    def _hdr(self):
        return {"api-key": self.s.hybrid_analysis_api_key, "user-agent": "Falcon Sandbox",
                "accept": "application/json"}

    def hash_lookup(self, hashes):
        sha = hashes.get("sha256")
        if sha:
            code, js, _ = self.eng.http.request("GET", f"{self.BASE}/overview/{sha}", headers=self._hdr())
        else:
            h = hashes.get("sha1") or hashes.get("md5")
            code, js, _ = self.eng.http.request("POST", f"{self.BASE}/search/hash", headers=self._hdr(),
                                                data={"hash": h})
        if code != 200 or not isinstance(js, dict):
            return _http_status("ha", code)
        if "verdict" not in js and "threat_score" not in js and "sha256" not in js:
            return _res("ha", "not_found")
        return _res("ha", "ok", verdict=_s(js.get("verdict") or "unknown", 40),
                    threat_score=js.get("threat_score"), av_detect=js.get("av_detect"),
                    family=_s(js.get("vx_family") or "", 60),
                    tags=[_s(t, 40) for t in (js.get("tags") or [])][:20],
                    file_type=_s(js.get("type") or js.get("type_short") or "", 80),
                    size=js.get("size"), file_name=_s(js.get("last_file_name") or "", 100),
                    last_analysis=_s(js.get("analysis_start_time") or js.get("last_multi_scan") or "", 30),
                    permalink=f"https://www.hybrid-analysis.com/sample/{js.get('sha256') or sha or ''}")


# ----------------------------------------------------------------------------
# AbuseIPDB
# ----------------------------------------------------------------------------

class AbuseIPDB:
    name = "abuseipdb"
    URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, eng):
        self.eng, self.s = eng, eng.settings

    def ip_lookup(self, ip):
        code, js, _ = self.eng.http.request("GET", self.URL, headers={"Key": self.s.abuseipdb_api_key},
                                            params={"ipAddress": ip, "maxAgeInDays": 90})
        if code != 200 or not isinstance(js, dict):
            return _http_status("abuseipdb", code)
        d = js.get("data") or {}
        return _res("abuseipdb", "ok", score=_int(d.get("abuseConfidenceScore")),
                    reports=_int(d.get("totalReports")), users=_int(d.get("numDistinctUsers")),
                    country=d.get("countryCode"), isp=_s(d.get("isp") or "", 60),
                    usage=_s(d.get("usageType") or "", 40), domain=_s(d.get("domain") or "", 60),
                    tor=bool(d.get("isTor")), last_reported=_s(d.get("lastReportedAt") or "", 30))


# ----------------------------------------------------------------------------
# Engine
# ----------------------------------------------------------------------------

_CLASSES = {"vt": VirusTotal, "mb": MalwareBazaar, "urlhaus": URLhaus, "threatfox": ThreatFox,
            "otx": OTX, "ha": HybridAnalysis, "abuseipdb": AbuseIPDB}
_KEY_ATTR = {"vt": "vt_api_key", "mb": "abusech_auth_key", "urlhaus": "abusech_auth_key",
             "threatfox": "abusech_auth_key", "otx": "otx_api_key", "ha": "hybrid_analysis_api_key",
             "abuseipdb": "abuseipdb_api_key"}


class IntelEngine:
    def __init__(self, settings, selected=None, enrich=False, log=None, refresh=False, use_cache=True):
        self.settings = settings
        self.enrich = enrich
        self.refresh = refresh
        self.log = log or (lambda m: None)
        self.cache = DiskCache(settings.cache_dir, settings.cache_ttl_hours, enabled=use_cache)
        self._lock = threading.Lock()
        self.http = Http(settings) if requests is not None else None
        configured = [p for p in _CLASSES if getattr(settings, _KEY_ATTR[p])]
        self.requested = list(selected) if selected else configured
        self.providers = {}
        for p in self.requested:
            if getattr(settings, _KEY_ATTR[p]) and self.http is not None:
                self.providers[p] = _CLASSES[p](self)

    def cache_get(self, key):
        return None if self.refresh else self.cache.get(key)

    # -- safe call ---------------------------------------------------------
    def _guard(self, provider, fn, *args):
        try:
            return fn(*args)
        except IntelError as e:
            return _res(provider, "error", error=redact(str(e), self.settings.secrets()))
        except Exception as e:  # never let one provider break the analysis
            return _res(provider, "error",
                        error=f"{type(e).__name__}: {redact(str(e), self.settings.secrets())}"[:200])

    def _missing(self):
        out = {}
        for p in self.requested:
            if p in self.providers:
                continue
            if self.http is None:
                out[p] = _res(p, "error", error="Python 'requests' is not installed (pip install requests).")
            else:
                out[p] = _res(p, "no_key", error="No API key configured (see .env).")
        return out

    # -- main --------------------------------------------------------------
    def run(self, hashes: dict, iocs: dict | None = None) -> dict:
        t0 = time.time()
        result = {"enabled": True, "requested": self.requested, "providers": {}, "network": {},
                  "enrichment_enabled": self.enrich, "queried_with": {}}
        result["providers"].update(self._missing())
        hash_provs = [p for p in self.providers if p in HASH_PROVIDERS]
        result["queried_with"] = {"hash_lookup": hash_provs,
                                  "note": "Only file hashes were sent; the sample was NOT uploaded."}

        # candidates for IOC enrichment (opt-in)
        ips, doms = [], []
        if self.enrich and iocs:
            lim = max(0, self.settings.enrich_limit)
            ips = [i for i in iocs.get("ips", []) if is_public_ip(i)][:lim]
            doms = iocs.get("domains", [])[:lim]
            result["queried_with"]["enrich_ips"] = ips
            result["queried_with"]["enrich_domains"] = doms
            result["queried_with"]["note"] = ("File hashes AND the listed domains/IPs extracted from the "
                                              "sample were sent to the selected providers.")

        def worker(p):
            prov = self.providers[p]
            out = self._guard(p, prov.hash_lookup, hashes) if p in HASH_PROVIDERS else None
            net = {}
            if self.enrich:
                for ip in ips:
                    if hasattr(prov, "ip_lookup"):
                        net[("ip", ip)] = self._guard(p, prov.ip_lookup, ip)
                for d in doms:
                    if hasattr(prov, "domain_lookup"):
                        net[("domain", d)] = self._guard(p, prov.domain_lookup, d)
            return p, out, net

        jobs = [p for p in self.providers if p in HASH_PROVIDERS or (self.enrich and p in NETWORK_PROVIDERS)]
        if jobs:
            with cf.ThreadPoolExecutor(max_workers=len(jobs)) as ex:
                for p, out, net in ex.map(worker, jobs):
                    if out is not None:
                        result["providers"][p] = out
                    for (typ, val), r in net.items():
                        entry = result["network"].setdefault(
                            f"{typ}:{val}", {"indicator": val, "type": typ, "providers": {}})
                        entry["providers"][p] = r

        # providers that were requested only for network (abuseipdb) but no enrichment
        for p in self.requested:
            if p in self.providers and p not in result["providers"] and p not in HASH_PROVIDERS:
                result["providers"][p] = _res(p, "skipped",
                                              error="Network-only provider; use --enrich to query IPs.")
        for entry in result["network"].values():
            entry["flagged"], entry["note"] = self._net_flag(entry)
        result["summary"] = summarize(result)
        result["elapsed_s"] = round(time.time() - t0, 1)
        return result

    @staticmethod
    def _net_flag(entry):
        notes = []
        for p, r in entry["providers"].items():
            if r.get("status") != "ok":
                continue
            if p == "vt" and (r.get("malicious", 0) + r.get("suspicious", 0)) > 0:
                notes.append(f"VT {r['malicious'] + r['suspicious']}/{r.get('total', 0)}")
            if p == "abuseipdb" and r.get("score", 0) >= 25:
                notes.append(f"AbuseIPDB {r['score']}%")
            if p == "otx" and r.get("pulse_count", 0) > 0:
                notes.append(f"OTX {r['pulse_count']} pulses")
            if p == "urlhaus" and r.get("url_count", 0) > 0:
                notes.append(f"URLhaus {r['url_count']} URLs")
            if p == "threatfox" and r.get("iocs"):
                notes.append("ThreatFox hit")
        return bool(notes), ", ".join(notes)


def hash_lookup_only(settings, hash_value: str, selected=None, log=None, refresh=False, use_cache=True):
    """Lookup a bare hash (no file)."""
    n = len(hash_value)
    key = {32: "md5", 40: "sha1", 64: "sha256"}.get(n)
    if not key:
        raise ValueError("Hash must be MD5 (32), SHA-1 (40) or SHA-256 (64) hex characters.")
    eng = IntelEngine(settings, selected=selected, enrich=False, log=log, refresh=refresh, use_cache=use_cache)
    return eng.run({key: hash_value.lower()}, None)


# ----------------------------------------------------------------------------
# Summary / verdict
# ----------------------------------------------------------------------------

def summarize(result: dict) -> dict:
    provs = result.get("providers", {})
    ok = [p for p, r in provs.items() if r.get("status") == "ok"]
    nf = [p for p, r in provs.items() if r.get("status") == "not_found"]
    bad = [p for p, r in provs.items() if r.get("status") in ("error", "rate_limited", "restricted")]
    skipped = [p for p, r in provs.items() if r.get("status") in ("no_key", "skipped")]

    vt = provs.get("vt", {})
    vt_mal = vt.get("malicious", 0) if vt.get("status") == "ok" else 0
    vt_sus = vt.get("suspicious", 0) if vt.get("status") == "ok" else 0
    vt_total = vt.get("total_engines", 0) if vt.get("status") == "ok" else 0

    fam = Counter()

    def add(name, w=1):
        n = clean_text(name or "", 50).strip().lower()
        if n and n not in {"unknown", "generic", "malware", "trojan", "agent", "none", "n/a"}:
            fam[n] += w

    if vt.get("status") == "ok":
        for f in vt.get("threat_families", []):
            add(f["value"], max(1, f.get("count", 1)) // 3 + 1)
    mb = provs.get("mb", {})
    if mb.get("status") == "ok":
        add(mb.get("signature"), 4)
    uh = provs.get("urlhaus", {})
    if uh.get("status") == "ok":
        add(uh.get("signature"), 3)
    tf = provs.get("threatfox", {})
    if tf.get("status") == "ok":
        for m in tf.get("malware", []):
            add(m, 3)
    ha = provs.get("ha", {})
    if ha.get("status") == "ok":
        add(ha.get("family"), 3)
    ox = provs.get("otx", {})
    if ox.get("status") == "ok":
        for f in ox.get("families", [])[:3]:
            add(f, 1)

    ha_verdict = (ha.get("verdict") or "").lower() if ha.get("status") == "ok" else ""
    hits = []
    if vt_mal >= 1 or vt_sus >= 1:
        hits.append("vt")
    for p in ("mb", "urlhaus", "threatfox"):
        if provs.get(p, {}).get("status") == "ok":
            hits.append(p)
    if "malicious" in ha_verdict or "suspicious" in ha_verdict:
        hits.append("ha")
    if ox.get("status") == "ok" and ox.get("pulse_count", 0) >= 3:
        hits.append("otx")

    if vt_mal >= 5 or provs.get("mb", {}).get("status") == "ok" or provs.get("threatfox", {}).get("status") == "ok" \
            or "malicious" in ha_verdict or provs.get("urlhaus", {}).get("status") == "ok":
        verdict = "malicious"
    elif vt_mal + vt_sus >= 1 or "suspicious" in ha_verdict or (ox.get("pulse_count", 0) >= 3):
        verdict = "suspicious"
    elif vt.get("status") == "ok" and vt_total >= 40 and vt_mal + vt_sus == 0:
        verdict = "no_detections"
    elif ok:
        verdict = "inconclusive"
    elif nf and not ok:
        verdict = "not_found"
    elif bad and not ok:
        verdict = "unavailable"          # every queried provider failed (bad key / outage / quota)
    else:
        verdict = "not_queried"

    first_seen = [d for d in [vt.get("first_submission"), mb.get("first_seen")] if d]
    sandbox_techniques = []
    if vt.get("status") == "ok":
        for m in (vt.get("behaviour") or {}).get("mitre_attack_techniques", []):
            sandbox_techniques.append({"id": m["id"], "description": m.get("description", ""), "source": "VirusTotal sandbox"})
        for m in vt.get("mitre", []) or []:
            sandbox_techniques.append({"id": m["technique_id"], "name": m["technique"],
                                       "tactic": m["tactic"], "source": "VirusTotal sandbox"})
    if ox.get("status") == "ok":
        for a in ox.get("attack_ids", [])[:15]:
            sandbox_techniques.append({"id": a["id"], "name": a.get("name"), "source": "OTX pulses"})

    return {
        "verdict": verdict,
        "providers_ok": ok, "providers_not_found": nf, "providers_failed": bad, "providers_skipped": skipped,
        "hits": hits,
        "vt_malicious": vt_mal, "vt_suspicious": vt_sus, "vt_total": vt_total,
        "ha_verdict": ha_verdict, "ha_threat_score": ha.get("threat_score") if ha.get("status") == "ok" else None,
        "families": [k for k, _ in fam.most_common(8)],
        "first_seen": min(first_seen) if first_seen else None,
        "observed_techniques": sandbox_techniques[:60],
        "network_flagged": sum(1 for e in result.get("network", {}).values() if e.get("flagged")),
    }
