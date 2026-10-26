import sys, json, argparse, re
ROOT = str(__import__("pathlib").Path(__file__).resolve().parent.parent)
sys.path.insert(0, ROOT)
from pathlib import Path
from mal import intel, cli
from mal.config import Settings

SHA = "abcd329bf9d2d654db54dea082b943867b2a9a3b7341c41bbb6dee0e4ebb8fc4"
KEY = "SECRETKEY-1234567890abcdef"

VT_FILE = {"data": {"id": SHA, "type": "file", "attributes": {
  "sha256": SHA, "md5": "m"*32, "sha1": "s"*40, "meaningful_name": "dropper.ps1", "names": ["dropper.ps1", "x.ps1"],
  "type_description": "PowerShell", "type_tag": "powershell", "size": 602, "reputation": -45,
  "last_analysis_stats": {"malicious": 31, "suspicious": 2, "harmless": 0, "undetected": 30, "timeout": 1, "type-unsupported": 3},
  "last_analysis_results": {"EngA": {"category": "malicious", "result": "Trojan.PS.Agent", "method": "blacklist"},
                            "EngB": {"category": "suspicious", "result": "Heur.Script"}, "EngC": {"category": "undetected", "result": None}},
  "popular_threat_classification": {"suggested_threat_label": "trojan.powershell/agent",
      "popular_threat_category": [{"count": 20, "value": "trojan"}, {"count": 5, "value": "downloader"}],
      "popular_threat_name": [{"count": 14, "value": "agent"}, {"count": 9, "value": "emotet"}]},
  "sandbox_verdicts": {"Zenbox": {"category": "malicious", "confidence": 90, "malware_classification": ["TROJAN"], "malware_names": ["Emotet"]}},
  "crowdsourced_yara_results": [{"rule_name": "PS_Downloader", "ruleset_name": "ruleset1", "author": "x", "source": "https://s"}],
  "sigma_analysis_results": [{"rule_title": "Encoded PowerShell", "rule_level": "high", "rule_source": "SigmaHQ"}],
  "sigma_analysis_stats": {"high": 1, "critical": 0, "medium": 0, "low": 0},
  "crowdsourced_ids_results": [{"rule_msg": "ET MALWARE X", "alert_severity": "high", "rule_category": "A Network Trojan", "rule_source": "ET"}],
  "signature_info": {"verified": "Unsigned", "signers details": [{"name": "Someone"}]},
  "crowdsourced_ai_results": [{"analysis": "The script downloads and runs a second stage.", "category": "malicious"}],
  "total_votes": {"harmless": 1, "malicious": 12}, "tags": ["powershell", "obfuscated"],
  "first_submission_date": 1700000000, "last_analysis_date": 1760000000, "times_submitted": 40, "unique_sources": 12,
  "trid": [{"file_type": "PowerShell", "probability": 80.0}], "packers": {"PEiD": "UPX"},
}}}
BEH = {"data": {"processes_created": ["powershell.exe -enc AAA", {"weird": "dict"}], "command_executions": ["cmd /c whoami"],
  "registry_keys_set": [{"key": "HKCU\\Run\\Upd", "value": "x"}], "dns_lookups": [{"hostname": "update-check.top", "resolved_ips": ["198.51.100.5"]}],
  "ip_traffic": [{"destination_ip": "198.51.100.5", "destination_port": 443, "transport_layer_protocol": "TCP"}],
  "http_conversations": [{"url": "http://update-check.top/stage2.ps1", "request_method": "GET", "response_status_code": 200}],
  "mitre_attack_techniques": [{"id": "T1059.001", "severity": "IMPACT_SEVERITY_HIGH", "signature_description": "Runs PowerShell"}],
  "mutexes_created": ["Global\\x"], "tags": ["PERSISTENCE"], "verdict_labels": ["trojan"]}}
def rel(items): return {"data": items, "meta": {"count": len(items)}}

class FakeHttp:
    def __init__(self, mode="ok"): self.mode=mode; self.calls=[]
    def request(self, method, url, headers=None, params=None, data=None, json_body=None):
        self.calls.append((method, url, headers))
        m=self.mode
        if m=="net": raise intel.IntelError("connection failed to https://x with key "+KEY)
        if m=="401": return 401, {"error":{}}, ""
        if m=="429": return 429, None, ""
        if m=="garbage": return 200, {"data": None}, ""
        if m=="nf": return 404, {"error":{"code":"NotFoundError"}}, ""
        u=url
        if "virustotal" in u:
            if u.endswith(f"/files/{SHA}"): return 200, VT_FILE, ""
            if u.endswith("behaviour_summary"): return 200, BEH, ""
            if u.endswith("contacted_domains"): return 200, rel([{"id":"update-check.top","attributes":{"last_analysis_stats":{"malicious":9},"reputation":-10}}]), ""
            if u.endswith("contacted_ips"): return 200, rel([{"id":"198.51.100.5","attributes":{"last_analysis_stats":{"malicious":4},"country":"NL","as_owner":"Host"}}]), ""
            if u.endswith("dropped_files"): return 200, rel([{"id":"d"*64,"attributes":{"meaningful_name":"upd.exe","type_description":"Win32 EXE","size":9000,"last_analysis_stats":{"malicious":40}}}]), ""
            if u.endswith("contacted_urls"): return 403, {"error":{"code":"ForbiddenError"}}, ""
            if u.endswith("behaviour_mitre_trees"): return 200, {"data":{"Zenbox":{"tactics":[{"name":"Execution","techniques":[{"id":"T1059.001","name":"PowerShell","severity":"HIGH","signatures":[{"description":"ran ps"}]}]}]}}}, ""
            if u.endswith("comments"): return 200, {"data":[{"attributes":{"text":"<script>alert(1)</script> seen in campaign","date":1700000000}}]}, ""
            if "/ip_addresses/" in u: return 200, {"data":{"attributes":{"last_analysis_stats":{"malicious":6,"harmless":60},"reputation":-20,"country":"RU","as_owner":"EvilNet"}}}, ""
            if "/domains/" in u: return 200, {"data":{"attributes":{"last_analysis_stats":{"malicious":8,"harmless":50},"reputation":-30,"registrar":"X","categories":{"a":"malware"}}}}, ""
        if "mb-api" in u: return 200, {"query_status":"ok","data":[{"sha256_hash":SHA,"signature":"Emotet","file_name":"d.ps1","file_type":"ps1","first_seen":"2026-01-01","tags":["ps1","emotet"],"intelligence":{"clamav":["Win.Trojan.X"],"downloads":"10","uploads":"2"},"vendor_intel":{"ReversingLabs":{"threat_name":"Script.Trojan.Emotet","status":"MALICIOUS"},"Spamhaus_HBL":[{"detection":"malware"}]},"yara_rules":[{"rule_name":"r1","author":"a"}]}]}, ""
        if "urlhaus" in u and "/payload/" in u: return 200, {"query_status":"ok","signature":"Emotet","url_count":"3","firstseen":"2026-01-02","urls":[{"url":"http://bad.top/x","url_status":"online","filename":"x.ps1","firstseen":"t"}],"virustotal":{"percent":50}}, ""
        if "urlhaus" in u and "/host/" in u: return 200, {"query_status":"ok","url_count":"2","urls":[{"url_status":"online","threat":"malware_download"}],"blacklists":{}}, ""
        if "threatfox" in u: return 200, {"query_status":"ok","data":[{"ioc":"198.51.100.5:443","ioc_type":"ip:port","threat_type":"botnet_cc","malware_printable":"Emotet","confidence_level":90,"first_seen":"t","tags":["emotet"]}]}, ""
        if "otx.alienvault" in u:
            pi={"count":4,"pulses":[{"name":"Emotet campaign","author_name":"a","modified":"2026","malware_families":[{"display_name":"Emotet"},"Loader"],"attack_ids":[{"id":"T1059.001","name":"PowerShell"}],"tags":["emotet"]}]}
            return 200, {"pulse_info":pi,"reputation":0,"country_name":"Russia"}, ""
        if "hybrid-analysis" in u: return 200, {"verdict":"malicious","threat_score":100,"av_detect":80,"vx_family":"Emotet","tags":["evasive"],"type":"script","sha256":SHA}, ""
        if "abuseipdb" in u: return 200, {"data":{"abuseConfidenceScore":97,"totalReports":50,"numDistinctUsers":9,"countryCode":"RU","isp":"EvilNet","usageType":"Data Center","isTor":False}}, ""
        return 404, None, ""

def settings(**kw):
    s = Settings(vt_api_key=KEY, abusech_auth_key=KEY, otx_api_key=KEY, abuseipdb_api_key=KEY,
                 hybrid_analysis_api_key=KEY, vt_rate_limit_per_min=0, cache_ttl_hours=0, vt_depth="full", enrich_limit=3)
    for k,v in kw.items(): setattr(s,k,v)
    return s

def engine(mode="ok", enrich=False, **kw):
    e = intel.IntelEngine(settings(**kw), enrich=enrich, use_cache=False)
    e.http = FakeHttp(mode)
    return e

H = {"sha256": SHA}
# --- 1. full success path
e = engine(enrich=True); iocs = {"ips": ["198.51.100.5", "10.0.0.1"], "domains": ["update-check.top"]}
r = e.run(H, iocs); s = r["summary"]
print("OK  verdict:", s["verdict"], "| families:", s["families"], "| hits:", s["hits"], "| VT", s["vt_malicious"], "/", s["vt_total"])
print("    providers:", {p: v["status"] for p, v in r["providers"].items()})
vt = r["providers"]["vt"]
print("    VT parsed -> label:", vt["threat_label"], "| fams:", [f["value"] for f in vt["threat_families"]], "| sandboxes:", len(vt["sandbox_verdicts"]),
      "| yara:", len(vt["crowdsourced_yara"]), "| sigma:", len(vt["sigma"]), "| ids:", len(vt["ids"]), "| insight:", bool(vt["code_insight"]))
print("    behaviour keys:", [k for k, v in vt["behaviour"].items() if v][:8])
print("    contacted_urls (403):", vt["relationships"]["contacted_urls"]["status"], "| dropped:", vt["relationships"]["dropped_files"]["items"][0]["name"])
print("    network:", {k: (v["flagged"], v["note"]) for k, v in r["network"].items()})
print("    private IP 10.0.0.1 was NOT sent:", not any("10.0.0.1" in str(c) for c in e.http.calls))
print("    sample upload endpoints used:", [c[1] for c in e.http.calls if "upload" in c[1] or c[0]=="PUT"] or "NONE")
# --- 2. failure modes must never crash and must never leak the key
for mode in ("401", "429", "net", "garbage", "nf"):
    e2 = engine(mode); rr = e2.run(H, None)
    blob = json.dumps(rr, default=str)
    print(f"{mode:8} statuses:", sorted({v['status'] for v in rr['providers'].values()}), "| verdict:", rr["summary"]["verdict"], "| key leaked:", KEY in blob)
# --- 3. no keys / selected providers
e3 = intel.IntelEngine(Settings(), use_cache=False); e3.http = FakeHttp()
print("no keys ->", {p: v["status"] for p, v in e3.run(H, None)["providers"].items()} or "no providers requested")
e4 = intel.IntelEngine(Settings(), selected=["vt","otx"], use_cache=False); e4.http = FakeHttp()
print("requested w/o keys ->", {p: v["status"] for p, v in e4.run(H, None)["providers"].items()})
print("parse list:", intel.parse_provider_list("vt, abusech"), intel.parse_provider_list("all"))
try: intel.parse_provider_list("bogus")
except ValueError as ex: print("bad provider rejected:", str(ex)[:50])

# --- 4. render a full report with this intel
args = argparse.Namespace(yara=None, no_deep=False)
eng = engine(enrich=True)
rep, ctx = cli.analyze_file(Path(__file__).resolve().parent / "samples" / "dropper.ps1", settings(), args, eng)
print("\nWith intel: risk", rep["risk"]["level"], rep["risk"]["score"], "| conf", rep["risk"]["confidence"],
      "| floor reason:", any(x["indicator"]=="reputation_floor" for x in rep["risk"]["reasons"]),
      "| observed techniques merged:", [a["technique_id"] for a in rep["attack"] if "VirusTotal sandbox" in a["sources"]])
import tempfile
out = Path(tempfile.mkdtemp())
paths = cli.write_outputs(rep, ctx, out, {"html","json","csv","stix"}, False)
h = paths["html"].read_text()
for needle in ["VirusTotal file intelligence","Sandbox verdicts","Crowdsourced detections","Flagging engines","Sandbox behaviour","Relationships","MalwareBazaar","URLhaus","ThreatFox","Hybrid Analysis","AlienVault OTX","Network IOC enrichment","Code Insight"]:
    print(f"   {'OK ' if needle in h else 'MISSING'} {needle}")
print("   hostile VT comment escaped:", "&lt;script&gt;alert(1)" in h and "<script>alert(1)" not in h)
print("   csv has intel IOCs:", "intel:virustotal-sandbox" in paths["csv"].read_text(), "| threatfox:", "intel:threatfox" in paths["csv"].read_text())

# --- 5. hash-only mode
from mal import cli as c2
r5 = c2.analyze_hash(SHA, settings(), args, engine())
p5 = c2.write_outputs(r5, {"strings": [], "data_len": 0}, out, {"html","json"}, False)
print("hash-only report:", r5["risk"]["level"], r5["risk"]["score"], "| html bytes:", len(p5["html"].read_text()))
