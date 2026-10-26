"""Self-contained HTML dashboard. All dynamic text passes through esc() (or Raw for trusted markup)."""

from __future__ import annotations

import json
import math

from . import __version__ as VERSION
from . import rules as R
from .intel import PROVIDER_LABELS
from .utils import Raw, defang, esc, fmt_size, trunc

LEVEL_COLOR = {"LOW": "#35d07f", "MEDIUM": "#f4c95d", "HIGH": "#ff9b5c", "CRITICAL": "#ff3d68"}
PALETTE = ["#63a4ff", "#35d07f", "#f4c95d", "#ff6577", "#a78bfa", "#5eead4", "#fb923c", "#94a3b8"]

CSS = r"""
:root{--bg:#080b12;--panel:#101621;--panel2:#151d2a;--border:#253044;--text:#e8edf7;--muted:#8e9bb0;
--accent:#63a4ff;--good:#35d07f;--warn:#f4c95d;--bad:#ff6577;--crit:#ff3d68}
*{box-sizing:border-box}
body{margin:0;background:linear-gradient(135deg,#070a10,#0b111b 45%,#080b12);color:var(--text);
font-family:Inter,Segoe UI,Arial,sans-serif;font-size:14px}
a{color:#75b3ff;text-decoration:none}a:hover{text-decoration:underline}
.app{display:flex;min-height:100vh}
.sidebar{width:230px;background:#0b1019;border-right:1px solid var(--border);padding:22px 14px;position:sticky;top:0;height:100vh;overflow:auto}
.brand{font-size:20px;font-weight:800}.brand span{color:var(--accent)}
.sub{font-size:11px;color:var(--muted);margin:4px 0 22px}
.nav a{display:block;padding:9px 12px;border-radius:8px;color:#aeb9ca;margin:3px 0;font-size:13px}
.nav a:hover,.nav a.active{background:#151e2c;color:#fff;text-decoration:none}
.nav a.active{border-left:3px solid var(--accent)}
.main{flex:1;padding:26px;min-width:0;max-width:1700px}
.tab{display:none}.tab.active{display:block}
.header{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;margin-bottom:18px}
h1{font-size:24px;margin:0 0 6px;word-break:break-all}h2{font-size:16px;margin:0 0 12px}h3{font-size:13px;margin:14px 0 8px;color:#c9d6ea}
.muted{color:var(--muted)}.small{font-size:11px}
.badge{display:inline-flex;align-items:center;border:1px solid var(--border);border-radius:999px;padding:4px 10px;font-size:11px;font-weight:700;margin:2px 3px 2px 0}
.badge.LOW,.badge.ok,.badge.good{color:var(--good)}.badge.MEDIUM,.badge.warn,.badge.suspicious{color:var(--warn)}
.badge.HIGH{color:#ff9b5c}.badge.CRITICAL,.badge.bad,.badge.malicious{color:var(--crit)}
.badge.info{color:var(--accent)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:16px}
.card,.panel{background:rgba(16,22,33,.92);border:1px solid var(--border);border-radius:12px;padding:15px}
.panel{margin-bottom:14px}
.kpi .label{font-size:10px;text-transform:uppercase;letter-spacing:.7px;color:var(--muted)}
.kpi .value{font-size:17px;font-weight:800;margin-top:6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.grid2>.panel,.grid3>.panel{margin-bottom:0}.row{margin-bottom:14px}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{text-align:left;padding:8px;border-bottom:1px solid #202a39;vertical-align:top;word-break:break-word}
th{font-size:10px;text-transform:uppercase;color:var(--muted);letter-spacing:.6px}
code{font-family:Consolas,Monaco,monospace;color:#cfe0ff;word-break:break-all}
pre{white-space:pre-wrap;word-break:break-word;background:#0a0f17;border:1px solid var(--border);padding:12px;border-radius:9px;font-size:11px;color:#c7d2e5;max-height:480px;overflow:auto}
details{border:1px solid var(--border);border-radius:9px;margin:8px 0;background:#0d131d}
summary{cursor:pointer;padding:10px 12px;font-size:12px;font-weight:700}details>div{padding:0 12px 12px}
.search{width:100%;background:#0a0f17;border:1px solid var(--border);border-radius:8px;padding:9px;color:#fff;outline:none;margin-bottom:10px}
.btn{background:#182235;border:1px solid #2b3a54;color:#dce8ff;padding:5px 9px;border-radius:7px;cursor:pointer;font-size:11px}
.btn:hover{background:#22304a}
.callout{border-left:3px solid var(--accent);padding:10px 13px;background:#0c1420;border-radius:7px;font-size:12px;margin:8px 0}
.callout.warn{border-color:var(--warn)}.callout.bad{border-color:var(--crit)}
.bar{height:8px;background:#202a3a;border-radius:99px;overflow:hidden}.bar>span{display:block;height:100%;border-radius:99px}
.barrow{display:grid;grid-template-columns:130px 1fr 54px;gap:10px;align-items:center;margin:7px 0;font-size:12px}
.big{font-size:38px;font-weight:900;line-height:1}
.scroll{overflow-x:auto}
.footer{color:#68758a;font-size:10px;margin-top:28px;padding:16px 0;border-top:1px solid var(--border)}
.tactic{margin:10px 0 4px;font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--accent)}
ul.clean{margin:6px 0;padding-left:18px}ul.clean li{margin:3px 0;font-size:12px}
@media(max-width:1100px){.grid2,.grid3{grid-template-columns:1fr}}
@media(max-width:800px){.sidebar{display:none}.main{padding:14px}}
@media print{.sidebar{display:none}.tab{display:block!important}body{background:#fff;color:#000}}
"""

JS = r"""
function showTab(id){
  document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('active',t.id==='tab-'+id));
  document.querySelectorAll('.nav a').forEach(a=>a.classList.toggle('active',a.dataset.tab===id));
  history.replaceState(null,'','#'+id);window.scrollTo(0,0);
}
document.querySelectorAll('.nav a').forEach(a=>a.addEventListener('click',e=>{e.preventDefault();showTab(a.dataset.tab)}));
document.addEventListener('click',e=>{
  const b=e.target.closest('[data-copy]');
  if(b){const v=b.dataset.copy;(navigator.clipboard?navigator.clipboard.writeText(v):Promise.reject()).catch(()=>{});
        b.textContent='Copied';setTimeout(()=>b.textContent='Copy',1200);}
});
function filt(inp,tbl){
  const q=document.getElementById(inp).value.toLowerCase();
  document.querySelectorAll('#'+tbl+' tbody tr').forEach(r=>{r.style.display=r.innerText.toLowerCase().includes(q)?'':'none'});
}
let defanged=true;
function toggleDefang(btn){
  defanged=!defanged;
  document.querySelectorAll('code.ioc').forEach(c=>{c.textContent=defanged?c.dataset.def:c.dataset.raw});
  btn.textContent=defanged?'Show raw (live) IOCs':'Defang IOCs';
}
const start=(location.hash||'#overview').slice(1);
showTab(document.getElementById('tab-'+start)?start:'overview');
"""


# ----------------------------------------------------------------------------
# tiny HTML helpers
# ----------------------------------------------------------------------------

def cell(x) -> str:
    return x if isinstance(x, Raw) else esc(x)


def code(x) -> Raw:
    return Raw(f"<code>{esc(x)}</code>")


def badge(text, kind="") -> Raw:
    return Raw(f'<span class="badge {esc(kind)}">{esc(text)}</span>')


def table(headers, rows, tid=None, empty="No data.") -> Raw:
    if not rows:
        return Raw(f'<div class="muted small">{esc(empty)}</div>')
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell(c)}</td>" for c in r) + "</tr>" for r in rows)
    idattr = f' id="{esc(tid)}"' if tid else ""
    return Raw(f'<div class="scroll"><table{idattr}><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>')


def kv(pairs) -> Raw:
    rows = [[Raw(f'<span class="muted">{esc(k)}</span>'), v if isinstance(v, Raw) else esc(v if v not in (None, "") else "-")]
            for k, v in pairs]
    body = "".join(f"<tr><th style='width:34%'>{r[0]}</th><td>{r[1]}</td></tr>" for r in rows)
    return Raw(f"<table><tbody>{body}</tbody></table>")


def panel(title, body, cls="") -> Raw:
    return Raw(f'<div class="panel {cls}"><h2>{esc(title)}</h2>{body}</div>')


def details(title, body, open_=False) -> Raw:
    return Raw(f'<details{" open" if open_ else ""}><summary>{esc(title)}</summary><div>{body}</div></details>')


def chips(items, kind="info") -> Raw:
    return Raw("".join(f'<span class="badge {kind}">{esc(i)}</span>' for i in items)) if items else Raw('<span class="muted small">none</span>')


def ioc_code(v) -> Raw:
    return Raw(f'<code class="ioc" data-raw="{esc(v)}" data-def="{esc(defang(v))}">{esc(defang(v))}</code>')


def ul(items) -> Raw:
    return Raw("<ul class='clean'>" + "".join(f"<li>{esc(i)}</li>" for i in items) + "</ul>") if items else Raw('<span class="muted small">none</span>')


def gauge(score, level) -> Raw:
    arc = math.pi * 80
    fill = max(0, min(100, score)) / 100 * arc
    color = LEVEL_COLOR.get(level, "#63a4ff")
    return Raw(
        '<svg viewBox="0 0 200 120" width="220" role="img" aria-label="risk gauge">'
        '<path d="M20 100 A80 80 0 0 1 180 100" fill="none" stroke="#202a3a" stroke-width="16" stroke-linecap="round"/>'
        f'<path d="M20 100 A80 80 0 0 1 180 100" fill="none" stroke="{color}" stroke-width="16" stroke-linecap="round" '
        f'stroke-dasharray="{fill:.1f} {arc:.1f}"/>'
        f'<text x="100" y="92" text-anchor="middle" fill="#e8edf7" font-size="34" font-weight="800">{int(score)}</text>'
        f'<text x="100" y="112" text-anchor="middle" fill="{color}" font-size="12" font-weight="700">{esc(level)}</text></svg>')


def entropy_svg(vals) -> Raw:
    if len(vals) < 2:
        return Raw('<div class="muted small">Not enough data.</div>')
    w, h = 640, 90
    pts = " ".join(f"{i * w / (len(vals) - 1):.1f},{h - 6 - v / 8 * (h - 12):.1f}" for i, v in enumerate(vals))
    y72 = h - 6 - 7.2 / 8 * (h - 12)
    return Raw(
        f'<svg viewBox="0 0 {w} {h}" width="100%" height="{h}" preserveAspectRatio="none" role="img" aria-label="entropy map">'
        f'<line x1="0" x2="{w}" y1="{y72:.1f}" y2="{y72:.1f}" stroke="#ff6577" stroke-dasharray="4 4" stroke-width="1"/>'
        f'<polyline fill="none" stroke="#63a4ff" stroke-width="1.6" points="{pts}"/></svg>'
        '<div class="muted small">Entropy across the file (0-8). Dashed line = 7.2 (typical packed / encrypted data).</div>')


def bars(cats) -> Raw:
    rows = []
    for i, (k, (v, cap)) in enumerate(cats):
        pct = 0 if not cap else min(100, v / cap * 100)
        rows.append(f'<div class="barrow"><span>{esc(k.replace("_", " ").title())}</span>'
                    f'<div class="bar"><span style="width:{pct:.0f}%;background:{PALETTE[i % len(PALETTE)]}"></span></div>'
                    f'<strong>{v}/{cap}</strong></div>')
    return Raw("".join(rows) or '<div class="muted small">No scored evidence.</div>')


# ----------------------------------------------------------------------------
# relationship graph
# ----------------------------------------------------------------------------

def graph_svg(report) -> Raw:
    nodes = []
    for d in report["iocs"].get("domains", [])[:10]:
        nodes.append(("domain", d, "#63a4ff"))
    for ip in report["iocs"].get("ips", [])[:6]:
        nodes.append(("ip", ip, "#f4c95d"))
    for u in report["iocs"].get("urls", [])[:5]:
        nodes.append(("url", u, "#a78bfa"))
    deob = report["deobfuscation"]
    for e in (deob["embedded_pe"] + deob["carved_pe"] + deob["xor"]["pe"])[:4]:
        nodes.append(("payload", (e.get("sha256") or "")[:14] + "...", "#fb923c"))
    vt = ((report.get("intel") or {}).get("providers") or {}).get("vt") or {}
    rel = vt.get("relationships") or {}
    for it in (rel.get("contacted_domains") or {}).get("items", [])[:6]:
        nodes.append(("vt-domain", it["value"], "#35d07f"))
    for it in (rel.get("contacted_ips") or {}).get("items", [])[:5]:
        nodes.append(("vt-ip", it["value"], "#5eead4"))
    for it in (rel.get("dropped_files") or {}).get("items", [])[:5]:
        nodes.append(("dropped", (it["value"] or "")[:14] + "...", "#ff6577"))
    if not nodes:
        return Raw('<div class="muted small">No relationships to draw (no network/payload indicators).</div>')
    nodes = nodes[:34]
    W, H, cx, cy = 980, 560, 490, 280
    parts = [f'<svg viewBox="0 0 {W} {H}" width="100%" role="img" aria-label="relationship graph">']
    n = len(nodes)
    pos = []
    for i, (typ, label, col) in enumerate(nodes):
        a = 2 * math.pi * i / n - math.pi / 2
        x, y = cx + 360 * math.cos(a), cy + 215 * math.sin(a)
        pos.append((x, y, a, typ, label, col))
        parts.append(f'<line x1="{cx}" y1="{cy}" x2="{x:.0f}" y2="{y:.0f}" stroke="#2b3a54" stroke-width="1"/>')
    for x, y, a, typ, label, col in pos:
        anchor = "start" if math.cos(a) > 0.2 else "end" if math.cos(a) < -0.2 else "middle"
        dx = 12 if anchor == "start" else -12 if anchor == "end" else 0
        dy = 4 if anchor != "middle" else (-12 if math.sin(a) < 0 else 20)
        parts.append(f'<circle cx="{x:.0f}" cy="{y:.0f}" r="7" fill="{col}"/>'
                     f'<text x="{x + dx:.0f}" y="{y + dy:.0f}" fill="#c7d2e5" font-size="11" text-anchor="{anchor}">'
                     f'{esc(trunc(defang(label), 34))}</text>')
    lvl = report["risk"]["level"]
    parts.append(f'<circle cx="{cx}" cy="{cy}" r="46" fill="#101621" stroke="{LEVEL_COLOR.get(lvl, "#63a4ff")}" stroke-width="3"/>'
                 f'<text x="{cx}" y="{cy - 2}" text-anchor="middle" fill="#e8edf7" font-size="12" font-weight="700">SAMPLE</text>'
                 f'<text x="{cx}" y="{cy + 14}" text-anchor="middle" fill="{LEVEL_COLOR.get(lvl, "#63a4ff")}" font-size="11">{esc(lvl)}</text>')
    legend = [("domain", "#63a4ff"), ("ip", "#f4c95d"), ("url", "#a78bfa"), ("embedded payload", "#fb923c"),
              ("VT contacted domain", "#35d07f"), ("VT contacted IP", "#5eead4"), ("VT dropped file", "#ff6577")]
    for i, (t, c) in enumerate(legend):
        parts.append(f'<circle cx="{20 + i * 135}" cy="{H - 14}" r="5" fill="{c}"/>'
                     f'<text x="{30 + i * 135}" y="{H - 10}" fill="#8e9bb0" font-size="10">{esc(t)}</text>')
    parts.append("</svg>")
    return Raw("".join(parts))


# ----------------------------------------------------------------------------
# narrative
# ----------------------------------------------------------------------------

def recommendations(report) -> list:
    recs, ids = [], {c["id"] for c in report["capabilities"]} | {f["id"] for f in report["findings"]}
    io = report["iocs"]
    lvl = report["risk"]["level"]
    if lvl in ("HIGH", "CRITICAL"):
        recs.append("Treat as hostile: do not open on a production host. Detonate in an isolated sandbox for behavioural "
                    "confirmation (MAL is static-only and never executes the sample).")
    if io.get("domains") or io.get("ips") or io.get("urls"):
        recs.append("Hunt/block: search DNS, proxy and firewall logs for the extracted domains, IPs and URLs "
                    "(use the IOC CSV / STIX export); remember they may be benign or sinkholed.")
    if ids & {"reg_run", "schtasks", "startup_folder", "sc_create", "ifeo", "wmi_event", "cron", "systemd_rc"}:
        recs.append("Persistence indicators present: check Run keys, scheduled tasks, services and startup folders on any host that ran it.")
    if ids & {"mimikatz", "lsass", "minidump", "sam_dump", "browser_creds"}:
        recs.append("Credential-theft indicators: reset credentials used on any affected host and review LSASS access telemetry.")
    if ids & {"vss_delete", "ransom_note", "combo_ransomware"}:
        recs.append("Ransomware-style indicators: verify offline backups and isolate affected hosts immediately.")
    if {"macro_present", "ooxml_remote_template", "rtf_objdata", "pdf_js"} & ids:
        recs.append("Document-borne threat: block the file type at the mail gateway and disable macros / external content by policy.")
    if report["sample"].get("sha256"):
        recs.append("Add the SHA-256 (and imphash if present) to EDR block/alert lists; the generated YARA rule is a starting point and must be tested.")
    return recs


def conclusion(report) -> Raw:
    r, i = report["risk"], report["intel"]["summary"]
    top = [x for x in r["reasons"][:3]]
    s = (f"<strong>{esc(r['level'])}</strong> risk ({r['score']}/100), confidence <strong>{esc(r['confidence'])}</strong>. ")
    if top:
        s += "Main drivers: " + "; ".join(esc(x["indicator"]) for x in top) + ". "
    if report["intel"].get("enabled"):
        s += (f"Threat intel verdict: <strong>{esc(i['verdict'].replace('_', ' '))}</strong>"
              + (f" (families: {esc(', '.join(i['families'][:3]))})" if i.get("families") else "") + ". ")
    s += "Scores reflect observed indicators, not proof of execution."
    return Raw(s)


# ----------------------------------------------------------------------------
# sections
# ----------------------------------------------------------------------------

def sec_overview(report) -> Raw:
    s, r, i = report["sample"], report["risk"], report["intel"]["summary"]
    kpis = [("Type", s["type"]), ("Size", fmt_size(s["size"]) if s.get("size") else "-"),
            ("Entropy", f"{s['entropy']:.3f}" if s.get("size") else "-"), ("Risk", r["level"]),
            ("Capabilities", len(report["capabilities"])), ("Findings", len(report["findings"])),
            ("ATT&CK", len(report["attack"])), ("YARA", len(report["yara"]["matches"])),
            ("Intel", i["verdict"].replace("_", " ").upper())]
    kp = "".join(f'<div class="card kpi"><div class="label">{esc(k)}</div><div class="value" title="{esc(v)}">{esc(v)}</div></div>'
                 for k, v in kpis)
    cats = [(k, (v, R.CATEGORY_CAPS.get(k, 20))) for k, v in r["categories"].items() if v > 0]
    reasons = [[esc(x["category"].replace("_", " ").title()), code(x["indicator"]), Raw(f"<strong>+{x['points']}</strong>"),
                x["evidence"], x["source"]] for x in r["reasons"][:25]]
    st = [Raw(f"<span class='badge info'>{esc(l)}</span>") for l in (
        [f"{PROVIDER_LABELS.get(p, p)}: {rr['status']}" for p, rr in report["intel"]["providers"].items()])]
    hashes = [("MD5", code(s["md5"])), ("SHA-1", code(s["sha1"])), ("SHA-256", code(s["sha256"]))]
    for lab, key in (("SHA3-256", "sha3_256"), ("ssdeep", "ssdeep"), ("TLSH", "tlsh")):
        if s.get(key):
            hashes.append((lab, code(s[key])))
    pe = report.get("pe") or {}
    if pe.get("imphash"):
        hashes.append(("Imphash", code(pe["imphash"])))
    copy_btn = Raw(f'<button class="btn" data-copy="{esc(s.get("sha256") or s.get("md5"))}">Copy</button>')
    recs = recommendations(report)
    return Raw(f"""
<header class="header"><div><h1>{esc(s['name'])}</h1>
<div class="muted small">{esc(s['type'])} &middot; analysed {esc(report['generated_at'])} &middot; MAL v{VERSION}</div></div>
<div>{badge(r['level'] + ' - ' + str(r['score']) + '/100', r['level'])} {copy_btn}</div></header>
<div class="kpis">{kp}</div>
<div class="grid2 row">
 {panel('Risk', '<div style="display:flex;gap:20px;align-items:center;flex-wrap:wrap">' + gauge(r['score'], r['level']) + '<div style="flex:1;min-width:220px">' + conclusion(report) + '</div></div>')}
 {panel('Evidence by category', bars(cats))}
</div>
<div class="grid2 row">
 {panel('Recommended next steps', ul(recs))}
 {panel('Sample profile', kv(hashes + [('Kind', s.get('kind')), ('Modified', s.get('modified'))]))}
</div>
{panel('Threat-intel providers', "".join(st) or '<span class="muted small">Intel was not requested. Run with --intel (see .env).</span>')}
{panel('Entropy map', entropy_svg(s.get('entropy_map', [])))}
{panel('Top risk contributors', table(['Category', 'Indicator', 'Points', 'Evidence', 'Source'], reasons))}
""")


def _vt_block(vt) -> str:
    out = []
    det = vt["malicious"] + vt["suspicious"]
    kind = "malicious" if vt["malicious"] >= 5 else "suspicious" if det else "good"
    out.append(f"""<div class="grid3 row">
<div class="card"><div class="muted small">DETECTIONS</div><div class="big">{det}/{vt['total_engines']}</div></div>
<div class="card"><div class="muted small">MALICIOUS / SUSPICIOUS</div><div class="big">{vt['malicious']} / {vt['suspicious']}</div></div>
<div class="card"><div class="muted small">COMMUNITY</div><div>reputation <strong>{esc(vt.get('reputation'))}</strong><br>votes: {vt['votes']['malicious']} malicious / {vt['votes']['harmless']} harmless</div></div></div>""")
    pairs = [("Suggested threat label", vt.get("threat_label") or "-"),
             ("Threat categories", chips([f"{c['value']} ({c['count']})" for c in vt["threat_categories"]], "malicious")),
             ("Family names", chips([f"{c['value']} ({c['count']})" for c in vt["threat_families"]], "malicious")),
             ("Known names", ul(vt["names"][:8])), ("Meaningful name", vt.get("meaningful_name")),
             ("File type", f"{vt.get('type_description')} ({vt.get('type_tag')})"),
             ("First submitted", vt.get("first_submission")), ("Last submitted", vt.get("last_submission")),
             ("Last analysed", vt.get("last_analysis")), ("Times submitted", f"{vt.get('times_submitted')} ({vt.get('unique_sources')} sources)"),
             ("Tags", chips(vt["tags"], "info")), ("Capabilities", chips(vt["capabilities"], "warn")),
             ("Packers", chips(vt["packers"], "warn")), ("TrID", ul(vt["trid"]))]
    out.append(str(panel("VirusTotal file intelligence", kv(pairs))))
    if vt.get("code_insight"):
        out.append(str(panel("VirusTotal Code Insight (AI summary, third-party)", "".join(f"<pre>{esc(t)}</pre>" for t in vt["code_insight"]))))
    if vt.get("signature"):
        out.append(str(panel("Digital signature info (reported by VT)", kv([(k, v if not isinstance(v, list) else ul(v))
                                                                          for k, v in vt["signature"].items()]))))
    sb = [[x["sandbox"], badge(str(x["category"]), "malicious" if x["category"] == "malicious" else "info"),
           x.get("confidence"), ", ".join(x["classification"]), ", ".join(x["names"])] for x in vt["sandbox_verdicts"]]
    if sb:
        out.append(str(panel("Sandbox verdicts", table(["Sandbox", "Verdict", "Confidence", "Classification", "Names"], sb))))
    cs = []
    if vt["crowdsourced_yara"]:
        cs.append(str(details(f"Crowdsourced YARA ({len(vt['crowdsourced_yara'])})", table(
            ["Rule", "Ruleset", "Author", "Source"], [[code(y["rule"]), y["ruleset"], y["author"], y["source"]] for y in vt["crowdsourced_yara"]]))))
    if vt["sigma"]:
        cs.append(str(details(f"Sigma matches ({len(vt['sigma'])})", table(
            ["Rule", "Level", "Source"], [[x["title"], x["level"], x["source"]] for x in vt["sigma"]]))))
    if vt["ids"]:
        cs.append(str(details(f"IDS / Suricata alerts ({len(vt['ids'])})", table(
            ["Message", "Severity", "Category", "Source"], [[x["msg"], x["severity"], x["category"], x["source"]] for x in vt["ids"]]))))
    if cs:
        out.append(str(panel("Crowdsourced detections", "".join(cs))))
    fl = [[x["engine"], badge(x["category"], "malicious" if x["category"] == "malicious" else "suspicious"), x["result"]]
          for x in vt["flagged_engines"]]
    out.append(str(panel(f"Flagging engines ({len(fl)})", '<input class="search" id="vtq" oninput="filt(\'vtq\',\'vtt\')" placeholder="Filter engines...">'
                         + str(table(["Engine", "Category", "Result"], fl, tid="vtt", empty="No engine flagged this hash.")))))
    b = vt.get("behaviour")
    if b and b.get("status") == "ok":
        sections = [("Processes created", "processes_created"), ("Command executions", "command_executions"),
                    ("Files written", "files_written"), ("Files dropped", "files_dropped"), ("Registry keys set", "registry_keys_set"),
                    ("Mutexes created", "mutexes_created"), ("Services started", "services_started"),
                    ("DNS lookups", "dns_lookups"), ("IP traffic", "ip_traffic"), ("HTTP conversations", "http_conversations"),
                    ("Modules loaded", "modules_loaded"), ("Highlighted API calls", "calls_highlighted"),
                    ("Files deleted", "files_deleted")]
        det = "".join(str(details(f"{t} ({len(b[k])})", ul(b[k]))) for t, k in sections if b.get(k))
        extra = ""
        if b.get("verdict_labels") or b.get("tags"):
            extra = f"<h3>Behaviour tags</h3>{chips(b.get('verdict_labels', []) + b.get('tags', []), 'warn')}"
        mt = [[code(m["id"]), m.get("severity"), m["description"]] for m in b.get("mitre_attack_techniques", [])]
        out.append(str(panel("Sandbox behaviour (observed by VirusTotal sandboxes, NOT by MAL)",
                             (det or '<span class="muted small">Sandbox report contained no behaviour entries.</span>') + extra
                             + ("<h3>MITRE ATT&amp;CK observed</h3>" + str(table(["ID", "Severity", "Signature"], mt)) if mt else ""))))
    elif b:
        out.append(str(panel("Sandbox behaviour", f'<div class="callout warn">Not available: {esc(b.get("status"))}. '
                                                 'Some behaviour endpoints need a premium key or have no sandbox report for this file.</div>')))
    rel = vt.get("relationships") or {}
    if rel:
        rp = []
        for kind, label in (("contacted_domains", "Contacted domains"), ("contacted_ips", "Contacted IPs"),
                            ("contacted_urls", "Contacted URLs"), ("dropped_files", "Dropped files")):
            r_ = rel.get(kind)
            if not r_:
                continue
            if kind == "dropped_files":
                rows = [[code(x["value"]), x["name"], x["type"], fmt_size(x["size"]) if x.get("size") else "-", x["malicious"]] for x in r_["items"]]
                body = table(["SHA-256", "Name", "Type", "Size", "Detections"], rows, empty=f"None ({r_['status']}).")
            else:
                rows = [[ioc_code(x["value"]), x.get("malicious"), x.get("reputation"), x.get("country") or "", x.get("owner") or ""] for x in r_["items"]]
                body = table(["Indicator", "VT detections", "Reputation", "Country", "Owner"], rows, empty=f"None ({r_['status']}).")
            rp.append(str(details(f"{label} ({r_.get('count') if r_.get('count') is not None else len(r_['items'])})", body, open_=bool(r_["items"]))))
        out.append(str(panel("Relationships (from VT sandbox runs)", "".join(rp))))
    if vt.get("mitre"):
        out.append(str(panel("MITRE ATT&CK tree (sandbox)", table(["Sandbox", "Tactic", "Technique", "Severity", "Signatures"],
                                                                 [[m["sandbox"], m["tactic"], f"{m['technique_id']} {m['technique']}", m["severity"], "; ".join(m["signatures"])] for m in vt["mitre"]]))))
    if vt.get("comments"):
        out.append(str(panel("Community comments (untrusted user content)", table(["Date", "Comment"], [[c["date"], c["text"]] for c in vt["comments"]]))))
    out.append(f'<div class="callout">Report limit: {esc(vt.get("depth"))} depth ({esc(vt.get("calls_note"))}). '
               f'<a href="{esc(vt["permalink"])}" target="_blank" rel="noopener noreferrer">Open on VirusTotal</a></div>')
    return "".join(out)


def sec_intel(report) -> Raw:
    intel = report["intel"]
    if not intel.get("enabled"):
        return Raw(str(panel("Threat intelligence", '<div class="callout">Not requested. Add keys to <code>.env</code> and run with '
                                                      '<code>--intel</code> (all providers) or <code>--intel vt,otx</code>. '
                                                      'Add <code>--enrich</code> to also look up domains/IPs found in the sample.</div>')))
    out = []
    s = intel["summary"]
    rows = []
    for p, r in intel["providers"].items():
        st = r["status"]
        kind = {"ok": "good", "not_found": "info"}.get(st, "warn" if st in ("no_key", "skipped", "restricted") else "bad")
        rows.append([PROVIDER_LABELS.get(p, p), badge(st, kind), r.get("error") or ("cached" if r.get("from_cache") else "")])
    out.append(str(panel("Provider status", table(["Provider", "Status", "Note"], rows)
                         + f'<div class="callout">Verdict: <strong>{esc(s["verdict"].replace("_", " "))}</strong>'
                           f'{" | families: " + esc(", ".join(s["families"])) if s.get("families") else ""}'
                           f'{" | first seen: " + esc(s["first_seen"]) if s.get("first_seen") else ""}<br>'
                           f'<span class="muted">{esc(intel.get("queried_with", {}).get("note", ""))}</span></div>')))
    P = intel["providers"]
    if P.get("vt", {}).get("status") == "ok":
        out.append(_vt_block(P["vt"]))
    mb = P.get("mb", {})
    if mb.get("status") == "ok":
        out.append(str(panel("MalwareBazaar (abuse.ch)", kv([
            ("Signature / family", mb.get("signature")), ("File name", mb.get("file_name")), ("Type", f"{mb.get('file_type')} / {mb.get('mime')}"),
            ("First / last seen", f"{mb.get('first_seen')} / {mb.get('last_seen')}"), ("Reporter", mb.get("reporter")),
            ("Origin country", mb.get("country")), ("Delivery", mb.get("delivery_method")), ("Tags", chips(mb.get("tags", []), "warn")),
            ("ClamAV", ul(mb.get("clamav", []))), ("Downloads / uploads", f"{mb.get('downloads')} / {mb.get('uploads')}"),
            ("Vendor intel", ul(mb.get("vendor_intel", []))),
            ("YARA", ul([f"{y['rule']} ({y['author']})" for y in mb.get("yara", [])])),
            ("Link", Raw(f'<a href="{esc(mb["permalink"])}" target="_blank" rel="noopener noreferrer">bazaar.abuse.ch</a>'))]))))
    uh = P.get("urlhaus", {})
    if uh.get("status") == "ok":
        out.append(str(panel("URLhaus (abuse.ch)", kv([("Signature", uh.get("signature")), ("First / last seen", f"{uh.get('first_seen')} / {uh.get('last_seen')}"),
                                                       ("Distribution URLs", uh.get("url_count"))])
                             + str(table(["URL", "Status", "File", "First seen"], [[ioc_code(u["url"]), u["status"], u["filename"], u["first_seen"]] for u in uh["distribution_urls"]])))))
    tf = P.get("threatfox", {})
    if tf.get("status") == "ok":
        out.append(str(panel("ThreatFox (abuse.ch) - IOCs linked to this sample",
                             table(["IOC", "Type", "Malware", "Threat", "Confidence", "First seen"],
                                   [[ioc_code(r["ioc"]), r["type"], r["malware"], r["threat_type"], r["confidence"], r["first_seen"]] for r in tf["iocs"]]))))
    ha = P.get("ha", {})
    if ha.get("status") == "ok":
        v = ha.get("verdict", "")
        out.append(str(panel("Hybrid Analysis", kv([("Verdict", badge(v, "malicious" if "malicious" in v else "suspicious" if "suspicious" in v else "info")),
                                                    ("Threat score", ha.get("threat_score")), ("AV detect %", ha.get("av_detect")), ("Family", ha.get("family")),
                                                    ("Type", ha.get("file_type")), ("Tags", chips(ha.get("tags", []), "warn")),
                                                    ("Link", Raw(f'<a href="{esc(ha["permalink"])}" target="_blank" rel="noopener noreferrer">hybrid-analysis.com</a>'))]))))
    ox = P.get("otx", {})
    if ox.get("status") == "ok":
        out.append(str(panel(f"AlienVault OTX - {ox.get('pulse_count')} pulse(s)", kv([("Families", chips(ox.get("families", []), "malicious")),
                                                                                        ("Tags", chips(ox.get("tags", []), "info")),
                                                                                        ("ATT&CK IDs", chips([f"{a['id']}" for a in ox.get("attack_ids", [])], "warn"))])
                             + str(table(["Pulse", "Author", "Modified", "Adversary"], [[p["name"], p["author"], p["modified"], p["adversary"]] for p in ox.get("pulses", [])])))))
    if intel.get("network"):
        rows = []
        for e in intel["network"].values():
            for p, r in e["providers"].items():
                if r.get("status") != "ok":
                    rows.append([e["type"], ioc_code(e["indicator"]), PROVIDER_LABELS.get(p, p), badge(r["status"], "info"), ""])
                    continue
                if p == "vt":
                    d = f"{r.get('malicious', 0) + r.get('suspicious', 0)}/{r.get('total', 0)} engines; rep {r.get('reputation')}; {r.get('owner') or r.get('registrar') or ''} {r.get('country') or ''}"
                elif p == "abuseipdb":
                    d = f"abuse score {r['score']}% ({r['reports']} reports); {r['isp']}; {r['usage']}; {r['country']}{' TOR' if r['tor'] else ''}"
                elif p == "otx":
                    d = f"{r['pulse_count']} pulse(s) {', '.join(r.get('families', []))}"
                elif p == "urlhaus":
                    d = f"{r['url_count']} URL(s), {r.get('online', 0)} online; {', '.join(r.get('threats', []))}"
                else:
                    d = ", ".join(r.get("malware", [])) or "hit"
                rows.append([e["type"], ioc_code(e["indicator"]), PROVIDER_LABELS.get(p, p), badge("ok", "good"), d])
        out.append(str(panel("Network IOC enrichment (opt-in --enrich)", table(["Type", "Indicator", "Provider", "Status", "Detail"], rows))))
    return Raw("".join(out))


def sec_static(report) -> Raw:
    out = []
    f = [[Raw(f"<strong>+{x['weight']}</strong>"), x["title"], x["detail"], x["category"].replace("_", " ")] for x in
         sorted(report["findings"], key=lambda x: -x["weight"])]
    out.append(str(panel("Structural findings", table(["Points", "Finding", "Detail", "Category"], f, empty="No structural anomalies."))))
    pe = report.get("pe")
    if pe:
        if not pe.get("available", True) or pe.get("error") and not pe.get("sections"):
            out.append(str(panel("PE", f'<div class="callout warn">{esc(pe.get("error") or "unavailable")}</div>')))
        else:
            prof = kv([("Format", f"{pe.get('format')} / {pe.get('machine')} / {pe.get('subsystem')}"),
                       ("Type", "DLL" if pe.get("is_dll") else "Driver" if pe.get("is_driver") else "EXE"),
                       (".NET", "yes" if pe.get("dotnet") else "no"),
                       ("Compile time", f"{pe.get('timestamp')} {('(' + pe['timestamp_note'] + ')') if pe.get('timestamp_note') else ''}"),
                       ("Entry point", f"{pe.get('entry_point')} in {pe.get('entry_section')}"), ("Image base", pe.get("image_base")),
                       ("ASLR / DEP / CFG", f"{pe.get('aslr')} / {pe.get('dep_nx')} / {pe.get('cfg')}"),
                       ("Imphash", code(pe["imphash"]) if pe.get("imphash") else "-"),
                       ("Rich header hash", code(pe["rich_header_hash"]) if pe.get("rich_header_hash") else "-"),
                       ("Signature", pe.get("signature_note")), ("TLS callbacks", pe.get("tls_callbacks")),
                       ("Overlay", f"{fmt_size(pe['overlay']['size'])} at 0x{pe['overlay']['offset']:x}, entropy {pe['overlay']['entropy']}" if pe.get("overlay") else "none"),
                       ("Anomalies", ul(pe.get("anomalies", [])))])
            vi = pe.get("version_info") or {}
            out.append(f'<div class="grid2 row">{panel("PE profile", prof)}{panel("Version info", kv(list(vi.items())[:12]) if vi else "<span class=muted>none</span>")}</div>')
            sec = [[code(s["name"]), s["virtual_address"], s["virtual_size"], s["raw_size"], f"{s['entropy']:.3f}", s["permissions"],
                    chips(s["flags"], "warn") if s["flags"] else ""] for s in pe.get("sections", [])]
            out.append(str(panel("Sections", table(["Name", "VA", "Virtual", "Raw", "Entropy", "Perm", "Flags"], sec))))
            grp = "".join(str(details(f"{g} ({len(v)})", ul(v))) for g, v in pe.get("import_groups", {}).items())
            out.append(str(panel(f"Imports ({pe.get('import_count', 0)}) grouped by behaviour", grp or "<span class='muted small'>No notable import groups.</span>"
                                 + "".join(str(details(f"{d} ({len(n)})", ul(n[:60]))) for d, n in list(pe.get("imports_by_dll", {}).items())[:40]))))
            if pe.get("export_count"):
                out.append(str(panel(f"Exports ({pe['export_count']})", ul(pe["exports"][:60]))))
            if pe.get("resources"):
                out.append(str(panel("Resources", table(["Type", "Size", "Entropy", "MZ"], [[r["type"], r["size"], r["entropy"], r["mz_header"]] for r in pe["resources"][:40]]))))
    elf = report.get("elf")
    if elf:
        out.append(str(panel("ELF profile", kv([("Class", elf.get("class")), ("Type", elf.get("type")), ("Machine", elf.get("machine")),
                                                ("Entry", elf.get("entry_point")), ("Interpreter", elf.get("interpreter")),
                                                ("Sections", elf.get("section_count")), ("Stripped", elf.get("stripped"))])
                             + str(table(["Section", "Size", "Entropy", "Flags"], [[code(s["name"]), s["size"], s["entropy"], s["flags"]] for s in elf.get("sections", [])])))))
    of = report.get("office")
    if of:
        pairs = [("Flavor", of.get("flavor"))]
        m = of.get("macros")
        if m:
            pairs += [("Macros", f"{'present' if m['present'] else 'none'} (engine: {m['engine']})"), ("Auto-exec", ul(m["autoexec"])),
                      ("Suspicious keywords", ul(m["suspicious"])), ("Macro IOCs", ul(m["iocs"]))]
        if of.get("external_links"):
            pairs.append(("External links", ul([f"{l['type']} -> {defang(l['target'])}" for l in of["external_links"]])))
        if of.get("embedded"):
            pairs.append(("Embedded parts", ul(of["embedded"][:20])))
        if of.get("metadata"):
            pairs += list(of["metadata"].items())
        if of.get("counts"):
            pairs.append(("RTF control words", ul([f"{k}: {v}" for k, v in of["counts"].items()])))
        out.append(str(panel("Office / RTF analysis", kv(pairs) + (f"<h3>Macro preview</h3><pre>{esc(m['code_preview'])}</pre>" if m and m.get("code_preview") else ""))))
    pdf = report.get("pdf")
    if pdf:
        out.append(str(panel("PDF analysis", kv([("Objects / streams", f"{pdf.get('object_count')} / {pdf.get('stream_count')}"),
                                                 ("Decoded Flate streams", pdf.get("decoded_streams")), ("Hex-escaped names", pdf.get("hex_escaped_names")),
                                                 ("Keyword counts", ul([f"{k}: {v}" for k, v in pdf["counts"].items()])),
                                                 ("URIs", ul([defang(u) for u in pdf.get("uris", [])]))]))))
    ar = report.get("archive")
    if ar:
        out.append(str(panel("Archive listing (metadata only; nothing extracted)", table(["Name", "Size", "Compressed", "Encrypted"],
                                                                                    [[e["name"], e["size"], e["compressed"], e["encrypted"]] for e in ar.get("entries", [])]))))
    return Raw("".join(out))


def sec_caps(report) -> Raw:
    caps = [[Raw(f"<strong>+{c['weight']}</strong>"), code(c["id"]), c["title"], c["category"].replace("_", " "),
             f"x{c['count']}", ", ".join(c["sources"]), Raw(f"<code>{esc(c['example'])}</code>")]
            for c in sorted(report["capabilities"], key=lambda c: -c["weight"])]
    combos = [[Raw(f"<strong>+{c['weight']}</strong>"), c["title"], c["evidence"]] for c in report["combos"]]
    out = [str(panel("Capability indicators (each scored once)", table(["Pts", "Rule", "Meaning", "Category", "Hits", "Seen in", "Example"], caps, empty="No capability indicators matched."))),
           str(panel("Correlated behaviour clusters", table(["Bonus", "Cluster", "Evidence"], combos, empty="No clusters.")))]
    by = {}
    for a in report["attack"]:
        by.setdefault(a["tactic"], []).append(a)
    body = []
    for tac in R.TACTIC_ORDER + [t for t in by if t not in R.TACTIC_ORDER]:
        if tac in by:
            body.append(f'<div class="tactic">{esc(tac)}</div>' + str(table(["Technique", "Name", "Evidence", "Source"], [
                [code(a["technique_id"]), a["name"], "; ".join(a["evidence"][:5]), ", ".join(a["sources"])] for a in by[tac]])))
    note = ('<div class="callout">Static technique mapping shows <em>capability</em>. Techniques tagged with a '
            'sandbox/OTX source were reported by third parties.</div>')
    out.append(str(panel("MITRE ATT&CK mapping",
                         ("".join(body) or '<span class="muted small">No techniques mapped.</span>') + note)))
    return Raw("".join(out))


def sec_iocs(report) -> Raw:
    origin = report.get("ioc_origin", {})
    rows = []
    for t, vals in report["iocs"].items():
        if t.startswith("_") or t == "hashes":
            continue
        for v in vals:
            o = origin.get(f"{t}|{v}", "static")
            rows.append([code(t.rstrip("s") if t not in ("file_paths", "registry", "pdb_paths") else t), ioc_code(v) if t in ("urls", "domains", "ips", "emails") else code(v), o])
    hashes = report["iocs"].get("hashes", [])
    sup = report["iocs"].get("_suppressed_benign", [])
    body = ('<button class="btn" onclick="toggleDefang(this)" style="margin-bottom:10px">Show raw (live) IOCs</button> '
            '<input class="search" id="iocq" oninput="filt(\'iocq\',\'ioct\')" placeholder="Search URLs, domains, IPs, paths, registry...">'
            + str(table(["Type", "Indicator", "Origin"], rows, tid="ioct", empty="No IOCs extracted.")))
    out = [str(panel("IOC explorer (network IOCs are defanged by default)", body))]
    if hashes:
        out.append(str(panel("Hashes found inside the sample", table(["Hash"], [[code(h)] for h in hashes[:60]]))))
    if sup:
        out.append(str(details(f"Suppressed as likely benign ({len(sup)})", ul(sup))))
    return Raw("".join(out))


def sec_decode(report) -> Raw:
    d = report["deobfuscation"]
    layers = [[l["method"], l["depth"], l["kind"], f"{l['decoded_len']} B", l.get("entropy"), Raw(f"<code>{esc(l['preview'])}</code>"), l.get("note", "")] for l in d["layers"]]
    pes = [[f"0x{e['offset']:x}", e.get("origin"), e.get("size"), e.get("arch"), e.get("is_dll"), code(e.get("sha256") or "")] for e in
           d["embedded_pe"] + d["carved_pe"] + d["xor"]["pe"]]
    xr = [[h["kind"], h["key"], f"0x{h['offset']:x}", Raw(f"<code>{esc(defang(h['value']))}</code>")] for h in d["xor"]["hits"]]
    out = [Raw('<div class="callout">All decoding is performed on bytes in memory. <strong>Nothing is executed or evaluated.</strong></div>'),
           panel("Decoded layers", table(["Method", "Depth", "Kind", "Size", "Entropy", "Preview (first 300 chars)", "Note"], layers, empty="No encoded layers found.")),
           panel("Embedded / decoded executables", table(["Offset", "Origin", "Size", "Arch", "DLL", "SHA-256"], pes, empty="No embedded PE files found.")),
           panel("Single-byte XOR findings", table(["Kind", "Key", "Offset", "Value"], xr, empty="None found."
                                                    + (" (scan covered first %s)" % fmt_size(report["analysis_limits"].get("xor_scan_bytes", 0)) if d["xor"].get("truncated") else "")))]
    if report.get("extracted_payloads"):
        out.append(panel("Extracted payload files", ul(report["extracted_payloads"])))
    return Raw("".join(str(x) for x in out))


def sec_yara(report) -> Raw:
    y = report["yara"]
    rows = [[code(m["rule"]), m["namespace"], ", ".join(m["tags"]), m.get("description"), "; ".join(m["strings"])] for m in y["matches"]]
    out = [str(panel(f"YARA matches ({y.get('rules_loaded', 0)} rule file(s) loaded)", table(["Rule", "Namespace", "Tags", "Description", "Matched strings"], rows,
                                                                                         empty="YARA not run." if not y["enabled"] else "No rules matched.")
                     + (f'<div class="callout bad">YARA error: {esc(y["error"])}</div>' if y.get("error") else "")))]
    g = report.get("generated_yara")
    if g:
        out.append(str(panel("Auto-generated YARA rule (review before use)", f'<button class="btn" data-copy="{esc(g)}">Copy</button><pre>{esc(g)}</pre>')))
    else:
        out.append('<div class="muted small">Run with <code>--formats yara</code> or <code>--formats all</code> to generate a rule from this sample.</div>')
    return Raw("".join(out))


def sec_raw(report) -> Raw:
    strs = report["strings"][:500]
    slim = {k: v for k, v in report.items() if k not in ("strings", "generated_yara")}
    return Raw(str(panel(f"Extracted strings ({len(strs)} of {report['string_count']} shown)", f"<pre>{esc(chr(10).join(strs))}</pre>"))
               + str(details("Machine-readable JSON (without strings)", f"<pre>{esc(json.dumps(slim, indent=2, ensure_ascii=False, default=str))}</pre>")))


# ----------------------------------------------------------------------------
# entry points
# ----------------------------------------------------------------------------

TABS = [("overview", "Overview"), ("intel", "Threat Intel"), ("static", "Static Analysis"), ("caps", "Capabilities & ATT&CK"),
        ("iocs", "IOCs"), ("decode", "Deobfuscation"), ("graph", "Graph"), ("yara", "YARA"), ("raw", "Raw Data")]


def build_html(report) -> str:
    hash_mode = report.get("mode") == "hash"
    tabs = [t for t in TABS if not (hash_mode and t[0] in ("static", "decode", "yara", "raw"))]
    body = {"overview": sec_overview, "intel": sec_intel, "static": sec_static, "caps": sec_caps, "iocs": sec_iocs,
            "decode": sec_decode, "graph": lambda r: panel("Relationship graph", graph_svg(r)), "yara": sec_yara, "raw": sec_raw}
    nav = "".join(f'<a href="#{k}" data-tab="{k}">{esc(v)}</a>' for k, v in tabs)
    secs = "".join(f'<section class="tab" id="tab-{k}">{body[k](report)}</section>' for k, _ in tabs)
    s = report["sample"]
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>MAL v{VERSION} - {esc(s['name'])}</title><style>{CSS}</style></head>
<body><div class="app"><aside class="sidebar"><div class="brand">MAL<span> v{VERSION}</span></div>
<div class="sub">Defensive malware analysis &amp; threat intelligence</div><nav class="nav">{nav}</nav>
<div class="small muted" style="margin-top:26px">Mode<br><strong>STATIC / SAFE</strong><br><br>Sample execution<br><strong>DISABLED</strong><br><br>Sample upload<br><strong>NEVER</strong></div></aside>
<main class="main">{secs}
<div class="footer">MAL v{VERSION} &middot; static analysis only, the sample is never executed or uploaded &middot; intel lookups send hashes
(and IOCs only with --enrich) &middot; third-party data is untrusted and shown escaped.</div></main></div><script>{JS}</script></body></html>"""


def build_index(rows) -> str:
    items = []
    for r in rows:
        if "error" in r:
            items.append((-1, [r["name"], badge("ERROR", "bad"), "", "", r["error"]]))
            continue
        rep = r["report"]
        k, i = rep["risk"], rep["intel"]["summary"]
        link = Raw(f'<a href="{esc(r["html"].name)}">{esc(r["name"])}</a>') if r.get("html") else r["name"]
        items.append((k["score"], [link, badge(f"{k['level']} {k['score']}", k["level"]),
                                   code(rep["sample"]["sha256"][:20] + "..."),
                                   ", ".join(i.get("families", [])[:2]) or i["verdict"].replace("_", " "),
                                   rep["sample"]["type"]]))
    ordered = [row for _, row in sorted(items, key=lambda x: -x[0])]
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>MAL v{VERSION} batch index</title><style>{CSS}</style></head>
<body><main class="main" style="margin:auto"><h1>MAL v{VERSION} - batch summary</h1>
{panel(f"{len(rows)} file(s)", table(["Sample", "Risk", "SHA-256", "Intel / family", "Type"], ordered))}</main></body></html>"""
