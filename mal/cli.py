"""Command-line interface and analysis pipeline for MAL v4."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import webbrowser
from pathlib import Path

from . import __version__ as VERSION
from . import exports, formats, scoring, triage
from .config import load_settings
from .intel import IntelEngine, parse_provider_list
from .utils import fmt_size, now_utc, safe_stem, block_entropy, entropy

try:
    import yara
except ImportError:
    yara = None

LEVEL_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def log(msg):
    print(f"[+] {msg}", file=sys.stderr, flush=True)


# ----------------------------------------------------------------------------
# YARA
# ----------------------------------------------------------------------------

def run_yara(data: bytes, yara_path):
    if not yara_path:
        return {"enabled": False, "matches": [], "error": None, "rules_loaded": 0}
    if yara is None:
        return {"enabled": True, "matches": [], "error": "yara-python is not installed (pip install yara-python).",
                "rules_loaded": 0}
    p = Path(yara_path)
    try:
        if p.is_dir():
            files = sorted([*p.glob("*.yar"), *p.glob("*.yara")])
            if not files:
                return {"enabled": True, "matches": [], "error": f"No .yar/.yara files in {p}", "rules_loaded": 0}
            rules = yara.compile(filepaths={f"r{i}_{f.stem}"[:60]: str(f) for i, f in enumerate(files)})
            n = len(files)
        else:
            rules = yara.compile(filepath=str(p))
            n = 1
        out = []
        for m in rules.match(data=data, timeout=60):
            strs = []
            for s in (m.strings or [])[:6]:
                try:                                   # yara-python >= 4.3
                    strs.append(f"{s.identifier} @ {s.instances[0].offset:#x}")
                except AttributeError:                 # older tuple API
                    strs.append(f"{s[1]} @ {s[0]:#x}")
            out.append({"rule": m.rule, "namespace": m.namespace, "tags": list(m.tags),
                        "description": str((m.meta or {}).get("description", ""))[:200], "strings": strs})
        return {"enabled": True, "matches": out, "error": None, "rules_loaded": n}
    except Exception as e:
        return {"enabled": True, "matches": [], "error": str(e)[:300], "rules_loaded": 0}


# ----------------------------------------------------------------------------
# Pipeline
# ----------------------------------------------------------------------------

def analyze_file(path: Path, settings, args, engine=None):
    data, hashes = triage.load_sample(path, settings.max_file_mb)
    t = triage.detect_type(data, path)
    kind = t["kind"]
    fuzzy = triage.fuzzy_hashes(data)

    findings = triage.analyze_name(path, kind)
    strings = triage.extract_strings(data)
    fmt = formats.analyze_formats(kind, data, path.name)
    findings += fmt["findings"]

    deob = triage.deobfuscate(data, strings, kind, deep=not args.no_deep)
    decoded = list(deob["decoded_texts"]) + list(fmt["extra_text"])
    macros = (fmt.get("office") or {}).get("macros")
    if macros:
        if macros.get("code_preview"):
            decoded.append(("vba_macro", macros["code_preview"]))
        for u in macros.get("iocs", []):
            decoded.append(("vba_macro", u))

    static_text = triage.strings_to_text(strings)
    iocs, origin = triage.build_ioc_set(static_text, decoded)

    pe = fmt.get("pe") or {}
    caps = scoring.detect_capabilities(static_text, decoded, pe.get("import_names", []))
    combos = scoring.evaluate_combos(caps)

    # decoded/embedded payload findings
    if deob["carved_pe"]:
        findings.append(_f("decoded_pe", "Decoded layer contains a PE executable",
                           f"{len(deob['carved_pe'])} payload(s) after decoding", 14, "obfuscation"))
    emb = deob["embedded_pe"]
    if emb:
        findings.append(_f("embedded_pe", "Embedded PE file(s) found inside the sample",
                           ", ".join(f"@0x{e['offset']:x} ({e['size']}B)" for e in emb[:4]),
                           12 if kind != "pe" else 8, "obfuscation"))
    if deob["xor"]["pe"]:
        findings.append(_f("xor_pe", "Single-byte-XOR encoded PE payload",
                           ", ".join(f"key {e['key']} @0x{e['offset']:x}" for e in deob["xor"]["pe"][:3]),
                           14, "obfuscation"))
    if any(h["kind"] == "url" for h in deob["xor"]["hits"]):
        findings.append(_f("xor_url", "XOR-encoded URL strings",
                           ", ".join(h["value"][:60] for h in deob["xor"]["hits"] if h["kind"] == "url")[:200],
                           8, "obfuscation"))
    if any(l["method"] in ("base64", "powershell_encodedcommand") and l["kind"] == "text" for l in deob["layers"]):
        findings.append(_f("decoded_text", "Encoded text layers decoded",
                           f"{sum(1 for l in deob['layers'] if l['kind'] == 'text')} readable layer(s)",
                           6, "obfuscation"))

    yres = run_yara(data, args.yara)

    intel = {"enabled": False, "providers": {}, "network": {}, "summary": {"verdict": "not_queried"}}
    if engine is not None:
        log("Querying threat intelligence (hash lookups only; sample is NOT uploaded)...")
        intel = engine.run(hashes, iocs)

    attack = scoring.build_attack(caps, combos, findings, intel.get("summary"))
    risk = scoring.calculate_risk(caps, combos, findings, iocs, yres, intel)

    st = path.stat()
    for d in deob["carved_pe"] + deob["embedded_pe"] + deob["xor"]["pe"]:
        d.setdefault("_bytes", b"")

    report = {
        "schema_version": "4.0", "tool": "MAL", "tool_version": VERSION, "generated_at": now_utc(),
        "mode": "file",
        "sample": {
            "name": path.name, "path": str(path.resolve()), "type": t["type"], "kind": kind,
            "size": len(data),
            "created": dt.datetime.fromtimestamp(st.st_ctime).isoformat(timespec="seconds"),
            "modified": dt.datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
            **hashes, **fuzzy,
            "entropy": round(entropy(data), 6), "entropy_map": block_entropy(data, 96),
        },
        "strings": strings[:2000], "string_count": len(strings),
        "iocs": iocs, "ioc_origin": {f"{k[0]}|{k[1]}": v for k, v in origin.items()},
        "capabilities": caps, "combos": combos, "findings": findings,
        "pe": fmt["pe"], "elf": fmt["elf"], "office": fmt["office"], "pdf": fmt["pdf"], "archive": fmt["archive"],
        "deobfuscation": {"layers": deob["layers"], "carved_pe": deob["carved_pe"],
                          "embedded_pe": deob["embedded_pe"], "xor": deob["xor"]},
        "yara": yres, "intel": intel, "attack": attack, "risk": risk,
        "analysis_limits": {
            "execution": False, "max_file_mb": settings.max_file_mb,
            "dynamic_behavior": "not collected by MAL (sandbox behaviour, if shown, comes from third-party intel)",
            "xor_scan_bytes": triage.XOR_SCAN_LIMIT,
            "notes": ["Authenticode signatures are detected but not cryptographically validated.",
                      "Only single-byte XOR is brute-forced; multi-byte / rolling XOR and custom crypto are not decoded.",
                      "Archives (.7z/.rar/.iso) are identified but their members are not inspected."],
        },
    }
    ctx = {"strings": strings, "data_len": len(data)}
    return report, ctx


def _f(fid, title, detail, weight, cat):
    from .utils import finding
    return finding(fid, title, detail, weight, cat, ("T1027", "Obfuscated Files or Information", "Defense Evasion"))


def strip_binary(report: dict) -> dict:
    """Remove raw bytes so the report is JSON-serializable."""
    d = report["deobfuscation"]
    for key in ("carved_pe", "embedded_pe"):
        d[key] = [{k: v for k, v in x.items() if k != "_bytes"} for x in d[key]]
    d["xor"]["pe"] = [{k: v for k, v in x.items() if k != "_bytes"} for x in d["xor"]["pe"]]
    return report


def extract_payloads(report: dict, outdir: Path):
    saved = []
    items = report["deobfuscation"]["carved_pe"] + report["deobfuscation"]["embedded_pe"] + \
        report["deobfuscation"]["xor"]["pe"]
    items = [i for i in items if i.get("_bytes")]
    if not items:
        return saved
    outdir.mkdir(parents=True, exist_ok=True)
    for i in items:
        p = outdir / f"{i['sha256'][:16]}.bin"      # .bin: never directly double-clickable
        p.write_bytes(i["_bytes"])
        saved.append(str(p))
    return saved


def analyze_hash(hash_value: str, settings, args, engine):
    n = len(hash_value)
    key = {32: "md5", 40: "sha1", 64: "sha256"}[n]
    hashes = {key: hash_value.lower()}
    intel = engine.run(hashes, None)
    risk = scoring.calculate_risk([], [], [], {"urls": [], "domains": [], "ips": []},
                                  {"matches": []}, intel)
    attack = scoring.build_attack([], [], [], intel.get("summary"))
    empty_iocs = {k: [] for k in ("urls", "domains", "ips", "emails", "file_paths", "registry", "mutexes",
                                  "pipes", "pdb_paths", "crypto", "hashes")}
    return {
        "schema_version": "4.0", "tool": "MAL", "tool_version": VERSION, "generated_at": now_utc(),
        "mode": "hash",
        "sample": {"name": hash_value.lower(), "type": "Hash-only lookup (no file analysed)", "kind": "hash",
                   "size": 0, "entropy": 0.0, "entropy_map": [], "md5": hashes.get("md5", ""),
                   "sha1": hashes.get("sha1", ""), "sha256": hashes.get("sha256", ""), "sha3_256": "",
                   "ssdeep": None, "tlsh": None, "path": "", "created": "", "modified": ""},
        "strings": [], "string_count": 0, "iocs": empty_iocs, "ioc_origin": {},
        "capabilities": [], "combos": [], "findings": [], "pe": None, "elf": None, "office": None, "pdf": None,
        "archive": None, "deobfuscation": {"layers": [], "carved_pe": [], "embedded_pe": [],
                                           "xor": {"hits": [], "pe": [], "truncated": False}},
        "yara": {"enabled": False, "matches": [], "error": None, "rules_loaded": 0},
        "intel": intel, "attack": attack, "risk": risk,
        "analysis_limits": {"execution": False, "notes": ["Hash-only mode: score reflects external reputation only."]},
    }


# ----------------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------------

def write_outputs(report, ctx, outdir: Path, fmts: set, extract: bool):
    from . import report as html_report
    outdir.mkdir(parents=True, exist_ok=True)
    s = report["sample"]
    stem = f"{safe_stem(Path(s['name']).stem if report['mode'] == 'file' else s['name'][:16])}_" \
           f"{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}_{(s.get('sha256') or s['name'])[:8]}"
    paths = {}
    saved = []
    if extract and report["mode"] == "file":
        saved = extract_payloads(report, outdir / f"{stem}_extracted")
    strip_binary(report)
    if saved:
        report["extracted_payloads"] = saved
    if "yara" in fmts and report["mode"] == "file":
        rule = exports.generate_yara(report, ctx["strings"], ctx["data_len"])
        report["generated_yara"] = rule
        (outdir / f"{stem}.generated.yar").write_text(rule, encoding="utf-8")
        paths["yara"] = outdir / f"{stem}.generated.yar"
    if "json" in fmts:
        (outdir / f"{stem}.json").write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str),
                                             encoding="utf-8")
        paths["json"] = outdir / f"{stem}.json"
    if "csv" in fmts:
        (outdir / f"{stem}.iocs.csv").write_text(exports.iocs_csv(report), encoding="utf-8", newline="")
        paths["csv"] = outdir / f"{stem}.iocs.csv"
    if "stix" in fmts:
        (outdir / f"{stem}.stix.json").write_text(json.dumps(exports.stix_bundle(report), indent=2), encoding="utf-8")
        paths["stix"] = outdir / f"{stem}.stix.json"
    if "html" in fmts:
        (outdir / f"{stem}.html").write_text(html_report.build_html(report), encoding="utf-8")
        paths["html"] = outdir / f"{stem}.html"
    return paths


def print_summary(report, paths):
    r, s, i = report["risk"], report["sample"], report["intel"]["summary"]
    print()
    print("=" * 68)
    print(" MAL v%s - ANALYSIS COMPLETE" % VERSION)
    print("=" * 68)
    print(f" Sample     : {s['name']}")
    print(f" Type       : {s['type']}")
    if s.get("size"):
        print(f" Size       : {fmt_size(s['size'])}   Entropy: {s['entropy']:.3f}")
    print(f" SHA256     : {s.get('sha256') or s.get('md5')}")
    print(f" Risk       : {r['level']} ({r['score']}/100)   Confidence: {r['confidence']}")
    print(f" Capabilities: {len(report['capabilities'])}   Findings: {len(report['findings'])}   "
          f"ATT&CK: {len(report['attack'])}   IOCs: "
          f"{sum(len(v) for k, v in report['iocs'].items() if not k.startswith('_') and k != 'hashes')}")
    if report["intel"].get("enabled"):
        print(f" Intel      : {i['verdict'].upper()}  (VT {i['vt_malicious'] + i['vt_suspicious']}/{i['vt_total']}"
              f"; hits: {', '.join(i['hits']) or 'none'})")
        if i["families"]:
            print(f" Families   : {', '.join(i['families'][:5])}")
        bad = i["providers_failed"]
        if bad:
            print(f" Provider issues: {', '.join(bad)} (see report)")
    print()
    for k, p in paths.items():
        print(f" [{k:5}] {p}")


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="MAL_v4.py", description=f"MAL v{VERSION} - Defensive static malware analysis + threat intelligence",
        epilog="Examples:\n  python MAL_v4.py sample.exe --intel --open\n"
               "  python MAL_v4.py sample.exe --intel vt,otx --enrich --formats all\n"
               "  python MAL_v4.py ./samples --recursive --intel\n"
               "  python MAL_v4.py --hash <sha256> --intel\n  python MAL_v4.py --check-config",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("target", nargs="?", help="File or directory to analyse (never executed)")
    p.add_argument("--hash", help="Look up a bare MD5/SHA-1/SHA-256 instead of analysing a file")
    p.add_argument("--recursive", "-r", action="store_true", help="Recurse into directories")
    p.add_argument("--intel", nargs="?", const="all", default=None, metavar="PROVIDERS",
                   help="Enable threat intel. Optional list: vt,mb,urlhaus,threatfox,otx,ha,abusech,all")
    p.add_argument("--vt", action="store_true", help="Alias for --intel vt (v3 compatibility)")
    p.add_argument("--vt-api-key", help="VirusTotal key (prefer .env)")
    p.add_argument("--vt-depth", choices=["basic", "standard", "full"],
                   help="VirusTotal detail: basic=1 call, standard=~5, full=~8+ (default from .env)")
    p.add_argument("--enrich", action="store_true",
                   help="ALSO send domains/IPs extracted from the sample to intel providers (opt-in)")
    p.add_argument("--no-intel", action="store_true", help="Force fully offline analysis")
    p.add_argument("--refresh", action="store_true", help="Ignore cached intel responses")
    p.add_argument("--no-cache", action="store_true", help="Do not read/write the intel cache")
    p.add_argument("--yara", help="YARA rules file or directory (default: ./rules if present)")
    p.add_argument("--formats", default="html,json",
                   help="Comma list of: html,json,csv,stix,yara or 'all' (default html,json)")
    p.add_argument("--output-dir", help="Output directory (default from .env / reports)")
    p.add_argument("--extract", action="store_true",
                   help="Save decoded/embedded PE payloads as .bin files for further analysis")
    p.add_argument("--no-deep", action="store_true", help="Skip XOR/embedded-PE scanning (faster on big files)")
    p.add_argument("--env", help="Path to a .env file (default: ./.env or next to the tool)")
    p.add_argument("--fail-on", choices=["MEDIUM", "HIGH", "CRITICAL"],
                   help="Exit code 3 if risk is at or above this level (CI use)")
    p.add_argument("--open", action="store_true", help="Open the HTML report in your browser")
    p.add_argument("--check-config", action="store_true", help="Show which API keys are configured and exit")
    p.add_argument("--version", action="version", version=f"MAL v{VERSION}")
    return p


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass
    args = build_parser().parse_args(argv)
    overrides = {"vt_api_key": args.vt_api_key, "vt_depth": args.vt_depth, "output_dir": args.output_dir}
    settings = load_settings(args.env, overrides)

    if args.check_config:
        print(f"MAL v{VERSION} configuration")
        print(f"  .env file : {settings.env_file or 'NOT FOUND (copy .env.example to .env)'}")
        for name, ok in settings.key_status().items():
            print(f"  {name:45} {'configured' if ok else 'missing'}")
        print(f"  VT depth={settings.vt_depth}  VT rate={settings.vt_rate_limit_per_min}/min  "
              f"cache={settings.cache_dir} ({settings.cache_ttl_hours:g}h)  enrich limit={settings.enrich_limit}")
        for w in settings.warnings:
            print(f"  WARNING: {w}")
        return 0

    for w in settings.warnings:
        print(f"[!] {w}", file=sys.stderr)

    if not args.target and not args.hash:
        build_parser().print_usage()
        print("error: provide a file/directory, or --hash", file=sys.stderr)
        return 2

    # ---- intel selection ----
    want_intel = (args.intel is not None) or args.vt or (settings.auto_intel and not args.no_intel)
    if args.no_intel:
        want_intel = False
    engine = None
    if want_intel:
        try:
            spec = parse_provider_list(args.intel) if args.intel is not None else None
        except ValueError as e:
            print(f"[ERROR] {e}", file=sys.stderr)
            return 2
        if args.vt and spec is not None:
            spec = list(dict.fromkeys(spec + ["vt"]))
        elif args.vt and args.intel is None:
            spec = ["vt"]
        engine = IntelEngine(settings, selected=spec, enrich=args.enrich, log=log,
                             refresh=args.refresh, use_cache=not args.no_cache)
        if not engine.providers:
            print("[!] Intel requested but no usable provider/API key. Run --check-config. "
                  "Continuing offline.", file=sys.stderr)
    if args.hash:
        h = args.hash.strip().lower()
        if len(h) not in (32, 40, 64) or any(c not in "0123456789abcdef" for c in h):
            print("[ERROR] --hash must be a 32/40/64-char hex MD5/SHA-1/SHA-256.", file=sys.stderr)
            return 2
        if engine is None:
            engine = IntelEngine(settings, selected=None, enrich=False, log=log,
                                 refresh=args.refresh, use_cache=not args.no_cache)
        report = analyze_hash(h, settings, args, engine)
        paths = write_outputs(report, {"strings": [], "data_len": 0}, Path(settings.output_dir),
                              _formats(args.formats, hash_mode=True), False)
        print_summary(report, paths)
        return _exit_code(args, [report])

    # ---- yara default ----
    if not args.yara:
        default_rules = Path(__file__).resolve().parent.parent / "rules"
        if default_rules.is_dir() and any(default_rules.glob("*.yar*")):
            args.yara = str(default_rules)

    target = Path(args.target).expanduser()
    if not target.exists():
        print(f"[ERROR] Not found: {target}", file=sys.stderr)
        return 2
    files = [target] if target.is_file() else sorted(
        f for f in (target.rglob("*") if args.recursive else target.glob("*")) if f.is_file())
    if not files:
        print("[ERROR] No files to analyse.", file=sys.stderr)
        return 2

    fmts = _formats(args.formats)
    outdir = Path(settings.output_dir)
    print(f"[+] MAL v{VERSION}  |  execution: DISABLED  |  files: {len(files)}", file=sys.stderr)
    reports, rows = [], []
    for f in files:
        log(f"Analysing {f.name}")
        try:
            report, ctx = analyze_file(f, settings, args, engine)
        except Exception as e:
            print(f"[ERROR] {f.name}: {e}", file=sys.stderr)
            rows.append({"name": f.name, "error": str(e)})
            continue
        paths = write_outputs(report, ctx, outdir, fmts, args.extract)
        print_summary(report, paths)
        reports.append(report)
        rows.append({"name": f.name, "report": report, "html": paths.get("html")})
        if args.open and "html" in paths and len(files) == 1:
            try:
                webbrowser.open(paths["html"].resolve().as_uri())
            except Exception:
                pass
    if len(files) > 1 and rows:
        from . import report as html_report
        idx = outdir / f"index_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        idx.write_text(html_report.build_index(rows), encoding="utf-8")
        print(f"\n[+] Batch index: {idx}")
        if args.open:
            try:
                webbrowser.open(idx.resolve().as_uri())
            except Exception:
                pass
    if not reports:
        return 1
    return _exit_code(args, reports)


def _formats(spec, hash_mode=False):
    f = {x.strip().lower() for x in spec.split(",") if x.strip()}
    if "all" in f:
        f = {"html", "json", "csv", "stix", "yara"}
    return f & {"html", "json", "csv", "stix", "yara"} or {"html", "json"}


def _exit_code(args, reports):
    if args.fail_on:
        worst = max(LEVEL_RANK[r["risk"]["level"]] for r in reports)
        if worst >= LEVEL_RANK[args.fail_on]:
            return 3
    return 0
