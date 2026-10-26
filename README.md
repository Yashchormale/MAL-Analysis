# MAL v4 — Defensive Malware Analysis & Threat Intelligence

Static analyzer with multi-provider threat intelligence. **It never executes the sample and never uploads it.**
Built for SOC / DFIR triage: drop in a file, get a risk score, extracted IOCs, ATT&CK mapping, decoded
payloads, and enrichment from VirusTotal and six other sources — as an HTML dashboard, JSON, IOC CSV,
STIX 2.1 and an auto-generated YARA rule.

## What's new vs v3

| Area | v3 | v4 |
|---|---|---|
| **VirusTotal** | detection count + engine list only | full file intel: threat label/category/family, sandbox verdicts, crowdsourced YARA / Sigma / IDS, signature info, tags, capabilities, names, first/last seen, votes, **sandbox behaviour** (processes, commands, registry, mutexes, DNS, HTTP, dropped files), **contacted domains/IPs/URLs**, MITRE tree, comments, Code Insight (when your key returns it) |
| Other intel | none | MalwareBazaar, URLhaus, ThreatFox (one abuse.ch key), AlienVault OTX, Hybrid Analysis, AbuseIPDB |
| Config | env var / CLI flag | **`.env` file**, masked status check, key redaction, quota-aware rate limiter, disk cache |
| Detection | ~20 strings | **94 capability rules + 11 correlation clusters**, each mapped to ATT&CK |
| Formats | PE (basic), ELF header, scripts | + advanced PE (imphash, packers, EP/overlay/TLS/resources/version info), real ELF section parsing, **OOXML/OLE macros, remote-template injection, DDE, RTF objects, PDF JS (incl. Flate-stream decoding), ZIP metadata, LNK** |
| Deobfuscation | flags long base64 | **decodes** base64, PowerShell `-EncodedCommand`, hex, `[char]`/`chr()` arrays, split strings, zlib/gzip; **XOR brute-force**; **carves embedded PEs** |
| IOCs | regex dump (lots of noise like `kernel32.dll`) | TLD-validated domains, benign-domain suppression, validated BTC addresses, mutexes, pipes, PDB paths, defanged by default, origin tracking (static / decoded / intel) |
| Evasion checks | none | RTLO, double extension, extension/content mismatch |
| Output | HTML + JSON | + IOC CSV, STIX 2.1, generated YARA, batch index, `--fail-on` for CI |
| Modes | single file | file, **directory (`-r`)**, **hash-only (`--hash`)** |

## Install

Python 3.7+ (3.9+ recommended).

```bash
pip install -r requirements.txt          # full feature set
# or: pip install -r requirements-min.txt   (requests + pefile only; everything else degrades gracefully)
```

## Set up your API keys (`.env`)

```bash
cp .env.example .env        # Windows: copy .env.example .env
# edit .env and paste keys after the "=" signs
python MAL_v4.py --check-config
```

| Provider | Where to get a key | Needed for |
|---|---|---|
| VirusTotal | virustotal.com → profile → API key | `VT_API_KEY` |
| abuse.ch | auth.abuse.ch (one key for all three) | `ABUSECH_AUTH_KEY` → MalwareBazaar, URLhaus, ThreatFox |
| AlienVault OTX | otx.alienvault.com → Settings → OTX Key | `OTX_API_KEY` |
| AbuseIPDB | abuseipdb.com → Account → API | `ABUSEIPDB_API_KEY` (IP lookups, with `--enrich`) |
| Hybrid Analysis | hybrid-analysis.com → profile → API key | `HYBRID_ANALYSIS_API_KEY` |

All keys are optional — leave blank to skip a provider. Free-tier quotas change; check each provider's site.
The VirusTotal free key is about 4 requests/minute, which MAL respects automatically (`VT_RATE_LIMIT_PER_MIN`).
`VT_DEPTH` controls how much VirusTotal data is pulled (and how many API calls it costs): `basic` = 1 call,
`standard` = ~5 (default), `full` = ~8+.

## Usage

```bash
python MAL_v4.py sample.exe                          # offline static analysis
python MAL_v4.py sample.exe --intel --open           # + all providers that have keys, open the report
python MAL_v4.py sample.exe --intel vt,otx           # choose providers
python MAL_v4.py sample.exe --intel --enrich         # ALSO look up domains/IPs found inside the sample
python MAL_v4.py sample.exe --intel --vt-depth full  # maximum VirusTotal detail
python MAL_v4.py ./samples -r --intel --formats all  # whole folder, batch index
python MAL_v4.py --hash <sha256> --intel             # look up a hash without having the file
python MAL_v4.py sample.exe --extract                # save decoded/embedded PEs as .bin for further analysis
python MAL_v4.py sample.exe --fail-on HIGH           # exit code 3 at HIGH+ (CI pipelines)
```

`--vt` still works (alias for `--intel vt`). Other useful flags: `--yara FILE_OR_DIR`, `--formats html,json,csv,stix,yara|all`,
`--refresh` (ignore cache), `--no-cache`, `--no-deep` (skip XOR/embedded-PE scan on huge files), `--output-dir`, `--env PATH`.

Outputs go to `reports/`: `*.html` (dashboard), `*.json` (full evidence), `*.iocs.csv`, `*.stix.json`, `*.generated.yar`.
Put your own `.yar` files in `rules/`; they load automatically (8 conservative default rules are included).

## Privacy & safety model

* The sample is **never executed** and **never uploaded**. There is no upload code path.
* `--intel` sends **file hashes only**.
* `--enrich` is a separate opt-in that also sends domains/IPs extracted from the sample (public IPs only; capped by
  `MAL_ENRICH_LIMIT`). Hosting attacker infrastructure lookups with third parties is your call, so it is off by default.
* API keys live in `.env`, travel only in HTTP headers, and are redacted from errors and reports. MAL warns if `.env`
  is readable by other users (POSIX).
* All third-party and sample-derived text is HTML-escaped; the report ships with a restrictive Content-Security-Policy.
  IOCs are shown **defanged** by default.
* Decoding is performed on bytes in memory. Nothing is `eval`'d, imported, or run.

## How the score works

Every rule/finding scores **once** (repeats are evidence only), points are summed per category, each category is
capped (see `mal/rules.py: CATEGORY_CAPS`), and the total is clamped to 100. Levels: LOW <25, MEDIUM 25–49, HIGH 50–74,
CRITICAL 75+. Two transparent floors exist and appear in the "Top risk contributors" table when they apply:
*reputation floor* (strong external consensus, e.g. ≥10 VirusTotal malicious verdicts or a MalwareBazaar/ThreatFox
hit) and *high-confidence floor* (e.g. reverse-shell, Mimikatz, injection API pair). The score reflects **observed
indicators, not proof of malicious intent or execution** — treat it as triage, not a verdict.

## Layout

```
MAL_v4.py            launcher
.env / .env.example  your keys and settings
rules/*.yar          YARA rules (auto-loaded)
mal/config.py        .env loader, settings
mal/triage.py        hashing, typing, strings, IOCs, deobfuscation, carving
mal/formats.py       PE / ELF / OOXML / OLE / RTF / PDF / archive analyzers
mal/rules.py         capability rules, ATT&CK map, correlation clusters (edit here to tune detection)
mal/scoring.py       capability engine + risk model
mal/intel.py         VirusTotal + 6 providers, cache, rate limiter
mal/report.py        HTML dashboard      mal/exports.py   CSV / STIX / YARA generation
tests/               sample generator + intel/offline tests (python tests/test_intel.py)
```

## Known limitations (read these)

* **Live API calls were not tested against the real services** during development (no internet in the build
  environment). Parsing and error handling were tested against API-shaped mock responses written from the providers'
  public documentation. If a provider changes its response format or an endpoint needs a higher plan, that section shows
  a clear status (`error` / `restricted`) instead of crashing — please report anything that looks wrong. The ThreatFox
  `search_hash` query and the Hybrid Analysis `/overview` response fields are the least certain.
* Some VirusTotal endpoints (behaviour, MITRE, some relationships) may return 403 on free keys; MAL shows "restricted".
* Static analysis only: no behaviour is *observed* by MAL itself. Behaviour shown under VirusTotal comes from their
  sandboxes. Use a real sandbox for dynamic confirmation.
* Authenticode is detected, **not validated**. Only single-byte XOR is brute-forced. `.7z/.rar/.iso` members are not
  inspected. Packed/encrypted payloads stay opaque by definition.
* Capability rules are string/API heuristics: legitimate admin tools and security software will trigger some of them
  (false positives), and determined malware can avoid them (false negatives).
* HTML was validated structurally and for injection-safety, but not visually in every browser.
* Analyse only files you are authorized to handle. Treat samples as live malware: use an isolated machine/VM.
