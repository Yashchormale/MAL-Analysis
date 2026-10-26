import sys, time, os, tempfile, json
ROOT = str(__import__("pathlib").Path(__file__).resolve().parent.parent)
sys.path.insert(0, ROOT); sys.path.insert(0, "/home/claude/tests")
from mal import intel, config
from mal.utils import RateLimiter, DiskCache, defang
from test_intel import FakeHttp, settings, SHA, H

# cache: 2nd run must make zero VT HTTP calls
d = tempfile.mkdtemp()
s = settings(cache_dir=d, cache_ttl_hours=24, vt_depth="standard")
e = intel.IntelEngine(s, selected=["vt"]); e.http = FakeHttp(); e.run(H, None); n1 = len(e.http.calls)
e2 = intel.IntelEngine(s, selected=["vt"]); e2.http = FakeHttp(); r = e2.run(H, None)
print(f"cache: first run {n1} calls, second run {len(e2.http.calls)} calls, from_cache={r['providers']['vt'].get('from_cache')}")
e3 = intel.IntelEngine(s, selected=["vt"], refresh=True); e3.http = FakeHttp(); e3.run(H, None)
print("--refresh bypasses cache:", len(e3.http.calls) == n1)
print("depth basic = 1 call:", end=" ")
e4 = intel.IntelEngine(settings(vt_depth="basic"), selected=["vt"], use_cache=False); e4.http = FakeHttp(); e4.run(H, None); print(len(e4.http.calls))

# rate limiter: 4/min means 15s spacing; test at 600/min = 0.1s
rl = RateLimiter(600); t = time.time(); [rl.wait() for _ in range(5)]
print(f"rate limiter: 5 calls took {time.time()-t:.2f}s (expect ~0.4s)"); print("unlimited when 0:", RateLimiter(0).wait() == 0)

# .env parsing
txt = '''# comment
VT_API_KEY="abc123SECRET"   
export OTX_API_KEY='otxkey999'
ABUSEIPDB_API_KEY=abuse_key_1 # inline comment
HYBRID_ANALYSIS_API_KEY=your_hybrid_key_here
ABUSECH_AUTH_KEY=
MAL_ENRICH_LIMIT=9
BAD LINE
'''
print(config.parse_env_text(txt))
with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as f: f.write(txt)
os.environ.pop("VT_API_KEY", None)
st = config.load_settings(f.name)
print("placeholder ignored:", st.hybrid_analysis_api_key == "", "| vt:", st.vt_api_key, "| enrich:", st.enrich_limit)
os.environ["VT_API_KEY"] = "REALENV"; print("real env beats .env:", config.load_settings(f.name).vt_api_key); del os.environ["VT_API_KEY"]
os.chmod(f.name, 0o644); print("perm warning:", bool(config.load_settings(f.name).warnings))
os.chmod(f.name, 0o600); print("no warning at 600:", not config.load_settings(f.name).warnings)
print("defang:", defang("http://evil.top/a.php"), defang("1.2.3.4"), defang("a@b.com"))
# public IP actually queried
e5 = intel.IntelEngine(settings(), selected=["vt","abuseipdb"], enrich=True, use_cache=False); e5.http = FakeHttp()
r5 = e5.run(H, {"ips": ["8.8.8.8","192.168.1.1"], "domains": []})
print("public IP enriched:", list(r5["network"]), "| abuseipdb:", r5["network"]["ip:8.8.8.8"]["providers"]["abuseipdb"]["score"])
