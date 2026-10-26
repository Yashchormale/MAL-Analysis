"""Format-specific static analyzers. Each returns a dict containing a `findings` list.

Nothing here opens, runs, or renders sample content: parsing only.
"""

from __future__ import annotations

import binascii
import datetime as dt
import hashlib
import io
import logging
import re
import struct
import zipfile
import zlib

from . import rules as R
from .utils import clean_text, entropy, finding, trunc

try:
    import pefile
except ImportError:
    pefile = None
try:
    import olefile
except ImportError:
    olefile = None
try:
    from oletools.olevba import VBA_Parser
except Exception:  # ImportError or oletools' own import-time problems
    VBA_Parser = None

logging.getLogger("olevba").setLevel(logging.CRITICAL)

T_PACK = ("T1027.002", "Obfuscated Files or Information: Software Packing", R.EVAS)
T_PAYLOAD = ("T1027.009", "Obfuscated Files or Information: Embedded Payloads", R.EVAS)
T_USER_EXEC = ("T1204.002", "User Execution: Malicious File", R.INIT)

MACHINE = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64", 0x200: "IA-64"}
SUBSYSTEM = {1: "Native (driver)", 2: "Windows GUI", 3: "Windows console", 5: "OS/2 console",
             7: "POSIX console", 9: "Windows CE", 10: "EFI application", 14: "Xbox"}


# ----------------------------------------------------------------------------
# PE
# ----------------------------------------------------------------------------

def analyze_pe(data: bytes, file_name: str = "") -> dict:
    if pefile is None:
        return {"available": False, "error": "pefile is not installed (pip install pefile)",
                "findings": []}

    res = {"available": True, "findings": []}
    F = res["findings"]
    try:
        pe = pefile.PE(data=data)
    except Exception as e:
        res["error"] = str(e)
        F.append(finding("pe_malformed", "Malformed or truncated PE headers", str(e), 6, "structure"))
        return res

    try:
        magic = pe.OPTIONAL_HEADER.Magic
        res["format"] = "PE32+" if magic == 0x20B else "PE32"
        res["machine"] = MACHINE.get(pe.FILE_HEADER.Machine, f"0x{pe.FILE_HEADER.Machine:x}")
        res["subsystem"] = SUBSYSTEM.get(pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem))
        chars = pe.FILE_HEADER.Characteristics
        res["is_dll"] = bool(chars & 0x2000)
        res["is_driver"] = pe.OPTIONAL_HEADER.Subsystem == 1
        res["entry_point"] = f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}"
        res["image_base"] = f"0x{pe.OPTIONAL_HEADER.ImageBase:x}"
        dllc = getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0)
        res["aslr"] = bool(dllc & 0x40)
        res["dep_nx"] = bool(dllc & 0x100)
        res["cfg"] = bool(dllc & 0x4000)

        # ---- compile timestamp ----
        ts = int(pe.FILE_HEADER.TimeDateStamp)
        res["timestamp_raw"] = ts
        try:
            res["timestamp"] = dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OverflowError, OSError, ValueError):
            res["timestamp"] = None
        now = dt.datetime.now(dt.timezone.utc).timestamp()
        if ts == 0:
            res["timestamp_note"] = "zeroed (stripped or reproducible build)"
        elif ts > now + 86400:
            res["timestamp_note"] = "in the future (forged)"
            F.append(finding("pe_ts_future", "Compile timestamp is in the future",
                             f"{res['timestamp']}", 4, "structure"))
        elif ts < 820454400:  # before 1996
            res["timestamp_note"] = "before 1996 (forged or Delphi default)"
            F.append(finding("pe_ts_old", "Implausibly old compile timestamp",
                             f"{res['timestamp']}", 3, "structure"))

        # ---- hashes ----
        try:
            res["imphash"] = pe.get_imphash() or None
        except Exception:
            res["imphash"] = None
        try:
            rh = getattr(pe, "RICH_HEADER", None)
            res["rich_header_hash"] = hashlib.md5(rh.clear_data).hexdigest() if rh else None
        except Exception:
            res["rich_header_hash"] = None

        # ---- .NET ----
        try:
            dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY
            res["dotnet"] = len(dd) > 14 and bool(dd[14].VirtualAddress)
        except Exception:
            res["dotnet"] = False

        # ---- sections ----
        ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        sections, packer_hits, hi_entropy, wx, raw0 = [], set(), [], [], []
        for sec in pe.sections:
            name = sec.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            c = sec.Characteristics
            perms = ("R" if c & 0x40000000 else "-") + ("W" if c & 0x80000000 else "-") + \
                    ("X" if c & 0x20000000 else "-")
            ent = round(sec.get_entropy(), 3)
            vs, rs = int(sec.Misc_VirtualSize), int(sec.SizeOfRawData)
            flags = []
            if name.lower().strip() in R.PACKER_SECTIONS:
                packer_hits.add(R.PACKER_SECTIONS[name.lower().strip()])
                flags.append("packer-name")
            if "W" in perms and "X" in perms:
                wx.append(name)
                flags.append("W+X")
            if ent >= 7.2 and rs >= 1024:
                hi_entropy.append(name)
                flags.append("high-entropy")
            if rs == 0 and vs > 0x1000 and ("X" in perms or "W" in perms):
                raw0.append(name)
                flags.append("raw=0")
            elif rs and vs > rs * 10 and vs > 0x10000:
                flags.append("virtual>>raw")
            if name.lower().strip() not in R.STANDARD_SECTIONS and "packer-name" not in flags:
                flags.append("non-standard")
            sections.append({"name": name, "virtual_address": f"0x{sec.VirtualAddress:x}",
                             "virtual_size": vs, "raw_size": rs, "entropy": ent,
                             "permissions": perms, "flags": flags})
        res["sections"] = sections

        if packer_hits:
            F.append(finding("pe_packer_sections", "Packer section names",
                             ", ".join(sorted(packer_hits)), 8, "obfuscation", T_PACK))
        if hi_entropy:
            F.append(finding("pe_high_entropy", "High-entropy section(s) (packed/encrypted data)",
                             ", ".join(hi_entropy[:8]), 8, "obfuscation", T_PACK))
        if wx:
            F.append(finding("pe_wx_section", "Section is both writable and executable",
                             ", ".join(wx[:8]), 6, "structure"))
        if raw0:
            F.append(finding("pe_unpack_space", "Executable section with no raw data (runtime unpacking space)",
                             ", ".join(raw0[:8]), 6, "obfuscation", T_PACK))

        # ---- entry point ----
        res["entry_section"] = None
        anomalies = []
        if ep_rva and pe.sections:
            esec = pe.get_section_by_rva(ep_rva)
            if esec is None:
                anomalies.append("entry point lies outside every section")
            else:
                en = esec.Name.rstrip(b"\x00").decode("ascii", "replace")
                res["entry_section"] = en
                if esec is pe.sections[-1] and len(pe.sections) > 1:
                    anomalies.append(f"entry point is in the LAST section ({en})")
                if esec.Characteristics & 0x80000000:
                    anomalies.append(f"entry-point section {en} is writable")
                if en.lower().strip() not in R.STANDARD_SECTIONS and en.lower().strip() not in R.PACKER_SECTIONS:
                    anomalies.append(f"entry point in non-standard section '{en}'")
        if anomalies:
            F.append(finding("pe_ep_anomaly", "Entry-point anomaly", "; ".join(anomalies), 6, "obfuscation", T_PACK))
        res["anomalies"] = anomalies

        # ---- imports ----
        imports_by_dll, flat = {}, []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = entry.dll.decode(errors="replace") if entry.dll else "UNKNOWN"
            names = []
            for imp in entry.imports:
                nm = imp.name.decode(errors="replace") if imp.name else f"ordinal_{imp.ordinal}"
                names.append(nm)
                flat.append(nm)
            imports_by_dll[dll] = names
        res["imports_by_dll"] = imports_by_dll
        res["import_names"] = flat
        res["import_count"] = len(flat)
        groups = {}
        for g, pat in R.IMPORT_GROUPS.items():
            rx = re.compile(pat, re.I)
            hit = [n for n in flat if rx.search(n)]
            if hit:
                groups[g] = hit[:25]
        res["import_groups"] = groups
        low = {n.lower() for n in flat}
        if len(flat) < 8 and ({"getprocaddress", "loadlibrarya", "loadlibraryw"} & low):
            F.append(finding("pe_few_imports", "Very few imports with dynamic loading (typical of packers)",
                             f"{len(flat)} imports", 6, "obfuscation", T_PACK))

        # ---- exports ----
        exports = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if sym.name:
                    exports.append(sym.name.decode(errors="replace"))
        res["exports"] = exports[:300]
        res["export_count"] = len(exports)

        # ---- TLS callbacks ----
        res["tls_callbacks"] = False
        tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
        if tls is not None and getattr(tls.struct, "AddressOfCallBacks", 0):
            res["tls_callbacks"] = True
            F.append(finding("pe_tls", "TLS callbacks present (code runs before entry point)",
                             "Often used for anti-debugging", 4, "anti_analysis",
                             ("T1622", "Debugger Evasion", R.EVAS)))

        # ---- resources ----
        resources, payload_res = [], []
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            try:
                for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    tname = pefile.RESOURCE_TYPE.get(rtype.id, None) if rtype.id is not None else None
                    tname = tname or (rtype.name.decode(errors="replace") if getattr(rtype, "name", None) else str(rtype.id))
                    if not hasattr(rtype, "directory"):
                        continue
                    for rid in rtype.directory.entries:
                        if not hasattr(rid, "directory"):
                            continue
                        for lang in rid.directory.entries:
                            rva, size = lang.data.struct.OffsetToData, lang.data.struct.Size
                            blob = pe.get_data(rva, min(size, 4 * 1024 * 1024)) if size else b""
                            ent = round(entropy(blob), 3) if len(blob) >= 256 else None
                            is_mz = blob[:2] == b"MZ"
                            item = {"type": tname, "size": size, "entropy": ent,
                                    "mz_header": is_mz}
                            resources.append(item)
                            if is_mz or (ent and ent >= 7.2 and size >= 4096 and tname not in
                                         ("RT_ICON", "RT_GROUP_ICON", "RT_BITMAP", "RT_CURSOR")):
                                payload_res.append(f"{tname} {size}B" + (" (MZ)" if is_mz else f" (ent {ent})"))
                            if len(resources) >= 80:
                                raise StopIteration
            except StopIteration:
                pass
            except Exception:
                pass
        res["resources"] = resources
        if payload_res:
            F.append(finding("pe_resource_payload", "Resource looks like an embedded payload",
                             "; ".join(payload_res[:5]), 8, "obfuscation", T_PAYLOAD))

        # ---- version info ----
        vi = {}
        for fi in getattr(pe, "FileInfo", []) or []:
            for entry in (fi if isinstance(fi, list) else [fi]):
                if getattr(entry, "Key", b"") == b"StringFileInfo":
                    for st in entry.StringTable:
                        for k, v in st.entries.items():
                            vi[k.decode(errors="replace")] = v.decode(errors="replace")
        res["version_info"] = vi
        orig = (vi.get("OriginalFilename") or "").lower().rsplit(".", 1)[0]
        cur = (file_name or "").lower().rsplit(".", 1)[0]
        if orig and cur and orig != cur and len(orig) > 2:
            res["renamed"] = True
            F.append(finding("pe_renamed", "File name differs from embedded OriginalFilename",
                             f"OriginalFilename={vi.get('OriginalFilename')} / file={file_name}",
                             2, "structure", ("T1036.005", "Masquerading: Match Legitimate Name or Location", R.EVAS)))

        # ---- signature directory + overlay ----
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        res["signature_present"] = bool(sec_dir.VirtualAddress and sec_dir.Size)
        res["signature_note"] = ("Authenticode block present (NOT cryptographically validated by MAL)"
                                 if res["signature_present"] else "Unsigned")
        ov = pe.get_overlay_data_start_offset()
        res["overlay"] = None
        if ov:
            ob = data[ov:]
            sig_size = sec_dir.Size if res["signature_present"] else 0
            real = max(0, len(ob) - sig_size)
            if real > 0:
                oe = round(entropy(ob[:2 * 1024 * 1024]), 3)
                res["overlay"] = {"offset": ov, "size": real, "entropy": oe,
                                  "mz_inside": b"MZ" in ob[:4096]}
                if real > 100 * 1024 and (oe >= 7.0 or res["overlay"]["mz_inside"]):
                    F.append(finding("pe_overlay", "Large high-entropy / executable overlay",
                                     f"{real} bytes at 0x{ov:x}, entropy {oe}", 6, "obfuscation", T_PAYLOAD))

        warns = pe.get_warnings()
        res["parser_warnings"] = [clean_text(w, 200) for w in warns[:10]]
        if len(warns) >= 3:
            F.append(finding("pe_warnings", "PE parser reported structural anomalies",
                             f"{len(warns)} warnings", 3, "structure"))
        pe.close()
    except Exception as e:
        res["error"] = f"partial PE analysis: {e}"
    return res


# ----------------------------------------------------------------------------
# ELF
# ----------------------------------------------------------------------------

ELF_TYPE = {1: "relocatable", 2: "executable", 3: "shared object / PIE", 4: "core"}
ELF_MACHINE = {3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 40: "ARM", 62: "x86-64",
               183: "AArch64", 243: "RISC-V"}


def analyze_elf(data: bytes) -> dict:
    res = {"available": True, "findings": []}
    F = res["findings"]
    try:
        is64 = data[4] == 2
        endian = "<" if data[5] == 1 else ">"
        res["class"] = "ELF64" if is64 else "ELF32"
        res["endianness"] = "little" if endian == "<" else "big"
        if is64:
            e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
            e_entry, e_phoff, e_shoff = struct.unpack_from(endian + "QQQ", data, 24)
            e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHHHH", data, 54)
        else:
            e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
            e_entry, e_phoff, e_shoff = struct.unpack_from(endian + "III", data, 24)
            e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHHHH", data, 42)
        res["type"] = ELF_TYPE.get(e_type, str(e_type))
        res["machine"] = ELF_MACHINE.get(e_machine, str(e_machine))
        res["entry_point"] = hex(e_entry)
        res["program_headers"] = e_phnum
        res["section_count"] = e_shnum

        # interpreter
        for i in range(min(e_phnum, 64)):
            off = e_phoff + i * e_phentsize
            if is64:
                p_type, _f, p_off, _va, _pa, p_filesz = struct.unpack_from(endian + "IIQQQQ", data, off)
            else:
                p_type, p_off, _va, _pa, p_filesz = struct.unpack_from(endian + "IIIII", data, off)
            if p_type == 3 and p_filesz < 256:
                res["interpreter"] = data[p_off:p_off + p_filesz].split(b"\x00")[0].decode("ascii", "replace")
                break

        # sections
        sections, wx = [], []
        if e_shoff and e_shnum and e_shnum < 200:
            raws = []
            for i in range(e_shnum):
                off = e_shoff + i * e_shentsize
                if is64:
                    n, t, fl, _a, so, sz = struct.unpack_from(endian + "IIQQQQ", data, off)
                else:
                    n, t, fl, _a, so, sz = struct.unpack_from(endian + "IIIIII", data, off)
                raws.append((n, t, fl, so, sz))
            strtab = b""
            if e_shstrndx < len(raws):
                _n, _t, _f, so, sz = raws[e_shstrndx]
                strtab = data[so: so + sz]
            for n, t, fl, so, sz in raws:
                name = strtab[n:].split(b"\x00")[0].decode("ascii", "replace") if strtab else ""
                body = data[so: so + min(sz, 4 * 1024 * 1024)] if t != 8 else b""
                perms = ("A" if fl & 2 else "-") + ("W" if fl & 1 else "-") + ("X" if fl & 4 else "-")
                if "W" in perms and "X" in perms:
                    wx.append(name)
                sections.append({"name": name, "size": sz,
                                 "entropy": round(entropy(body), 3) if len(body) >= 256 else None,
                                 "flags": perms})
        res["sections"] = sections
        names = {s["name"] for s in sections}
        res["stripped"] = bool(sections) and ".symtab" not in names
        if b"UPX!" in data[:4096] or b"UPX!" in data[-4096:]:
            F.append(finding("elf_upx", "UPX-packed ELF", "UPX! magic found", 6, "obfuscation", T_PACK))
        if wx:
            F.append(finding("elf_wx", "Section both writable and executable", ", ".join(wx[:5]), 5, "structure"))
        if e_shnum == 0:
            F.append(finding("elf_nosections", "Section header table removed",
                             "Typical of packers / hand-crafted ELF", 4, "obfuscation", T_PACK))
        hi = [s["name"] for s in sections if s["entropy"] and s["entropy"] >= 7.4 and s["size"] > 4096]
        if hi:
            F.append(finding("elf_entropy", "High-entropy ELF section(s)", ", ".join(hi[:5]), 6,
                             "obfuscation", T_PACK))
    except Exception as e:
        res["error"] = f"partial ELF parse: {e}"
    return res


# ----------------------------------------------------------------------------
# Office: macros (shared), OOXML, OLE, RTF
# ----------------------------------------------------------------------------

def olevba_analyze(data: bytes, file_name: str) -> dict:
    """Macro analysis. Uses oletools when installed, else heuristic detection."""
    out = {"present": False, "engine": "heuristic", "autoexec": [], "suspicious": [],
           "iocs": [], "obfuscation": [], "code_preview": None, "module_count": 0}
    if VBA_Parser is not None:
        try:
            vp = VBA_Parser(file_name or "sample", data=data)
            try:
                out["engine"] = "oletools/olevba"
                if vp.detect_vba_macros():
                    out["present"] = True
                    for kind, kw, desc in vp.analyze_macros(show_decoded_strings=False):
                        entry = f"{kw}: {desc}" if desc else str(kw)
                        k = str(kind).lower()
                        if k == "autoexec":
                            out["autoexec"].append(entry)
                        elif k == "suspicious":
                            out["suspicious"].append(entry)
                        elif k == "ioc":
                            out["iocs"].append(str(kw))
                        else:
                            out["obfuscation"].append(f"{kind}: {kw}")
                    first = None
                    for _f, _p, _vn, code in vp.extract_macros():
                        out["module_count"] += 1
                        if first is None and code and code.strip():
                            first = code
                    if first:
                        out["code_preview"] = clean_text(first.strip()[:1200], 1200)
            finally:
                vp.close()
            for k in ("autoexec", "suspicious", "iocs", "obfuscation"):
                out[k] = out[k][:40]
            return out
        except Exception as e:
            out["engine"] = f"heuristic (olevba failed: {trunc(e, 80)})"
    low = data.lower()
    if b"vbaproject.bin" in low or b"_vba_project" in low or "vba".encode("utf-16le") in low:
        out["present"] = True
    return out


def _macro_findings(m: dict, F: list):
    if not m["present"]:
        return
    F.append(finding("macro_present", "VBA macros present", f"engine: {m['engine']}", 8, "execution",
                     ("T1059.005", "Command and Scripting Interpreter: Visual Basic", R.EXEC)))
    if m["autoexec"]:
        F.append(finding("macro_autoexec", "Macro runs automatically on open",
                         "; ".join(m["autoexec"][:4]), 8, "execution", T_USER_EXEC))
    if m["suspicious"]:
        F.append(finding("macro_suspicious", "Suspicious macro keywords",
                         "; ".join(m["suspicious"][:6]), min(14, 4 + 2 * len(m["suspicious"])), "execution",
                         ("T1059.005", "Command and Scripting Interpreter: Visual Basic", R.EXEC)))
    if m["obfuscation"]:
        F.append(finding("macro_obfuscation", "Obfuscated strings in macro code",
                         "; ".join(m["obfuscation"][:4]), 6, "obfuscation",
                         ("T1027", "Obfuscated Files or Information", R.EVAS)))


_REL_RE = re.compile(r"<Relationship\b([^>]*)>", re.I)
_ATTR_RE = re.compile(r'(\w+)="([^"]*)"')


def analyze_ooxml(data: bytes, file_name: str) -> dict:
    res = {"available": True, "findings": [], "entries": [], "external_links": [], "embedded": [],
           "macros": None}
    F = res["findings"]
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except Exception as e:
        res["error"] = str(e)
        return res
    infos = z.infolist()[:3000]
    res["entry_count"] = len(infos)
    res["entries"] = [i.filename for i in infos[:120]]

    for info in infos:
        low = info.filename.lower()
        if low.endswith(".rels") and info.file_size < 1024 * 1024:
            try:
                xml = z.read(info).decode("utf-8", errors="ignore")
            except Exception:
                continue
            for m in _REL_RE.finditer(xml):
                a = dict(_ATTR_RE.findall(m.group(1)))
                if a.get("TargetMode", "").lower() != "external":
                    continue
                tgt, typ = a.get("Target", ""), a.get("Type", "").rsplit("/", 1)[-1]
                res["external_links"].append({"part": info.filename, "type": typ, "target": clean_text(tgt, 300)})
        if "/embeddings/" in low or "oleobject" in low or low.startswith("word/activex") or "/activex/" in low:
            res["embedded"].append(info.filename)
        ext = "." + low.rsplit(".", 1)[-1] if "." in low else ""
        if ext in R.RISKY_ARCHIVE_MEMBER_EXT and "customui" not in low:
            res["embedded"].append(info.filename)

    for link in res["external_links"]:
        t, typ = link["target"], link["type"].lower()
        if typ == "attachedtemplate" and t.lower().startswith(("http://", "https://", "\\\\", "file:")):
            F.append(finding("ooxml_remote_template", "Remote template injection",
                             f"{typ} -> {t}", 12, "evasion",
                             ("T1221", "Template Injection", R.EVAS)))
        elif t.lower().startswith(("\\\\", "file://")):
            F.append(finding("ooxml_unc", "External link to UNC/file path (NTLM leak risk)",
                             f"{typ} -> {t}", 6, "credential_access",
                             ("T1187", "Forced Authentication", R.CRED)))
        elif typ in {"oleobject", "frame", "subdocument", "externallinkpath"}:
            F.append(finding("ooxml_ext_object", f"External {typ} reference", t, 6, "execution", T_USER_EXEC))
    if res["embedded"]:
        exe = [e for e in res["embedded"] if "." + e.lower().rsplit(".", 1)[-1] in R.RISKY_ARCHIVE_MEMBER_EXT]
        if exe:
            F.append(finding("ooxml_embedded_exec", "Executable/script embedded in Office package",
                             ", ".join(exe[:5]), 10, "execution", T_PAYLOAD))
        elif any("oleobject" in e.lower() or "embeddings" in e.lower() for e in res["embedded"]):
            F.append(finding("ooxml_embedded_ole", "Embedded OLE object(s)",
                             ", ".join(res["embedded"][:5]), 5, "execution", T_USER_EXEC))
        if any("activex" in e.lower() for e in res["embedded"]):
            F.append(finding("ooxml_activex", "ActiveX controls", "word/activeX*", 4, "execution", T_USER_EXEC))

    for doc in ("word/document.xml", "xl/workbook.xml"):
        try:
            if doc in z.namelist() and z.getinfo(doc).file_size < 8 * 1024 * 1024:
                txt = z.read(doc).decode("utf-8", errors="ignore")
                if re.search(r"\bDDE(?:AUTO)?\b[^<]{0,40}", txt):
                    F.append(finding("ooxml_dde", "DDE field in document body", doc, 8, "execution",
                                     ("T1559.002", "Inter-Process Communication: Dynamic Data Exchange", R.EXEC)))
        except Exception:
            pass

    res["extra_text"] = []
    for link in res["external_links"]:
        res["extra_text"].append(link["target"])
    for info in infos:
        low = info.filename.lower()
        if len(res["extra_text"]) >= 12:
            break
        if low in ("word/document.xml", "xl/sharedstrings.xml", "ppt/slides/slide1.xml") and info.file_size < 2 * 1024 * 1024:
            try:
                res["extra_text"].append(z.read(info).decode("utf-8", errors="ignore"))
            except Exception:
                pass

    if any(i.filename.lower().endswith("vbaproject.bin") for i in infos):
        m = olevba_analyze(data, file_name)
        m["present"] = True
        res["macros"] = m
        _macro_findings(m, F)
    z.close()
    return res


def analyze_ole(data: bytes, file_name: str) -> dict:
    res = {"available": True, "findings": [], "streams": [], "metadata": {}, "macros": None}
    F = res["findings"]
    if olefile is not None:
        try:
            ole = olefile.OleFileIO(io.BytesIO(data))
            res["streams"] = ["/".join(s) for s in ole.listdir()][:80]
            try:
                meta = ole.get_metadata()
                for k in ("author", "last_saved_by", "creating_application", "create_time",
                          "last_saved_time", "title", "company"):
                    v = getattr(meta, k, None)
                    if v:
                        res["metadata"][k] = clean_text(v.decode("latin-1", "replace") if isinstance(v, bytes) else v, 120)
            except Exception:
                pass
            if any("EncryptedPackage" in s for s in res["streams"]):
                F.append(finding("ole_encrypted", "Password-protected / encrypted Office package",
                                 "Content cannot be statically inspected", 4, "obfuscation",
                                 ("T1027.013", "Obfuscated Files or Information: Encrypted/Encoded File", R.EVAS)))
            ole.close()
        except Exception as e:
            res["error"] = trunc(e, 120)
    m = olevba_analyze(data, file_name)
    res["macros"] = m
    _macro_findings(m, F)
    return res


def analyze_rtf(data: bytes) -> dict:
    res = {"available": True, "findings": [], "counts": {}}
    F = res["findings"]
    head = data[:20 * 1024 * 1024]
    for token in (rb"\objdata", rb"\objemb", rb"\objupdate", rb"\objautlink", rb"\objclass", rb"\*\datastore"):
        n = head.lower().count(token)
        if n:
            res["counts"][token.decode()] = n
    objdata_n = res["counts"].get("\\objdata", 0)
    if objdata_n:
        F.append(finding("rtf_objdata", "Embedded OLE object data in RTF",
                         "%d objdata block(s)" % objdata_n, 8, "execution",
                         ("T1203", "Exploitation for Client Execution", R.EXEC)))
        m = re.search(rb"\\objdata\s*([0-9A-Fa-f\s\r\n]{64,})", head, re.I)
        if m:
            hexbody = re.sub(rb"[^0-9A-Fa-f]", b"", m.group(1))[:4 * 1024 * 1024]
            try:
                raw = binascii.unhexlify(hexbody[: len(hexbody) // 2 * 2])
            except (binascii.Error, ValueError):
                raw = b""
            res["objdata_magic"] = ("OLE2" if raw[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" else
                                    "PE" if raw[:2] == b"MZ" else (raw[:4].hex() if raw else None))
            if b"MZ" in raw[:4096] or b"This program" in raw:
                F.append(finding("rtf_embedded_pe", "Executable inside RTF object data", "MZ header in \\objdata",
                                 12, "execution", T_PAYLOAD))
    if re.search(rb"equation", head[:200000], re.I) and objdata_n:
        F.append(finding("rtf_equation", "Equation Editor object (frequently exploited legacy component)",
                         "objclass Equation.*", 10, "execution",
                         ("T1203", "Exploitation for Client Execution", R.EXEC)))
    return res


# ----------------------------------------------------------------------------
# PDF
# ----------------------------------------------------------------------------

_PDF_TOKENS = {
    "/JavaScript": (10, "execution", "Embedded JavaScript",
                    ("T1059.007", "Command and Scripting Interpreter: JavaScript", R.EXEC)),
    "/JS": (0, None, None, None),
    "/OpenAction": (4, "execution", "Auto-run action on open", T_USER_EXEC),
    "/AA": (3, "execution", "Additional-actions trigger", T_USER_EXEC),
    "/Launch": (10, "execution", "Launch action (runs external program)", T_USER_EXEC),
    "/EmbeddedFile": (5, "execution", "Embedded file", T_PAYLOAD),
    "/RichMedia": (6, "execution", "Rich media (Flash) content", T_USER_EXEC),
    "/XFA": (5, "execution", "XFA forms (historically exploited)", T_USER_EXEC),
    "/SubmitForm": (3, "network", "Form submission to remote host", None),
    "/GoToR": (3, "network", "Remote go-to action", None),
}


def analyze_pdf(data: bytes) -> dict:
    res = {"available": True, "findings": [], "counts": {}, "decoded_text": [], "uris": []}
    F = res["findings"]
    sample = data[:30 * 1024 * 1024]
    norm = re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), sample)  # un-escape /J#53
    res["hex_escaped_names"] = len(re.findall(rb"/[A-Za-z]*#[0-9A-Fa-f]{2}", sample))
    for tok in list(_PDF_TOKENS) + ["/ObjStm", "/Encrypt", "/URI", "/AcroForm"]:
        n = len(re.findall(re.escape(tok).encode() + b"(?![A-Za-z])", norm))
        if n:
            res["counts"][tok] = n
    res["object_count"] = len(re.findall(rb"\d+\s+\d+\s+obj\b", sample))
    res["stream_count"] = len(re.findall(rb"\bstream\r?\n", sample))
    res["uris"] = [clean_text(u.decode("latin-1"), 200) for u in
                   re.findall(rb"/URI\s*\(([^)]{4,300})\)", norm)[:30]]

    # decode Flate streams so hidden JS/URLs are visible to the rule engine
    total = 0
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", sample, re.S):
        if len(res["decoded_text"]) >= 200 or total > 4 * 1024 * 1024:
            break
        try:
            out = zlib.decompressobj().decompress(m.group(1), 2 * 1024 * 1024)
        except Exception:
            continue
        if out and sum(1 for c in out[:2000] if 32 <= c < 127 or c in (9, 10, 13)) > 0.8 * min(len(out), 2000):
            t = out.decode("latin-1", errors="ignore")
            res["decoded_text"].append(t)
            total += len(t)
    res["decoded_streams"] = len(res["decoded_text"])
    blob = "\n".join(res["decoded_text"]).lower()
    c = res["counts"]
    js_count = c.get("/JavaScript", 0) + c.get("/JS", 0)
    if js_count or re.search(r"app\.(?:launchurl|alert|exec)|this\.exportdataobject|util\.printf|eval\(", blob):
        F.append(finding("pdf_js", "Embedded JavaScript", f"{js_count} /JS reference(s)"
                         + (" + script API in streams" if blob and "app." in blob else ""),
                         10, "execution", _PDF_TOKENS["/JavaScript"][3]))
    for tok, (w, cat, title, atk) in _PDF_TOKENS.items():
        if tok in ("/JS", "/JavaScript") or not w or tok not in c:
            continue
        F.append(finding("pdf_" + tok.strip("/").lower(), title, f"{c[tok]}x {tok}", w, cat, atk))
    if res["hex_escaped_names"] >= 3:
        F.append(finding("pdf_name_obfuscation", "Hex-escaped PDF names (parser-evasion trick)",
                         f"{res['hex_escaped_names']} escaped names", 6, "obfuscation",
                         ("T1027", "Obfuscated Files or Information", R.EVAS)))
    if c.get("/Encrypt"):
        F.append(finding("pdf_encrypt", "Encrypted PDF", "Content may hide from scanners", 2, "obfuscation"))
    if res["object_count"] and res["object_count"] <= 4 and res["stream_count"] == 0 and js_count:
        F.append(finding("pdf_minimal", "Minimal PDF with script and almost no content",
                         f"{res['object_count']} objects", 4, "structure"))
    return res


# ----------------------------------------------------------------------------
# Archives (metadata only; members are never extracted)
# ----------------------------------------------------------------------------

def analyze_zip(data: bytes) -> dict:
    res = {"available": True, "findings": [], "entries": []}
    F = res["findings"]
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except Exception as e:
        res["error"] = str(e)
        return res
    infos = z.infolist()
    res["entry_count"] = len(infos)
    enc, risky, dbl, nested = [], [], [], []
    total_u = total_c = 0
    for i in infos[:5000]:
        total_u += i.file_size
        total_c += i.compress_size
        low = i.filename.lower()
        ext = "." + low.rsplit(".", 1)[-1] if "." in low else ""
        if i.flag_bits & 0x1:
            enc.append(i.filename)
        if ext in R.RISKY_ARCHIVE_MEMBER_EXT:
            risky.append(i.filename)
        if R.DOUBLE_EXT_RE.search(i.filename):
            dbl.append(i.filename)
        if ext in {".zip", ".rar", ".7z", ".iso", ".img", ".cab", ".gz"}:
            nested.append(i.filename)
        if len(res["entries"]) < 150:
            res["entries"].append({"name": clean_text(i.filename, 120), "size": i.file_size,
                                   "compressed": i.compress_size, "encrypted": bool(i.flag_bits & 1)})
    res["total_uncompressed"] = total_u
    if enc:
        F.append(finding("zip_encrypted", "Password-protected archive entries",
                         f"{len(enc)} encrypted: {', '.join(enc[:3])}", 6, "obfuscation",
                         ("T1027.013", "Obfuscated Files or Information: Encrypted/Encoded File", R.EVAS)))
    if risky:
        F.append(finding("zip_risky_members", "Archive contains executable/script/shortcut files",
                         ", ".join(risky[:6]), 8, "execution", T_USER_EXEC))
    if dbl:
        F.append(finding("zip_double_ext", "Archive member with double extension", ", ".join(dbl[:4]), 8,
                         "evasion", ("T1036.007", "Masquerading: Double File Extension", R.EVAS)))
    if nested:
        F.append(finding("zip_nested", "Nested archive / disk image inside archive", ", ".join(nested[:4]),
                         3, "obfuscation"))
    if total_c and total_u / max(total_c, 1) > 200 and total_u > 500 * 1024 * 1024:
        F.append(finding("zip_bomb", "Extreme compression ratio (possible decompression bomb)",
                         f"{total_u // (1024 * 1024)} MB from {total_c // 1024} KB", 6, "structure"))
    z.close()
    return res


def analyze_lnk(data: bytes) -> dict:
    return {"available": True, "findings": [
        finding("lnk_file", "Windows shortcut file", "Shortcuts are a common phishing launcher; "
                "command line is scanned via strings", 5, "execution", T_USER_EXEC)]}


# ----------------------------------------------------------------------------
# Dispatcher
# ----------------------------------------------------------------------------

def analyze_formats(kind: str, data: bytes, path_name: str) -> dict:
    """Run the analyzers relevant to the detected kind."""
    out = {"pe": None, "elf": None, "office": None, "pdf": None, "archive": None,
           "findings": [], "extra_text": []}
    if kind == "pe":
        out["pe"] = analyze_pe(data, path_name)
    elif kind == "elf":
        out["elf"] = analyze_elf(data)
    elif kind == "ooxml":
        out["office"] = analyze_ooxml(data, path_name)
        out["office"]["flavor"] = "ooxml"
        out["extra_text"] = [("ooxml_part", t) for t in out["office"].pop("extra_text", [])]
    elif kind == "ole":
        out["office"] = analyze_ole(data, path_name)
        out["office"]["flavor"] = "ole"
    elif kind == "rtf":
        out["office"] = analyze_rtf(data)
        out["office"]["flavor"] = "rtf"
    elif kind == "pdf":
        out["pdf"] = analyze_pdf(data)
        out["extra_text"] = [("pdf_stream", t) for t in out["pdf"].pop("decoded_text", [])]
    elif kind in {"zip", "jar", "apk"}:
        out["archive"] = analyze_zip(data)
    elif kind == "lnk":
        out["archive"] = None
        out["office"] = None
        out["findings"] += analyze_lnk(data)["findings"]
    for key in ("pe", "elf", "office", "pdf", "archive"):
        if out[key]:
            out["findings"] += out[key].get("findings", [])
    return out
