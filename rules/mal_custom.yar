/*
  MAL v4 - custom YARA rule pack (defensive detection)
  Drop this file in the rules/ folder; MAL loads it automatically.
  Standalone use:  yara -r rules/mal_custom.yar <file-or-folder>

  Each rule has meta: description, severity (low/medium/high), mitre_attack, category.
  Rules are intentionally CONSERVATIVE (multiple indicators, not single words) to limit
  false positives, but string-based detection is never perfect. Test on your own clean
  files before using them for blocking.
*/

import "pe"
import "math"

// ----------------------------------------------------------------------------
// Scripts / PowerShell
// ----------------------------------------------------------------------------

rule MALX_PowerShell_AMSI_Bypass
{
    meta:
        description = "PowerShell/.NET code that references AMSI internals (bypass pattern)"
        severity = "high"
        mitre_attack = "T1562.001"
        category = "defense-evasion"
    strings:
        $a1 = "AmsiUtils" nocase wide ascii
        $a2 = "amsiInitFailed" nocase wide ascii
        $a3 = "AmsiScanBuffer" nocase wide ascii
        $ref = "System.Management.Automation" nocase wide ascii
    condition:
        ($a1 and $a2) or ($a3 and $ref) or ($a2 and $ref)
}

rule MALX_PowerShell_Obfuscated_Launcher
{
    meta:
        description = "PowerShell launched with several stealth switches (encoded, hidden, bypass)"
        severity = "high"
        mitre_attack = "T1059.001, T1027.010"
        category = "execution"
    strings:
        $ps  = "powershell" nocase wide ascii
        $enc = /-e(nc|ncodedcommand)?[ ]+[A-Za-z0-9+\/=]{30,}/ nocase
        $hid = /-w(indowstyle)?[ ]+hidden/ nocase
        $byp = /-ex(ecutionpolicy)?[ ]+bypass/ nocase
        $nop = /-nop(rofile)?\b/ nocase
        $noni = /-noni(nteractive)?\b/ nocase
    condition:
        $ps and 3 of ($enc, $hid, $byp, $nop, $noni)
}

rule MALX_Script_Downloader_Dropper
{
    meta:
        description = "Classic WSH/VBS/JS downloader: HTTP object + ADODB.Stream + SaveToFile"
        severity = "high"
        mitre_attack = "T1105"
        category = "downloader"
    strings:
        $http1 = "Msxml2.XMLHTTP" nocase
        $http2 = "WinHttp.WinHttpRequest" nocase
        $http3 = "Microsoft.XMLHTTP" nocase
        $strm  = "ADODB.Stream" nocase
        $save  = "SaveToFile" nocase
        $run   = /(\.Run|\.Exec|ShellExecute)\b/ nocase
    condition:
        1 of ($http*) and $strm and $save and $run
}

rule MALX_HTA_Obfuscated_Launcher
{
    meta:
        description = "HTA file combining script obfuscation primitives with shell/COM execution"
        severity = "high"
        mitre_attack = "T1218.005, T1027"
        category = "execution"
    strings:
        $hta = "<hta:application" nocase
        $o1 = "unescape(" nocase
        $o2 = "fromCharCode" nocase
        $o3 = "eval(" nocase
        $o4 = /chr\(\s*[0-9]{2,3}\s*\)\s*&/ nocase
        $x1 = "WScript.Shell" nocase
        $x2 = "powershell" nocase
        $x3 = "ActiveXObject" nocase
        $x4 = "cmd.exe" nocase
    condition:
        $hta and 1 of ($o*) and 1 of ($x*)
}

rule MALX_Base64_Embedded_PE_In_NonPE
{
    meta:
        description = "Base64-encoded Windows executable header inside a file that is not itself a PE"
        severity = "high"
        mitre_attack = "T1027.009, T1140"
        category = "payload-embedding"
    strings:
        $b1 = "TVqQAAMAAAAEAAAA"
        $b2 = "TVpQAAIAAAAEAA8A"
        $b3 = "TVoAAAAAAAAAAAAA"
        $b4 = "TVqAAAEAAAAEABAA"
        $b5 = "TVpBUlVIieVI"
    condition:
        uint16(0) != 0x5A4D and any of them
}

// ----------------------------------------------------------------------------
// Office / documents
// ----------------------------------------------------------------------------

rule MALX_OOXML_Macro_Enabled
{
    meta:
        description = "Office Open XML package that contains a VBA project"
        severity = "medium"
        mitre_attack = "T1059.005, T1204.002"
        category = "document"
    strings:
        $vba = "vbaProject.bin"
        $w = "word/"
        $x = "xl/"
        $p = "ppt/"
    condition:
        uint32(0) == 0x04034B50 and $vba and any of ($w, $x, $p)
}

rule MALX_OOXML_Embedded_Executable
{
    meta:
        description = "Office package whose file list includes an executable or script member"
        severity = "high"
        mitre_attack = "T1027.009"
        category = "document"
    strings:
        $ct = "[Content_Types].xml"
        $e1 = /(embeddings|media|activeX)\/[A-Za-z0-9_\-\.]{1,60}\.(exe|dll|scr|js|vbs|hta|ps1|bat|lnk)/ nocase
    condition:
        uint32(0) == 0x04034B50 and $ct and $e1
}

rule MALX_OLE_Macro_AutoExec_Shell
{
    meta:
        description = "Legacy OLE document with macro project markers and auto-run + shell strings (best confirmed with olevba)"
        severity = "medium"
        mitre_attack = "T1059.005, T1204.002"
        category = "document"
    strings:
        $vba = "_VBA_PROJECT" wide ascii
        $ao1 = "AutoOpen" nocase wide ascii
        $ao2 = "Auto_Open" nocase wide ascii
        $ao3 = "Document_Open" nocase wide ascii
        $ao4 = "Workbook_Open" nocase wide ascii
        $sh1 = "WScript.Shell" nocase wide ascii
        $sh2 = "powershell" nocase wide ascii
        $sh3 = "URLDownloadToFile" nocase wide ascii
        $sh4 = "CreateObject" nocase wide ascii
    condition:
        uint32(0) == 0xE011CFD0 and $vba and 1 of ($ao*) and 1 of ($sh*)
}

rule MALX_RTF_Embedded_Object_Exploit_Pattern
{
    meta:
        description = "RTF with embedded object data and auto-update or Equation Editor markers"
        severity = "high"
        mitre_attack = "T1203"
        category = "document"
    strings:
        $obj = "\\objdata" nocase
        $upd = "\\objupdate" nocase
        $eq1 = "Equation.3" nocase
        $eq2 = "0002CE02" nocase
        $lnk = "\\objautlink" nocase
    condition:
        uint32(0) == 0x74725C7B and $obj and ($upd or $lnk or any of ($eq*))
}

rule MALX_PDF_Launch_Shell
{
    meta:
        description = "PDF with a Launch action that references a shell or script host"
        severity = "high"
        mitre_attack = "T1204.002"
        category = "document"
    strings:
        $launch = "/Launch" 
        $s1 = "cmd.exe" nocase
        $s2 = "powershell" nocase
        $s3 = "wscript" nocase
        $s4 = "mshta" nocase
    condition:
        uint32(0) == 0x46445025 and $launch and 1 of ($s*)
}

rule MALX_LNK_Shell_Command
{
    meta:
        description = "Windows shortcut that embeds a command interpreter / script host command line"
        severity = "high"
        mitre_attack = "T1204.002, T1059"
        category = "phishing-launcher"
    strings:
        $c1 = "powershell" nocase wide
        $c2 = "cmd.exe" nocase wide
        $c3 = "mshta" nocase wide
        $c4 = "wscript" nocase wide
        $c5 = "-enc" nocase wide
        $c6 = "http" nocase wide
    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and 2 of them
}

rule MALX_Archive_Double_Extension_Member
{
    meta:
        description = "ZIP archive containing a member that pretends to be a document but is executable (report.pdf.exe)"
        severity = "high"
        mitre_attack = "T1036.007"
        category = "phishing-archive"
    strings:
        $dbl = /[A-Za-z0-9_\- ]{1,60}\.(pdf|docx?|xlsx?|jpe?g|png|txt)[ ]*\.(exe|scr|js|vbs|hta|lnk|bat|cmd)/ nocase
    condition:
        uint32(0) == 0x04034B50 and $dbl
}

// ----------------------------------------------------------------------------
// PE structure (uses the YARA pe module)
// ----------------------------------------------------------------------------

rule MALX_PE_Classic_Injection_Imports
{
    meta:
        description = "PE importing the classic remote-process-injection API trio"
        severity = "high"
        mitre_attack = "T1055"
        category = "injection"
    condition:
        pe.is_pe and
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        (pe.imports("kernel32.dll", "CreateRemoteThread") or
         pe.imports("ntdll.dll", "NtCreateThreadEx") or
         pe.imports("kernel32.dll", "QueueUserAPC"))
}

rule MALX_PE_Process_Hollowing_Imports
{
    meta:
        description = "PE importing the API set used for process hollowing"
        severity = "high"
        mitre_attack = "T1055.012"
        category = "injection"
    condition:
        pe.is_pe and
        pe.imports("ntdll.dll", "NtUnmapViewOfSection") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        (pe.imports("kernel32.dll", "SetThreadContext") or pe.imports("kernel32.dll", "ResumeThread"))
}

rule MALX_PE_Packed_High_Entropy_Few_Imports
{
    meta:
        description = "PE with a high-entropy section and almost no imports (typical of packed/encrypted payloads)"
        severity = "medium"
        mitre_attack = "T1027.002"
        category = "packing"
    condition:
        pe.is_pe and
        pe.number_of_imported_functions < 12 and
        for any s in pe.sections : (
            s.raw_data_size > 8192 and
            math.entropy(s.raw_data_offset, s.raw_data_size) > 7.2
        )
}

rule MALX_PE_Known_Packer_Section_Names
{
    meta:
        description = "PE with section names left behind by common packers/protectors"
        severity = "medium"
        mitre_attack = "T1027.002"
        category = "packing"
    condition:
        pe.is_pe and
        for any s in pe.sections : (
            s.name startswith "UPX" or s.name == ".aspack" or s.name == ".adata" or
            s.name == ".themida" or s.name startswith ".vmp" or s.name == ".petite" or
            s.name startswith ".MPRESS" or s.name startswith ".nsp" or s.name == ".enigma1"
        )
}

rule MALX_PE_WX_Section_Entry_Last
{
    meta:
        description = "PE whose entry point is in a writable+executable last section (unpacking stub layout)"
        severity = "medium"
        mitre_attack = "T1027.002"
        category = "packing"
    condition:
        pe.is_pe and pe.number_of_sections >= 2 and
        for any i in (pe.number_of_sections - 1) : (
            pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE != 0 and
            pe.sections[i].characteristics & pe.SECTION_MEM_WRITE != 0 and
            pe.entry_point >= pe.sections[i].raw_data_offset and
            pe.entry_point < pe.sections[i].raw_data_offset + pe.sections[i].raw_data_size
        )
}

// ----------------------------------------------------------------------------
// Credential theft / exfiltration / impact
// ----------------------------------------------------------------------------

rule MALX_Credential_Dumping_Tool_Strings
{
    meta:
        description = "Strings typical of LSASS / SAM credential-dumping tooling"
        severity = "high"
        mitre_attack = "T1003"
        category = "credential-access"
    strings:
        $a1 = "sekurlsa" nocase wide ascii
        $a2 = "logonpasswords" nocase wide ascii
        $a3 = "lsadump::" nocase wide ascii
        $a4 = "kerberos::" nocase wide ascii
        $a5 = "privilege::debug" nocase wide ascii
        $a6 = "ntds.dit" nocase wide ascii
    condition:
        2 of them
}

rule MALX_LSASS_Memory_Dump_Command
{
    meta:
        description = "Command lines that dump LSASS memory using built-in or admin tools"
        severity = "high"
        mitre_attack = "T1003.001"
        category = "credential-access"
    strings:
        $c1 = /comsvcs\.dll[, ]+[^\r\n]{0,30}minidump/ nocase wide ascii
        $c2 = /procdump(64)?(\.exe)?[ ]+[^\r\n]{0,30}-ma[ ]+lsass/ nocase wide ascii
        $c3 = /rundll32[^\r\n]{0,60}comsvcs/ nocase wide ascii
        $c4 = "lsass.dmp" nocase wide ascii
    condition:
        any of ($c1, $c2, $c3) or ($c4 and uint16(0) != 0x5A4D)
}

rule MALX_Exfil_Webhook_Or_Bot_API
{
    meta:
        description = "Hard-coded Telegram bot API or Discord webhook URL (common stealer exfiltration channel)"
        severity = "medium"
        mitre_attack = "T1567, T1102"
        category = "exfiltration"
    strings:
        $t = /api\.telegram\.org\/bot[0-9]{8,10}:[A-Za-z0-9_\-]{30,}/ nocase wide ascii
        $d = /discord(app)?\.com\/api\/webhooks\/[0-9]{15,}\/[A-Za-z0-9_\-]{30,}/ nocase wide ascii
    condition:
        any of them
}

rule MALX_Cryptominer_Config
{
    meta:
        description = "Cryptocurrency miner configuration / pool strings"
        severity = "medium"
        mitre_attack = "T1496"
        category = "resource-hijacking"
    strings:
        $s1 = /stratum\+(tcp|ssl):\/\// nocase wide ascii
        $s2 = "xmrig" nocase wide ascii
        $s3 = "--donate-level" nocase wide ascii
        $s4 = "cryptonight" nocase wide ascii
        $s5 = "randomx" nocase wide ascii
        $w  = /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/
    condition:
        ($s1 and 1 of ($s2, $s3, $s4, $s5)) or ($w and 1 of ($s*)) or ($s2 and $s3)
}

rule MALX_Ransomware_Recovery_Destruction
{
    meta:
        description = "Commands that delete backups/shadow copies, optionally with ransom-note wording"
        severity = "high"
        mitre_attack = "T1490, T1486"
        category = "impact"
    strings:
        $v1 = /vssadmin(\.exe)?[ ]+delete[ ]+shadows/ nocase wide ascii
        $v2 = /wmic[ ]+shadowcopy[ ]+delete/ nocase wide ascii
        $v3 = /wbadmin[ ]+delete[ ]+(catalog|backup|systemstatebackup)/ nocase wide ascii
        $v4 = /bcdedit[^\r\n]{0,40}(recoveryenabled[ ]+no|ignoreallfailures)/ nocase wide ascii
        $n1 = /your[ ]+(files|data|network)[ ]+(have[ ]+been|are|was)[ ]+(encrypted|locked)/ nocase wide ascii
        $n2 = /(decrypt|recover)[ ]+(your[ ]+)?files/ nocase wide ascii
        $n3 = /(pay|payment)[^\r\n]{0,40}(bitcoin|btc|monero|xmr)/ nocase wide ascii
    condition:
        2 of ($v*) or (1 of ($v*) and 1 of ($n*)) or 2 of ($n*)
}

// ----------------------------------------------------------------------------
// Linux / web
// ----------------------------------------------------------------------------

rule MALX_Linux_Persistence_Downloader
{
    meta:
        description = "Shell/ELF content combining download-and-run with a persistence location"
        severity = "high"
        mitre_attack = "T1053.003, T1105"
        category = "linux-persistence"
    strings:
        $dl1 = /(curl|wget)[ ]+[^\r\n|;&]{0,200}\|[ ]*(sudo[ ]+)?(ba)?sh/
        $dl2 = /(curl|wget)[ ]+[^\r\n]{0,120}(\/tmp|\/dev\/shm|\/var\/tmp)\//
        $p1 = "/etc/cron" 
        $p2 = "crontab -"
        $p3 = "/etc/rc.local"
        $p4 = "authorized_keys"
        $p5 = "ld.so.preload"
        $p6 = "systemctl enable"
    condition:
        (uint32(0) == 0x464C457F or uint16(0) == 0x2123 or filesize < 200KB) and 1 of ($dl*) and 1 of ($p*)
}

rule MALX_PHP_Webshell_Patterns
{
    meta:
        description = "PHP code that executes request-supplied input (generic web-shell patterns)"
        severity = "high"
        mitre_attack = "T1505.003"
        category = "webshell"
    strings:
        $php = "<?php" nocase
        $w1 = /eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $w2 = /assert\s*\(\s*\$_(POST|GET|REQUEST)/ nocase
        $w3 = /(system|passthru|shell_exec|exec)\s*\(\s*\$_(POST|GET|REQUEST)/ nocase
        $w4 = /eval\s*\(\s*(base64_decode|gzinflate|str_rot13)\s*\(/ nocase
    condition:
        $php and 1 of ($w*)
}
