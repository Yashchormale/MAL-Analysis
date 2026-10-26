"""Detection knowledge base for MAL v4 (pure data, no logic).

Every capability rule is a tuple:
    (id, regex, title, category, weight, attack)
where `attack` is (technique_id, technique_name, tactic) or None.
Each rule scores AT MOST ONCE; repetition is shown as evidence only.
"""

from __future__ import annotations

import re

TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact", "Other",
]

CATEGORY_CAPS = {
    "execution": 25,
    "network": 18,
    "persistence": 18,
    "injection": 25,
    "obfuscation": 18,
    "evasion": 14,
    "anti_analysis": 12,
    "credential_access": 20,
    "collection": 12,
    "impact": 25,
    "structure": 18,
    "reputation": 30,
    "ioc": 6,
}

EXEC, PERS, PRIV = "Execution", "Persistence", "Privilege Escalation"
EVAS, CRED, DISC = "Defense Evasion", "Credential Access", "Discovery"
LAT, COLL, C2 = "Lateral Movement", "Collection", "Command and Control"
EXFIL, IMPACT, INIT = "Exfiltration", "Impact", "Initial Access"

CAPABILITY_RULES = [
    # ---------------- PowerShell / scripting ----------------
    ("ps_exec", r"powershell(?:\.exe)?\b", "PowerShell reference", "execution", 6,
     ("T1059.001", "Command and Scripting Interpreter: PowerShell", EXEC)),
    ("ps_enc", r"\s-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}", "PowerShell encoded command",
     "obfuscation", 12, ("T1027.010", "Obfuscated Files or Information: Command Obfuscation", EVAS)),
    ("ps_hidden", r"-w(?:indowstyle)?\s+hidden|-windowstyle\s+h\b", "Hidden window execution",
     "evasion", 7, ("T1564.003", "Hide Artifacts: Hidden Window", EVAS)),
    ("ps_bypass", r"-ex(?:ecutionpolicy)?\s+bypass|\s-nop(?:rofile)?\b|-noni(?:nteractive)?\b",
     "PowerShell policy bypass / no-profile", "execution", 5,
     ("T1059.001", "Command and Scripting Interpreter: PowerShell", EXEC)),
    ("ps_iex", r"\binvoke-expression\b|\biex\b\s*[\(\$\"']", "Dynamic code execution (IEX)",
     "execution", 8, ("T1059.001", "Command and Scripting Interpreter: PowerShell", EXEC)),
    ("ps_cradle",
     r"downloadstring|downloadfile|downloaddata|invoke-webrequest|invoke-restmethod|"
     r"net\.webclient|start-bitstransfer|system\.net\.http",
     "Remote content download cradle", "network", 8,
     ("T1105", "Ingress Tool Transfer", C2)),
    ("ps_reflect",
     r"\[reflection\.assembly\]::load|assembly\.load\(|frombase64string|\[system\.convert\]::frombase64",
     "Reflective / in-memory .NET loading", "obfuscation", 8,
     ("T1620", "Reflective Code Loading", EVAS)),
    ("ps_amsi", r"amsiutils|amsiinitfailed|amsiscanbuffer|amsi\.dll", "AMSI tampering reference",
     "evasion", 12, ("T1562.001", "Impair Defenses: Disable or Modify Tools", EVAS)),
    ("ps_pinvoke", r"add-type[^\n]{0,120}dllimport|\[dllimport\(\s*\"(?:kernel32|user32|ntdll)",
     "Win32 API access from script (P/Invoke)", "execution", 7,
     ("T1106", "Native API", EXEC)),
    ("wsh", r"wscript\.shell|wscript\.exe|cscript\.exe", "Windows Script Host", "execution", 7,
     ("T1059.005", "Command and Scripting Interpreter: Visual Basic", EXEC)),
    ("createobject", r"createobject\s*\(", "COM object creation", "execution", 4,
     ("T1059.005", "Command and Scripting Interpreter: Visual Basic", EXEC)),
    ("adodb_stream", r"adodb\.stream|scripting\.filesystemobject", "File/stream write via COM",
     "execution", 5, ("T1105", "Ingress Tool Transfer", C2)),
    ("xml_http", r"msxml2\.(?:server)?xmlhttp|winhttp\.winhttprequest|microsoft\.xmlhttp",
     "HTTP request object", "network", 6,
     ("T1071.001", "Application Layer Protocol: Web Protocols", C2)),
    ("js_eval", r"\beval\s*\(|\bunescape\s*\(|\bfromcharcode\b|\bactivexobject\b",
     "JavaScript obfuscation / ActiveX", "obfuscation", 6,
     ("T1027", "Obfuscated Files or Information", EVAS)),
    ("hta_content", r"<hta:application|language\s*=\s*[\"']?vbscript", "HTA / script-host content",
     "execution", 5, ("T1218.005", "System Binary Proxy Execution: Mshta", EVAS)),
    ("py_exec",
     r"\bexec\s*\(\s*(?:base64|zlib|marshal|compile)|marshal\.loads|pickle\.loads|"
     r"\bos\.system\s*\(|subprocess\.(?:popen|call|run)\b",
     "Python dynamic execution / shell-out", "execution", 6,
     ("T1059.006", "Command and Scripting Interpreter: Python", EXEC)),
    ("php_webshell",
     r"eval\s*\(\s*\$_(?:post|get|request)|base64_decode\s*\(\s*\$_|assert\s*\(\s*\$_|"
     r"system\s*\(\s*\$_(?:get|post|request)|c99shell|r57shell|china\s*chopper",
     "Web-shell pattern", "persistence", 14, ("T1505.003", "Server Software Component: Web Shell", PERS)),
    ("cmd_c", r"\bcmd(?:\.exe)?\s+/[ck]\b", "cmd.exe command execution", "execution", 5,
     ("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", EXEC)),

    # ---------------- LOLBins / proxy execution ----------------
    ("mshta", r"\bmshta(?:\.exe)?\b", "mshta.exe", "execution", 8,
     ("T1218.005", "System Binary Proxy Execution: Mshta", EVAS)),
    ("rundll32", r"\brundll32(?:\.exe)?\b", "rundll32.exe", "execution", 7,
     ("T1218.011", "System Binary Proxy Execution: Rundll32", EVAS)),
    ("regsvr32", r"\bregsvr32(?:\.exe)?\b", "regsvr32.exe", "execution", 7,
     ("T1218.010", "System Binary Proxy Execution: Regsvr32", EVAS)),
    ("certutil", r"certutil(?:\.exe)?[^\n]{0,60}-(?:urlcache|decode|encode)",
     "certutil download/decode", "execution", 9, ("T1140", "Deobfuscate/Decode Files or Information", EVAS)),
    ("bitsadmin", r"bitsadmin(?:\.exe)?[^\n]{0,60}/(?:transfer|addfile)", "BITS job transfer",
     "network", 8, ("T1197", "BITS Jobs", EVAS)),
    ("wmi_exec", r"wmic(?:\.exe)?\s+(?:process\s+call|/node)|winmgmts:|win32_process\b",
     "WMI execution", "execution", 7, ("T1047", "Windows Management Instrumentation", EXEC)),
    ("lolbin_misc",
     r"\b(?:msiexec|installutil|regasm|regsvcs|msbuild|forfiles|pcalua|odbcconf|ieexec|infdefaultinstall)"
     r"(?:\.exe)?\b[^\n]{0,60}(?:/q|/i\b|http|\\\\|/y)",
     "Other LOLBin proxy execution", "execution", 7,
     ("T1218", "System Binary Proxy Execution", EVAS)),
    ("uac_bypass",
     r"fodhelper|eventvwr\.exe|computerdefaults|\bsdclt\b|\bcmstp(?:\.exe)?\b|ms-settings\\shell\\open",
     "UAC bypass technique", "evasion", 10,
     ("T1548.002", "Abuse Elevation Control Mechanism: Bypass UAC", PRIV)),

    # ---------------- Persistence ----------------
    ("reg_run", r"currentversion\\run(?:once)?\b", "Registry Run key", "persistence", 9,
     ("T1547.001", "Boot or Logon Autostart: Registry Run Keys / Startup Folder", PERS)),
    ("startup_folder", r"\\start menu\\programs\\startup", "Startup folder", "persistence", 8,
     ("T1547.001", "Boot or Logon Autostart: Registry Run Keys / Startup Folder", PERS)),
    ("schtasks", r"\bschtasks(?:\.exe)?\b", "Scheduled task utility", "persistence", 8,
     ("T1053.005", "Scheduled Task/Job: Scheduled Task", PERS)),
    ("sc_create", r"\bsc(?:\.exe)?\s+create\b|\bcreateservice[aw]?\b", "Service creation",
     "persistence", 7, ("T1543.003", "Create or Modify System Process: Windows Service", PERS)),
    ("reg_add", r"\breg(?:\.exe)?\s+add\b", "Registry modification command", "persistence", 5,
     ("T1112", "Modify Registry", EVAS)),
    ("ifeo", r"image file execution options|winlogon\\(?:shell|userinit)",
     "IFEO / Winlogon hijack", "persistence", 10,
     ("T1546.012", "Event Triggered Execution: Image File Execution Options Injection", PERS)),
    ("wmi_event", r"__eventfilter|commandlineeventconsumer", "WMI event subscription",
     "persistence", 10, ("T1546.003", "Event Triggered Execution: WMI Event Subscription", PERS)),
    ("appinit", r"appinit_dlls", "AppInit DLLs", "persistence", 8,
     ("T1546.010", "Event Triggered Execution: AppInit DLLs", PERS)),
    ("com_hijack", r"inprocserver32", "COM server registration", "persistence", 4,
     ("T1546.015", "Event Triggered Execution: Component Object Model Hijacking", PERS)),
    ("cron", r"/etc/cron|crontab\s+-|/var/spool/cron", "Cron persistence", "persistence", 7,
     ("T1053.003", "Scheduled Task/Job: Cron", PERS)),
    ("systemd_rc", r"/etc/systemd|systemctl\s+enable|/etc/rc\.local|/etc/init\.d|\.bashrc|\.bash_profile",
     "Linux boot/shell persistence", "persistence", 6,
     ("T1543.002", "Create or Modify System Process: Systemd Service", PERS)),
    ("ssh_keys", r"authorized_keys", "SSH authorized_keys access", "persistence", 6,
     ("T1098.004", "Account Manipulation: SSH Authorized Keys", PERS)),
    ("ld_preload", r"ld\.so\.preload|ld_preload", "LD_PRELOAD hijack", "evasion", 8,
     ("T1574.006", "Hijack Execution Flow: Dynamic Linker Hijacking", PERS)),

    # ---------------- Injection / native API ----------------
    ("api_remote_thread",
     r"\b(?:createremotethread(?:ex)?|ntcreatethreadex|rtlcreateuserthread|queueuserapc|"
     r"ntqueueapcthread(?:ex)?|setthreadcontext)\b",
     "Remote thread / APC injection API", "injection", 10, ("T1055", "Process Injection", PRIV)),
    ("api_write_proc",
     r"\b(?:writeprocessmemory|ntwritevirtualmemory|virtualallocex|ntallocatevirtualmemory)\b",
     "Cross-process memory write API", "injection", 10, ("T1055", "Process Injection", PRIV)),
    ("api_hollow", r"\b(?:ntunmapviewofsection|zwunmapviewofsection)\b", "Process hollowing API",
     "injection", 10, ("T1055.012", "Process Injection: Process Hollowing", PRIV)),
    ("api_virtualprotect", r"\b(?:virtualprotect(?:ex)?|ntprotectvirtualmemory)\b",
     "Memory protection change", "injection", 4, None),
    ("api_getproc", r"\bgetprocaddress\b", "Dynamic API resolution", "obfuscation", 2, None),
    ("api_loadlib", r"\bloadlibrary(?:a|w|exa|exw)?\b", "Dynamic library loading", "obfuscation", 1, None),
    ("api_openproc", r"\bopenprocess\b", "Open foreign process", "injection", 3, None),
    ("api_createproc",
     r"\bcreateprocess(?:a|w|asuser[aw]|internal[aw])?\b|\bwinexec\b|\bshellexecute(?:ex)?[aw]?\b",
     "Process creation API", "execution", 4, ("T1106", "Native API", EXEC)),
    ("api_download",
     r"\burldownloadtofile[aw]?\b|\binternetopenurl[aw]?\b|\binternetreadfile\b|"
     r"\bwinhttpsendrequest\b|\bhttpsendrequest[aw]?\b",
     "Network download API", "network", 6,
     ("T1071.001", "Application Layer Protocol: Web Protocols", C2)),
    ("api_sockets", r"\bwsastartup\b|\bwsasocket[aw]?\b|\bgethostbyname\b|\bgetaddrinfo\b",
     "Socket / DNS API", "network", 2, None),
    ("api_reg_set", r"\bregsetvalueex[aw]?\b|\bregcreatekeyex[aw]?\b", "Registry write API",
     "persistence", 3, ("T1112", "Modify Registry", EVAS)),
    ("token_priv",
     r"sedebugprivilege|\badjusttokenprivileges\b|impersonateloggedonuser|\bduplicatetokenex\b|"
     r"seimpersonateprivilege",
     "Token / privilege manipulation", "injection", 7,
     ("T1134", "Access Token Manipulation", PRIV)),
    ("proc_mem", r"/proc/self/(?:exe|maps|mem|fd)|/proc/\d+/mem", "Linux process-memory access",
     "injection", 5, ("T1055.009", "Process Injection: Proc Memory", PRIV)),

    # ---------------- Anti-analysis / evasion ----------------
    ("api_antidebug",
     r"\bisdebuggerpresent\b|\bcheckremotedebuggerpresent\b|\bntqueryinformationprocess\b|"
     r"\boutputdebugstring[aw]?\b|\bntsetinformationthread\b",
     "Debugger detection API", "anti_analysis", 6, ("T1622", "Debugger Evasion", EVAS)),
    ("vm_artifacts",
     r"vboxservice|vboxguest|vboxmouse|vmtoolsd|vmwaretray|vmware|virtualbox|\bqemu\b|sbiedll|"
     r"sandboxie|wine_get_unix_file_name",
     "Virtual machine / sandbox artifacts", "anti_analysis", 6,
     ("T1497.001", "Virtualization/Sandbox Evasion: System Checks", EVAS)),
    ("analysis_tools",
     r"wireshark|procmon|procexp|x64dbg|ollydbg|\bida(?:64)?\.exe|fiddler|processhacker|autoruns",
     "Analysis-tool process names", "anti_analysis", 6,
     ("T1057", "Process Discovery", DISC)),
    ("sandbox_words", r"\bcuckoo\b|\bany\.run\b|\bjoebox\b|\bsandbox\b", "Sandbox keywords",
     "anti_analysis", 3, ("T1497", "Virtualization/Sandbox Evasion", EVAS)),
    ("ptrace", r"\bptrace\b", "ptrace (anti-debug on Linux)", "anti_analysis", 4,
     ("T1622", "Debugger Evasion", EVAS)),
    ("av_disable",
     r"set-mppreference\s+-disable|disablerealtimemonitoring|add-mppreference\s+-exclusionpath|"
     r"\bsc(?:\.exe)?\s+(?:stop|config)\s+(?:windefend|wscsvc|sense)\b|"
     r"taskkill\s+/f\s+/im\s+(?:msmpeng|mbam|avp)|netsh\s+(?:advfirewall|firewall)\s+(?:set|add)",
     "Security tooling / firewall tampering", "evasion", 14,
     ("T1562.001", "Impair Defenses: Disable or Modify Tools", EVAS)),
    ("clear_logs",
     r"wevtutil(?:\.exe)?\s+cl\b|clear-eventlog|fsutil\s+usn\s+deletejournal|unset\s+histfile|"
     r"rm\s+-rf?\s+/var/log|\bhistory\s+-c\b",
     "Log / evidence clearing", "evasion", 10, ("T1070", "Indicator Removal", EVAS)),
    ("packer_names",
     r"themida|vmprotect|\.vmp[01]\b|enigma\s*protector|aspack|petite|mpress|pecompact|"
     r"confuserex|\.netreactor|eazfuscator|smartassembly|dotfuscator|obfuscar",
     "Known packer / protector name", "obfuscation", 8,
     ("T1027.002", "Obfuscated Files or Information: Software Packing", EVAS)),
    ("upx", r"\bupx!|this file is packed with the upx", "UPX packer", "obfuscation", 6,
     ("T1027.002", "Obfuscated Files or Information: Software Packing", EVAS)),

    # ---------------- Credential access / collection ----------------
    ("mimikatz", r"mimikatz|sekurlsa|kerberos::|lsadump::|logonpasswords|privilege::debug",
     "Mimikatz-style credential tooling", "credential_access", 16,
     ("T1003.001", "OS Credential Dumping: LSASS Memory", CRED)),
    ("lsass", r"\blsass(?:\.exe)?\b", "LSASS reference", "credential_access", 6,
     ("T1003.001", "OS Credential Dumping: LSASS Memory", CRED)),
    ("minidump", r"minidumpwritedump|comsvcs\.dll[^\n]{0,20}minidump", "Process memory dump API",
     "credential_access", 12, ("T1003.001", "OS Credential Dumping: LSASS Memory", CRED)),
    ("sam_dump", r"\bhklm\\sam\b|\bhklm\\security\b|ntds\.dit|reg(?:\.exe)?\s+save\s+hklm",
     "SAM / NTDS credential store access", "credential_access", 12,
     ("T1003.002", "OS Credential Dumping: Security Account Manager", CRED)),
    ("browser_creds",
     r"login data|logins\.json|key[34]\.db|cookies\.sqlite|\\google\\chrome\\user data|"
     r"\\mozilla\\firefox\\profiles|encrypted_key|\bcryptunprotectdata\b",
     "Browser credential stores", "credential_access", 10,
     ("T1555.003", "Credentials from Password Stores: Credentials from Web Browsers", CRED)),
    ("wallets", r"wallet\.dat|\\exodus\\|\\electrum\\|metamask|\\atomic\\", "Crypto-wallet files",
     "collection", 8, ("T1005", "Data from Local System", COLL)),
    ("keylog", r"\b(?:getasynckeystate|setwindowshookex[aw]?|getkeyboardstate)\b", "Keystroke capture API",
     "collection", 8, ("T1056.001", "Input Capture: Keylogging", COLL)),
    ("screen_cap", r"\b(?:bitblt|createcompatiblebitmap|getdesktopwindow)\b", "Screen capture API",
     "collection", 3, ("T1113", "Screen Capture", COLL)),
    ("clipboard", r"\b(?:getclipboarddata|openclipboard)\b", "Clipboard access", "collection", 3,
     ("T1115", "Clipboard Data", COLL)),
    ("webcam", r"capcreatecapturewindow|avicap32|waveinopen", "Webcam / microphone capture",
     "collection", 6, ("T1125", "Video Capture", COLL)),
    ("archive_data", r"\brar(?:\.exe)?\s+a\s+-hp|7z(?:\.exe)?\s+a\s+-p|\bcompress-archive\b",
     "Archiving of collected data", "collection", 5,
     ("T1560.001", "Archive Collected Data: Archive via Utility", COLL)),
    ("net_discovery",
     r"\bnet(?:\.exe)?\s+(?:user|group|localgroup|view|share|accounts)\b|\bwhoami\s*/(?:all|priv)|"
     r"\bnltest\b|\bsysteminfo\b|\bipconfig\s*/all|\bquser\b",
     "Host / account discovery commands", "collection", 4,
     ("T1082", "System Information Discovery", DISC)),
    ("av_discovery", r"antivirusproduct|root\\securitycenter2", "Security-product discovery",
     "collection", 5, ("T1518.001", "Software Discovery: Security Software Discovery", DISC)),

    # ---------------- C2 / exfil / lateral ----------------
    ("telegram_c2", r"api\.telegram\.org/bot", "Telegram bot API (C2/exfil)", "network", 12,
     ("T1102", "Web Service", C2)),
    ("discord_hook", r"discord(?:app)?\.com/api/webhooks", "Discord webhook (exfil)", "network", 12,
     ("T1567", "Exfiltration Over Web Service", EXFIL)),
    ("paste_hosting",
     r"pastebin\.com/raw|raw\.githubusercontent\.com|paste\.ee|transfer\.sh|anonfiles|gofile\.io|"
     r"\bfile\.io\b|0x0\.st|ngrok(?:-free)?\.(?:io|app)|trycloudflare\.com|duckdns\.org|"
     r"no-ip\.(?:org|com)|ddns\.net",
     "Paste / file host / dynamic-DNS service", "network", 8,
     ("T1102", "Web Service", C2)),
    ("tor_proxy", r"\b[a-z2-7]{16,56}\.onion\b|socks5h?://", "Tor / SOCKS proxy", "network", 8,
     ("T1090.003", "Proxy: Multi-hop Proxy", C2)),
    ("c2_framework",
     r"cobalt\s*strike|beacon\.(?:dll|exe)|meterpreter|metasploit|sliver|havoc|brute\s*ratel|"
     r"poshc2|reverse_tcp|reverse_https|\bstager\b",
     "Known C2 framework / payload name", "network", 14,
     ("T1071", "Application Layer Protocol", C2)),
    ("reverse_shell",
     r"/dev/tcp/|bash\s+-i\s+>&|\bnc(?:at)?\s+(?:-e|-c)\b|mkfifo\s+/tmp/|"
     r"python\s+-c\s+['\"]import\s+socket|pty\.spawn",
     "Reverse-shell pattern", "network", 14,
     ("T1059.004", "Command and Scripting Interpreter: Unix Shell", EXEC)),
    ("curl_pipe", r"(?:curl|wget)\s+[^\n|;&]{0,200}\|\s*(?:sudo\s+)?(?:ba)?sh\b",
     "Download piped to shell", "network", 12, ("T1105", "Ingress Tool Transfer", C2)),
    ("tmp_exec", r"chmod\s+(?:\+x|[0-7]*7[0-7]*)\s+/(?:tmp|dev/shm|var/tmp)|/dev/shm/",
     "Execution from temp / shared-memory path", "execution", 6,
     ("T1059.004", "Command and Scripting Interpreter: Unix Shell", EXEC)),
    ("lateral_smb", r"psexec|paexec|\\admin\$|\\ipc\$|wmiexec|smbexec|invoke-command|\bwinrm\b",
     "Lateral-movement tooling", "network", 8,
     ("T1021.002", "Remote Services: SMB/Windows Admin Shares", LAT)),

    # ---------------- Impact ----------------
    ("vss_delete",
     r"vssadmin(?:\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|"
     r"bcdedit[^\n]{0,40}(?:recoveryenabled\s+no|ignoreallfailures)|wbadmin\s+delete\s+(?:catalog|backup)",
     "Backup / shadow-copy destruction", "impact", 18,
     ("T1490", "Inhibit System Recovery", IMPACT)),
    ("ransom_note",
     r"your\s+files\s+(?:have\s+been|are)\s+(?:encrypted|locked)|decrypt(?:ion)?\s+(?:key|tool|instructions)|"
     r"how[_\s]to[_\s](?:decrypt|recover)|restore[-_ ]my[-_ ]files|"
     r"pay\s+(?:the\s+)?(?:ransom|btc|bitcoin|monero)|bitcoin\s+(?:address|wallet)",
     "Ransom-note language", "impact", 12, ("T1486", "Data Encrypted for Impact", IMPACT)),
    ("crypto_apis",
     r"\b(?:cryptencrypt|cryptgenkey|cryptderivekey|cryptacquirecontext[aw]?|bcryptencrypt|"
     r"bcryptgeneratesymmetrickey|chacha20|salsa20)\b",
     "Cryptographic API usage", "impact", 2, None),
    ("file_enum", r"\bfindfirstfile(?:ex)?[aw]?\b|\bfindnextfile[aw]?\b", "File enumeration API",
     "impact", 1, None),
    ("ext_list",
     r"\.(?:docx?|xlsx?|pptx?|pdf|jpe?g|png|sql|mdb|bak|psd|zip|rar)\b[^\n]{0,40}"
     r"\.(?:docx?|xlsx?|pptx?|pdf|jpe?g|png|sql|mdb|bak|psd|zip|rar)\b",
     "Target file-extension list", "impact", 3, ("T1083", "File and Directory Discovery", DISC)),
    ("miner",
     r"stratum\+(?:tcp|ssl)://|xmrig|cryptonight|randomx|minergate|nicehash|nanopool|--donate-level|"
     r"pool\.(?:minexmr|supportxmr)",
     "Cryptocurrency miner", "impact", 14, ("T1496", "Resource Hijacking", IMPACT)),
    ("ddos", r"\bsyn\s*flood|udp\s*flood|slowloris|http\s*flood|\bddos\b", "DoS capability",
     "impact", 8, ("T1498", "Network Denial of Service", IMPACT)),

    # ---------------- Document / initial access ----------------
    ("office_macro",
     r"\bautoopen\b|\bauto_open\b|\bdocument_open\b|\bworkbook_open\b|\bautoexec\b",
     "Office auto-execute macro", "execution", 8,
     ("T1204.002", "User Execution: Malicious File", INIT)),
    ("vba_exec", r"\bcallbyname\b|\bmacroexec\b|\bexecuteglobal\b", "VBA dynamic call", "execution", 4,
     ("T1059.005", "Command and Scripting Interpreter: Visual Basic", EXEC)),
    ("ole_object", r"\\objdata|\\objupdate|ole2link|equation\.3|\\objautlink",
     "Embedded OLE object / equation editor", "execution", 8,
     ("T1203", "Exploitation for Client Execution", EXEC)),
    ("dde", r"\bddeauto\b", "DDE auto-execute field", "execution", 8,
     ("T1559.002", "Inter-Process Communication: Dynamic Data Exchange", EXEC)),
]

# (id, required_ids, any_of_ids, min_any, title, bonus, category, attack)
COMBO_RULES = [
    ("combo_injection", {"api_write_proc", "api_remote_thread"}, set(), 0,
     "Classic remote-process-injection API pair", 8, "injection",
     ("T1055", "Process Injection", PRIV)),
    ("combo_dyn_api", {"api_getproc", "api_loadlib", "api_virtualprotect"}, set(), 0,
     "Dynamic API resolution + memory-permission change", 4, "obfuscation", None),
    ("combo_dropper", {"ps_cradle", "ps_iex"}, set(), 0,
     "Download-and-execute cradle", 8, "execution",
     ("T1059.001", "Command and Scripting Interpreter: PowerShell", EXEC)),
    ("combo_stealth_ps", set(), {"ps_enc", "ps_hidden", "ps_bypass", "ps_iex"}, 3,
     "Stealth PowerShell launch pattern", 8, "execution",
     ("T1059.001", "Command and Scripting Interpreter: PowerShell", EXEC)),
    ("combo_ransomware", set(), {"vss_delete", "ransom_note", "crypto_apis", "file_enum", "ext_list"}, 3,
     "Ransomware-like capability cluster", 15, "impact",
     ("T1486", "Data Encrypted for Impact", IMPACT)),
    ("combo_stealer", set(), {"browser_creds", "wallets", "telegram_c2", "discord_hook", "keylog"}, 2,
     "Information-stealer capability cluster", 10, "collection",
     ("T1555", "Credentials from Password Stores", CRED)),
    ("combo_persist", set(), {"reg_run", "schtasks", "startup_folder", "sc_create"}, 2,
     "Multiple persistence mechanisms", 5, "persistence", None),
    ("combo_macro_dropper", {"office_macro"},
     {"ps_exec", "wsh", "ps_cradle", "certutil", "cmd_c", "mshta"}, 1,
     "Macro that launches a shell / downloader", 10, "execution",
     ("T1204.002", "User Execution: Malicious File", INIT)),
    ("combo_lolbin", set(), {"mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "lolbin_misc", "wmi_exec"}, 3,
     "Multiple living-off-the-land binaries", 6, "execution",
     ("T1218", "System Binary Proxy Execution", EVAS)),
    ("combo_credential", set(), {"mimikatz", "lsass", "sam_dump", "minidump"}, 2,
     "Credential-dumping cluster", 8, "credential_access",
     ("T1003", "OS Credential Dumping", CRED)),
    ("combo_defense_evasion", set(), {"av_disable", "clear_logs", "ps_amsi", "uac_bypass"}, 2,
     "Defense-evasion cluster", 8, "evasion",
     ("T1562", "Impair Defenses", EVAS)),
]

# --------------------------- PE helper tables ---------------------------

PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".aspack": "ASPack", ".adata": "ASPack",
    ".themida": "Themida", ".winlice": "Themida", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
    ".vmp2": "VMProtect", ".petite": "Petite", ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    ".nsp0": "NsPack", ".nsp1": "NsPack", ".nsp2": "NsPack", ".enigma1": "Enigma",
    ".enigma2": "Enigma", ".perplex": "PESpin", ".boom": "The Boomerang", ".yp": "Y0da",
    ".packed": "Generic packer", "pec1": "PECompact", "pec2": "PECompact", ".rlpack": "RLPack",
    ".themida ": "Themida", "mew": "MEW", ".neolite": "NeoLite",
}

STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".rsrc", ".reloc", ".pdata", ".tls",
    ".crt", ".didat", ".gfids", ".xdata", ".cormeta", "code", "data", "bss", ".code", ".init",
    ".fini", ".eh_fram", ".sxdata", ".retplne", ".00cfg", ".detourc", ".detourd", "init", "page",
    ".buildid", ".mrdata", ".lib",
}

# Import-name categories shown in the PE panel.
IMPORT_GROUPS = {
    "Injection / memory": r"virtualalloc|virtualprotect|writeprocessmemory|createremotethread|"
                          r"ntunmapviewofsection|queueuserapc|setthreadcontext|ntwritevirtualmemory",
    "Process / execution": r"createprocess|shellexecute|winexec|openprocess|terminateprocess|createthread",
    "Network": r"internet|winhttp|urldownload|wsastartup|socket|connect|send|recv|gethostby|getaddrinfo|http",
    "Registry / persistence": r"reg(?:set|create|open)|createservice|startservice",
    "Anti-debug": r"isdebuggerpresent|checkremotedebugger|ntqueryinformationprocess|outputdebugstring",
    "Crypto": r"crypt|bcrypt|cert",
    "File system": r"createfile|writefile|readfile|deletefile|findfirstfile|movefile|copyfile",
    "Keyboard / screen": r"getasynckeystate|setwindowshook|getkeyboardstate|bitblt|getdc|getclipboard",
}

# --------------------------- IOC helper tables ---------------------------

COMMON_TLDS = {
    "com", "net", "org", "info", "biz", "io", "co", "us", "uk", "de", "ru", "cn", "jp", "fr", "br", "in",
    "it", "nl", "es", "au", "ca", "ch", "se", "no", "fi", "ua", "tr", "ir", "kr", "tw", "hk", "sg", "id",
    "vn", "th", "my", "ph", "mx", "ar", "cl", "za", "ng", "eg", "il", "sa", "ae", "xyz", "top", "site",
    "online", "club", "shop", "app", "dev", "cloud", "link", "live", "store", "tech", "pro", "icu", "tv",
    "me", "ws", "to", "su", "ly", "gg", "pw", "tk", "ml", "ga", "cf", "gq", "work", "click", "space",
    "fun", "vip", "bid", "loan", "date", "men", "win", "download", "stream", "review", "trade",
    "accountant", "science", "party", "gdn", "racing", "cricket", "faith", "edu", "gov", "mil", "int",
    "eu", "asia", "name", "mobi", "tel", "cat", "one", "rest", "host", "website", "press", "digital",
    "network", "systems", "solutions", "agency", "email", "center", "world", "today", "news", "life",
    "support", "pk", "bd", "lk", "np", "kz", "by", "ro", "cz", "gr", "hu", "pt", "at", "be", "dk", "ie",
    "onion",
}

BENIGN_DOMAIN_SUFFIXES = (
    "w3.org", "microsoft.com", "openxmlformats.org", "purl.org", "adobe.com", "digicert.com",
    "verisign.com", "symantec.com", "globalsign.com", "sectigo.com", "usertrust.com", "thawte.com",
    "windowsupdate.com", "mozilla.org", "apache.org", "python.org", "gnu.org", "example.com",
    "example.org", "example.net", "xmlsoap.org", "schemas.android.com", "oracle.com", "java.com",
    "sun.com", "msocsp.com", "windows.com", "office.com", "live.com", "bing.com", "msftncsi.com",
    "godaddy.com", "entrust.net", "comodoca.com", "letsencrypt.org", "mozilla.com", "khronos.org",
    "unicode.org", "iana.org", "ietf.org", "xmlns.com", "dublincore.org", "ocsp.digicert.com",
)

EMAIL_RE_PATTERN = r"\b[A-Za-z0-9._%+-]{2,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}\b"

DOUBLE_EXT_RE = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|zip|mp3|mp4|csv|odt)\s*\.(?:exe|scr|com|bat|cmd|vbs|"
    r"vbe|js|jse|hta|ps1|lnk|jar|msi|dll|pif|wsf)$", re.I)

# extension -> kinds of content that are legitimate for it
EXPECTED_KINDS = {
    ".pdf": {"pdf"}, ".doc": {"ole"}, ".xls": {"ole"}, ".ppt": {"ole"},
    ".docx": {"ooxml"}, ".xlsx": {"ooxml"}, ".pptx": {"ooxml"}, ".docm": {"ooxml"},
    ".xlsm": {"ooxml"}, ".jpg": {"image"}, ".jpeg": {"image"}, ".png": {"image"}, ".gif": {"image"},
    ".exe": {"pe"}, ".dll": {"pe"}, ".scr": {"pe"}, ".sys": {"pe"}, ".ocx": {"pe"},
    ".zip": {"zip", "ooxml", "jar", "apk"}, ".lnk": {"lnk"}, ".rtf": {"rtf"},
    ".txt": {"text", "script"},
}

RISKY_ARCHIVE_MEMBER_EXT = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".hta", ".ps1", ".lnk",
    ".jar", ".msi", ".iso", ".img", ".wsf", ".com", ".pif", ".cpl", ".reg", ".sct", ".chm",
}

ATTACK_NAMES = {}
for _r in CAPABILITY_RULES:
    if _r[5]:
        ATTACK_NAMES[_r[5][0]] = (_r[5][1], _r[5][2])
for _c in COMBO_RULES:
    if _c[7]:
        ATTACK_NAMES.setdefault(_c[7][0], (_c[7][1], _c[7][2]))
for _tid, _name, _tac in [
    ("T1036.002", "Masquerading: Right-to-Left Override", EVAS),
    ("T1036.007", "Masquerading: Double File Extension", EVAS),
    ("T1036.008", "Masquerading: Masquerade File Type", EVAS),
    ("T1027.009", "Obfuscated Files or Information: Embedded Payloads", EVAS),
    ("T1027.013", "Obfuscated Files or Information: Encrypted/Encoded File", EVAS),
    ("T1221", "Template Injection", EVAS),
    ("T1187", "Forced Authentication", CRED),
    ("T1059.007", "Command and Scripting Interpreter: JavaScript", EXEC),
    ("T1204.002", "User Execution: Malicious File", INIT),
    ("T1027", "Obfuscated Files or Information", EVAS),
    ("T1622", "Debugger Evasion", EVAS),
]:
    ATTACK_NAMES.setdefault(_tid, (_name, _tac))
