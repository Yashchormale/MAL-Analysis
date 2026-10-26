/*
  MAL v4 default rules - generic, defensive, intentionally conservative.
  Add your own .yar files to this folder; MAL loads every *.yar / *.yara here automatically.
*/

rule MAL_PowerShell_Download_Cradle
{
    meta: description = "PowerShell download-and-execute cradle"
    strings:
        $dl  = /downloadstring|downloadfile|invoke-webrequest|net\.webclient|start-bitstransfer/ nocase
        $ex  = /invoke-expression|\biex\b/ nocase
        $enc = /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{20,}/ nocase
        $hid = /-w(indowstyle)?\s+hidden/ nocase
    condition:
        ($dl and $ex) or (2 of ($enc, $hid, $dl))
}

rule MAL_PE_Embedded_In_NonPE
{
    meta: description = "DOS-stub text inside a file that is not itself a PE (embedded/dropped executable)"
    strings:
        $stub = "This program cannot be run in DOS mode"
    condition:
        uint16(0) != 0x5A4D and $stub
}

rule MAL_Process_Injection_APIs
{
    meta: description = "PE referencing the classic remote-injection API set"
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
        $d = "NtUnmapViewOfSection"
        $e = "QueueUserAPC"
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule MAL_Ransom_Note_Language
{
    meta: description = "Ransom-note style language plus backup destruction"
    strings:
        $n1 = /your (files|data) (have been|are) (encrypted|locked)/ nocase
        $n2 = /how to (decrypt|recover|restore)/ nocase
        $n3 = /(pay|payment)[^\n]{0,30}(bitcoin|btc|monero)/ nocase
        $v1 = /vssadmin(\.exe)?\s+delete\s+shadows/ nocase
        $v2 = /wbadmin\s+delete\s+(catalog|backup)/ nocase
    condition:
        (2 of ($n*)) or (1 of ($n*) and 1 of ($v*))
}

rule MAL_PDF_Script_Launch
{
    meta: description = "PDF with JavaScript plus automatic action or launch"
    strings:
        $js = /\/(JavaScript|JS)\b/
        $oa = /\/(OpenAction|AA|Launch)\b/
    condition:
        uint32(0) == 0x46445025 and $js and $oa
}

rule MAL_Linux_Reverse_Shell
{
    meta: description = "Common reverse-shell one-liners"
    strings:
        $a = "/dev/tcp/"
        $b = "bash -i"
        $c = /nc(at)?\s+-e\s/
        $d = "pty.spawn"
        $e = "mkfifo /tmp/"
    condition:
        ($a and $b) or $c or $d or $e
}

rule MAL_UPX_Packed_PE
{
    meta: description = "PE with UPX section names"
    strings:
        $u0 = "UPX0"
        $u1 = "UPX1"
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule MAL_HTA_Shell_Launcher
{
    meta: description = "HTA application that creates a shell object"
    strings:
        $h = "<hta:application" nocase
        $s = /wscript\.shell|shell\.application|createobject/ nocase
    condition:
        $h and $s
}
