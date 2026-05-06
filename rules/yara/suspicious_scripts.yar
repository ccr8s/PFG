/*
    FileGuard - Suspicious Script Detection Rules
    Detects obfuscated, encoded, and malicious scripts.
*/

import "math"

rule PowerShell_Download_Execute
{
    meta:
        description = "PowerShell download and execute pattern"
        severity = 80
        attack_technique = "T1059.001,T1105"
        attack_tactic = "Execution,Command and Control"
        confidence = "high"
        author = "FileGuard"

    strings:
        $dl1 = "DownloadString" ascii wide nocase
        $dl2 = "DownloadFile" ascii wide nocase
        $dl3 = "DownloadData" ascii wide nocase
        $dl4 = "Invoke-WebRequest" ascii wide nocase
        $dl5 = "Start-BitsTransfer" ascii wide nocase
        $dl6 = "Net.WebClient" ascii wide nocase
        $ex1 = "Invoke-Expression" ascii wide nocase
        $ex2 = "IEX(" ascii wide nocase
        $ex3 = "IEX (" ascii wide nocase

    condition:
        any of ($dl*) and any of ($ex*)
}

rule PowerShell_Encoded_Command
{
    meta:
        description = "PowerShell encoded command execution"
        severity = 60
        attack_technique = "T1059.001,T1027"
        attack_tactic = "Execution,Defense Evasion"
        confidence = "medium"
        author = "FileGuard"

    strings:
        $ps = "powershell" ascii wide nocase
        $enc1 = "-enc " ascii wide nocase
        $enc2 = "-encodedcommand " ascii wide nocase
        $enc3 = "-ec " ascii wide nocase
        $hidden = "-windowstyle hidden" ascii wide nocase
        $nop = "-nop" ascii wide nocase
        $bypass = "bypass" ascii wide nocase

    condition:
        $ps and (any of ($enc*)) and ($hidden or $nop or $bypass)
}

rule PowerShell_Reflective_Loading
{
    meta:
        description = "PowerShell reflective assembly loading"
        severity = 75
        attack_technique = "T1059.001,T1620"
        attack_tactic = "Execution,Defense Evasion"
        confidence = "medium"
        author = "FileGuard"

    strings:
        $s1 = "Reflection.Assembly" ascii wide nocase
        $s2 = "[System.Reflection.Assembly]::Load" ascii wide nocase
        $s3 = "LoadWithPartialName" ascii wide nocase
        $s4 = "FromBase64String" ascii wide nocase
        $s5 = "[Convert]::FromBase64String" ascii wide nocase

    condition:
        2 of them
}

rule LOLBin_CertUtil_Abuse
{
    meta:
        description = "CertUtil LOLBin abuse for download or decode"
        severity = 55
        attack_technique = "T1140,T1105"
        attack_tactic = "Defense Evasion,Command and Control"
        confidence = "high"
        author = "FileGuard"

    strings:
        $certutil = "certutil" ascii wide nocase
        $decode = "-decode" ascii wide nocase
        $urlcache = "-urlcache" ascii wide nocase
        $split = "-split" ascii wide nocase
        $http = "http" ascii wide nocase

    condition:
        $certutil and ($decode or ($urlcache and ($split or $http)))
}

rule LOLBin_MSHTA_Abuse
{
    meta:
        description = "MSHTA LOLBin abuse for script execution"
        severity = 60
        attack_technique = "T1218.005"
        attack_tactic = "Defense Evasion"
        confidence = "high"
        author = "FileGuard"

    strings:
        $mshta = "mshta" ascii wide nocase
        $vbs = "vbscript" ascii wide nocase
        $js = "javascript" ascii wide nocase
        $http = "http://" ascii wide nocase
        $https = "https://" ascii wide nocase

    condition:
        $mshta and ($vbs or $js or $http or $https)
}

rule LOLBin_Regsvr32_Abuse
{
    meta:
        description = "Regsvr32 LOLBin proxy execution"
        severity = 55
        attack_technique = "T1218.010"
        attack_tactic = "Defense Evasion"
        confidence = "medium"
        author = "FileGuard"

    strings:
        $regsvr = "regsvr32" ascii wide nocase
        $s = "/s" ascii wide nocase
        $n = "/n" ascii wide nocase
        $u = "/u" ascii wide nocase
        $i_http = "/i:http" ascii wide nocase

    condition:
        $regsvr and (($s and $n and $u) or $i_http)
}

rule Base64_Encoded_PE
{
    meta:
        description = "Base64 encoded PE file detected in script"
        severity = 65
        attack_technique = "T1027,T1140"
        attack_tactic = "Defense Evasion"
        confidence = "medium"
        author = "FileGuard"

    strings:
        $b64_mz = "TVqQAAMAAAAEAAAA" ascii wide  // Base64 of MZ header

    condition:
        $b64_mz
}

rule VBScript_Shell_Execution
{
    meta:
        description = "VBScript executing shell commands"
        severity = 50
        attack_technique = "T1059.005"
        attack_tactic = "Execution"
        confidence = "medium"
        author = "FileGuard"

    strings:
        $wsh1 = "WScript.Shell" ascii wide nocase
        $wsh2 = "Wscript.CreateObject" ascii wide nocase
        $run1 = ".Run " ascii wide
        $run2 = ".Exec " ascii wide
        $cmd = "cmd" ascii wide nocase
        $ps = "powershell" ascii wide nocase

    condition:
        (any of ($wsh*)) and (any of ($run*)) and ($cmd or $ps)
}

rule Batch_Persistence_Install
{
    meta:
        description = "Batch script installing persistence mechanism"
        severity = 55
        attack_technique = "T1547.001,T1053.005"
        attack_tactic = "Persistence"
        confidence = "medium"
        author = "FileGuard"

    strings:
        $reg1 = "reg add" ascii wide nocase
        $reg2 = "CurrentVersion\\Run" ascii wide nocase
        $schtask = "schtasks /create" ascii wide nocase
        $startup = "Startup" ascii wide nocase
        $copy = "copy " ascii wide nocase

    condition:
        ($reg1 and $reg2) or $schtask or ($copy and $startup)
}

rule High_Entropy_Script
{
    meta:
        description = "Script file with unusually high entropy (obfuscated)"
        severity = 40
        attack_technique = "T1027"
        attack_tactic = "Defense Evasion"
        confidence = "low"
        author = "FileGuard"

    condition:
        filesize < 1MB and
        math.entropy(0, filesize) > 6.5
}
