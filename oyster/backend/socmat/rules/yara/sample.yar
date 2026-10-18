/*
   Sample YARA rules for SOC Copilot Workbench — static triage only.
   These are educational examples for a defensive SOC workbench.
   Files are NEVER executed. All analysis is static.
*/

rule PowerShell_Encoded_Command
{
    meta:
        description = "Detects PowerShell with encoded command arguments — commonly used to obfuscate malicious execution"
        author = "SOC Copilot Workbench"
        severity = "high"
        mitre = "T1059.001, T1027"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
    strings:
        $ps  = "powershell" nocase
        $e1  = "-EncodedCommand" nocase
        $e2  = " -enc " nocase
        $e3  = " -e " nocase
        $e4  = "-noprofile" nocase
        $e5  = "-windowstyle hidden" nocase
    condition:
        $ps and (1 of ($e1, $e2, $e3) or (2 of ($e4, $e5)))
}

rule Suspicious_LOLBAS_Usage
{
    meta:
        description = "Detects references to Living-off-the-Land binaries commonly abused by attackers for execution and defense evasion"
        author = "SOC Copilot Workbench"
        severity = "medium"
        mitre = "T1218"
        reference = "https://lolbas-project.github.io/"
    strings:
        $s1 = "rundll32" nocase
        $s2 = "regsvr32" nocase
        $s3 = "mshta" nocase
        $s4 = "wscript" nocase
        $s5 = "certutil" nocase
        $s6 = "cscript" nocase
    condition:
        any of them
}

rule Persistence_Registry_Run_Keys
{
    meta:
        description = "Detects common registry Run key paths used for persistence"
        author = "SOC Copilot Workbench"
        severity = "medium"
        mitre = "T1547.001"
        reference = "https://attack.mitre.org/techniques/T1547/001/"
    strings:
        $r1 = "CurrentVersion\\Run" nocase
        $r2 = "CurrentVersion\\RunOnce" nocase
        $r3 = "Winlogon\\Shell" nocase
        $r4 = "\\Start Menu\\Programs\\Startup" nocase
    condition:
        any of them
}

rule Windows_PE_Executable
{
    meta:
        description = "Detects a Windows PE (portable executable) file — review origin and legitimacy"
        author = "SOC Copilot Workbench"
        severity = "informational"
        mitre = "T1204.002"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
    strings:
        $mz       = { 4D 5A }
        $dos_stub = "This program cannot be run in DOS mode"
    condition:
        $mz at 0 and $dos_stub
}

rule Suspicious_Delivery_Infrastructure
{
    meta:
        description = "Detects references to infrastructure commonly used in malware delivery and C2"
        author = "SOC Copilot Workbench"
        severity = "medium"
        mitre = "T1102, T1105"
        reference = "https://attack.mitre.org/techniques/T1105/"
    strings:
        $pastebin    = "pastebin.com" nocase
        $raw_github  = "raw.githubusercontent.com" nocase
        $ngrok       = ".ngrok.io" nocase
        $transfer_sh = "transfer.sh" nocase
        $tor_onion   = ".onion" nocase
    condition:
        any of them
}
