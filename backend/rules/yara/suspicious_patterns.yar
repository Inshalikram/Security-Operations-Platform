rule Suspicious_PowerShell_Encoded_Command
{
    meta:
        description = "Detects base64-encoded PowerShell commands, common in malware droppers"
        severity = "high"
        mitre_technique = "T1059.001"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $powershell = "powershell" nocase
    condition:
        $powershell and ($enc1 or $enc2)
}

rule Suspicious_Reverse_Shell_Strings
{
    meta:
        description = "Detects common reverse shell indicator strings"
        severity = "critical"
        mitre_technique = "T1059"
    strings:
        $rs1 = "/bin/bash -i" nocase
        $rs2 = "nc -e" nocase
        $rs3 = "socket.socket(" nocase
        $rs4 = "Invoke-Expression" nocase
    condition:
        any of them
}

rule Suspicious_Ransomware_Note_Keywords
{
    meta:
        description = "Detects common ransomware note language"
        severity = "critical"
        mitre_technique = "T1486"
    strings:
        $r1 = "your files have been encrypted" nocase
        $r2 = "bitcoin" nocase
        $r3 = "decrypt" nocase
        $r4 = "pay within" nocase
    condition:
        2 of them
}

rule Suspicious_Executable_PE_Header_Anomaly
{
    meta:
        description = "Flags PE files with suspiciously small section count (packer indicator)"
        severity = "medium"
    condition:
        uint16(0) == 0x5A4D  // MZ header
}