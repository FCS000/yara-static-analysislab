rule Suspicious_PowerShell_Download_Execute
{
    meta:
        description = "Flags PowerShell scripts combining download and in-memory execution (IEX + WebClient), a common fileless-malware pattern"
        author = "Furkan Can Sume"
        date = "2026-09-30"

    strings:
        $iex = "IEX" nocase
        $invoke_expression = "Invoke-Expression" nocase
        $download = "DownloadString" nocase
        $webclient = "Net.WebClient" nocase

    condition:
        ($iex or $invoke_expression) and $download and $webclient
}
