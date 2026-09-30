rule Tiny_Suspicious_Downloader
{
    meta:
        description = "Flags very small script files containing a download/invoke pattern — small size can indicate an attempt to evade signature-heavy detection"
        author = "Furkan Can Sume"
        date = "2026-09-30"

    strings:
        $iwr = "iwr" nocase
        $invoke_webrequest = "Invoke-WebRequest" nocase
        $outfile = "-OutFile" nocase

    condition:
        filesize < 200 and ($iwr or $invoke_webrequest) and $outfile
}
