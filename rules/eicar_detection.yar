
rule EICAR_Test_Detection
{
    meta:
        description = "Detects the EICAR standard antivirus test file"
        author = "Furkan Can Sume"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
        date = "2026-09-30"

    strings:
        $eicar_string = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    condition:
        $eicar_string
}
