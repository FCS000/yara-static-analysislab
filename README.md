# YARA Static Analysis Lab

A small, self-contained lab demonstrating static detection of suspicious file
patterns using [YARA](https://virustotal.github.io/yara/), the pattern-matching
engine widely used in malware analysis and threat hunting.

All samples in this repository are **safe and non-functional** — they either use
the industry-standard EICAR test string or contain benign scripts written purely
to demonstrate detection logic. Nothing in this repo will execute a real payload.

## Why this project

Static signature matching with YARA is a foundational skill in defensive
cybersecurity — used in incident response, malware triage, and threat hunting.
This lab was built to practice writing YARA rules from scratch, understand how
detection logic is structured, and verify that each rule catches what it should
**without** flagging benign files (false positives).

## Rules

### 1. `EICAR_Test_Detection`
Detects the standard EICAR antivirus test string. Used as a safe way to confirm
a detection pipeline is working, without any real malicious code involved.

### 2. `Suspicious_PowerShell_Download_Execute`
Flags PowerShell scripts that combine an execution command (`IEX` /
`Invoke-Expression`) with a remote download call (`Net.WebClient.DownloadString`).
Neither pattern alone is necessarily malicious — legitimate scripts use both
independently — but the **combination** is a well-known signature of fileless
malware, where code is downloaded and run directly in memory without touching disk.

### 3. `Tiny_Suspicious_Downloader`
Flags very small script files (under 200 bytes) containing a download-and-save
pattern (`Invoke-WebRequest` / `iwr` + `-OutFile`). Small file size is sometimes
used deliberately to evade detection tools that rely on more complex heuristics.
This rule shows how YARA conditions can combine file metadata (`filesize`) with
string matching, not just strings alone.

## Testing methodology

Every rule was tested against both:
- A **positive sample** — a file expected to match
- A **negative / benign sample** — a similar-looking file expected NOT to match

This confirms each rule detects the intended pattern without over-triggering.

| Rule | Sample | Result |
|---|---|---|
| `EICAR_Test_Detection` | `eicar_test.txt` | ✅ Match |
| `Suspicious_PowerShell_Download_Execute` | `suspicious_script.ps1` | ✅ Match |
| `Suspicious_PowerShell_Download_Execute` | `benign_script.ps1` | ✅ No match (expected) |
| `Tiny_Suspicious_Downloader` | `tiny_downloader.ps1` | ✅ Match |
| `Tiny_Suspicious_Downloader` | `large_script_with_same_command.ps1` | ✅ No match (expected) |

## How to run it yourself

```bash
git clone <your-repo-url>
cd yara-lab
for f in samples/*; do
  echo "--- $f ---"
  yara rules/*.yar "$f"
done
```

## What I learned

- How YARA rules are structured (`meta`, `strings`, `condition`) and why the
  `meta` section matters for documentation and attribution in real detection
  pipelines.
- Why single indicators are usually weak on their own, and how combining
  conditions (`and`/`or`, `filesize`) reduces false positives.
- The importance of testing detection rules against both malicious-looking
  *and* benign samples — a rule that only "detects" isn't useful if it also
  fires constantly on legitimate files.
- How evasion techniques (like keeping a script very small) can be accounted
  for directly in detection logic.

## Environment

- YARA 4.5.0
- Ubuntu (WSL2)

---

*This project is for educational purposes as part of my transition into
defensive cybersecurity. All samples are safe and were created specifically
for this lab.*
