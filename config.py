# config.py

# -----------------------------------
# Suspicious Parent → Child Rules
# -----------------------------------
SUSPICIOUS_PARENT_CHILD = {
    "winword.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
    "excel.exe": ["cmd.exe", "powershell.exe"],
    "outlook.exe": ["cmd.exe", "powershell.exe"],
    "explorer.exe": ["powershell.exe"],  # Added comma here ✅
    "chrome.exe": ["cmd.exe"],  # browser spawning shell = suspicious
}

# -----------------------------------
# Suspicious Processes (LOLBins)
# -----------------------------------
SUSPICIOUS_CHILD_PROCESSES = [
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe"
]

# -----------------------------------
# Safe Processes (to reduce false positives)
# -----------------------------------
SAFE_CHILD_PROCESSES = [
    "chrome.exe",
    "msedge.exe",
    "explorer.exe",
    "onedrive.exe",
    "ms-teams.exe",
    "onenotem.exe",
    "securityhealthsystray.exe",
    "rtkauduservice64.exe",
    "git-bash.exe"
]
