# config.py

# Suspicious Parent → Child mappings
SUSPICIOUS_PARENT_CHILD = {
    "winword.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
    "excel.exe": ["cmd.exe", "powershell.exe"],
    "outlook.exe": ["cmd.exe", "powershell.exe"],
    "chrome.exe": ["cmd.exe"],
    "explorer.exe": ["powershell.exe"]
}
