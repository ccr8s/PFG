"""
FileGuard knowledge base.

Beginner-friendly descriptions of ATT&CK techniques, tactics,
and step-by-step remediation guides written in plain language.
"""

from typing import Dict, Optional


# ── ATT&CK Technique Descriptions (plain language) ─────────────

TECHNIQUE_INFO: Dict[str, Dict[str, str]] = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "what": (
            "An attacker is using a built-in tool on your computer "
            "(like PowerShell or Command Prompt) to run harmful commands. "
            "Think of it like a burglar using your own keys to unlock your doors."
        ),
        "danger": "High",
        "fix": (
            "1. Open Task Manager (Ctrl+Shift+Esc) and look for anything "
            "unusual running.\n"
            "2. If you see a suspicious PowerShell or CMD window you didn't "
            "open, right-click it and choose 'End Task'.\n"
            "3. Run a full antivirus scan.\n"
            "4. If you're unsure, disconnect from the internet (unplug the "
            "cable or turn off WiFi) and ask for help."
        ),
    },
    "T1059.001": {
        "name": "PowerShell",
        "what": (
            "PowerShell is a powerful tool built into Windows that can do "
            "almost anything on your computer. Attackers love it because "
            "it's already installed and trusted by the system. It's like "
            "someone using your TV remote to change all your settings "
            "without you knowing."
        ),
        "danger": "High",
        "fix": (
            "1. Open Task Manager (Ctrl+Shift+Esc).\n"
            "2. Look for 'powershell.exe' processes you didn't start.\n"
            "3. End any suspicious PowerShell processes.\n"
            "4. Run a full antivirus scan immediately.\n"
            "5. Check your Startup programs (Task Manager > Startup tab) "
            "and disable anything you don't recognize.\n"
            "6. Consider temporarily disabling PowerShell scripts:\n"
            "   - Open PowerShell as Admin\n"
            "   - Type: Set-ExecutionPolicy Restricted\n"
            "7. If the file came from email or a download, delete it."
        ),
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "what": (
            "The attacker is using the old-school Command Prompt (the black "
            "window with white text) to run harmful commands. It's like "
            "someone typing secret instructions into your computer."
        ),
        "danger": "Medium-High",
        "fix": (
            "1. Close any Command Prompt windows you didn't open.\n"
            "2. Check Task Manager for 'cmd.exe' processes.\n"
            "3. Run a full antivirus scan.\n"
            "4. Check your scheduled tasks (search 'Task Scheduler' in "
            "Start menu) for anything suspicious."
        ),
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "what": (
            "Something on your computer is downloading files from the "
            "internet without you asking. It's like someone secretly "
            "ordering packages to your house that you never wanted."
        ),
        "danger": "High",
        "fix": (
            "1. Disconnect from the internet RIGHT NOW (unplug cable or "
            "turn off WiFi).\n"
            "2. This stops the download from finishing.\n"
            "3. Run a full antivirus scan while offline.\n"
            "4. Check your Downloads folder for files you didn't download.\n"
            "5. Delete anything suspicious.\n"
            "6. Only reconnect to internet after the scan is clean."
        ),
    },
    "T1140": {
        "name": "Deobfuscate/Decode Files",
        "what": (
            "A file is trying to unscramble hidden code, like reading a "
            "secret message written in invisible ink. Attackers hide their "
            "malware in scrambled form so antivirus can't easily spot it."
        ),
        "danger": "Medium-High",
        "fix": (
            "1. Don't open or run the suspicious file.\n"
            "2. Run a full antivirus scan.\n"
            "3. Delete the suspicious file.\n"
            "4. If the file was an email attachment, delete the email too.\n"
            "5. Empty your Recycle Bin."
        ),
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "what": (
            "Someone has deliberately scrambled a file to hide what it "
            "really does. Normal programs don't need to do this. It's "
            "like someone wearing a disguise -- they're hiding something."
        ),
        "danger": "Medium-High",
        "fix": (
            "1. Do NOT open or run the file.\n"
            "2. Run a full antivirus scan.\n"
            "3. Quarantine or delete the file.\n"
            "4. Check if the file came from a download or email and "
            "remove the source too."
        ),
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "what": (
            "An attacker is trying to steal all the usernames and passwords "
            "stored on your computer. It's like someone photocopying every "
            "key on your keyring."
        ),
        "danger": "CRITICAL",
        "fix": (
            "1. Disconnect from the internet IMMEDIATELY.\n"
            "2. This is very serious -- your passwords may be stolen.\n"
            "3. On another device, change your important passwords:\n"
            "   - Email password\n"
            "   - Bank passwords\n"
            "   - Social media passwords\n"
            "4. Run a full antivirus scan.\n"
            "5. Consider getting professional help (IT support).\n"
            "6. Enable two-factor authentication on all accounts."
        ),
    },
    "T1003.001": {
        "name": "LSASS Memory (Password Stealing)",
        "what": (
            "A tool like Mimikatz is trying to read passwords directly "
            "from your computer's memory. LSASS is where Windows keeps "
            "your login info while you're using the computer. This is "
            "like someone reading your diary while it's open on your desk."
        ),
        "danger": "CRITICAL",
        "fix": (
            "1. Disconnect from the internet IMMEDIATELY.\n"
            "2. Your passwords are likely compromised.\n"
            "3. From a DIFFERENT device, change ALL passwords:\n"
            "   - Email, bank, social media, work accounts\n"
            "4. Call your IT support if this is a work computer.\n"
            "5. Run a full antivirus scan.\n"
            "6. Enable two-factor authentication everywhere.\n"
            "7. Consider reinstalling Windows for full safety."
        ),
    },
    "T1055": {
        "name": "Process Injection",
        "what": (
            "Malware is hiding inside a normal program, like a parasite "
            "inside a healthy animal. It injects its bad code into a "
            "program you trust so it can run without being noticed."
        ),
        "danger": "High",
        "fix": (
            "1. Restart your computer in Safe Mode:\n"
            "   - Hold Shift while clicking Restart\n"
            "   - Choose Troubleshoot > Advanced > Startup Settings\n"
            "2. Run a full antivirus scan in Safe Mode.\n"
            "3. This is more effective because malware can't hide as well "
            "in Safe Mode."
        ),
    },
    "T1486": {
        "name": "Data Encrypted for Impact (Ransomware)",
        "what": (
            "This is RANSOMWARE. It locks up your files by encrypting them "
            "(scrambling them with a secret code) so you can't open them. "
            "Then it demands money to unlock them. It's like someone "
            "changing all the locks in your house and selling you the keys."
        ),
        "danger": "CRITICAL",
        "fix": (
            "1. DISCONNECT FROM INTERNET AND NETWORK IMMEDIATELY.\n"
            "   - Unplug ethernet cable\n"
            "   - Turn off WiFi\n"
            "   - This stops it from spreading to other computers\n"
            "2. DO NOT PAY THE RANSOM -- there's no guarantee you'll "
            "get your files back.\n"
            "3. DO NOT turn off the computer (evidence may be lost).\n"
            "4. Take a photo of any ransom message on screen.\n"
            "5. If this is a work computer, call IT support NOW.\n"
            "6. Check if you have backups (external drive, cloud).\n"
            "7. Report to authorities:\n"
            "   - FBI IC3: ic3.gov\n"
            "   - CISA: cisa.gov/report\n"
            "8. Check nomoreransom.org -- free decryption tools may exist "
            "for your specific ransomware."
        ),
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "what": (
            "The attacker is deleting your computer's backup copies "
            "(called Shadow Copies). It's like a burglar cutting the "
            "phone line so you can't call for help. They do this so "
            "you can't recover your files after ransomware."
        ),
        "danger": "CRITICAL",
        "fix": (
            "1. This usually happens WITH ransomware.\n"
            "2. Follow all ransomware steps above.\n"
            "3. If you catch it early, your external backups may still "
            "be safe -- but disconnect the backup drive NOW.\n"
            "4. Do NOT connect backup drives to an infected computer."
        ),
    },
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "what": (
            "Something has added itself to start automatically every time "
            "you turn on your computer. It's like someone sneaking an extra "
            "app onto your phone that opens every time you unlock it."
        ),
        "danger": "Medium-High",
        "fix": (
            "1. Open Task Manager (Ctrl+Shift+Esc).\n"
            "2. Click the 'Startup' tab.\n"
            "3. Look for anything you don't recognize.\n"
            "4. Right-click suspicious items and choose 'Disable'.\n"
            "5. Run a full antivirus scan.\n"
            "6. Check the Startup folder:\n"
            "   - Press Win+R, type: shell:startup\n"
            "   - Delete anything suspicious there."
        ),
    },
    "T1547.004": {
        "name": "Winlogon Helper DLL",
        "what": (
            "Malware has inserted itself into Windows' login process. "
            "Every time anyone logs in, the malware runs too. It's like "
            "someone rigging your front door so an alarm (but a bad one) "
            "goes off every time you open it."
        ),
        "danger": "High",
        "fix": (
            "1. This is advanced malware -- consider getting professional help.\n"
            "2. Run a full antivirus scan in Safe Mode.\n"
            "3. If the scan doesn't fix it, you may need to reinstall Windows."
        ),
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "what": (
            "The attacker created a scheduled task -- like setting an alarm "
            "clock for malware. At a certain time or event, the bad program "
            "will run automatically."
        ),
        "danger": "Medium-High",
        "fix": (
            "1. Search 'Task Scheduler' in the Start menu and open it.\n"
            "2. Look through the list for tasks you don't recognize.\n"
            "3. Check what program each task runs (look at the 'Actions' tab).\n"
            "4. Delete any suspicious tasks.\n"
            "5. Run a full antivirus scan."
        ),
    },
    "T1070.001": {
        "name": "Clear Windows Event Logs",
        "what": (
            "Someone is erasing the computer's diary (event logs). Windows "
            "keeps a record of everything that happens, and the attacker "
            "is deleting it to cover their tracks. It's like a thief "
            "wiping fingerprints off everything they touched."
        ),
        "danger": "High",
        "fix": (
            "1. This means someone was (or is) doing something bad and "
            "trying to hide it.\n"
            "2. Disconnect from the internet.\n"
            "3. Run a full antivirus scan.\n"
            "4. If this is a work computer, report to IT immediately.\n"
            "5. The cleared logs themselves are evidence of tampering."
        ),
    },
    "T1070.006": {
        "name": "Timestomp",
        "what": (
            "Someone changed the dates on files to make them look older or "
            "newer than they really are. It's like changing the date stamp "
            "on a photo to pretend it was taken years ago."
        ),
        "danger": "Medium",
        "fix": (
            "1. This is a sign someone is hiding when files were created.\n"
            "2. Run a full antivirus scan.\n"
            "3. The files with changed dates are suspicious -- don't open them.\n"
            "4. Report to IT if this is a work computer."
        ),
    },
    "T1564.001": {
        "name": "Hidden Files and Directories",
        "what": (
            "Files are being hidden so you can't see them in File Explorer. "
            "It's like someone hiding things under your bed -- they're "
            "still there, you just can't see them."
        ),
        "danger": "Medium",
        "fix": (
            "1. Show hidden files in File Explorer:\n"
            "   - Click 'View' tab at the top\n"
            "   - Check 'Hidden items'\n"
            "2. Look for files or folders you don't recognize.\n"
            "3. Run a full antivirus scan.\n"
            "4. Don't delete system hidden files (they're normal)."
        ),
    },
    "T1564.004": {
        "name": "NTFS Alternate Data Streams",
        "what": (
            "Data is being hidden inside other files using a special "
            "Windows trick called Alternate Data Streams. It's like "
            "hiding a secret note inside the spine of a book -- you'd "
            "never know it's there unless you look carefully."
        ),
        "danger": "Medium-High",
        "fix": (
            "1. Run a full antivirus scan.\n"
            "2. The file containing the hidden data should be quarantined.\n"
            "3. This is a sneaky technique -- if you see it, take it seriously."
        ),
    },
    "T1555": {
        "name": "Credentials from Password Stores",
        "what": (
            "A tool is trying to steal saved passwords from your browser, "
            "Windows credential manager, or password vaults. It's like "
            "someone breaking into a safe where you keep all your keys."
        ),
        "danger": "CRITICAL",
        "fix": (
            "1. Disconnect from the internet.\n"
            "2. Change ALL your saved passwords from a different device.\n"
            "3. Start with: email, bank, and any financial accounts.\n"
            "4. Enable two-factor authentication on everything.\n"
            "5. Run a full antivirus scan.\n"
            "6. Consider using a password manager going forward."
        ),
    },
    "T1558": {
        "name": "Steal or Forge Kerberos Tickets",
        "what": (
            "An attacker is forging VIP passes (Kerberos tickets) to "
            "access network resources they shouldn't. This is an advanced "
            "attack mostly seen on work/corporate networks."
        ),
        "danger": "CRITICAL",
        "fix": (
            "1. Report to your IT/security team IMMEDIATELY.\n"
            "2. This is an advanced attack that needs professional response.\n"
            "3. Disconnect the affected computer from the network.\n"
            "4. Do not try to fix this yourself."
        ),
    },
    "T1087.002": {
        "name": "Domain Account Discovery",
        "what": (
            "Someone is looking up all the user accounts on your network. "
            "It's like a burglar checking which apartments are in a "
            "building before deciding which one to rob."
        ),
        "danger": "Medium",
        "fix": (
            "1. If this is a work computer, report to IT.\n"
            "2. This is usually a sign of a bigger attack in progress.\n"
            "3. Run a full antivirus scan.\n"
            "4. Monitor for other suspicious activity."
        ),
    },
    "T1047": {
        "name": "Windows Management Instrumentation (WMI)",
        "what": (
            "An attacker is using WMI, a powerful Windows management tool, "
            "to run commands remotely or gather information about your "
            "system. It's like someone using the building's maintenance "
            "access to get into any room."
        ),
        "danger": "High",
        "fix": (
            "1. Run a full antivirus scan.\n"
            "2. Check Task Manager for suspicious processes.\n"
            "3. If on a network, alert IT support.\n"
            "4. Consider disabling WMI if not needed (advanced users)."
        ),
    },
    "T1197": {
        "name": "BITS Jobs",
        "what": (
            "The attacker is using Windows' built-in download service "
            "(BITS) to secretly download malware. BITS normally handles "
            "Windows Updates, so this activity blends in. It's like a "
            "thief hiding stolen goods in a delivery truck."
        ),
        "danger": "Medium-High",
        "fix": (
            "1. Open Command Prompt as Admin.\n"
            "2. Type: bitsadmin /list /allusers\n"
            "3. Look for jobs you don't recognize.\n"
            "4. Cancel suspicious jobs: bitsadmin /cancel [jobname]\n"
            "5. Run a full antivirus scan."
        ),
    },
    "T1218.005": {
        "name": "Mshta (Living off the Land)",
        "what": (
            "An attacker is using mshta.exe, a legitimate Windows program, "
            "to run malicious scripts. It's called 'Living off the Land' "
            "because they use tools already on your computer instead of "
            "bringing their own."
        ),
        "danger": "High",
        "fix": (
            "1. End any mshta.exe processes in Task Manager.\n"
            "2. Run a full antivirus scan.\n"
            "3. Check what triggered mshta -- usually a malicious document "
            "or link.\n"
            "4. Delete the source file/email."
        ),
    },
    "T1569.002": {
        "name": "Service Execution",
        "what": (
            "An attacker installed a malicious Windows service -- a program "
            "that runs in the background. It's like someone hiring a "
            "fake janitor who has keys to everything."
        ),
        "danger": "High",
        "fix": (
            "1. Open Services (search 'services.msc' in Start).\n"
            "2. Look for services you don't recognize.\n"
            "3. Right-click suspicious ones > Properties > Stop.\n"
            "4. Set them to 'Disabled'.\n"
            "5. Run a full antivirus scan."
        ),
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "what": (
            "Someone is using network file sharing to move between "
            "computers on your network. It's like someone using the "
            "connecting doors between hotel rooms to get into rooms "
            "they shouldn't be in."
        ),
        "danger": "High",
        "fix": (
            "1. Disconnect the affected computer from the network.\n"
            "2. Alert IT support -- this affects the whole network.\n"
            "3. Change the local admin password.\n"
            "4. This is a sign the attacker is already inside your network."
        ),
    },
    "T1204": {
        "name": "User Execution",
        "what": (
            "This file matched a known malware hash -- it's a file that "
            "has been identified as malicious before. It's like finding "
            "something on a 'Most Wanted' list."
        ),
        "danger": "CRITICAL",
        "fix": (
            "1. Do NOT open or run this file.\n"
            "2. Delete it immediately.\n"
            "3. Empty the Recycle Bin.\n"
            "4. Run a full antivirus scan.\n"
            "5. If you already opened it, disconnect from internet and "
            "run a full scan."
        ),
    },
}

# ── Tactic Descriptions ────────────────────────────────────────

TACTIC_INFO: Dict[str, Dict[str, str]] = {
    "Execution": {
        "what": (
            "The attacker is running (executing) malicious code on your "
            "computer. This is the step where they actually DO the bad thing."
        ),
    },
    "Persistence": {
        "what": (
            "The attacker is making sure their malware survives reboots "
            "and stays on your computer permanently, like a weed that "
            "keeps growing back."
        ),
    },
    "Defense Evasion": {
        "what": (
            "The attacker is trying to hide from antivirus and security "
            "tools. They're wearing a disguise so your computer's "
            "defenses don't notice them."
        ),
    },
    "Credential Access": {
        "what": (
            "The attacker is trying to steal passwords and login info. "
            "This is very dangerous because they can use your identity "
            "to access your accounts."
        ),
    },
    "Discovery": {
        "what": (
            "The attacker is looking around your computer and network to "
            "figure out what's there. They're like a burglar casing a "
            "house before the robbery."
        ),
    },
    "Lateral Movement": {
        "what": (
            "The attacker is moving from one computer to another on your "
            "network. Once they get into one machine, they try to spread "
            "to others."
        ),
    },
    "Impact": {
        "what": (
            "The attacker is doing damage -- encrypting files (ransomware), "
            "deleting data, or disrupting services. This is the worst-case "
            "scenario stage."
        ),
    },
    "Command and Control": {
        "what": (
            "Your computer is secretly communicating with the attacker's "
            "server, receiving instructions like a spy receiving orders "
            "from headquarters."
        ),
    },
    "Resource Development": {
        "what": (
            "The attacker is setting up the tools and infrastructure "
            "they need for their attack, like a burglar buying lockpicks "
            "before a heist."
        ),
    },
}


def get_technique_info(technique_id: str) -> Optional[Dict[str, str]]:
    """Look up beginner-friendly info for an ATT&CK technique."""
    return TECHNIQUE_INFO.get(technique_id)


def get_tactic_info(tactic_name: str) -> Optional[Dict[str, str]]:
    """Look up beginner-friendly info for an ATT&CK tactic."""
    return TACTIC_INFO.get(tactic_name)
