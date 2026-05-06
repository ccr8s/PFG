# FileGuard Detection Patterns Database
# Add to: config/signatures.yaml

# =============================================================================
# POWERSHELL SUSPICIOUS PATTERNS
# =============================================================================
powershell:
  critical:
    - pattern: "-enc"
      description: "Encoded command execution"
      score: 40
    - pattern: "-encodedcommand"
      description: "Encoded command execution"
      score: 40
    - pattern: "frombase64string"
      description: "Base64 decoding (common obfuscation)"
      score: 35
    - pattern: "invoke-expression"
      description: "Dynamic code execution"
      score: 45
    - pattern: "iex("
      description: "Dynamic code execution (alias)"
      score: 45
    - pattern: "downloadstring"
      description: "Remote code download"
      score: 50
    - pattern: "downloadfile"
      description: "Remote file download"
      score: 45
    - pattern: "invoke-webrequest"
      description: "Web request (potential download)"
      score: 30
    - pattern: "start-bitstransfer"
      description: "BITS transfer (evasion technique)"
      score: 40
    - pattern: "reflection.assembly"
      description: "Reflective loading"
      score: 50
    - pattern: "[system.net.webclient]"
      description: "Web client instantiation"
      score: 35
    - pattern: "bypass"
      description: "Execution policy bypass"
      score: 35
    - pattern: "-nop"
      description: "No profile (evasion)"
      score: 25
    - pattern: "-w hidden"
      description: "Hidden window"
      score: 40
    - pattern: "-windowstyle hidden"
      description: "Hidden window"
      score: 40
    - pattern: "invoke-mimikatz"
      description: "Mimikatz execution"
      score: 95
    - pattern: "invoke-shellcode"
      description: "Shellcode injection"
      score: 90
    - pattern: "get-keystrokes"
      description: "Keylogger"
      score: 85
    - pattern: "invoke-dllinjection"
      description: "DLL injection"
      score: 85

# =============================================================================
# CMD / BATCH SUSPICIOUS PATTERNS
# =============================================================================
cmd_batch:
  critical:
    - pattern: "certutil -decode"
      description: "CertUtil abuse for decoding"
      score: 50
    - pattern: "certutil -urlcache"
      description: "CertUtil abuse for download"
      score: 55
    - pattern: "bitsadmin /transfer"
      description: "BITS transfer"
      score: 45
    - pattern: "mshta vbscript"
      description: "MSHTA script execution"
      score: 60
    - pattern: "mshta javascript"
      description: "MSHTA script execution"
      score: 60
    - pattern: "regsvr32 /s /n /u"
      description: "Regsvr32 proxy execution"
      score: 55
    - pattern: "rundll32 javascript"
      description: "Rundll32 script execution"
      score: 60
    - pattern: "wmic process call create"
      description: "WMIC process creation"
      score: 50
    - pattern: "wmic /node:"
      description: "WMIC lateral movement"
      score: 65
    - pattern: "psexec"
      description: "PsExec remote execution"
      score: 55
    - pattern: "net user /add"
      description: "User creation"
      score: 45
    - pattern: "net localgroup administrators"
      description: "Admin group modification"
      score: 55
    - pattern: "schtasks /create"
      description: "Scheduled task creation"
      score: 40
    - pattern: "reg add.*\\run"
      description: "Registry run key modification"
      score: 50
    - pattern: "vssadmin delete shadows"
      description: "Shadow copy deletion (ransomware)"
      score: 90
    - pattern: "wbadmin delete"
      description: "Backup deletion (ransomware)"
      score: 85
    - pattern: "bcdedit /set.*recoveryenabled no"
      description: "Recovery disabled (ransomware)"
      score: 85

# =============================================================================
# MALWARE TOOL NAMES
# =============================================================================
tool_names:
  critical:
    - pattern: "mimikatz"
      description: "Credential dumping tool"
      score: 95
    - pattern: "lazagne"
      description: "Password recovery tool"
      score: 85
    - pattern: "bloodhound"
      description: "AD reconnaissance tool"
      score: 75
    - pattern: "sharphound"
      description: "BloodHound collector"
      score: 75
    - pattern: "rubeus"
      description: "Kerberos attack tool"
      score: 90
    - pattern: "covenant"
      description: "C2 framework"
      score: 90
    - pattern: "cobalt"
      description: "Cobalt Strike"
      score: 95
    - pattern: "beacon"
      description: "C2 beacon"
      score: 85
    - pattern: "meterpreter"
      description: "Metasploit payload"
      score: 95
    - pattern: "empire"
      description: "PowerShell Empire"
      score: 85
    - pattern: "powercat"
      description: "PowerShell netcat"
      score: 70
    - pattern: "nishang"
      description: "PowerShell attack framework"
      score: 80
    - pattern: "crackmapexec"
      description: "Network attack tool"
      score: 85
    - pattern: "impacket"
      description: "Network protocol attacks"
      score: 75
    - pattern: "secretsdump"
      description: "Credential dumping"
      score: 90
    - pattern: "procdump"
      description: "Process dumper (lsass targeting)"
      score: 60
    - pattern: "nanodump"
      description: "LSASS dumper"
      score: 90

# =============================================================================
# SUSPICIOUS FILE EXTENSIONS
# =============================================================================
suspicious_extensions:
  high_risk:
    - ext: ".scr"
      description: "Screensaver (often malware)"
      score: 35
    - ext: ".pif"
      description: "Program Information File"
      score: 40
    - ext: ".hta"
      description: "HTML Application"
      score: 45
    - ext: ".vbs"
      description: "VBScript"
      score: 30
    - ext: ".vbe"
      description: "Encoded VBScript"
      score: 40
    - ext: ".jse"
      description: "Encoded JScript"
      score: 40
    - ext: ".wsf"
      description: "Windows Script File"
      score: 35
    - ext: ".wsh"
      description: "Windows Script Host"
      score: 35
    - ext: ".ps1"
      description: "PowerShell Script"
      score: 25
    - ext: ".psm1"
      description: "PowerShell Module"
      score: 25
    - ext: ".psd1"
      description: "PowerShell Data"
      score: 20
    - ext: ".jar"
      description: "Java Archive"
      score: 20
    - ext: ".bat"
      description: "Batch file"
      score: 20
    - ext: ".cmd"
      description: "Command script"
      score: 20
    - ext: ".lnk"
      description: "Shortcut (can hide commands)"
      score: 25

# =============================================================================
# DOUBLE EXTENSIONS (DECEPTION)
# =============================================================================
double_extensions:
  patterns:
    - pattern: ".pdf.exe"
      score: 60
    - pattern: ".doc.exe"
      score: 60
    - pattern: ".docx.exe"
      score: 60
    - pattern: ".jpg.exe"
      score: 60
    - pattern: ".png.exe"
      score: 60
    - pattern: ".txt.exe"
      score: 55
    - pattern: ".mp3.exe"
      score: 55
    - pattern: ".pdf.scr"
      score: 65
    - pattern: ".doc.scr"
      score: 65
    - pattern: ".xlsx.exe"
      score: 60

# =============================================================================
# SUSPICIOUS LOCATIONS (Windows)
# =============================================================================
suspicious_locations:
  critical:
    - path: "\\AppData\\Local\\Temp"
      description: "User temp folder"
      score_modifier: 15
    - path: "\\Windows\\Temp"
      description: "System temp folder"
      score_modifier: 20
    - path: "\\Startup"
      description: "Startup folder"
      score_modifier: 25
    - path: "\\Start Menu\\Programs\\Startup"
      description: "All users startup"
      score_modifier: 25
    - path: "\\ProgramData"
      description: "Hidden ProgramData"
      score_modifier: 10
    - path: "\\Downloads"
      description: "Downloads folder"
      score_modifier: 10
    - path: "\\Recycle.Bin"
      description: "Recycle bin hiding"
      score_modifier: 30
    - path: "\\$Recycle.Bin"
      description: "Recycle bin hiding"
      score_modifier: 30

# =============================================================================
# C2 / NETWORK INDICATORS
# =============================================================================
network_indicators:
  patterns:
    - pattern: "socket.connect"
      description: "Raw socket connection"
      score: 25
    - pattern: "reverse_tcp"
      description: "Reverse shell"
      score: 80
    - pattern: "bind_tcp"
      description: "Bind shell"
      score: 75
    - pattern: "/c2/"
      description: "C2 path indicator"
      score: 50
    - pattern: "beacon_interval"
      description: "C2 beacon config"
      score: 70
    - pattern: "user-agent.*mozilla"
      description: "Hardcoded user agent"
      score: 20

# =============================================================================
# RANSOMWARE INDICATORS
# =============================================================================
ransomware:
  critical:
    - pattern: "your files have been encrypted"
      description: "Ransom note text"
      score: 95
    - pattern: "bitcoin"
      description: "Cryptocurrency reference"
      score: 15
    - pattern: "decrypt"
      description: "Decryption reference"
      score: 10
    - pattern: ".onion"
      description: "Tor address"
      score: 40
    - pattern: "cryptolocker"
      description: "Ransomware family"
      score: 95
    - pattern: "wannacry"
      description: "Ransomware family"
      score: 95
    - pattern: "AES256"
      description: "Encryption indicator"
      score: 10

# =============================================================================
# PERSISTENCE MECHANISMS
# =============================================================================
persistence:
  registry_keys:
    - key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
      description: "System startup"
      score: 30
    - key: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
      description: "User startup"
      score: 30
    - key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
      description: "One-time startup"
      score: 35
    - key: "HKLM\\SYSTEM\\CurrentControlSet\\Services"
      description: "Service creation"
      score: 35
    - key: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
      description: "Winlogon hooks"
      score: 45
    - key: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
      description: "IFEO hijack"
      score: 60

# =============================================================================
# EVENT LOG TAMPERING INDICATORS
# =============================================================================
event_log_tampering:
  event_ids:
    - id: 1102
      log: "Security"
      description: "Audit log cleared"
      score: 90
    - id: 104
      log: "System"
      description: "System log cleared"
      score: 85
    - id: 1100
      log: "Security"
      description: "Event logging service shutdown"
      score: 70
  
  anomalies:
    - type: "gap_in_sequence"
      description: "Missing sequential event IDs"
      score: 60
    - type: "future_timestamp"
      description: "Events with future timestamps"
      score: 80
    - type: "size_mismatch"
      description: "Log file size doesn't match content"
      score: 70

# =============================================================================
# TIMESTOMPING INDICATORS
# =============================================================================
timestomping:
  indicators:
    - type: "mft_mismatch"
      description: "$STANDARD_INFO != $FILE_NAME timestamps"
      score: 75
    - type: "impossible_date"
      description: "Date before file format existed"
      score: 85
    - type: "round_timestamp"
      description: "Exactly midnight/noon timestamps"
      score: 40
    - type: "mass_same_time"
      description: "Many files with identical timestamps"
      score: 65

# =============================================================================
# LOLBINS (Living Off the Land Binaries)
# =============================================================================
lolbins:
  binaries:
    - name: "certutil.exe"
      suspicious_args: ["-decode", "-urlcache", "-split"]
      score: 50
    - name: "mshta.exe"
      suspicious_args: ["vbscript", "javascript", "http"]
      score: 60
    - name: "regsvr32.exe"
      suspicious_args: ["/s", "/n", "/u", "/i:http"]
      score: 55
    - name: "rundll32.exe"
      suspicious_args: ["javascript", "vbscript"]
      score: 55
    - name: "msiexec.exe"
      suspicious_args: ["/q", "http://", "https://"]
      score: 45
    - name: "installutil.exe"
      suspicious_args: ["/logfile=", "/logtoconsole=false"]
      score: 60
    - name: "regasm.exe"
      suspicious_args: ["/u"]
      score: 55
    - name: "regsvcs.exe"
      suspicious_args: []
      score: 50
    - name: "msbuild.exe"
      suspicious_args: []
      score: 50
    - name: "cmstp.exe"
      suspicious_args: ["/s", "/ni"]
      score: 65
    - name: "wmic.exe"
      suspicious_args: ["process call create", "/node:"]
      score: 55
    - name: "forfiles.exe"
      suspicious_args: ["/c"]
      score: 40
    - name: "pcalua.exe"
      suspicious_args: ["-a"]
      score: 50
    - name: "syncappvpublishingserver.exe"
      suspicious_args: []
      score: 55

# =============================================================================
# PE FILE ANOMALIES
# =============================================================================
pe_anomalies:
  indicators:
    - type: "no_imports"
      description: "PE file with no imports"
      score: 45
    - type: "suspicious_section"
      description: "Section name like UPX, .nsp, etc."
      score: 35
    - type: "entry_outside_section"
      description: "Entry point outside any section"
      score: 60
    - type: "high_entropy_section"
      description: "Section with entropy > 7.5"
      score: 40
    - type: "multiple_executable_sections"
      description: "More than 2 executable sections"
      score: 30
    - type: "checksum_mismatch"
      description: "PE checksum doesn't match"
      score: 25
    - type: "truncated_headers"
      description: "Malformed PE headers"
      score: 50

# =============================================================================
# LANGUAGE KEYWORDS (Multi-language suspicious strings)
# =============================================================================
multilang_keywords:
  # Chinese
  chinese:
    - "密码"        # password
    - "木马"        # trojan
    - "后门"        # backdoor
    - "远程控制"    # remote control
  
  # Russian
  russian:
    - "пароль"      # password
    - "троян"       # trojan
    - "бэкдор"      # backdoor
    - "взлом"       # hack
  
  # Spanish
  spanish:
    - "contraseña"  # password
    - "troyano"     # trojan
  
  # Common across languages
  universal:
    - "keylog"
    - "stealer"
    - "logger"
    - "dump"
    - "inject"
    - "hook"
    - "payload"
    - "shellcode"
    - "exploit"