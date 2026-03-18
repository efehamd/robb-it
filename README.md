# Robb-IT Security

Terminal-based cybersecurity tool for Windows. Scans for malware, monitors network traffic, blocks connections, and bypasses DPI — all from your terminal.

## Install

Open PowerShell and paste:

```powershell
$d="$env:LOCALAPPDATA\RobbIT";md $d -f>$null;irm https://github.com/efehamd/robb-it/releases/latest/download/RobbIT.exe -o "$d\robbit.exe";$env:PATH+=";$d";[Environment]::SetEnvironmentVariable("PATH",$env:PATH,"User");robbit
```

After install, launch anytime with:

```
robbit
```

> Run as Administrator for full functionality.

---

## Features

- **Full System Scan** — processes, startup, scheduled tasks, WMI, hosts file
- **Directory Scan** — scan any folder for threats
- **Live Traffic Monitor** — real-time connection tracking with threat alerts
- **Block Connections** — block/unblock IPs via Windows Firewall
- **DPI Bypass** — encrypted DNS (1.1.1.1 DoH) + TLS fragmentation proxy, no external tools needed
- **File Hash** — MD5, SHA1, SHA256 + entropy analysis
- **Report Export** — save scan results to Desktop

---

## Requirements

- Windows 10 / 11
- PowerShell (built-in)
- Administrator rights recommended
