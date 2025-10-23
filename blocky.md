# Blocky HTB Writeup

## Reconnaissance

### Initial Enumeration

The penetration testing began with network reconnaissance to identify open ports and services.

```bash
export target=10.129.48.128
```

<img width="486" height="105" alt="image" src="https://github.com/user-attachments/assets/bf85c074-44b4-4342-b167-ab5085ea5b18" />

#### Comprehensive Port Scan
```bash
sudo nmap -p- --min-rate 5000 -sT -vvv $target
```

<img width="791" height="951" alt="image" src="https://github.com/user-attachments/assets/69278595-a225-4e3d-8805-41faa1778c17" />

#### Targeted Service Enumeration
```bash
sudo nmap -p 21,22,80,25565 -sC -sV -T4 $target
```

<img width="841" height="392" alt="image" src="https://github.com/user-attachments/assets/8099989c-e815-4e88-9fbc-b9d6f4ced3ea" />

### DNS Configuration
Added the hostname to the local hosts file for proper web application testing:
```bash
echo "10.129.48.128 blocky.htb" | sudo tee -a /etc/hosts
```

<img width="577" height="235" alt="image" src="https://github.com/user-attachments/assets/ab54012c-9890-495d-b549-ab716f6fa9ae" />


## Web Application Assessment

### Directory Bruteforcing
Conducted comprehensive directory enumeration using Gobuster:
```bash
gobuster dir -u http://blocky.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html -t 100 -b "302"
```
Also you can use dirbuster
<img width="770" height="563" alt="image" src="https://github.com/user-attachments/assets/c43cec07-7abb-438e-9de9-e0ccc240a5c3" />
<img width="770" height="563" alt="image" src="https://github.com/user-attachments/assets/62cee60e-eb34-4759-b6e2-18efa3d1f720" />

### Critical Discovery
The `/plugins/` directory was identified as particularly interesting, containing Java archive files:
- `BlockyCore.jar`
- `griefprevention-1.12.2-4.3.0.660.jar`

<img width="1251" height="488" alt="image" src="https://github.com/user-attachments/assets/3082d560-6211-4f20-b317-e9dc12cc9204" />


### Source Code Analysis
Using **jadx-gui**, the `BlockyCore.jar` file was decompiled, revealing hardcoded database credentials:

<img width="1046" height="508" alt="image" src="https://github.com/user-attachments/assets/958b8ef7-d441-4cb7-9237-3fcc5180f6a5" />


**Credentials Found:**
- **Username:** `root`
- **Password:** `8YsqfCTnvxAUeduzjNSXe22`

### User Enumeration
Additional reconnaissance uncovered potential usernames:
- Visiting `http://blocky.htb/index.php/author/notch/` revealed user "notch"
- Source code analysis confirmed both "notch" and "root" as valid users

## Initial Access

### Credential Validation
Verified SSH credentials using CrackMapExec:
```bash
crackmapexec ssh 10.129.48.128 -u users.txt -p pass.txt
```

<img width="954" height="483" alt="image" src="https://github.com/user-attachments/assets/36883438-1cf1-4229-a43e-375178651fc2" />


### Successful Authentication
Gained initial access via SSH using discovered credentials:
```bash
ssh notch@10.129.48.174
```

<img width="963" height="492" alt="image" src="https://github.com/user-attachments/assets/e7f1281c-f400-4463-afcc-482c4372a0e4" />


## Privilege Escalation

### Privilege Assessment
Checked sudo permissions for the notch user:
```bash
sudo -l
```

<img width="946" height="267" alt="image" src="https://github.com/user-attachments/assets/84511c44-cb3b-47fd-8586-6af73813c652" />


### Root Access Acquisition
The notch user had extensive sudo privileges, allowing direct elevation to root:
```bash
sudo su
```

<img width="739" height="698" alt="image" src="https://github.com/user-attachments/assets/b9766075-04a1-49f9-adec-efb9284932dc" />

## Post-Exploitation

### Flag Extraction

**User Flag:**
```bash
cat /home/notch/user.txt
83d32e43c1d7bdb805813bc15394c761
```

**Root Flag:**
```bash
cat /root/root.txt
97f70114622d2f0ec00963ed1caa998b
```

## Security Assessment Summary

### Critical Vulnerabilities Identified

1. **Information Disclosure**
   - Hardcoded credentials in compiled Java binaries
   - Directory listing enabled on web server

2. **Weak Access Controls**
   - Excessive sudo privileges for standard user accounts
   - Reuse of database credentials for system authentication

3. **Poor Credential Management**
   - Plaintext passwords in application binaries
   - Password reuse across different services

### Remediation Recommendations

1. **Implement Secure Coding Practices**
   - Remove hardcoded credentials from application code
   - Use secure credential storage solutions

2. **Enforce Principle of Least Privilege**
   - Review and restrict sudo permissions
   - Implement role-based access control

3. **Enhance System Hardening**
   - Disable directory listing on web servers
   - Implement regular security audits
   - Use credential rotation policies

## Technical Details

### Attack Chain
1. Network reconnaissance → 2. Web directory enumeration → 3. Source code analysis → 4. Credential discovery → 5. SSH authentication → 6. Privilege escalation

### Tools Utilized
- **Nmap**: Network scanning and service enumeration
- **Gobuster**: Web directory bruteforcing
- **JADX**: Java decompilation and static analysis
- **CrackMapExec**: Credential validation
- **SSH**: Remote access

<div align="center">
  
**Penetration Testing Report** | **Blocky HTB** | **High Severity**
  
</div>
