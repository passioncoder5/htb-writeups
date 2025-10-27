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

####Also you can use dirbuster


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

<style> body { background-color: #0a0a0a; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; } .container { max-width: 1200px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; } h1, h2, h3 { color: #00ff00; border-bottom: 2px solid #333; padding-bottom: 10px; } h1 { text-align: center; color: #00ff00; font-size: 2.5em; margin-bottom: 30px; } .header-section { text-align: center; margin-bottom: 40px; padding: 20px; background: #151515; border-radius: 8px; border-left: 4px solid #00ff00; } .difficulty-badge { display: inline-block; padding: 5px 15px; background: #ffa500; color: #000; border-radius: 20px; font-weight: bold; margin: 10px 0; } .severity-badge { display: inline-block; padding: 5px 15px; background: #ff4444; color: #fff; border-radius: 20px; font-weight: bold; margin-left: 10px; } .tech-tag { background: #333; color: #00ff00; padding: 4px 12px; border-radius: 15px; font-size: 0.9em; margin: 5px 5px 5px 0; display: inline-block; border: 1px solid #00ff00; } pre { background: #000000; border: 1px solid #333; border-left: 4px solid #00ff00; padding: 15px; overflow-x: auto; margin: 20px 0; border-radius: 5px; color: #ffffff; } code { color: #ffffff; background: #000000; padding: 2px 6px; border-radius: 3px; } .image-container { text-align: center; margin: 20px 0; padding: 10px; background: #151515; border-radius: 8px; border: 1px solid #333; } .image-container img { max-width: 100%; height: auto; border: 1px solid #444; border-radius: 5px; } .vulnerability-list { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #ff4444; margin: 20px 0; } .vulnerability-list li { margin: 10px 0; padding-left: 10px; } .attack-chain { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; margin: 20px 0; } .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; } .tool-item { background: #151515; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; } .tool-item:hover { border-color: #00ff00; transform: translateY(-2px); transition: all 0.3s ease; } /* Scrollbar Styling */ ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: #1a1a1a; } ::-webkit-scrollbar-thumb { background: #00ff00; border-radius: 4px; } ::-webkit-scrollbar-thumb:hover { background: #00cc00; } /* Responsive Design */ @media (max-width: 768px) { .container { padding: 15px; margin: 10px; } h1 { font-size: 2em; } .tools-grid { grid-template-columns: 1fr; } } /* Animation for headers */ h2, h3 { position: relative; } h2::after, h3::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 0; height: 2px; background: #00ff00; transition: width 0.3s ease; } h2:hover::after, h3:hover::after { width: 100%; } </style>
