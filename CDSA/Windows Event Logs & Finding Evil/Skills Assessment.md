1:
By examining the logs located in the “C:\Logs\DLLHijack” directory, determine the process responsible for executing a DLL hijacking attack. Enter the process name as your answer. Answer format: _.exe
Get-WinEvent -Path 'C:\Logs\DLLHijack\*' | Where-Object{$_.ID -like "7"} | Where-Object{$_.Message -like "*signed: false*"} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message

2:
By examining the logs located in the “C:\Logs\PowershellExec” directory, determine the process that executed unmanaged PowerShell code. Enter the process name as your answer. Answer format: _.exe
Get-WinEvent -Path 'C:\Logs\PowershellExec\*' | Where-Object{$_.ID -like "7"} | Where-Object{$_.Message -like "*clr.dll*"} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message

3:
By examining the logs located in the “C:\Logs\PowershellExec” directory, determine the process that injected into the process that executed unmanaged PowerShell code. Enter the process name as your answer. Answer format: _.exe
Get-WinEvent -Path 'C:\Logs\PowershellExec\*' | Where-Object{$_.ID -like "8"} | Where-Object{$_.Message -like "*Calculator.exe*"} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message

4:
By examining the logs located in the “C:\Logs\Dump” directory, determine the process that performed an LSASS dump. Enter the process name as your answer. Answer format: _.exe
Get-WinEvent -Path 'C:\Logs\Dump\*' | Where-Object{$_.ID -like "10"} | Where-Object{$_.Message -like "*TargetImage*lsass.exe*"} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message

5:
By examining the logs located in the “C:\Logs\Dump” directory, determine if an ill-intended login took place after the LSASS dump. Answer format: Yes or No
No
Get-WinEvent -Path 'C:\Logs\dump\*' | Where-Object{$_.Id -like "4624"} | Where-Object{$_.TimeCreated -gt (get-date "4/27/2022 7:08:47 PM")} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message


6:
By examining the logs located in the “C:\Logs\StrangePPID” directory, determine a process that was used to temporarily execute code based on a strange parent-child relationship. Enter the process name as your answer. Answer format: _.exe
Get-WinEvent -Path 'C:\Logs\StrangePPID\*' | Where-Object{$_.ID -like "1"} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message
