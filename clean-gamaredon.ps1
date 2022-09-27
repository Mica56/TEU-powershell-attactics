﻿# T1053.005
Unregister-ScheduledTask -TaskName "AtomicTaskModifed" -confirm:$false >$null 2>&1
Stop-Process -Name  "notepad"
Remove-Item "$env:TEMP\T1053.005-macrocode.txt" -ErrorAction Ignore

# T1112
# try { Set-ExecutionPolicy -ExecutionPolicy Default -Scope LocalMachine -Force } catch {}
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -Force -ErrorAction Ignore
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLinkedConnections -Force -ErrorAction Ignore
Remove-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name LongPathsEnabled -Force -ErrorAction Ignore

#T1059
del "%TEMP%\test.bin" >$null 2>&1
Remove-Item $env:TEMP\T1059.005.out.txt -ErrorAction Ignore
Remove-Item $env:TEMP\sys_info.vbs -ErrorAction Ignore
Remove-Item "$env:TEMP\atomic_t1059_005_test_output.bin" -ErrorAction Ignore
Remove-Item "$env:TEMP\T1059_005-macrocode.txt" -ErrorAction Ignore

#T1106
Stop-Process -Name  "calculator"
Remove-Item "$env:TEMP\CreateProcess.cs" -ErrorAction Ignore
Remove-Item "%tmp%/T1106.exe" -ErrorAction Ignore