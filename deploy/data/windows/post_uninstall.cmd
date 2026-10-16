rem AVPN: Tribe names. Upstream removed AmneziaVPN-service, its tunnel and its logs - that is the
rem original Amnezia VPN app (installed side by side), while our Tribe-service stayed registered and
rem running. Ours: Tribe-service (SERVICE_NAME), AmneziaWGTunnel$TribeVPN (TUNNEL_SERVICE_NAME),
rem logs under APPLICATION_NAME=AVPN / ORGANIZATION_NAME=AVPN.ORG (version.h.in, Logger).
set TribePath=%~dp0
echo %TribePath%

rem Define directories for logs
set "ORG_DIR=%AppData%\AVPN.ORG"
set "USER_APP_DIR=%ORG_DIR%\AVPN"
set "USER_LOG_DIR=%USER_APP_DIR%\log"
set "SYS_APP_DIR=%ProgramData%\AVPN"
set "SYS_LOG_DIR=%SYS_APP_DIR%\log"
set "SYS_LOG_FILE=%SYS_LOG_DIR%\Tribe-service.log"

timeout /t 1
sc stop AmneziaWGTunnel$TribeVPN
sc stop Tribe-service
taskkill /IM "Tribe-service.exe" /F
sc delete AmneziaWGTunnel$TribeVPN
sc delete Tribe-service
powershell -NoProfile -NonInteractive -Command "Get-Process -Name AmneziaVPN -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '%~dp0*' } | Stop-Process -Force"

rem Delete the service log file under ProgramData
if exist "%SYS_LOG_FILE%" del /F /Q "%SYS_LOG_FILE%"
if exist "%SYS_LOG_DIR%" rmdir /S /Q "%SYS_LOG_DIR%"
rem Try to remove application dir if empty
rd "%SYS_APP_DIR%" 2>nul

rem Delete client logs under current user's AppData\Roaming (Organization\Application)
if exist "%USER_LOG_DIR%" rmdir /S /Q "%USER_LOG_DIR%"
rem Try to remove app and org directories if empty
rd "%USER_APP_DIR%" 2>nul
rd "%ORG_DIR%" 2>nul

exit /b 0
