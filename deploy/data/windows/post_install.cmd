rem AVPN: Tribe names. Upstream stopped AmneziaWGTunnel$AmneziaVPN and killed every AmneziaVPN.exe -
rem that is the original Amnezia VPN app, not ours. Our tunnel = AmneziaWGTunnel$TribeVPN
rem (TUNNEL_SERVICE_NAME), service = Tribe-service, GUI = AmneziaVPN.exe from THIS folder only.
sc stop AmneziaWGTunnel$TribeVPN
sc delete AmneziaWGTunnel$TribeVPN
taskkill /IM "Tribe-service.exe" /F
powershell -NoProfile -NonInteractive -Command "Get-Process -Name AmneziaVPN -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '%~dp0*' } | Stop-Process -Force"
exit /b 0
