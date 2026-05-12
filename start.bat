@echo off
title rage license server

:: Open firewall port 3000 (requires admin — right-click > Run as administrator)
netsh advfirewall firewall show rule name="rage-license-3000" >nul 2>&1
if errorlevel 1 (
    echo [*] Adding firewall rule for port 3000...
    netsh advfirewall firewall add rule name="rage-license-3000" dir=in action=allow protocol=TCP localport=3000 profile=any >nul
    echo [+] Firewall rule added.
) else (
    echo [+] Firewall rule already exists.
)

echo.
echo  rage license server
echo  ─────────────────────────────────────────
echo  Local:     http://localhost:3000
echo  Dashboard: http://localhost:3000/dashboard
echo.
echo  For public access:
echo    - Disable VPN + port-forward 3000 on router
echo    - OR deploy to Render.com for a permanent URL
echo  ─────────────────────────────────────────
echo.

python "%~dp0server.py"
pause
