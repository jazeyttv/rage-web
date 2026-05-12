#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

Write-Host ""
Write-Host " rage license server — self-host setup" -ForegroundColor White
Write-Host " ──────────────────────────────────────" -ForegroundColor DarkGray

# ── 1. Check for VPN ──────────────────────────────────────────────────────────
$vpnAdapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'mullvad|vpn|tun|tap|wireguard' -and $_.Status -eq 'Up' }
if ($vpnAdapters) {
    Write-Host ""
    Write-Host " [!] VPN is active ($($vpnAdapters.Name)). Disable it first, then re-run this script." -ForegroundColor Yellow
    Write-Host "     Your public IP right now is your VPN's — buyers can't reach it." -ForegroundColor DarkGray
    Write-Host ""
    pause
    exit 1
}

# ── 2. Get real public IP ─────────────────────────────────────────────────────
Write-Host ""
Write-Host " [*] Getting your public IP..." -ForegroundColor Cyan
try {
    $publicIp = (Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 5).Trim()
} catch {
    Write-Host " [!] Could not reach ipify.org. Check your internet connection." -ForegroundColor Red
    pause; exit 1
}
Write-Host " [+] Public IP: $publicIp" -ForegroundColor Green

# ── 3. Firewall rule ──────────────────────────────────────────────────────────
Write-Host " [*] Adding firewall rule for port 3000..." -ForegroundColor Cyan
$existing = netsh advfirewall firewall show rule name="rage-license-3000" 2>&1
if ($existing -notmatch 'No rules match') {
    netsh advfirewall firewall delete rule name="rage-license-3000" | Out-Null
}
netsh advfirewall firewall add rule name="rage-license-3000" dir=in action=allow protocol=TCP localport=3000 profile=any | Out-Null
Write-Host " [+] Firewall rule set." -ForegroundColor Green

# ── 4. Patch rage.lua ─────────────────────────────────────────────────────────
$luaPath = "C:\Users\Rage\Desktop\lua\rage.lua"
if (Test-Path $luaPath) {
    Write-Host " [*] Patching LICENSE_URL in rage.lua..." -ForegroundColor Cyan
    $lua = Get-Content $luaPath -Raw
    $newUrl = "http://$publicIp`:3000/verify"
    $lua = $lua -replace "local LICENSE_URL = '[^']*'", "local LICENSE_URL = '$newUrl'"
    Set-Content $luaPath $lua -Encoding UTF8
    Write-Host " [+] LICENSE_URL set to: $newUrl" -ForegroundColor Green
} else {
    Write-Host " [!] rage.lua not found at $luaPath — update LICENSE_URL manually." -ForegroundColor Yellow
}

# ── 5. Summary ────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host " ──────────────────────────────────────" -ForegroundColor DarkGray
Write-Host " Done! One manual step left:" -ForegroundColor White
Write-Host ""
Write-Host "   Port-forward TCP 3000 on your router → this PC" -ForegroundColor Yellow
Write-Host "   (log into your router at 192.168.x.x and add the rule)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "   Your local IP for the port-forward rule:" -ForegroundColor DarkGray
$localIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.*' -and $_.IPAddress -notlike '10.8.*'
} | Select-Object -First 1).IPAddress
Write-Host "   $localIp" -ForegroundColor Cyan
Write-Host ""
Write-Host " Then run start.bat to launch the server." -ForegroundColor White
Write-Host " ──────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""
pause
