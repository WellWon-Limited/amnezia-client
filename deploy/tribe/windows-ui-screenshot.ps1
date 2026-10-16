# Снимок первого запуска Tribe VPN на CI-раннере (экран раннера 1024x768 — как маленький ноутбук):
# запускает установленный GUI, ждёт онбординг, пишет геометрию окна и рабочей области, снимает экран.
# Проверка «окно целиком на экране»: нижний край окна не ниже рабочей области (иначе кнопки
# онбординга уходят за край — жалоба 16.10.2026).
param(
    [string]$OutDir = (Join-Path $env:RUNNER_TEMP 'ui-shot'),
    [int]$WaitSec = 25
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class Win {
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
}
'@
[Win]::SetProcessDPIAware() | Out-Null

$exe = Join-Path $env:ProgramFiles 'TribeVPN\AmneziaVPN.exe'
Get-Process -Name AmneziaVPN -ErrorAction SilentlyContinue | Stop-Process -Force
$p = Start-Process -FilePath $exe -PassThru
Start-Sleep -Seconds $WaitSec
$p.Refresh()

$screen = [System.Windows.Forms.Screen]::PrimaryScreen
$work = $screen.WorkingArea
Write-Host "screen=$($screen.Bounds.Width)x$($screen.Bounds.Height) workarea: top=$($work.Top) bottom=$($work.Bottom)"

$ok = $true
if ($p.MainWindowHandle -eq [IntPtr]::Zero) {
    Write-Host 'FAIL окно Tribe не появилось'
    $ok = $false
} else {
    $r = New-Object Win+RECT
    [Win]::GetWindowRect($p.MainWindowHandle, [ref]$r) | Out-Null
    Write-Host "window: left=$($r.Left) top=$($r.Top) right=$($r.Right) bottom=$($r.Bottom) height=$($r.Bottom - $r.Top)"
    if ($r.Bottom -gt $work.Bottom -or $r.Top -lt $work.Top) {
        Write-Host "FAIL окно выходит за рабочую область экрана (низ $($r.Bottom) > $($work.Bottom))"
        $ok = $false
    } else {
        Write-Host 'OK   окно целиком в рабочей области экрана'
    }
}

$bmp = New-Object System.Drawing.Bitmap $screen.Bounds.Width, $screen.Bounds.Height
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($screen.Bounds.Location, [System.Drawing.Point]::Empty, $screen.Bounds.Size)
$bmp.Save((Join-Path $OutDir 'first-run.png'), [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Host "screenshot: $(Join-Path $OutDir 'first-run.png')"

Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
if (-not $ok) { exit 1 }
exit 0
