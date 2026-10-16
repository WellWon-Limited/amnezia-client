# Смоук-тест Windows-инсталлера Tribe VPN на CI-раннере (workflow tribe-windows.yml).
# Сценарии: обновление поверх опубликованной на сайте версии, повторная установка, удаление,
# установка из файла с именем TribeVPN.exe. Рядом стоит «оригинальная Amnezia» (служба
# AmneziaVPN-service + её логи) — инсталлер и деинсталлятор Tribe не должны её трогать.
# Каждый запуск инсталлера ограничен по времени: зависший диалог (Retry-цикл) = падение теста.
param(
    [Parameter(Mandatory = $true)][string]$Installer,
    [string]$PublishedUrl = 'https://tribevpn.com/dl/TribeVPN.exe',
    [string]$BuildDir = 'deploy\build'
)
$ErrorActionPreference = 'Stop'

$work = Join-Path $env:RUNNER_TEMP 'installer-smoke'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$installDir = Join-Path $env:ProgramFiles 'TribeVPN'
$maintenance = Join-Path $installDir 'maintenancetool.exe'
$tunnel = 'AmneziaWGTunnel$TribeVPN'
$failures = New-Object System.Collections.Generic.List[string]

function Step($text) { Write-Host "`n=== $text" }
function Check($ok, $text) {
    if ($ok) { Write-Host "OK   $text" } else { Write-Host "FAIL $text"; $failures.Add($text) }
}
function ServiceExists($name) { [bool](Get-Service -Name $name -ErrorAction SilentlyContinue) }

function RunTool($exe, [string[]]$argList, [int]$timeoutSec = 900) {
    Write-Host "> $exe $($argList -join ' ')"
    $out = Join-Path $work ("run-{0}.log" -f [guid]::NewGuid())
    $p = Start-Process -FilePath $exe -ArgumentList $argList -PassThru -NoNewWindow `
        -RedirectStandardOutput $out -RedirectStandardError "$out.err"
    $null = $p.Handle  # без этого ExitCode у Start-Process бывает пустым
    $finished = $p.WaitForExit($timeoutSec * 1000)
    if (-not $finished) { $p.Kill() }
    $text = ((Get-Content $out -Raw -ErrorAction SilentlyContinue) + (Get-Content "$out.err" -Raw -ErrorAction SilentlyContinue))
    Write-Host $text
    # Исключение в скрипте инсталлера = сломанный сценарий, даже если код выхода «правильный».
    Check ($text -notmatch 'Exception while loading') "без исключений в скриптах инсталлера: $(Split-Path $exe -Leaf) $($argList[0])"
    if (-not $finished) {
        Write-Host "TIMEOUT after $timeoutSec s"
        return 'timeout'
    }
    Write-Host "exit=$($p.ExitCode)"
    return $p.ExitCode
}

function Install($file) { RunTool $file @('install', '--accept-licenses', '--accept-messages', '--confirm-command') }
function Uninstall() { RunTool $maintenance @('purge', '--default-answer', '--confirm-command') }

function ExpectedServiceHashes() {
    Get-ChildItem -Path $BuildDir -Recurse -Filter 'Tribe-service.exe' -ErrorAction SilentlyContinue |
        ForEach-Object { (Get-FileHash $_.FullName -Algorithm SHA256).Hash } | Sort-Object -Unique
}

function CheckInstalledFresh($label) {
    Check (Test-Path $maintenance) "${label}: maintenancetool.exe на месте"
    Check (ServiceExists 'Tribe-service') "${label}: служба Tribe-service зарегистрирована"
    $bin = (Get-CimInstance Win32_Service -Filter "Name='Tribe-service'" -ErrorAction SilentlyContinue).PathName
    Check ($bin -and $bin -like "*$installDir*") "${label}: Tribe-service указывает в $installDir ($bin)"
    $svcExe = Join-Path $installDir 'Tribe-service.exe'
    $expected = @(ExpectedServiceHashes)
    if ($expected.Count -gt 0 -and (Test-Path $svcExe)) {
        $actual = (Get-FileHash $svcExe -Algorithm SHA256).Hash
        Check ($expected -contains $actual) "${label}: Tribe-service.exe из новой сборки, а не старый залоченный"
    }
    CheckAmneziaIntact $label
}

function CheckAmneziaIntact($label) {
    Check (ServiceExists 'AmneziaVPN-service') "${label}: служба оригинальной Amnezia цела"
    Check (Test-Path $amneziaMarker) "${label}: логи оригинальной Amnezia целы"
}

$setup = Join-Path $work 'TribeVPN-Setup.exe'
$asOldName = Join-Path $work 'TribeVPN.exe'
Copy-Item $Installer $setup -Force
Copy-Item $Installer $asOldName -Force

Step 'Подставная «оригинальная Amnezia»'
& sc.exe create AmneziaVPN-service 'binPath=' 'C:\Windows\System32\cmd.exe' 'start=' 'demand' | Out-Host
$amneziaLogDir = Join-Path $env:ProgramData 'AmneziaVPN\log'
New-Item -ItemType Directory -Force -Path $amneziaLogDir | Out-Null
$amneziaMarker = Join-Path $amneziaLogDir 'marker.txt'
Set-Content -Path $amneziaMarker -Value 'amnezia'

Step "Установка опубликованной версии ($PublishedUrl)"
$published = Join-Path $work 'TribeVPN-Published-Setup.exe'
Invoke-WebRequest -Uri $PublishedUrl -OutFile $published -UseBasicParsing
Check ((Install $published) -eq 0) 'опубликованная версия ставится'
& sc.exe start Tribe-service | Out-Host  # запущенная служба = залоченный exe, как у пользователя
Start-Sleep -Seconds 3
$legacy = (Test-Path (Join-Path $installDir 'post_uninstall.cmd')) -and
          ((Get-Content (Join-Path $installDir 'post_uninstall.cmd') -Raw) -match 'AmneziaVPN-service')
Write-Host "опубликованная версия со старым деинсталлятором: $legacy"

if ($legacy) {
    Step 'Новый инсталлер с именем TribeVPN.exe поверх старой версии -> понятный отказ, без зависания'
    $r = Install $asOldName
    Check (($r -ne 'timeout') -and ($r -ne 0)) 'инсталлер TribeVPN.exe отказался сразу'
    Check (Test-Path $maintenance) 'старая установка не тронута'
}

Step 'Обновление поверх опубликованной версии'
Check ((Install $setup) -eq 0) 'обновление прошло'
CheckInstalledFresh 'после обновления'

Step 'Повторная установка поверх новой версии'
& sc.exe start Tribe-service | Out-Host
Start-Sleep -Seconds 3
Check ((Install $setup) -eq 0) 'повторная установка прошла'
CheckInstalledFresh 'после повторной установки'

Step 'Обновление при запущенном Tribe (как у пользователя: окно спрятано в трей)'
$gui = Start-Process -FilePath (Join-Path $installDir 'AmneziaVPN.exe') -PassThru
Start-Sleep -Seconds 15
Check (-not $gui.HasExited) 'GUI Tribe запущен перед обновлением'
Check ((Install $setup) -eq 0) 'обновление при запущенном Tribe прошло без зависания на «TribeVPN is active»'
CheckInstalledFresh 'после обновления при запущенном Tribe'
Get-Process -Name AmneziaVPN -ErrorAction SilentlyContinue | Stop-Process -Force

Step 'Удаление'
Check ((Uninstall) -eq 0) 'удаление прошло'
Start-Sleep -Seconds 3
Check (-not (ServiceExists 'Tribe-service')) 'служба Tribe-service снята'
Check (-not (ServiceExists $tunnel)) 'служба туннеля Tribe снята'
Check (-not (Test-Path $maintenance)) 'папка установки очищена'
CheckAmneziaIntact 'после удаления'

Step 'Чистая установка из файла с именем TribeVPN.exe (так его сохраняет браузер)'
Check ((Install $asOldName) -eq 0) 'установка из TribeVPN.exe не зависает на «TribeVPN is active»'
CheckInstalledFresh 'после установки из TribeVPN.exe'

Step 'Итог'
if ($failures.Count -gt 0) {
    Write-Host "Провалено проверок: $($failures.Count)"
    $failures | ForEach-Object { Write-Host " - $_" }
    exit 1
}
Write-Host 'Все проверки инсталлера пройдены'
exit 0
