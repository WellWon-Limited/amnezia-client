var requestToQuitFromApp = false;
var updaterCompleted = 0;
var desktopAppProcessRunning = false;
var appInstalledUninstallerPath;
var appInstalledUninstallerPath_x86;

// AVPN: отмена в IFW 4.x — installer.setCanceled(). Upstream звал setCancelled() (нет такого метода):
// любая отмена (Cancel в «уже установлено», отказ деинсталлятора) падала исключением скрипта.

function appName()
{
    return installer.value("Name");
}

// AVPN: на Windows GUI = AmneziaVPN.exe (upstream-имя цели клиента), а Name = TribeVPN — как в
// componentscript.js. "TribeVPN.exe" искать нельзя: так называется сам скачанный инсталлер
// (/dl/TribeVPN.exe) — он находил себя в tasklist и бесконечно показывал «TribeVPN is active».
function appExecutableFileName()
{
    if (runningOnWindows()) {
        return "AmneziaVPN.exe";
    } else {
        return appName();
    }
}

function appInstalled()
{
    if (runningOnWindows()) {
        // AVPN: ставимся в Program Files/TribeVPN (CPACK_PACKAGE_INSTALL_DIRECTORY). Upstream-папка
        // AmneziaVPN — чужое приложение: старую установку Tribe мы не видели, а Amnezia предлагали снести.
        appInstalledUninstallerPath = installer.value("RootDir") + "Program Files/" + appName() + "/maintenancetool.exe";
        appInstalledUninstallerPath_x86 = installer.value("RootDir") + "Program Files (x86)/" + appName() + "/maintenancetool.exe";
    } else if (runningOnMacOS()){
        appInstalledUninstallerPath = "/Applications/" + appName() + ".app/maintenancetool.app/Contents/MacOS/maintenancetool";
    } else if (runningOnLinux()){
        appInstalledUninstallerPath = "/opt/" + appName() + "/maintenancetool";
    }

    return installer.fileExists(appInstalledUninstallerPath) || installer.fileExists(appInstalledUninstallerPath_x86);
}

function endsWith(str, suffix)
{
    return str.indexOf(suffix, str.length - suffix.length) !== -1;
}

function runningOnWindows()
{
    return (installer.value("os") === "win");
}

function runningOnMacOS()
{
    return (installer.value("os") === "mac");
}

function runningOnLinux()
{
    return ((installer.value("os") === "linux") || (installer.value("os") === "x11"));
}

function sleep(milliseconds) {
    var currentTime = new Date().getTime();
    while (currentTime + milliseconds >= new Date().getTime()) {}
}

function raiseInstallerWindow()
{
    if (!runningOnMacOS()) {
        return;
    }

    var result = installer.execute("/bin/bash", ["-c", "ps -A | grep -m1 '" + appName() + "' | awk '{print $1}'"]);
    if (Number(result[0]) > 0) {
        var arg = 'tell application \"System Events\" ' +
                '\n      set frontmost of the first process whose unix id is ' + Number(result[0]) + ' to true ' +
                '\n      end tell' +
                '\n       ';
        installer.execute("osascript", ["-e", arg]);
    }
}

function appProcessIsRunning()
{
    if (runningOnWindows()) {
        // AVPN: считаем только GUI из нашей папки — AmneziaVPN.exe оригинальной Amnezia не наш.
        var ps = installer.execute("powershell", ["-NoProfile", "-NonInteractive", "-Command",
            "@(Get-Process -Name AmneziaVPN -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '*\\" + appName() + "\\*' }).Count"]);
        if (Number(ps[1]) === 0) {
            return Number(String(ps[0]).trim()) > 0;
        }
        var result = installer.execute("tasklist", ["/FI", "IMAGENAME eq " + appExecutableFileName(), "/NH"]);
        if ( Number(result[1]) === 0 ) {
            if (result[0].indexOf(appExecutableFileName()) !== -1) {
                return true;
            }
        }
    } else {
        return checkProcessIsRunning("pgrep -x '" + appName() + "'")
    }

    return false;
}

// AVPN: перед установкой гасим и снимаем НАШИ службы. Деинсталляторы Tribe до 5.1.100 несли upstream
// post_uninstall.cmd: он удалял AmneziaVPN-service (служба оригинальной Amnezia) и чистил её логи, а
// Tribe-service оставлял запущенной — залоченный Tribe-service.exe не перезаписывался, «sc create»
// новой установки падал (служба уже есть). Поэтому: стоп + удаление служб Tribe, а старый
// post_uninstall.cmd заменяем пустым, чтобы деинсталлятор старой версии не тронул Amnezia.
function stopTribeServicesBeforeInstall()
{
    if (!runningOnWindows()) {
        return;
    }
    if (!installer.gainAdminRights()) {
        console.log("No admin rights: Tribe services are not stopped before install");
        return;
    }
    var cmd = "$ErrorActionPreference = 'SilentlyContinue'; " +
              "sc.exe stop 'AmneziaWGTunnel$" + appName() + "' | Out-Null; sc.exe stop Tribe-service | Out-Null; " +
              "Start-Sleep -Seconds 2; Stop-Process -Name Tribe-service -Force; Start-Sleep -Seconds 1; " +
              "sc.exe delete 'AmneziaWGTunnel$" + appName() + "' | Out-Null; sc.exe delete Tribe-service | Out-Null; " +
              "foreach ($d in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) { if ($d) { " +
              "$f = Join-Path (Join-Path $d '" + appName() + "') 'post_uninstall.cmd'; " +
              "if (Test-Path -LiteralPath $f) { Set-Content -LiteralPath $f -Value 'exit /b 0' -Encoding ASCII } } }";
    var result = installer.execute("powershell", ["-NoProfile", "-NonInteractive", "-Command", cmd]);
    console.log("Tribe services stopped before install, code: " + result[1]);
    installer.dropAdminRights();
}

// AVPN: старую версию удаляем без окон мастера (IFW CLI): юзер уже подтвердил удаление в диалоге
// выше, а тихий режим проверяется смоук-тестом инсталлера в CI (deploy/tribe/windows-installer-smoke.ps1).
function uninstallerArgs()
{
    return runningOnWindows() ? ["purge", "--confirm-command", "--default-answer"] : [];
}

// AVPN: деинсталлятор Tribe до 5.1.100 (upstream post_uninstall.cmd с AmneziaVPN-service) считает
// «приложение запущено», если в tasklist есть TribeVPN.exe, — а так назван и этот инсталлер, если его
// скачали со старой ссылки как есть. Тогда старая версия не даёт себя удалить.
function installedUninstallerIsLegacy()
{
    var paths = [appInstalledUninstallerPath, appInstalledUninstallerPath_x86];
    for (var i = 0; i < paths.length; i++) {
        var script = String(paths[i]).replace("maintenancetool.exe", "post_uninstall.cmd");
        if (installer.fileExists(script) && String(installer.readFile(script, "UTF-8")).indexOf("AmneziaVPN-service") !== -1) {
            return true;
        }
    }
    return false;
}

function installerFileIsNamedLikeOldApp()
{
    var path = String(installer.value("InstallerFilePath") || "").replace(/\\/g, "/");
    var name = path.substring(path.lastIndexOf("/") + 1).toLowerCase();
    return name === (appName() + ".exe").toLowerCase();
}

function checkProcessIsRunning(arg)
{
    var cmdArgs = ["-c", arg];
    var result = installer.execute("/bin/bash", cmdArgs);
    var lines = result[0].trim().split(/\n+/);
    var resultArg1 = Number(lines[0])
    if (resultArg1 >= 2) {
        return true;
    }
    return false;
}

function requestToQuit(installer,gui)
{
    requestToQuitFromApp = true;

    installer.setDefaultPageVisible(QInstaller.IntroductionPage, false);
    installer.setDefaultPageVisible(QInstaller.TargetDirectory, false);
    installer.setDefaultPageVisible(QInstaller.ComponentSelection, false);
    installer.setDefaultPageVisible(QInstaller.LicenseCheck, false);
    installer.setDefaultPageVisible(QInstaller.StartMenuSelection, false);
    installer.setDefaultPageVisible(QInstaller.ReadyForInstallation, false);
    installer.setDefaultPageVisible(QInstaller.PerformInstallation, false);
    installer.setDefaultPageVisible(QInstaller.FinishedPage, false);

    gui.clickButton(buttons.NextButton);
    gui.clickButton(buttons.FinishButton);
    gui.clickButton(buttons.CancelButton);

    if (runningOnWindows()) {
        installer.setCanceled();
    }
}


Controller.prototype.PerformInstallationPageCallback = function()
{
    gui.clickButton(buttons.NextButton);
}

Controller.prototype.LicenseAgreementPageCallback = function()
{
    gui.clickButton(buttons.NextButton);
}

Controller.prototype.FinishedPageCallback = function ()
{
    if (desktopAppProcessRunning) {
        gui.clickButton(buttons.FinishButton);
    } else if (installer.isUpdater()) {
        installer.autoAcceptMessageBoxes();
        gui.clickButton(buttons.FinishButton);
    }
}

Controller.prototype.RestartPageCallback = function ()
{
    updaterCompleted = 1;
    gui.clickButton(buttons.FinishButton);
}

Controller.prototype.StartMenuDirectoryPageCallback = function()
{
    gui.clickButton(buttons.NextButton);
}

Controller.prototype.ComponentSelectionPageCallback = function()
{
    gui.clickButton(buttons.NextButton);
}

Controller.prototype.ReadyForInstallationPageCallback = function()
{
    if (installer.isUpdater()) {
        gui.clickButton(buttons.CommitButton);
    }
}

Controller.prototype.TargetDirectoryPageCallback = function ()
{
    var widget = gui.pageById(QInstaller.TargetDirectory);

    if (widget !== null) {
        widget.BrowseDirectoryButton.clicked.disconnect(onBrowseButtonClicked);
        widget.BrowseDirectoryButton.clicked.connect(onBrowseButtonClicked);

        gui.clickButton(buttons.NextButton);
    }
}

Controller.prototype.IntroductionPageCallback = function ()
{
    var widget = gui.currentPageWidget();
    if (installer.isUpdater() && updaterCompleted === 1) {
        gui.clickButton(buttons.FinishButton);
        gui.clickButton(buttons.CancelButton);
        return;
    }

    if (installer.isUninstaller()) {
        if (widget !== null) {
            widget.findChild("PackageManagerRadioButton").visible = false;
            widget.findChild("UpdaterRadioButton").visible = false;
        }
    }

    if (installer.isUpdater()) {
        gui.clickButton(buttons.NextButton);
    }
}

onBrowseButtonClicked = function()
{
    var widget = gui.pageById(QInstaller.TargetDirectory);
    if (widget !== null) {
        if (runningOnWindows()) {
            // On Windows we are appending \<APP_NAME> if selected path don't ends with <APP_NAME>
            var targetDir = widget.TargetDirectoryLineEdit.text;
            if (! endsWith(targetDir, appName())) {
                targetDir = targetDir + "\\" + appName();
            }
            installer.setValue("TargetDir", targetDir);
            widget.TargetDirectoryLineEdit.setText(installer.value("TargetDir"));
        }
    }
}

onNextButtonClicked = function()
{
    var widget = gui.pageById(QInstaller.TargetDirectory);
    if (widget !== null) {
        installer.setValue("APP_BUNDLE_TARGET_DIR", widget.TargetDirectoryLineEdit.text);
    }
}

function Controller () {
    console.log("OS: %1, architecture: %2".arg(systemInfo.prettyProductName).arg(systemInfo.currentCpuArchitecture));

    if (installer.isInstaller() || installer.isUpdater()) {
        console.log("Check if app already installed: " + appInstalled());
    }

    if (runningOnWindows()) {
        installer.setValue("AllUsers", "true");
    }

    if (installer.isInstaller()) {
        installer.setDefaultPageVisible(QInstaller.ComponentSelection, false);
        installer.setDefaultPageVisible(QInstaller.TargetDirectory, false);
        installer.setDefaultPageVisible(QInstaller.StartMenuDirectoryPage, false);
        installer.setDefaultPageVisible(QInstaller.LicenseCheck, false);

        isDesktopAppProcessRunningMessageLoop();

        if (requestToQuitFromApp === true) {
            requestToQuit(installer, gui);
            return;
        }

        if (runningOnMacOS()) {
            installer.setMessageBoxAutomaticAnswer("OverwriteTargetDirectory", QMessageBox.Yes);
        }

        if (runningOnWindows() && appInstalled() && installedUninstallerIsLegacy() && installerFileIsNamedLikeOldApp()) {
            QMessageBox.critical("os.information", appName(),
                                 "Файл установщика называется " + appName() + ".exe — старая версия Tribe VPN примет его за " +
                                 "запущенное приложение и не даст себя удалить. Переименуйте файл, например в " +
                                 appName() + "-Setup.exe, и запустите установку снова.", QMessageBox.Ok);
            installer.setCanceled();
            return;
        }

        if (appInstalled()) {
            if (QMessageBox.Ok === QMessageBox.information("os.information", appName(),
                                                           qsTr("The application is already installed.") + " " +
                                                           qsTr("We need to remove the old installation first. Do you wish to proceed?"),
                                                           QMessageBox.Ok | QMessageBox.Cancel)) {

                stopTribeServicesBeforeInstall();

                if (appInstalled()) {
                    var resultArray = [];

                    if (installer.fileExists(appInstalledUninstallerPath_x86)) {
                        console.log("Starting uninstallation " + appInstalledUninstallerPath_x86);
                        resultArray = installer.execute(appInstalledUninstallerPath_x86, uninstallerArgs());
                    }

                    if (installer.fileExists(appInstalledUninstallerPath)) {
                        console.log("Starting uninstallation " + appInstalledUninstallerPath);
                        resultArray = installer.execute(appInstalledUninstallerPath, uninstallerArgs());
                    }

                    console.log("Uninstaller finished with code: " + resultArray[1])

                    if (Number(resultArray[1]) !== 0) {
                        console.log("Uninstallation aborted by user");
                        installer.setCanceled();
                        return;
                    } else {
                        for (var i = 0; i < 300; i++) {
                            sleep(100);
                            if (!installer.fileExists(appInstalledUninstallerPath)) {
                                break;
                            }
                        }
                    }
                }

                raiseInstallerWindow();

            } else {
                console.log("Request to quit from user");
                installer.setCanceled();
                return;
            }
        } else {
            // AVPN: установки нет, но служба могла остаться от старого деинсталлятора — снимаем.
            stopTribeServicesBeforeInstall();
        }

    } else if (installer.isUninstaller()) {
        isDesktopAppProcessRunningMessageLoop();

        if (requestToQuitFromApp === true) {
            requestToQuit(installer, gui);
            return;
        }

    } else if (installer.isUpdater()) {
        installer.setMessageBoxAutomaticAnswer("cancelInstallation", QMessageBox.No);
        installer.installationFinished.connect(function() {
            gui.clickButton(buttons.NextButton);
        });
    }
}

isDesktopAppProcessRunningMessageLoop = function ()
{
    if (requestToQuitFromApp === true) {
        return;
    }

    if (installer.isUpdater()) {
        for (var i = 0; i < 400; i++) {
            desktopAppProcessRunning = appProcessIsRunning();
            if (!desktopAppProcessRunning) {
                break;
            }
        }
    }
    desktopAppProcessRunning = appProcessIsRunning();

    if (desktopAppProcessRunning) {
        var result = QMessageBox.warning("QMessageBox", appName() + " installer",
                                         appName() + " is active. Close the app and press \"Retry\" button to continue installation. Press \"Abort\" button to abort the installer and exit.",
                                         QMessageBox.Retry | QMessageBox.Abort);
        if (result === QMessageBox.Retry) {
            isDesktopAppProcessRunningMessageLoop();
        } else {
            requestToQuitFromApp = true;
            return;
        }
    }
}
