// AVPN (macOS desktop): авто-установка root-демона Tribe-service из вшитого payload.
// Компилируется только под macOS-desktop (avpn.cmake: APPLE AND NOT IOS AND NOT MACOS_NE).
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include "MacServiceInstaller.h"
#include "version.h"
#include <QHash>
#include <QProcess>
#include <QStringList>
#include <QThread>

namespace avpn {

bool macServiceInstalled()
{
    return [[NSFileManager defaultManager]
            fileExistsAtPath:@"/Library/LaunchDaemons/Tribe-service.plist"];
}

bool macServiceRunning()
{
    // Bind readiness to the top-level launchd job fields and the exact kernel
    // text vnode. A same-name process (or a nested coalition `state` field) is
    // not evidence that Tribe's privileged service is healthy.
    QProcess launchctl;
    launchctl.start(QStringLiteral("/bin/launchctl"),
                    {QStringLiteral("print"), QStringLiteral("system/Tribe-service")});
    if (!launchctl.waitForFinished(3000) || launchctl.exitCode() != 0)
        return false;
    const QString output = QString::fromUtf8(launchctl.readAllStandardOutput());
    int topIndent = -1;
    QHash<QString, QString> fields;
    QHash<QString, int> counts;
    for (const QString &line : output.split(QLatin1Char('\n'))) {
        int indentation = 0;
        while (indentation < line.size()
               && (line.at(indentation) == QLatin1Char(' ')
                   || line.at(indentation) == QLatin1Char('\t'))) {
            ++indentation;
        }
        const QStringList parts = line.mid(indentation).simplified().split(QLatin1Char(' '));
        if (parts.size() < 3 || parts.at(1) != QStringLiteral("="))
            continue;
        if (topIndent < 0 && parts.at(0) == QStringLiteral("path"))
            topIndent = indentation;
        if (topIndent >= 0 && indentation == topIndent) {
            const QString key = parts.at(0);
            if (key == QStringLiteral("program") || key == QStringLiteral("state")
                || key == QStringLiteral("pid")) {
                fields.insert(key, parts.at(2));
                counts.insert(key, counts.value(key) + 1);
            }
        }
    }
    const QString expected = QStringLiteral("/Library/PrivilegedHelperTools/TribeVPN/Tribe-service");
    if (topIndent < 0 || counts.value(QStringLiteral("program")) != 1
        || counts.value(QStringLiteral("state")) != 1
        || counts.value(QStringLiteral("pid")) != 1
        || fields.value(QStringLiteral("program")) != expected
        || fields.value(QStringLiteral("state")) != QStringLiteral("running")) {
        return false;
    }
    bool pidOk = false;
    const qlonglong pid = fields.value(QStringLiteral("pid")).toLongLong(&pidOk);
    if (!pidOk || pid <= 1)
        return false;
    QProcess lsof;
    lsof.start(QStringLiteral("/usr/sbin/lsof"),
               {QStringLiteral("-a"), QStringLiteral("-p"), QString::number(pid),
                QStringLiteral("-d"), QStringLiteral("txt"), QStringLiteral("-Fn")});
    if (!lsof.waitForFinished(3000) || lsof.exitCode() != 0)
        return false;
    const QString expectedLine = QStringLiteral("n") + expected;
    return QString::fromUtf8(lsof.readAllStandardOutput())
               .split(QLatin1Char('\n')).count(expectedLine) == 1;
}

bool macServiceOutdated()
{
    @autoreleasepool {
        // Версия, вшитая в ЭТУ сборку app (ресурс tribe-svc.version). Нет ресурса (старая сборка
        // без версионирования) → не можем судить → считаем НЕ устаревшим (не дёргаем зря промпт).
        NSString *res = [[NSBundle mainBundle] pathForResource:@"tribe-svc" ofType:@"version"];
        if (res == nil)
            return false;
        NSString *bundled = [[NSString stringWithContentsOfFile:res encoding:NSUTF8StringEncoding error:nil]
                             stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (bundled.length == 0)
            return false;
        // Версия УСТАНОВЛЕННОГО демона. Нет файла = демон старой сборки (без маркера) → устарел.
        NSString *inst = [[NSString stringWithContentsOfFile:@"/Library/PrivilegedHelperTools/TribeVPN/VERSION"
                                                    encoding:NSUTF8StringEncoding error:nil]
                          stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (inst == nil || inst.length == 0)
            return true;
        return ![bundled isEqualToString:inst];
    }
}

static bool pgrepFull(const QString &pattern)
{
    QProcess p;
    p.start(QStringLiteral("/usr/bin/pgrep"), {QStringLiteral("-f"), pattern});
    if (!p.waitForFinished(3000))
        return false;
    return p.exitCode() == 0;
}

QString macForeignVpnName()
{
    // Наш туннель уже поднят (наш amneziawg-go жив)? Тогда utun-egress = НАШ → не конфликт (reconnect).
    if (pgrepFull(QStringLiteral("/Library/PrivilegedHelperTools/TribeVPN/amneziawg-go")))
        return QString();

    // Официальная Amnezia активно туннелирует (её wireguard-go) — гарантированный конфликт.
    if (pgrepFull(QStringLiteral("AmneziaVPN.app/Contents/MacOS/wireguard-go")))
        return QStringLiteral("Amnezia VPN");

    // Общий случай: публичный трафик уже идёт через какой-то utun (наш туннель ещё не поднят) →
    // активен чужой full-tunnel VPN. `route -n get 1.1.1.1` → "interface: utunN".
    QProcess r;
    r.start(QStringLiteral("/sbin/route"), {QStringLiteral("-n"), QStringLiteral("get"), QStringLiteral("1.1.1.1")});
    if (r.waitForFinished(3000)) {
        const QString out = QString::fromUtf8(r.readAllStandardOutput());
        for (const QString &line : out.split('\n')) {
            const QString t = line.trimmed();
            if (t.startsWith(QStringLiteral("interface:")) && t.contains(QStringLiteral("utun")))
                return QStringLiteral("другой VPN");
        }
    }
    return QString();
}

bool macInstallServiceConfirm(MacServiceInstallReason reason, QString *errOut)
{
    @autoreleasepool {
        // ГЛАВНЫЙ поток. NSAppleScript IN-PROCESS → диалог идёт от «Tribe VPN» (а не «osascript»);
        // display dialog крутит СВОЙ модальный цикл и качает события — окно приложения живое.
        // Пароль здесь НЕ спрашиваем — привилегированная часть ушла в macInstallServiceRun (фон).
        NSString *src = nil;
        NSString *acceptedButton = nil;
        switch (reason) {
        case MacServiceInstallReason::FirstInstall:
            acceptedButton = @"Установить службу";
            src =
                @"button returned of (display dialog \"Tribe VPN установит системную службу. "
                 "Она управляет VPN-туннелем и необходима для подключения. После подтверждения "
                 "macOS запросит пароль администратора.\" with title "
                 "\"Установка системной службы Tribe VPN\" buttons "
                 "{\"Отмена\", \"Установить службу\"} default button \"Установить службу\" "
                 "cancel button \"Отмена\" with icon note)";
            break;
        case MacServiceInstallReason::Update:
            acceptedButton = @"Обновить службу";
            src =
                @"button returned of (display dialog \"Tribe VPN обновит существующую системную "
                 "службу до версии, совместимой с этим приложением. Служба управляет "
                 "VPN-туннелями; аккаунт и настройки сохранятся. После подтверждения macOS "
                 "запросит пароль администратора.\" with title "
                 "\"Обновление системной службы Tribe VPN\" buttons "
                 "{\"Отмена\", \"Обновить службу\"} default button \"Обновить службу\" "
                 "cancel button \"Отмена\" with icon note)";
            break;
        case MacServiceInstallReason::Repair:
            acceptedButton = @"Восстановить службу";
            src =
                @"button returned of (display dialog \"Системная служба Tribe VPN установлена, "
                 "но сейчас не работает. Tribe VPN проверит и восстановит её, чтобы снова можно "
                 "было подключаться. Аккаунт и настройки сохранятся. После подтверждения macOS "
                 "запросит пароль администратора.\" with title "
                 "\"Восстановление системной службы Tribe VPN\" buttons "
                 "{\"Отмена\", \"Восстановить службу\"} default button "
                 "\"Восстановить службу\" cancel button \"Отмена\" with icon caution)";
            break;
        }
        NSDictionary *asErr = nil;
        NSAppleScript *as = [[NSAppleScript alloc] initWithSource:src];
        NSAppleEventDescriptor *res = [as executeAndReturnError:&asErr];
        // -128 = отмена; любой другой исход без точной кнопки действия трактуем так же.
        if (asErr != nil || res == nil || acceptedButton == nil
            || ![[res stringValue] isEqualToString:acceptedButton]) {
            if (errOut) *errOut = QStringLiteral("Изменение системной службы Tribe VPN отменено");
            return false;
        }
        return true;
    }
}

static bool runPrivilegedSnapshotAction(NSString *action, QString *errOut)
{
    @autoreleasepool {
        NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
        NSString *expectedAppVersion = [NSString stringWithUTF8String:APP_VERSION];
        if (bundlePath == nil || (![action isEqualToString:@"install"]
                              && ![action isEqualToString:@"uninstall"])) {
            if (errOut) *errOut = QStringLiteral("Установщик службы VPN не найден в приложении");
            return false;
        }

        // Never elevate a script directly from the user-controlled dragged app.
        // The fixed bootstrap below is part of the already-running signed binary.
        // Root first takes an unpredictable 0700 snapshot, verifies the complete
        // snapshot against the exact Tribe Developer ID requirement, rejects
        // special/writable/hard-linked nodes, and executes only snapshot resources.
        NSString *bootstrap =
            @"set -euo pipefail\n"
             "export PATH=/usr/sbin:/usr/bin:/sbin:/bin\n"
             "source_app=$1\n"
             "action=$2\n"
             "expected_app_version=$3\n"
             "case \"$action\" in install|uninstall) ;; *) exit 64 ;; esac\n"
             "snapshot=$(/usr/bin/mktemp -d /private/var/tmp/tribevpn-bootstrap.XXXXXX)\n"
             "cleanup() { /bin/rm -rf \"$snapshot\"; }\n"
             "trap cleanup EXIT\n"
             "trap 'exit 1' HUP INT TERM\n"
             "/bin/chmod 700 \"$snapshot\"\n"
             "/usr/bin/ditto --norsrc --noqtn \"$source_app\" \"$snapshot/TribeVPN.app\"\n"
             "trusted_app=$snapshot/TribeVPN.app\n"
             "test -d \"$trusted_app\" && test ! -L \"$trusted_app\"\n"
             "requirement='identifier \"hk.wellwon.vpn\" and anchor apple generic and certificate leaf[subject.OU] = \"Q7DVH5MCWF\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'\n"
             "/usr/bin/codesign --verify --deep --strict --all-architectures -R=\"$requirement\" \"$trusted_app\"\n"
             "snapshot_short=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \"$trusted_app/Contents/Info.plist\")\n"
             "snapshot_build=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' \"$trusted_app/Contents/Info.plist\")\n"
             "test \"$snapshot_short.$snapshot_build\" = \"$expected_app_version\"\n"
             "test -z \"$(/usr/bin/find \"$trusted_app\" ! -type d ! -type f ! -type l -print -quit)\"\n"
             "test -z \"$(/usr/bin/find \"$trusted_app\" -type f -links +1 -print -quit)\"\n"
             "while IFS= read -r -d '' node; do mode=$(/usr/bin/stat -f '%Lp' \"$node\"); if (( (8#$mode & 06022) != 0 )); then echo \"unsafe signed-app mode $mode: $node\" >&2; exit 1; fi; done < <(/usr/bin/find \"$trusted_app\" ! -type l -print0)\n"
             "/usr/sbin/chown -R -P root:wheel \"$trusted_app\"\n"
             "installer=$trusted_app/Contents/Resources/tribe-svc-install.sh\n"
             "tarball=$trusted_app/Contents/Resources/tribe-svc.tar.gz\n"
             "digest=$trusted_app/Contents/Resources/tribe-svc.tar.sha256\n"
             "version=$trusted_app/Contents/Resources/tribe-svc.version\n"
             "epoch=$trusted_app/Contents/Resources/tribe-svc.epoch\n"
             "verifier=$trusted_app/Contents/Resources/macos-service-payload.sh\n"
             "launchctl_parser=$trusted_app/Contents/Resources/launchctl-job-field.sh\n"
             "for critical in \"$installer\" \"$tarball\" \"$digest\" \"$version\" \"$epoch\" \"$verifier\" \"$launchctl_parser\"; do test -f \"$critical\"; test ! -L \"$critical\"; test \"$(/usr/bin/stat -f '%l' \"$critical\")\" = 1; done\n"
             "test -x \"$installer\" && test -x \"$verifier\" && test -x \"$launchctl_parser\"\n"
             "if test \"$action\" = install; then /bin/bash \"$installer\" \"$tarball\"; else /bin/bash \"$installer\" --uninstall; fi\n";

        // Quote both the fixed program and the source bundle as opaque shell
        // arguments, then quote the resulting command for AppleScript.
        auto shEsc = [](NSString *p) {  // ' → '\''  (безопасно внутри одинарных кавычек shell)
            return [p stringByReplacingOccurrencesOfString:@"'" withString:@"'\\''"];
        };
        NSString *shellCmd = [NSString stringWithFormat:@"/bin/bash -c '%@' -- '%@' '%@' '%@'",
                              shEsc(bootstrap), shEsc(bundlePath), shEsc(action),
                              shEsc(expectedAppVersion)];
        NSString *shForAS = [shellCmd stringByReplacingOccurrencesOfString:@"\\" withString:@"\\\\"];
        shForAS = [shForAS stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];

        // NSAppleScript IN-PROCESS → системный промпт пароля атрибутирован «Tribe VPN» (а НЕ
        // «osascript»); промпт рисует SecurityAgent (отдельный процесс) — поток вызова ему не важен.
        // `do shell script ... with administrator privileges` НАДЁЖНО поднимает root (в отличие от
        // AuthorizationExecuteWithPrivileges, который на macOS 26 не элевейтит). UI-элементов
        // (display dialog и т.п.) в этом скрипте быть НЕ должно — вне главного потока это -1713.
        NSString *src = [NSString stringWithFormat:
            @"do shell script \"%@\" with administrator privileges", shForAS];

        NSDictionary *asErr = nil;
        NSAppleScript *as = [[NSAppleScript alloc] initWithSource:src];
        [as executeAndReturnError:&asErr];
        if (asErr != nil) {
            // -128 = пользователь отменил промпт пароля.
            NSNumber *code = asErr[@"NSAppleScriptErrorNumber"];
            if (errOut) *errOut = (code.intValue == -128)
                ? QStringLiteral("Установка службы VPN отменена")
                : QStringLiteral("Не удалось установить службу VPN (нет прав администратора)");
            return false;
        }

        if ([action isEqualToString:@"install"]) {
            // Confirm that the newly installed daemon survived bootstrap.
            for (int i = 0; i < 16 && !macServiceRunning(); ++i)
                QThread::msleep(300);
            if (!macServiceRunning()) {
                if (errOut) *errOut = QStringLiteral("Служба VPN установлена, но не запустилась");
                return false;
            }
        } else if (macServiceInstalled() || macServiceRunning()) {
            if (errOut) *errOut = QStringLiteral("Системная служба VPN не была полностью удалена");
            return false;
        }
        return true;
    }
}

bool macInstallServiceRun(QString *errOut)
{
    return runPrivilegedSnapshotAction(@"install", errOut);
}

bool macUninstallServiceConfirm(QString *errOut)
{
    @autoreleasepool {
        NSString *src =
            @"button returned of (display dialog \"Удалить системную службу Tribe VPN? "
             "VPN отключится; само приложение и данные аккаунта останутся.\" "
             "with title \"Tribe VPN\" buttons {\"Отмена\", \"Удалить службу\"} "
             "default button \"Отмена\" cancel button \"Отмена\" with icon caution)";
        NSDictionary *asErr = nil;
        NSAppleScript *as = [[NSAppleScript alloc] initWithSource:src];
        NSAppleEventDescriptor *res = [as executeAndReturnError:&asErr];
        if (asErr != nil || res == nil || ![[res stringValue] isEqualToString:@"Удалить службу"]) {
            if (errOut) *errOut = QStringLiteral("Удаление службы VPN отменено");
            return false;
        }
        return true;
    }
}

bool macUninstallServiceRun(QString *errOut)
{
    return runPrivilegedSnapshotAction(@"uninstall", errOut);
}

}
