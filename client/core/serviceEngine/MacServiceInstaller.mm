// AVPN (macOS desktop): авто-установка root-демона Tribe-service из вшитого payload.
// Компилируется только под macOS-desktop (avpn.cmake: APPLE AND NOT IOS AND NOT MACOS_NE).
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include "MacServiceInstaller.h"
#include <QProcess>
#include <QThread>

namespace avpn {

bool macServiceInstalled()
{
    return [[NSFileManager defaultManager]
            fileExistsAtPath:@"/Library/LaunchDaemons/Tribe-service.plist"];
}

bool macServiceRunning()
{
    // pgrep -x Tribe-service (точное имя процесса демона). exitCode 0 = найден.
    QProcess p;
    p.start(QStringLiteral("/usr/bin/pgrep"), {QStringLiteral("-x"), QStringLiteral("Tribe-service")});
    if (!p.waitForFinished(3000))
        return false;
    return p.exitCode() == 0;
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

bool macInstallService(QString *errOut)
{
    @autoreleasepool {
        // Установщик + payload-tarball — РЕСУРСЫ app. Скрипт распаковывает tarball в /Library и
        // поднимает демон. Привилегии запрашиваем через Authorization Services (а НЕ osascript) —
        // тогда системное окно показывает «Tribe VPN» + НАШ понятный текст (что ставится VPN-служба),
        // а не пугающее «osascript хочет внести изменения».
        NSString *script = [[NSBundle mainBundle] pathForResource:@"tribe-svc-install" ofType:@"sh"];
        NSString *tar    = [[[NSBundle mainBundle] resourcePath]
            stringByAppendingPathComponent:@"tribe-svc.tar.gz"];
        if (script == nil || tar == nil
            || ![[NSFileManager defaultManager] fileExistsAtPath:script]
            || ![[NSFileManager defaultManager] fileExistsAtPath:tar]) {
            if (errOut) *errOut = QStringLiteral("Установщик службы VPN не найден в приложении");
            return false;
        }

        // Экранируем пути для shell (одинарные кавычки) и затем для строкового литерала AppleScript.
        auto shEsc = [](NSString *p) {  // ' → '\''  (безопасно внутри одинарных кавычек shell)
            return [p stringByReplacingOccurrencesOfString:@"'" withString:@"'\\''"];
        };
        NSString *shellCmd = [NSString stringWithFormat:@"/bin/bash '%@' '%@'",
                              shEsc(script), shEsc(tar)];
        NSString *shForAS = [shellCmd stringByReplacingOccurrencesOfString:@"\\" withString:@"\\\\"];
        shForAS = [shForAS stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];

        // NSAppleScript IN-PROCESS → запрос прав показывает «Tribe VPN» (а НЕ «osascript»), и
        // `do shell script ... with administrator privileges` НАДЁЖНО поднимает root (в отличие от
        // AuthorizationExecuteWithPrivileges, который на macOS 26 не элевейтит). Сначала — понятный
        // пояснительный диалог (что произойдёт), потом системное окно пароля.
        NSString *src = [NSString stringWithFormat:
            @"set q to button returned of (display dialog \"«Tribe VPN» установит системную службу VPN, "
             "необходимую для подключения. Сейчас потребуется пароль администратора Mac.\" "
             "with title \"Установка службы Tribe VPN\" buttons {\"Отмена\", \"Продолжить\"} "
             "default button \"Продолжить\" with icon note)\n"
             "if q is \"Продолжить\" then\n"
             "  do shell script \"%@\" with administrator privileges\n"
             "end if\n"
             "return q", shForAS];

        NSDictionary *asErr = nil;
        NSAppleScript *as = [[NSAppleScript alloc] initWithSource:src];
        NSAppleEventDescriptor *res = [as executeAndReturnError:&asErr];
        if (asErr != nil) {
            // -128 = пользователь отменил.
            NSNumber *code = asErr[@"NSAppleScriptErrorNumber"];
            if (errOut) *errOut = (code.intValue == -128)
                ? QStringLiteral("Установка службы VPN отменена")
                : QStringLiteral("Не удалось установить службу VPN (нет прав администратора)");
            return false;
        }
        if (res != nil && ![[res stringValue] isEqualToString:@"Продолжить"]) {
            if (errOut) *errOut = QStringLiteral("Установка службы VPN отменена");
            return false;
        }

        // Подтверждаем, что демон реально поднялся (postinstall bootstrap синхронен; ждём до ~5с).
        for (int i = 0; i < 16 && !macServiceRunning(); ++i)
            QThread::msleep(300);
        if (!macServiceRunning()) {
            if (errOut) *errOut = QStringLiteral("Служба VPN установлена, но не запустилась");
            return false;
        }
        return true;
    }
}

}
