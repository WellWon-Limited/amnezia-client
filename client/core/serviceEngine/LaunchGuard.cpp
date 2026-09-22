// client/core/serviceEngine/LaunchGuard.cpp
// AVPN (macOS self-update v2): IO/процессы фасада LaunchGuard. Чистая логика — в LaunchGuard.h.
// Реализация только для десктопного macOS (как SelfUpdate.cpp); на остальных платформах —
// no-op, чтобы общий serviceEngine собирался везде (PLATFORM-SCOPING.md).
#include "LaunchGuard.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QStandardPaths>
#include <QTimer>

#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
#define AVPN_LAUNCHGUARD_IMPL 1
#include <QProcess>
#endif

namespace avpn {

namespace {

constexpr const char *kTeamId = "Q7DVH5MCWF";
constexpr const char *kBundleId = "hk.wellwon.vpn";

// $1 установленный app, $2 каталог состояния, $3 причина, $4 PID приложения (0 = не ждать),
// $5 Team ID, $6 bundle id, $7 каталог журнала.
// Откат — ЕДИНСТВЕННЫЙ путь, где версия назначения ниже текущей; он не использует сеть:
// только локальная копия, прошедшая ту же проверку подписи/нотаризации, что и обновление.
constexpr const char *kRollbackScript = R"SH(#!/bin/bash
set -u
umask 077
dst="$1"; state="$2"; reason="$3"; parent="$4"; team="$5"; bid="$6"; log_dir="$7"
mkdir -p "$log_dir" 2>/dev/null
log="$log_dir/self-update.log"
exec >>"$log" 2>&1
date
echo "rollback: reason=$reason dst=$dst"

alert() {
  /usr/bin/osascript - "$1" <<'APPLESCRIPT'
on run argv
  display alert "Tribe VPN: не удалось вернуть предыдущую версию" message (item 1 of argv) as warning
end run
APPLESCRIPT
}
# Провал отката снимает pending: иначе следующий старт снова получит вердикт crash-loop, снова
# упадёт здесь же, и приложение перестанет запускаться вовсе (ревью 2026-09-22).
fail() {
  echo "rollback failed: $1"
  [ -f "$state/pending.json" ] && mv -f -- "$state/pending.json" "$state/pending.failed"
  alert "$1"
  exit 1
}

prev="$state/previous.app"
# Ссылка проходит codesign цели, но mv перенёс бы саму ссылку: содержимое можно подменить
# после проверки, а финишер обновлений отказывает ссылке навсегда.
[ -L "$prev" ] && fail "Сохранённая версия — ссылка, а не приложение. Скачайте Tribe VPN заново с tribevpn.com."
[ -d "$prev/Contents" ] || fail "Сохранённой предыдущей версии нет. Скачайте Tribe VPN заново с tribevpn.com."
case "$dst" in
  /Volumes/*|*/AppTranslocation/*) fail "Приложение запущено не из папки «Программы»" ;;
esac
[ -d "$dst/Contents" ] || fail "Установленное приложение не найдено"

# Та же проверка доверия, что у обновления: наша команда, наш bundle id, нотаризация Apple.
if ! codesign --verify --deep --strict \
    -R="anchor apple generic and certificate leaf[subject.OU] = \"$team\" and identifier \"$bid\"" \
    "$prev" >/dev/null; then
  fail "Сохранённая версия не прошла проверку подписи"
fi
got_bid="$(/usr/libexec/PlistBuddy -c 'Print CFBundleIdentifier' "$prev/Contents/Info.plist" 2>/dev/null)"
[ "$got_bid" = "$bid" ] || fail "Сохранённая версия — другое приложение"
if ! codesign --verify --check-notarization -R=notarized "$prev" >/dev/null; then
  fail "Сохранённая версия не заверена Apple"
fi
prev_ver="$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$prev/Contents/Info.plist" 2>/dev/null)"
cur_ver="$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$dst/Contents/Info.plist" 2>/dev/null)"
[ -n "$prev_ver" ] || fail "У сохранённой версии нет номера"
[ -n "$cur_ver" ] || cur_ver="unknown"

# Ждём выхода приложения (до 30 с) — под живым процессом бандл не меняем.
if [ "$parent" != "0" ]; then
  for _ in $(seq 1 60); do
    kill -0 "$parent" 2>/dev/null || break
    sleep 0.5
  done
  kill -0 "$parent" 2>/dev/null && fail "Приложение не завершилось. Закройте Tribe VPN и повторите."
fi

attempts="$(grep -oE '"attempts"[[:space:]]*:[[:space:]]*[0-9]+' "$state/pending.json" 2>/dev/null | grep -oE '[0-9]+$' | head -1)"
mode="$(grep -oE '"mode"[[:space:]]*:[[:space:]]*"[a-z]+"' "$state/pending.json" 2>/dev/null | grep -oE '[a-z]+"$' | tr -d '"' | head -1)"
[ -n "$attempts" ] || attempts=0
[ -n "$mode" ] || mode="unknown"

failed="$state/failed.app"
rm -rf -- "$failed"
mv -- "$dst" "$failed" || fail "Не удалось убрать текущую версию"
if ! mv -- "$prev" "$dst"; then
  mv -- "$failed" "$dst"
  fail "Не удалось вернуть предыдущую версию"
fi
printf '{"from":"%s","to":"%s","reason":"%s","attempts":%s,"mode":"%s","at":%s}\n' \
  "$cur_ver" "$prev_ver" "$reason" "$attempts" "$mode" "$(date +%s)" > "$state/rollback.json"
rm -f -- "$state/pending.json" "$state/previous.json" "$state/confirmed"
if ! open -n "$dst"; then
  fail "Прежняя версия $prev_ver возвращена, но не запустилась. Откройте Tribe VPN из папки «Программы»."
fi
echo "rollback ok: $cur_ver -> $prev_ver"
exit 0
)SH";

QString logDir()
{
    return QDir::homePath() + QStringLiteral("/Library/Logs/Tribe VPN");
}

} // namespace

LaunchGuard &LaunchGuard::instance()
{
    static LaunchGuard g;
    return g;
}

LaunchGuard::LaunchGuard(QObject *parent) : QObject(parent) {}

bool LaunchGuard::isSupported()
{
#ifdef AVPN_LAUNCHGUARD_IMPL
    return true;
#else
    return false;
#endif
}

QString LaunchGuard::defaultStateDir()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
           + QStringLiteral("/update");
}

QString LaunchGuard::installedAppPath()
{
#ifdef AVPN_LAUNCHGUARD_IMPL
    const QDir executableDir(QCoreApplication::applicationDirPath());
    const QString appPath = QDir::cleanPath(executableDir.absoluteFilePath(QStringLiteral("../..")));
    if (appPath.endsWith(QLatin1String(".app"))
        && QFileInfo::exists(appPath + QStringLiteral("/Contents/Info.plist")))
        return appPath;
#endif
    return {};
}

QString LaunchGuard::rollbackScriptPath() const
{
    return m_stateDir + QStringLiteral("/rollback.sh");
}

bool LaunchGuard::writeRollbackScript(const QString &stateDir)
{
    if (stateDir.isEmpty() || !QDir().mkpath(stateDir))
        return false;
    QSaveFile f(stateDir + QStringLiteral("/rollback.sh"));
    if (!f.open(QIODevice::WriteOnly))
        return false;
    f.write(kRollbackScript);
    f.setPermissions(QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);
    return f.commit();
}

bool LaunchGuard::startNeedsRollback(const QString &stateDir, const QString &appVersion,
                                     const QString &appPath)
{
#ifdef AVPN_LAUNCHGUARD_IMPL
    const QString pendingPath = stateDir + QStringLiteral("/pending.json");
    QFile pf(pendingPath);
    if (!pf.exists() || !pf.open(QIODevice::ReadOnly))
        return false;
    const launchguard::Pending p = launchguard::parsePending(pf.readAll());
    pf.close();
    const launchguard::StartDecision d = launchguard::decideOnStart(p, appVersion, appPath);
    if (d.clearPending) {
        QFile::remove(pendingPath);
        return false;
    }
    if (d.verdict == launchguard::StartVerdict::NotPending)
        return false;
    QSaveFile out(pendingPath);
    if (out.open(QIODevice::WriteOnly)) {
        out.write(launchguard::serializePending(d.pending));
        out.commit();
    }
    if (d.verdict == launchguard::StartVerdict::Rollback) {
        qWarning() << "[launchguard] version" << appVersion << "started" << d.pending.attempts
                   << "times without confirming — rolling back";
        return QFileInfo::exists(stateDir + QStringLiteral("/previous.app/Contents"));
    }
    return false;
#else
    Q_UNUSED(stateDir)
    Q_UNUSED(appVersion)
    Q_UNUSED(appPath)
    return false;
#endif
}

bool LaunchGuard::spawnRollback(const QString &stateDir, const QString &appPath, const QString &reason,
                                qint64 parentPid)
{
#ifdef AVPN_LAUNCHGUARD_IMPL
    if (appPath.isEmpty() || !writeRollbackScript(stateDir))
        return false;
    const QString script = stateDir + QStringLiteral("/rollback.sh");
    QProcess proc;
    proc.setProgram(QStringLiteral("/bin/bash"));
    proc.setArguments({ script, appPath, stateDir, reason, QString::number(parentPid),
                        QString::fromLatin1(kTeamId), QString::fromLatin1(kBundleId), logDir() });
    proc.setStandardInputFile(QProcess::nullDevice());
    proc.setStandardOutputFile(QProcess::nullDevice());
    proc.setStandardErrorFile(QProcess::nullDevice());
    qint64 pid = 0;
    const bool ok = proc.startDetached(&pid);
    qInfo() << "[launchguard] rollback spawned:" << ok << "pid" << pid << "reason" << reason;
    return ok;
#else
    Q_UNUSED(stateDir)
    Q_UNUSED(appPath)
    Q_UNUSED(reason)
    Q_UNUSED(parentPid)
    return false;
#endif
}

void LaunchGuard::install(const QString &stateDir, const QString &appVersion, const QString &appPath)
{
    m_stateDir = stateDir;
    m_appVersion = appVersion;
    m_appPath = appPath;
    if (!isSupported() || stateDir.isEmpty())
        return;
    if (!writeRollbackScript(stateDir))
        qWarning() << "[launchguard] cannot write rollback script into" << stateDir;
    readPrevious();
    // Старая failed.app (диагностика прошлого отката) живёт до следующего обновления — её
    // чистит финишер SelfUpdate; здесь ничего не удаляем.
}

void LaunchGuard::readPrevious()
{
    m_previousVersion.clear();
    m_previousPath.clear();
    QFile f(m_stateDir + QStringLiteral("/previous.json"));
    if (!f.open(QIODevice::ReadOnly))
        return;
    const QJsonObject o = QJsonDocument::fromJson(f.readAll()).object();
    const QString path = o.value(QStringLiteral("path")).toString();
    const QString ver = o.value(QStringLiteral("version")).toString();
    if (!path.isEmpty() && !ver.isEmpty()
        && QFileInfo::exists(path + QStringLiteral("/Contents/Info.plist"))) {
        m_previousPath = path;
        m_previousVersion = ver;
    }
}

void LaunchGuard::onMainWindowCreated()
{
    if (m_windowCreated)
        return;
    m_windowCreated = true;
    m_windowClock.start();
    QTimer::singleShot(m_configApplied ? launchguard::kConfirmMinAfterWindowMs : launchguard::kConfirmAfterMs,
                       this, [this] { confirm(); });
}

// Вызывается только на СВЕЖИЙ (сетевой) конфиг: LKG-кеш применяется синхронно ещё в
// конструкторе и подтверждал версию в момент создания окна (ревью 2026-09-22).
void LaunchGuard::onConfigApplied()
{
    if (m_configApplied)
        return;
    m_configApplied = true;
    if (!m_windowCreated)
        return; // окно ещё не создано — onMainWindowCreated выберет короткий срок
    const qint64 left = launchguard::kConfirmMinAfterWindowMs - m_windowClock.elapsed();
    QTimer::singleShot(int(qMax<qint64>(0, left)), this, [this] { confirm(); });
}

void LaunchGuard::confirm()
{
    if (m_confirmed)
        return;
    m_confirmed = true;
    if (!isSupported() || m_stateDir.isEmpty())
        return;
    const QString pendingPath = m_stateDir + QStringLiteral("/pending.json");
    if (QFile::exists(pendingPath)) {
        QFile marker(m_stateDir + QStringLiteral("/confirmed"));
        if (marker.open(QIODevice::WriteOnly))
            marker.write(m_appVersion.toUtf8() + '\n');
        QFile::remove(pendingPath);
        qInfo() << "[launchguard] version" << m_appVersion << "confirmed alive";
    }
    emit confirmed();
}

launchguard::RollbackReport LaunchGuard::takeRollbackReport()
{
    launchguard::RollbackReport r;
    if (m_stateDir.isEmpty())
        return r;
    const QString path = m_stateDir + QStringLiteral("/rollback.json");
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return r;
    r = launchguard::parseRollbackReport(f.readAll());
    f.close();
    QFile::remove(path);
    return r;
}

bool LaunchGuard::rollbackToPrevious(const QString &reason)
{
    if (!isSupported() || !hasPrevious() || m_appPath.isEmpty())
        return false;
    return spawnRollback(m_stateDir, m_appPath, reason, QCoreApplication::applicationPid());
}

} // namespace avpn
