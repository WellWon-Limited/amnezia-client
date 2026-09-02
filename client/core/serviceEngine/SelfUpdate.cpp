// AVPN (реш. владельца 2026-09-02): установка обновления внутри приложения на десктопном macOS.
// Логика установки живёт в шелл-скрипте, который пишется во временный файл на время работы:
// так её видно целиком одним куском (аудит), и она не требует изменений бандла/CMake-инсталла.
//
// Скрипт печатает строки вида "stage:<текст>" (прогресс) и "fail:<причина>" (отказ). Любой отказ —
// терминальный: приложение НЕ устанавливается, пользователю показывается причина.

#include "SelfUpdate.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
// QProcess есть не на всех наших платформах: в iOS-сборке Qt его нет вовсе, поэтому
// реализация установки компилируется только под десктопным macOS (PLATFORM-SCOPING.md).
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
#define AVPN_SELFUPDATE_IMPL 1
#include <QProcess>
#endif
#include <QStandardPaths>
#include <QTemporaryFile>
#include <QUrl>

namespace avpn {

namespace {

// Наш Team ID и bundle id — жёстко вкомпилены: они не данные, а часть доверия (backend-first §5).
constexpr const char *kTeamId = "Q7DVH5MCWF";
constexpr const char *kBundleId = "hk.wellwon.vpn";
constexpr const char *kDefaultDmgUrl = "https://tribevpn.com/dl/TribeVPN.dmg";
constexpr const char *kAllowedHostSuffix = "tribevpn.com";

// Скрипт установки. Аргументы: $1 = URL образа, $2 = текущая версия, $3 = Team ID, $4 = bundle id.
// Каждый шаг печатает стадию; любой провал печатает fail: и выходит с ненулевым кодом.
constexpr const char *kScript = R"SH(#!/bin/bash
set -u
set -o pipefail

url="$1"; cur="$2"; team="$3"; bid="$4"
app_dst="/Applications/Tribe VPN.app"
tmp="$(mktemp -d /tmp/tribe-update.XXXXXX)" || { echo "fail:Не удалось подготовить папку для загрузки"; exit 1; }
mnt=""

cleanup() {
  [ -n "$mnt" ] && hdiutil detach "$mnt" -quiet >/dev/null 2>&1
  rm -rf "$tmp"
}
trap cleanup EXIT

echo "stage:Скачиваем обновление"
if ! curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --retry-delay 2 --max-time 900 \
        -o "$tmp/Tribe.dmg" "$url"; then
  echo "fail:Не удалось скачать обновление. Проверьте соединение."
  exit 1
fi

echo "stage:Проверяем подпись"
mnt="$(hdiutil attach "$tmp/Tribe.dmg" -nobrowse -readonly -mountrandom /tmp 2>/dev/null \
      | awk -F'\t' '/\/tmp\//{print $NF}' | tail -1)"
if [ -z "$mnt" ] || [ ! -d "$mnt" ]; then
  echo "fail:Образ обновления повреждён"
  exit 1
fi

app_src="$(/usr/bin/find "$mnt" -maxdepth 1 -name '*.app' -print -quit)"
if [ -z "$app_src" ]; then
  echo "fail:В образе нет приложения"
  exit 1
fi

# Подпись нашей командой разработки.
if ! codesign --verify --deep --strict "$app_src" >/dev/null 2>&1; then
  echo "fail:Подпись обновления не прошла проверку"
  exit 1
fi
got_team="$(codesign -dv "$app_src" 2>&1 | awk -F= '/TeamIdentifier/{print $2}')"
if [ "$got_team" != "$team" ]; then
  echo "fail:Обновление подписано не нами"
  exit 1
fi
got_bid="$(/usr/libexec/PlistBuddy -c 'Print CFBundleIdentifier' "$app_src/Contents/Info.plist" 2>/dev/null)"
if [ "$got_bid" != "$bid" ]; then
  echo "fail:В образе другое приложение"
  exit 1
fi

# Нотаризация: Gatekeeper должен принять бандл для запуска.
if ! spctl -a -vv -t exec "$app_src" >/dev/null 2>&1; then
  echo "fail:Обновление не заверено Apple"
  exit 1
fi

new_ver="$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$app_src/Contents/Info.plist" 2>/dev/null)"
if [ -z "$new_ver" ]; then
  echo "fail:В образе не указана версия"
  exit 1
fi
# Строго новее текущей: сравниваем как версии, не как строки.
newest="$(printf '%s\n%s\n' "$cur" "$new_ver" | sort -V | tail -1)"
if [ "$new_ver" = "$cur" ] || [ "$newest" != "$new_ver" ]; then
  echo "fail:В образе не более новая версия"
  exit 1
fi

# Права на замену: без них честно отказываемся, а не портим установленную копию.
if [ -e "$app_dst" ] && [ ! -w "/Applications" ]; then
  echo "fail:Нет прав на замену приложения в папке «Программы»"
  exit 1
fi

echo "stage:Устанавливаем"
staged="$tmp/staged.app"
if ! ditto "$app_src" "$staged" >/dev/null 2>&1; then
  echo "fail:Не удалось подготовить установку"
  exit 1
fi

# Замена и перезапуск — уже после выхода приложения: отдельный процесс переживает наш quit.
runner="$tmp/finish.sh"
cat > "$runner" <<'INNER'
#!/bin/bash
set -u
staged="$1"; dst="$2"; parent="$3"; tmp="$4"
# Ждём выхода приложения (до 30 секунд), затем меняем бандл.
for _ in $(seq 1 60); do
  kill -0 "$parent" 2>/dev/null || break
  sleep 0.5
done
backup=""
if [ -e "$dst" ]; then
  backup="${dst%.app}.old.app"
  rm -rf "$backup"
  mv "$dst" "$backup" || exit 1
fi
if ! ditto "$staged" "$dst"; then
  # откат: возвращаем прежнюю копию, чтобы человек не остался без приложения
  [ -n "$backup" ] && rm -rf "$dst" && mv "$backup" "$dst"
  exit 1
fi
rm -rf "$backup"
open -a "$dst"
rm -rf "$tmp"
INNER
chmod +x "$runner"

# Скрипт замены не должен умереть вместе с нами и не должен удалить свою же папку раньше времени.
trap - EXIT
nohup "$runner" "$staged" "$app_dst" "$PPID" "$tmp" >/dev/null 2>&1 &
disown 2>/dev/null || true

echo "stage:Перезапускаем приложение"
echo "ok:$new_ver"
exit 0
)SH";

} // namespace

SelfUpdate::SelfUpdate(QObject *parent) : QObject(parent) {}

SelfUpdate::~SelfUpdate()
{
    if (!m_scriptPath.isEmpty())
        QFile::remove(m_scriptPath);
}

bool SelfUpdate::isSupported()
{
#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
    return true;
#else
    return false;
#endif
}

QString SelfUpdate::defaultDmgUrl()
{
    return QString::fromLatin1(kDefaultDmgUrl);
}

bool SelfUpdate::running() const
{
    return m_proc != nullptr;
}

void SelfUpdate::start(const QString &dmgUrl, const QString &currentVersion)
{
    if (!isSupported()) {
        emit failed(tr("Обновление внутри приложения тут недоступно"));
        return;
    }
    if (m_proc)   // повторный клик — не плодим второй загрузчик
        return;

    // Хост-гард: даже если конфиг подписан, URL обязан вести на наш домен по https.
    const QUrl url(dmgUrl.isEmpty() ? defaultDmgUrl() : dmgUrl);
    const bool hostOk = url.scheme() == QLatin1String("https")
                        && (url.host() == QLatin1String(kAllowedHostSuffix)
                            || url.host().endsWith(QLatin1String(".") + QLatin1String(kAllowedHostSuffix)));
    if (!hostOk) {
        emit failed(tr("Адрес обновления не прошёл проверку"));
        return;
    }

    // Скрипт кладём во временный файл на время установки (0700) и удаляем за собой.
    QTemporaryFile script(QDir::tempPath() + QStringLiteral("/tribe-update-XXXXXX.sh"));
    script.setAutoRemove(false);
    if (!script.open()) {
        emit failed(tr("Не удалось подготовить обновление"));
        return;
    }
    script.write(kScript);
    script.close();
    QFile::setPermissions(script.fileName(),
                          QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);
    m_scriptPath = script.fileName();

#ifdef AVPN_SELFUPDATE_IMPL
    m_proc = new QProcess(this);
    m_proc->setProcessChannelMode(QProcess::MergedChannels);

    connect(m_proc, &QProcess::readyReadStandardOutput, this, [this]() {
        while (m_proc && m_proc->canReadLine()) {
            const QString line = QString::fromUtf8(m_proc->readLine()).trimmed();
            if (line.startsWith(QLatin1String("stage:")))
                emit progress(line.mid(6));
            else if (line.startsWith(QLatin1String("fail:")))
                finish(line.mid(5));
        }
    });
    connect(m_proc, &QProcess::errorOccurred, this,
            [this](QProcess::ProcessError) { finish(tr("Не удалось запустить обновление")); });
    connect(m_proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
            [this](int code, QProcess::ExitStatus) {
                finish(code == 0 ? QString() : tr("Обновление не установилось"));
            });

    m_proc->start(QStringLiteral("/bin/bash"),
                  { m_scriptPath, url.toString(), currentVersion,
                    QString::fromLatin1(kTeamId), QString::fromLatin1(kBundleId) });
#else
    Q_UNUSED(currentVersion)
#endif
}

void SelfUpdate::cancel()
{
    if (!m_proc)
        return;
#ifdef AVPN_SELFUPDATE_IMPL
    m_proc->kill();
#endif
    finish(QString());
}

void SelfUpdate::finish(const QString &reason)
{
    if (!m_scriptPath.isEmpty()) {
        QFile::remove(m_scriptPath);
        m_scriptPath.clear();
    }
    if (m_proc) {
#ifdef AVPN_SELFUPDATE_IMPL
        m_proc->disconnect(this);
        m_proc->deleteLater();
#endif
        m_proc = nullptr;
    }
    if (reason.isEmpty())
        emit installed();
    else
        emit failed(reason);
}

} // namespace avpn
