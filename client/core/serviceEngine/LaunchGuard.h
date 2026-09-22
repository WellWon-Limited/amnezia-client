// client/core/serviceEngine/LaunchGuard.h
// AVPN (macOS self-update v2, 2026-09-22): безопасный запуск после обновления + откат.
// Спека: tribe-front docs/superpowers/specs/2026-09-22-macos-self-update-v2-design.md §2-§3.
//
// Инцидент 2026-09-22: 5.1.83 (112) упала через 2 с после старта на ВСЕХ устройствах — апдейтер
// доставил её штатно, а откатить было нечем (приложение падает раньше, чем читает конфиг).
// Теперь финишер апдейтера (SelfUpdate.cpp) СОХРАНЯЕТ предыдущую версию и пишет
// pending.json; новая версия обязана подтвердить «жива» (окно создано + конфиг прочитан или
// 15 с без падения). Нет подтверждения — откат: сторож финишера (≤40 с) или третий старт подряд
// без подтверждения (crash-loop). Откат — только на локальную ПРОВЕРЕННУЮ (codesign) копию,
// сеть не участвует. Восстановленная версия отправляет отчёт update_rollback (type:"crash").
//
// Два уровня, как в CrashGuard: namespace launchguard{} — чистая логика (header-only, только
// QtCore, тест tests/launch_guard_check.cpp); class LaunchGuard — фасад с IO/процессами под
// #ifdef (PLATFORM-SCOPING: реализация только для десктопного macOS, на остальных — no-op).
//
// Каталог состояния: <AppDataLocation>/update/
//   pending.json   {"from","to","app","installed_at","attempts","mode"} — пишет финишер
//   previous.app   сохранённая предыдущая версия (переезжает из transaction/previous.app)
//   previous.json  {"version","path","kept_at"}
//   confirmed      маркер «новая версия жива» (создаёт новая версия)
//   rollback.json  {"from","to","reason","attempts","mode","at"} — отчёт для сервера
//   rollback.sh    скрипт отката (перезаписывается из вкомпиленной константы на каждом старте)
//   failed.app     версия, с которой откатились (диагностика; чистится следующим обновлением)
#pragma once

#include <QByteArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMap>
#include <QString>
#include <QStringList>

namespace avpn {
namespace launchguard {

static constexpr int kMaxStartAttempts = 3;   // третий старт без подтверждения = crash-loop
static constexpr int kConfirmAfterMs = 15000; // окно есть и столько прожили — считаем живой

struct Pending
{
    QString from;       // версия до обновления
    QString to;         // установленная версия (ожидает подтверждения)
    QString app;        // путь установленного бандла (защита от чужой копии/dev-сборки)
    QString mode;       // "auto" | "manual"
    int     attempts = 0;
    qint64  installedAt = 0; // epoch s
    bool    valid = false;
};

inline Pending parsePending(const QByteArray &json)
{
    Pending p;
    const QJsonObject o = QJsonDocument::fromJson(json).object();
    if (o.isEmpty())
        return p;
    p.from = o.value(QStringLiteral("from")).toString();
    p.to = o.value(QStringLiteral("to")).toString();
    p.app = o.value(QStringLiteral("app")).toString();
    p.mode = o.value(QStringLiteral("mode")).toString(QStringLiteral("manual"));
    p.attempts = o.value(QStringLiteral("attempts")).toInt(0);
    p.installedAt = qint64(o.value(QStringLiteral("installed_at")).toDouble(0));
    p.valid = !p.to.isEmpty();
    return p;
}

inline QByteArray serializePending(const Pending &p)
{
    QJsonObject o;
    o.insert(QStringLiteral("from"), p.from);
    o.insert(QStringLiteral("to"), p.to);
    o.insert(QStringLiteral("app"), p.app);
    o.insert(QStringLiteral("mode"), p.mode);
    o.insert(QStringLiteral("attempts"), p.attempts);
    o.insert(QStringLiteral("installed_at"), double(p.installedAt));
    return QJsonDocument(o).toJson(QJsonDocument::Compact) + '\n';
}

enum class StartVerdict {
    NotPending, // обновления не было (или запись чужая/устаревшая — её надо снять)
    Continue,   // ждём подтверждения этим запуском (attempts уже увеличен)
    Rollback    // лимит запусков без подтверждения исчерпан
};

struct StartDecision
{
    StartVerdict verdict = StartVerdict::NotPending;
    Pending      pending;      // обновлённая запись (attempts+1) для Continue/Rollback
    bool         clearPending = false; // запись устарела — удалить файл
};

// Маркетинговая версия: первые три компонента («5.1.85.114» → «5.1.85»). pending.to пишет
// финишер из CFBundleShortVersionString (три компонента), APP_VERSION — четыре.
inline QString marketingVersion(const QString &v)
{
    const QStringList parts = v.split(QLatin1Char('.'));
    return parts.size() > 3 ? parts.mid(0, 3).join(QLatin1Char('.')) : v;
}

// Решение на старте. appPath пустой = не проверять путь (тесты/платформы без бандла).
inline StartDecision decideOnStart(const Pending &p, const QString &appVersion,
                                   const QString &appPath, int maxAttempts = kMaxStartAttempts)
{
    StartDecision d;
    d.pending = p;
    if (!p.valid)
        return d;
    // Ожидалась другая версия (уже откатились или человек поставил что-то руками) — запись стейл.
    if (marketingVersion(p.to) != marketingVersion(appVersion)
        || (!appPath.isEmpty() && !p.app.isEmpty() && p.app != appPath)) {
        d.clearPending = true;
        return d;
    }
    d.pending.attempts = p.attempts + 1;
    d.verdict = d.pending.attempts >= maxAttempts ? StartVerdict::Rollback : StartVerdict::Continue;
    return d;
}

struct RollbackReport
{
    QString from;     // версия, которая не запустилась
    QString to;       // версия, к которой вернулись
    QString reason;   // watchdog | crash_loop | blocked
    QString mode;     // auto | manual
    int     attempts = 0;
    qint64  at = 0;   // epoch s
    bool    valid = false;
};

inline RollbackReport parseRollbackReport(const QByteArray &json)
{
    RollbackReport r;
    const QJsonObject o = QJsonDocument::fromJson(json).object();
    if (o.isEmpty())
        return r;
    r.from = o.value(QStringLiteral("from")).toString();
    r.to = o.value(QStringLiteral("to")).toString();
    r.reason = o.value(QStringLiteral("reason")).toString();
    r.mode = o.value(QStringLiteral("mode")).toString();
    r.attempts = o.value(QStringLiteral("attempts")).toInt(0);
    r.at = qint64(o.value(QStringLiteral("at")).toDouble(0));
    r.valid = !r.to.isEmpty() && !r.reason.isEmpty();
    return r;
}

// Отчёт для /v1/bench/report — той же схемы, что краш-отчёты CrashGuard (type:"crash", schema 1),
// чтобы карточка Доктора в /panel показала его как «Краш — update_rollback» без правок бэка.
inline QJsonObject rollbackReportJson(const RollbackReport &r, const QString &build,
                                      const QString &platform, const QString &os)
{
    QJsonObject o;
    o.insert(QStringLiteral("type"), QStringLiteral("crash"));
    o.insert(QStringLiteral("schema"), 1);
    o.insert(QStringLiteral("subtype"), QStringLiteral("update_rollback"));
    o.insert(QStringLiteral("build"), build);
    o.insert(QStringLiteral("platform"), platform);
    o.insert(QStringLiteral("os"), os);
    o.insert(QStringLiteral("phase"), QStringLiteral("launch"));
    o.insert(QStringLiteral("from"), r.from);
    o.insert(QStringLiteral("to"), r.to);
    o.insert(QStringLiteral("reason"), r.reason);
    o.insert(QStringLiteral("mode"), r.mode);
    o.insert(QStringLiteral("attempts"), r.attempts);
    o.insert(QStringLiteral("at"), double(r.at));
    return o;
}

// Человеческий текст одноразового уведомления после отката (баннер главного экрана).
inline QString rollbackNoticeText(const RollbackReport &r)
{
    if (!r.valid)
        return {};
    if (r.reason == QLatin1String("blocked"))
        return QStringLiteral("Версия %1 отозвана — вернули %2.").arg(r.from, r.to);
    return QStringLiteral("Версия %1 не запустилась — вернули %2. Мы уже знаем.").arg(r.from, r.to);
}

} // namespace launchguard

#ifndef LAUNCHGUARD_PURE_LOGIC_ONLY

class LaunchGuard : public QObject
{
    Q_OBJECT
public:
    static LaunchGuard &instance();

    // Есть ли реализация на этой платформе (десктопный macOS). На остальных всё — no-op.
    static bool isSupported();
    // <AppDataLocation>/update
    static QString defaultStateDir();
    // Путь установленного бандла (…/Tribe VPN.app) или пусто, если процесс не в бандле.
    static QString installedAppPath();

    // ВЫЗЫВАТЬ ДО app.init()/QML (main.cpp): читает pending.json, увеличивает attempts.
    // true = лимит исчерпан, вызывающий обязан spawnRollback(...) и выйти из main.
    static bool startNeedsRollback(const QString &stateDir, const QString &appVersion,
                                   const QString &appPath);
    // Пишет rollback.sh в stateDir и запускает его отдельным процессом (nohup, ждёт выхода
    // parentPid ≤30 с, затем меняет бандл и открывает прежнюю версию). true = процесс запущен.
    static bool spawnRollback(const QString &stateDir, const QString &appPath, const QString &reason,
                              qint64 parentPid);

    // Штатная инициализация из движка (после старта): перезаписывает rollback.sh (0700),
    // забирает rollback.json прошлого запуска, читает previous.json.
    void install(const QString &stateDir, const QString &appVersion, const QString &appPath);
    // Хуки подтверждения: главное окно создано (objectCreated) + первый применённый конфиг ИЛИ
    // 15 с без падения после создания окна → confirm().
    void onMainWindowCreated();
    void onConfigApplied();
    void confirm();
    bool confirmedThisRun() const { return m_confirmed; }

    // Отчёт об откате прошлого запуска (одноразово; после take файл удалён).
    launchguard::RollbackReport takeRollbackReport();
    bool hasPrevious() const { return !m_previousVersion.isEmpty(); }
    QString previousVersion() const { return m_previousVersion; }
    QString previousAppPath() const { return m_previousPath; }
    QString stateDir() const { return m_stateDir; }
    QString rollbackScriptPath() const;

    // Откат по требованию (текущая версия отозвана сервером): запускает rollback.sh с нашим PID,
    // после чего вызывающий обязан завершить приложение. false = нечего/не удалось.
    bool rollbackToPrevious(const QString &reason);

signals:
    void confirmed();

private:
    explicit LaunchGuard(QObject *parent = nullptr);
    static bool writeRollbackScript(const QString &stateDir);
    void readPrevious();

    QString m_stateDir;
    QString m_appVersion;
    QString m_appPath;
    QString m_previousVersion;
    QString m_previousPath;
    bool    m_windowCreated = false;
    bool    m_configApplied = false;
    bool    m_confirmed = false;
};

#endif // LAUNCHGUARD_PURE_LOGIC_ONLY

} // namespace avpn
