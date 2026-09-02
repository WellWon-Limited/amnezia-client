// client/core/serviceEngine/TribeDiagReport.h
// AVPN backend-first-3 (Task 4): сборщик ЕДИНОГО text/plain диагностического отчёта для чата
// поддержки. Две секции: "=== TRIBE DIAG v1 ===" (compact-JSON снапшот: версия/платформа/состояние/
// подписка/пул с RTT/switchLog/байпас) + "=== LOG TAIL ===" (хвост лог-файла приложения <= 256 КБ,
// выровнен по началу строки). Header-only (стиль DebugSnapshot.h/TuningStore.h), тестируется без
// движка (tests/test_diag_report.cpp). Секреты (privkey/subscription token/push token) в снапшот
// НЕ попадают by construction (инвариант DebugSnapshot.h); лог не фильтруем — маскирует сам Logger
// (Logger::sensitive). Итог клампится kMaxReportBytes (2 МБ - 4 КБ): режется НАЧАЛО лог-хвоста
// (свежие строки в конце ценнее), JSON-секция цела всегда.
#pragma once

#include "DebugSnapshot.h"

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

namespace avpn {

// Контекст, который движок не знает сам (версия/платформа/язык — от фасада AvpnEngineQml).
struct DiagMeta {
    QString appVersion;              // tribe_version (как в bench: QCoreApplication::applicationVersion())
    QString platform;                // QSysInfo::productType() + productVersion()
    QString lang;                    // язык приложения (appLang)
    qint64  configAppliedAgeSec = -1; // возраст последнего configApplied; < 0 = неизвестен → ключ опущен
};

class TribeDiagReport
{
public:
    // Кламп итогового отчёта: лимит вложения 2 МБ минус 4 КБ на заголовки/обвязку транспорта.
    static constexpr qint64 kMaxReportBytes = 2 * 1024 * 1024 - 4 * 1024;
    // Кап хвоста лог-файла при чтении с диска.
    static constexpr qint64 kLogTailCapBytes = 256 * 1024;

    // Хвост лог-файла: open → size → seek(max(0, size-cap)) → readAll; если резали — выровнять
    // по началу следующей строки (обрывок первой строки отбрасывается). Нет файла → пусто.
    static QString readLogTail(const QString &path, qint64 capBytes = kLogTailCapBytes)
    {
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly))
            return {};
        const qint64 size = f.size();
        const qint64 from = qMax<qint64>(0, size - capBytes);
        f.seek(from);
        QByteArray tail = f.readAll();
        if (from > 0)
            tail = alignToLineStart(tail);
        return QString::fromUtf8(tail);
    }

    // Единый отчёт: JSON-снапшот + лог-хвост. bypassMasterOn читается снаружи (QSettings в
    // QML-домене — applyRuBypassSplit) и передаётся параметром. Кламп: при превышении
    // kMaxReportBytes режется начало лог-хвоста (не JSON), с выравниванием по строке.
    static QString build(const DebugSnapshot &s, bool bypassMasterOn, const QString &logTail,
                         const DiagMeta &meta = {})
    {
        QJsonObject o;
        o.insert(QStringLiteral("app_version"), meta.appVersion);
        o.insert(QStringLiteral("platform"), meta.platform);
        o.insert(QStringLiteral("lang"), meta.lang);
        o.insert(QStringLiteral("state"), s.state);
        o.insert(QStringLiteral("currentNodeId"), s.currentNodeId);
        o.insert(QStringLiteral("handshakeAgeSec"), double(s.latestHandshakeAgeSec));
        o.insert(QStringLiteral("rxBytes"), double(s.rxBytes));
        o.insert(QStringLiteral("txBytes"), double(s.txBytes));
        o.insert(QStringLiteral("subStatus"), s.subStatus);
        o.insert(QStringLiteral("expiresAt"), s.expiresAt);
        o.insert(QStringLiteral("graceUntil"), s.graceUntil);
        o.insert(QStringLiteral("trafficUsed"), double(s.trafficUsed));
        o.insert(QStringLiteral("trafficLimit"), double(s.trafficLimit));
        o.insert(QStringLiteral("lkgStale"), s.lkgStale);
        o.insert(QStringLiteral("bypassMasterOn"), bypassMasterOn);
        o.insert(QStringLiteral("bypassListVersion"), s.bypassListVersion);
        if (meta.configAppliedAgeSec >= 0)
            o.insert(QStringLiteral("configAppliedAgeSec"), double(meta.configAppliedAgeSec));
        // AVPN awg31-xray-v1 (§2.3 «отчёт содержит proto»): транспорт текущей ноды, ручной режим,
        // фаза verifying, ревизия пула — поддержка видит, каким транспортом шёл пользователь.
        o.insert(QStringLiteral("activeProto"), s.activeProto);
        o.insert(QStringLiteral("transportMode"), s.transportMode);
        o.insert(QStringLiteral("verifying"), s.verifying);
        o.insert(QStringLiteral("poolRevision"), double(s.poolRevision));

        QJsonArray pool;
        for (const NodeDebugRow &r : s.pool) {
            QJsonObject n;
            n.insert(QStringLiteral("id"), r.nodeId);
            n.insert(QStringLiteral("region"), r.region);
            n.insert(QStringLiteral("countryCode"), r.countryCode);
            n.insert(QStringLiteral("endpoint"), r.endpoint);
            n.insert(QStringLiteral("proto"), r.proto);
            n.insert(QStringLiteral("protoVersion"), r.protoVersion);
            n.insert(QStringLiteral("hostId"), r.hostId);              // AVPN awg31-xray-v1: локация
            n.insert(QStringLiteral("location"), r.location);
            n.insert(QStringLiteral("transportRank"), r.transportRank);
            n.insert(QStringLiteral("transportSupported"), r.transportSupported);
            n.insert(QStringLiteral("weight"), r.weight);
            n.insert(QStringLiteral("healthAgg"), r.healthAgg);
            n.insert(QStringLiteral("rttMs"), r.scoreMs); // измеренный off-tunnel ICMP RTT (0 = нет замера)
            n.insert(QStringLiteral("alive"), r.alive);
            n.insert(QStringLiteral("current"), r.current);
            n.insert(QStringLiteral("reason"), r.reason);
            pool.append(n);
        }
        o.insert(QStringLiteral("pool"), pool);
        o.insert(QStringLiteral("switchLog"), QJsonArray::fromStringList(s.switchLog));

        const QString head = QStringLiteral("=== TRIBE DIAG v1 ===\n")
            + QString::fromUtf8(QJsonDocument(o).toJson(QJsonDocument::Compact))
            + QStringLiteral("\n\n=== LOG TAIL ===\n");

        // Кламп: бюджет лога = лимит минус JSON-часть; режем НАЧАЛО хвоста (свежее — в конце).
        QByteArray tailUtf8 = logTail.toUtf8();
        const qint64 budget = kMaxReportBytes - head.toUtf8().size();
        if (budget <= 0)
            tailUtf8.clear();
        else if (tailUtf8.size() > budget)
            tailUtf8 = alignToLineStart(tailUtf8.right(int(budget)));
        return head + QString::fromUtf8(tailUtf8);
    }

private:
    // Обрывок первой строки после среза → отбросить до следующего '\n' (нет '\n' → как есть:
    // лучше обрывок, чем пустой лог).
    static QByteArray alignToLineStart(const QByteArray &tail)
    {
        const int nl = tail.indexOf('\n');
        return (nl >= 0 && nl + 1 < tail.size()) ? tail.mid(nl + 1) : tail;
    }
};

} // namespace avpn
