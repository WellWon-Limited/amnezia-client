#pragma once
#include <QCryptographicHash>
#include <QJsonArray>
#include <QStringList>
#include <QJsonDocument>
#include <QJsonObject>
#include <QUuid>

namespace avpn {
inline QString reportContentId(const QByteArray &body)
{
    return QString::fromLatin1(QCryptographicHash::hash(body, QCryptographicHash::Sha256).toHex());
}
inline QString reportAcknowledgement(int status, bool transportOk, const QByteArray &body)
{
    if (!transportOk || status < 200 || status >= 300) return {};
    const QString id = QJsonDocument::fromJson(body).object().value(QStringLiteral("id")).toString();
    return QUuid(id).isNull() ? QString() : id;
}

// AVPN (фикс-волна 2026-09-22, A12): исход отправки отчёта из outbox.
//  Delivered    — 2xx с квитанцией (id-UUID): удалить файл, запомнить хэш.
//  DropTerminal — терминальный 4xx (кроме 408 таймаут, 429 лимит и 401 — токен ротируется
//                 bootstrap-самохилом, следующий flush уйдёт со свежим): повтор бессмыслен, файл
//                 удаляется, иначе outbox вечно пересылает 400/404/413 на каждом Connected.
//  Retry        — сеть/5xx/408/429/401/2xx без квитанции: файл остаётся в ограниченном outbox.
enum class ReportOutcome { Delivered, Retry, DropTerminal };
inline ReportOutcome classifyReportResponse(int status, bool transportOk, const QByteArray &body)
{
    if (!reportAcknowledgement(status, transportOk, body).isEmpty())
        return ReportOutcome::Delivered;
    if (status >= 400 && status < 500 && status != 408 && status != 429 && status != 401)
        return ReportOutcome::DropTerminal;
    return ReportOutcome::Retry;
}
// Пересылка outbox по фронту Connected — не чаще раза в minGapMs (10 мин); lastMs<0 = ещё не было.
inline bool outboxConnectedFlushDue(qint64 lastFlushMs, qint64 nowMs, qint64 minGapMs = 600000)
{
    return lastFlushMs < 0 || nowMs - lastFlushMs >= minGapMs;
}
// Критик полноты (U10, жалоба 2 «сам выключается»): отчёты Доктора и краша несут журнал свитчей
// движка и кольцо reliability-переходов фасада (кто и почему гасил туннель: guarded_stop why=...).
// Берём ХВОСТ (самые свежие строки) в пределах байтового капа — отчёт не раздувается.
inline QStringList tailWithinBytes(const QStringList &lines, int maxBytes)
{
    QStringList out;
    int total = 0;
    for (int i = lines.size() - 1; i >= 0; --i) {
        const int n = lines.at(i).toUtf8().size() + 1;
        if (total + n > maxBytes)
            break;
        total += n;
        out.prepend(lines.at(i));
    }
    return out;
}
inline void attachReliabilityContext(QJsonObject &o, const QStringList &switchLog,
                                     const QStringList &reliabilityRing,
                                     int maxSwitchLogBytes = 4096, int maxRingBytes = 12288)
{
    o.insert(QStringLiteral("switch_log"),
             QJsonArray::fromStringList(tailWithinBytes(switchLog, maxSwitchLogBytes)));
    o.insert(QStringLiteral("reliability_ring"),
             QJsonArray::fromStringList(tailWithinBytes(reliabilityRing, maxRingBytes)));
}
} // namespace avpn
