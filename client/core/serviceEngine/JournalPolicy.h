// client/core/serviceEngine/JournalPolicy.h
//
// AVPN (журнал тестирования, Tribe-Backend docs/specs/2026-09-23-tester-journal-design.md):
// чистые решения журнала — кому виден/когда включён, разбор строк текстовых логов (Qt-лог
// приложения, ne.log туннеля) в JSON-события, сборка пачки по смещениям источников и обрезка
// уже отправленного лога. Только QtCore; покрыто tests/journal_policy_check.cpp. Сеть и UIKit —
// в TribeJournal.cpp.
#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QFile>
#include <QHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QList>
#include <QString>
#include <QTimeZone>

namespace avpn::journal {

// Пачка: до ~256 КБ прочитанного входа; JSON-обёртка коротких строк даёт не больше ~3× —
// с запасом под серверный кап 4 МиБ распакованного.
inline constexpr qint64 kBatchRawBytes = 256 * 1024;
// За один «сброс» — не больше стольких пачек (догоним на следующем).
inline constexpr int kMaxBatchesPerFlush = 12;
// Текстовый лог, отправленный целиком и выросший больше этого, обнуляется.
inline constexpr qint64 kTextLogCapBytes = 16 * 1024 * 1024;
// Выше этого лог обнуляется даже неотправленным (неделю без сети — лучше потерять, чем расти).
inline constexpr qint64 kTextLogHardCapBytes = 48 * 1024 * 1024;
// Структурный журнал ротируется в *.1 при этом размере.
inline constexpr qint64 kStructRotateBytes = 8 * 1024 * 1024;
// Кап одного сообщения в событии.
inline constexpr int kMaxMessageChars = 4000;

enum class TextFormat {
    Structured, // уже JSONL-события (журнал приложения)
    QtLog,      // "[yyyy-MM-dd hh:mm:ss.zzzZ] [LEVEL] app class : msg" — UTC
    NeLog,      // "yyyy-MM-dd HH:mm:ss level msg" — локальное время устройства
};

// Переключатель виден: сборка TestFlight, админ-устройство или включено удалённо из /panel.
inline bool journalVisible(bool testFlight, bool admin, bool forced)
{
    return testFlight || admin || forced;
}

// Журнал пишется: удалённое включение — всегда; выбор пользователя — пока переключатель ему виден.
inline bool journalEnabled(bool userOn, bool forced, bool visible)
{
    return forced || (userOn && visible);
}

inline QString isoUtcMs(const QDateTime &dt)
{
    return dt.toUTC().toString(QStringLiteral("yyyy-MM-ddTHH:mm:ss.zzzZ"));
}

// Время строки лога в ISO UTC с миллисекундами; пусто — строка без распознаваемого времени.
inline QString parseTimestamp(const QByteArray &line, TextFormat fmt, int utcOffsetSec)
{
    if (fmt == TextFormat::QtLog) {
        if (line.size() < 26 || line.at(0) != '[')
            return {};
        const QString s = QString::fromLatin1(line.mid(1, 23)); // yyyy-MM-dd hh:mm:ss.zzz
        QDateTime dt = QDateTime::fromString(s, QStringLiteral("yyyy-MM-dd hh:mm:ss.zzz"));
        if (!dt.isValid())
            return {};
        dt.setTimeZone(QTimeZone::UTC);
        return isoUtcMs(dt);
    }
    if (fmt == TextFormat::NeLog) {
        if (line.size() < 19)
            return {};
        const QString s = QString::fromLatin1(line.left(19)); // yyyy-MM-dd HH:mm:ss
        QDateTime dt = QDateTime::fromString(s, QStringLiteral("yyyy-MM-dd HH:mm:ss"));
        if (!dt.isValid())
            return {};
        dt.setTimeZone(QTimeZone::UTC);
        return isoUtcMs(dt.addSecs(-utcOffsetSec));
    }
    return {};
}

// Строка текстового лога → одна JSON-строка события (без '\n'); пустая строка → пусто.
inline QByteArray textLineToEvent(const QByteArray &rawLine, TextFormat fmt, const QString &src,
                                  int utcOffsetSec, const QString &fallbackIso)
{
    const QByteArray line = rawLine.trimmed();
    if (line.isEmpty())
        return {};
    QString t = parseTimestamp(line, fmt, utcOffsetSec);
    if (t.isEmpty())
        t = fallbackIso.isEmpty() ? isoUtcMs(QDateTime::currentDateTimeUtc()) : fallbackIso;
    QString msg = QString::fromUtf8(line);
    if (msg.size() > kMaxMessageChars)
        msg = msg.left(kMaxMessageChars) + QChar(0x2026);
    QJsonObject e;
    e.insert(QStringLiteral("t"), t);
    e.insert(QStringLiteral("src"), src);
    e.insert(QStringLiteral("ev"), QStringLiteral("log"));
    e.insert(QStringLiteral("msg"), msg);
    return QJsonDocument(e).toJson(QJsonDocument::Compact);
}

// Сохранённое смещение, если файл с тех пор не укоротился (ротация/обрезка → с начала).
inline qint64 effectiveOffset(qint64 stored, qint64 size)
{
    if (stored < 0 || stored > size)
        return 0;
    return stored;
}

// Сколько байт из прочитанного куска можно отдать: до последнего '\n' в пределах maxBytes.
// Одна строка длиннее maxBytes режется по капу — иначе источник встал бы навсегда.
inline qint64 completePrefix(const QByteArray &chunk, qint64 maxBytes)
{
    const qint64 limit = qMin<qint64>(chunk.size(), maxBytes);
    const qint64 nl = chunk.lastIndexOf('\n', limit - 1);
    if (nl >= 0)
        return nl + 1;
    if (chunk.size() > maxBytes)
        return maxBytes;
    return 0;
}

// Отправленный целиком большой лог — обнулить; сверх жёсткого капа — обнулить в любом случае.
inline bool shouldTruncate(qint64 size, qint64 sentOffset)
{
    return (sentOffset >= size && size > kTextLogCapBytes) || size > kTextLogHardCapBytes;
}

// Насколько лог может вырасти, пока журнал выключен, чтобы при повторном включении досылать
// неотправленное (при выключенном журнале нативный лог обычно не пишется вовсе).
inline constexpr qint64 kReenableGapBytes = 1024 * 1024;

// Смещение текстового лога при включении журнала. sizeAtDisable < 0 — метки выключения нет
// (первое включение): старую историю не шлём, смещение в конец. Повторное включение (выкл→вкл):
// строки, записанные пока журнал был включён и ещё не отправленные, досылаем — смещение остаётся,
// если за время выключения лог не укоротился и вырос не больше kReenableGapBytes; иначе — в конец.
// Разбор 25.09: выкл→вкл после двух неудачных досылок выбросил ночь ne.log.
inline qint64 offsetOnEnable(qint64 stored, qint64 sizeAtDisable, qint64 sizeNow)
{
    if (sizeAtDisable < 0 || sizeNow < sizeAtDisable || sizeNow - sizeAtDisable > kReenableGapBytes)
        return sizeNow;
    return effectiveOffset(stored, sizeNow);
}

struct JournalSource {
    QString key;       // ключ смещения (QSettings)
    QString path;      // файл
    TextFormat fmt;
    QString src;       // "app" | "ne" — поле src событий и тег пачки
};

struct BatchPlan {
    QByteArray jsonl;                   // события, по одному JSON на строку
    QHash<QString, qint64> newOffsets;  // смещения источников после этой пачки
    QString srcTag;                     // "app" | "ne" | "mix" — заголовок X-Journal-Source
    int events = 0;
};

// Собрать следующую пачку: источники по порядку, от их смещений, только полные строки, пока
// прочитанный вход не дорос до maxRaw байт. Смещения меняются только в плане — вызывающий
// применяет их после 2xx.
inline BatchPlan planBatch(const QList<JournalSource> &sources, const QHash<QString, qint64> &offsets,
                           qint64 maxRaw, int utcOffsetSec, const QString &nowIso)
{
    BatchPlan plan;
    bool sawApp = false, sawNe = false;
    qint64 consumed = 0;
    for (const JournalSource &s : sources) {
        if (consumed >= maxRaw)
            break;
        QFile f(s.path);
        if (!f.exists() || !f.open(QIODevice::ReadOnly))
            continue;
        const qint64 size = f.size();
        const qint64 from = effectiveOffset(offsets.value(s.key, 0), size);
        if (from >= size)
            continue;
        f.seek(from);
        const qint64 budget = maxRaw - consumed;
        // +1 байт: строка длиннее бюджета должна резаться по капу, а не «ждать» вечно.
        const QByteArray chunk = f.read(qMin<qint64>(size - from, budget + 1));
        const qint64 take = completePrefix(chunk, budget);
        if (take <= 0)
            continue;
        QString lastTs = nowIso;
        int added = 0;
        for (const QByteArray &line : chunk.left(take).split('\n')) {
            QByteArray ev;
            if (s.fmt == TextFormat::Structured) {
                const QJsonDocument doc = QJsonDocument::fromJson(line.trimmed());
                if (!doc.isObject() || !doc.object().value(QStringLiteral("t")).isString())
                    continue; // мусор/обрывок — пропускаем, но смещение его «съедает»
                ev = line.trimmed();
            } else {
                const QString t = parseTimestamp(line.trimmed(), s.fmt, utcOffsetSec);
                if (!t.isEmpty())
                    lastTs = t;
                ev = textLineToEvent(line, s.fmt, s.src, utcOffsetSec, lastTs);
                if (ev.isEmpty())
                    continue;
            }
            plan.jsonl += ev;
            plan.jsonl += '\n';
            ++added;
        }
        plan.newOffsets.insert(s.key, from + take);
        consumed += take;
        if (added > 0) {
            plan.events += added;
            (s.src == QLatin1String("ne") ? sawNe : sawApp) = true;
        }
    }
    plan.srcTag = sawApp && sawNe ? QStringLiteral("mix") : sawNe ? QStringLiteral("ne") : QStringLiteral("app");
    return plan;
}

} // namespace avpn::journal
