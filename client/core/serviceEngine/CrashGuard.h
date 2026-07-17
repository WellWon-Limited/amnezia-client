// client/core/serviceEngine/CrashGuard.h
// AVPN (наблюдаемость, волна CR-1) — свой краш-репортинг БЕЗ сторонних SDK (спека
// docs/superpowers/specs/2026-07-17-observability-crash-telemetry-design.md §1). Overlay-файл,
// апстрим не трогаем; вся платформенщина — под #ifdef в CrashGuard.cpp (PLATFORM-SCOPING).
//
// Два уровня:
//  1) namespace crashguard{} — ЧИСТАЯ логика (header-only, только QtCore): парс/сборка sentinel,
//     классификация subtype, кодирование/парс signal.bin, скраб лог-хвоста, сборка JSON-отчёта
//     схемы §1.3. Тестируется standalone (tests/crash_guard_check.cpp), как DoctorReport.h.
//  2) class CrashGuard — фасад с платформенными хендлерами (реализация в .cpp). Async-signal-safe
//     сигнал-хендлеры (заранее открытый fd, только write(); никакого malloc/Qt в хендлере).
//
// iOS/macOS: mach-исключения НЕ ловим (конфликт с системным репортером) — только POSIX-сигналы +
// sentinel. dirty_exit шлём ТОЛЬКО на десктопах (на iOS/Android ОС штатно убивает фон → шум,
// там лишь локальный счётчик dirty_exits_since_last в следующий отчёт).
#pragma once

#include <QByteArray>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QList>
#include <QRegularExpression>
#include <QString>
#include <QStringList>

#include <cstdint>
#include <cstring>

namespace crashguard {

// ── Константы схемы/клампов ────────────────────────────────────────────────────────────────────
static constexpr int      kSchema = 1;              // §1.3 схема отчёта type:"crash"
static constexpr qint64   kLogTailCapBytes = 16 * 1024; // §0.3 лог-хвост <= 16 КБ
static constexpr int      kMaxFrames = 32;          // §1.1 до 32 адресов backtrace()
static constexpr int      kMaxPending = 3;          // §1.1 не копить больше 3 неотправленных

// ── Sentinel (crash/running.json) ──────────────────────────────────────────────────────────────
struct Sentinel {
    bool    valid = false;
    QString build;
    QString platform;
    QString os;
    QString phase;
    qint64  uptimeS = 0;
    qint64  startedMs = 0;              // epoch ms на момент install (для пересчёта uptime в heartbeat)
    int     dirtyExitsSinceLast = 0;    // накопленный локальный счётчик (мобилки)
};

inline QByteArray buildSentinel(const Sentinel &s)
{
    QJsonObject o;
    o.insert(QStringLiteral("build"), s.build);
    o.insert(QStringLiteral("platform"), s.platform);
    o.insert(QStringLiteral("os"), s.os);
    o.insert(QStringLiteral("phase"), s.phase);
    o.insert(QStringLiteral("uptime_s"), double(s.uptimeS));
    o.insert(QStringLiteral("started_ms"), double(s.startedMs));
    o.insert(QStringLiteral("dirty_exits_since_last"), s.dirtyExitsSinceLast);
    return QJsonDocument(o).toJson(QJsonDocument::Compact);
}

inline Sentinel parseSentinel(const QByteArray &json)
{
    Sentinel s;
    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(json, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return s; // valid=false
    const QJsonObject o = doc.object();
    // Минимальный признак валидности: есть build (иначе это не наш sentinel).
    if (!o.contains(QStringLiteral("build")))
        return s;
    s.valid    = true;
    s.build    = o.value(QStringLiteral("build")).toString();
    s.platform = o.value(QStringLiteral("platform")).toString();
    s.os       = o.value(QStringLiteral("os")).toString();
    s.phase    = o.value(QStringLiteral("phase")).toString();
    s.uptimeS  = qint64(o.value(QStringLiteral("uptime_s")).toDouble());
    s.startedMs = qint64(o.value(QStringLiteral("started_ms")).toDouble());
    s.dirtyExitsSinceLast = o.value(QStringLiteral("dirty_exits_since_last")).toInt();
    return s;
}

// ── Классификация subtype ──────────────────────────────────────────────────────────────────────
enum class Subtype { None, Signal, DirtyExit, Java, Seh };

inline QString subtypeName(Subtype t)
{
    switch (t) {
    case Subtype::Signal:    return QStringLiteral("signal");
    case Subtype::DirtyExit: return QStringLiteral("dirty_exit");
    case Subtype::Java:      return QStringLiteral("java");
    case Subtype::Seh:       return QStringLiteral("seh");
    case Subtype::None:      break;
    }
    return QString();
}

// Приоритет улик прошлого запуска: нативный сигнал важнее Java-исключения (сигнал = падение
// процесса), SEH — Windows-ветка. Только sentinel (без улик) → dirty_exit. Нет sentinel → None
// (чистый выход удаляет sentinel; отсутствие = штатно, отчёта нет).
inline Subtype classify(bool hasSignal, bool hasJava, bool hasSeh, bool hasSentinel)
{
    if (hasSignal) return Subtype::Signal;
    if (hasSeh)    return Subtype::Seh;
    if (hasJava)   return Subtype::Java;
    if (hasSentinel) return Subtype::DirtyExit;
    return Subtype::None;
}

// dirty_exit шлём ТОЛЬКО на десктопах; на мобилках (isDesktop=false) — лишь счётчик, отчёта нет.
// Signal/Java/Seh шлём на всех платформах.
inline bool shouldEmitReport(Subtype t, bool isDesktop)
{
    if (t == Subtype::None) return false;
    if (t == Subtype::DirtyExit) return isDesktop;
    return true;
}

// ── signal.bin (async-signal-safe бинарь) ──────────────────────────────────────────────────────
// Фикс-layout, little-endian (все наши таргеты — arm64/x64 LE). Пишется в хендлере одним write();
// парсится на следующем старте. kind: 0 = POSIX-сигнал, 1 = Windows SEH.
struct SignalInfo {
    bool            valid = false;
    int             kind = 0;         // 0 signal, 1 seh
    quint32         signalOrCode = 0; // номер сигнала или код SEH-исключения
    quint64         faultAddr = 0;
    quint64         imageBase = 0;
    QList<quint64>  frames;
};

// Заголовок: magic(4) kind(1) pad(3) code(u32) pad(4) faultAddr(u64) imageBase(u64) frameCount(u32) pad(4)
static constexpr int kSigHeaderBytes = 4 + 1 + 3 + 4 + 4 + 8 + 8 + 4 + 4; // = 40
static constexpr char kSigMagic[4] = { 'C', 'G', 'S', '1' };

// Кодировщик — общий для теста и для справки; в самом сигнал-хендлере используется РУЧНАЯ
// сборка через memcpy в статический буфер (async-signal-safe), но layout ИДЕНТИЧЕН этому.
inline QByteArray encodeSignalBin(const SignalInfo &si)
{
    const quint32 n = quint32(qMin(si.frames.size(), kMaxFrames));
    QByteArray b(kSigHeaderBytes + int(n) * 8, '\0');
    char *p = b.data();
    std::memcpy(p + 0, kSigMagic, 4);
    p[4] = char(si.kind);
    std::memcpy(p + 8, &si.signalOrCode, 4);
    std::memcpy(p + 16, &si.faultAddr, 8);
    std::memcpy(p + 24, &si.imageBase, 8);
    std::memcpy(p + 32, &n, 4);
    for (quint32 i = 0; i < n; ++i) {
        const quint64 f = quint64(si.frames.at(int(i)));
        std::memcpy(p + kSigHeaderBytes + int(i) * 8, &f, 8);
    }
    return b;
}

inline SignalInfo parseSignalBin(const QByteArray &b)
{
    SignalInfo si;
    if (b.size() < kSigHeaderBytes)
        return si;
    if (std::memcmp(b.constData(), kSigMagic, 4) != 0)
        return si;
    const char *p = b.constData();
    si.kind = int(quint8(p[4]));
    std::memcpy(&si.signalOrCode, p + 8, 4);
    std::memcpy(&si.faultAddr, p + 16, 8);
    std::memcpy(&si.imageBase, p + 24, 8);
    quint32 n = 0;
    std::memcpy(&n, p + 32, 4);
    if (n > quint32(kMaxFrames)) n = kMaxFrames;
    const int need = kSigHeaderBytes + int(n) * 8;
    if (b.size() < need)
        return si; // усечённый файл (краш во время write) — читаем что смогли ниже
    for (quint32 i = 0; i < n; ++i) {
        quint64 f = 0;
        std::memcpy(&f, p + kSigHeaderBytes + int(i) * 8, 8);
        si.frames.append(f);
    }
    si.valid = true;
    return si;
}

inline QString hex(quint64 v)
{
    return QStringLiteral("0x") + QString::number(v, 16);
}

// ── Скраб лог-хвоста ───────────────────────────────────────────────────────────────────────────
// Тот же принцип, что диаг-отчёт (урок TuningStore: секреты в лог не пишем, фильтр перед отправкой
// обязателен). Режем: Bearer-токены, JWT (eyJ...), строки PrivateKey/PresharedKey/*_key/token/
// secret/password/authorization и «голые» base64-ключи WireGuard (44 симв. с '=').
inline QString scrubLogTail(const QString &in)
{
    QString s = in;
    // 1) Bearer <token>
    s.replace(QRegularExpression(QStringLiteral("Bearer\\s+[A-Za-z0-9._~+/=-]+")),
              QStringLiteral("Bearer <redacted>"));
    // 2) JWT (три base64url-сегмента через точку)
    s.replace(QRegularExpression(QStringLiteral("eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")),
              QStringLiteral("<jwt-redacted>"));
    // 3) key/value секреты: <ключ> = <значение> и <ключ>: <значение> (в т.ч. в кавычках/JSON)
    // (Authorization: Bearer ... уже покрыт правилом 1 выше — сюда «authorization» не включаем,
    // иначе съест сам маркер «Bearer <redacted>».)
    s.replace(QRegularExpression(
                  QStringLiteral("(?i)(private_?key|preshared_?key|client_priv_key|api[_-]?key|"
                                 "auth[_-]?token|subscription_token|access_?token|secret|password|"
                                 "token)(\"?\\s*[=:]\\s*\"?)([A-Za-z0-9._~+/=-]{6,})")),
              QStringLiteral("\\1\\2<redacted>"));
    // 4) «голый» base64-ключ WireGuard (44 символа, оканчивается '=')
    s.replace(QRegularExpression(QStringLiteral("\\b[A-Za-z0-9+/]{42,43}=\\b")),
              QStringLiteral("<key-redacted>"));
    return s;
}

// Кламп хвоста до kLogTailCapBytes: берём КОНЕЦ (свежие строки ценнее), выравниваем по началу
// строки (обрывок первой строки отбрасываем). Скраб — ДО клампа (порядок не важен, скраб
// построчный). Вызывать: clampLogTail(scrubLogTail(raw)).
inline QString clampLogTail(const QString &in, qint64 capBytes = kLogTailCapBytes)
{
    QByteArray u = in.toUtf8();
    if (u.size() <= capBytes)
        return in;
    u = u.right(int(capBytes));
    const int nl = u.indexOf('\n');
    if (nl >= 0 && nl + 1 < u.size())
        u = u.mid(nl + 1);
    return QString::fromUtf8(u);
}

// ── Сборка отчёта (§1.3 схема v1) ──────────────────────────────────────────────────────────────
// sig != nullptr для subtype signal/seh; javaStack непуст для subtype java (уже скрабнут снаружи).
// logTail — уже скрабнутый и склампленный. dirtyExits — накопленный локальный счётчик.
inline QJsonObject buildReport(Subtype subtype, const Sentinel &sen, const SignalInfo *sig,
                               const QString &logTail, int dirtyExits,
                               const QString &javaStack = QString())
{
    QJsonObject o;
    o.insert(QStringLiteral("type"), QStringLiteral("crash"));
    o.insert(QStringLiteral("schema"), kSchema);
    o.insert(QStringLiteral("subtype"), subtypeName(subtype));
    o.insert(QStringLiteral("build"), sen.build);
    o.insert(QStringLiteral("platform"), sen.platform);
    o.insert(QStringLiteral("os"), sen.os);
    o.insert(QStringLiteral("phase"), sen.phase);
    o.insert(QStringLiteral("uptime_s"), double(sen.uptimeS));
    o.insert(QStringLiteral("dirty_exits_since_last"), dirtyExits);

    if (sig && sig->valid) {
        if (sig->kind == 1)
            o.insert(QStringLiteral("seh_code"), hex(sig->signalOrCode));
        else
            o.insert(QStringLiteral("signal"), int(sig->signalOrCode));
        o.insert(QStringLiteral("fault_addr"), hex(sig->faultAddr));
        o.insert(QStringLiteral("image_base"), hex(sig->imageBase));
        QJsonArray fr;
        for (quint64 f : sig->frames)
            fr.append(hex(f));
        o.insert(QStringLiteral("frames"), fr);
    }
    if (!javaStack.isEmpty())
        o.insert(QStringLiteral("java_stack"), javaStack); // backend хранит opaque JSON — доп. поле ок
    if (!logTail.isEmpty())
        o.insert(QStringLiteral("log_tail"), logTail);
    return o;
}

} // namespace crashguard


// ═══════════════════════════════════════════════════════════════════════════════════════════════
// Фасад CrashGuard — платформенные хендлеры + жизненный цикл (реализация в CrashGuard.cpp).
// Самодостаточный API (движок дёргает эти методы; см. wiring-инструкцию волны CR-1).
// ═══════════════════════════════════════════════════════════════════════════════════════════════
#ifndef CRASHGUARD_PURE_LOGIC_ONLY   // юнит-тест собирает только namespace crashguard (без .cpp/QtGui)

#include <QObject>

class CrashGuard : public QObject
{
    Q_OBJECT
public:
    static CrashGuard &instance();

    // Установка: вычисляет пути (dirPath/{running.json,signal.bin,seh.bin,java.txt,tail.txt,pending/}),
    // СНАЧАЛА классифицирует прошлый запуск (строит pending-отчёт, если была улика), затем пишет
    // свежий sentinel, заранее открывает fd под signal.bin и ставит сигнал-хендлеры. Идемпотентна.
    // buildStr — версия (tribe_version), platform/os — от фасада (QSysInfo).
    void install(const QString &dirPath, const QString &buildStr,
                 const QString &platform, const QString &os);

    // Обновить фазу (idle/connecting/connected/doctor/bench). const char* — чтобы можно было звать
    // из околосигнальных мест; строка копируется под мьютексом, sentinel НЕ переписывается тут
    // (перепишется на ближайшем heartbeat). async-signal-safe НЕ гарантируется — не звать из хендлера.
    void setPhase(const char *phase);

    // Периодический тик (раз в ~30с): пересчитать uptime_s, переписать sentinel, сбросить лог-хвост
    // из внутреннего ring в tail.txt. Движок вешает на QTimer.
    void heartbeat();

    // Наполнение внутреннего ring-буфера лог-хвоста из внешнего qInstallMessageHandler'а движка.
    // Потокобезопасно, дёшево (только push в кольцо). Хвост уходит в tail.txt на heartbeat.
    void appendLogLine(const QString &line);

    // Неотправленные краш-отчёты прошлых запусков (<= 3). Каждый объект несёт служебный ключ
    // "_pending_id" — движок ОБЯЗАН удалить его перед POST и вернуть в markSent(id) после успеха.
    QList<QJsonObject> takePendingReports();

    // Отметить отчёт отправленным — удаляет pending/<id>.json.
    void markSent(const QString &pendingId);

    // Накопленный локальный счётчик dirty_exit (мобилки): движок может прицепить к отчёту Доктора.
    int  dirtyExitCount() const;
    void resetDirtyExitCount();

    // true на десктопах (macOS/Windows/Linux), false на iOS/Android — определяется #ifdef в .cpp.
    static bool isDesktopPlatform();

private:
    explicit CrashGuard(QObject *parent = nullptr);
    struct Priv;
    Priv *d;
};

#endif // CRASHGUARD_PURE_LOGIC_ONLY
