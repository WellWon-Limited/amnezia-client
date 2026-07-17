// client/core/serviceEngine/CrashGuard.cpp
// AVPN (наблюдаемость, волна CR-1) — фасад CrashGuard: платформенные ловцы + жизненный цикл.
// Чистая логика (sentinel/классификация/скраб/JSON) — в CrashGuard.h (namespace crashguard),
// тестируется standalone. Здесь — только IO/сигналы/платформенщина под #ifdef (PLATFORM-SCOPING):
//   POSIX (iOS/macOS/Android/Linux): async-signal-safe хендлеры SIGSEGV/SIGABRT/SIGBUS/SIGILL/SIGFPE
//   Windows: SetUnhandledExceptionFilter (subtype seh)
// iOS/macOS: mach-исключения НЕ ловим (конфликт с системным репортером) — только POSIX-сигналы.
#include "CrashGuard.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QMutex>
#include <QMutexLocker>

#include <atomic>
#include <cstring>

#if defined(Q_OS_WIN)
#  include <windows.h>
#else
#  include <csignal>
#  include <fcntl.h>
#  include <unistd.h>
#  if !defined(Q_OS_ANDROID)
#    include <execinfo.h>   // backtrace()
#  endif
#  include <dlfcn.h>        // dladdr() — image base
#endif

using namespace crashguard;

// ─── Async-signal-safe глобальное состояние ─────────────────────────────────────────────────────
// В сигнал-хендлере МОЖНО касаться только этого (POD/atomic), делать open/write/close/_exit и
// backtrace(). Никакого Qt/malloc/new/QString. Пути — заранее в C-строках (вычислены в install).
namespace {

#if !defined(Q_OS_WIN)
static int              g_sigDirFd = -1;              // O_DIRECTORY fd каталога crash/ (для openat)
static char             g_sigFileName[64] = { 0 };    // "signal.bin"
static std::atomic<int> g_installedSignals{0};
static quint64          g_imageBase = 0;
static const int        kCaughtSignals[] = { SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE };
static struct sigaction g_prevActions[sizeof(kCaughtSignals) / sizeof(int)];

// Async-signal-safe запись беззнакового в little-endian буфер (без memcpy-зависимостей рантайма
// это тоже safe, но пишем побайтно во избежание сюрпризов).
static inline void putU32(char *p, quint32 v)
{
    p[0] = char(v & 0xff); p[1] = char((v >> 8) & 0xff);
    p[2] = char((v >> 16) & 0xff); p[3] = char((v >> 24) & 0xff);
}
static inline void putU64(char *p, quint64 v)
{
    for (int i = 0; i < 8; ++i) p[i] = char((v >> (8 * i)) & 0xff);
}

// САМ хендлер. Строго async-signal-safe. Пишет signal.bin одним write(), восстанавливает дефолт и
// ре-райзит сигнал (чтобы системный крэш-репортер/WER всё равно отработал).
extern "C" void avpn_crash_signal_handler(int sig, siginfo_t *info, void *)
{
    // Статический буфер: заголовок + до 32 адресов. Никаких аллокаций.
    static char buf[kSigHeaderBytes + kMaxFrames * 8];

    std::memcpy(buf + 0, kSigMagic, 4);
    buf[4] = 0; // kind = signal
    buf[5] = buf[6] = buf[7] = 0;
    putU32(buf + 8, quint32(sig));
    const quint64 faultAddr = info ? quint64(reinterpret_cast<uintptr_t>(info->si_addr)) : 0;
    putU64(buf + 16, faultAddr);
    putU64(buf + 24, g_imageBase);

    int nframes = 0;
#if !defined(Q_OS_ANDROID)
    void *frames[kMaxFrames];
    nframes = backtrace(frames, kMaxFrames); // не строго async-safe, но принято в крэш-хендлерах
    if (nframes < 0) nframes = 0;
    if (nframes > kMaxFrames) nframes = kMaxFrames;
    for (int i = 0; i < nframes; ++i)
        putU64(buf + kSigHeaderBytes + i * 8, quint64(reinterpret_cast<uintptr_t>(frames[i])));
#endif
    putU32(buf + 32, quint32(nframes));

    const int total = kSigHeaderBytes + nframes * 8;
    if (g_sigDirFd >= 0) {
        const int fd = ::openat(g_sigDirFd, g_sigFileName, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            ssize_t off = 0;
            while (off < total) {
                const ssize_t w = ::write(fd, buf + off, size_t(total - off));
                if (w <= 0) break;
                off += w;
            }
            ::close(fd);
        }
    }

    // Восстановить дефолтный обработчик и ре-райзить — путь к системному репортеру/кор-дампу.
    const size_t n = sizeof(kCaughtSignals) / sizeof(int);
    for (size_t i = 0; i < n; ++i)
        if (kCaughtSignals[i] == sig) { ::sigaction(sig, &g_prevActions[i], nullptr); break; }
    ::raise(sig);
}
#endif // !Q_OS_WIN

#if defined(Q_OS_WIN)
static QString g_sehPath; // заранее вычисленный путь seh.bin (Windows-хендлер — вне сигнального контекста)

static LONG WINAPI avpn_crash_seh_filter(EXCEPTION_POINTERS *ep)
{
    SignalInfo si;
    si.valid = true;
    si.kind  = 1; // seh
    if (ep && ep->ExceptionRecord) {
        si.signalOrCode = quint32(ep->ExceptionRecord->ExceptionCode);
        si.faultAddr    = quint64(reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress));
    }
    si.imageBase = quint64(reinterpret_cast<uintptr_t>(::GetModuleHandleW(nullptr)));
    void *frames[kMaxFrames];
    const USHORT n = ::RtlCaptureStackBackTrace(0, kMaxFrames, frames, nullptr);
    for (USHORT i = 0; i < n; ++i)
        si.frames.append(quint64(reinterpret_cast<uintptr_t>(frames[i])));

    const QByteArray bin = encodeSignalBin(si);
    QFile f(g_sehPath);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        f.write(bin);
        f.close();
    }
    return EXCEPTION_CONTINUE_SEARCH; // отдать дальше WER — минидампы не пишем, но системный путь цел
}
#endif // Q_OS_WIN

} // namespace

// ─── Приватное состояние фасада ─────────────────────────────────────────────────────────────────
struct CrashGuard::Priv {
    QMutex        mtx;
    bool          installed = false;
    QString       dir;                 // crash/
    QString       pendingDir;          // crash/pending/
    QString       sentinelPath;        // crash/running.json
    QString       signalPath;          // crash/signal.bin
    QString       sehPath;             // crash/seh.bin
    QString       javaPath;            // crash/java.txt
    QString       tailPath;            // crash/tail.txt
    Sentinel      sentinel;
    QStringList   ring;                // кольцевой лог-хвост (внешний message-handler кормит appendLogLine)
    int           ringCap = 200;
    int           dirtyExits = 0;      // накопленный счётчик мобилок (персистится в sentinel)
};

CrashGuard::CrashGuard(QObject *parent) : QObject(parent), d(new Priv) {}

CrashGuard &CrashGuard::instance()
{
    static CrashGuard s;
    return s;
}

bool CrashGuard::isDesktopPlatform()
{
#if defined(Q_OS_ANDROID) || defined(Q_OS_IOS)
    return false;
#else
    return true;
#endif
}

// Классификация улик прошлого запуска → pending-отчёт. Дёргается один раз из install() ДО
// перезаписи sentinel. Читает файлы, консьюмит их (удаляет), кладёт отчёт в pending/ (если нужно).
static void classifyPreviousLocked(CrashGuard::Priv *d)
{
    const QByteArray senRaw = [&] {
        QFile f(d->sentinelPath);
        return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray();
    }();
    const Sentinel prev = parseSentinel(senRaw);

    QFile sigF(d->signalPath);
    const bool hasSignal = sigF.exists() && sigF.size() >= kSigHeaderBytes;
    QFile sehF(d->sehPath);
    const bool hasSeh = sehF.exists() && sehF.size() >= kSigHeaderBytes;
    QFile javaF(d->javaPath);
    const bool hasJava = javaF.exists() && javaF.size() > 0;

    const Subtype st = classify(hasSignal, hasJava, hasSeh, prev.valid);

    // Накопим счётчик dirty_exit мобилок (переносится из прошлого sentinel + текущий чистый-dirty).
    d->dirtyExits = prev.dirtyExitsSinceLast;
    if (st == Subtype::DirtyExit && !CrashGuard::isDesktopPlatform())
        d->dirtyExits += 1; // мобилка: dirty не шлём отчётом, только считаем

    if (shouldEmitReport(st, CrashGuard::isDesktopPlatform()) && prev.valid) {
        SignalInfo si;
        if (st == Subtype::Signal) {
            if (sigF.open(QIODevice::ReadOnly)) { si = parseSignalBin(sigF.readAll()); sigF.close(); }
        } else if (st == Subtype::Seh) {
            if (sehF.open(QIODevice::ReadOnly)) { si = parseSignalBin(sehF.readAll()); sehF.close(); }
        }
        QString javaStack;
        if (st == Subtype::Java && javaF.open(QIODevice::ReadOnly)) {
            javaStack = clampLogTail(scrubLogTail(QString::fromUtf8(javaF.readAll())));
            javaF.close();
        }
        // Лог-хвост из tail.txt прошлого запуска (скраб + кламп 16 КБ).
        QString logTail;
        {
            QFile tf(d->tailPath);
            if (tf.open(QIODevice::ReadOnly))
                logTail = clampLogTail(scrubLogTail(QString::fromUtf8(tf.readAll())));
        }
        const SignalInfo *sp = (st == Subtype::Signal || st == Subtype::Seh) && si.valid ? &si : nullptr;
        const QJsonObject rep = buildReport(st, prev, sp, logTail, d->dirtyExits, javaStack);

        // Записать в pending/<ts>.json (id = имя файла без .json). Не копить > 3.
        QDir().mkpath(d->pendingDir);
        const QString id = QStringLiteral("%1_%2")
                               .arg(subtypeName(st))
                               .arg(QDateTime::currentMSecsSinceEpoch());
        QFile pf(d->pendingDir + QDir::separator() + id + QStringLiteral(".json"));
        if (pf.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            pf.write(QJsonDocument(rep).toJson(QJsonDocument::Compact));
            pf.close();
        }
        // Отчёт отправлен → dirty-счётчик, уехавший в это тело, обнуляем (десктоп dirty_exit тоже).
        d->dirtyExits = 0;

        // Ограничить pending 3 самыми свежими.
        QDir pd(d->pendingDir);
        QStringList js = pd.entryList(QStringList{QStringLiteral("*.json")}, QDir::Files, QDir::Time);
        for (int i = kMaxPending; i < js.size(); ++i)
            pd.remove(js.at(i));
    }

    // Консьюмим улики — чтобы следующий старт их не переклассифицировал.
    sigF.remove();
    sehF.remove();
    javaF.remove();
    QFile(d->tailPath).remove();
    QFile(d->sentinelPath).remove();
}

void CrashGuard::install(const QString &dirPath, const QString &buildStr,
                         const QString &platform, const QString &os)
{
    QMutexLocker lock(&d->mtx);
    if (d->installed)
        return;

    d->dir          = dirPath;
    d->pendingDir   = dirPath + QDir::separator() + QStringLiteral("pending");
    d->sentinelPath = dirPath + QDir::separator() + QStringLiteral("running.json");
    d->signalPath   = dirPath + QDir::separator() + QStringLiteral("signal.bin");
    d->sehPath      = dirPath + QDir::separator() + QStringLiteral("seh.bin");
    d->javaPath     = dirPath + QDir::separator() + QStringLiteral("java.txt");
    d->tailPath     = dirPath + QDir::separator() + QStringLiteral("tail.txt");
    QDir().mkpath(dirPath);

    // 1) Разобрать прошлый запуск (может создать pending-отчёт), затем зачистить улики.
    classifyPreviousLocked(d);

    // 2) Свежий sentinel.
    d->sentinel = Sentinel{};
    d->sentinel.valid    = true;
    d->sentinel.build    = buildStr;
    d->sentinel.platform = platform;
    d->sentinel.os       = os;
    d->sentinel.phase    = QStringLiteral("idle");
    d->sentinel.startedMs = QDateTime::currentMSecsSinceEpoch();
    d->sentinel.uptimeS  = 0;
    d->sentinel.dirtyExitsSinceLast = d->dirtyExits;
    {
        QFile f(d->sentinelPath);
        if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            f.write(buildSentinel(d->sentinel));
            f.close();
        }
    }

    // 3) Платформенные ловцы. iOS/macOS: только POSIX-сигналы (mach — системному репортеру).
#if defined(Q_OS_WIN)
    g_sehPath = d->sehPath;
    ::SetUnhandledExceptionFilter(avpn_crash_seh_filter);
#else
    // Заранее вычислить image base (async-safe справочник для символизации).
    Dl_info dli;
    if (dladdr(reinterpret_cast<void *>(&avpn_crash_signal_handler), &dli) && dli.dli_fbase)
        g_imageBase = quint64(reinterpret_cast<uintptr_t>(dli.dli_fbase));

    // fd каталога crash/ для openat в хендлере (не держим fd самого signal.bin — иначе он
    // «существует» пустым и ломает классификацию; openat в хендлере async-signal-safe).
    g_sigDirFd = ::open(QFile::encodeName(dirPath).constData(), O_RDONLY | O_DIRECTORY);
    std::strncpy(g_sigFileName, "signal.bin", sizeof(g_sigFileName) - 1);

    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = avpn_crash_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESETHAND;
    const size_t n = sizeof(kCaughtSignals) / sizeof(int);
    for (size_t i = 0; i < n; ++i)
        ::sigaction(kCaughtSignals[i], &sa, &g_prevActions[i]);
    g_installedSignals.store(int(n));
#endif

    d->installed = true;
}

void CrashGuard::setPhase(const char *phase)
{
    if (!phase) return;
    QMutexLocker lock(&d->mtx);
    d->sentinel.phase = QString::fromUtf8(phase);
}

void CrashGuard::heartbeat()
{
    QMutexLocker lock(&d->mtx);
    if (!d->installed) return;

    // Пересчёт uptime + перезапись sentinel.
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    d->sentinel.uptimeS = (now - d->sentinel.startedMs) / 1000;
    d->sentinel.dirtyExitsSinceLast = d->dirtyExits;
    {
        QFile f(d->sentinelPath);
        if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            f.write(buildSentinel(d->sentinel));
            f.close();
        }
    }
    // Сброс лог-хвоста в tail.txt (перезапись). Хвост на диске переживёт смерть процесса.
    {
        QFile f(d->tailPath);
        if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            f.write(d->ring.join(QLatin1Char('\n')).toUtf8());
            f.close();
        }
    }
}

void CrashGuard::appendLogLine(const QString &line)
{
    QMutexLocker lock(&d->mtx);
    d->ring.append(line);
    while (d->ring.size() > d->ringCap)
        d->ring.removeFirst();
}

QList<QJsonObject> CrashGuard::takePendingReports()
{
    QMutexLocker lock(&d->mtx);
    QList<QJsonObject> out;
    QDir pd(d->pendingDir);
    if (!pd.exists())
        return out;
    const QStringList js = pd.entryList(QStringList{QStringLiteral("*.json")}, QDir::Files, QDir::Time);
    for (int i = 0; i < js.size() && i < kMaxPending; ++i) {
        QFile f(pd.filePath(js.at(i)));
        if (!f.open(QIODevice::ReadOnly)) continue;
        QJsonParseError e{};
        const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &e);
        f.close();
        if (e.error != QJsonParseError::NoError || !doc.isObject()) continue;
        QJsonObject o = doc.object();
        const QString id = js.at(i);
        o.insert(QStringLiteral("_pending_id"), id.left(id.size() - 5)); // без ".json"
        out.append(o);
    }
    return out;
}

void CrashGuard::markSent(const QString &pendingId)
{
    QMutexLocker lock(&d->mtx);
    if (pendingId.isEmpty()) return;
    QFile::remove(d->pendingDir + QDir::separator() + pendingId + QStringLiteral(".json"));
}

int CrashGuard::dirtyExitCount() const
{
    QMutexLocker lock(&d->mtx);
    return d->dirtyExits;
}

void CrashGuard::resetDirtyExitCount()
{
    QMutexLocker lock(&d->mtx);
    d->dirtyExits = 0;
    d->sentinel.dirtyExitsSinceLast = 0;
}
