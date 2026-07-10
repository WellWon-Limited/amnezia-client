// client/core/serviceEngine/TuningStore.h
// AVPN backend-first (план 2026-07-10): потокобезопасный снапшот numbers/features/lists
// из ПОСЛЕДНЕГО применённого /v1/config (LKG на старте, свежий после fetch). Читатели —
// разбросанные классы движка (GoodputProbe/SignalQuality/ServiceProbe/чат/ретраи): им не
// нужен доступ к ConfigService, только этот статический снапшот. Пусто/офлайн → def
// (вкомпиленный фолбэк). featureFlag default TRUE = kill-switch, не opt-in.
#pragma once
#include <QMap>
#include <QMutex>
#include <QMutexLocker>
#include <QString>
#include <QStringList>

namespace avpn {

class TuningStore
{
public:
    static void set(const QMap<QString, double> &numbers, const QMap<QString, bool> &features,
                    const QMap<QString, QStringList> &lists = {})
    {
        QMutexLocker l(&mutex());
        numbersRef() = numbers;
        featuresRef() = features;
        listsRef() = lists;
    }
    static double numberOr(const QString &key, double def)
    {
        QMutexLocker l(&mutex());
        const auto &m = numbersRef();
        const auto it = m.constFind(key);
        return it != m.constEnd() ? it.value() : def;
    }
    static bool flag(const QString &key, bool def = true)
    {
        QMutexLocker l(&mutex());
        const auto &f = featuresRef();
        const auto it = f.constFind(key);
        return it != f.constEnd() ? it.value() : def;
    }
    static QStringList listOr(const QString &key, const QStringList &def)
    {
        QMutexLocker l(&mutex());
        const auto &ls = listsRef();
        const auto it = ls.constFind(key);
        return it != ls.constEnd() ? it.value() : def;
    }
    static void reset() { set({}, {}, {}); }

private:
    static QMutex &mutex() { static QMutex m; return m; }
    static QMap<QString, double> &numbersRef() { static QMap<QString, double> n; return n; }
    static QMap<QString, bool> &featuresRef() { static QMap<QString, bool> f; return f; }
    static QMap<QString, QStringList> &listsRef() { static QMap<QString, QStringList> l; return l; }
};

} // namespace avpn
