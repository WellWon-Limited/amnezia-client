// client/core/serviceEngine/TuningStore.h
// AVPN backend-first (план 2026-07-10): потокобезопасный снапшот numbers/features/lists/strings
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
                    const QMap<QString, QStringList> &lists = {},
                    const QMap<QString, QString> &strings = {})
    {
        QMutexLocker l(&mutex());
        numbersRef() = numbers;
        featuresRef() = features;
        listsRef() = lists;
        stringsRef() = strings;
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
    // Контракт (backend-first, единый источник правды): пусто с сервера = фолбэк на def, ТАК ЖЕ
    // как отсутствующий ключ. Это осознанное решение — сервер не может «стереть» непустой
    // вкомпиленный default пустым значением (list/string), только заменить его непустым.
    // Все читатели (ServiceProbe/YoutubeSource/…) обязаны звать эти методы напрямую, БЕЗ
    // локальных guard'ов/дублей поверх (единственное место с этой семантикой — здесь).
    static QStringList listOr(const QString &key, const QStringList &def)
    {
        QMutexLocker l(&mutex());
        const auto &ls = listsRef();
        const auto it = ls.constFind(key);
        return (it != ls.constEnd() && !it.value().isEmpty()) ? it.value() : def;
    }
    static QString stringOr(const QString &key, const QString &def)
    {
        QMutexLocker l(&mutex());
        const auto &s = stringsRef();
        const auto it = s.constFind(key);
        return (it != s.constEnd() && !it.value().isEmpty()) ? it.value() : def;
    }
    static void reset() { set({}, {}, {}, {}); }

private:
    static QMutex &mutex() { static QMutex m; return m; }
    static QMap<QString, double> &numbersRef() { static QMap<QString, double> n; return n; }
    static QMap<QString, bool> &featuresRef() { static QMap<QString, bool> f; return f; }
    static QMap<QString, QStringList> &listsRef() { static QMap<QString, QStringList> l; return l; }
    static QMap<QString, QString> &stringsRef() { static QMap<QString, QString> s; return s; }
};

} // namespace avpn
