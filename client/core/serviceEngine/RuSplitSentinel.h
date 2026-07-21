#pragma once
// AVPN (Доктор D-3 п.26, 2026-07-17): RU-split-дозорный — приложение САМО замечает
// «сайт РФ не открывается у клиента» и шлёт телеметрию БЕЗ участия юзера (кейс Аэрофлота).
// Механика: server-driven вахт-лист lists.rusplit_watch (фолбэк вкомпилен), фоновая проба
// после коннекта при включённом «Доступе к РФ» + раз в numbers.rusplit_watch_interval_h.
// Анти-шум: отчёт ТОЛЬКО на смене состояния ok<->fail (+ не чаще 1/сутки на target).
// Kill-switch features.rusplit_sentinel. ПРИВАТНОСТЬ: пробуем только НАШ вахт-лист —
// реальный браузинг пользователя не отслеживается никогда (философия анонимности).
// Спека: tribe-front docs/superpowers/specs/2026-07-17-doctor-v2-roadmap.md п.26.

#include <QJsonArray>
#include <QJsonObject>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QTimer>

#include <functional>

class QNetworkAccessManager;

namespace avpn {

// ── чистая логика (юнит tests/rusplit_sentinel_check.cpp) ─────────────────────────────────

namespace rusentinel {

// Класс ошибки пробы по (QNetworkReply::NetworkError, httpCode). Категории обезличены.
//   qtError: значение enum как int (0 = NoError); httpCode: 0 = ответа не было.
inline QString classifyProbe(int qtError, int httpCode)
{
    if (httpCode > 0 && httpCode < 500)
        return QStringLiteral("ok");         // любой осмысленный ответ = сайт доступен
    if (httpCode >= 500)
        return QStringLiteral("http_5xx");   // дошли, но сайту плохо (не наша маршрутизация)
    switch (qtError) {                        // ответа не было — по транспортной причине
    case 3:  return QStringLiteral("dns");            // HostNotFoundError
    case 1:  return QStringLiteral("refused");        // ConnectionRefusedError
    case 4:  return QStringLiteral("timeout");        // TimeoutError
    case 2:  return QStringLiteral("closed");         // RemoteHostClosedError
    case 6:  return QStringLiteral("tls");            // SslHandshakeFailedError
    case 0:  return QStringLiteral("ok");             // NoError без кода (редко) — не пугаем
    default: return QStringLiteral("net");
    }
}

inline bool probeOk(const QString &cls)
{
    // http_5xx = сайт сам болеет, маршрут ДОВЁЛ до него — для дозорного это «доступен»
    return cls == QLatin1String("ok") || cls == QLatin1String("http_5xx");
}

// Надо ли слать отчёт: ТОЛЬКО переходы состояния (ok->fail и fail->ok), троттлинг 1/сутки.
//   prevState: -1 = target ещё не видели; 0 = был fail; 1 = был ok.
//   lastReportDay/todayDay — дни с эпохи (для суточного троттлинга).
inline bool shouldReport(int prevState, bool nowOk, qint64 lastReportDay, qint64 todayDay)
{
    const int nowState = nowOk ? 1 : 0;
    if (prevState == nowState)
        return false;                        // состояние не менялось — молчим
    if (prevState == -1 && nowOk)
        return false;                        // первый раз увидели и всё ок — не о чем
    if (lastReportDay == todayDay)
        return false;                        // суточный троттлинг per-target
    return true;
}

// Кламп интервала фоновой пробы: 1..48 часов, дефолт 6.
inline int clampIntervalHours(double v)
{
    if (v != v || v <= 0) return 6;
    if (v < 1)  return 1;
    if (v > 48) return 48;
    return int(v);
}

// Фолбэк вахт-листа (ЕДИНЫЙ для дозорного и стадии «Сайты РФ» Доктора; server-driven
// lists.rusplit_watch, формат "Имя|URL"). Пересмотр 2026-07-22 (BUG-5): VK и Аэрофлот убраны —
// их бот-защита отвечает 418/403 и давала вечное ложное «Не открылись» в каждом отчёте;
// вместо них реальные маркеры рунета, которыми пользуются (Ozon/Wildberries/Госуслуги).
inline const QStringList &defaultWatch()
{
    static const QStringList w{
        QStringLiteral("Яндекс|https://ya.ru/"),
        QStringLiteral("Ozon|https://www.ozon.ru/"),
        QStringLiteral("Wildberries|https://www.wildberries.ru/"),
        QStringLiteral("Госуслуги|https://www.gosuslugi.ru/"),
    };
    return w;
}

// Парс элемента вахт-листа "Имя|https://url" -> (name, url); без '|' -> (host, url).
inline bool parseWatchEntry(const QString &entry, QString &name, QString &url)
{
    const int sep = entry.indexOf(QLatin1Char('|'));
    if (sep > 0) {
        name = entry.left(sep).trimmed();
        url = entry.mid(sep + 1).trimmed();
    } else {
        url = entry.trimmed();
        name = url;
        name.remove(QStringLiteral("https://")).remove(QStringLiteral("http://"));
        const int slash = name.indexOf(QLatin1Char('/'));
        if (slash > 0) name.truncate(slash);
    }
    return !url.startsWith(QStringLiteral("http")) ? false : !name.isEmpty();
}

} // namespace rusentinel

// ── оркестрация (движок владеет, зовёт onTunnelStateChanged из changed()) ─────────────────

class RuSplitSentinel : public QObject {
    Q_OBJECT
public:
    // submit — отправка готового JSON-отчёта (движок: uploadReport quiet);
    // netType — контекст для отчёта ("cellular"/"wifi"/...);
    // masterOn — фактическое положение тумблера «Доступ к сайтам РФ».
    RuSplitSentinel(QNetworkAccessManager *nam,
                    std::function<void(const QJsonObject &)> submit,
                    std::function<QString()> netType,
                    std::function<bool()> masterOn,
                    QObject *parent = nullptr);

    // Дёргается из движка на каждом changed(): сам детектит фронт connected/idle.
    void onTunnelStateChanged(const QString &state);

private:
    void scheduleRun(int delayMs);
    void runProbes();
    void finishRound();

    QNetworkAccessManager *m_nam = nullptr;
    std::function<void(const QJsonObject &)> m_submit;
    std::function<QString()> m_netType;
    std::function<bool()> m_masterOn;

    QTimer m_kick;       // одноразовый прогон после коннекта (20с — дать сплиту посеяться)
    QTimer m_interval;   // фоновые прогоны раз в rusplit_watch_interval_h
    bool m_wasConnected = false;
    bool m_inFlight = false;
    int  m_gen = 0;      // инвалидация колбэков отменённого раунда

    struct Probe { QString name; QString cls; };
    QList<Probe> m_round;
    int m_pending = 0;
    bool m_tunnelAlive = false;
};

} // namespace avpn
