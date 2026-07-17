// AVPN (Доктор D-3 п.26): RU-split-дозорный — см. RuSplitSentinel.h.
#include "RuSplitSentinel.h"

#include "TuningStore.h"

#include <QDateTime>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSettings>
#include <QUrl>

namespace avpn {

namespace {
// Фолбэк вахт-листа (server-driven через lists.rusplit_watch, формат "Имя|URL").
const QStringList kDefaultWatch{
    QStringLiteral("Яндекс|https://ya.ru/"),
    QStringLiteral("VK|https://vk.com/favicon.ico"),
    QStringLiteral("Аэрофлот|https://www.aeroflot.ru/"),
};

QString stateKey(const QString &name)
{
    // ключ QSettings на target: состояние + день последнего отчёта
    return QStringLiteral("AvpnSentinel/") + name;
}
} // namespace

RuSplitSentinel::RuSplitSentinel(QNetworkAccessManager *nam,
                                 std::function<void(const QJsonObject &)> submit,
                                 std::function<QString()> netType,
                                 std::function<bool()> masterOn, QObject *parent)
    : QObject(parent), m_nam(nam), m_submit(std::move(submit)),
      m_netType(std::move(netType)), m_masterOn(std::move(masterOn))
{
    m_kick.setSingleShot(true);
    connect(&m_kick, &QTimer::timeout, this, &RuSplitSentinel::runProbes);
    connect(&m_interval, &QTimer::timeout, this, &RuSplitSentinel::runProbes);
}

void RuSplitSentinel::onTunnelStateChanged(const QString &state)
{
    const bool up = (state == QLatin1String("connected"));
    if (up && !m_wasConnected) {
        // фронт подключения: первый прогон через 20с (сплиту надо посеяться), затем интервал
        scheduleRun(20000);
        const int hours = rusentinel::clampIntervalHours(
            TuningStore::numberOr(QStringLiteral("rusplit_watch_interval_h"), 6));
        m_interval.start(hours * 3600 * 1000);
    } else if (!up && m_wasConnected) {
        m_kick.stop();
        m_interval.stop();
        ++m_gen; // висящие пробы устаревают
        m_inFlight = false;
    }
    m_wasConnected = up;
}

void RuSplitSentinel::scheduleRun(int delayMs)
{
    m_kick.start(delayMs);
}

void RuSplitSentinel::runProbes()
{
    if (m_inFlight || !m_nam)
        return;
    if (!TuningStore::flag(QStringLiteral("rusplit_sentinel"), true))
        return; // kill-switch с бэка
    if (!m_masterOn || !m_masterOn())
        return; // дозор имеет смысл только при включённом «Доступе к РФ»
    const QStringList raw =
        TuningStore::listOr(QStringLiteral("rusplit_watch"), kDefaultWatch);
    m_round.clear();
    m_pending = 0;
    m_tunnelAlive = false;
    m_inFlight = true;
    const int gen = ++m_gen;

    for (const QString &entry : raw) {
        QString name, url;
        if (!rusentinel::parseWatchEntry(entry, name, url))
            continue;
        const int idx = m_round.size();
        m_round.append({name, QStringLiteral("net")});
        ++m_pending;
        QNetworkRequest req{QUrl(url)};
        req.setTransferTimeout(8000);
        req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
        req.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
        QNetworkReply *rep = m_nam->head(req);
        connect(rep, &QNetworkReply::finished, this, [this, rep, idx, gen] {
            rep->deleteLater();
            if (gen != m_gen) return;
            const int code = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            if (idx < m_round.size())
                m_round[idx].cls = rusentinel::classifyProbe(int(rep->error()), code);
            if (--m_pending <= 0)
                finishRound();
        });
    }
    if (m_pending == 0)
        m_inFlight = false; // вахт-лист пуст/битый — раунда нет
}

void RuSplitSentinel::finishRound()
{
    // контрольная проба «туннель жив» (через VPN): различает «сайт РФ отвалился» от
    // «интернета нет вообще» — второй случай не про сплит, отчёт не шлём.
    const int gen = m_gen;
    QNetworkRequest req{QUrl(QStringLiteral("https://connectivitycheck.gstatic.com/generate_204"))};
    req.setTransferTimeout(6000);
    req.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::AlwaysNetwork);
    QNetworkReply *rep = m_nam->head(req);
    connect(rep, &QNetworkReply::finished, this, [this, rep, gen] {
        rep->deleteLater();
        if (gen != m_gen) return;
        m_inFlight = false;
        const int code = rep->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        m_tunnelAlive = (rep->error() == QNetworkReply::NoError && code > 0);

        QSettings st;
        const qint64 today = QDateTime::currentSecsSinceEpoch() / 86400;
        bool report = false;
        QJsonArray targets;
        for (const auto &p : m_round) {
            const bool ok = rusentinel::probeOk(p.cls);
            // персистентное состояние: "0|день" / "1|день" (переживает рестарт — анти-дубли)
            const QStringList prev = st.value(stateKey(p.name)).toString().split(QLatin1Char('|'));
            const int prevState = prev.size() == 2 ? prev.at(0).toInt() : -1;
            qint64 lastDay = prev.size() == 2 ? prev.at(1).toLongLong() : -1;
            if (m_tunnelAlive && rusentinel::shouldReport(prevState, ok, lastDay, today)) {
                report = true;
                lastDay = today;
            }
            if (m_tunnelAlive) // состояние обновляем только при живом интернете (иначе шум обрыва)
                st.setValue(stateKey(p.name),
                            QStringLiteral("%1|%2").arg(ok ? 1 : 0).arg(lastDay));
            QJsonObject t;
            t.insert(QStringLiteral("name"), p.name);
            t.insert(QStringLiteral("ok"), ok);
            if (!ok) t.insert(QStringLiteral("error"), p.cls);
            targets.append(t);
        }
        if (!report || !m_submit)
            return;
        QJsonObject o;
        o.insert(QStringLiteral("type"), QStringLiteral("rusplit_fail"));
        o.insert(QStringLiteral("schema"), 1);
        o.insert(QStringLiteral("targets"), targets);
        o.insert(QStringLiteral("tunnel_alive"), m_tunnelAlive);
        if (m_netType) {
            const QString nt = m_netType();
            if (!nt.isEmpty()) o.insert(QStringLiteral("net_type"), nt);
        }
        m_submit(o);
    });
}

} // namespace avpn
