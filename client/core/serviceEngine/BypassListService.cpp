// client/core/serviceEngine/BypassListService.cpp
// AVPN server-driven АнтиВПН (Task 9): см. BypassListService.h. Логика LKG round-trip/
// анти-downgrade вынесена в чистый header-only слой BypassListLkg.h (юнит test_bypass_lkg.cpp
// гоняет её без сети/этого файла).
#include "BypassListService.h"

#include "BypassListLkg.h"
#include "Ed25519Verify.h"
#include "NetAwait.h"
#include "TuningStore.h"

#include <QDebug>
#include <QDir>
#include <QFile>
#include <QMutex>
#include <QMutexLocker>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSaveFile>
#include <QStandardPaths>
#include <QTimer>

namespace avpn {

namespace {

QMutex      g_bypassStoreMutex;
BypassLists g_bypassStoreSnapshot; // default: valid=false (пусто до первого успешного LKG/фетча)

// AVPN: повторный фетч раз в 6ч — сервер меняет ru_cidrs редко (реестр РКН обновляется не
// поминутно), никакой ретрай-шторм не нужен; сетевые/verify-ошибки просто ждут следующего тика.
constexpr int kRefetchIntervalMs = 6 * 60 * 60 * 1000;

// AVPN backend-first-3 (Task 8): server-tunable (numbers.bypass_refetch_ms), клампы 15мин..24ч.
// Читается на КАЖДОМ взводе таймера (см. start()), не только один раз в конструкторе/первом
// start() — PATCH /admin/config подхватывается после очередного цикла без рестарта клиента.
int bypassRefetchIntervalMsTuned()
{
    return qBound(900000,
                  int(TuningStore::numberOr(QStringLiteral("bypass_refetch_ms"), double(kRefetchIntervalMs))),
                  86400000);
}

QString lkgFilePath()
{
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(dir);
    return dir + QStringLiteral("/bypass_lists.lkg");
}

} // namespace

void BypassListStore::set(const BypassLists &l)
{
    QMutexLocker lock(&g_bypassStoreMutex);
    g_bypassStoreSnapshot = l;
}

BypassLists BypassListStore::get()
{
    QMutexLocker lock(&g_bypassStoreMutex);
    return g_bypassStoreSnapshot;
}

BypassListService::BypassListService(QNetworkAccessManager *nam, const QString &baseUrl,
                                     const QString &pubKeyHex, QObject *parent)
    : QObject(parent), m_nam(nam), m_baseUrl(baseUrl), m_pubKeyHex(pubKeyHex)
{
}

void BypassListService::setBaseUrl(const QString &b)
{
    m_baseUrl = b; // на будущие фетчи; немедленный рефетч НЕ триггерим (см. .h)
}

void BypassListService::start()
{
    // AVPN: loadLkg() тоже под kill-switch — configApplied уже прилетел синхронно ДО start()
    // (см. реордер connect'ов в AvpnEngineQml) и мог взвести m_disabled=true на тёплом старте
    // с персистнутым remote_bypass_lists=false. Без гварда loadLkg() тут воскрешала бы
    // доверенный, но выключенный сервером список в BypassListStore/listsApplied ещё ДО того,
    // как читатели узнают про kill-switch. Обратное включение уже обрабатывает
    // onRemoteConfigApplied() сама (loadLkg()+fetch() в ветке re-enable) — дублировать не нужно.
    if (!m_disabled)
        loadLkg();
    if (!m_timer) {
        m_timer = new QTimer(this);
        connect(m_timer, &QTimer::timeout, this, [this]() {
            // AVPN (Task 8): перечитать интервал ПЕРЕД следующим взводом — так PATCH
            // numbers.bypass_refetch_ms доезжает без пересоздания таймера/рестарта сервиса.
            m_timer->setInterval(bypassRefetchIntervalMsTuned());
            if (!m_disabled)
                fetch();
        });
        m_timer->start(bypassRefetchIntervalMsTuned());
    }
    if (!m_disabled)
        fetch();
}

void BypassListService::loadLkg()
{
    QFile f(lkgFilePath());
    if (!f.open(QIODevice::ReadOnly))
        return; // нет LKG (первый запуск после апдейта/установки) — не ошибка
    const QByteArray json = f.readAll();
    f.close();

    BypassLists out;
    QByteArray  etag;
    QString     err;
    if (!loadVerifiedBypassListsLkg(json, m_pubKeyHex, out, etag, err)) {
        qWarning() << "AVPN bypass-lists: LKG rejected:" << err;
        return; // без сева до первого успешного фетча — не применяем недоверенный кэш
    }
    m_lkgVersion = out.version;
    m_etag = QString::fromUtf8(etag);
    BypassListStore::set(out);
    emit listsApplied(out);
}

void BypassListService::fetch()
{
    if (!m_nam || m_baseUrl.isEmpty())
        return;
    // AVPN: дедуп — повторный вызов (таймер тикнул поверх ещё не завершённого start()-фетча,
    // либо onRemoteConfigApplied(true) догнал уже идущий запрос) не должен породить второй
    // in-flight запрос. Снимается ниже в finished — для ЛЮБОГО исхода (2xx/3xx/4xx/5xx/abort).
    if (m_fetching)
        return;
    m_fetching = true;
    QNetworkRequest req{ QUrl(m_baseUrl + QStringLiteral("/v1/bypass-lists")) };
    if (!m_etag.isEmpty())
        req.setRawHeader(QByteArrayLiteral("If-None-Match"), m_etag.toUtf8());
    QNetworkReply *reply = m_nam->get(req);
    armTimeout(reply);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        m_fetching = false; // снимаем ПЕРВЫМ — до любого early return ниже
        const int code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (code == 304)
            return; // не изменилось — LKG актуален, no-op
        if (code == 404) {
            // Один лог за запуск процесса: эндпоинт ещё не выкачен на бэке — не спамить.
            if (!m_loggedNotFound) {
                qWarning() << "AVPN bypass-lists: /v1/bypass-lists 404 (not deployed yet?)";
                m_loggedNotFound = true;
            }
            return;
        }
        if (code < 200 || code >= 300)
            return; // транспортный/серверный сбой (включая armTimeout-abort, code==0) — остаёмся
                    // на LKG, следующая попытка по таймеру

        const QByteArray body = reply->readAll();
        const QByteArray sig  = reply->rawHeader(QByteArrayLiteral("X-Tribe-Sig"));
        const QByteArray etag = reply->rawHeader(QByteArrayLiteral("ETag"));
        applyBody(body, sig, etag);
    });
}

void BypassListService::applyBody(const QByteArray &body, const QByteArray &sigB64, const QByteArray &etag)
{
    // AVPN server-driven АнтиВПН: kill-switch перекрывает и in-flight ответ — запрос мог
    // стартовать ДО onRemoteConfigApplied(false); если сервер уже выключил фичу, тело,
    // пришедшее позже, применять нельзя (иначе kill-switch на мгновение "воскрешает" список).
    if (m_disabled)
        return;
    if (!verifyDetached(m_pubKeyHex, body, sigB64))
        return; // подпись не прошла → игнор, остаёмся на LKG/фолбэке
    BypassLists out;
    QString     err;
    if (!parseBypassLists(body, out, err))
        return; // битый/недостаточный payload (см. kMinValidRuCidrs) → остаёмся на LKG

    // Анти-downgrade/анти-replay: строго новее уже сохранённого, иначе тихо discard (это НЕ
    // ошибка сети/подписи — валидный, но устаревший/повторный ответ, лишний лог не нужен).
    if (!isBypassListVersionNewer(out.version, m_lkgVersion))
        return;

    saveLkg(body, sigB64, etag);
    m_lkgVersion = out.version;
    m_etag = QString::fromUtf8(etag);
    BypassListStore::set(out);
    emit listsApplied(out);
}

void BypassListService::saveLkg(const QByteArray &body, const QByteArray &sigB64, const QByteArray &etag)
{
    const QByteArray json = serializeBypassListsLkg(body, sigB64, etag);
    // AVPN: атомарная запись через QSaveFile (пишет во временный файл рядом + commit-переименование)
    // — обрыв процесса/питания посреди write() не должен оставить bypass_lists.lkg битым/пустым,
    // иначе следующий loadLkg() потеряет ПОСЛЕДНИЙ доверенный список.
    QSaveFile f(lkgFilePath());
    if (!f.open(QIODevice::WriteOnly)) {
        qWarning() << "AVPN bypass-lists: LKG save failed (open):" << f.errorString();
        return; // применённое в памяти состояние (BypassListStore/m_lkgVersion) оставляем как есть
    }
    f.write(json);
    if (!f.commit())
        qWarning() << "AVPN bypass-lists: LKG save failed (commit):" << f.errorString();
}

void BypassListService::onRemoteConfigApplied(const RemoteConfig &cfg)
{
    const bool enabled = featureFlag(cfg, QStringLiteral("remote_bypass_lists"), true);
    if (enabled) {
        if (m_disabled) {
            // Обратное включение сервером: снова читаем LKG и пробуем свежий фетч.
            m_disabled = false;
            loadLkg();
            fetch();
        }
        return;
    }
    // Kill-switch: сервер выключил фичу → пустой invalid снапшот (читатели видят "нет сева",
    // не старый потенциально проблемный список) + фетч на паузу до следующего configApplied.
    m_disabled = true;
    BypassListStore::set(BypassLists());
}

} // namespace avpn
