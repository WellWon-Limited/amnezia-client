// AVPN serviceEngine — гарды data-plane волны awg31-xray-v1 (независимое ревью 2026-09-02):
//   MAJOR-1 — кап ПОДРЯД идущих провалов data-plane за сессию (без него failover крутится вечно:
//             up → verifying → verifyFailed → down → up при мёртвом data-plane, ошибки юзер не видит);
//   MAJOR-2 — сохранённый ручной режим «Xray» при выключенном kill-switch features.xray_client
//             приводится к «Авто» (иначе hard-filter отсекает всё и connect() = no_transport);
//   MAJOR-3 — верификация xray доказывает ТУННЕЛЬ, а не интернет: HTTP-200 + rx>0 через туннель
//             (verifyStepFor, ConnectTunables.h; 0 = «неизвестно» по §17.1);
//   MINOR-7 — единый предикат «туннель поднят» (isTunnelUpStateName) включает verifying.
// Сборка/запуск: core/serviceEngine/tests/build_dataplane_guard.sh (образец build_proto_forward.sh).
#include "../ConnectTunables.h"
#include "../DebugSnapshot.h"
#include "../NodeRotation.h"
#include "../Enrollment.h"
#include "../Identity.h"
#include "../ServiceEngine.h"
#include "../TuningStore.h"

#include <QCoreApplication>
#include <cstdio>

using namespace avpn;

static int g_failed = 0;
static int g_total = 0;

#define CHECK(expr)                                                                                 \
    do {                                                                                            \
        ++g_total;                                                                                  \
        if (!(expr)) {                                                                              \
            ++g_failed;                                                                             \
            fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, #expr);                       \
        }                                                                                           \
    } while (0)

// Туннель-стаб (по образцу transport_pick_check): фиксирует up/down, всегда успешен.
struct FakeTunnel : ITunnelControl {
    QString lastUpNodeId;
    int upCalls = 0;
    int downCalls = 0;
    TunnelStats st;
    TunnelResult up(const Subscription &, const SubscriptionNode &node) override
    {
        ++upCalls;
        lastUpNodeId = node.nodeId;
        return TunnelResult::success();
    }
    TunnelResult applyPeer(const Subscription &, const SubscriptionNode &node) override
    {
        lastUpNodeId = node.nodeId;
        return TunnelResult::success();
    }
    TunnelStats readStats() override { return st; }
    void down() override { ++downCalls; }
};

static QByteArray awgNodeJson(const char *id, int hostId, const char *cc, double weight)
{
    return QByteArray(R"({ "node_id": ")") + id + R"(", "region": "eu", "host_id": )"
        + QByteArray::number(hostId) + R"(, "transport_rank": 10,
        "endpoint": "203.0.113.10:585",
        "server_pubkey": "K1nDpUbLiCkEyExAmPlE0000000000000000000000=",
        "proto": "awg", "weight": )" + QByteArray::number(weight) + R"(,
        "country_code": ")" + cc + R"(",
        "allowed_ips": ["0.0.0.0/0", "::/0"], "dns": ["1.1.1.1", "1.0.0.1"],
        "mtu": 1280, "persistent_keepalive": 25,
        "awg_params": { "Jc": 4, "Jmin": 50, "Jmax": 1000, "S1": 86, "S2": 57,
                        "H1": 1, "H2": 2, "H3": 3, "H4": 4 } })";
}

static QByteArray xrayNodeJson(const char *id, int hostId, const char *cc)
{
    return QByteArray(R"({ "node_id": ")") + id + R"(", "region": "eu", "host_id": )"
        + QByteArray::number(hostId) + R"(, "transport_rank": 20,
        "endpoint": "203.0.113.10:443", "proto": "xray", "weight": 1.0,
        "country_code": ")" + cc + R"(",
        "xray_params": { "uuid": "8f14e45f-ceea-4a7c-9d6b-2a1b3c4d5e6f",
                         "public_key": "SbVjZ9Yl3dR3QpG1v8k2Wx0aU7Hq4Nn6Tt5Bc8Jd1mE",
                         "short_id": "a1b2c3d4", "server_name": "vision.example.com",
                         "fingerprint": "chrome", "flow": "xtls-rprx-vision",
                         "network": "tcp", "security": "reality" } })";
}

static QByteArray subJson(const QList<QByteArray> &nodes)
{
    QByteArray joined;
    for (int i = 0; i < nodes.size(); ++i) {
        if (i) joined += ",";
        joined += nodes[i];
    }
    return R"({ "version": 1, "address": ["10.7.0.5/32"], "status": "active",
        "expires_at": "2026-09-01T00:00:00Z", "traffic": { "used": 0, "limit": 0 },
        "nodes": [)" + joined + "] }";
}

// Один круг «нода не пропускает трафик»: реальный обрыв из Connected → failover на следующую.
// Возвращает true, если движок ушёл в свитч (false = сдался/кандидатов нет).
static bool deadRound(ServiceEngine &eng)
{
    const bool switched = eng.notifyConnectionLost();
    if (switched)
        eng.onTunnelConnected(); // поднялись на следующем кандидате (двухфазность здесь не нужна)
    return switched;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    TuningStore::set({}, {{QStringLiteral("xray_client"), true},
                          {QStringLiteral("transport_auto_pick"), true}}, {}, {});

    // --- 1) MAJOR-3: verifyStepFor — «Подключено по xray только после реального трафика» ---
    {
        // Проба не прошла — ждём следующей попытки в пределах бюджета, чем бы ни были счётчики.
        CHECK(verifyStepFor(false, true, 0) == VerifyStep::KeepTrying);
        CHECK(verifyStepFor(false, true, 999) == VerifyStep::KeepTrying);
        CHECK(verifyStepFor(false, false, 0) == VerifyStep::KeepTrying);
        // Проба прошла И rx через туннель > 0 — доказано.
        CHECK(verifyStepFor(true, true, 1) == VerifyStep::Confirmed);
        CHECK(verifyStepFor(true, false, 1) == VerifyStep::Confirmed);
        // Главный случай ревью: HTTP-200 есть, а rx нулевой при ЖИВОМ источнике статистики —
        // трафик ушёл мимо туннеля (tun2socks/маршруты не встали) ⇒ «Подключено» не показываем.
        CHECK(verifyStepFor(true, true, 0) == VerifyStep::KeepTrying);
        // Источника статистики нет вовсе — на этом коннект не валим (иначе сбой IPC = нет VPN),
        // но помечаем «без доказательства» (лог + отчёт verify_rx_proof).
        CHECK(verifyStepFor(true, false, 0) == VerifyStep::AcceptedWithoutStats);
    }

    // --- 2) MINOR-7: единый предикат «туннель поднят» включает verifying ---
    {
        CHECK(isTunnelUpStateName(QStringLiteral("connected")));
        CHECK(isTunnelUpStateName(QStringLiteral("connecting")));
        CHECK(isTunnelUpStateName(QStringLiteral("switching")));
        CHECK(isTunnelUpStateName(QStringLiteral("selecting")));
        CHECK(isTunnelUpStateName(QStringLiteral("verifying"))); // фаза xray — туннель ПОДНЯТ
        CHECK(!isTunnelUpStateName(QStringLiteral("disconnected")));
        CHECK(!isTunnelUpStateName(QStringLiteral("error")));
        CHECK(!isTunnelUpStateName(QString()));
    }

    // --- 3) MAJOR-1: кламп капа провалов data-plane (§17.2 — только через ConnectTunables) ---
    {
        TuningStore::set({}, {}, {}, {});
        CHECK(dataPlaneFailMaxTriesTuned() == 4); // дефолт
        TuningStore::set({{QStringLiteral("data_plane_fail_max_tries"), 0}}, {}, {}, {});
        CHECK(dataPlaneFailMaxTriesTuned() == 1); // пол: механизм нельзя выключить числом
        TuningStore::set({{QStringLiteral("data_plane_fail_max_tries"), -50}}, {}, {}, {});
        CHECK(dataPlaneFailMaxTriesTuned() == 1);
        TuningStore::set({{QStringLiteral("data_plane_fail_max_tries"), 999}}, {}, {}, {});
        CHECK(dataPlaneFailMaxTriesTuned() == 10); // потолок: выше — та же вечная карусель
        TuningStore::set({{QStringLiteral("data_plane_fail_max_tries"), 3}}, {}, {}, {});
        CHECK(dataPlaneFailMaxTriesTuned() == 3);
    }

    // --- 4) MAJOR-2: недоступный Xray читается как Auto (kill-switch xray_client) ---
    {
        TuningStore::set({}, {{QStringLiteral("xray_client"), true}}, {}, {});
        CHECK(effectiveTransportMode(TransportMode::Xray) == TransportMode::Xray);
        CHECK(effectiveTransportMode(TransportMode::Awg) == TransportMode::Awg);
        TuningStore::set({}, {{QStringLiteral("xray_client"), false}}, {}, {});
        CHECK(effectiveTransportMode(TransportMode::Xray) == TransportMode::Auto);
        CHECK(effectiveTransportMode(TransportMode::Awg) == TransportMode::Awg); // awg не трогаем

        // Сценарий инцидента: настройка «Xray» сохранена, бэк погасил kill-switch. Раньше это
        // означало no_transport на КАЖДОМ коннекте, пока пользователь сам не выберет «Авто».
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ awgNodeJson("9:awg", 9, "EE", 1.0),
                                             xrayNodeJson("9:xray", 9, "EE") }), err));
        eng.setTransportMode(TransportMode::Xray);        // «загрузка настройки» фасадом
        CHECK(eng.transportMode() == TransportMode::Auto); // и в UI, и в выборе — Авто
        CHECK(eng.debugSnapshot().transportMode == QLatin1String("auto"));
        CHECK(eng.connect(err));                          // коннект есть (awg-нода локации)
        CHECK(tun.lastUpNodeId == QLatin1String("9:awg"));

        // Kill-switch вернулся — сохранённый режим снова действует после явной установки.
        TuningStore::set({}, {{QStringLiteral("xray_client"), true}}, {}, {});
        eng.setTransportMode(TransportMode::Xray);
        CHECK(eng.transportMode() == TransportMode::Xray);
        // ...и гаснет прямо в сессии: normalizeTransportMode в connect() снимает мёртвый режим.
        TuningStore::set({}, {{QStringLiteral("xray_client"), false}}, {}, {});
        eng.requestStop();
        CHECK(eng.connect(err));
        CHECK(eng.transportMode() == TransportMode::Auto);
        CHECK(tun.lastUpNodeId == QLatin1String("9:awg"));
    }

    // --- 5) MAJOR-1: кап провалов data-plane — движок сдаётся вместо вечной карусели ---
    {
        TuningStore::set({{QStringLiteral("data_plane_fail_max_tries"), 3}},
                         {{QStringLiteral("rebind_heal"), false}}, {}, {});
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ awgNodeJson("9:awg", 9, "EE", 1.0),
                                             awgNodeJson("2:awg", 2, "PL", 1.0),
                                             awgNodeJson("5:awg", 5, "US", 1.0) }), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        CHECK(eng.dataPlaneFailStreak() == 0 && !eng.dataPlaneExhausted());

        CHECK(deadRound(eng));                    // 1-й провал → следующий кандидат
        CHECK(eng.dataPlaneFailStreak() == 1);
        CHECK(deadRound(eng));                    // 2-й
        CHECK(eng.dataPlaneFailStreak() == 2);
        // 3-й = кап: сдаёмся вместо очередного круга (третья ветка выбора игнорирует сессионные
        // провалы и снова выдала бы уже провалившийся узел — именно это крутило цикл вечно).
        CHECK(!eng.notifyConnectionLost());
        CHECK(eng.dataPlaneFailStreak() == 3);
        CHECK(eng.dataPlaneExhausted());
        CHECK(eng.state() == EngineState::Error);
        CHECK(eng.debugSnapshot().state == QLatin1String("error"));
        const int upsAtGiveUp = tun.upCalls;

        // Из Error движок туннель больше не поднимает (намерение снимает фасад, §13).
        CHECK(!eng.notifyConnectionLost());
        CHECK(tun.upCalls == upsAtGiveUp);

        // Явный стоп пользователя = новая сессия наблюдения: бюджет вернулся.
        eng.requestStop();
        CHECK(eng.dataPlaneFailStreak() == 0 && !eng.dataPlaneExhausted());
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        CHECK(eng.state() == EngineState::Connected);
    }

    // --- 6) MAJOR-1: удачная проба через туннель возвращает бюджет (оба транспорта) ---
    {
        TuningStore::set({{QStringLiteral("data_plane_fail_max_tries"), 2}},
                         {{QStringLiteral("rebind_heal"), false}}, {}, {});
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ awgNodeJson("9:awg", 9, "EE", 1.0),
                                             awgNodeJson("2:awg", 2, "PL", 1.0),
                                             awgNodeJson("5:awg", 5, "US", 1.0) }), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        CHECK(deadRound(eng));
        CHECK(eng.dataPlaneFailStreak() == 1);
        // awg своей фазы verify не имеет — доказательство живого data-plane даёт живая проба
        // (QualityProbe фасада). Без этого сброса редкие смерти нод за часы работы накопились бы
        // в ложное «сдаёмся».
        CHECK(!eng.feedProbeResult(true));
        CHECK(eng.dataPlaneFailStreak() == 0);
        CHECK(deadRound(eng));
        CHECK(deadRound(eng) == false);           // кап 2 исчерпан
        CHECK(eng.dataPlaneExhausted());
    }

    // --- 7) MAJOR-1: verifySucceeded (xray) тоже возвращает бюджет ---
    {
        TuningStore::set({{QStringLiteral("data_plane_fail_max_tries"), 4}},
                         {{QStringLiteral("xray_client"), true},
                          {QStringLiteral("transport_auto_pick"), true},
                          {QStringLiteral("rebind_heal"), false}}, {}, {});
        ServiceEngine eng;
        FakeTunnel tun;
        eng.setTunnel(&tun);
        QString err;
        CHECK(eng.loadSubscription(subJson({ awgNodeJson("9:awg", 9, "EE", 1.0),
                                             xrayNodeJson("9:xray", 9, "EE"),
                                             awgNodeJson("2:awg", 2, "PL", 1.0) }), err));
        CHECK(eng.connect(err));
        CHECK(eng.onTunnelConnected());
        CHECK(deadRound(eng));                    // ушли на другой транспорт той же локации
        CHECK(eng.dataPlaneFailStreak() == 1);
        if (eng.isVerifying()) {                  // подняли xray → фаза проверки трафика
            CHECK(eng.verifySucceeded());
            CHECK(eng.dataPlaneFailStreak() == 0);
            CHECK(!eng.dataPlaneExhausted());
        } else {
            CHECK(!eng.feedProbeResult(true));
            CHECK(eng.dataPlaneFailStreak() == 0);
        }
        // Адопт живого туннеля (§19) — тоже новая сессия наблюдения.
        eng.requestStop();
        CHECK(eng.adoptTunnelConnected());
        CHECK(eng.dataPlaneFailStreak() == 0 && !eng.dataPlaneExhausted());
    }

    if (g_failed == 0) {
        fprintf(stderr, "dataplane_guard_check: OK (%d checks — кап провалов, режим транспорта, "
                        "доказательство трафика, предикат фаз)\n", g_total);
        return 0;
    }
    fprintf(stderr, "dataplane_guard_check: FAILED %d/%d\n", g_failed, g_total);
    return 1;
}

// --- линк-стабы: сетевые части движка тестом не вызываются, но нужны линкеру (как failover_check). ---
namespace avpn {

bool Enrollment::enroll(QNetworkAccessManager *, const QString &, Identity &,
                        SecureAppSettingsRepository *, TrialResponse &, QString &error,
                        FetchOutcome *)
{
    error = QStringLiteral("stub");
    return false;
}

bool Enrollment::fetchSubscription(QNetworkAccessManager *, const QString &, const QString &,
                                   QByteArray &, QString &error, FetchOutcome *)
{
    error = QStringLiteral("stub");
    return false;
}

void Enrollment::saveLkgSubscription(const QByteArray &) { }

QString Enrollment::loadToken()
{
    return {};
}

void Enrollment::clearToken() { }

bool Identity::ensureKeys(SecureAppSettingsRepository *, QString &)
{
    return true;
}

} // namespace avpn
