// client/core/serviceEngine/tests/probe_targets_check.cpp
// AVPN: дефолты чипов + мерж серверных probe_targets (ServiceProbeTargets.h).
//
// Регресс инцидента 2026-07-11: боевой /v1/config отдавал probe_targets АРБИТРА
// (kind:"tcp", telegram→web.telegram.org, без instagram) — старый applyRemoteProbeTargets
// ЗАМЕЩАЛ им вшитые цели чипов целиком: MTProto-проба била в веб-фронтенд (RST) ⇒
// Telegram вечно красный; instagram выпадал из набора ⇒ вечно серый. Контракт после
// фикса: мержим с дефолтами, чипы переопределяют ТОЛЬКО явные kind mtproto/goodput/https,
// kind "tcp"/неизвестный = данные арбитра (игнор), неизвестный target = игнор (чипа нет).
#include "../ServiceProbeTargets.h"
#include <QCoreApplication>
#include <cstdio>

static int g_fail = 0;
#define CHECK(cond, msg) do { if (cond) printf("OK   %s\n", msg); \
    else { printf("FAIL %s\n", msg); ++g_fail; } } while (0)

using avpn::ProbeTarget;
using avpn::ServiceProbeConfig;

static ProbeTarget pt(const char *target, const char *kind, const char *host, int port = 443)
{
    ProbeTarget t;
    t.target = QString::fromLatin1(target);
    t.kind = QString::fromLatin1(kind);
    t.host = QString::fromLatin1(host);
    t.port = port;
    return t;
}

static bool sameAsDefaults(const QList<ServiceProbeConfig> &cfgs)
{
    const QList<ServiceProbeConfig> def = avpn::defaultServiceProbeConfigs();
    if (cfgs.size() != def.size())
        return false;
    for (int i = 0; i < cfgs.size(); ++i) {
        if (cfgs[i].key != def[i].key || cfgs[i].kind != def[i].kind
            || cfgs[i].host != def[i].host || cfgs[i].port != def[i].port
            || cfgs[i].fallbackHosts != def[i].fallbackHosts)
            return false;
    }
    return true;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    // --- Дефолты (единый источник для конструктора и мержа) ---
    const QList<ServiceProbeConfig> def = avpn::defaultServiceProbeConfigs();
    CHECK(def.size() == 4, "defaults: четыре сервиса (Доктор v1: +whatsapp)");
    CHECK(def[0].key == "telegram" && def[0].kind == ServiceProbeConfig::Mtproto,
          "defaults: telegram = Mtproto");
    CHECK(def[0].host == "149.154.167.51" && def[0].fallbackHosts
              == QStringList({"149.154.167.91", "91.108.56.130"}),
          "defaults: telegram три seed-DC");
    CHECK(def[1].key == "youtube" && def[1].kind == ServiceProbeConfig::Goodput
              && def[1].host == "redirector.googlevideo.com",
          "defaults: youtube = Goodput");
    CHECK(def[2].key == "instagram" && def[2].kind == ServiceProbeConfig::Goodput
              && def[2].host == "static.cdninstagram.com",
          "defaults: instagram = Goodput");

    // --- Регресс инцидента: константа арбитра (kind tcp) НЕ трогает чипы ---
    const QList<ProbeTarget> arbiter = {
        pt("telegram", "tcp", "web.telegram.org"),
        pt("youtube", "tcp", "www.youtube.com"),
        pt("gemini", "tcp", "gemini.google.com"),
        pt("openai", "tcp", "api.openai.com"),
    };
    CHECK(sameAsDefaults(avpn::mergeRemoteProbeTargets(def, arbiter)),
          "арбитр-константа (tcp) => дефолты нетронуты");

    // --- Пустой список => дефолты ---
    CHECK(sameAsDefaults(avpn::mergeRemoteProbeTargets(def, {})),
          "пустой probe_targets => дефолты");

    // --- Явный mtproto-оверрайд: один хост заменяет seed'ы ---
    {
        const auto out = avpn::mergeRemoteProbeTargets(def, {pt("telegram", "mtproto", "1.2.3.4", 8443)});
        CHECK(out.size() == 4, "mtproto-оверрайд: набор сервисов не худеет");
        CHECK(out[0].key == "telegram" && out[0].kind == ServiceProbeConfig::Mtproto
                  && out[0].host == "1.2.3.4" && out[0].port == 8443
                  && out[0].fallbackHosts.isEmpty(),
              "mtproto-оверрайд: host/port заменены, старые seed'ы убраны");
        CHECK(out[1].host == def[1].host && out[2].host == def[2].host,
              "mtproto-оверрайд: youtube/instagram нетронуты");
    }

    // --- Группа из нескольких записей одного target => host + fallbackHosts по порядку ---
    {
        const auto out = avpn::mergeRemoteProbeTargets(
            def, {pt("telegram", "mtproto", "1.1.1.1"), pt("telegram", "mtproto", "2.2.2.2"),
                  pt("telegram", "mtproto", "3.3.3.3")});
        CHECK(out[0].host == "1.1.1.1"
                  && out[0].fallbackHosts == QStringList({"2.2.2.2", "3.3.3.3"}),
              "multi-seed группа: первый = host, остальные = fallbackHosts");
    }

    // --- Goodput-оверрайд youtube: только fallback-SNI меняется ---
    {
        const auto out = avpn::mergeRemoteProbeTargets(def, {pt("youtube", "goodput", "rr1.googlevideo.com")});
        CHECK(out[1].kind == ServiceProbeConfig::Goodput && out[1].host == "rr1.googlevideo.com",
              "goodput-оверрайд: youtube host заменён");
        CHECK(out[0].host == def[0].host && out[0].fallbackHosts == def[0].fallbackHosts,
              "goodput-оверрайд: telegram seed'ы нетронуты");
    }

    // --- Https-деградация тоже явная ---
    {
        const auto out = avpn::mergeRemoteProbeTargets(def, {pt("instagram", "https", "www.instagram.com")});
        CHECK(out[2].kind == ServiceProbeConfig::Https && out[2].host == "www.instagram.com",
              "https-оверрайд: instagram деградирует явно");
    }

    // --- Неизвестный target / неизвестный kind => игнор ---
    // (Доктор v1: whatsapp теперь В ДЕФОЛТАХ — контракт сменён осознанно; «неизвестным» стал discord)
    CHECK(sameAsDefaults(avpn::mergeRemoteProbeTargets(def, {pt("discord", "https", "discord.com")})),
          "неизвестный target => игнор (чипа в UI нет)");
    {
        const auto out = avpn::mergeRemoteProbeTargets(def, {pt("whatsapp", "https", "wa.example.org")});
        CHECK(out.last().key == "whatsapp" && out.last().host == "wa.example.org",
              "whatsapp в дефолтах (последним) => сервер оверрайдит хост");
    }
    CHECK(sameAsDefaults(avpn::mergeRemoteProbeTargets(def, {pt("telegram", "udp", "1.2.3.4")})),
          "неизвестный kind => игнор");

    // --- Смесь: арбитр-tcp рядом с явным оверрайдом — работает только явный ---
    {
        const auto out = avpn::mergeRemoteProbeTargets(
            def, {pt("telegram", "tcp", "web.telegram.org"), pt("youtube", "goodput", "rr2.googlevideo.com")});
        CHECK(out[0].host == def[0].host && out[1].host == "rr2.googlevideo.com",
              "смесь tcp+goodput: tcp игнор, goodput применён");
    }

    if (g_fail) {
        printf(">>> probe_targets: %d FAIL\n", g_fail);
        return 1;
    }
    printf(">>> probe_targets: OK\n");
    return 0;
}
