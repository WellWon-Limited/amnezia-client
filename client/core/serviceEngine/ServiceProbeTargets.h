// AVPN serviceEngine — вшитые цели проб чипов + мерж серверного probe_targets. [IN-FORK / header-only]
//
// ИНЦИДЕНТ 2026-07-11 (не повторять): /v1/config исторически отдаёт probe_targets АРБИТРА
// (бэкенд-константа PROBE_TARGETS, kind:"tcp" — reachability с egress нод: web.telegram.org,
// gemini, openai…). Старый applyRemoteProbeTargets считал это оверрайдом ЧИПОВ и ЗАМЕЩАЛ
// setServices() целиком: MTProto-проба била в web.telegram.org (веб-фронтенд, RST на MTProto)
// ⇒ Telegram вечно красный; instagram в списке арбитра нет ⇒ выпадал из проб, чип вечно серый.
//
// КОНТРАКТ (после фикса):
//   • серверные записи мержатся С ДЕФОЛТАМИ, никогда не замещают набор целиком;
//   • оверрайд чипа — ТОЛЬКО явный kind "mtproto"/"goodput"/"https" (клиентская семантика);
//     kind "tcp"/неизвестный = данные арбитра/будущее ⇒ для чипов игнор;
//   • target, которого нет в дефолтах, игнорируется (чипа в UI нет — m_serviceStatus сидируется
//     дефолтами, проба без чипа = мусорный трафик);
//   • несколько записей одного target = multi-seed: первый host — основной, остальные — fallbackHosts
//     (как вшитые seed-DC Telegram);
//   • пусто/ничего не удостоено ⇒ вшитые дефолты (бэкенд откатывает поведение, PATCH probe_targets:[]).
#pragma once

#include "ConfigTypes.h"
#include "ServiceProbe.h"

#include <QHash>
#include <QList>
#include <QString>
#include <QStringList>

namespace avpn {

// Единый источник вшитых целей чипов (конструктор AvpnEngineQml + база мержа).
// Telegram: несколько seed-DC-IP (OONI-стабильные DC2/DC4/DC5) — первый ответивший resPQ ⇒ works;
// так один сменившийся/легший IP не даёт ложный «заблок». YouTube/Instagram (v2): reachUrls =
// ДВА лёгких официальных голоса разных контуров (web/API-tier + CDN-tier; все проверены вживую
// 2026-07-12: 204/200/крошечные ответы, без consent/login-редиректов) — кворум решает
// зелёный/красный (ChipLogic.h), server-driven через lists.chip_reach_urls_<key>;
// host = fallback-SNI для серверных целей без пары голосов.
inline QList<ServiceProbeConfig> defaultServiceProbeConfigs()
{
    QList<ServiceProbeConfig> cfgs;
    cfgs.append({QStringLiteral("telegram"), ServiceProbeConfig::Mtproto,
                 QStringLiteral("149.154.167.51"), 443, 1500,
                 QStringList{QStringLiteral("149.154.167.91"), QStringLiteral("91.108.56.130")}});
    {
        ServiceProbeConfig yt;
        yt.key = QStringLiteral("youtube");
        yt.kind = ServiceProbeConfig::Goodput;
        yt.host = QStringLiteral("redirector.googlevideo.com");
        // Голос 1 — web/API-tier (204, 0 байт, consent не триггерит); голос 2 — видео-CDN-контур
        // googlevideo (именно его душат/режут — RST здесь при живом вебе ⇒ потолок slow).
        yt.reachUrls = QStringList{QStringLiteral("https://www.youtube.com/generate_204"),
                                   QStringLiteral("https://redirector.googlevideo.com/generate_204")};
        cfgs.append(yt);
    }
    {
        ServiceProbeConfig ig;
        ig.key = QStringLiteral("instagram");
        ig.kind = ServiceProbeConfig::Goodput;
        ig.host = QStringLiteral("static.cdninstagram.com");
        // Голос 1 — API-домен нативного приложения (200, 15 байт, без auth; 4xx тоже = «жив»);
        // голос 2 — web-tier favicon (200, ~2 КБ, без login-редиректа). HTML главной больше
        // НЕ парсим (гео-A/B вёрстка/бот-детект — источник «вечно серого» чипа).
        ig.reachUrls = QStringList{QStringLiteral("https://i.instagram.com/api/v1/si/fetch_headers/"),
                                   QStringLiteral("https://www.instagram.com/favicon.ico")};
        cfgs.append(ig);
    }
    {
        // AVPN (Доктор v1, 2026-07-17): WhatsApp — HEAD https://web.whatsapp.com/ с реальным SNI
        // (probeHttps): DPI-блок домена = RST/timeout ⇒ Blocked; живой ответ (2xx/3xx) ⇒ works.
        // Сырой TCP-connect к e{1..16}.whatsapp.net:443/5222 (OONI ts-018) — v2 (нужен новый Kind).
        // Сервер может оверрайдить через probe_targets, гасить — lists.service_chips_disabled.
        // В КОНЦЕ списка намеренно: контракт-тесты и чипы держат порядок tg/yt/ig стабильным.
        ServiceProbeConfig wa;
        wa.key = QStringLiteral("whatsapp");
        wa.kind = ServiceProbeConfig::Https;
        wa.host = QStringLiteral("web.whatsapp.com");
        cfgs.append(wa);
    }
    return cfgs;
}

// kind-строка контракта → Kind чипов. true только для ЯВНОЙ клиентской семантики.
inline bool chipKindFromString(const QString &kind, ServiceProbeConfig::Kind &out)
{
    if (kind == QLatin1String("mtproto")) { out = ServiceProbeConfig::Mtproto; return true; }
    if (kind == QLatin1String("goodput")) { out = ServiceProbeConfig::Goodput; return true; }
    if (kind == QLatin1String("https"))   { out = ServiceProbeConfig::Https;   return true; }
    return false; // "tcp" (арбитр) и всё неизвестное — не для чипов
}

// Мерж серверного probe_targets в дефолты чипов (см. КОНТРАКТ выше). Чистая функция — TDD в
// tests/probe_targets_check.cpp (build_probe_targets.sh).
inline QList<ServiceProbeConfig> mergeRemoteProbeTargets(const QList<ServiceProbeConfig> &defaults,
                                                         const QList<ProbeTarget> &remote)
{
    QList<ServiceProbeConfig> out = defaults;
    QHash<QString, int> idxByKey; // key → индекс в out
    for (int i = 0; i < out.size(); ++i)
        idxByKey.insert(out[i].key, i);

    QHash<QString, bool> seen; // target уже начал группу → следующие записи = fallbackHosts
    for (const ProbeTarget &t : remote) {
        ServiceProbeConfig::Kind kind;
        if (!chipKindFromString(t.kind, kind))
            continue; // данные арбитра / будущий kind — чипы не трогаем
        const auto it = idxByKey.constFind(t.target);
        if (it == idxByKey.constEnd())
            continue; // сервиса нет в дефолтах ⇒ нет чипа ⇒ игнор
        ServiceProbeConfig &c = out[it.value()];
        if (!seen.value(t.target)) {
            // первая запись группы — полный оверрайд цели (host/port/kind), seed'ы дефолта убираем:
            // оператор задал явный список, старые вперемешку с новым дали бы неконсистентную серию
            c.kind = kind;
            c.host = t.host;
            c.port = t.port;
            c.fallbackHosts.clear();
            seen.insert(t.target, true);
        } else {
            c.fallbackHosts.append(t.host); // multi-seed: доп. хост группы
        }
    }
    return out;
}

} // namespace avpn
