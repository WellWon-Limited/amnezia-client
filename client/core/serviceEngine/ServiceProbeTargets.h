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
// так один сменившийся/легший IP не даёт ложный «заблок». YouTube/Instagram: host = fallback-SNI
// на душимом CDN (reachability, если byte-source не резолвится); sampleBytes/пороги — дефолтные.
inline QList<ServiceProbeConfig> defaultServiceProbeConfigs()
{
    QList<ServiceProbeConfig> cfgs;
    cfgs.append({QStringLiteral("telegram"), ServiceProbeConfig::Mtproto,
                 QStringLiteral("149.154.167.51"), 443, 1500,
                 QStringList{QStringLiteral("149.154.167.91"), QStringLiteral("91.108.56.130")}});
    cfgs.append({QStringLiteral("youtube"), ServiceProbeConfig::Goodput,
                 QStringLiteral("redirector.googlevideo.com")});
    cfgs.append({QStringLiteral("instagram"), ServiceProbeConfig::Goodput,
                 QStringLiteral("static.cdninstagram.com")});
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
