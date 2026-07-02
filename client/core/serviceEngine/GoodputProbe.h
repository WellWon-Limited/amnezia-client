// AVPN serviceEngine — классификация РЕАЛЬНОЙ пропускной способности (goodput) сервиса. [чистая логика — тестируема]
//
// Зачем: reachability («TLS собрался») = ложно-зелёный при DPI-троттлинге (RU душит YouTube ~128 кбит/с
// по SNI *.googlevideo.com — TLS проходит мгновенно, а видео не грузится). Правдивый сигнал — СКОЛЬКО
// реальных байт в секунду идёт через туннель на CDN сервиса. Раннер (ServiceProbe.cpp) качает N байт
// с реального byte-source (YoutubeSource/InstagramSource) и зовёт classify(). Здесь — ЧИСТАЯ арифметика.
#pragma once

#include <QtGlobal>

namespace avpn {

// Пороги kbit/s. RU-троттл ~128 кбит/с ⇒ попадает в Slow; нормальный VPN = единицы Мбит/с ⇒ Works.
struct GoodputThresholds {
    double worksKbps = 1000.0; // ≥ ⇒ works
    double slowKbps  = 100.0;  // [slow,works) ⇒ slow (троттлинг); < ⇒ blocked (задушено в ноль)
    qint64 minBytes  = 32768;  // меньше не считаем достоверным замером ⇒ blocked
};

class GoodputProbe {
public:
    using Thresholds = GoodputThresholds;

    // kbit/s = bytes*8 / ms (bits/(ms/1000)/1000). elapsedMs<=0 ⇒ 0 (нечего мерить).
    static double kbitPerSec(qint64 bytes, qint64 elapsedMs)
    {
        if (elapsedMs <= 0)
            return 0.0;
        return double(bytes) * 8.0 / double(elapsedMs);
    }

    // Классификация в ServiceState-int: 0 blocked, 1 slow, 2 works.
    // Меньше minBytes ⇒ замер недостоверен ⇒ blocked (не выдаём случайный «works» на крохах).
    static int classify(qint64 bytes, qint64 elapsedMs, const Thresholds &t = Thresholds{})
    {
        if (bytes < t.minBytes)
            return 0;                       // blocked: слишком мало данных для честного замера
        if (elapsedMs <= 0)
            return 2;                       // мгновенно ⇒ works
        const double kbps = kbitPerSec(bytes, elapsedMs);
        if (kbps >= t.worksKbps)
            return 2;                       // works
        if (kbps >= t.slowKbps)
            return 1;                       // slow (троттлинг)
        return 0;                           // blocked (задушено ниже порога полезности)
    }
};

} // namespace avpn
