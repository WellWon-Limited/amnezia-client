// AVPN (Доктор D-3): iOS-мост поколения сотовой сети — CoreTelephony
// CTTelephonyNetworkInfo.serviceCurrentRadioAccessTechnology (без разрешений).
// Возвращает статическую C-строку: "5g" | "lte" | "3g" | "2g" | "" (не сотовая/неизвестно).
// Образец моста — TribeHapticsIos.mm (extern "C", зовётся из TribeNetInfo.cpp).
// @import — авто-линк CoreTelephony clang-модулем (паттерн AvpnDiagnostics.mm: обычный
// #import НЕ линкует фреймворк, ld падал «symbol(s) not found» на архиве)
@import CoreTelephony;
@import Foundation;

extern "C" const char *TribeNetInfo_cellGen()
{
    static CTTelephonyNetworkInfo *info = [[CTTelephonyNetworkInfo alloc] init];
    NSDictionary<NSString *, NSString *> *rats = info.serviceCurrentRadioAccessTechnology;
    if (rats.count == 0)
        return "";
    // Несколько SIM — берём «лучшую» технологию (данные обычно идут через неё).
    int best = 0; // 0 unknown, 1=2g, 2=3g, 3=lte, 4=5g
    for (NSString *rat in rats.allValues) {
        int gen = 0;
        if (@available(iOS 14.1, *)) {
            if ([rat isEqualToString:CTRadioAccessTechnologyNR]
                || [rat isEqualToString:CTRadioAccessTechnologyNRNSA])
                gen = 4;
        }
        if (gen == 0) {
            if ([rat isEqualToString:CTRadioAccessTechnologyLTE])
                gen = 3;
            else if ([rat isEqualToString:CTRadioAccessTechnologyWCDMA]
                     || [rat isEqualToString:CTRadioAccessTechnologyHSDPA]
                     || [rat isEqualToString:CTRadioAccessTechnologyHSUPA]
                     || [rat isEqualToString:CTRadioAccessTechnologyCDMAEVDORev0]
                     || [rat isEqualToString:CTRadioAccessTechnologyCDMAEVDORevA]
                     || [rat isEqualToString:CTRadioAccessTechnologyCDMAEVDORevB]
                     || [rat isEqualToString:CTRadioAccessTechnologyeHRPD])
                gen = 2;
            else if ([rat isEqualToString:CTRadioAccessTechnologyEdge]
                     || [rat isEqualToString:CTRadioAccessTechnologyGPRS]
                     || [rat isEqualToString:CTRadioAccessTechnologyCDMA1x])
                gen = 1;
        }
        if (gen > best)
            best = gen;
    }
    switch (best) {
    case 4: return "5g";
    case 3: return "lte";
    case 2: return "3g";
    case 1: return "2g";
    default: return "";
    }
}
