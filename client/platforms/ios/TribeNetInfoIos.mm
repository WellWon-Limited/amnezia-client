// AVPN (Доктор D-3): iOS-мост поколения сотовой сети — CoreTelephony
// CTTelephonyNetworkInfo.serviceCurrentRadioAccessTechnology (без разрешений).
// Возвращает статическую C-строку: "5g" | "lte" | "3g" | "2g" | "" (не сотовая/неизвестно).
// Образец моста — TribeHapticsIos.mm (extern "C", зовётся из TribeNetInfo.cpp).
// НЕ @import: в .mm C++-модули выключены (-fcxx-modules off) → @import не компилится;
// фреймворк линкуется явно в ios.cmake (FW_CORETELEPHONY) — паттерн AvpnDiagnostics.mm.
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <Foundation/Foundation.h>

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

// AVPN (Доктор): обезличенный код оператора MCC-MNC (напр. "250-02" = МегаФон РФ) — НЕ имя сети.
// Apple с iOS 16 задепрекейтила CTCarrier: mobileCountryCode/mobileNetworkCode возвращают nil или
// "65535" (спец-значение «недоступно») → тогда честное "". Работает лишь на iOS < 16; на новых
// устройствах оператор через API недоступен вообще (для них — ручной выбор в UI).
extern "C" const char *TribeNetInfo_carrier()
{
    static char buf[16] = "";
    buf[0] = '\0';
    static CTTelephonyNetworkInfo *info = [[CTTelephonyNetworkInfo alloc] init];
    NSDictionary<NSString *, CTCarrier *> *carriers = info.serviceSubscriberCellularProviders;
    for (CTCarrier *c in carriers.allValues) {
        NSString *mcc = c.mobileCountryCode;
        NSString *mnc = c.mobileNetworkCode;
        if (mcc.length && mnc.length
            && ![mcc isEqualToString:@"65535"] && ![mnc isEqualToString:@"65535"]) {
            snprintf(buf, sizeof(buf), "%s-%s", mcc.UTF8String, mnc.UTF8String);
            return buf;
        }
    }
    return buf; // "" — iOS 16+ закрыл оператора, либо не сотовая
}
