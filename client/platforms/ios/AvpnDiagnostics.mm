// AVPN — реализация авто-сбора диагностики вылетов (MetricKit). См. AvpnDiagnostics.h.
#import "AvpnDiagnostics.h"

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <MetricKit/MetricKit.h> // НЕ @import: в .mm C++-модули выключены (-fcxx-modules off) → @import не компилится; фреймворк линкуется явно в ios.cmake (FW_METRICKIT)

// AVPN backend-first (2026-07-10): база «переезжает» вместе с edge-walk движка
// (AvpnDiagnostics_setBase из activeEdgeChanged). Фолбэк — вкомпиленный дефолт control plane.
static NSString *const kAvpnDiagDefaultBase = @"https://api.tribevpn.com";
static NSString *const kAvpnDiagBaseKey = @"AvpnDiagBase";

void AvpnDiagnostics_setBase(const char *baseUrl)
{
    if (baseUrl && *baseUrl)
        [[NSUserDefaults standardUserDefaults] setObject:[NSString stringWithUTF8String:baseUrl]
                                                  forKey:kAvpnDiagBaseKey];
}

static NSURL *avpnDiagUrl(void)
{
    NSString *base = [[NSUserDefaults standardUserDefaults] stringForKey:kAvpnDiagBaseKey];
    if (base.length == 0)
        base = kAvpnDiagDefaultBase;
    return [NSURL URLWithString:[base stringByAppendingString:@"/v1/diag/crash"]];
}

// Best-effort POST одного payload'а. Тело — сырой JSON MetricKit (со стеком/сигналом/UUID/build).
// Приватность: НЕ отправляем идентификатор устройства (IDFV) — крэш-диагностика анонимна,
// привязки к устройству/аккаунту нет (App Privacy: Crash Data = Not Linked). Атрибуция — только
// по версии/сборке приложения (какая сборка падает), без Apple Device-ID.
static void avpnDiagPost(NSData *json)
{
    if (json.length == 0)
        return;
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:avpnDiagUrl()];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 20;
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    NSString *build = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
    if (build) [req setValue:build forHTTPHeaderField:@"X-App-Build"];
    NSString *ver = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
    if (ver) [req setValue:ver forHTTPHeaderField:@"X-App-Version"];
    req.HTTPBody = json;
    NSURLSessionDataTask *task = [[NSURLSession sharedSession]
        dataTaskWithRequest:req
          completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
              // best-effort: если бэк недоступен, iOS повторно отдаст payload на следующих запусках
              // (MetricKit держит окно ~24h), терять диагностику не страшно — не ретраим вручную.
              (void)d; (void)r; (void)e;
          }];
    [task resume];
}

API_AVAILABLE(ios(14.0))
@interface AvpnMetricSubscriber : NSObject <MXMetricManagerSubscriber>
@end

@implementation AvpnMetricSubscriber
// Диагностика (краши/зависания/cpu-exception). Метрики (didReceiveMetricPayloads) нам не нужны.
- (void)didReceiveDiagnosticPayloads:(NSArray<MXDiagnosticPayload *> *)payloads API_AVAILABLE(ios(14.0))
{
    for (MXDiagnosticPayload *payload in payloads)
        avpnDiagPost([payload JSONRepresentation]);
}
@end

void AvpnDiagnostics_install(void)
{
#if !MACOS_NE
    if (@available(iOS 14.0, *)) {
        static AvpnMetricSubscriber *subscriber = nil; // strong-удержание на время жизни процесса
        static dispatch_once_t once;
        dispatch_once(&once, ^{
            subscriber = [AvpnMetricSubscriber new];
            [[MXMetricManager sharedManager] addSubscriber:subscriber];
            NSLog(@"AvpnDiagnostics: MetricKit subscriber installed");
        });
    }
#endif
}
