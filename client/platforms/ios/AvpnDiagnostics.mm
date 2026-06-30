// AVPN — реализация авто-сбора диагностики вылетов (MetricKit). См. AvpnDiagnostics.h.
#import "AvpnDiagnostics.h"

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
@import MetricKit; // clang-module auto-link MetricKit.framework (как UserNotifications в AvpnPush)

// Куда шлём payload'ы. Совпадает с дефолтным control-plane движка (AvpnEngineQml m_baseUrl).
static NSString *const kAvpnDiagUrl = @"https://api.tribevpn.com/v1/diag/crash";

// Best-effort POST одного payload'а. Тело — сырой JSON MetricKit (со стеком/сигналом/UUID/build).
// Заголовки X-Device/X-App-Build — для атрибуции (какой тестер/сборка) без парсинга на клиенте.
static void avpnDiagPost(NSData *json)
{
    if (json.length == 0)
        return;
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:kAvpnDiagUrl]];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 20;
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    NSString *idfv = [[[UIDevice currentDevice] identifierForVendor] UUIDString];
    if (idfv) [req setValue:idfv forHTTPHeaderField:@"X-Device"];
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
