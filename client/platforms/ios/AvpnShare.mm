// AVPN: нативный iOS share sheet для произвольного текста/ссылки (рефералка, перенос подписки).
// В отличие от апстримного IosController::shareText (файлы + вложенный QEventLoop) — non-blocking:
// презентуем UIActivityViewController и сразу возвращаемся (правило движка: никаких nested event
// loop на GUI-потоке). Валидный http(s)-URL шарим как NSURL (мессенджеры видят именно ссылку).
#import <UIKit/UIKit.h>

static UIViewController *avpnTopViewController()
{
    UIWindow *keyWin = nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class])
            continue;
        for (UIWindow *win in ((UIWindowScene *)scene).windows) {
            if (win.isKeyWindow) { keyWin = win; break; }
        }
        if (keyWin)
            break;
    }
    if (!keyWin)
        keyWin = UIApplication.sharedApplication.windows.firstObject;

    UIViewController *vc = keyWin.rootViewController;
    while (vc.presentedViewController)
        vc = vc.presentedViewController;
    return vc;
}

extern "C" bool AvpnShare_presentText(const char *utf8Text)
{
    NSString *text = utf8Text ? [NSString stringWithUTF8String:utf8Text] : nil;
    if (text.length == 0)
        return false;

    UIViewController *host = avpnTopViewController();
    if (!host)
        return false;

    id item = text;
    NSURL *url = [NSURL URLWithString:text];
    if (url && ([url.scheme isEqualToString:@"https"] || [url.scheme isEqualToString:@"http"]))
        item = url;

    UIActivityViewController *activity =
            [[UIActivityViewController alloc] initWithActivityItems:@[ item ] applicationActivities:nil];

    // iPad: без sourceView поповер падает — якорим по центру хост-вью
    UIPopoverPresentationController *pop = activity.popoverPresentationController;
    if (pop) {
        pop.sourceView = host.view;
        pop.sourceRect = CGRectMake(CGRectGetMidX(host.view.bounds), CGRectGetMidY(host.view.bounds), 1, 1);
        pop.permittedArrowDirections = 0;
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        [host presentViewController:activity animated:YES completion:nil];
    });
    return true;
}
