// AVPN: нативный iOS safe-area inset. Окно на iOS поднято с Qt.ExpandedClientAreaHint (заходит под
// вырез/Dynamic Island), поэтому Qt SafeArea/PageController.safeAreaTopMargin дают 0 — читаем инсет
// напрямую из UIKit (значения в points = единицы QML). Вызывается из pageController.cpp под Q_OS_IOS.
#import <UIKit/UIKit.h>

static UIEdgeInsets avpnKeyWindowSafeInsets()
{
    UIWindow *keyWin = nil;
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
            if (![scene isKindOfClass:UIWindowScene.class]) continue;
            for (UIWindow *win in ((UIWindowScene *)scene).windows) {
                if (win.isKeyWindow) { keyWin = win; break; }
            }
            if (keyWin) break;
        }
    }
    if (!keyWin) {
        // фолбэк: первое доступное окно приложения
        for (UIWindow *win in UIApplication.sharedApplication.windows) {
            if (win.isKeyWindow) { keyWin = win; break; }
        }
        if (!keyWin) keyWin = UIApplication.sharedApplication.windows.firstObject;
    }
    if (!keyWin) return UIEdgeInsetsZero;
    if (@available(iOS 11.0, *)) return keyWin.safeAreaInsets;
    return UIEdgeInsetsZero;
}

extern "C" int avpnSafeAreaTop()    { return (int)(avpnKeyWindowSafeInsets().top + 0.5); }
extern "C" int avpnSafeAreaBottom() { return (int)(avpnKeyWindowSafeInsets().bottom + 0.5); }
