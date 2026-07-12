// AVPN — Tribe: гаситель авто-сдвига окна при клавиатуре (iOS).
//
// ПРОБЛЕМА (билды 75–77, 2026-07-11): QIOSInputContext::scroll() уводит root view вверх
// через layer.sublayerTransform (CoreAnimation; Qt-геометрия сдвига НЕ видит), если на
// момент показа клавиатуры курсор «перекрыт». Наш layout (телеграм-схема Занавеса:
// навбар скрыт, контент сжат margin'ом = высоте клавиатуры) уже поднимает композер сам —
// сдвиг Qt поверх даёт двойную компенсацию: «чёрная дыра» высотой с клавиатуру.
// Отключить их скролл нельзя (публичного API нет), «мягкий» пере-запуск их проверки не
// работает: diff в ImeState::update смотрит ЛОКАЛЬНЫЙ прямоугольник курсора внутри поля,
// а он не меняется, когда поле переезжает целиком (см. qiosinputcontext.mm).
//
// РЕШЕНИЕ: свой observer на те же UIKeyboard*-уведомления. NSNotificationCenter зовёт
// подписчиков в порядке регистрации: Qt подписан при старте плагина, мы — позже, значит
// наш обработчик выполняется ПОСЛЕ их scroll() в том же уведомлении — сбрасываем трансформ
// в identity до отрисовки кадра (визуально сдвига нет вообще). Отложенные повторы —
// страховка от их анимации и поздних пере-скроллов.
#import <QuartzCore/QuartzCore.h>
#import <UIKit/UIKit.h>

extern "C" void Avpn_resetKeyboardScroll(void)
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
        return;
    UIView *root = keyWin.rootViewController.view;
    if (!root)
        return;
    // Ключ анимации — из qiosinputcontext.mm (scroll()); снятие обязательно, иначе
    // CoreAnimation доигрывает их сдвиг поверх нашего identity.
    [root.layer removeAnimationForKey:@"AnimateSubLayerTransform"];
    if (!CATransform3DIsIdentity(root.layer.sublayerTransform))
        root.layer.sublayerTransform = CATransform3DIdentity;
}

static void avpnScheduleResets(void)
{
    Avpn_resetKeyboardScroll();
    // Страховочные повторы: их scroll() анимируется длительностью клавиатуры (~0.25с)
    // и может прилететь повторно (didChangeFrame). Сброс идемпотентен и дёшев.
    static const double kDelays[] = {0.05, 0.15, 0.35, 0.7};
    for (double delay : kDelays) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ Avpn_resetKeyboardScroll(); });
    }
}

// pageController.cpp: единая точка m_imeHeight. Репорт из willShow/willHide = момент
// СТАРТА анимации клавиатуры — QML-подъём композера стартует тем же кадром (жалоба
// 2026-07-12 «клавиатура появляется, а поле выезжает позже»: Qt-путь
// keyboardRectangleChanged сообщал высоту с опозданием).
extern "C" void Avpn_onKeyboardFrame(double height);

static void avpnReportKeyboardFrame(NSNotification *note)
{
    NSValue *endVal = note.userInfo[UIKeyboardFrameEndUserInfoKey];
    if (!endVal)
        return;
    const CGRect end = endVal.CGRectValue;
    const CGFloat screenH = UIScreen.mainScreen.bounds.size.height;
    // скрытие: endFrame целиком за нижней кромкой экрана → высота 0
    Avpn_onKeyboardFrame(MAX(0.0, screenH - CGRectGetMinY(end)));
}

extern "C" void Avpn_installKeyboardScrollKiller(void)
{
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSNotificationCenter *nc = NSNotificationCenter.defaultCenter;
        for (NSNotificationName name in @[
                 UIKeyboardWillShowNotification,
                 UIKeyboardDidShowNotification,
                 UIKeyboardWillChangeFrameNotification,
                 UIKeyboardDidChangeFrameNotification,
                 UIKeyboardWillHideNotification ]) {
            [nc addObserverForName:name
                            object:nil
                             queue:NSOperationQueue.mainQueue
                        usingBlock:^(NSNotification *note) {
                avpnReportKeyboardFrame(note);
                avpnScheduleResets();
            }];
        }
    });
}
