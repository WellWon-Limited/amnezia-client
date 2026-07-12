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

// ПОКАДРОВЫЙ гаситель (2026-07-12): пока наш margin АНИМИРУЕТСЯ (композер едет к
// клавиатуре), поле первые кадры ещё «перекрыто» — Qt перезапускает scrollToCursor
// посреди анимации (вне UIKeyboard*-уведомлений: у них триггер — смена cursor rect).
// Редкие dispatch_after-сбросы оставляли до ~200мс отрисованного чужого сдвига —
// контент видимо «прилетал сверху вниз». CADisplayLink снимает трансформ КАЖДЫЙ кадр
// в течение окна после последнего клавиатурного события — сдвигу Qt не достаётся ни
// одного кадра. Тик дёшев (проверка identity + присваивание).
static CADisplayLink *g_avpnKbLink = nil;
static CFTimeInterval g_avpnKbLinkUntil = 0;

@interface AvpnKbResetTarget : NSObject
- (void)tick:(CADisplayLink *)link;
@end
@implementation AvpnKbResetTarget
- (void)tick:(CADisplayLink *)link
{
    Avpn_resetKeyboardScroll();
    if (CACurrentMediaTime() > g_avpnKbLinkUntil) {
        [link invalidate];
        g_avpnKbLink = nil;
    }
}
@end

static void avpnScheduleResets(void)
{
    Avpn_resetKeyboardScroll();
    // окно с запасом: анимация клавиатуры ~0.25с + поздние пере-скроллы Qt (didShow и
    // реакция на движение поля нашим margin-Behavior 0.25с)
    g_avpnKbLinkUntil = CACurrentMediaTime() + 1.0;
    if (!g_avpnKbLink) {
        static AvpnKbResetTarget *target = nil;
        static dispatch_once_t once;
        dispatch_once(&once, ^{ target = [AvpnKbResetTarget new]; });
        g_avpnKbLink = [CADisplayLink displayLinkWithTarget:target selector:@selector(tick:)];
        [g_avpnKbLink addToRunLoop:NSRunLoop.mainRunLoop forMode:NSRunLoopCommonModes];
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
