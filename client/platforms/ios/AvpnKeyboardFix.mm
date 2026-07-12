// AVPN — Tribe: гаситель авто-сдвига окна при клавиатуре (iOS).
//
// ПРОБЛЕМА (билды 75–77, 2026-07-11): QIOSInputContext::scroll() уводит root view вверх
// через layer.sublayerTransform (CoreAnimation; Qt-геометрия сдвига НЕ видит), если на
// момент показа клавиатуры курсор «перекрыт». Наш layout (телеграм-схема Занавеса:
// навбар скрыт, контент сжат margin'ом = высоте клавиатуры) уже поднимает композер сам —
// сдвиг Qt поверх даёт двойную компенсацию: «чёрная дыра» высотой с клавиатуру.
// Отключить их скролл публичным API нельзя; «мягкий» пере-запуск их проверки не работает
// (diff ImeState::update смотрит ЛОКАЛЬНЫЙ прямоугольник курсора — см. qiosinputcontext.mm).
//
// ЭВОЛЮЦИЯ РЕШЕНИЯ (2026-07-12): сбросы transform'а ПОСЛЕ факта (observer + dispatch_after,
// затем CADisplayLink покадрово) гонку не выигрывают детерминированно: Qt пере-скроллит к
// курсору ПОСРЕДИ нашей margin-анимации (поле в первые кадры формально «перекрыто», его
// триггер — смена cursor rect, НЕ клавиатурные уведомления), и в части кадров успевал
// отрисоваться его убывающий сдвиг — «приложение съезжает сверху вниз к клавиатуре».
//
// ФИНАЛ: канал сдвига закрывается СОВСЕМ — isa-swizzle слоя root view (штатный приём
// ObjC-рантайма, так же работает системный KVO): динамический сабкласс перекрывает
// setSublayerTransform: (всегда identity) и addAnimation:forKey: (ключ их скролла —
// в мусор). Qt физически не может сдвинуть окно; единственная анимация — наш подъём
// композера (PageStart, Behavior на bottomMargin) синхронно с клавиатурой.
// У root view приложения sublayerTransform больше никем не используется — безопасно.
#import <QuartzCore/QuartzCore.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>

static const char *kAvpnNoScrollPrefix = "AvpnNoScroll_";

static void avpnSetSublayerTransformIMP(id self, SEL _cmd, CATransform3D t)
{
    (void)t; // единственный писатель у root view — клавиатурный скролл Qt; держим identity
    struct objc_super sup = { self, class_getSuperclass(object_getClass(self)) };
    ((void (*)(struct objc_super *, SEL, CATransform3D))objc_msgSendSuper)(&sup, _cmd,
                                                                           CATransform3DIdentity);
}

static void avpnAddAnimationIMP(id self, SEL _cmd, CAAnimation *anim, NSString *key)
{
    // ключ анимации их скролла — из qiosinputcontext.mm; без этого фильтра presentation
    // доигрывал бы сдвиг даже при неизменной модели
    if ([key isEqualToString:@"AnimateSubLayerTransform"])
        return;
    struct objc_super sup = { self, class_getSuperclass(object_getClass(self)) };
    ((void (*)(struct objc_super *, SEL, CAAnimation *, NSString *))objc_msgSendSuper)(&sup, _cmd,
                                                                                       anim, key);
}

static void avpnNeuterLayer(CALayer *layer)
{
    if (!layer)
        return;
    Class cur = object_getClass(layer);
    if (strncmp(class_getName(cur), kAvpnNoScrollPrefix, strlen(kAvpnNoScrollPrefix)) == 0)
        return; // уже подменён
    char subName[256];
    snprintf(subName, sizeof(subName), "%s%s", kAvpnNoScrollPrefix, class_getName(cur));
    Class sub = objc_getClass(subName);
    if (!sub) {
        sub = objc_allocateClassPair(cur, subName, 0);
        if (!sub)
            return; // не смогли — остаёмся на сбросах ниже (хуже, но работает)
        Method mT = class_getInstanceMethod(cur, @selector(setSublayerTransform:));
        Method mA = class_getInstanceMethod(cur, @selector(addAnimation:forKey:));
        if (!mT || !mA)
            return;
        class_addMethod(sub, @selector(setSublayerTransform:), (IMP)avpnSetSublayerTransformIMP,
                        method_getTypeEncoding(mT));
        class_addMethod(sub, @selector(addAnimation:forKey:), (IMP)avpnAddAnimationIMP,
                        method_getTypeEncoding(mA));
        objc_registerClassPair(sub);
    }
    object_setClass(layer, sub);
}

extern "C" void Avpn_resetKeyboardScroll(void)
{
    UIView *root = nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class])
            continue;
        for (UIWindow *win in ((UIWindowScene *)scene).windows) {
            if (win.isKeyWindow) { root = win.rootViewController.view; break; }
        }
        if (root)
            break;
    }
    if (!root)
        return;
    // Закрыть канал сдвига (идемпотентно) + вычистить, что могло примениться ДО подмены
    // (Qt-observer в том же уведомлении бежит раньше нашего — кадр отрисоваться не успевает).
    avpnNeuterLayer(root.layer);
    [root.layer removeAnimationForKey:@"AnimateSubLayerTransform"];
    if (!CATransform3DIsIdentity(root.layer.sublayerTransform))
        root.layer.sublayerTransform = CATransform3DIdentity;
}

// ── «приклейка» композера к клавиатуре (2026-07-12, финал синхронизации) ─────
// Как WhatsApp/Telegram, но для QML: невидимый UIView пристёгнут констрейном к
// keyboardLayoutGuide.topAnchor (публичный API iOS 15+) — UIKit ведёт его В ТОЙ ЖЕ
// анимации, что клавиатуру (та самая приватная spring-кривая, интерактивное закрытие
// пальцем — тоже). CADisplayLink каждый кадр читает ФАКТИЧЕСКОЕ положение трекера
// (presentationLayer) и отдаёт высоту в QML БЕЗ нашей анимации (Behavior на iOS выкл.) —
// margin повторяет реальное движение клавиатуры покадрово. Аппроксимации кривой
// (250мс OutCubic → 500мс bezier) «чуть-чуть отставали» — теперь источник один.
extern "C" void Avpn_onKeyboardFrame(double height);

static UIView *g_avpnKbTracker = nil;
static CADisplayLink *g_avpnKbLink = nil;
static double g_avpnKbLastH = -1;
static CFTimeInterval g_avpnKbStableSince = 0;

static UIView *avpnRootView(void)
{
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class])
            continue;
        for (UIWindow *win in ((UIWindowScene *)scene).windows)
            if (win.isKeyWindow)
                return win.rootViewController.view;
    }
    return nil;
}

static void avpnEnsureTracker(void)
{
    if (g_avpnKbTracker)
        return;
    if (@available(iOS 15.0, *)) {
        UIView *root = avpnRootView();
        if (!root)
            return;
        UIView *v = [UIView new];
        v.userInteractionEnabled = NO;
        v.hidden = YES; // скрытые вьюхи участвуют в layout — нам нужна только геометрия
        v.translatesAutoresizingMaskIntoConstraints = NO;
        [root addSubview:v];
        [NSLayoutConstraint activateConstraints:@[
            [v.leadingAnchor constraintEqualToAnchor:root.leadingAnchor],
            [v.trailingAnchor constraintEqualToAnchor:root.trailingAnchor],
            [v.topAnchor constraintEqualToAnchor:root.keyboardLayoutGuide.topAnchor],
            [v.bottomAnchor constraintEqualToAnchor:root.bottomAnchor],
        ]];
        g_avpnKbTracker = v;
    }
}

// ФАЗОВАЯ СИНХРОНИЗАЦИЯ (2026-07-12, итог всех подходов): displaylink здесь НЕ пишет в QML —
// он только (а) обновляет g_avpnKbLastH из presentationLayer трекера и (б) будит рендер Qt
// (Avpn_pokeQtFrame → QQuickWindow::update). ПРИМЕНЯЕТ высоту pageController В НАЧАЛЕ КАДРА
// Qt (QQuickWindow::afterAnimating → Avpn_currentKeyboardHeight) — значение и кадр рисуются
// синфазно. Прошлый вариант (сет свойства из displaylink в произвольный момент ран-лупа)
// гонялся с кадром Qt — рывки; паттерн «читать в кадре» = как keyboard-controller в RN.
extern "C" void Avpn_pokeQtFrame(void);  // pageController.cpp: QQuickWindow::update()
extern "C" int Avpn_qtFrameHooked(void); // pageController.cpp: окно Qt уже подхвачено?

extern "C" double Avpn_currentKeyboardHeight(void)
{
    return g_avpnKbLink ? g_avpnKbLastH : -1.0; // −1 = трекинг не идёт, кадру нечего применять
}

@interface AvpnKbTickTarget : NSObject
- (void)tick:(CADisplayLink *)link;
@end
@implementation AvpnKbTickTarget
- (void)tick:(CADisplayLink *)link
{
    Avpn_resetKeyboardScroll(); // канал закрыт подменой слоя; это — дешёвая страховка
    if (!g_avpnKbTracker) {
        [link invalidate];
        g_avpnKbLink = nil;
        return;
    }
    CALayer *pres = g_avpnKbTracker.layer.presentationLayer ?: g_avpnKbTracker.layer;
    double h = pres.frame.size.height;
    // клавиатура скрыта → keyboardLayoutGuide прилипает к safe area (высота = home-инсет);
    // это «нет клавиатуры», не 34px клавиатуры
    const UIWindow *win = g_avpnKbTracker.window;
    const double safeB = win ? win.safeAreaInsets.bottom : 0;
    if (h <= safeB + 1.0)
        h = 0;
    if (fabs(h - g_avpnKbLastH) > 0.1) {
        g_avpnKbLastH = h;
        g_avpnKbStableSince = CACurrentMediaTime();
        // AVPN DEV: УБРАТЬ после калибровки — сэмплы реальной траектории клавиатуры
        NSLog(@"AVPNKB %.3f %.2f", CACurrentMediaTime(), h);
    } else if (CACurrentMediaTime() - g_avpnKbStableSince > 0.6) {
        [link invalidate]; // высота устоялась — до следующего клавиатурного события
        g_avpnKbLink = nil;
        return;
    }
    Avpn_pokeQtFrame(); // разбудить рендер Qt — afterAnimating применит высоту в кадре
}
@end

static void avpnStartKbTracking(void)
{
    avpnEnsureTracker();
    if (!g_avpnKbTracker)
        return;
    g_avpnKbStableSince = CACurrentMediaTime();
    if (!g_avpnKbLink) {
        static AvpnKbTickTarget *target = nil;
        static dispatch_once_t once;
        dispatch_once(&once, ^{ target = [AvpnKbTickTarget new]; });
        g_avpnKbLink = [CADisplayLink displayLinkWithTarget:target selector:@selector(tick:)];
        [g_avpnKbLink addToRunLoop:NSRunLoop.mainRunLoop forMode:NSRunLoopCommonModes];
    }
}

// Фолбэк iOS <15 (без keyboardLayoutGuide): скачок сразу к конечной высоте из endFrame.
static void avpnReportKeyboardFrame(NSNotification *note)
{
    NSValue *endVal = note.userInfo[UIKeyboardFrameEndUserInfoKey];
    if (!endVal)
        return;
    const CGRect end = endVal.CGRectValue;
    const CGRect screen = UIScreen.mainScreen.bounds;
    // мусорные кадры (CGRectZero и промежуточные от сторонних клавиатур) — игнор
    if (CGRectGetWidth(end) < CGRectGetWidth(screen) * 0.5)
        return;
    Avpn_onKeyboardFrame(MAX(0.0, CGRectGetMaxY(screen) - CGRectGetMinY(end)));
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
                Avpn_resetKeyboardScroll(); // заодно подменяет слой (avpnNeuterLayer)
                avpnStartKbTracking();
                // без покадрового пути (iOS <15 / окно Qt ещё не подхвачено) —
                // одиночный репорт конечной высоты, чтобы layout не остался старым
                if (!g_avpnKbTracker || !Avpn_qtFrameHooked())
                    avpnReportKeyboardFrame(note);
            }];
        }
    });
}
