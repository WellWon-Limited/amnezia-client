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
    // Закрыть канал сдвига (идемпотентно) + вычистить, что могло примениться ДО подмены
    // (Qt-observer в том же уведомлении бежит раньше нашего — кадр отрисоваться не успевает).
    avpnNeuterLayer(root.layer);
    [root.layer removeAnimationForKey:@"AnimateSubLayerTransform"];
    if (!CATransform3DIsIdentity(root.layer.sublayerTransform))
        root.layer.sublayerTransform = CATransform3DIdentity;
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
    const CGRect screen = UIScreen.mainScreen.bounds;
    // мусорные кадры (CGRectZero и промежуточные от сторонних клавиатур) — игнор:
    // высота «во весь экран» роняла margin в потолок, композер прилетал сверху
    if (CGRectGetWidth(end) < CGRectGetWidth(screen) * 0.5)
        return;
    // скрытие: endFrame целиком за нижней кромкой экрана → высота 0
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
                avpnReportKeyboardFrame(note);
                Avpn_resetKeyboardScroll(); // заодно подменяет слой (avpnNeuterLayer)
            }];
        }
    });
}
