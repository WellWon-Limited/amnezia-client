// TribePasteMenuFix.mm — Tribe VPN (форк Amnezia), iOS
//
// Убирает системный промпт iOS 16+ «Разрешить вставку / Не разрешать», который
// выскакивал при КАЖДОМ фокусе на текстовом поле, если в буфере что-то было.
//
// Корень (нативный, НЕ QML): Qt в -[QUIView canPerformAction:withSender:] для
// @selector(paste:) читает [UIPasteboard generalPasteboard].string, чтобы решить,
// показывать ли пункт «Вставить». В iOS 16+ любое ЧТЕНИЕ содержимого буфера
// рождает системный secure-paste промпт. Удаление пункта «Вставить» из нашего
// QML-меню (ContextMenuType.qml) этот нативный зонд не глушит — поэтому промпт и
// «возвращался» после апгрейда Qt / рефакторинга QML.
//
// Фикс: свизлим canPerformAction:withSender: у приватного Qt-класса QUIView и
// возвращаем NO для paste-семейства ДО того, как отработает код Qt → буфер не
// читается → нет промпта, пункт «Вставить» исчезает из нативного callout. Для всех
// прочих действий (copy/cut/select/selectAll) зовём оригинал Qt — копирование и
// выделение целы. Explicit textField.paste() из setup-wizard идёт МИМО
// canPerformAction (прямое чтение QClipboard) и продолжает работать.
//
// Тот же приём +load-свизла Qt-приватного класса уже применяется в
// AmneziaSceneDelegateHooks.mm — фикс консистентен с существующим кодом.
//
// ДИАГНОСТИКА (2026-07-04): попап «Разрешить вставку» ЖИВ после свизла QUIView — при этом
// анализ исходников Qt 6.11.1 (qiostextresponder/qiosclipboard/quiview) показал: canPerformAction
// буфер НЕ читает (решает по выделению), единственное чтение контента = QIOSMimeData::retrieveData
// (потребитель QClipboard). Явных чтений в коде приложения нет. Чтобы поймать реального виновника
// на устройстве, ниже — ТРАССЕР: свизлим все промптящие геттеры UIPasteboard и логируем стек вызова
// ([TRIBE-PB] в unified log → idevicesyslog/Console). Промпт триггерят ТОЛЬКО эти чтения, они редки —
// лог не шумит; на решение «показывать ли попап» трассер не влияет (оригинал вызывается всегда).

#import <UIKit/UIKit.h>
#import <objc/runtime.h>

typedef BOOL (*CanPerformActionIMP)(id, SEL, SEL, id);
static CanPerformActionIMP g_origCanPerformAction = nullptr;

static BOOL tribe_canPerformAction(id self, SEL _cmd, SEL action, id sender)
{
    // Гасим paste-семейство: не даём iOS/Qt прочитать UIPasteboard ради решения
    // «показывать ли Вставить» → нет secure-paste промпта, нет пункта «Вставить».
    if (action == @selector(paste:)
        || action == @selector(pasteAndMatchStyle:)
        || action == sel_registerName("_promptForReplace:")
        || action == sel_registerName("pasteAndGo:")
        || action == sel_registerName("pasteAndSearch:")) {
        return NO;
    }
    if (g_origCanPerformAction) {
        return g_origCanPerformAction(self, _cmd, action, sender);
    }
    return NO;
}

// ── Трассер промптящих чтений UIPasteboard ──────────────────────────────────────────────────
// Логирует селектор + стек (кто прочитал буфер). Кадры 0-1 (сам трассер) пропускаем.
static void tribeLogPasteboardRead(SEL sel)
{
    NSArray<NSString *> *syms = [NSThread callStackSymbols];
    NSMutableString *bt = [NSMutableString string];
    const NSUInteger n = MIN((NSUInteger)18, syms.count);
    for (NSUInteger i = 2; i < n; ++i)
        [bt appendFormat:@"\n    %@", syms[i]];
    NSLog(@"[TRIBE-PB] чтение UIPasteboard -%@ (это триггер secure-paste промпта) — стек:%@",
          NSStringFromSelector(sel), bt);
}

// Геттеры-свойства без аргументов (string/strings/URL/URLs/image/images/color/colors/items/itemProviders).
static void tribeSwizzlePbGetter(SEL sel)
{
    Method m = class_getInstanceMethod(UIPasteboard.class, sel);
    if (!m)
        return;
    typedef id (*GetterIMP)(id, SEL);
    GetterIMP orig = reinterpret_cast<GetterIMP>(method_getImplementation(m));
    IMP repl = imp_implementationWithBlock(^id(id pb) {
        tribeLogPasteboardRead(sel);
        return orig(pb, sel);
    });
    method_setImplementation(m, repl);
}

// Методы с 1 объектным аргументом (dataForPasteboardType:, valueForPasteboardType:).
static void tribeSwizzlePb1Arg(SEL sel)
{
    Method m = class_getInstanceMethod(UIPasteboard.class, sel);
    if (!m)
        return;
    typedef id (*OneArgIMP)(id, SEL, id);
    OneArgIMP orig = reinterpret_cast<OneArgIMP>(method_getImplementation(m));
    IMP repl = imp_implementationWithBlock(^id(id pb, id a1) {
        tribeLogPasteboardRead(sel);
        return orig(pb, sel, a1);
    });
    method_setImplementation(m, repl);
}

// Методы с 2 объектными аргументами (dataForPasteboardType:inItemSet:, valuesForPasteboardType:inItemSet:).
static void tribeSwizzlePb2Arg(SEL sel)
{
    Method m = class_getInstanceMethod(UIPasteboard.class, sel);
    if (!m)
        return;
    typedef id (*TwoArgIMP)(id, SEL, id, id);
    TwoArgIMP orig = reinterpret_cast<TwoArgIMP>(method_getImplementation(m));
    IMP repl = imp_implementationWithBlock(^id(id pb, id a1, id a2) {
        tribeLogPasteboardRead(sel);
        return orig(pb, sel, a1, a2);
    });
    method_setImplementation(m, repl);
}

@interface TribePasteMenuFix : NSObject
@end

@implementation TribePasteMenuFix

+ (void)load
{
    // Трассер чтений буфера (диагностика «попап жив»). Ставим ДО свизла QUIView — не зависят друг от друга.
    tribeSwizzlePbGetter(@selector(string));
    tribeSwizzlePbGetter(@selector(strings));
    tribeSwizzlePbGetter(@selector(URL));
    tribeSwizzlePbGetter(@selector(URLs));
    tribeSwizzlePbGetter(@selector(image));
    tribeSwizzlePbGetter(@selector(images));
    tribeSwizzlePbGetter(@selector(color));
    tribeSwizzlePbGetter(@selector(colors));
    tribeSwizzlePbGetter(@selector(items));
    tribeSwizzlePbGetter(@selector(itemProviders));
    tribeSwizzlePb1Arg(@selector(dataForPasteboardType:));
    tribeSwizzlePb1Arg(@selector(valueForPasteboardType:));
    tribeSwizzlePb2Arg(@selector(dataForPasteboardType:inItemSet:));
    tribeSwizzlePb2Arg(@selector(valuesForPasteboardType:inItemSet:));

    Class cls = objc_getClass("QUIView");
    if (!cls) {
        return;
    }

    SEL sel = @selector(canPerformAction:withSender:);
    Method existing = class_getInstanceMethod(cls, sel);

    // Тип-энкодинг метода: BOOL(B), self(@), _cmd(:), action(SEL=:), sender(id=@).
    const char *types = existing ? method_getTypeEncoding(existing) : "B@::@";

    // Сохраняем текущую реализацию (собственную QUIView либо унаследованную от
    // UIResponder) — её зовём для проброса всех НЕ-paste действий.
    g_origCanPerformAction = existing
        ? reinterpret_cast<CanPerformActionIMP>(method_getImplementation(existing))
        : nullptr;

    // class_addMethod вернёт YES только если у QUIView НЕТ собственной реализации
    // (тогда наш override добавляется ИМЕННО на QUIView, суперкласс не трогаем).
    // Вернёт NO → у QUIView своя реализация; свизлим её на месте, сохранив оригинал.
    if (!class_addMethod(cls, sel, reinterpret_cast<IMP>(tribe_canPerformAction), types)) {
        Method own = class_getInstanceMethod(cls, sel);
        g_origCanPerformAction = reinterpret_cast<CanPerformActionIMP>(method_getImplementation(own));
        method_setImplementation(own, reinterpret_cast<IMP>(tribe_canPerformAction));
    }
}

@end
