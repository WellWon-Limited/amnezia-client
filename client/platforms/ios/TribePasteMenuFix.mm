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

@interface TribePasteMenuFix : NSObject
@end

@implementation TribePasteMenuFix

+ (void)load
{
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
