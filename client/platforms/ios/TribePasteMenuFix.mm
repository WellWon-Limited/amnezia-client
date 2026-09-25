// TribePasteMenuFix.mm — Tribe VPN (форк Amnezia), iOS
//
// Заслон от системного промпта iOS 16+ «Разрешить вставку / Не разрешать»: содержимое общего
// буфера обмена читается ТОЛЬКО сразу после того, как пользователь сам нажал «Вставить».
//
// Корень (найден 2026-09-25 по исходникам Qt 6.11.1): QQuickTextInput — то есть ЛЮБОЙ
// TextField/TribeField — в canPaste() и q_canPasteChanged() зовёт QMimeData::text() →
// QIOSMimeData::retrieveData → -[UIPasteboard dataForPasteboardType:]. Это чтение содержимого,
// а оно в iOS 16+ без жеста пользователя = промпт. q_canPasteChanged висит на
// QClipboard::dataChanged, а QIOSClipboard шлёт его на UIApplicationDidBecomeActive, если
// буфер сменился. Итог: скопировал что-то в Safari/на Маке → открыл Tribe → промпт от каждого
// живого текстового поля. Апстрим Qt починил в qtdeclarative ef692a52e3 (QTBUG-149610, ветки
// 6.11/6.12; в релизах 6.11.2 и 6.12.0-rc1 фикса ещё нет).
//
// Почему заслон на границе с iOS, а не правка QML/Qt: прежние фиксы били не туда — убирали
// canPaste из ContextMenuType.qml (чтение по dataChanged оставалось), свизлили
// -[QUIView canPerformAction:] (он буфер не читает). Заслону всё равно, какая версия Qt,
// что вернёт очередное слияние апстрима и какой SDK полезет в буфер.
//
// Как: UIPasteboard — кластер классов, реальный объект — _UIConcretePasteboard*, и геттеры
// переопределены именно там (свизл на UIPasteboard.class не перехватывает НИЧЕГО — поэтому
// прежний трассер f11647a8 и «не поймал виновника»). Оборачиваем геттеры СОДЕРЖИМОГО на
// конкретном классе общего буфера и на базовом. Вне окна вставки они возвращают nil/@[] и
// буфер не трогают → нет промпта; Qt видит «пусто» → canPaste=false. Метаданные
// (pasteboardTypes/hasStrings/changeCount) промпта не вызывают — их не трогаем. Именные
// буферы тоже не трогаем.
//
// Окно вставки: -[QIOSTextInputResponder paste:] (системное меню «Вставить», Cmd+V) открывает
// его на kPasteGrantSeconds. Окно, а не флаг на время вызова: Qt доставляет Ctrl+V
// асинхронно (QWindowSystemInterface DefaultDelivery), и буфер читается уже после возврата.
//
// Цена: программная вставка без системного жеста (кнопки «Вставить» апстрим-мастера
// PageSetupWizard*, в UI Tribe недостижимы) ничего не вставит — вместо промпта.
//
// Тест: client/platforms/ios/tests/build_paste_gate.sh (Mac Catalyst, без устройства).
// Диагностика: -DTRIBE_PASTE_TRACE=1 к флагам этого файла в client/cmake/ios.cmake →
// [TRIBE-PB] в unified log: каждое чтение общего буфера, решение заслона и стек вызова.

#import <UIKit/UIKit.h>
#import <objc/runtime.h>

#include <atomic>

namespace {

constexpr NSTimeInterval kPasteGrantSeconds = 2.0;

std::atomic<NSTimeInterval> g_pasteGrantUntil{0};
UIPasteboard *g_generalPasteboard = nil; // синглтон общего буфера, живёт весь процесс

NSTimeInterval uptimeSeconds()
{
    return NSProcessInfo.processInfo.systemUptime;
}

bool contentReadAllowed(id pasteboard, SEL sel)
{
    if (pasteboard != g_generalPasteboard) {
        return true; // именные буферы промпта не вызывают
    }
    const bool allowed = uptimeSeconds() < g_pasteGrantUntil.load();
#if defined(TRIBE_PASTE_TRACE)
    NSArray<NSString *> *syms = [NSThread callStackSymbols];
    NSMutableString *bt = [NSMutableString string];
    const NSUInteger n = MIN((NSUInteger)18, syms.count);
    for (NSUInteger i = 2; i < n; ++i)
        [bt appendFormat:@"\n    %@", syms[i]];
    NSLog(@"[TRIBE-PB] -%@ %@ — стек:%@", NSStringFromSelector(sel),
          allowed ? @"пропущено (окно вставки)" : @"ЗАБЛОКИРОВАНО (без жеста = был бы промпт)", bt);
#else
    (void)sel;
#endif
    return allowed;
}

// Метод, объявленный в САМОМ классе (не унаследованный) — иначе обернём чужую реализацию
// суперкласса или обернём одно и то же дважды.
Method ownMethod(Class cls, SEL sel)
{
    unsigned count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    Method found = nullptr;
    for (unsigned i = 0; i < count; ++i) {
        if (method_getName(methods[i]) == sel) {
            found = methods[i];
            break;
        }
    }
    free(methods);
    return found;
}

// Геттеры без аргументов. nonnull-массивы (items/itemProviders) отдаём пустыми, не nil.
void gateGetter(Class cls, SEL sel, bool emptyArray)
{
    Method m = ownMethod(cls, sel);
    if (!m)
        return;
    using Getter = id (*)(id, SEL);
    Getter orig = reinterpret_cast<Getter>(method_getImplementation(m));
    method_setImplementation(m, imp_implementationWithBlock(^id(id pb) {
        if (contentReadAllowed(pb, sel))
            return orig(pb, sel);
        return emptyArray ? @[] : nil;
    }));
}

// dataForPasteboardType:, valueForPasteboardType:
void gate1Arg(Class cls, SEL sel)
{
    Method m = ownMethod(cls, sel);
    if (!m)
        return;
    using OneArg = id (*)(id, SEL, id);
    OneArg orig = reinterpret_cast<OneArg>(method_getImplementation(m));
    method_setImplementation(m, imp_implementationWithBlock(^id(id pb, id a1) {
        return contentReadAllowed(pb, sel) ? orig(pb, sel, a1) : nil;
    }));
}

// dataForPasteboardType:inItemSet:, valuesForPasteboardType:inItemSet:
void gate2Arg(Class cls, SEL sel)
{
    Method m = ownMethod(cls, sel);
    if (!m)
        return;
    using TwoArg = id (*)(id, SEL, id, id);
    TwoArg orig = reinterpret_cast<TwoArg>(method_getImplementation(m));
    method_setImplementation(m, imp_implementationWithBlock(^id(id pb, id a1, id a2) {
        return contentReadAllowed(pb, sel) ? orig(pb, sel, a1, a2) : nil;
    }));
}

void gatePasteboardClass(Class cls)
{
    gateGetter(cls, @selector(string), false);
    gateGetter(cls, @selector(strings), false);
    gateGetter(cls, @selector(URL), false);
    gateGetter(cls, @selector(URLs), false);
    gateGetter(cls, @selector(image), false);
    gateGetter(cls, @selector(images), false);
    gateGetter(cls, @selector(color), false);
    gateGetter(cls, @selector(colors), false);
    gateGetter(cls, @selector(items), true);
    gateGetter(cls, @selector(itemProviders), true);
    gate1Arg(cls, @selector(dataForPasteboardType:));
    gate1Arg(cls, @selector(valueForPasteboardType:));
    gate2Arg(cls, @selector(dataForPasteboardType:inItemSet:));
    gate2Arg(cls, @selector(valuesForPasteboardType:inItemSet:));
}

// Системное «Вставить» → -[… paste:] открывает окно, затем отрабатывает код Qt.
bool grantOnPasteAction(Class cls)
{
    Method m = cls ? ownMethod(cls, @selector(paste:)) : nullptr;
    if (!m)
        return false;
    using Action = void (*)(id, SEL, id);
    Action orig = reinterpret_cast<Action>(method_getImplementation(m));
    method_setImplementation(m, imp_implementationWithBlock(^(id responder, id sender) {
        g_pasteGrantUntil.store(uptimeSeconds() + kPasteGrantSeconds);
        orig(responder, @selector(paste:), sender);
    }));
    return true;
}

} // namespace

@interface TribePasteMenuFix : NSObject
@end

@implementation TribePasteMenuFix

+ (void)load
{
    g_generalPasteboard = [UIPasteboard.generalPasteboard retain];

    Class concrete = object_getClass(g_generalPasteboard);
    gatePasteboardClass(concrete);
    if (concrete != UIPasteboard.class) {
        gatePasteboardClass(UIPasteboard.class);
    }

    // paste: живёт в QIOSTextInputResponder (Qt 6.11); базовый QIOSTextResponder — на случай,
    // если Qt перенесёт его туда. Не нашли ни там, ни там → системная вставка перестанет
    // вставлять (промпта всё равно не будет) — видно в логе.
    const bool input = grantOnPasteAction(objc_getClass("QIOSTextInputResponder"));
    const bool base = grantOnPasteAction(objc_getClass("QIOSTextResponder"));
    if (!input && !base) {
        NSLog(@"[TRIBE-PB] -paste: у QIOSTextInputResponder/QIOSTextResponder не найден — "
              @"системное «Вставить» не откроет окно чтения буфера");
    }
}

@end
