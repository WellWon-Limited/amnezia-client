// Юнит заслона чтений UIPasteboard (TribePasteMenuFix.mm) — iOS-промпт «Разрешить вставку».
// Автономно, без Qt и без реального буфера: +load этого файла (он ПЕРВЫЙ в строке линковки)
// подменяет геттеры заглушками ДО того, как их обернёт заслон, поэтому тест не читает и не
// затирает настоящий буфер Мака. UIPasteboard — кластер классов: геттеры переопределены на
// конкретном классе (_UIConcretePasteboard*), заглушки ставим туда же, куда бьёт заслон.
// Запуск: build_paste_gate.sh (Mac Catalyst).
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

#include <cstdio>
#include <unistd.h>

static int g_fail = 0;
#define CHECK(cond, name)                                                                          \
    do {                                                                                           \
        if (cond) {                                                                                \
            std::printf("OK   %s\n", name);                                                        \
        } else {                                                                                   \
            std::printf("FAIL %s\n", name);                                                        \
            ++g_fail;                                                                              \
        }                                                                                          \
    } while (0)

// Счётчик «реальных» чтений содержимого — на устройстве каждое такое чтение = промпт.
static int g_contentReads = 0;
static NSString *const kSentinel = @"tribe-sentinel";

static Class concretePasteboardClass()
{
    return object_getClass(UIPasteboard.generalPasteboard);
}

static void stubGetter(SEL sel, id value)
{
    Method m = class_getInstanceMethod(concretePasteboardClass(), sel);
    if (!m)
        return;
    [value retain];
    method_setImplementation(m, imp_implementationWithBlock(^id(id) {
        ++g_contentReads;
        return value;
    }));
}

static void stub1Arg(SEL sel, id value)
{
    Method m = class_getInstanceMethod(concretePasteboardClass(), sel);
    if (!m)
        return;
    [value retain];
    method_setImplementation(m, imp_implementationWithBlock(^id(id, id) {
        ++g_contentReads;
        return value;
    }));
}

static void stub2Arg(SEL sel, id value)
{
    Method m = class_getInstanceMethod(concretePasteboardClass(), sel);
    if (!m)
        return;
    [value retain];
    method_setImplementation(m, imp_implementationWithBlock(^id(id, id, id) {
        ++g_contentReads;
        return value;
    }));
}

@interface TribePasteGateTestStubs : NSObject
@end

@implementation TribePasteGateTestStubs
+ (void)load
{
    NSData *data = [kSentinel dataUsingEncoding:NSUTF8StringEncoding];
    stubGetter(@selector(string), kSentinel);
    stubGetter(@selector(strings), @[ kSentinel ]);
    stubGetter(@selector(URL), [NSURL URLWithString:@"https://example.com"]);
    stubGetter(@selector(URLs), @[ [NSURL URLWithString:@"https://example.com"] ]);
    stubGetter(@selector(image), [[[UIImage alloc] init] autorelease]);
    stubGetter(@selector(images), @[ [[[UIImage alloc] init] autorelease] ]);
    stubGetter(@selector(color), UIColor.redColor);
    stubGetter(@selector(colors), @[ UIColor.redColor ]);
    stubGetter(@selector(items), @[ @{ @"public.utf8-plain-text" : data } ]);
    stubGetter(@selector(itemProviders), @[ [[[NSItemProvider alloc] initWithObject:kSentinel] autorelease] ]);
    stub1Arg(@selector(dataForPasteboardType:), data);
    stub1Arg(@selector(valueForPasteboardType:), kSentinel);
    stub2Arg(@selector(dataForPasteboardType:inItemSet:), @[ data ]);
    stub2Arg(@selector(valuesForPasteboardType:inItemSet:), @[ kSentinel ]);

    // Метаданные: промпта не вызывают, заслон их пропускать обязан.
    Method types = class_getInstanceMethod(concretePasteboardClass(), @selector(pasteboardTypes));
    method_setImplementation(types, imp_implementationWithBlock(^id(id) {
        return @[ @"public.utf8-plain-text" ];
    }));
    Method has = class_getInstanceMethod(concretePasteboardClass(), @selector(hasStrings));
    method_setImplementation(has, imp_implementationWithBlock(^BOOL(id) {
        return YES;
    }));
}
@end

// Стенд Qt-класса: системное «Вставить» зовёт -[QIOSTextInputResponder paste:], а Qt читает
// буфер уже ПОСЛЕ возврата (асинхронная доставка Ctrl+V). Имитируем оба чтения.
@interface QIOSTextInputResponder : UIResponder
@property(nonatomic, retain) NSString *readInsidePaste;
@end

@implementation QIOSTextInputResponder
- (void)paste:(id)sender
{
    self.readInsidePaste = UIPasteboard.generalPasteboard.string;
}
@end

int main()
{
    @autoreleasepool {
        UIPasteboard *pb = UIPasteboard.generalPasteboard;

        // 1) Без действия пользователя содержимое не читается — ни один геттер не доходит до буфера.
        g_contentReads = 0;
        CHECK(pb.string == nil, "closed: string -> nil");
        CHECK(pb.strings.count == 0, "closed: strings -> empty");
        CHECK(pb.URL == nil, "closed: URL -> nil");
        CHECK(pb.URLs.count == 0, "closed: URLs -> empty");
        CHECK(pb.image == nil, "closed: image -> nil");
        CHECK(pb.images.count == 0, "closed: images -> empty");
        CHECK(pb.color == nil, "closed: color -> nil");
        CHECK(pb.colors.count == 0, "closed: colors -> empty");
        CHECK(pb.items != nil && pb.items.count == 0, "closed: items -> @[] (nonnull)");
        CHECK(pb.itemProviders != nil && pb.itemProviders.count == 0, "closed: itemProviders -> @[] (nonnull)");
        CHECK([pb dataForPasteboardType:@"public.utf8-plain-text"] == nil,
              "closed: dataForPasteboardType (Qt QIOSMimeData::retrieveData) -> nil");
        CHECK([pb valueForPasteboardType:@"public.utf8-plain-text"] == nil, "closed: valueForPasteboardType -> nil");
        NSIndexSet *first = [NSIndexSet indexSetWithIndex:0];
        CHECK([pb dataForPasteboardType:@"public.utf8-plain-text" inItemSet:first] == nil,
              "closed: dataForPasteboardType:inItemSet -> nil");
        CHECK([pb valuesForPasteboardType:@"public.utf8-plain-text" inItemSet:first] == nil,
              "closed: valuesForPasteboardType:inItemSet -> nil");
        CHECK(g_contentReads == 0, "closed: zero real content reads (no prompt)");

        // 2) Метаданные проходят как есть (Qt по ним решает hasText без промпта).
        CHECK(pb.pasteboardTypes.count == 1, "closed: pasteboardTypes passes through");
        CHECK(pb.hasStrings, "closed: hasStrings passes through");

        // 3) Системное «Вставить» открывает окно: чтение внутри paste: и сразу после него (Qt async).
        QIOSTextInputResponder *responder = [[QIOSTextInputResponder alloc] init];
        [responder paste:nil];
        CHECK([responder.readInsidePaste isEqualToString:kSentinel], "paste: read inside action -> content");
        g_contentReads = 0;
        CHECK([pb.string isEqualToString:kSentinel], "paste: async read right after -> content");
        CHECK([pb dataForPasteboardType:@"public.utf8-plain-text"] != nil, "paste: dataForPasteboardType -> content");
        CHECK(g_contentReads == 2, "paste: reads reach the pasteboard");
        [responder release];

        // 4) Окно закрывается само — следующий «фоновый» пробег Qt снова не читает буфер.
        usleep(2'200'000);
        g_contentReads = 0;
        CHECK(pb.string == nil, "window expired: string -> nil");
        CHECK(g_contentReads == 0, "window expired: zero real content reads");

        // 5) Именные (не общий) буферы промпта не вызывают — их заслон не трогает.
        UIPasteboard *named = [UIPasteboard pasteboardWithUniqueName];
        CHECK([named.string isEqualToString:kSentinel], "named pasteboard: passes through");
    }

    std::printf(g_fail ? "\n%d FAILED\n" : "\nALL OK\n", g_fail);
    return g_fail ? 1 : 0;
}
