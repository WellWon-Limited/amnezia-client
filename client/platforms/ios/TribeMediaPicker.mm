// AVPN — Tribe: нативный iOS-пикер фото/видео для чата поддержки (PHPickerViewController).
//
// Почему не QML FileDialog: на iOS он открывает UIDocumentPicker (файлы), а пользователь
// ждёт свою фотоплёнку. PHPicker работает БЕЗ разрешения на фотобиблиотеку (out-of-process),
// ничего не добавляем в Info.plist. iOS 14+ (деплой-таргет форка выше).
//
// Идиома моста как у AvpnShare.mm: extern "C" презентует контроллер non-blocking (никаких
// nested event loop — правило движка), выбранный файл копируется во временную папку и
// отдаётся обратно в C++ через Tribe_supportPickedMedia(path) (реализация — в
// TribeSupportChat.cpp, маршалит в Qt-поток).
#import <PhotosUI/PhotosUI.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>

extern "C" void Tribe_supportPickedMedia(const char *utf8Path); // TribeSupportChat.cpp

static UIViewController *tribeTopViewController()
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

// Делегат держим статически: PHPicker хранит delegate weak — локальный объект умер бы
// до колбэка и пикер молча ничего не возвращал.
@interface TribeMediaPickerDelegate : NSObject <PHPickerViewControllerDelegate>
@end

static TribeMediaPickerDelegate *s_delegate = nil;

@implementation TribeMediaPickerDelegate

- (void)picker:(PHPickerViewController *)picker didFinishPicking:(NSArray<PHPickerResult *> *)results
{
    [picker dismissViewControllerAnimated:YES completion:nil];
    if (results.count == 0)
        return; // отмена — тишина, QML ничего не ждёт

    NSItemProvider *provider = results.firstObject.itemProvider;
    NSString *typeId = nil;
    if ([provider hasItemConformingToTypeIdentifier:UTTypeMovie.identifier])
        typeId = UTTypeMovie.identifier;
    else if ([provider hasItemConformingToTypeIdentifier:UTTypeImage.identifier])
        typeId = UTTypeImage.identifier;
    if (typeId == nil)
        return;

    [provider loadFileRepresentationForTypeIdentifier:typeId
                                    completionHandler:^(NSURL *url, NSError *error) {
        if (error != nil || url == nil)
            return;
        // URL живёт только внутри completion — копируем во временную папку приложения.
        NSString *dir = [NSTemporaryDirectory() stringByAppendingPathComponent:@"tribe-picker"];
        [NSFileManager.defaultManager createDirectoryAtPath:dir
                                withIntermediateDirectories:YES
                                                 attributes:nil
                                                      error:nil];
        NSString *name = url.lastPathComponent.length > 0 ? url.lastPathComponent : @"media";
        NSString *dst = [dir stringByAppendingPathComponent:name];
        [NSFileManager.defaultManager removeItemAtPath:dst error:nil]; // перезапись повторного выбора
        NSError *copyErr = nil;
        if (![NSFileManager.defaultManager copyItemAtURL:url
                                                   toURL:[NSURL fileURLWithPath:dst]
                                                   error:&copyErr])
            return;
        // dst ретейнится блоком — UTF8String берём ВНУТРИ (сырой указатель снаружи
        // пережил бы autorelease-пул completion-хендлера).
        dispatch_async(dispatch_get_main_queue(), ^{
            Tribe_supportPickedMedia(dst.UTF8String);
        });
    }];
}

@end

extern "C" bool TribeMediaPicker_present()
{
    UIViewController *host = tribeTopViewController();
    if (!host)
        return false;

    PHPickerConfiguration *cfg = [[PHPickerConfiguration alloc] init]; // без PHPhotoLibrary → без пермишена
    cfg.selectionLimit = 1;
    cfg.filter = [PHPickerFilter anyFilterMatchingSubfilters:@[
        PHPickerFilter.imagesFilter, PHPickerFilter.videosFilter
    ]];

    if (s_delegate == nil)
        s_delegate = [TribeMediaPickerDelegate new];

    PHPickerViewController *picker = [[PHPickerViewController alloc] initWithConfiguration:cfg];
    picker.delegate = s_delegate;
    [host presentViewController:picker animated:YES completion:nil];
    return true;
}
