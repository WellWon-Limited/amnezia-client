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
#import <AVFoundation/AVFoundation.h>
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

// AVPN (handoff Занавеса §C.2): мгновенный локальный постер видео — кадр ~0.5с через
// AVAssetImageGenerator, JPEG рядом с файлом (<видео>.poster.jpg). C++ (sendAttachmentFile)
// подхватывает его по конвенции имени в localUrl эха; серверный постер (точнее по кадру)
// потом тихо заменит. Синхронно, но мы уже на background-очереди completion-хендлера.
static void tribeGenerateVideoPoster(NSString *videoPath)
{
    AVURLAsset *asset = [AVURLAsset URLAssetWithURL:[NSURL fileURLWithPath:videoPath] options:nil];
    AVAssetImageGenerator *gen = [[AVAssetImageGenerator alloc] initWithAsset:asset];
    gen.appliesPreferredTrackTransform = YES; // учесть rotation-метаданные
    gen.maximumSize = CGSizeMake(960, 960);
    NSError *err = nil;
    CGImageRef cg = [gen copyCGImageAtTime:CMTimeMakeWithSeconds(0.5, 600)
                                actualTime:nil
                                     error:&err];
    if (cg == NULL)
        return; // нет постера — карточка с play и плейсхолдером, не смертельно
    UIImage *ui = [UIImage imageWithCGImage:cg];
    CGImageRelease(cg);
    NSData *jpg = UIImageJPEGRepresentation(ui, 0.8);
    if (jpg != nil)
        [jpg writeToFile:[videoPath stringByAppendingString:@".poster.jpg"] atomically:YES];
}

// ПРИВАТНОСТЬ (аудит 2026-07-09): видео с камеры несёт точный GPS в QuickTime-атоме
// (com.apple.quicktime.location.ISO6709) — PHPicker его НЕ вырезает. Чистим штатным
// AVMetadataItemFilter forSharing (Apple делает его именно для этого) через passthrough-
// экспорт: без перекодирования, быстро, качество не трогаем. Мы на background-очереди
// completion-хендлера — семафор допустим (как и синхронный постер рядом).
// Не смогли очистить (битый файл/таймаут) — отдаём оригинал: деградация к старому
// поведению, чат важнее (webm AVFoundation не читает, но у него и нет GPS-стандарта).
static NSString *tribeStripVideoLocation(NSString *path)
{
    AVURLAsset *asset = [AVURLAsset URLAssetWithURL:[NSURL fileURLWithPath:path] options:nil];
    AVAssetExportSession *ex =
        [[AVAssetExportSession alloc] initWithAsset:asset
                                         presetName:AVAssetExportPresetPassthrough];
    if (ex == nil)
        return path;
    const BOOL isMp4 = [path.pathExtension.lowercaseString isEqualToString:@"mp4"];
    NSString *out = [path stringByAppendingString:isMp4 ? @".clean.mp4" : @".clean.mov"];
    [NSFileManager.defaultManager removeItemAtPath:out error:nil];
    ex.outputURL = [NSURL fileURLWithPath:out];
    ex.outputFileType = isMp4 ? AVFileTypeMPEG4 : AVFileTypeQuickTimeMovie;
    ex.metadataItemFilter = [AVMetadataItemFilter metadataItemFilterForSharing];
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    [ex exportAsynchronouslyWithCompletionHandler:^{ dispatch_semaphore_signal(sem); }];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(60 * NSEC_PER_SEC)));
    if (ex.status == AVAssetExportSessionStatusCompleted) {
        // Имя сохраняем (конвенция постера <видео>.poster.jpg и C++ пути) — подменяем файл.
        [NSFileManager.defaultManager removeItemAtPath:path error:nil];
        if ([NSFileManager.defaultManager moveItemAtPath:out toPath:path error:nil])
            return path;
        return out; // переезд не удался — отдаём очищенный файл под clean-именем
    }
    [NSFileManager.defaultManager removeItemAtPath:out error:nil];
    return path;
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
        // Видео: сначала срезать GPS/идентифицирующие метаданные, потом постер-кадр
        // (мы на background-очереди — можно синхронно).
        NSString *finalPath = dst;
        if ([typeId isEqualToString:UTTypeMovie.identifier]) {
            finalPath = tribeStripVideoLocation(dst);
            tribeGenerateVideoPoster(finalPath);
        }
        // finalPath ретейнится блоком — UTF8String берём ВНУТРИ (сырой указатель снаружи
        // пережил бы autorelease-пул completion-хендлера).
        dispatch_async(dispatch_get_main_queue(), ^{
            Tribe_supportPickedMedia(finalPath.UTF8String);
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
