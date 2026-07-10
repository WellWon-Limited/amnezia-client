// AVPN — Tribe: нативный iOS-просмотр скачанного вложения чата поддержки (QLPreviewController):
// видео открывается со встроенным плеером, фото — с зумом. Причина: Qt.openUrlExternally(file://…)
// на iOS молча ничего не делает (UIApplication openURL не умеет file-URL) — «видео не игралось».
//
// Идиома моста как у TribeMediaPicker.mm: extern "C", презентация non-blocking (никаких nested
// event loop — правило движка). dataSource держим статически: QLPreviewController хранит его weak.
#import <QuickLook/QuickLook.h>
#import <UIKit/UIKit.h>

@interface TribeMediaViewerDataSource : NSObject <QLPreviewControllerDataSource>
@property (nonatomic, strong) NSURL *fileUrl;
@end

@implementation TribeMediaViewerDataSource

- (NSInteger)numberOfPreviewItemsInPreviewController:(QLPreviewController *)controller
{
    return 1;
}

- (id<QLPreviewItem>)previewController:(QLPreviewController *)controller
                    previewItemAtIndex:(NSInteger)index
{
    return self.fileUrl;
}

@end

static TribeMediaViewerDataSource *s_viewerSource = nil;

static UIViewController *tribeViewerTopViewController(void)
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

extern "C" bool TribeMediaViewer_present(const char *utf8Path)
{
    NSString *path = utf8Path != NULL ? [NSString stringWithUTF8String:utf8Path] : nil;
    if (path.length == 0 || ![NSFileManager.defaultManager fileExistsAtPath:path])
        return false;

    UIViewController *host = tribeViewerTopViewController();
    if (!host)
        return false;

    if (s_viewerSource == nil)
        s_viewerSource = [TribeMediaViewerDataSource new];
    s_viewerSource.fileUrl = [NSURL fileURLWithPath:path];

    QLPreviewController *ql = [[QLPreviewController alloc] init];
    ql.dataSource = s_viewerSource;
    [host presentViewController:ql animated:YES completion:nil];
    return true;
}
