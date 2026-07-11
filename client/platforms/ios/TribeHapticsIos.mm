// AVPN (haptics): iOS-реализация TribeHaptics — системные UIFeedbackGenerator.
// Генераторы статические (переиспользование + prepare() держит Taptic Engine тёплым);
// вся работа — на main queue (требование UIKit). Система сама уважает настройку
// «Системная тактильная отдача» — своих гейтов не нужно.
#import <UIKit/UIKit.h>

// Маппинг kind — enum HapticKind из TribeHaptics.cpp:
// 0 selection, 1 light, 2 medium, 3 success, 4 warning, 5 error.
extern "C" void TribeHaptics_play(int kind)
{
    dispatch_async(dispatch_get_main_queue(), ^{
        static UISelectionFeedbackGenerator *sel;
        static UIImpactFeedbackGenerator *light;
        static UIImpactFeedbackGenerator *medium;
        static UINotificationFeedbackGenerator *notify;
        static dispatch_once_t once;
        dispatch_once(&once, ^{
            sel = [[UISelectionFeedbackGenerator alloc] init];
            light = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleLight];
            medium = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleMedium];
            notify = [[UINotificationFeedbackGenerator alloc] init];
        });

        switch (kind) {
        case 0:
            [sel selectionChanged];
            [sel prepare];
            break;
        case 1:
            [light impactOccurred];
            [light prepare];
            break;
        case 2:
            [medium impactOccurred];
            [medium prepare];
            break;
        case 3:
            [notify notificationOccurred:UINotificationFeedbackTypeSuccess];
            break;
        case 4:
            [notify notificationOccurred:UINotificationFeedbackTypeWarning];
            break;
        case 5:
            [notify notificationOccurred:UINotificationFeedbackTypeError];
            break;
        default:
            break;
        }
    });
}
