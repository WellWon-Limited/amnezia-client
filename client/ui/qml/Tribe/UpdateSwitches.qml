pragma Singleton

import QtQuick

// AVPN (emulator round 26.11.2026, D4): the update switches as QML reads them, in one place.
// «Обновлять автоматически» is the silent install of a new version, so it exists only where the app installs itself
// (desktop macOS, avpn::SelfUpdate). canSelfUpdate is true on Android too since the site APK updates itself in the app
// (241138564), but there Android always asks the person in its own dialog: no silent install, no switch
// (BUILD-ANDROID.md 7b), and the engine never reads the setting (maybeAutoUpdate needs SelfUpdate). Settings showed the
// switch on Android because only the update sheet carried the Android term; both now read autoUpdateShown.
QtObject {
    readonly property bool hasEngine: typeof TribeEngine !== "undefined"
    readonly property bool autoUpdateShown: hasEngine && TribeEngine.canSelfUpdate === true
                                            && Qt.platform.os !== "android"
}
