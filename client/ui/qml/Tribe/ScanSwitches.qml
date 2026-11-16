pragma Singleton

import QtQuick

// AVPN: the Scanner's client switches as QML reads them (plan scanner-client-plan.md §4, §6 G6), in one place.
// The engine owns the values (TribeEngine.scannerEnabled / doctorLegacy / scannerReturnHome, NOTIFY
// scannerSwitchesChanged); a binary whose engine lacks them reads the coordinator's copies (TribeScanner.enabled /
// doctorLegacy / returnHome, scanner-api-note.md (b)). Compiled fallbacks of a binary with neither:
//   scanner             absent -> false: no Scanner entry point anywhere, today's UI unchanged (S9);
//   doctor_legacy       absent -> false;
//   scanner_return_home absent -> false (the WHEN is the engine's scannerReturnHomeRequested(), not this flag).
// scanner_connect_on_open is the coordinator's (ScanOpen.connectOnOpen): the screen only draws what the view says
// (NoScan vpn_off -> «Подключиться и проверить»).
QtObject {
    readonly property bool hasEngine: typeof TribeEngine !== "undefined" && TribeEngine.scannerEnabled !== undefined
    readonly property bool hasScanner: typeof TribeScanner !== "undefined"
    readonly property bool scanner: hasEngine ? TribeEngine.scannerEnabled === true
                                              : (hasScanner && TribeScanner.enabled === true)
    readonly property bool doctorLegacy: hasEngine ? TribeEngine.doctorLegacy === true
                                                   : (hasScanner && TribeScanner.doctorLegacy === true)
    readonly property bool returnHome: hasEngine ? TribeEngine.scannerReturnHome === true
                                                 : (hasScanner && TribeScanner.returnHome === true)
    // The home button row and the chat's «run_diag» open the Scanner instead of the Doctor sheet.
    readonly property bool replacesDoctor: scanner && !doctorLegacy
}
