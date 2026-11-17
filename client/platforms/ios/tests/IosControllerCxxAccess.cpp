// AVPN (crash 5.1.110, S4): compiled as plain C++, as AvpnEngineQml.cpp is in the app, so the harness
// sees IosController the way a .cpp translation unit sees it. Before the fix the class was 16 bytes
// smaller here than in ios_controller.mm (Objective-C members under #ifdef __OBJC__), and the inline
// setUplinkProbe below wrote into other members and destroyed garbage as the old std::function.
#include "ios_controller.h"

#include <cstddef>

std::size_t avpnHarnessIosControllerSizeFromCxx()
{
    return sizeof(IosController);
}

void avpnHarnessSetUplinkProbeFromCxx(bool up)
{
    IosController::Instance()->setUplinkProbe([up] { return up; });
}
