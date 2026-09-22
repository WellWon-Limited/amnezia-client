#!/bin/bash
# AVPN (фикс-волна 2026-09-22, зона CL-C): сборка и прогон поведенческого харнесса IosController
# (IosControllerHarnessTests.mm) и AvpnIntentController (AvpnIntentControllerTests.mm) на macOS.
#
#   build_ios_controller_harness.sh               — против рабочего дерева
#   BASE=<git-rev> build_ios_controller_harness.sh — против старого кода натива из <git-rev>
#                                                   (ожидаемо: тесты фиксов ПАДАЮТ)
#   ONLY=<test> ...                                — один тест
# Выход: 0 — все тесты прошли. OUT — каталог сборки (по умолчанию mktemp).
set -euo pipefail
QT="${QT_ROOT:-$HOME/Qt/6.11.1/macos}"
[ -d "$QT" ] || QT="$HOME/Qt/6.10.2/macos"
HERE="$(cd "$(dirname "$0")" && pwd)"
CLIENT="$(cd "$HERE/../../.." && pwd)"
OUT="${OUT:-$(mktemp -d "${TMPDIR:-/tmp}/tribe-ios-harness.XXXXXX")}"
mkdir -p "$OUT/shim/core/utils" "$OUT/src/platforms/ios"

# Шимы: сгенерированный Swift-хедер (StoreKit2Helper) и конфиг swift-моста.
printf '#pragma once\n' > "$OUT/shim/core/utils/swiftBridgeConfig.h"
cat > "$OUT/shim/HarnessSwift.h" <<'EOF'
#pragma once
#import <Foundation/Foundation.h>
@interface StoreKit2Helper : NSObject
+ (instancetype)shared;
- (void)purchaseProductWithProductIdentifier:(NSString *)p completion:(void (^)(BOOL, NSString *, NSString *, NSString *, NSString *, NSError *))c;
- (void)finishTransactionWithTransactionId:(NSString *)t completion:(void (^)(BOOL))c;
- (void)startTransactionUpdatesListenerWithHandler:(void (^)(NSDictionary *))h;
- (void)fetchCurrentEntitlementsWithCompletion:(void (^)(BOOL, NSArray *, NSError *))c;
- (void)fetchLocalEntitlementsWithCompletion:(void (^)(BOOL, NSArray *, NSError *))c;
- (void)fetchProductsWithIdentifiers:(NSSet *)ids completion:(void (^)(NSArray *, NSArray *, NSError *))c;
@end
EOF

# Vpn::staticMetaObject (Q_NAMESPACE из vpnProtocol.h) без класса VpnProtocol и его зависимостей.
cat > "$OUT/shim/HarnessVpnNamespace.h" <<'EOF'
#pragma once
#include <QObject>
namespace Vpn {
Q_NAMESPACE
enum ConnectionState { Unknown, Disconnected, Preparing, Connecting, Connected, Disconnecting, Reconnecting, Error };
Q_ENUM_NS(ConnectionState)
}
EOF

# Исходники натива: рабочее дерево или BASE-ревизия (только файлы зоны CL-C).
NATIVE="$CLIENT/platforms/ios"
DEFS=()
if [ -n "${BASE:-}" ]; then
    NATIVE="$OUT/src/platforms/ios"
    for f in ios_controller.h ios_controller.mm ios_controller_wrapper.h ios_controller_wrapper.mm \
             IosStatusRequest.h AvpnIntentController.h AvpnIntentController.mm; do
        git -C "$CLIENT" show "$BASE:client/platforms/ios/$f" > "$NATIVE/$f"
    done
    DEFS+=(-DHARNESS_OLD=1)
fi

COMMON=(-std=c++17 -DQ_OS_IOS -DMACOS_NE=1 '-DVPN_NE_BUNDLEID="x.ne"' '-DSWIFT_BRIDGE_OBJC_HEADER="HarnessSwift.h"'
        -I"$NATIVE" -I"$OUT/shim" -I"$CLIENT/platforms/ios" -F"$QT/lib"
        -I"$QT/lib/QtCore.framework/Headers" -I"$QT/lib/QtQml.framework/Headers" -I"$QT/include"
        -I"$CLIENT" ${DEFS[@]+"${DEFS[@]}"})
OBJC=(-x objective-c++ -fno-objc-arc -Wno-deprecated-declarations -Wno-objc-method-access)

"$QT/libexec/moc" -DQ_OS_IOS -DMACOS_NE=1 -I"$CLIENT" -I"$NATIVE" "$NATIVE/ios_controller.h" -o "$OUT/moc_ios_controller.cpp"
"$QT/libexec/moc" "$OUT/shim/HarnessVpnNamespace.h" -o "$OUT/moc_vpnProtocol.cpp"
xcrun clang++ "${COMMON[@]}" "${OBJC[@]}" -c "$NATIVE/ios_controller.mm" -o "$OUT/ios_controller.o"
xcrun clang++ "${COMMON[@]}" "${OBJC[@]}" -c "$NATIVE/ios_controller_wrapper.mm" -o "$OUT/ios_controller_wrapper.o"
xcrun clang++ "${COMMON[@]}" "${OBJC[@]}" -c "$OUT/moc_ios_controller.cpp" -o "$OUT/moc_ios_controller.o"
xcrun clang++ "${COMMON[@]}" "${OBJC[@]}" -c "$OUT/moc_vpnProtocol.cpp" -o "$OUT/moc_vpnProtocol.o"
xcrun clang++ "${COMMON[@]}" "${OBJC[@]}" -c "$HERE/IosControllerHarnessTests.mm" -o "$OUT/harness.o"
LINK=(-F"$QT/lib" -framework QtCore -framework QtQml -framework Foundation -framework NetworkExtension
      -Wl,-rpath,"$QT/lib")
xcrun clang++ "$OUT/ios_controller.o" "$OUT/ios_controller_wrapper.o" "$OUT/moc_ios_controller.o" \
    "$OUT/moc_vpnProtocol.o" "$OUT/harness.o" "${LINK[@]}" -o "$OUT/ios_controller_harness"

# AvpnIntentController: лок (C6) и схлопывание журнала (C8) на настоящем файловом App Group
# (containerURL подменён на временный каталог).
xcrun clang++ "${COMMON[@]}" "${OBJC[@]}" -c "$NATIVE/AvpnIntentController.mm" -o "$OUT/intent.o"
xcrun clang++ "${COMMON[@]}" "${OBJC[@]}" -c "$HERE/AvpnIntentControllerTests.mm" -o "$OUT/intent_tests.o"
xcrun clang++ "$OUT/intent.o" "$OUT/intent_tests.o" "${LINK[@]}" -o "$OUT/intent_harness"

fail=0
run() {
    local bin="$1" name="$2" log="$OUT/$2.log"
    if "$bin" "$name" >"$log" 2>&1; then cat "$log" | grep -E '^(PASS|FAIL)' || true
    else cat "$log"; fail=1; fi
}
for t in $("$OUT/ios_controller_harness" --list); do
    [ -n "${ONLY:-}" ] && [ "$ONLY" != "$t" ] && continue
    run "$OUT/ios_controller_harness" "$t"
done
for t in $("$OUT/intent_harness" --list); do
    [ -n "${ONLY:-}" ] && [ "$ONLY" != "$t" ] && continue
    run "$OUT/intent_harness" "$t"
done
if [ "$fail" -ne 0 ]; then echo "ios controller harness: FAILED (logs in $OUT)"; exit 1; fi
echo "ios controller harness: all tests passed"
