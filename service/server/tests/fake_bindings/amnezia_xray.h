// service/server/tests/fake_bindings/amnezia_xray.h
// AVPN test double of the bindings header (recipes/amnezia-xray-bindings, cgo-generated in the real
// build): the same declarations, implemented by tribe_scan_fakes.cpp so the relay tests link without
// the Go archive. Keep the signatures equal to the real header (service_syntax compiles tribe_scan.cpp
// against the real one).
#pragma once

#include <stddef.h>
#include <stdint.h>

typedef void (*amnezia_xray_sockcallback)(uintptr_t fd, void* ctx);
typedef void (*amnezia_xray_loghandler)(char* str, void* ctx);

#ifdef __cplusplus
extern "C" {
#endif

extern void amnezia_xray_free(void* ptr);
extern char* amnezia_xray_configure(char* cConfig);
extern char* amnezia_xray_start(void);
extern char* amnezia_xray_stop(void);
extern char* amnezia_xray_setsockcallback(amnezia_xray_sockcallback cb, void* ctx);
extern void amnezia_xray_setloghandler(amnezia_xray_loghandler cb, void* ctx);
extern char* amnezia_xray_scan_message(char* cMessage, char* cHostOptions);
extern char* amnezia_xray_scan_stop_all(int64_t waitMs);

#ifdef __cplusplus
}
#endif
