#ifndef PROTOCOLUTILS_H
#define PROTOCOLUTILS_H
// Test stand-in for client/core/protocols/protocolUtils.h (xray_protocol_end_check).
#include <QString>
#include "core/utils/protocolEnum.h"
namespace amnezia {
using namespace ProtocolEnumNS;
namespace ProtocolUtils {
inline QString key_proto_config_data(Proto p) { return p == Proto::SSXray ? QStringLiteral("ssxray_config_data") : QStringLiteral("xray_config_data"); }
}
}
#endif
