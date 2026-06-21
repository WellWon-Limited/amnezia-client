// AVPN: точка входа macOS System Extension.
// appex запускался через _NSExtensionMain (авто Xcode). System Extension — обычный исполняемый
// бандл: его main обязан перевести процесс в режим расширения через NEProvider.startSystemExtensionMode(),
// тогда система инстанцирует PacketTunnelProvider по NEProviderClasses из Info.plist (NetworkExtension dict).
// Только macOS-NE (sysext). iOS использует appex и этот файл не подключает.
import Foundation
import NetworkExtension

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
