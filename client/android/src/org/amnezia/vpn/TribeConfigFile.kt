package org.amnezia.vpn

import android.content.Context

// AVPN: обход binder-лимита при доставке vpnConfig в процесс VPN-сервиса.
// RU-direct split сеет весь рунет-CIDR в splitTunnelSites → конфиг ~700 КБ; парсел такого размера
// в Intent/Messenger роняет процесс сервиса на старте (TransactionTooLargeException: binder-буфер
// ~1 МБ на процесс, у async-транзакций — доля от него). Большой конфиг передаём файлом
// (activity и сервис — один UID/sandbox), в парселе — только путь. Маленькие конфиги идут
// апстрим-путём (inline в парселе), чтобы не менять поведение ванильных сценариев.

object TribeConfigFile {
    const val MSG_VPN_CONFIG_REF = "VPN_CONFIG_REF_V1"

    fun write(context: Context, config: String): String {
        return AndroidVpnConfigVault.stage(context.applicationContext, config)
    }

    fun read(context: Context, opaqueReference: String?): String? =
        AndroidVpnConfigVault.consume(context.applicationContext, opaqueReference)
}
