package org.amnezia.vpn

import android.content.Context
import java.io.File
import org.amnezia.vpn.util.Log

// AVPN: обход binder-лимита при доставке vpnConfig в процесс VPN-сервиса.
// RU-direct split сеет весь рунет-CIDR в splitTunnelSites → конфиг ~700 КБ; парсел такого размера
// в Intent/Messenger роняет процесс сервиса на старте (TransactionTooLargeException: binder-буфер
// ~1 МБ на процесс, у async-транзакций — доля от него). Большой конфиг передаём файлом
// (activity и сервис — один UID/sandbox), в парселе — только путь. Маленькие конфиги идут
// апстрим-путём (inline в парселе), чтобы не менять поведение ванильных сценариев.

private const val TAG = "TribeConfigFile"

object TribeConfigFile {
    const val MSG_VPN_CONFIG_FILE = "VPN_CONFIG_FILE"

    // Порог с запасом: >100К символов (~200 КБ UTF-16 в парселе) — уже риск при занятом binder-буфере.
    const val INLINE_LIMIT = 100_000

    fun write(context: Context, config: String): String {
        val dir = File(context.filesDir, "tribe").apply { mkdirs() }
        val tmp = File(dir, "vpn_config.json.tmp")
        val dst = File(dir, "vpn_config.json")
        tmp.writeText(config)
        if (!tmp.renameTo(dst)) {
            dst.delete()
            if (!tmp.renameTo(dst)) dst.writeText(config)
        }
        Log.d(TAG, "VPN config handed off via file (${config.length} chars)")
        return dst.absolutePath
    }

    fun read(path: String?): String? =
        path?.let {
            runCatching { File(it).readText() }
                .onFailure { e -> Log.e(TAG, "Failed to read VPN config file: $e") }
                .getOrNull()
        }
}
