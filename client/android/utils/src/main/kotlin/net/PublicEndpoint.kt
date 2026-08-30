package org.amnezia.vpn.util.net

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/** Strict public-unicast policy for server endpoints and route exclusions. */
fun InetAddress.isPublicUnicastEndpoint(): Boolean {
    if (isAnyLocalAddress || isLoopbackAddress || isLinkLocalAddress ||
        isSiteLocalAddress || isMulticastAddress
    ) return false

    val bytes = address.map { it.toInt() and 0xff }
    return when (this) {
        is Inet4Address -> {
            val first = bytes[0]
            val second = bytes[1]
            !(
                first == 0 || first == 10 || first == 127 ||
                    (first == 100 && second in 64..127) ||
                    (first == 169 && second == 254) ||
                    (first == 172 && second in 16..31) ||
                    (first == 192 && second == 0) ||
                    (first == 192 && second == 168) ||
                    (first == 198 && second in 18..19) ||
                    (first == 198 && second == 51 && bytes[2] == 100) ||
                    (first == 203 && second == 0 && bytes[2] == 113) ||
                    first >= 224
                )
        }

        is Inet6Address -> {
            val first16 = (bytes[0] shl 8) or bytes[1]
            val first32 = (first16.toLong() shl 16) or
                ((bytes[2] shl 8) or bytes[3]).toLong()
            val documentation = first32 == 0x20010db8L
            val uniqueLocal = first16 and 0xfe00 == 0xfc00
            val discarded = first16 and 0xffc0 == 0xfe80
            val orchid = first32 == 0x20010020L
            val v4Mapped = bytes.take(10).all { it == 0 } && bytes[10] == 0xff && bytes[11] == 0xff
            !documentation && !uniqueLocal && !discarded && !orchid && !v4Mapped
        }

        else -> false
    }
}

/** Parses a canonical numeric endpoint without ever invoking hostname DNS. */
fun parsePublicEndpointLiteral(value: String): InetAddress? {
    if (value.isEmpty() || value.length > 64) return null
    val isV4Syntax = value.all { it in '0'..'9' || it == '.' } && value.count { it == '.' } == 3
    val isV6Syntax = ':' in value && value.all {
        it == ':' || it == '.' || it in '0'..'9' || it in 'a'..'f'
    }
    if (!isV4Syntax && !isV6Syntax) return null
    val parsed = runCatching { InetAddress.getByName(value) }.getOrNull() ?: return null
    if (isV4Syntax && parsed !is Inet4Address) return null
    if (isV6Syntax && parsed !is Inet6Address) return null
    if (canonicalNumericLiteral(parsed) != value) return null
    return parsed.takeIf(InetAddress::isPublicUnicastEndpoint)
}

private fun canonicalNumericLiteral(address: InetAddress): String = when (address) {
    is Inet4Address -> address.address.joinToString(".") { (it.toInt() and 0xff).toString() }
    is Inet6Address -> {
        val bytes = address.address
        val groups = IntArray(8) { index ->
            ((bytes[index * 2].toInt() and 0xff) shl 8) or
                (bytes[index * 2 + 1].toInt() and 0xff)
        }
        var bestStart = -1
        var bestLength = 0
        var cursor = 0
        while (cursor < groups.size) {
            if (groups[cursor] != 0) {
                cursor++
                continue
            }
            val start = cursor
            while (cursor < groups.size && groups[cursor] == 0) cursor++
            val length = cursor - start
            if (length >= 2 && length > bestLength) {
                bestStart = start
                bestLength = length
            }
        }
        if (bestStart < 0) {
            groups.joinToString(":") { it.toString(16) }
        } else {
            val prefix = groups.take(bestStart).joinToString(":") { it.toString(16) }
            val suffix = groups.drop(bestStart + bestLength)
                .joinToString(":") { it.toString(16) }
            when {
                prefix.isEmpty() && suffix.isEmpty() -> "::"
                prefix.isEmpty() -> "::$suffix"
                suffix.isEmpty() -> "$prefix::"
                else -> "$prefix::$suffix"
            }
        }
    }
    else -> ""
}
