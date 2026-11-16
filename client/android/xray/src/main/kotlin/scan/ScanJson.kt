package org.amnezia.vpn.protocol.xray.scan

// AVPN (Scanner, lane A3; plan ~/avpn-build/plans/provider-pool/scanner-client-plan.md v2.2 §2.5): read and splice
// the engine's reply without re-encoding it - the Kotlin twin of TribeScanJSON in
// client/platforms/ios/TribeScanHost.swift. The relay rule: the engine's reply bytes stay its bytes; a host addition
// is a splice into the top-level object (a member's value replaced, or members appended before the closing brace).
// Pure, JVM-tested (src/test/kotlin/scan).
object ScanJson {
    class Member(val key: String, val value: IntRange)

    // A top-level object: the indices of "{" and "}" and its members in order.
    class Obj(val open: Int, val close: Int, val members: List<Member>) {
        fun value(key: String): IntRange? = members.firstOrNull { it.key == key }?.value
    }

    class Edit(val range: IntRange, val text: String) // an empty range (start > end) = an insertion at range.first

    private fun skipSpace(s: String, from: Int, end: Int): Int {
        var i = from
        while (i < end && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++
        return i
    }

    // End (exclusive) of the string starting at `start` ('"'); -1 when unterminated.
    private fun stringEnd(s: String, start: Int, end: Int): Int {
        var i = start + 1
        while (i < end) {
            when (s[i]) {
                '\\' -> i += 2
                '"' -> return i + 1
                else -> i++
            }
        }
        return -1
    }

    // End (exclusive) of the value starting at `start`; -1 when malformed.
    private fun valueEnd(s: String, start: Int, end: Int): Int {
        if (start >= end) return -1
        val c = s[start]
        if (c == '"') return stringEnd(s, start, end)
        if (c == '{' || c == '[') {
            var depth = 0
            var i = start
            while (i < end) {
                when (s[i]) {
                    '"' -> { i = stringEnd(s, i, end); if (i < 0) return -1; continue }
                    '{', '[' -> depth++
                    '}', ']' -> { depth--; if (depth == 0) return i + 1 }
                }
                i++
            }
            return -1
        }
        var i = start
        while (i < end && s[i] != ',' && s[i] != '}' && s[i] != ']' && !s[i].isWhitespace()) i++
        return if (i > start) i else -1
    }

    // The object starting (after spaces) at `from`; null when it is not a well-formed object.
    fun objectAt(s: String, from: Int, end: Int = s.length): Obj? {
        var i = skipSpace(s, from, end)
        if (i >= end || s[i] != '{') return null
        val open = i
        val members = ArrayList<Member>()
        i = skipSpace(s, i + 1, end)
        if (i < end && s[i] == '}') return Obj(open, i, members)
        while (i < end) {
            if (s[i] != '"') return null
            val keyEnd = stringEnd(s, i, end)
            if (keyEnd < 0) return null
            val key = decodeString(s, i, keyEnd) ?: return null
            i = skipSpace(s, keyEnd, end)
            if (i >= end || s[i] != ':') return null
            i = skipSpace(s, i + 1, end)
            val vEnd = valueEnd(s, i, end)
            if (vEnd < 0) return null
            members += Member(key, i until vEnd)
            i = skipSpace(s, vEnd, end)
            if (i < end && s[i] == ',') { i = skipSpace(s, i + 1, end); continue }
            if (i < end && s[i] == '}') return Obj(open, i, members)
            return null
        }
        return null
    }

    // The single top-level object of a reply (only spaces may follow it); null otherwise.
    fun topLevel(s: String): Obj? {
        val o = objectAt(s, 0) ?: return null
        return if (skipSpace(s, o.close + 1, s.length) == s.length) o else null
    }

    fun decodeString(s: String, start: Int, endExclusive: Int): String? {
        if (endExclusive - start < 2 || s[start] != '"' || s[endExclusive - 1] != '"') return null
        val raw = s.substring(start + 1, endExclusive - 1)
        if (!raw.contains('\\')) return raw
        return runCatching { org.json.JSONArray("[" + s.substring(start, endExclusive) + "]").getString(0) }.getOrNull()
    }

    fun string(s: String, r: IntRange): String? = decodeString(s, r.first, r.last + 1)

    fun isLiteral(s: String, r: IntRange, literal: String): Boolean = s.substring(r.first, r.last + 1) == literal

    fun int(s: String, r: IntRange): Long? = s.substring(r.first, r.last + 1).toLongOrNull()

    fun isAbsentOrNull(o: Obj, s: String, key: String): Boolean {
        val r = o.value(key) ?: return true
        return isLiteral(s, r, "null")
    }

    // Set members of `o`: an existing key gets its value replaced, a new one is appended before "}".
    fun setMembers(o: Obj, pairs: List<Pair<String, String>>): List<Edit> {
        val edits = ArrayList<Edit>()
        val appended = ArrayList<String>()
        for ((key, raw) in pairs) {
            val r = o.value(key)
            if (r != null) edits += Edit(r, raw) else appended += "\"" + key + "\":" + raw
        }
        if (appended.isNotEmpty()) {
            val text = (if (o.members.isEmpty()) "" else ",") + appended.joinToString(",")
            edits += Edit(o.close until o.close, text)
        }
        return edits
    }

    // Applies non-overlapping edits (any order).
    fun apply(s: String, edits: List<Edit>): String {
        if (edits.isEmpty()) return s
        val sb = StringBuilder(s)
        for (e in edits.sortedByDescending { it.range.first }) {
            val endExclusive = if (e.range.isEmpty()) e.range.first else e.range.last + 1
            sb.replace(e.range.first, endExclusive, e.text)
        }
        return sb.toString()
    }
}
