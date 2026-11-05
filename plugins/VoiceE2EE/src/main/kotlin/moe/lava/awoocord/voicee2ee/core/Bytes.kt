package moe.lava.awoocord.voicee2ee.core

/**
 * Small byte helpers. Kept dependency free: this package must run on the plain JVM (unit tests) and on
 * Android 5+ with Discord's bundled Kotlin 1.5 stdlib, so only long-stable stdlib/java APIs are used.
 */
internal object Bytes {
    fun u16(b: ByteArray, off: Int): Int = ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    fun u32(b: ByteArray, off: Int): Long =
        ((b[off].toLong() and 0xFF) shl 24) or ((b[off + 1].toLong() and 0xFF) shl 16) or
            ((b[off + 2].toLong() and 0xFF) shl 8) or (b[off + 3].toLong() and 0xFF)

    fun putU16(b: ByteArray, off: Int, v: Int) {
        b[off] = (v ushr 8).toByte()
        b[off + 1] = v.toByte()
    }

    fun putU32(b: ByteArray, off: Int, v: Long) {
        b[off] = (v ushr 24).toByte()
        b[off + 1] = (v ushr 16).toByte()
        b[off + 2] = (v ushr 8).toByte()
        b[off + 3] = v.toByte()
    }

    /** Big-endian 8 bytes, as used for the MLS basic credential identity (the Discord user id). */
    fun u64be(v: Long): ByteArray = ByteArray(8) { i -> (v ushr (56 - 8 * i)).toByte() }

    /** Little-endian 8 bytes, as used for the MLS exporter context of the sender key. */
    fun u64le(v: Long): ByteArray = ByteArray(8) { i -> (v ushr (8 * i)).toByte() }

    fun fromU64be(b: ByteArray): Long {
        var v = 0L
        for (x in b) v = (v shl 8) or (x.toLong() and 0xFF)
        return v
    }

    fun concat(vararg parts: ByteArray): ByteArray {
        var n = 0
        for (p in parts) n += p.size
        val out = ByteArray(n)
        var o = 0
        for (p in parts) {
            System.arraycopy(p, 0, out, o, p.size)
            o += p.size
        }
        return out
    }

    fun hex(b: ByteArray, max: Int = b.size): String {
        val sb = StringBuilder()
        for (i in 0 until minOf(max, b.size)) {
            val v = b[i].toInt() and 0xFF
            sb.append("0123456789abcdef"[v shr 4]).append("0123456789abcdef"[v and 15])
        }
        return sb.toString()
    }

    /** Constant-time comparison of the first [len] bytes of two arrays at the given offsets. */
    fun ctEquals(a: ByteArray, aOff: Int, b: ByteArray, bOff: Int, len: Int): Boolean {
        var r = 0
        for (i in 0 until len) r = r or (a[aOff + i].toInt() xor b[bOff + i].toInt())
        return r == 0
    }
}

/** Unsigned LEB128, as used by the DAVE protocol frame footer. */
internal object Leb128 {
    // Values are treated as unsigned; "v and 0x7F.inv() != 0" is "v >= 0x80 unsigned" without
    // java.lang.Long.compareUnsigned, which only exists from Android API 26.
    fun size(value: Long): Int {
        var v = value
        var n = 1
        while (v and 0x7FL.inv() != 0L) {
            v = v ushr 7
            n++
        }
        return n
    }

    /** Writes [value] at [off] and returns the number of bytes written. */
    fun write(value: Long, out: ByteArray, off: Int): Int {
        var v = value
        var o = off
        while (v and 0x7FL.inv() != 0L) {
            out[o++] = (0x80 or (v and 0x7F).toInt()).toByte()
            v = v ushr 7
        }
        out[o++] = v.toByte()
        return o - off
    }

    /**
     * Reads a value from [buf] starting at [pos] and not reading at or past [end].
     * Returns the value and stores the new position in [posOut]\[0\], or returns -1 with posOut\[0\] = -1 on malformed input.
     */
    fun read(buf: ByteArray, pos: Int, end: Int, posOut: IntArray): Long {
        var result = 0L
        var shift = 0
        var p = pos
        while (p < end) {
            val b = buf[p++].toInt() and 0xFF
            if (shift >= 64 || (shift == 63 && (b and 0x7E) != 0)) break // overflow
            result = result or ((b and 0x7F).toLong() shl shift)
            if (b and 0x80 == 0) {
                posOut[0] = p
                return result
            }
            shift += 7
        }
        posOut[0] = -1
        return -1
    }
}
