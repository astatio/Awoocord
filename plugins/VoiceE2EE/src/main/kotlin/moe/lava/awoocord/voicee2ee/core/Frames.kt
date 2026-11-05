package moe.lava.awoocord.voicee2ee.core

/** Monotonic millisecond clock; replaceable in tests. */
fun interface Clock {
    fun nowMs(): Long

    companion object {
        val SYSTEM = Clock { System.nanoTime() / 1_000_000L }
    }
}

/** Media codecs the encryptor knows (plain ints: Kotlin 2 enums need a newer stdlib than Discord ships). */
object Codec {
    const val OPUS = 0
    const val VP8 = 1
    const val UNKNOWN = -1
}

/**
 * DAVE protocol media frame format (protocol.md, "Payload Format"):
 *   interleaved frame | 8 byte tag | ULEB128 nonce | ULEB128 (offset,size) unencrypted ranges | 1 byte supplemental
 *   size | 0xFAFA
 */
internal object ProtocolFrame {
    const val MARKER: Int = 0xFAFA
    const val MIN_SUPPLEMENTAL = AesGcm64.TAG_BYTES + 1 + 2
    private const val GENERATION_SHIFT = 24

    val OPUS_SILENCE = byteArrayOf(0xF8.toByte(), 0xFF.toByte(), 0xFE.toByte())

    fun isOpusSilence(frame: ByteArray) = frame.size == 3 && frame[0] == OPUS_SILENCE[0] &&
        frame[1] == OPUS_SILENCE[1] && frame[2] == OPUS_SILENCE[2]

    fun generationOf(truncatedNonce: Long) = (truncatedNonce ushr GENERATION_SHIFT) and 0xFF

    /** Expand to the 96 bit AES-GCM nonce: 8 zero bytes then the 32 bit nonce (little endian, as libdave's memcpy). */
    fun fullNonce(truncatedNonce: Long): ByteArray {
        val n = ByteArray(12)
        n[8] = truncatedNonce.toByte()
        n[9] = (truncatedNonce ushr 8).toByte()
        n[10] = (truncatedNonce ushr 16).toByte()
        n[11] = (truncatedNonce ushr 24).toByte()
        return n
    }

    /** Wraps an 8 bit generation into the full generation space relative to [oldest] (libdave ComputeWrappedGeneration). */
    fun wrappedGeneration(oldest: Long, generation: Long): Long {
        val remainder = oldest % 256
        val factor = oldest / 256 + if (generation < remainder) 1 else 0
        return factor * 256 + generation
    }

    fun wrappedBigNonce(generation: Long, truncatedNonce: Long): Long =
        (generation shl GENERATION_SHIFT) or (truncatedNonce and 0xFFFFFF)

    /**
     * Unencrypted prefix length for the codec. The encryptor is codec aware, the decryptor is not.
     *  - Opus: everything encrypted.
     *  - VP8: 10 bytes for key frames (payload header + uncompressed header), 1 byte for delta frames.
     */
    fun unencryptedPrefix(codec: Int, frame: ByteArray): Int = when (codec) {
        Codec.VP8 -> if (frame.isEmpty()) 0 else if (frame[0].toInt() and 1 == 0) minOf(10, frame.size) else 1
        else -> 0
    }

    class Parsed(
        val tag: ByteArray,
        val tagOff: Int,
        val truncatedNonce: Long,
        /** Concatenated unencrypted bytes (the AEAD additional data). */
        val aad: ByteArray,
        val ciphertext: ByteArray,
        /** Pairs of (offset, size) for the unencrypted ranges, in frame order. */
        val ranges: LongArray,
        val mediaSize: Int,
    )

    /** Protocol frame check + parse; returns null when [frame] is not a DAVE protocol frame. */
    fun parse(frame: ByteArray): Parsed? {
        val n = frame.size
        if (n < MIN_SUPPLEMENTAL) return null
        if (frame[n - 1] != 0xFA.toByte() || frame[n - 2] != 0xFA.toByte()) return null
        val supplemental = frame[n - 3].toInt() and 0xFF
        if (supplemental < MIN_SUPPLEMENTAL || supplemental > n) return null
        val suppStart = n - supplemental
        val tagOff = suppStart
        val pos = IntArray(1)
        val end = n - 3
        val nonce = Leb128.read(frame, tagOff + AesGcm64.TAG_BYTES, end, pos)
        if (pos[0] < 0 || nonce > 0xFFFFFFFFL || nonce < 0) return null
        var p = pos[0]
        val ranges = ArrayList<Long>()
        while (p < end) {
            val off = Leb128.read(frame, p, end, pos)
            if (pos[0] < 0) return null
            p = pos[0]
            val size = Leb128.read(frame, p, end, pos)
            if (pos[0] < 0) return null
            p = pos[0]
            ranges.add(off)
            ranges.add(size)
        }
        if (p != end) return null
        val mediaSize = suppStart
        // ranges must be ordered, non overlapping and inside the media part
        var i = 0
        while (i < ranges.size) {
            val off = ranges[i]
            val size = ranges[i + 1]
            val maxEnd = if (i + 2 < ranges.size) ranges[i + 2] else frame.size.toLong()
            if (off < 0 || size < 0 || off + size < off || off + size > maxEnd) return null
            i += 2
        }
        // split the media into aad and ciphertext
        val aad = java.io.ByteArrayOutputStream()
        val ct = java.io.ByteArrayOutputStream()
        var idx = 0
        i = 0
        while (i < ranges.size) {
            val off = ranges[i].toInt()
            val size = ranges[i + 1].toInt()
            if (off + size > mediaSize) return null
            if (off > idx) ct.write(frame, idx, off - idx)
            aad.write(frame, off, size)
            idx = off + size
            i += 2
        }
        if (idx < mediaSize) ct.write(frame, idx, mediaSize - idx)
        return Parsed(frame, tagOff, nonce, aad.toByteArray(), ct.toByteArray(), ranges.toLongArray(), mediaSize)
    }

    /** Reassembles the media frame from the unencrypted ranges and the decrypted bytes. */
    fun reconstruct(p: Parsed, plaintext: ByteArray): ByteArray {
        val out = ByteArray(p.aad.size + plaintext.size)
        var o = 0
        var aadIdx = 0
        var ptIdx = 0
        var i = 0
        while (i < p.ranges.size) {
            val off = p.ranges[i].toInt()
            val size = p.ranges[i + 1].toInt()
            if (off > o) {
                val n = off - o
                System.arraycopy(plaintext, ptIdx, out, o, n)
                ptIdx += n
                o += n
            }
            System.arraycopy(p.aad, aadIdx, out, o, size)
            aadIdx += size
            o += size
            i += 2
        }
        if (ptIdx < plaintext.size) System.arraycopy(plaintext, ptIdx, out, o, plaintext.size - ptIdx)
        return out
    }
}

/** Sends frames for the local user. Thread safe. */
class FrameEncryptor {
    private var ratchet: KeyRatchet? = null
    private var domain: ByteArray? = null
    private var generation = 0L
    private var truncatedNonce = 0L
    private var cryptor: AesGcm64? = null
    private var cryptorGeneration = -1L

    /** When true, frames are sent unmodified (protocol version 0 / downgraded sessions). */
    @Volatile
    var passthrough = false

    val hasKey: Boolean @Synchronized get() = ratchet != null

    @Synchronized
    fun setKeyRatchet(r: KeyRatchet?) {
        if (r != null && !java.util.Arrays.equals(r.domainIdentity, domain)) {
            // a new key domain restarts the nonce sequence; reinstalling the same one must not (nonce reuse)
            domain = r.domainIdentity
            generation = 0
            truncatedNonce = 0
        }
        ratchet = r
        cryptor = null
        cryptorGeneration = -1
    }

    /** Returns the protocol frame, the frame itself in passthrough mode, or null when it must be dropped. */
    @Synchronized
    fun encrypt(codec: Int, frame: ByteArray): ByteArray? {
        if (passthrough) return frame
        val r = ratchet ?: return null
        truncatedNonce = (truncatedNonce + 1) and 0xFFFFFFFFL
        val gen = ProtocolFrame.wrappedGeneration(generation, ProtocolFrame.generationOf(truncatedNonce))
        if (gen != cryptorGeneration || cryptor == null) {
            val key = r.get(gen) ?: return null
            cryptor = AesGcm64(key)
            cryptorGeneration = gen
            generation = gen
        }
        val clear = ProtocolFrame.unencryptedPrefix(codec, frame)
        val aad = frame.copyOfRange(0, clear)
        val plaintext = frame.copyOfRange(clear, frame.size)
        val nonceLen = Leb128.size(truncatedNonce)
        val rangesLen = if (clear > 0) Leb128.size(0) + Leb128.size(clear.toLong()) else 0
        val supplemental = AesGcm64.TAG_BYTES + nonceLen + rangesLen + 1 + 2
        val out = ByteArray(frame.size + supplemental)
        val ct = cryptor!!.encrypt(ProtocolFrame.fullNonce(truncatedNonce), plaintext, aad, out, frame.size)
        System.arraycopy(aad, 0, out, 0, clear)
        System.arraycopy(ct, 0, out, clear, ct.size)
        var o = frame.size + AesGcm64.TAG_BYTES
        o += Leb128.write(truncatedNonce, out, o)
        if (clear > 0) {
            o += Leb128.write(0, out, o)
            o += Leb128.write(clear.toLong(), out, o)
        }
        out[o++] = supplemental.toByte()
        out[o++] = 0xFA.toByte()
        out[o] = 0xFA.toByte()
        return out
    }
}

/** Decryption state for one sender key ratchet (libdave CryptorManager). */
internal class CryptorManager(private val clock: Clock, private val ratchet: KeyRatchet) {
    val domainIdentity: ByteArray get() = ratchet.domainIdentity

    private val created = clock.nowMs()
    private var expiry = Long.MAX_VALUE
    private var oldestGeneration = 0L
    private var newestGeneration = 0L
    private var newestProcessedNonce = -1L
    private val missingNonces = java.util.ArrayDeque<Long>()
    private val cryptors = HashMap<Long, Pair<AesGcm64, Long>>() // generation -> (cryptor, expiry)

    fun isExpired() = expiry < clock.nowMs()

    fun updateExpiry(maxExpiry: Long) {
        expiry = minOf(expiry, maxExpiry)
    }

    fun wrappedGeneration(gen8: Long) = ProtocolFrame.wrappedGeneration(oldestGeneration, gen8)

    fun canProcessNonce(generation: Long, nonce: Long): Boolean {
        val big = ProtocolFrame.wrappedBigNonce(generation, nonce)
        val expected = newestProcessedNonce + 1
        return big >= expected || missingNonces.contains(big)
    }

    fun cryptorFor(generation: Long): AesGcm64? {
        cleanup()
        if (generation < oldestGeneration) return null
        if (generation > newestGeneration + MAX_GENERATION_GAP) return null
        val lifetimeSec = (clock.nowMs() - created) / 1000
        val maxLifetimeGenerations = (MAX_FRAMES_PER_SECOND * lifetimeSec) shr 24
        if (generation > maxLifetimeGenerations) return null
        cryptors[generation]?.let { return it.first }
        val key = ratchet.get(generation) ?: return null
        val exp = if (generation < newestGeneration) clock.nowMs() + EXPIRY_MS else Long.MAX_VALUE
        val c = AesGcm64(key)
        cryptors[generation] = c to exp
        return c
    }

    fun reportSuccess(generation: Long, nonce: Long) {
        val big = ProtocolFrame.wrappedBigNonce(generation, nonce)
        val expected = newestProcessedNonce + 1
        if (big >= expected) {
            val missing = minOf(big - expected, MAX_MISSING_NONCES.toLong())
            while (missingNonces.isNotEmpty() && missingNonces.size + missing > MAX_MISSING_NONCES) missingNonces.pollFirst()
            var i = big - missing
            while (i < big) missingNonces.addLast(i++)
            newestProcessedNonce = big
        } else {
            missingNonces.remove(big)
        }
        if (generation <= newestGeneration || !cryptors.containsKey(generation)) return
        newestGeneration = generation
        val exp = clock.nowMs() + EXPIRY_MS
        for ((g, v) in cryptors.entries.toList()) {
            if (g < newestGeneration) cryptors[g] = v.first to minOf(v.second, exp)
        }
    }

    private fun cleanup() {
        val now = clock.nowMs()
        cryptors.entries.removeAll { it.value.second < now }
        while (oldestGeneration < newestGeneration && !cryptors.containsKey(oldestGeneration)) {
            ratchet.erase(oldestGeneration)
            oldestGeneration++
        }
    }

    companion object {
        const val EXPIRY_MS = 10_000L
        const val MAX_GENERATION_GAP = 250
        const val MAX_MISSING_NONCES = 1000
        const val MAX_FRAMES_PER_SECOND = 50 + 2 * 60L
    }
}

/** Receives frames from one remote user. Codec agnostic. Thread safe. */
class FrameDecryptor(private val clock: Clock = Clock.SYSTEM) {
    private val managers = java.util.ArrayDeque<CryptorManager>()
    private var passthroughUntil = Long.MAX_VALUE

    /** decrypt results. */
    object Result {
        const val OK = 0
        const val PASSTHROUGH = 1
        const val NOT_ENCRYPTED = 2
        const val NO_KEY = 3
        const val INVALID_NONCE = 4
        const val FAILED = 5
    }

    /** Output of the last [decrypt] call (valid when the result is OK or PASSTHROUGH). */
    var output: ByteArray = ByteArray(0)
        private set

    @Synchronized
    fun transitionToKeyRatchet(r: KeyRatchet?, expiryMs: Long = CryptorManager.EXPIRY_MS) {
        managers.removeAll { it.isExpired() }
        if (r != null && managers.any { java.util.Arrays.equals(it.domainIdentity, r.domainIdentity) }) return
        val maxExpiry = clock.nowMs() + expiryMs
        for (m in managers) m.updateExpiry(maxExpiry)
        if (r != null) managers.addLast(CryptorManager(clock, r))
    }

    @Synchronized
    fun transitionToPassthrough(enabled: Boolean, expiryMs: Long = CryptorManager.EXPIRY_MS) {
        passthroughUntil = if (enabled) Long.MAX_VALUE else minOf(passthroughUntil, clock.nowMs() + expiryMs)
    }

    @Synchronized
    fun decrypt(audio: Boolean, frame: ByteArray): Int {
        if (audio && ProtocolFrame.isOpusSilence(frame)) {
            output = frame
            return Result.PASSTHROUGH
        }
        while (managers.isNotEmpty() && managers.peekFirst().isExpired()) managers.pollFirst()
        val parsed = ProtocolFrame.parse(frame)
        if (parsed == null) {
            if (passthroughUntil > clock.nowMs()) {
                output = frame
                return Result.PASSTHROUGH
            }
            return Result.NOT_ENCRYPTED
        }
        var result = Result.NO_KEY
        val it = managers.descendingIterator()
        while (it.hasNext()) {
            val m = it.next()
            val gen = m.wrappedGeneration(ProtocolFrame.generationOf(parsed.truncatedNonce))
            if (!m.canProcessNonce(gen, parsed.truncatedNonce)) {
                result = Result.INVALID_NONCE
                continue
            }
            val c = m.cryptorFor(gen)
            if (c == null) {
                result = Result.NO_KEY
                continue
            }
            val pt = c.decrypt(ProtocolFrame.fullNonce(parsed.truncatedNonce), parsed.ciphertext, parsed.aad, parsed.tag, parsed.tagOff)
            if (pt != null) {
                m.reportSuccess(gen, parsed.truncatedNonce)
                output = ProtocolFrame.reconstruct(parsed, pt)
                return Result.OK
            }
            result = Result.FAILED
        }
        return result
    }
}
