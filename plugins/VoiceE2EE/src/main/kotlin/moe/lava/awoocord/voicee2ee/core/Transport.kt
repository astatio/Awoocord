package moe.lava.awoocord.voicee2ee.core

import org.bouncycastle.crypto.engines.XSalsa20Engine
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** RTP/RTCP helpers. */
object Rtp {
    fun isRtpOrRtcp(p: ByteArray, len: Int) = len >= 12 && (p[0].toInt() and 0xC0) == 0x80

    /** RTCP packet types 200..204 sit where RTP has marker + payload type. */
    fun isRtcp(p: ByteArray) = (p[1].toInt() and 0xFF) in 200..204

    fun payloadType(p: ByteArray) = p[1].toInt() and 0x7F
    fun marker(p: ByteArray) = p[1].toInt() and 0x80 != 0
    fun seq(p: ByteArray) = Bytes.u16(p, 2)
    fun timestamp(p: ByteArray) = Bytes.u32(p, 4)
    fun ssrc(p: ByteArray) = Bytes.u32(p, 8)
    fun hasExtension(p: ByteArray) = p[0].toInt() and 0x10 != 0
    fun hasPadding(p: ByteArray) = p[0].toInt() and 0x20 != 0
    private fun csrcCount(p: ByteArray) = p[0].toInt() and 0x0F

    /** Bytes left unencrypted by the non-"rtpsize" modes: the fixed header and CSRCs only (8 for RTCP). */
    fun fixedHeaderLen(p: ByteArray, len: Int): Int {
        if (isRtcp(p)) return 8
        val n = 12 + 4 * csrcCount(p)
        return if (n <= len) n else -1
    }

    /** Bytes left unencrypted by the "rtpsize" modes: fixed header, CSRCs and the 4 byte extension header. */
    fun rtpsizeHeaderLen(p: ByteArray, len: Int): Int {
        if (isRtcp(p)) return 8
        val n = 12 + 4 * csrcCount(p) + if (hasExtension(p)) 4 else 0
        return if (n <= len) n else -1
    }

    /** Length of the (encrypted in rtpsize modes) header extension body, from the extension header. */
    fun extensionBodyLen(p: ByteArray): Int {
        if (!hasExtension(p)) return 0
        val off = 12 + 4 * csrcCount(p)
        return 4 * Bytes.u16(p, off + 2)
    }
}

/**
 * Transport encryption between a voice client and Discord's media server ("rtpsize" modes): the header (see
 * [Rtp.rtpsizeHeaderLen]) stays clear, everything after it is encrypted, and a 32 bit nonce counter is appended.
 * Implementations are not thread safe.
 */
abstract class TransportCipher(
    /** false: only the fixed header + CSRCs stay clear (the extension header is encrypted too). */
    private val rtpsizeHeader: Boolean = true,
) {
    /** Last nonce used by [seal]; carried over when a cipher for the same key is replaced. */
    var counter = 0L

    private fun clearHeaderLen(p: ByteArray, len: Int) =
        if (rtpsizeHeader) Rtp.rtpsizeHeaderLen(p, len) else Rtp.fixedHeaderLen(p, len)

    /** Decrypts [len] bytes of [packet]; returns header + plaintext, or null when it doesn't authenticate. */
    open fun open(packet: ByteArray, len: Int): ByteArray? {
        val hdr = clearHeaderLen(packet, len)
        if (hdr < 0 || len < hdr + overhead()) return null
        val nonce = packet.copyOfRange(len - 4, len)
        val pt = decrypt(packet.copyOfRange(0, hdr), packet.copyOfRange(hdr, len - 4), nonce) ?: return null
        val out = ByteArray(hdr + pt.size)
        System.arraycopy(packet, 0, out, 0, hdr)
        System.arraycopy(pt, 0, out, hdr, pt.size)
        return out
    }

    /** Encrypts a plain packet (header + payload) with the next nonce; returns the wire packet. */
    open fun seal(plain: ByteArray): ByteArray {
        val hdr = clearHeaderLen(plain, plain.size)
        counter = (counter + 1) and 0xFFFFFFFFL
        val nonce = ByteArray(4)
        Bytes.putU32(nonce, 0, counter)
        val header = plain.copyOfRange(0, hdr)
        val ct = encrypt(header, plain.copyOfRange(hdr, plain.size), nonce)
        return Bytes.concat(header, ct, nonce)
    }

    /** Tag + nonce bytes added to each packet. */
    protected open fun overhead() = 16 + 4

    protected abstract fun encrypt(header: ByteArray, plaintext: ByteArray, nonce4: ByteArray): ByteArray
    protected abstract fun decrypt(header: ByteArray, ciphertext: ByteArray, nonce4: ByteArray): ByteArray?

    companion object {
        const val AES256_GCM = "aead_aes256_gcm_rtpsize"
        const val XCHACHA20 = "aead_xchacha20_poly1305_rtpsize"
        const val XSALSA20_LITE = "xsalsa20_poly1305_lite_rtpsize"

        fun create(mode: String, key: ByteArray): TransportCipher? = when (mode) {
            AES256_GCM -> AesGcmRtpSize(key)
            XCHACHA20 -> XChaChaRtpSize(key)
            XSALSA20_LITE -> XSalsaLiteRtpSize(key)
            else -> null
        }

        /**
         * Layouts Discord 126.21's engine might actually use on the local leg when told [mode], the documented one
         * first. The relay tries the others when the engine's packets don't open with the documented one; an
         * authenticated (AEAD) open can't succeed with the wrong layout, so a match is conclusive.
         */
        fun localVariants(mode: String, key: ByteArray): List<Pair<String, TransportCipher>> = when (mode) {
            AES256_GCM -> listOf(
                "rtpsize, nonce first" to AesGcmRtpSize(key),
                "rtpsize, nonce last" to AesGcmRtpSize(key, noncePos = 8),
                "fixed header, nonce first" to AesGcmRtpSize(key, rtpsizeHeader = false),
                "fixed header, nonce last" to AesGcmRtpSize(key, noncePos = 8, rtpsizeHeader = false),
            )
            XSALSA20_LITE -> listOf(
                "rtpsize" to XSalsaLiteRtpSize(key),
                "fixed header" to XSalsaLiteRtpSize(key, rtpsizeHeader = false),
            )
            else -> listOfNotNull(create(mode, key)?.let { "default" to it })
        }
    }
}

/** No transport encryption: what an engine that didn't accept the requested mode would send. Detection only. */
class PlainTransport : TransportCipher() {
    override fun open(packet: ByteArray, len: Int): ByteArray? = packet.copyOf(len)
    override fun seal(plain: ByteArray): ByteArray = plain
    override fun encrypt(header: ByteArray, plaintext: ByteArray, nonce4: ByteArray) = plaintext
    override fun decrypt(header: ByteArray, ciphertext: ByteArray, nonce4: ByteArray) = ciphertext
}

/**
 * aead_aes256_gcm_rtpsize: AES-256-GCM, 12 byte nonce = 32 bit big-endian counter then zeros, AAD = header.
 * [noncePos] / [rtpsizeHeader] only differ for probing what the old engine does (see [TransportCipher.localVariants]).
 */
class AesGcmRtpSize(key: ByteArray, private val noncePos: Int = 0, rtpsizeHeader: Boolean = true) : TransportCipher(rtpsizeHeader) {
    private val keySpec = SecretKeySpec(key, "AES")
    private val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    private val nonce = ByteArray(12)

    override fun encrypt(header: ByteArray, plaintext: ByteArray, nonce4: ByteArray): ByteArray {
        System.arraycopy(nonce4, 0, nonce, noncePos, 4)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(128, nonce))
        cipher.updateAAD(header)
        return cipher.doFinal(plaintext)
    }

    override fun decrypt(header: ByteArray, ciphertext: ByteArray, nonce4: ByteArray): ByteArray? {
        System.arraycopy(nonce4, 0, nonce, noncePos, 4)
        return try {
            cipher.init(Cipher.DECRYPT_MODE, keySpec, GCMParameterSpec(128, nonce))
            cipher.updateAAD(header)
            cipher.doFinal(ciphertext)
        } catch (e: java.security.GeneralSecurityException) {
            null
        }
    }
}

/** aead_xchacha20_poly1305_rtpsize: XChaCha20-Poly1305 (IETF), 24 byte nonce = 32 bit big-endian counter then zeros. */
class XChaChaRtpSize(private val key: ByteArray) : TransportCipher() {
    private val aead = ChaCha20Poly1305()

    private fun init(forEncryption: Boolean, header: ByteArray, nonce4: ByteArray) {
        val nonce24 = ByteArray(24)
        System.arraycopy(nonce4, 0, nonce24, 0, 4)
        val subKey = hChaCha20(key, nonce24)
        val nonce12 = ByteArray(12)
        System.arraycopy(nonce24, 16, nonce12, 4, 8)
        aead.init(forEncryption, AEADParameters(KeyParameter(subKey), 128, nonce12, header))
    }

    override fun encrypt(header: ByteArray, plaintext: ByteArray, nonce4: ByteArray): ByteArray {
        init(true, header, nonce4)
        val out = ByteArray(aead.getOutputSize(plaintext.size))
        val n = aead.processBytes(plaintext, 0, plaintext.size, out, 0)
        aead.doFinal(out, n)
        return out
    }

    override fun decrypt(header: ByteArray, ciphertext: ByteArray, nonce4: ByteArray): ByteArray? {
        init(false, header, nonce4)
        val out = ByteArray(aead.getOutputSize(ciphertext.size))
        return try {
            val n = aead.processBytes(ciphertext, 0, ciphertext.size, out, 0)
            aead.doFinal(out, n)
            out
        } catch (e: org.bouncycastle.crypto.InvalidCipherTextException) {
            null
        }
    }

    companion object {
        /** HChaCha20 (draft-irtf-cfrg-xchacha section 2.2): ChaCha20 rounds over key + first 16 nonce bytes. */
        fun hChaCha20(key: ByteArray, nonce: ByteArray): ByteArray {
            val s = IntArray(16)
            s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574
            for (i in 0 until 8) s[4 + i] = le32(key, 4 * i)
            for (i in 0 until 4) s[12 + i] = le32(nonce, 4 * i)
            repeat(10) {
                qr(s, 0, 4, 8, 12); qr(s, 1, 5, 9, 13); qr(s, 2, 6, 10, 14); qr(s, 3, 7, 11, 15)
                qr(s, 0, 5, 10, 15); qr(s, 1, 6, 11, 12); qr(s, 2, 7, 8, 13); qr(s, 3, 4, 9, 14)
            }
            val out = ByteArray(32)
            for (i in 0 until 4) putLe32(out, 4 * i, s[i])
            for (i in 0 until 4) putLe32(out, 16 + 4 * i, s[12 + i])
            return out
        }

        private fun qr(s: IntArray, a: Int, b: Int, c: Int, d: Int) {
            s[a] += s[b]; s[d] = Integer.rotateLeft(s[d] xor s[a], 16)
            s[c] += s[d]; s[b] = Integer.rotateLeft(s[b] xor s[c], 12)
            s[a] += s[b]; s[d] = Integer.rotateLeft(s[d] xor s[a], 8)
            s[c] += s[d]; s[b] = Integer.rotateLeft(s[b] xor s[c], 7)
        }

        private fun le32(b: ByteArray, o: Int) = (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8) or
            ((b[o + 2].toInt() and 0xFF) shl 16) or ((b[o + 3].toInt() and 0xFF) shl 24)

        private fun putLe32(b: ByteArray, o: Int, v: Int) {
            b[o] = v.toByte(); b[o + 1] = (v ushr 8).toByte(); b[o + 2] = (v ushr 16).toByte(); b[o + 3] = (v ushr 24).toByte()
        }
    }
}

/**
 * xsalsa20_poly1305_lite_rtpsize (NaCl secretbox, 24 byte nonce = 32 bit big-endian counter then zeros, no AAD).
 * Retired by Discord's servers but still understood by Discord 126.21's engine; only offered for the local leg.
 */
class XSalsaLiteRtpSize(private val key: ByteArray, rtpsizeHeader: Boolean = true) : TransportCipher(rtpsizeHeader) {
    private val salsa = XSalsa20Engine()
    private val mac = Poly1305()

    private fun start(nonce4: ByteArray): ByteArray {
        val nonce = ByteArray(24)
        System.arraycopy(nonce4, 0, nonce, 0, 4)
        salsa.init(true, ParametersWithIV(KeyParameter(key), nonce))
        val polyKey = ByteArray(32)
        salsa.processBytes(ByteArray(32), 0, 32, polyKey, 0)
        mac.init(KeyParameter(polyKey))
        return polyKey
    }

    override fun encrypt(header: ByteArray, plaintext: ByteArray, nonce4: ByteArray): ByteArray {
        start(nonce4)
        val out = ByteArray(16 + plaintext.size)
        salsa.processBytes(plaintext, 0, plaintext.size, out, 16)
        mac.update(out, 16, plaintext.size)
        mac.doFinal(out, 0)
        return out
    }

    override fun decrypt(header: ByteArray, ciphertext: ByteArray, nonce4: ByteArray): ByteArray? {
        if (ciphertext.size < 16) return null
        start(nonce4)
        mac.update(ciphertext, 16, ciphertext.size - 16)
        val tag = ByteArray(16)
        mac.doFinal(tag, 0)
        if (!Bytes.ctEquals(tag, 0, ciphertext, 0, 16)) return null
        val out = ByteArray(ciphertext.size - 16)
        salsa.processBytes(ciphertext, 16, out.size, out, 0)
        return out
    }
}
