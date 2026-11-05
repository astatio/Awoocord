package moe.lava.awoocord.voicee2ee.core

import java.io.ByteArrayOutputStream
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * HKDF-SHA256 "ExpandWithLabel" from RFC 9420 section 8, using the platform HMAC (hardware/BoringSSL backed on
 * Android) instead of BouncyCastle so the per-frame media path never touches the bundled pure-Java crypto.
 */
internal object MlsKdf {
    private const val HASH_LEN = 32

    fun expandWithLabel(secret: ByteArray, label: String, context: ByteArray, length: Int): ByteArray {
        val info = ByteArrayOutputStream()
        info.write(length ushr 8)
        info.write(length)
        writeOpaque(info, ("MLS 1.0 $label").toByteArray(Charsets.US_ASCII))
        writeOpaque(info, context)
        return hkdfExpand(secret, info.toByteArray(), length)
    }

    /** RFC 9420 DeriveTreeSecret: the generation is a big-endian uint32 context. */
    fun deriveTreeSecret(secret: ByteArray, label: String, generation: Long, length: Int): ByteArray {
        val ctx = ByteArray(4)
        Bytes.putU32(ctx, 0, generation)
        return expandWithLabel(secret, label, ctx, length)
    }

    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val out = ByteArray(length)
        var t = ByteArray(0)
        var pos = 0
        var counter = 1
        while (pos < length) {
            mac.update(t)
            mac.update(info)
            mac.update(counter.toByte())
            t = mac.doFinal()
            val n = minOf(HASH_LEN, length - pos)
            System.arraycopy(t, 0, out, pos, n)
            pos += n
            counter++
        }
        return out
    }

    /** MLS variable-size vector header (RFC 9420 section 2.1.2) followed by the bytes. */
    private fun writeOpaque(out: ByteArrayOutputStream, data: ByteArray) {
        val n = data.size
        when {
            n < 0x40 -> out.write(n)
            n < 0x4000 -> {
                out.write(0x40 or (n ushr 8))
                out.write(n)
            }
            else -> {
                out.write(0x80 or (n ushr 24))
                out.write(n ushr 16)
                out.write(n ushr 8)
                out.write(n)
            }
        }
        out.write(data)
    }
}

/**
 * Per-sender media key ratchet (DAVE "Sender Key Derivation"): the MLS AEAD hash ratchet of RFC 9420 section 9.1
 * seeded with the exported per-sender base secret. Generations below the newest derived one are only available while
 * cached; [erase] drops them for good.
 */
class KeyRatchet(baseSecret: ByteArray) {
    /** Identifies the key domain (epoch + sender) so a reinstall of the same ratchet can be recognised. */
    val domainIdentity: ByteArray = baseSecret.clone()

    private var nextSecret: ByteArray = baseSecret.clone()
    private var nextGeneration = 0L
    private val cache = HashMap<Long, ByteArray>()

    @Synchronized
    fun get(generation: Long): ByteArray? {
        cache[generation]?.let { return it }
        if (generation < nextGeneration) return null // erased
        while (nextGeneration <= generation) {
            val g = nextGeneration
            cache[g] = MlsKdf.deriveTreeSecret(nextSecret, "key", g, KEY_BYTES)
            nextSecret = MlsKdf.deriveTreeSecret(nextSecret, "secret", g, SECRET_BYTES)
            nextGeneration++
        }
        return cache[generation]
    }

    @Synchronized
    fun erase(generation: Long) {
        cache.remove(generation)
    }

    companion object {
        const val KEY_BYTES = 16
        private const val SECRET_BYTES = 32 // SHA-256 output size of MLS ciphersuite 2
    }
}

/**
 * AES-128-GCM with the 64-bit truncated tag DAVE uses for media frames.
 *
 * javax.crypto providers (SunJCE, Conscrypt) don't accept 64-bit GCM tags, so:
 *  - encrypt is plain GCM with a 128-bit tag, truncated to its first 8 bytes (a truncated GCM tag is exactly that);
 *  - decrypt runs AES-CTR from counter block 2 (GCM's keystream) and recomputes the tag by re-encrypting the
 *    recovered plaintext; the plaintext is only handed out when the first 8 tag bytes match (constant time).
 * Both are hardware accelerated through the platform provider. Not thread safe; one instance per user of it.
 */
class AesGcm64(key: ByteArray) {
    private val keySpec = SecretKeySpec(key, "AES")
    private var gcm: Cipher = Cipher.getInstance("AES/GCM/NoPadding")
    private val ctr: Cipher = Cipher.getInstance("AES/CTR/NoPadding")
    private val ctrIv = ByteArray(16)

    /** Returns ciphertext (same length as [plaintext]); the 8 byte tag is written to [tagOut] at [tagOff]. */
    fun encrypt(nonce: ByteArray, plaintext: ByteArray, aad: ByteArray, tagOut: ByteArray, tagOff: Int): ByteArray {
        val full = gcmEncrypt(nonce, plaintext, aad)
        System.arraycopy(full, plaintext.size, tagOut, tagOff, TAG_BYTES)
        return full.copyOf(plaintext.size)
    }

    /** Returns the plaintext, or null when authentication fails. */
    fun decrypt(nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray, tag: ByteArray, tagOff: Int): ByteArray? {
        System.arraycopy(nonce, 0, ctrIv, 0, 12)
        ctrIv[12] = 0; ctrIv[13] = 0; ctrIv[14] = 0; ctrIv[15] = 2
        ctr.init(Cipher.ENCRYPT_MODE, keySpec, IvParameterSpec(ctrIv))
        val plaintext = ctr.doFinal(ciphertext)
        val full = gcmEncrypt(nonce, plaintext, aad)
        return if (Bytes.ctEquals(full, plaintext.size, tag, tagOff, TAG_BYTES)) plaintext else null
    }

    private fun gcmEncrypt(nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        return try {
            gcm.init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(128, nonce))
            if (aad.isNotEmpty()) gcm.updateAAD(aad)
            gcm.doFinal(plaintext)
        } catch (e: java.security.InvalidAlgorithmParameterException) {
            // SunJCE refuses re-initialising with the key/IV pair it was last used with (only reachable when a
            // frame is verified twice); a fresh instance has no such history.
            gcm = Cipher.getInstance("AES/GCM/NoPadding")
            gcm.init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(128, nonce))
            if (aad.isNotEmpty()) gcm.updateAAD(aad)
            gcm.doFinal(plaintext)
        }
    }

    companion object {
        const val TAG_BYTES = 8
    }
}
