package moe.lava.awoocord.voicee2ee.core

/** VP8 RTP payload descriptor (RFC 7741 section 4.2). */
internal object Vp8 {
    /** Descriptor length at the start of a VP8 RTP payload, or -1 when malformed. */
    fun descriptorSize(p: ByteArray): Int {
        if (p.isEmpty()) return -1
        var n = 1
        if (p[0].toInt() and 0x80 != 0) { // X
            if (p.size < 2) return -1
            val x = p[1].toInt()
            n = 2
            if (x and 0x80 != 0) { // I: picture id, 7 or 15 bits
                if (p.size <= n) return -1
                n += if (p[n].toInt() and 0x80 != 0) 2 else 1
            }
            if (x and 0x40 != 0) n++ // L: TL0PICIDX
            if (x and 0x30 != 0) n++ // T or K: TID/Y/KEYIDX
        }
        return if (n <= p.size) n else -1
    }

    /** S bit set and partition index 0: first packet of a frame. */
    fun isFrameStart(p: ByteArray) = p.isNotEmpty() && (p[0].toInt() and 0x10) != 0 && (p[0].toInt() and 0x07) == 0
}

/** One decrypted (transport-wise) RTP packet split into its parts. */
internal class RtpParts(
    /** Clear header (fixed + CSRC + extension header), padding bit cleared. */
    val header: ByteArray,
    /** Header extension body (encrypted on the wire in rtpsize modes). */
    val extBody: ByteArray,
    /** RTP payload without padding. */
    val payload: ByteArray,
) {
    val seq: Int get() = Rtp.seq(header)
    val marker: Boolean get() = Rtp.marker(header)
    val timestamp: Long get() = Rtp.timestamp(header)
    val ssrc: Long get() = Rtp.ssrc(header)

    fun toPlainPacket(newPayload: ByteArray = payload): ByteArray = Bytes.concat(header, extBody, newPayload)

    companion object {
        /** Splits a packet as returned by [TransportCipher.open]. */
        fun parse(plain: ByteArray): RtpParts? {
            val hdr = Rtp.rtpsizeHeaderLen(plain, plain.size)
            if (hdr < 0) return null
            val ext = Rtp.extensionBodyLen(plain)
            var end = plain.size
            if (Rtp.hasPadding(plain)) {
                val pad = plain[end - 1].toInt() and 0xFF
                if (pad == 0 || hdr + ext + pad > end) return null
                end -= pad
            }
            if (hdr + ext > end) return null
            val header = plain.copyOfRange(0, hdr)
            header[0] = (header[0].toInt() and 0x20.inv()).toByte()
            return RtpParts(header, plain.copyOfRange(hdr, hdr + ext), plain.copyOfRange(hdr + ext, end))
        }

        fun withSeqAndPayloadType(header: ByteArray, seq: Int, pt: Int, ssrc: Long): ByteArray {
            val h = header.clone()
            h[1] = ((h[1].toInt() and 0x80) or (pt and 0x7F)).toByte()
            Bytes.putU16(h, 2, seq)
            Bytes.putU32(h, 8, ssrc)
            return h
        }
    }
}

private fun seqDiff(a: Int, b: Int): Int = ((a - b + 0x8000) and 0xFFFF) - 0x8000

/**
 * Outgoing VP8: the engine packetises unencrypted frames, so packets are collected until the frame's last packet
 * (marker bit), the frame (concatenated payloads after the descriptors) is DAVE-encrypted in place and the protocol
 * footer appended to the last packet. Encrypted payloads are kept so the engine's RTX retransmissions can be served.
 */
internal class OutgoingVideo(private val encrypt: (ByteArray) -> ByteArray?) {
    private class Pending(val parts: RtpParts, val descriptor: Int)

    private val frames = HashMap<Long, MutableList<Pending>>() // ssrc -> current frame
    private val rtxCache = HashMap<Long, LinkedHashMap<Int, ByteArray>>() // ssrc -> seq -> encrypted payload

    /** Returns the plain packets to send now (possibly none while a frame is being collected). */
    fun onPacket(p: RtpParts): List<ByteArray> {
        val d = Vp8.descriptorSize(p.payload)
        if (d < 0) return emptyList()
        val list = frames.getOrPut(p.ssrc) { ArrayList() }
        val out = ArrayList<ByteArray>()
        if (list.isNotEmpty() && list[0].parts.timestamp != p.timestamp) {
            out += flush(p.ssrc, list) // missed marker: close the previous frame
        }
        list.add(Pending(p, d))
        if (p.marker) out += flush(p.ssrc, list)
        return out
    }

    private fun flush(ssrc: Long, list: MutableList<Pending>): List<ByteArray> {
        val packets = list.sortedWith(Comparator { a, b -> seqDiff(a.parts.seq, b.parts.seq) })
        list.clear()
        val frameLen = packets.sumOf { it.parts.payload.size - it.descriptor }
        val frame = ByteArray(frameLen)
        var o = 0
        for (pk in packets) {
            val n = pk.parts.payload.size - pk.descriptor
            System.arraycopy(pk.parts.payload, pk.descriptor, frame, o, n)
            o += n
        }
        val sealed = encrypt(frame) ?: return emptyList()
        val cache = rtxCache.getOrPut(ssrc) { LinkedHashMap() }
        val out = ArrayList<ByteArray>(packets.size)
        o = 0
        for ((i, pk) in packets.withIndex()) {
            val n = pk.parts.payload.size - pk.descriptor
            val take = if (i == packets.size - 1) sealed.size - o else n // footer goes on the last packet
            val payload = ByteArray(pk.descriptor + take)
            System.arraycopy(pk.parts.payload, 0, payload, 0, pk.descriptor)
            System.arraycopy(sealed, o, payload, pk.descriptor, take)
            o += take
            cache[pk.parts.seq] = payload
            out += pk.parts.toPlainPacket(payload)
        }
        while (cache.size > RTX_CACHE) cache.remove(cache.keys.first())
        return out
    }

    /** RTX payload = original sequence number + original payload; swaps in the encrypted payload. */
    fun onRtx(p: RtpParts, mediaSsrc: Long): ByteArray? {
        if (p.payload.size < 2) return null
        val osn = Bytes.u16(p.payload, 0)
        val enc = rtxCache[mediaSsrc]?.get(osn) ?: return null
        val payload = ByteArray(2 + enc.size)
        System.arraycopy(p.payload, 0, payload, 0, 2)
        System.arraycopy(enc, 0, payload, 2, enc.size)
        return p.toPlainPacket(payload)
    }

    companion object {
        private const val RTX_CACHE = 1024
    }
}

/**
 * Incoming VP8: the DAVE frame spans packets with the footer at its end, so packets are held until the frame is
 * complete (start packet .. marker packet, no gaps), decrypted as a whole and handed to the engine with the plaintext
 * spread back over the same packets (same sequence numbers, the footer bytes removed).
 * RTX retransmissions are turned back into the original packets so lost packets can complete a frame.
 */
internal class IncomingVideo(
    private val clock: Clock,
    /** Decrypts a whole frame for the sender of [ssrc]; returns the plaintext or null to drop it. */
    private val decrypt: (ssrc: Long, frame: ByteArray) -> ByteArray?,
) {
    private class Frame(val created: Long) {
        val packets = HashMap<Int, RtpParts>()
    }

    private class Stream {
        val frames = HashMap<Long, Frame>() // rtp timestamp -> frame
        val delivered = LinkedHashSet<Int>()
    }

    private val streams = HashMap<Long, Stream>()

    /** Returns plain packets ready for the engine. */
    fun onPacket(p: RtpParts): List<ByteArray> {
        val s = streams.getOrPut(p.ssrc) { Stream() }
        if (p.seq in s.delivered) return emptyList()
        val now = clock.nowMs()
        s.frames.entries.removeAll { now - it.value.created > FRAME_TIMEOUT_MS }
        val f = s.frames.getOrPut(p.timestamp) { Frame(now) }
        f.packets[p.seq] = p
        return tryComplete(p.ssrc, s, p.timestamp, f)
    }

    private fun tryComplete(ssrc: Long, s: Stream, ts: Long, f: Frame): List<ByteArray> {
        val start = f.packets.values.firstOrNull { Vp8.isFrameStart(it.payload) } ?: return emptyList()
        val end = f.packets.values.firstOrNull { it.marker } ?: return emptyList()
        val count = seqDiff(end.seq, start.seq) + 1
        if (count <= 0 || count > MAX_PACKETS) return emptyList()
        val ordered = ArrayList<RtpParts>(count)
        for (i in 0 until count) ordered += f.packets[(start.seq + i) and 0xFFFF] ?: return emptyList()
        s.frames.remove(ts)
        for (pk in ordered) {
            s.delivered.add(pk.seq)
            if (s.delivered.size > DELIVERED_MEMORY) s.delivered.remove(s.delivered.first())
        }

        val desc = IntArray(count) { Vp8.descriptorSize(ordered[it].payload) }
        if (desc.any { it < 0 }) return emptyList()
        val sizes = IntArray(count) { ordered[it].payload.size - desc[it] }
        val total = sizes.sum()
        val frame = ByteArray(total)
        var o = 0
        for (i in 0 until count) {
            System.arraycopy(ordered[i].payload, desc[i], frame, o, sizes[i])
            o += sizes[i]
        }
        val plain = decrypt(ssrc, frame) ?: return emptyList()
        // Shrink from the end (the footer is gone) keeping at least one byte per packet, then refill in order.
        var excess = total - plain.size
        if (excess < 0 || plain.size < count) return emptyList()
        var i = count - 1
        while (excess > 0 && i >= 0) {
            val take = minOf(excess, sizes[i] - 1)
            if (take > 0) {
                sizes[i] -= take
                excess -= take
            }
            i--
        }
        if (excess > 0) return emptyList()
        val out = ArrayList<ByteArray>(count)
        o = 0
        for (k in 0 until count) {
            val payload = ByteArray(desc[k] + sizes[k])
            System.arraycopy(ordered[k].payload, 0, payload, 0, desc[k])
            System.arraycopy(plain, o, payload, desc[k], sizes[k])
            o += sizes[k]
            out += ordered[k].toPlainPacket(payload)
        }
        return out
    }

    /** Converts an RTX packet back into the original packet of [mediaSsrc]/[mediaPt] and feeds it in. */
    fun onRtx(p: RtpParts, mediaSsrc: Long, mediaPt: Int): List<ByteArray> {
        if (p.payload.size < 2) return emptyList()
        val osn = Bytes.u16(p.payload, 0)
        val header = RtpParts.withSeqAndPayloadType(p.header, osn, mediaPt, mediaSsrc)
        return onPacket(RtpParts(header, p.extBody, p.payload.copyOfRange(2, p.payload.size)))
    }

    companion object {
        private const val FRAME_TIMEOUT_MS = 2_000L
        private const val MAX_PACKETS = 2048
        private const val DELIVERED_MEMORY = 2048
    }
}
