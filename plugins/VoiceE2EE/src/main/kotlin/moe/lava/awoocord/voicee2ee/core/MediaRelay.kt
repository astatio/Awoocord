package moe.lava.awoocord.voicee2ee.core

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/** SSRC / payload type bookkeeping for one voice connection. All members are safe to use from any thread. */
class SsrcMap {
    @Volatile var ownAudioSsrc = -1L

    /** own video ssrc -> its rtx ssrc */
    val ownVideo = ConcurrentHashMap<Long, Long>()
    /** remote ssrc (audio, video or rtx) -> user id */
    val users = ConcurrentHashMap<Long, Long>()
    /** remote rtx ssrc -> media ssrc */
    val rtxToMedia = ConcurrentHashMap<Long, Long>()

    @Volatile var opusPt = 120
    @Volatile var vp8Pt = -1
    @Volatile var vp8RtxPt = -1

    fun ownRtxMedia(rtxSsrc: Long): Long? = ownVideo.entries.firstOrNull { it.value == rtxSsrc }?.key
}

/**
 * Local UDP relay in front of Discord 126.21's native voice engine, which predates DAVE.
 *
 * The engine is pointed at 127.0.0.1:[localPort] and given a throwaway key for [localMode]. Every RTP/RTCP packet is
 * opened with that key, media frames get DAVE frame encryption added (outgoing) or removed (incoming), and the packet
 * is sealed again with the real transport key for Discord's media server, and vice versa. Anything else (IP discovery)
 * is forwarded untouched, so the server reports the relay's public address, which is the one it sees.
 */
class MediaRelay(
    serverHost: String,
    serverPort: Int,
    private val dave: DaveProtocol,
    val ssrcs: SsrcMap,
    val localMode: String,
    private val log: (String) -> Unit,
    private val clock: Clock = Clock.SYSTEM,
    threadFactory: (String, Runnable) -> Thread = { name, r -> Thread(r, name) },
) {
    private val server: SocketAddress = InetSocketAddress(InetAddress.getByName(serverHost), serverPort)
    private val localSocket = DatagramSocket(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
    private val remoteSocket = DatagramSocket()

    val localPort: Int get() = localSocket.localPort

    /** Throwaway key the engine uses towards the relay. */
    val localKey: ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    @Volatile private var engine: SocketAddress? = null
    @Volatile private var serverMode: String? = null
    @Volatile private var serverKey: ByteArray? = null
    @Volatile private var serverGeneration = 0
    @Volatile var closed = false
        private set

    // Engine-side layout: see TransportCipher.localVariants. Index == variants.size means "no encryption".
    private val variantNames = TransportCipher.localVariants(localMode, localKey).map { it.first } + "unencrypted"
    @Volatile private var localVariant = 0
    @Volatile private var localGeneration = 0
    @Volatile private var variantSettled = false
    private var plainLooking = 0
    val localLayout: String get() = variantNames[localVariant] + if (variantSettled) "" else " (unconfirmed)"

    private fun localCipher(variant: Int): TransportCipher =
        if (variant >= variantNames.size - 1) PlainTransport() else TransportCipher.localVariants(localMode, localKey)[variant].second

    // stats for /voicee2ee
    @Volatile var sentFrames = 0L; private set
    @Volatile var droppedSendFrames = 0L; private set
    @Volatile var receivedFrames = 0L; private set
    @Volatile var failedReceiveFrames = 0L; private set
    @Volatile var enginePackets = 0L; private set
    @Volatile var engineUnreadable = 0L; private set
    @Volatile var toServer = 0L; private set
    @Volatile var serverPackets = 0L; private set
    @Volatile var serverUnreadable = 0L; private set
    @Volatile var toEngine = 0L; private set
    @Volatile var beforeKey = 0L; private set
    @Volatile var unknownPayloadType = -1; private set

    private val outVideo = OutgoingVideo { frame -> dave.encryptor.encrypt(Codec.VP8, frame) }
    private val inVideo = IncomingVideo(clock) { ssrc, frame -> decryptFrame(ssrc, false, frame) }

    private val upThread = threadFactory("VoiceE2EE-up") { pump(true) }
    private val downThread = threadFactory("VoiceE2EE-down") { pump(false) }

    init {
        upThread.isDaemon = true
        downThread.isDaemon = true
        upThread.start()
        downThread.start()
    }

    /** Transport mode and key from the session description, for the leg towards Discord. */
    fun setServerKey(mode: String, key: ByteArray) {
        serverMode = mode
        serverKey = key.clone()
        serverGeneration++
        log("server transport: $mode, engine transport: $localMode")
    }

    fun close() {
        closed = true
        localSocket.close()
        remoteSocket.close()
    }

    private fun pump(up: Boolean) {
        val inSocket = if (up) localSocket else remoteSocket
        val outSocket = if (up) remoteSocket else localSocket
        val buf = ByteArray(4096)
        val packet = DatagramPacket(buf, buf.size)
        var local: TransportCipher? = null
        var remote: TransportCipher? = null
        var seenLocal = -1
        var seenServer = -1
        while (!closed) {
            try {
                packet.setData(buf, 0, buf.size)
                inSocket.receive(packet)
                val len = packet.length
                if (up) {
                    engine = packet.socketAddress
                } else if (packet.socketAddress != server) {
                    continue
                }
                val target = (if (up) server else engine) ?: continue

                if (!Rtp.isRtpOrRtcp(buf, len)) { // IP discovery etc.
                    outSocket.send(DatagramPacket(buf, 0, len, target))
                    continue
                }
                if (up) enginePackets++ else serverPackets++
                if (seenServer != serverGeneration) {
                    val key = serverKey
                    val mode = serverMode
                    if (key == null || mode == null) { // nothing can be relayed before the session description
                        beforeKey++
                        continue
                    }
                    remote = TransportCipher.create(mode, key) ?: run {
                        log("unsupported server transport mode $mode")
                        null
                    }
                    seenServer = serverGeneration
                }
                if (seenLocal != localGeneration) {
                    val next = localCipher(localVariant)
                    local?.let { next.counter = it.counter } // never reuse a nonce under the local key
                    local = next
                    seenLocal = localGeneration
                }
                val r = remote ?: continue
                val l = local!!
                val opener = if (up) l else r
                val sealer = if (up) r else l

                var plain = opener.open(buf, len)
                if (plain == null) {
                    if (up) {
                        engineUnreadable++
                        if (engineUnreadable <= 5) log("unreadable engine packet: ${len}B ${Bytes.hex(buf, 16)}")
                        plain = probeEngineLayout(buf, len)
                    } else {
                        serverUnreadable++
                        if (serverUnreadable <= 5) log("unreadable server packet: ${len}B ${Bytes.hex(buf, 16)}")
                    }
                    if (plain == null) continue
                } else if (up && !variantSettled) {
                    variantSettled = true
                    log("engine transport layout: ${variantNames[localVariant]}")
                }
                val outPackets = if (Rtp.isRtcp(plain)) listOf(plain) else if (up) outgoing(plain) else incoming(plain)
                for (p in outPackets) {
                    val wire = sealer.seal(p)
                    outSocket.send(DatagramPacket(wire, wire.size, target))
                    if (up) toServer++ else toEngine++
                }
            } catch (e: Exception) {
                if (!closed) log("relay ${if (up) "up" else "down"}: $e")
            }
        }
    }

    /**
     * The engine's packet didn't open with the layout in use: try the other layouts it might use. An authenticated
     * open is conclusive and switches both directions; "unencrypted" is only assumed after many packets that open
     * with nothing but look like plain RTP/RTCP from this engine.
     */
    private fun probeEngineLayout(buf: ByteArray, len: Int): ByteArray? {
        if (variantSettled) return null
        val variants = TransportCipher.localVariants(localMode, localKey)
        for ((i, v) in variants.withIndex()) {
            if (i == localVariant) continue
            val plain = v.second.open(buf, len) ?: continue
            switchLayout(i)
            return plain
        }
        val looksPlain = Rtp.isRtcp(buf) || Rtp.payloadType(buf) == ssrcs.opusPt || Rtp.ssrc(buf) == ssrcs.ownAudioSsrc ||
            ssrcs.ownVideo.containsKey(Rtp.ssrc(buf))
        if (looksPlain && ++plainLooking >= PLAIN_EVIDENCE) {
            switchLayout(variantNames.size - 1)
            return buf.copyOf(len)
        }
        return null
    }

    private fun switchLayout(variant: Int) {
        localVariant = variant
        variantSettled = true
        localGeneration++
        log("engine transport layout detected: ${variantNames[variant]}")
    }

    // region outgoing (engine -> Discord)

    private fun outgoing(plain: ByteArray): List<ByteArray> {
        val parts = RtpParts.parse(plain) ?: return emptyList()
        val pt = Rtp.payloadType(parts.header)
        val ssrc = parts.ssrc
        return when {
            pt == ssrcs.opusPt || ssrc == ssrcs.ownAudioSsrc -> {
                if (ProtocolFrame.isOpusSilence(parts.payload)) return listOf(parts.toPlainPacket())
                val sealed = dave.encryptor.encrypt(Codec.OPUS, parts.payload)
                if (sealed == null) {
                    droppedSendFrames++
                    emptyList()
                } else {
                    sentFrames++
                    listOf(parts.toPlainPacket(sealed))
                }
            }
            pt == ssrcs.vp8RtxPt -> {
                val media = ssrcs.ownRtxMedia(ssrc) ?: return emptyList()
                synchronized(outVideo) { listOfNotNull(outVideo.onRtx(parts, media)) }
            }
            pt == ssrcs.vp8Pt -> synchronized(outVideo) { outVideo.onPacket(parts) }.also { sentFrames += if (it.isEmpty()) 0 else 1 }
            else -> {
                unknownPayloadType = pt
                emptyList() // never let an unencrypted media frame of an unknown codec out
            }
        }
    }

    // endregion

    // region incoming (Discord -> engine)

    private fun incoming(plain: ByteArray): List<ByteArray> {
        val parts = RtpParts.parse(plain) ?: return emptyList()
        val pt = Rtp.payloadType(parts.header)
        return when {
            pt == ssrcs.opusPt -> {
                val out = decryptFrame(parts.ssrc, true, parts.payload) ?: return emptyList()
                listOf(parts.toPlainPacket(out))
            }
            pt == ssrcs.vp8RtxPt -> {
                val media = ssrcs.rtxToMedia[parts.ssrc] ?: return emptyList()
                inVideo.onRtx(parts, media, ssrcs.vp8Pt)
            }
            pt == ssrcs.vp8Pt -> inVideo.onPacket(parts)
            else -> emptyList()
        }
    }

    private fun decryptFrame(ssrc: Long, audio: Boolean, frame: ByteArray): ByteArray? {
        val user = ssrcs.users[ssrc] ?: return null // not mapped to a user yet (speaking/video event pending)
        val d = dave.decryptor(user)
        val r = d.decrypt(audio, frame)
        return when (r) {
            FrameDecryptor.Result.OK, FrameDecryptor.Result.PASSTHROUGH -> {
                receivedFrames++
                if (r == FrameDecryptor.Result.OK) dave.reportDecryptSuccess()
                d.output
            }
            else -> {
                failedReceiveFrames++
                if (r == FrameDecryptor.Result.FAILED || r == FrameDecryptor.Result.NO_KEY) dave.reportDecryptFailure()
                null
            }
        }
    }

    // endregion

    companion object {
        private const val PLAIN_EVIDENCE = 25
    }
}
