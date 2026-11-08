package moe.lava.awoocord.voicee2ee

import moe.lava.awoocord.voicee2ee.core.DaveGateway
import moe.lava.awoocord.voicee2ee.core.DaveProtocol
import moe.lava.awoocord.voicee2ee.core.MediaRelay
import moe.lava.awoocord.voicee2ee.core.SsrcMap
import moe.lava.awoocord.voicee2ee.core.TransportCipher
import okhttp3.WebSocket
import okio.ByteString
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Voice gateway v8 + DAVE state for one voice websocket (b.a.q.n0.a, "RtcControlSocket") of Discord 126.21.
 *
 * The app's own socket code stays in charge; this class rewrites what crosses it (v5 -> v8 differences, DAVE fields)
 * and handles the opcodes the app doesn't know (DAVE JSON 21-24/31 and binary 25-30).
 */
internal class VoiceSession(
    private val socket: Any,
    val userId: Long,
    val channelId: Long,
    val isStream: Boolean,
    private val localMode: () -> String,
    private val logger: (String) -> Unit,
) : DaveGateway {
    private val executor: ExecutorService = Executors.newSingleThreadExecutor { r ->
        Thread(r, "VoiceE2EE-gateway").apply { isDaemon = true }
    }

    val ssrcs = SsrcMap()

    @Volatile var dave = newDave()
        private set

    @Volatile var relay: MediaRelay? = null
        private set

    /** Last sequence number received (voice gateway v8 buffered resume / seq_ack). */
    @Volatile var seq = -1
        private set

    @Volatile private var serverModes: List<String> = emptyList()
    @Volatile var serverMode = TransportCipher.AES256_GCM
        private set

    @Volatile var closed = false
        private set

    private fun newDave() = DaveProtocol(userId, channelId, this, { log("[dave] $it") }, onGatewayThread = { r ->
        post("recovery") { r.run() }
    })

    fun log(msg: String) = logger("[${if (isStream) "stream" else "voice"} $channelId] $msg")

    private fun post(what: String, block: () -> Unit) {
        if (closed) return
        executor.execute {
            try {
                block()
            } catch (e: Throwable) {
                log("$what failed: $e")
            }
        }
    }

    // region incoming

    /** Returns the text the app should see, or null to hide the message from it. */
    fun onIncomingText(text: String): String? {
        val msg = try {
            JSONObject(text)
        } catch (e: Exception) {
            return text
        }
        if (msg.has("seq")) seq = msg.optInt("seq", seq)
        val op = msg.optInt("op", -1)
        val d = msg.opt("d")
        when (op) {
            OP_READY -> if (d is JSONObject) onReadyPayload(d)
            OP_SESSION_DESCRIPTION -> if (d is JSONObject) {
                val version = d.optInt("dave_protocol_version", 0)
                log("session description: mode ${d.optString("mode")}, DAVE v$version")
                post("session description") { dave.onSessionDescription(version) }
            }
            OP_SPEAKING -> if (d is JSONObject) {
                val uid = d.optString("user_id").toLongOrNull()
                if (uid != null && d.has("ssrc")) ssrcs.users[d.optLong("ssrc")] = uid
            }
            OP_HEARTBEAT_ACK -> if (d is JSONObject) {
                // v8 acks with {"t": nonce}; the app parses d as the nonce (a Long)
                msg.put("d", d.optLong("t"))
                return msg.toString()
            }
            OP_HELLO -> if (d is JSONObject) {
                // the app parses this as a long; v8 can send a fractional interval
                d.put("heartbeat_interval", d.optDouble("heartbeat_interval", 13750.0).toLong())
                return msg.toString()
            }
            OP_CLIENTS_CONNECT -> if (d is JSONObject) {
                val ids = d.optJSONArray("user_ids")
                val list = ArrayList<Long>()
                for (i in 0 until (ids?.length() ?: 0)) ids!!.optString(i).toLongOrNull()?.let { list.add(it) }
                post("clients connect") { dave.onClientsConnect(list) }
                return null
            }
            OP_VIDEO -> if (d is JSONObject) onVideoPayload(d)
            OP_CLIENT_DISCONNECT -> if (d is JSONObject) {
                val uid = d.optString("user_id").toLongOrNull()
                if (uid != null) {
                    ssrcs.users.entries.removeAll { it.value == uid }
                    post("client disconnect") { dave.onClientDisconnect(uid) }
                }
            }
            OP_DAVE_PREPARE_TRANSITION -> {
                val o = d as? JSONObject ?: return null
                post("prepare transition") { dave.onPrepareTransition(o.optInt("transition_id"), o.optInt("protocol_version")) }
                return null
            }
            OP_DAVE_EXECUTE_TRANSITION -> {
                val o = d as? JSONObject ?: return null
                post("execute transition") { dave.onExecuteTransition(o.optInt("transition_id")) }
                return null
            }
            OP_DAVE_PREPARE_EPOCH -> {
                val o = d as? JSONObject ?: return null
                post("prepare epoch") { dave.onPrepareEpoch(o.optLong("epoch"), o.optInt("protocol_version")) }
                return null
            }
            in 15..40 -> if (op != OP_MEDIA_SINK_WANTS && op != OP_SESSION_UPDATE) return null // unknown to the app
        }
        return text
    }

    fun onIncomingBinary(bytes: ByteArray) {
        if (bytes.size < 3) return
        seq = ((bytes[0].toInt() and 0xFF) shl 8) or (bytes[1].toInt() and 0xFF)
        val op = bytes[2].toInt() and 0xFF
        val payload = bytes.copyOfRange(3, bytes.size)
        when (op) {
            OP_MLS_EXTERNAL_SENDER -> post("external sender") { dave.onExternalSender(payload) }
            OP_MLS_PROPOSALS -> post("proposals") { dave.onProposals(payload) }
            OP_MLS_ANNOUNCE_COMMIT -> post("commit") { dave.onAnnounceCommit(payload) }
            OP_MLS_WELCOME -> post("welcome") { dave.onWelcome(payload) }
            else -> log("unknown binary opcode $op")
        }
    }

    private fun onReadyPayload(d: JSONObject) {
        ssrcs.ownAudioSsrc = d.optLong("ssrc", -1)
        ssrcs.ownVideo.clear()
        val streams = d.optJSONArray("streams")
        for (i in 0 until (streams?.length() ?: 0)) {
            val s = streams!!.optJSONObject(i) ?: continue
            if (s.has("ssrc")) ssrcs.ownVideo[s.optLong("ssrc")] = s.optLong("rtx_ssrc", -1)
        }
        val modes = d.optJSONArray("modes")
        serverModes = (0 until (modes?.length() ?: 0)).map { modes!!.optString(it) }
        serverMode = when {
            TransportCipher.AES256_GCM in serverModes -> TransportCipher.AES256_GCM
            TransportCipher.XCHACHA20 in serverModes -> TransportCipher.XCHACHA20
            else -> TransportCipher.AES256_GCM
        }
        log("ready: ssrc ${ssrcs.ownAudioSsrc}, server modes $serverModes -> $serverMode")
    }

    private fun onVideoPayload(d: JSONObject) {
        val uid = d.optString("user_id").toLongOrNull() ?: return
        fun map(ssrc: Long, rtx: Long) {
            if (ssrc > 0) ssrcs.users[ssrc] = uid
            if (rtx > 0) {
                ssrcs.users[rtx] = uid
                if (ssrc > 0) ssrcs.rtxToMedia[rtx] = ssrc
            }
        }
        if (d.optLong("audio_ssrc") > 0) ssrcs.users[d.optLong("audio_ssrc")] = uid
        map(d.optLong("video_ssrc"), d.optLong("rtx_ssrc"))
        val streams = d.optJSONArray("streams")
        for (i in 0 until (streams?.length() ?: 0)) {
            val s = streams!!.optJSONObject(i) ?: continue
            map(s.optLong("ssrc"), s.optLong("rtx_ssrc"))
        }
    }

    // endregion

    // region outgoing

    /** Rewrites the app's outgoing message (as JSON) for voice gateway v8 + DAVE. */
    fun rewriteOutgoing(op: Int, msg: JSONObject): JSONObject {
        when (op) {
            OP_IDENTIFY -> {
                // a fresh session: new DAVE state
                dave = newDave()
                msg.getJSONObject("d").put("max_dave_protocol_version", DaveProtocol.MAX_PROTOCOL_VERSION)
            }
            OP_SELECT_PROTOCOL -> {
                val d = msg.getJSONObject("d")
                d.optJSONObject("data")?.put("mode", serverMode)
                restrictCodecs(d)
            }
            OP_HEARTBEAT -> {
                val nonce = msg.opt("d").toString().toLongOrNull() ?: System.currentTimeMillis()
                msg.put("d", JSONObject().put("t", nonce).put("seq_ack", seq))
            }
            OP_RESUME -> msg.getJSONObject("d").put("seq_ack", seq)
        }
        return msg
    }

    /**
     * Offer only Opus and VP8 (+ its RTX). DAVE needs codec-aware handling of each video codec, and the relay
     * implements VP8; the SFU doesn't transcode, so the call then uses VP8 for everyone.
     */
    private fun restrictCodecs(d: JSONObject) {
        val codecs = d.optJSONArray("codecs") ?: return
        val kept = JSONArray()
        for (i in 0 until codecs.length()) {
            val c = codecs.optJSONObject(i) ?: continue
            val name = c.optString("name")
            when {
                c.optString("type") == "audio" -> {
                    if (name.equals("opus", true)) ssrcs.opusPt = c.optInt("payload_type", 120)
                    kept.put(c)
                }
                name.equals("VP8", true) -> {
                    ssrcs.vp8Pt = c.optInt("payload_type", -1)
                    ssrcs.vp8RtxPt = c.optInt("rtx_payload_type", -1)
                    kept.put(c.put("priority", 1000))
                }
            }
        }
        d.put("codecs", kept)
        log("codecs offered: opus pt ${ssrcs.opusPt}, VP8 pt ${ssrcs.vp8Pt} rtx ${ssrcs.vp8RtxPt}")
    }

    // endregion

    // region media engine

    /** READY reached the engine: start the relay and return where the engine should connect instead. */
    fun startRelay(serverIp: String, serverPort: Int): MediaRelay {
        relay?.close()
        val r = MediaRelay(serverIp, serverPort, dave, ssrcs, localMode(), { log("[relay] $it") }, threadFactory = { name, run ->
            Thread({
                try {
                    android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_URGENT_AUDIO)
                } catch (_: Throwable) {
                }
                run.run()
            }, name)
        })
        relay = r
        log("relay on 127.0.0.1:${r.localPort} for $serverIp:$serverPort")
        return r
    }

    // endregion

    // region DaveGateway

    override fun sendKeyPackage(keyPackage: ByteArray) = sendBinary(OP_MLS_KEY_PACKAGE, keyPackage)

    override fun sendCommitWelcome(commitWelcome: ByteArray) = sendBinary(OP_MLS_COMMIT_WELCOME, commitWelcome)

    override fun sendReadyForTransition(transitionId: Int) =
        sendJson(OP_DAVE_READY_FOR_TRANSITION, JSONObject().put("transition_id", transitionId))

    override fun sendInvalidCommitWelcome(transitionId: Int) =
        sendJson(OP_MLS_INVALID_COMMIT_WELCOME, JSONObject().put("transition_id", transitionId))

    private fun webSocket(): WebSocket? = Reflect.get(socket, "s") as WebSocket?

    private fun sendJson(op: Int, d: JSONObject) {
        val ws = webSocket() ?: return log("can't send op $op: no websocket")
        ws.a(JSONObject().put("op", op).put("d", d).toString())
    }

    /**
     * OkHttp's binary send was inlined away by R8 in 126.21, so queue a binary message the way its text send does:
     * RealWebSocket (f0.e0.n.d) message queue k, queue size l, failed p / closing m flags, then wake the writer (l()).
     */
    private fun sendBinary(op: Int, payload: ByteArray) {
        val ws = webSocket() ?: return log("can't send op $op: no websocket")
        val data = ByteString(ByteArray(payload.size + 1).also {
            it[0] = op.toByte()
            System.arraycopy(payload, 0, it, 1, payload.size)
        })
        synchronized(ws) {
            if (Reflect.get(ws, "p") == true || Reflect.get(ws, "m") == true) return log("can't send op $op: socket closing")
            val queued = Reflect.getLong(ws, "l")
            Reflect.set(ws, "l", queued + data.j())
            @Suppress("UNCHECKED_CAST")
            val queue = Reflect.get(ws, "k") as java.util.ArrayDeque<Any>
            val messageClass = Class.forName("f0.e0.n.d\$b")
            val ctor = messageClass.getDeclaredConstructor(Int::class.javaPrimitiveType, ByteString::class.java).apply { isAccessible = true }
            queue.add(ctor.newInstance(2 /* binary */, data))
            Reflect.method(ws.javaClass, "l").invoke(ws)
        }
    }

    // endregion

    fun close() {
        if (closed) return
        closed = true
        relay?.close()
        relay = null
        executor.shutdownNow()
    }

    fun status(): String {
        val d = dave
        val r = relay
        val sb = StringBuilder()
        sb.append(if (isStream) "Go Live stream" else "Voice").append(" in <#").append(channelId).append(">\n")
        sb.append("• DAVE protocol v").append(d.protocolVersion)
        if (d.mls.established) {
            sb.append(", MLS epoch ").append(d.mls.epoch).append(", ").append(d.mls.roster.size).append(" member(s)\n")
            sb.append("• Privacy code: `").append(d.privacyCode()).append("`\n")
        } else {
            sb.append(if (d.protocolVersion == 0) " (not end-to-end encrypted)\n" else ", waiting for the MLS group\n")
        }
        sb.append("• Transport: ").append(serverMode).append(" (engine side ").append(r?.localMode ?: localMode()).append(")\n")
        if (r != null) {
            sb.append("• Frames sent ").append(r.sentFrames).append(", dropped ").append(r.droppedSendFrames)
                .append(" | received ").append(r.receivedFrames).append(", undecryptable ").append(r.failedReceiveFrames).append('\n')
            sb.append("• Engine → relay: ").append(r.enginePackets).append(" packets, ").append(r.engineUnreadable)
                .append(" unreadable, ").append(r.toServer).append(" sent on; layout ").append(r.localLayout).append('\n')
            sb.append("• Server → relay: ").append(r.serverPackets).append(" packets, ").append(r.serverUnreadable)
                .append(" unreadable, ").append(r.toEngine).append(" passed to engine")
            if (r.beforeKey > 0) sb.append("\n• ").append(r.beforeKey).append(" packets before the session key")
            if (r.unknownPayloadType >= 0) sb.append("\n• Unknown outgoing payload type ").append(r.unknownPayloadType)
                .append(" (opus ").append(ssrcs.opusPt).append(", VP8 ").append(ssrcs.vp8Pt).append(')')
        } else {
            sb.append("• Media relay not running")
        }
        return sb.toString()
    }

    companion object {
        const val OP_IDENTIFY = 0
        const val OP_SELECT_PROTOCOL = 1
        const val OP_READY = 2
        const val OP_HEARTBEAT = 3
        const val OP_SESSION_DESCRIPTION = 4
        const val OP_SPEAKING = 5
        const val OP_HEARTBEAT_ACK = 6
        const val OP_RESUME = 7
        const val OP_HELLO = 8
        const val OP_CLIENTS_CONNECT = 11
        const val OP_VIDEO = 12
        const val OP_CLIENT_DISCONNECT = 13
        const val OP_SESSION_UPDATE = 14
        const val OP_MEDIA_SINK_WANTS = 15
        const val OP_DAVE_PREPARE_TRANSITION = 21
        const val OP_DAVE_EXECUTE_TRANSITION = 22
        const val OP_DAVE_READY_FOR_TRANSITION = 23
        const val OP_DAVE_PREPARE_EPOCH = 24
        const val OP_MLS_EXTERNAL_SENDER = 25
        const val OP_MLS_KEY_PACKAGE = 26
        const val OP_MLS_PROPOSALS = 27
        const val OP_MLS_COMMIT_WELCOME = 28
        const val OP_MLS_ANNOUNCE_COMMIT = 29
        const val OP_MLS_WELCOME = 30
        const val OP_MLS_INVALID_COMMIT_WELCOME = 31
    }
}
