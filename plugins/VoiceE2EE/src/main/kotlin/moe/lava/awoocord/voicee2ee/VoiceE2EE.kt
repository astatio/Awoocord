package moe.lava.awoocord.voicee2ee

import android.content.Context
import com.aliucord.annotations.AliucordPlugin
import com.aliucord.api.CommandsAPI
import com.aliucord.entities.Plugin
import com.aliucord.patcher.PreHook
import com.discord.rtcconnection.RtcConnection
import com.discord.rtcconnection.socket.io.Payloads
import com.google.gson.Gson
import moe.lava.awoocord.voicee2ee.core.TransportCipher
import okhttp3.Request
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import org.json.JSONObject
import java.util.Collections
import java.util.WeakHashMap
import b.a.q.h0 as RtcSocketListener
import b.a.q.n0.a as RtcControlSocket
import f0.x as OkHttpClient

/**
 * Discord requires DAVE (end-to-end encrypted audio/video) for calls, DMs, server voice channels and Go Live since
 * March 2026. Discord 126.21's native voice engine predates it (and only speaks retired transport modes).
 *
 * The voice gateway is Java in 126.21, so it is upgraded to v8 and DAVE's MLS key exchange runs there; the native
 * engine is left alone behind a local UDP relay that adds/removes DAVE frame encryption (see core.MediaRelay).
 */
@AliucordPlugin(requiresRestart = true)
@Suppress("unused")
class VoiceE2EE : Plugin() {
    private val sessions: MutableMap<Any, VoiceSession> = Collections.synchronizedMap(WeakHashMap())

    // xsalsa20_poly1305_lite_rtpsize is the mode Discord 126.21's engine handles correctly on the local leg (tested
    // on a real call); its aead_aes256_gcm_rtpsize support didn't carry audio either way.
    private fun localMode(): String = settings.getString(SETTING_ENGINE_MODE, TransportCipher.XSALSA20_LITE)

    override fun start(context: Context) {
        hookConnect()
        hookOutgoing()
        hookIncomingText()
        hookIncomingBinary()
        hookReady()
        hookSessionDescription()
        hookClose()

        commands.registerCommand("voicee2ee", "Show the end-to-end encryption status of your current call(s)") {
            val active = synchronized(sessions) { sessions.values.filter { !it.closed } }
            CommandsAPI.CommandResult(
                if (active.isEmpty()) "Not in a call." else active.joinToString("\n\n") { it.status() },
                null,
                false,
            )
        }
        commands.registerCommand(
            "voicee2ee-engine-mode",
            "Switch how the voice engine talks to the local relay (applies to the next call)",
        ) {
            val next = if (localMode() == TransportCipher.XSALSA20_LITE) TransportCipher.AES256_GCM else TransportCipher.XSALSA20_LITE
            settings.setString(SETTING_ENGINE_MODE, next)
            CommandsAPI.CommandResult("Engine transport mode is now `$next`; rejoin the call to apply it.", null, false)
        }
    }

    override fun stop(context: Context) {
        patcher.unpatchAll()
        commands.unregisterAll()
        synchronized(sessions) {
            sessions.values.forEach { it.close() }
            sessions.clear()
        }
    }

    private fun sessionFor(socket: Any): VoiceSession? = sessions[socket]?.takeIf { !it.closed }

    private fun rtcConnectionOf(socket: Any): RtcConnection? {
        @Suppress("UNCHECKED_CAST")
        val listeners = Reflect.get(socket, "q") as? Iterable<Any> ?: return null
        val listener = listeners.firstOrNull { it is RtcSocketListener } ?: return null
        return Reflect.get(listener, "a") as? RtcConnection
    }

    private inline fun guard(what: String, block: () -> Unit) {
        try {
            block()
        } catch (e: Throwable) {
            logger.error("$what failed", e)
        }
    }

    /** Voice websocket connect: create the session and ask for gateway v8 instead of v5. */
    private fun hookConnect() {
        val m = OkHttpClient::class.java.getDeclaredMethod("g", Request::class.java, WebSocketListener::class.java)
        patcher.patch(m, PreHook { param ->
            guard("connect") {
                val socket = param.args[1] as? RtcControlSocket ?: return@guard
                val request = param.args[0] as Request
                val url = Reflect.get(request, "b").toString()
                if (sessionFor(socket) == null) {
                    val rtc = rtcConnectionOf(socket) ?: return@guard logger.warn("voice socket without RtcConnection")
                    val type = Reflect.get(rtc, "X")
                    val session = VoiceSession(
                        socket,
                        userId = Reflect.getLong(rtc, "T"),
                        channelId = Reflect.getLong(rtc, "P"),
                        isStream = type != null && type.javaClass.simpleName == "b", // RtcConnection.d.b = Go Live stream
                        localMode = ::localMode,
                        logger = { logger.info(it) },
                    )
                    sessions[socket]?.close()
                    sessions[socket] = session
                }
                if (url.contains("v=5")) {
                    param.args[0] = Request.a(request).f(url.replace("v=5", "v=8")).a()
                }
            }
        })
    }

    /** Everything the app sends goes through RtcControlSocket.n(opcode, payload). */
    private fun hookOutgoing() {
        val m = RtcControlSocket::class.java.getDeclaredMethod("n", Int::class.javaPrimitiveType, Any::class.java)
        patcher.patch(m, PreHook { param ->
            guard("send") {
                val socket = param.thisObject
                val session = sessionFor(socket) ?: return@guard
                val ws = Reflect.get(socket, "s") as WebSocket? ?: return@guard // let the app log it
                val op = param.args[0] as Int
                if (op != VoiceSession.OP_IDENTIFY && op != VoiceSession.OP_SELECT_PROTOCOL &&
                    op != VoiceSession.OP_HEARTBEAT && op != VoiceSession.OP_RESUME
                ) return@guard
                val gson = Reflect.get(socket, "n") as Gson
                val json = JSONObject(gson.m(Payloads.Outgoing(op, param.args[1])))
                val text = session.rewriteOutgoing(op, json).toString()
                ws.a(text)
                param.result = null
            }
        })
    }

    private fun hookIncomingText() {
        val m = RtcControlSocket::class.java.getDeclaredMethod("onMessage", WebSocket::class.java, String::class.java)
        patcher.patch(m, PreHook { param ->
            guard("receive") {
                val session = sessionFor(param.thisObject) ?: return@guard
                val replaced = session.onIncomingText(param.args[1] as String)
                if (replaced == null) param.result = null else param.args[1] = replaced
            }
        })
    }

    /** The app never overrides the binary callback; DAVE's MLS messages arrive here. */
    private fun hookIncomingBinary() {
        val m = WebSocketListener::class.java.getDeclaredMethod("onMessage", WebSocket::class.java, ByteString::class.java)
        patcher.patch(m, PreHook { param ->
            guard("receive binary") {
                val socket = param.thisObject as? RtcControlSocket ?: return@guard
                val session = sessionFor(socket) ?: return@guard
                session.onIncomingBinary((param.args[1] as ByteString).l())
            }
        })
    }

    /** READY: point the native engine at the local relay instead of Discord's media server. */
    private fun hookReady() {
        val m = RtcSocketListener::class.java.getDeclaredMethod(
            "k", Int::class.javaPrimitiveType, Int::class.javaPrimitiveType, String::class.java, List::class.java,
        )
        patcher.patch(m, PreHook { param ->
            guard("ready") {
                val rtc = Reflect.get(param.thisObject, "a") as RtcConnection
                val socket = Reflect.get(rtc, "w") ?: return@guard
                val session = sessionFor(socket) ?: return@guard
                val relay = session.startRelay(param.args[2] as String, param.args[0] as Int)
                param.args[0] = relay.localPort
                param.args[2] = "127.0.0.1"
            }
        })
    }

    /** Session description: the real transport key goes to the relay, the engine gets the relay's throwaway one. */
    private fun hookSessionDescription() {
        val m = RtcSocketListener::class.java.getDeclaredMethod("c", String::class.java, List::class.java)
        patcher.patch(m, PreHook { param ->
            guard("session description") {
                val rtc = Reflect.get(param.thisObject, "a") as RtcConnection
                val socket = Reflect.get(rtc, "w") ?: return@guard
                val session = sessionFor(socket) ?: return@guard
                val relay = session.relay ?: return@guard session.log("session description before READY")
                @Suppress("UNCHECKED_CAST")
                val key = (param.args[1] as List<Int>).let { l -> ByteArray(l.size) { l[it].toByte() } }
                relay.setServerKey(param.args[0] as String, key)
                param.args[0] = relay.localMode
                param.args[1] = relay.localKey.map { it.toInt() and 0xFF }
            }
        })
    }

    private fun hookClose() {
        // c(): explicit close; f(...): disconnected for good. Reconnects keep the socket object (and the session).
        val close = RtcControlSocket::class.java.getDeclaredMethod("c")
        val disconnect = RtcControlSocket::class.java.getDeclaredMethod(
            "f", Boolean::class.javaPrimitiveType, java.lang.Integer::class.java, String::class.java,
        )
        val hook = PreHook { param ->
            guard("close") {
                sessions.remove(param.thisObject)?.let {
                    it.log("closed")
                    it.close()
                }
            }
        }
        patcher.patch(close, hook)
        patcher.patch(disconnect, hook)
    }

    companion object {
        // new key in 0.1.1 so everyone starts on the new default (0.1.0's AES default didn't work)
        private const val SETTING_ENGINE_MODE = "engineModeV2"
    }
}
