package moe.lava.awoocord.voicee2ee

import moe.lava.awoocord.voicee2ee.core.TransportCipher
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The voice gateway v5 (Discord 126.21) <-> v8 + DAVE rewriting. */
class VoiceSessionTest {
    private val logs = ArrayList<String>()
    private val session = VoiceSession(Any(), 42L, 7L, false, { TransportCipher.AES256_GCM }, { logs += it })

    @Test
    fun identifyAdvertisesDave() {
        val msg = JSONObject("""{"op":0,"d":{"server_id":"1","user_id":42,"session_id":"s","token":"t","video":true}}""")
        val out = session.rewriteOutgoing(VoiceSession.OP_IDENTIFY, msg)
        assertEquals(1, out.getJSONObject("d").getInt("max_dave_protocol_version"))
    }

    @Test
    fun heartbeatAndAckFollowV8() {
        session.onIncomingText("""{"op":5,"seq":17,"d":{"user_id":"9","ssrc":5,"speaking":1}}""")
        val hb = session.rewriteOutgoing(VoiceSession.OP_HEARTBEAT, JSONObject().put("op", 3).put("d", "1700000000000"))
        assertEquals(1700000000000L, hb.getJSONObject("d").getLong("t"))
        assertEquals(17, hb.getJSONObject("d").getInt("seq_ack"))
        val ack = session.onIncomingText("""{"op":6,"d":{"t":1700000000000}}""")!!
        assertEquals(1700000000000L, JSONObject(ack).getLong("d"))
        assertEquals(9L, session.ssrcs.users[5L])
        val hello = session.onIncomingText("""{"op":8,"d":{"heartbeat_interval":13750.25}}""")!!
        assertEquals(13750L, JSONObject(hello).getJSONObject("d").getLong("heartbeat_interval"))
        val resume = session.rewriteOutgoing(VoiceSession.OP_RESUME, JSONObject("""{"op":7,"d":{"server_id":"1"}}"""))
        assertEquals(17, resume.getJSONObject("d").getInt("seq_ack"))
    }

    @Test
    fun selectProtocolPicksAeadModeAndVp8() {
        session.onIncomingText(
            """{"op":2,"d":{"ssrc":1234,"ip":"1.2.3.4","port":50000,
               "modes":["aead_xchacha20_poly1305_rtpsize","aead_aes256_gcm_rtpsize"],
               "streams":[{"type":"video","rid":"100","ssrc":1235,"rtx_ssrc":1236,"quality":100,"active":false}]}}""",
        )
        assertEquals(1234L, session.ssrcs.ownAudioSsrc)
        assertEquals(1236L, session.ssrcs.ownVideo[1235L])
        val codecs = JSONArray()
            .put(JSONObject().put("name", "opus").put("type", "audio").put("priority", 1000).put("payload_type", 120))
            .put(JSONObject().put("name", "AV1X").put("type", "video").put("priority", 1000).put("payload_type", 101).put("rtx_payload_type", 102))
            .put(JSONObject().put("name", "H264").put("type", "video").put("priority", 2000).put("payload_type", 103).put("rtx_payload_type", 104))
            .put(JSONObject().put("name", "VP8").put("type", "video").put("priority", 3000).put("payload_type", 105).put("rtx_payload_type", 106))
        val msg = JSONObject().put("op", 1).put("d", JSONObject().put("protocol", "udp")
            .put("data", JSONObject().put("address", "5.6.7.8").put("port", 1).put("mode", "xsalsa20_poly1305_lite_rtpsize"))
            .put("codecs", codecs))
        val d = session.rewriteOutgoing(VoiceSession.OP_SELECT_PROTOCOL, msg).getJSONObject("d")
        assertEquals(TransportCipher.AES256_GCM, d.getJSONObject("data").getString("mode"))
        val names = (0 until d.getJSONArray("codecs").length()).map { d.getJSONArray("codecs").getJSONObject(it).getString("name") }
        assertEquals(listOf("opus", "VP8"), names)
        assertEquals(105, session.ssrcs.vp8Pt)
        assertEquals(106, session.ssrcs.vp8RtxPt)
    }

    @Test
    fun daveOpcodesAreHiddenFromTheApp() {
        for (op in intArrayOf(11, 21, 22, 24, 18, 20)) {
            assertNull("op $op", session.onIncomingText("""{"op":$op,"d":{"transition_id":1,"protocol_version":1,"epoch":1,"user_ids":["5"]}}"""))
        }
        // ops the app understands still reach it
        assertTrue(session.onIncomingText("""{"op":13,"d":{"user_id":"5"}}""") != null)
        assertTrue(session.onIncomingText("""{"op":15,"d":{"any":100}}""") != null)
        session.onIncomingBinary(byteArrayOf(0x01, 0x02, 99))
        assertEquals(0x0102, session.seq)
        session.close()
    }
}
