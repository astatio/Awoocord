package moe.lava.awoocord.voicee2ee.core

import java.util.concurrent.ConcurrentHashMap

/** Messages DAVE sends back to the voice gateway. */
interface DaveGateway {
    /** dave_mls_key_package (26), binary. */
    fun sendKeyPackage(keyPackage: ByteArray)

    /** dave_mls_commit_welcome (28), binary. */
    fun sendCommitWelcome(commitWelcome: ByteArray)

    /** dave_protocol_ready_for_transition (23), JSON. */
    fun sendReadyForTransition(transitionId: Int)

    /** dave_mls_invalid_commit_welcome (31), JSON. */
    fun sendInvalidCommitWelcome(transitionId: Int)
}

/**
 * DAVE protocol state for one voice gateway connection (protocol.md; libdave's DaveSessionManager sample flow).
 * Gateway events must come from a single thread; the media side ([encryptor], [decryptor]) is thread safe.
 */
class DaveProtocol(
    val selfUserId: Long,
    private val channelId: Long,
    private val gateway: DaveGateway,
    private val log: (String) -> Unit,
    private val clock: Clock = Clock.SYSTEM,
    identity: () -> org.bouncycastle.crypto.AsymmetricCipherKeyPair = DaveIdentity::signatureKeyPair,
    /** Runs work on the thread that delivers gateway events (used by the media side's failure recovery). */
    private val onGatewayThread: (Runnable) -> Unit = { it.run() },
) {
    val mls = MlsSession(selfUserId, log, identity)
    val encryptor = FrameEncryptor()
    private val decryptors = ConcurrentHashMap<Long, FrameDecryptor>()

    @Volatile
    var protocolVersion = 0
        private set

    private val recognizedUsers = java.util.Collections.newSetFromMap(ConcurrentHashMap<Long, Boolean>())
    private val pendingTransitions = HashMap<Int, Int>()
    private var latestPreparedVersion = 0
    private var lastTransitionId = -1
    private var reinitializing = false

    @Volatile
    private var consecutiveFailures = 0

    fun decryptor(userId: Long): FrameDecryptor = decryptors[userId] ?: synchronized(decryptors) {
        decryptors.getOrPut(userId) { FrameDecryptor(clock).also { setupUserRatchet(userId, latestPreparedVersion, it) } }
    }

    // region gateway events

    /** select_protocol_ack / session description (4): the initial protocol version. */
    fun onSessionDescription(daveProtocolVersion: Int) {
        protocolVersion = daveProtocolVersion
        handleInit(daveProtocolVersion)
    }

    fun onClientsConnect(userIds: Collection<Long>) {
        for (id in userIds) {
            if (recognizedUsers.add(id)) decryptor(id)
        }
    }

    fun onClientDisconnect(userId: Long) {
        recognizedUsers.remove(userId)
        decryptors.remove(userId)
    }

    /** dave_protocol_prepare_transition (21). */
    fun onPrepareTransition(transitionId: Int, version: Int) {
        log("prepare transition $transitionId -> v$version")
        prepareRatchets(transitionId, version)
        if (transitionId != INIT_TRANSITION_ID) gateway.sendReadyForTransition(transitionId)
    }

    /** dave_protocol_execute_transition (22). */
    fun onExecuteTransition(transitionId: Int) {
        executeTransition(transitionId)
    }

    /** dave_protocol_prepare_epoch (24). */
    fun onPrepareEpoch(epoch: Long, version: Int) {
        log("prepare epoch $epoch v$version")
        if (epoch == 1L) {
            protocolVersion = version
            mls.init(channelId)
            sendKeyPackage()
        }
    }

    /** dave_mls_external_sender_package (25), payload after the opcode. */
    fun onExternalSender(payload: ByteArray) {
        mls.setExternalSender(payload)
    }

    /** dave_mls_proposals (27), payload after the opcode. */
    fun onProposals(payload: ByteArray) {
        val out = try {
            mls.processProposals(payload, recognizedUsers + selfUserId)
        } catch (e: Exception) {
            log("invalid proposals: $e")
            null
        }
        if (out != null) gateway.sendCommitWelcome(out)
    }

    /** dave_mls_announce_commit_transition (29), payload after the opcode. */
    fun onAnnounceCommit(payload: ByteArray) {
        val transitionId = Bytes.u16(payload, 0)
        when (mls.processCommit(payload.copyOfRange(2, payload.size))) {
            MlsSession.CommitResult.OK -> joinedGroup(transitionId)
            MlsSession.CommitResult.IGNORED -> {}
            MlsSession.CommitResult.FAILED -> recoverFromInvalidTransition(transitionId)
        }
    }

    /** dave_mls_welcome (30), payload after the opcode. */
    fun onWelcome(payload: ByteArray) {
        val transitionId = Bytes.u16(payload, 0)
        if (mls.processWelcome(payload.copyOfRange(2, payload.size), recognizedUsers + selfUserId)) {
            joinedGroup(transitionId)
        } else {
            gateway.sendInvalidCommitWelcome(transitionId)
            sendKeyPackage()
        }
    }

    // endregion

    /** Called by the media side when a frame from a known user could not be decrypted. */
    fun reportDecryptFailure() {
        if (protocolVersion == 0) return
        if (++consecutiveFailures > DECRYPT_FAILURE_TOLERANCE) {
            consecutiveFailures = 0
            onGatewayThread(Runnable {
                // like discord.js: persistent failures outside of transitions mean our group state is bad
                if (!reinitializing && pendingTransitions.isEmpty() && lastTransitionId > 0) {
                    recoverFromInvalidTransition(lastTransitionId)
                }
            })
        }
    }

    fun reportDecryptSuccess() {
        consecutiveFailures = 0
    }

    private fun joinedGroup(transitionId: Int) {
        log("joined MLS group epoch ${mls.epoch} with ${mls.roster.size} member(s), transition $transitionId")
        reinitializing = false
        prepareRatchets(transitionId, protocolVersion)
        if (transitionId != INIT_TRANSITION_ID) gateway.sendReadyForTransition(transitionId)
    }

    private fun recoverFromInvalidTransition(transitionId: Int) {
        if (reinitializing) return
        log("invalid commit/welcome for transition $transitionId, reinitialising")
        reinitializing = true
        gateway.sendInvalidCommitWelcome(transitionId)
        handleInit(protocolVersion)
    }

    private fun handleInit(version: Int) {
        if (version > 0) {
            mls.init(channelId)
            sendKeyPackage()
        } else {
            prepareRatchets(INIT_TRANSITION_ID, version)
            executeTransition(INIT_TRANSITION_ID)
        }
    }

    private fun sendKeyPackage() {
        try {
            gateway.sendKeyPackage(mls.keyPackage())
        } catch (e: Exception) {
            log("failed to create key package: $e")
        }
    }

    private fun prepareRatchets(transitionId: Int, version: Int) {
        for (uid in recognizedUsers) {
            if (uid != selfUserId) setupUserRatchet(uid, version, decryptors[uid] ?: continue)
        }
        if (transitionId == INIT_TRANSITION_ID) {
            setupSelfRatchet(version)
            lastTransitionId = transitionId
        } else {
            pendingTransitions[transitionId] = version
        }
        latestPreparedVersion = version
    }

    private fun executeTransition(transitionId: Int) {
        val version = pendingTransitions.remove(transitionId)
        if (version == null) {
            if (transitionId != INIT_TRANSITION_ID) log("execute for unknown transition $transitionId")
            return
        }
        log("execute transition $transitionId (v$protocolVersion -> v$version)")
        protocolVersion = version
        if (version == 0) mls.reset()
        setupSelfRatchet(version)
        lastTransitionId = transitionId
    }

    private fun setupUserRatchet(userId: Long, version: Int, d: FrameDecryptor) {
        if (version == 0) {
            d.transitionToPassthrough(true)
            return
        }
        val r = mls.keyRatchet(userId)
        if (r != null) {
            d.transitionToKeyRatchet(r)
            d.transitionToPassthrough(false)
        }
    }

    private fun setupSelfRatchet(version: Int) {
        if (version == 0) {
            encryptor.passthrough = true
            return
        }
        encryptor.passthrough = false
        encryptor.setKeyRatchet(mls.keyRatchet(selfUserId))
    }

    /** "Voice privacy code": the epoch authenticator as 30 digits in groups of 5, or null without a group. */
    fun privacyCode(): String? = mls.epochAuthenticator?.let { displayableCode(it, 30, 5) }

    companion object {
        const val INIT_TRANSITION_ID = 0
        const val MAX_PROTOCOL_VERSION = 1
        private const val DECRYPT_FAILURE_TOLERANCE = 36

        /** protocol.md "Displayable Codes". */
        fun displayableCode(data: ByteArray, length: Int, groupSize: Int): String {
            require(data.size >= length && length % groupSize == 0 && groupSize < 8)
            val sb = StringBuilder()
            var mod = 1L
            repeat(groupSize) { mod *= 10 }
            for (g in 0 until length / groupSize) {
                var v = 0L
                for (i in 0 until groupSize) v = (v shl 8) or (data[g * groupSize + i].toLong() and 0xFF)
                val s = (v % mod).toString()
                if (sb.isNotEmpty()) sb.append(' ')
                repeat(groupSize - s.length) { sb.append('0') }
                sb.append(s)
            }
            return sb.toString()
        }
    }
}
