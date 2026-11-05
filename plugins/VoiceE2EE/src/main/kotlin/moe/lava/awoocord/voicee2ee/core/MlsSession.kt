package moe.lava.awoocord.voicee2ee.core

import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.mls.TreeKEM.LeafIndex
import org.bouncycastle.mls.TreeKEM.LeafNode
import org.bouncycastle.mls.TreeKEM.LifeTime
import org.bouncycastle.mls.codec.Capabilities
import org.bouncycastle.mls.codec.ContentType
import org.bouncycastle.mls.codec.Credential
import org.bouncycastle.mls.codec.Extension
import org.bouncycastle.mls.codec.ExtensionType
import org.bouncycastle.mls.codec.ExternalSender
import org.bouncycastle.mls.codec.KeyPackage
import org.bouncycastle.mls.codec.MLSInputStream
import org.bouncycastle.mls.codec.MLSMessage
import org.bouncycastle.mls.codec.MLSOutputStream
import org.bouncycastle.mls.codec.ProposalOrRefType
import org.bouncycastle.mls.codec.ProposalType
import org.bouncycastle.mls.codec.SenderType
import org.bouncycastle.mls.codec.Welcome
import org.bouncycastle.mls.codec.WireFormat
import org.bouncycastle.mls.crypto.MlsCipherSuite
import org.bouncycastle.mls.crypto.Secret
import org.bouncycastle.mls.protocol.Group
import java.security.SecureRandom

/** Process wide MLS signature key: DAVE wants the same identity key on all simultaneous voice connections. */
object DaveIdentity {
    val suite: MlsCipherSuite get() = MlsCipherSuite.getSuite(MlsCipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256)

    @Volatile
    private var keyPair: AsymmetricCipherKeyPair? = null

    @Synchronized
    fun signatureKeyPair(): AsymmetricCipherKeyPair = keyPair ?: suite.generateSignatureKeyPair().also { keyPair = it }
}

/**
 * The MLS half of DAVE ("Group Key Exchange"), following libdave's mls::Session over BouncyCastle's bcmls.
 * Not thread safe: driven from the single voice gateway thread.
 */
class MlsSession(
    private val selfUserId: Long,
    private val log: (String) -> Unit,
    private val identity: () -> AsymmetricCipherKeyPair = DaveIdentity::signatureKeyPair,
) {
    private val suite = DaveIdentity.suite
    private val random = SecureRandom()

    private var groupId: ByteArray? = null
    private var externalSender: ExternalSender? = null
    private var externalSenderBytes: ByteArray? = null

    private var sigKeyPair: AsymmetricCipherKeyPair? = null
    private var sigPriv: ByteArray? = null
    private var leafKeyPair: AsymmetricCipherKeyPair? = null
    private var leafNode: LeafNode? = null
    private var joinInitKeyPair: AsymmetricCipherKeyPair? = null
    private var joinKeyPackage: KeyPackage? = null

    private var pendingGroup: Group? = null
    private var currentGroup: Group? = null
    /** Commits we sent for the current epoch, with the state each leads to (any of them may be the one chosen). */
    private val outboundCommits = ArrayList<Pair<ByteArray, Group>>()

    /** user id -> signature public key of the established group. */
    var roster: Map<Long, ByteArray> = emptyMap()
        private set

    val established: Boolean get() = currentGroup != null
    val epoch: Long get() = currentGroup?.epoch ?: 0
    val epochAuthenticator: ByteArray? get() = currentGroup?.epochAuthenticator

    /** DAVE "Initial Group Creation": resets everything and prepares a pending local group when possible. */
    fun init(channelId: Long) {
        reset()
        groupId = Bytes.u64be(channelId)
        val kp = identity()
        sigKeyPair = kp
        sigPriv = suite.serializeSignaturePrivateKey(kp.private)
        val leaf = suite.hpke.generatePrivateKey()
        leafKeyPair = leaf
        val caps = Capabilities()
        BcmlsAccess.restrict(caps, suite.suiteID)
        leafNode = LeafNode(
            suite,
            suite.hpke.serializePublicKey(leaf.public),
            suite.serializeSignaturePublicKey(kp.public),
            Credential.forBasic(Bytes.u64be(selfUserId)),
            caps,
            LifeTime(), // not_before = 0, not_after = 2^64-1 as the gateway requires
            emptyList(),
            sigPriv,
        )
        if (externalSender != null) createPendingGroup()
    }

    fun reset() {
        clearPendingState()
        currentGroup = null
        roster = emptyMap()
        groupId = null
    }

    fun setExternalSender(marshalled: ByteArray) {
        if (currentGroup != null) {
            log("ignoring external sender: group already established")
            return
        }
        externalSender = MLSInputStream.decode(marshalled, ExternalSender::class.java) as ExternalSender
        externalSenderBytes = marshalled.clone()
        if (groupId != null) createPendingGroup()
    }

    private fun createPendingGroup() {
        val gid = groupId ?: return
        val es = externalSender ?: return
        val leaf = leafNode ?: return
        pendingGroup = Group(gid, suite, leafKeyPair, sigPriv, leaf, listOf(Extension.externalSender(listOf(es))))
    }

    /** A fresh key package each time (they must not be reused). Returns the marshalled KeyPackage. */
    fun keyPackage(): ByteArray {
        val leaf = leafNode ?: throw IllegalStateException("session not initialised")
        val init = suite.hpke.generatePrivateKey()
        val kp = KeyPackage(suite, suite.hpke.serializePublicKey(init.public), leaf, emptyList(), sigPriv)
        joinInitKeyPair = init
        joinKeyPackage = kp
        return MLSOutputStream.encode(kp)
    }

    /**
     * dave_mls_proposals (27) payload after the opcode: operation type, then the proposals or refs.
     * Returns commit (+ welcome) bytes to send with opcode 28, or null when there is nothing to commit.
     * Throws on invalid input.
     */
    fun processProposals(payload: ByteArray, recognizedUsers: Set<Long>): ByteArray? {
        val base = currentGroup ?: pendingGroup
        if (base == null) {
            log("proposals without MLS state, ignored")
            return null
        }
        val op = payload[0].toInt()
        val body = payload.copyOfRange(1, payload.size)
        if (op == 1) {
            val refs = readOpaqueVector(body)
            val pending = pendingProposals(base)
            for (ref in refs) {
                val idx = pending.indexOfFirst { java.util.Arrays.equals(proposalRef(it), ref) }
                if (idx < 0) throw IllegalArgumentException("unknown proposal revoked")
                pending.removeAt(idx)
            }
        } else {
            val messages = ArrayList<MLSMessage>()
            MLSInputStream(body).readList(messages, MLSMessage::class.java)
            for (m in messages) {
                validateProposal(m, base, recognizedUsers)
                base.handle(MLSOutputStream.encode(m), null)
            }
        }
        if (pendingProposals(base).isEmpty()) return null

        val leafSecret = ByteArray(suite.kdf.hashLength).also { random.nextBytes(it) }
        val result = base.commit(
            Secret(leafSecret),
            Group.CommitOptions(emptyList(), true, false, Group.LeafNodeOptions()),
            Group.MessageOptions(false, ByteArray(0), 0),
            Group.CommitParameters(Group.NORMAL_COMMIT_PARAMS),
        )
        val commit = MLSOutputStream.encode(result.message)
        outboundCommits.add(commit to result.group)
        val welcome = result.message.welcome
        return if (welcome != null && BcmlsAccess.welcomeSecretCount(welcome) > 0) {
            Bytes.concat(commit, MLSOutputStream.encode(welcome))
        } else commit
    }

    private fun validateProposal(m: MLSMessage, target: Group, recognized: Set<Long>) {
        if (m.wireFormat != WireFormat.mls_public_message) throw IllegalArgumentException("proposal not a public message")
        val content = BcmlsAccess.content(m.publicMessage)
        if (content.epoch != target.epoch) throw IllegalArgumentException("proposal epoch mismatch")
        if (content.contentType != ContentType.PROPOSAL) throw IllegalArgumentException("not a proposal")
        if (content.sender.senderType != SenderType.EXTERNAL) throw IllegalArgumentException("proposal not from external sender")
        val proposal = content.proposal
        when (proposal.proposalType) {
            ProposalType.ADD -> {
                val uid = userIdOf(proposal.add.keyPackage.leafNode.credential)
                if (uid == null || uid !in recognized) throw IllegalArgumentException("add proposal for unexpected user $uid")
            }
            ProposalType.REMOVE -> {}
            else -> throw IllegalArgumentException("unexpected proposal type ${proposal.proposalType}")
        }
    }

    /** processCommit results (plain ints: Kotlin 2 enums need a newer stdlib than Discord ships). */
    object CommitResult {
        const val OK = 0
        const val IGNORED = 1
        const val FAILED = 2
    }

    /** dave_mls_announce_commit_transition (29) commit message. */
    fun processCommit(commit: ByteArray): Int {
        val base = currentGroup ?: pendingGroup
        if (base == null) return CommitResult.IGNORED
        val own = outboundCommits.firstOrNull { java.util.Arrays.equals(it.first, commit) }?.second
        val isOwn = own != null
        if (currentGroup == null && !isOwn) {
            // Before we are in an established group, only our own initial commit can apply to us; the welcome
            // for someone else's commit arrives separately (opcode 30).
            log("commit for a group we're not in yet, waiting for welcome")
            return CommitResult.IGNORED
        }
        return try {
            val msg = MLSInputStream.decode(commit, MLSMessage::class.java) as MLSMessage
            if (msg.wireFormat != WireFormat.mls_public_message) throw IllegalArgumentException("commit not public")
            val content = BcmlsAccess.content(msg.publicMessage)
            if (!java.util.Arrays.equals(content.groupID, groupId)) throw IllegalArgumentException("commit for another group")
            if (content.epoch != base.epoch) throw IllegalArgumentException("commit epoch mismatch")
            if (content.contentType != ContentType.COMMIT) throw IllegalArgumentException("not a commit")
            if (content.sender.senderType != SenderType.MEMBER) throw IllegalArgumentException("commit not from a member")
            val cached = pendingProposals(base)
            for (p in content.commit.proposals) {
                if (p.type != ProposalOrRefType.REFERENCE) throw IllegalArgumentException("commit with inline proposal")
                // bcmls skips unknown references silently; DAVE requires refusing them
                if (cached.none { java.util.Arrays.equals(proposalRef(it), p.reference) }) {
                    throw IllegalArgumentException("commit references a proposal we don't have")
                }
            }
            if (!isOwn && content.sender.sender == base.index) throw IllegalArgumentException("foreign commit from our leaf")
            val next = base.handle(commit, own)
                ?: throw IllegalStateException("commit produced no state")
            replaceState(next)
            clearPendingState()
            CommitResult.OK
        } catch (e: Exception) {
            log("commit failed: $e")
            CommitResult.FAILED
        }
    }

    /** dave_mls_welcome (30) welcome. Returns false when it can't be used (then flag it and send a new key package). */
    fun processWelcome(welcomeBytes: ByteArray, recognizedUsers: Set<Long>): Boolean {
        return try {
            if (currentGroup != null) throw IllegalStateException("already in a group")
            val kp = joinKeyPackage ?: throw IllegalStateException("no key package")
            val init = joinInitKeyPair ?: throw IllegalStateException("no init key")
            val es = externalSenderBytes ?: throw IllegalStateException("no external sender")
            val welcome = MLSInputStream.decode(welcomeBytes, Welcome::class.java) as Welcome
            val group = Group(
                suite.hpke.serializePrivateKey(init.private),
                leafKeyPair,
                sigPriv,
                kp,
                welcome,
                null,
                HashMap(),
                HashMap(),
            )
            if (!java.util.Arrays.equals(group.groupID, groupId)) throw IllegalArgumentException("welcome for another group")
            val senders = group.extensions.filter { it.extensionType == ExtensionType.EXTERNAL_SENDERS }
            if (senders.size != 1) throw IllegalArgumentException("welcome without exactly one external senders extension")
            val list = senders[0].senders
            if (list.size != 1 || !java.util.Arrays.equals(MLSOutputStream.encode(list[0]), es)) {
                throw IllegalArgumentException("welcome lists an unexpected external sender")
            }
            for (uid in rosterOf(group).keys) {
                if (uid !in recognizedUsers && uid != selfUserId) throw IllegalArgumentException("welcome lists unexpected user $uid")
            }
            replaceState(group)
            clearPendingState()
            true
        } catch (e: Exception) {
            log("welcome failed: $e")
            false
        }
    }

    /** Sender key ratchet for [userId] in the current epoch. */
    fun keyRatchet(userId: Long): KeyRatchet? {
        val g = currentGroup ?: return null
        val base = g.keySchedule.MLSExporter("Discord Secure Frames v0", Bytes.u64le(userId), KeyRatchet.KEY_BYTES)
        return KeyRatchet(base)
    }

    private fun replaceState(g: Group) {
        roster = rosterOf(g)
        currentGroup = g
    }

    private fun rosterOf(g: Group): Map<Long, ByteArray> {
        val out = LinkedHashMap<Long, ByteArray>()
        val tree = g.tree
        val leaves = tree.size.leafCount()
        for (i in 0 until leaves) {
            val idx = LeafIndex(i.toInt())
            if (!tree.hasLeaf(idx)) continue
            val leaf = tree.getLeafNode(idx) ?: continue
            val uid = userIdOf(leaf.credential) ?: throw IllegalArgumentException("non-basic credential in roster")
            if (out.put(uid, leaf.signatureKey) != null) throw IllegalArgumentException("duplicate user $uid in roster")
        }
        return out
    }

    private fun userIdOf(c: Credential): Long? {
        if (c.credentialType != org.bouncycastle.mls.codec.CredentialType.basic) return null
        val id = c.identity ?: return null
        if (id.size > 8) return null
        return Bytes.fromU64be(id)
    }

    private fun clearPendingState() {
        pendingGroup = null
        outboundCommits.clear()
        joinInitKeyPair = null
        joinKeyPackage = null
        leafNode = null
        leafKeyPair = null
    }

    companion object {
        private fun pendingProposals(g: Group) = BcmlsAccess.pendingProposals(g)

        private fun proposalRef(cached: Any) = BcmlsAccess.proposalRef(cached)

        /** vector<opaque<V>> with MLS variable length headers. */
        internal fun readOpaqueVector(b: ByteArray): List<ByteArray> {
            val out = ArrayList<ByteArray>()
            val pos = IntArray(1)
            val total = readVarint(b, 0, pos)
            var p = pos[0]
            val end = p + total
            if (end > b.size) throw IllegalArgumentException("truncated vector")
            while (p < end) {
                val n = readVarint(b, p, pos)
                p = pos[0]
                if (p + n > end) throw IllegalArgumentException("truncated vector element")
                out.add(b.copyOfRange(p, p + n))
                p += n
            }
            return out
        }

        private fun readVarint(b: ByteArray, off: Int, pos: IntArray): Int {
            val first = b[off].toInt() and 0xFF
            return when (first ushr 6) {
                0 -> { pos[0] = off + 1; first and 0x3F }
                1 -> { pos[0] = off + 2; ((first and 0x3F) shl 8) or (b[off + 1].toInt() and 0xFF) }
                2 -> {
                    pos[0] = off + 4
                    ((first and 0x3F) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
                        ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)
                }
                else -> throw IllegalArgumentException("invalid varint")
            }
        }
    }
}
