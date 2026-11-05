package moe.lava.awoocord.voicee2ee.core

import org.bouncycastle.mls.TreeKEM.LeafIndex
import org.bouncycastle.mls.codec.Credential
import org.bouncycastle.mls.codec.ExternalSender
import org.bouncycastle.mls.codec.KeyPackage
import org.bouncycastle.mls.codec.MLSInputStream
import org.bouncycastle.mls.codec.MLSMessage
import org.bouncycastle.mls.codec.MLSOutputStream
import org.bouncycastle.mls.codec.Proposal
import org.bouncycastle.mls.codec.Welcome
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.Random

/**
 * Drives several [DaveProtocol] clients through an in-memory model of Discord's voice gateway acting as MLS delivery
 * service and external sender (protocol.md "Group Key Exchange"), then checks that media frames encrypted by each
 * member decrypt at every other member.
 */
class DaveProtocolTest {
    private val channelId = 1_234_567_890_123_456_789L
    private val rnd = Random(7)

    /** Minimal voice gateway: proposals, first-commit-wins, welcomes and transitions. */
    private inner class FakeGateway {
        val suite = DaveIdentity.suite
        private val sig = suite.generateSignatureKeyPair()
        private val sigPriv = suite.serializeSignaturePrivateKey(sig.private)
        val sigPrivForTests: ByteArray get() = sigPriv
        val externalSender = MLSOutputStream.encode(
            ExternalSender(suite.serializeSignaturePublicKey(sig.public), Credential.forBasic(byteArrayOf(0, 1, 1, 0))),
        )
        val groupId = Bytes.u64be(channelId)

        val clients = LinkedHashMap<Long, Client>()
        var epoch = 0L // 0 while no group is established
        private var transitionCounter = 0
        /** user -> leaf index in the established group */
        val leaves = HashMap<Long, Int>()
        /** proposals of the current epoch: (ref-less) adds pending commit, with the user they add */
        private val pendingAdds = LinkedHashMap<Long, KeyPackage>()
        private val pendingRemoves = LinkedHashSet<Long>()
        private var awaitingReady: MutableSet<Long>? = null
        private var readyTransition = -1
        val queue = ArrayDeque<() -> Unit>()

        fun connect(c: Client) {
            clients.values.forEach { it.dave.onClientsConnect(listOf(c.id)) }
            c.dave.onClientsConnect(clients.keys.toList())
            clients[c.id] = c
            c.dave.onExternalSender(externalSender)
            c.dave.onSessionDescription(1)
        }

        fun disconnect(id: Long) {
            clients.remove(id)
            clients.values.forEach { it.dave.onClientDisconnect(id) }
            if (leaves.containsKey(id)) {
                pendingRemoves.add(id)
                queue.addLast { broadcastProposals() }
            }
        }

        fun onKeyPackage(from: Long, kp: ByteArray) {
            val keyPackage = MLSInputStream.decode(kp, KeyPackage::class.java) as KeyPackage
            if (leaves.containsKey(from)) pendingRemoves.add(from) // re-add with a new key package
            pendingAdds[from] = keyPackage
            signedAdds.remove(from)
            queue.addLast { broadcastProposals() }
        }

        /** Removes, then adds of users other than [target] (nobody is proposed to themselves). */
        // Each proposal is signed once and the same bytes go to every member (signatures are randomised, and the
        // proposal reference is a hash of the message).
        private val signedRemoves = HashMap<Long, MLSMessage>()
        private val signedAdds = HashMap<Long, MLSMessage>()

        private fun proposalMessages(target: Long): List<MLSMessage> {
            val list = ArrayList<MLSMessage>()
            for (uid in pendingRemoves) {
                list += signedRemoves.getOrPut(uid) {
                    MLSMessage.externalProposal(suite, groupId, epoch, Proposal.remove(LeafIndex(leaves[uid]!!)), 0, sigPriv)
                }
            }
            for ((uid, kp) in pendingAdds) {
                if (uid != target) list += signedAdds.getOrPut(uid) {
                    MLSMessage.externalProposal(suite, groupId, epoch, Proposal.add(kp), 0, sigPriv)
                }
            }
            return list
        }

        private fun broadcastProposals() {
            if (pendingAdds.isEmpty() && pendingRemoves.isEmpty()) return
            // Established group: its connected members. Initial creation: every pending member.
            val targets = if (epoch == 0L) pendingAdds.keys.filter { it in clients } else leaves.keys.filter { it in clients }
            for (t in targets) {
                val msgs = proposalMessages(t)
                if (msgs.isEmpty()) continue
                val out = ByteArrayOutputStream()
                out.write(0) // append
                out.write(MLSOutputStream.encode(VectorOf(msgs)))
                clients[t]?.dave?.onProposals(out.toByteArray())
            }
        }

        fun onCommitWelcome(from: Long, data: ByteArray) {
            val stream = MLSInputStream(data)
            val commit = stream.read(MLSMessage::class.java) as MLSMessage
            // first commit for the current epoch wins; stale ones are dropped
            if (committedThisRound || BcmlsAccess.content(commit.publicMessage).epoch != epoch) return
            committedThisRound = true
            val commitBytes = MLSOutputStream.encode(commit)
            val welcome = if (commitBytes.size < data.size) data.copyOfRange(commitBytes.size, data.size) else null
            val transitionId = ++transitionCounter
            // new leaf layout after the commit: removes blank leaves, adds fill the leftmost blanks
            val initial = epoch == 0L
            if (initial) {
                leaves.clear(); leaves[from] = 0
            }
            for (r in pendingRemoves) leaves.remove(r)
            for (uid in pendingAdds.keys) {
                if (uid == from && initial) continue
                var i = 0
                while (leaves.containsValue(i)) i++
                leaves[uid] = i
            }
            val added = pendingAdds.keys.filter { it != from || !initial }.toSet()
            pendingAdds.clear(); pendingRemoves.clear(); signedAdds.clear(); signedRemoves.clear()
            epoch = if (initial) 1 else epoch + 1
            awaitingReady = leaves.keys.filter { it in clients }.toMutableSet()
            readyTransition = transitionId
            queue.addLast {
                committedThisRound = false
                val tid = byteArrayOf((transitionId shr 8).toByte(), transitionId.toByte())
                // the commit goes to everyone connected (pending members must ignore it), the welcome to the added
                for ((uid, c) in clients) {
                    if (uid in added && welcome != null) {
                        val w = MLSInputStream.decode(welcome, Welcome::class.java) as Welcome
                        c.dave.onWelcome(tid + MLSOutputStream.encode(w))
                    } else {
                        c.dave.onAnnounceCommit(tid + commitBytes)
                    }
                }
            }
        }

        private var committedThisRound = false

        fun onReady(from: Long, transitionId: Int) {
            if (transitionId != readyTransition) return
            val waiting = awaitingReady ?: return
            waiting.remove(from)
            if (waiting.isEmpty()) {
                awaitingReady = null
                queue.addLast { clients.values.forEach { it.dave.onExecuteTransition(transitionId) } }
            }
        }

        fun onInvalid(from: Long, transitionId: Int) {
            invalidReports++
        }

        var invalidReports = 0

        fun pump() {
            var guard = 0
            while (queue.isNotEmpty()) {
                queue.removeFirst()()
                check(++guard < 10_000) { "gateway did not settle" }
            }
        }
    }

    /** Encodes a vector<MLSMessage> with an MLS variable-size length header. */
    private class VectorOf(val items: List<MLSMessage>) : MLSOutputStream.Writable {
        override fun writeTo(stream: MLSOutputStream) = stream.writeList(items)
    }

    private inner class Client(val id: Long, val gw: FakeGateway) : DaveGateway {
        val logs = ArrayList<String>()
        // each simulated user has its own identity key (in the app it is one per process = per user)
        private val key = DaveIdentity.suite.generateSignatureKeyPair()
        val dave = DaveProtocol(id, channelId, this, { logs += it }, identity = { key })
        override fun sendKeyPackage(keyPackage: ByteArray) = gw.queue.addLast { gw.onKeyPackage(id, keyPackage) }
        override fun sendCommitWelcome(commitWelcome: ByteArray) = gw.queue.addLast { gw.onCommitWelcome(id, commitWelcome) }
        override fun sendReadyForTransition(transitionId: Int) = gw.queue.addLast { gw.onReady(id, transitionId) }
        override fun sendInvalidCommitWelcome(transitionId: Int) = gw.queue.addLast { gw.onInvalid(id, transitionId) }
    }

    private fun assertMediaFlows(clients: Collection<Client>) {
        for (a in clients) for (b in clients) {
            if (a === b) continue
            val frame = ByteArray(100).also { rnd.nextBytes(it) }
            val sealed = a.dave.encryptor.encrypt(Codec.OPUS, frame)
            assertNotNull("${a.id} has no send key (${a.logs})", sealed)
            val r = b.dave.decryptor(a.id).decrypt(true, sealed!!)
            assertEquals("${b.id} decrypting ${a.id}: ${b.logs}", FrameDecryptor.Result.OK, r)
            assertArrayEquals(frame, b.dave.decryptor(a.id).output)
        }
        val codes = clients.map { it.dave.privacyCode() }.toSet()
        assertEquals("all members see the same epoch authenticator", 1, codes.size)
        assertTrue(codes.single()!!.matches(Regex("(\\d{5} ){5}\\d{5}")))
    }

    @Test
    fun groupCreationJoinLeaveAndRejoin() {
        val gw = FakeGateway()
        val a = Client(111L, gw)
        val b = Client(222L, gw)
        val c = Client(333L, gw)

        gw.connect(a); gw.pump()
        gw.connect(b); gw.pump()
        assertEquals(1L, gw.epoch)
        assertEquals(1L, a.dave.mls.epoch)
        assertEquals(1L, b.dave.mls.epoch)
        assertMediaFlows(listOf(a, b))

        gw.connect(c); gw.pump()
        assertEquals(2L, gw.epoch)
        assertEquals(a.logs.joinToString("\n"), setOf(111L, 222L, 333L), a.dave.mls.roster.keys)
        assertMediaFlows(listOf(a, b, c))

        gw.disconnect(b.id); gw.pump()
        assertEquals(setOf(111L, 333L), c.dave.mls.roster.keys)
        assertMediaFlows(listOf(a, c))

        // b reconnects with a new session: added again in a new epoch
        val b2 = Client(222L, gw)
        gw.connect(b2); gw.pump()
        assertMediaFlows(listOf(a, b2, c))
        assertEquals(0, gw.invalidReports)
    }

    @Test
    fun simultaneousInitialJoinPicksOneCommit() {
        val gw = FakeGateway()
        val a = Client(10L, gw)
        val b = Client(20L, gw)
        // both connect before anything is processed: both have pending local groups and both commit
        gw.connect(a)
        gw.connect(b)
        gw.pump()
        assertEquals(1L, a.dave.mls.epoch)
        assertEquals(1L, b.dave.mls.epoch)
        assertMediaFlows(listOf(a, b))
        assertEquals(0, gw.invalidReports)
    }

    @Test
    fun forgedProposalsAreRefused() {
        val gw = FakeGateway()
        val a = Client(1L, gw)
        val b = Client(2L, gw)
        gw.connect(a); gw.pump()
        gw.connect(b); gw.pump()
        val c = Client(3L, gw)
        a.dave.onClientsConnect(listOf(3L))
        c.dave.mls.setExternalSender(gw.externalSender)
        c.dave.mls.init(channelId)
        val kp = MLSInputStream.decode(c.dave.mls.keyPackage(), KeyPackage::class.java) as KeyPackage
        val otherKey = gw.suite.serializeSignaturePrivateKey(gw.suite.generateSignatureKeyPair().private)
        val forged = MLSMessage.externalProposal(gw.suite, gw.groupId, gw.epoch, Proposal.add(kp), 0, otherKey)
        a.dave.onProposals(byteArrayOf(0) + MLSOutputStream.encode(VectorOf(listOf(forged))))
        assertTrue("no commit for a forged proposal", gw.queue.isEmpty())
        // an add for a user the gateway never announced is refused too
        val d = Client(4L, gw)
        d.dave.mls.setExternalSender(gw.externalSender)
        d.dave.mls.init(channelId)
        val kp4 = MLSInputStream.decode(d.dave.mls.keyPackage(), KeyPackage::class.java) as KeyPackage
        val unknown = MLSMessage.externalProposal(gw.suite, gw.groupId, gw.epoch, Proposal.add(kp4), 0, gw.sigPrivForTests)
        a.dave.onProposals(byteArrayOf(0) + MLSOutputStream.encode(VectorOf(listOf(unknown))))
        assertTrue("no commit for an unexpected user", gw.queue.isEmpty())
        assertMediaFlows(listOf(a, b))
    }

    @Test
    fun revokedProposalsAreNotCommitted() {
        val gw = FakeGateway()
        val a = Client(1L, gw)
        val b = Client(2L, gw)
        gw.connect(a); gw.pump()
        gw.connect(b); gw.pump()
        val c = Client(3L, gw)
        a.dave.onClientsConnect(listOf(3L))
        c.dave.mls.setExternalSender(gw.externalSender)
        c.dave.mls.init(channelId)
        val kp = MLSInputStream.decode(c.dave.mls.keyPackage(), KeyPackage::class.java) as KeyPackage
        val add = MLSMessage.externalProposal(gw.suite, gw.groupId, gw.epoch, Proposal.add(kp), 0, gw.sigPrivForTests)
        a.dave.onProposals(byteArrayOf(0) + MLSOutputStream.encode(VectorOf(listOf(add))))
        assertEquals("append produces a commit", 1, gw.queue.size)
        gw.queue.clear()
        val ref = TestRefs.proposalRef(gw.suite, add)
        val revoke = ByteArrayOutputStream().apply {
            write(1)
            write(ref.size + 1) // vector length (single byte varint: < 64)
            write(ref.size)
            write(ref)
        }.toByteArray()
        a.dave.onProposals(revoke)
        assertTrue("nothing left to commit after the revoke", gw.queue.isEmpty())
        assertMediaFlows(listOf(a, b))
    }
}
