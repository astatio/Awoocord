package moe.lava.awoocord.voicee2ee.core

import org.bouncycastle.mls.codec.AuthenticatedContent
import org.bouncycastle.mls.codec.MLSMessage
import org.bouncycastle.mls.codec.MLSOutputStream
import org.bouncycastle.mls.codec.PublicMessage
import org.bouncycastle.mls.codec.WireFormat
import org.bouncycastle.mls.crypto.MlsCipherSuite

/** RFC 9420 ProposalRef = RefHash("MLS 1.0 Proposal Reference", AuthenticatedContent). */
object TestRefs {
    fun proposalRef(suite: MlsCipherSuite, m: MLSMessage): ByteArray {
        val pm = m.publicMessage
        val authData = PublicMessage::class.java.getDeclaredField("auth").apply { isAccessible = true }.get(pm)
        val ctor = AuthenticatedContent::class.java.constructors.single { it.parameterTypes.size == 3 }
        val auth = ctor.newInstance(WireFormat.mls_public_message, BcmlsAccess.content(pm), authData) as AuthenticatedContent
        return suite.refHash(MLSOutputStream.encode(auth), "MLS 1.0 Proposal Reference")
    }
}
