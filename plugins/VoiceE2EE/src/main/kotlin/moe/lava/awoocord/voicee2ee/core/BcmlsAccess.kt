package moe.lava.awoocord.voicee2ee.core

import org.bouncycastle.mls.codec.Capabilities
import org.bouncycastle.mls.codec.FramedContent
import org.bouncycastle.mls.codec.PublicMessage
import org.bouncycastle.mls.codec.Welcome
import org.bouncycastle.mls.protocol.CachedProposal
import org.bouncycastle.mls.protocol.Group
import java.lang.reflect.Field

/**
 * The few non-public bcmls members DAVE needs. Reflection rather than a same-package helper because bcmls is a signed
 * jar on the JVM (tests); bcmls is bundled un-obfuscated (see bundle-rules.pro), so the names are stable.
 */
internal object BcmlsAccess {
    private fun field(c: Class<*>, name: String): Field = c.getDeclaredField(name).apply { isAccessible = true }

    private val publicContent by lazy { field(PublicMessage::class.java, "content") }
    private val capSuites by lazy { field(Capabilities::class.java, "cipherSuites") }
    private val capCredentials by lazy { field(Capabilities::class.java, "credentials") }
    private val welcomeSecrets by lazy { field(Welcome::class.java, "secrets") }
    private val groupPending by lazy { field(Group::class.java, "pendingProposals") }
    private val cachedRef by lazy { field(CachedProposal::class.java, "proposalRef") }

    const val CREDENTIAL_BASIC: Short = 1

    fun content(message: PublicMessage): FramedContent = publicContent.get(message) as FramedContent

    /** DAVE leaf capabilities: ciphersuite 2 only and basic credentials only (as libdave advertises). */
    fun restrict(capabilities: Capabilities, cipherSuite: Short) {
        capSuites.set(capabilities, arrayListOf(cipherSuite))
        capCredentials.set(capabilities, arrayListOf(CREDENTIAL_BASIC))
    }

    fun welcomeSecretCount(welcome: Welcome): Int = (welcomeSecrets.get(welcome) as List<*>).size

    @Suppress("UNCHECKED_CAST")
    fun pendingProposals(g: Group): MutableList<Any> = groupPending.get(g) as MutableList<Any>

    fun proposalRef(cached: Any): ByteArray = cachedRef.get(cached) as ByteArray
}
