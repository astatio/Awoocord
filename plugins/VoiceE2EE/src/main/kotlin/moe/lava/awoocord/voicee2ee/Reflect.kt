package moe.lava.awoocord.voicee2ee

import java.lang.reflect.Field
import java.lang.reflect.Method
import java.util.concurrent.ConcurrentHashMap

/**
 * Field/method access by obfuscated name. The Discord jar plugins compile against is "publicized", but members can
 * be private in the real app, so anything not part of a public API goes through here.
 */
internal object Reflect {
    private val fields = ConcurrentHashMap<String, Field>()
    private val methods = ConcurrentHashMap<String, Method>()

    private fun field(c: Class<*>, name: String): Field = fields.getOrPut(c.name + "#" + name) {
        var k: Class<*>? = c
        while (k != null) {
            try {
                return@getOrPut k.getDeclaredField(name).apply { isAccessible = true }
            } catch (_: NoSuchFieldException) {
                k = k.superclass
            }
        }
        throw NoSuchFieldException("${c.name}.$name")
    }

    fun get(o: Any, name: String): Any? = field(o.javaClass, name).get(o)

    fun getLong(o: Any, name: String): Long = field(o.javaClass, name).getLong(o)

    fun set(o: Any, name: String, v: Any?) = field(o.javaClass, name).set(o, v)

    fun method(c: Class<*>, name: String, vararg params: Class<*>): Method =
        methods.getOrPut(c.name + "#" + name + params.joinToString(",") { it.name }) {
            c.getDeclaredMethod(name, *params).apply { isAccessible = true }
        }
}
