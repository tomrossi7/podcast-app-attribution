// Minting a Verified App Attribution token in Kotlin. JDK classes only, so it runs on the JVM
// and on Android (API 26 or later); drop this file into an app.
//
//     val token = Attribution.mint(key, kid = "2026-11", iss = "https://exampleplayer.com", url = url)
//     val request = Request.Builder().url(Attribution.attach(url, token)).build()
//
// Leave `url` out for a session token that can be attached to any request until it expires.
//
// Where the key lives is up to you. The specification asks that signing keys be protected from
// extraction; minting on infrastructure you control and handing the token to the app is one way.

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.util.Base64

object Attribution {
    // CWT and CAT claim labels (IANA CWT Claims registry).
    private const val ISS = 1
    private const val AUD = 3
    private const val EXP = 4
    private const val IAT = 6
    private const val CTI = 7
    private const val CATV = 310
    private const val CATU = 312
    private const val CATM = 313

    // COSE header labels and the ES256 algorithm value.
    private const val ALG = 1
    private const val KID = 4
    private const val ES256 = -7

    fun mint(
        key: PrivateKey,
        kid: String,
        iss: String,
        url: String? = null,
        methods: List<String> = listOf("GET", "HEAD"),
        aud: String? = null,
        lifetime: Long = 300,
        now: Long = System.currentTimeMillis() / 1000,
    ): String {
        val claims = linkedMapOf<Any, Any>(
            ISS to iss,
            EXP to now + lifetime,
            IAT to now,
            CTI to ByteArray(16).also { SecureRandom().nextBytes(it) },
            CATV to 1,
        )
        if (aud != null) claims[AUD] = aud
        if (url != null) {
            claims[CATU] = exactUrl(url)
            claims[CATM] = methods
        }

        // COSE_Sign1 (RFC 9052 §4.2): [protected header as bytes, unprotected header, payload, signature].
        // The signature covers the Sig_structure of §4.4 with empty external data.
        val protectedHeader = cbor(linkedMapOf(ALG to ES256, KID to kid.toByteArray()))
        val payload = cbor(claims)
        val toBeSigned = cbor(listOf("Signature1", protectedHeader, ByteArray(0), payload))
        val der = Signature.getInstance("SHA256withECDSA").run {
            initSign(key)
            update(toBeSigned)
            sign()
        }
        val token = cbor(Tagged(18, listOf(protectedHeader, emptyMap<Any, Any>(), payload, derToRaw(der))))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token)
    }

    /** Appends the token, leaving the URL alone if it already carries one. */
    fun attach(url: String, token: String): String {
        val query = split(url).query
        if (extractTokens(query).first.isNotEmpty()) return url
        return url + (if (query == null) "?" else "&") + "CAT=" + token
    }

    /** A P-256 private key from a JWK's "d" value. */
    fun privateKey(d: String): PrivateKey {
        val curve = AlgorithmParameters.getInstance("EC")
            .apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(ECParameterSpec::class.java)
        val scalar = BigInteger(1, Base64.getUrlDecoder().decode(d))
        return KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(scalar, curve))
    }

    /**
     * A catu that matches exactly this URL: scheme, host, path and query, after removing any CAT
     * parameter and normalizing. Port is left out, so any port matches.
     */
    private fun exactUrl(url: String): Map<Any, Any> {
        val parts = split(url)
        val n = normalize(parts.copy(query = extractTokens(parts.query).second))
        fun exact(value: String) = linkedMapOf<Any, Any>(0 to value)
        return linkedMapOf(0 to exact(n.scheme), 1 to exact(n.host), 3 to exact(n.path), 4 to exact(n.query ?: ""))
    }

    /** Java signs in DER: SEQUENCE { INTEGER r, INTEGER s }. COSE wants r then s, 32 bytes each. */
    private fun derToRaw(der: ByteArray): ByteArray {
        var position = 2 // past the SEQUENCE tag and its one-byte length
        fun integer(): ByteArray {
            val length = der[position + 1].toInt()
            val value = der.copyOfRange(position + 2, position + 2 + length).dropWhile { it == 0.toByte() }
            position += 2 + length
            return ByteArray(32 - value.size) + value
        }
        return integer() + integer()
    }

    // --- CBOR -----------------------------------------------------------------------------------
    // The subset of CBOR (RFC 8949) a token uses, encoded deterministically.

    private class Tagged(val tag: Long, val value: Any)

    private fun cbor(value: Any?): ByteArray = ByteArrayOutputStream().also { write(it, value) }.toByteArray()

    private fun write(out: ByteArrayOutputStream, value: Any?) {
        when (value) {
            is Int -> write(out, value.toLong())
            is Long -> if (value >= 0) head(out, 0, value) else head(out, 1, -1 - value)
            is ByteArray -> {
                head(out, 2, value.size.toLong())
                out.write(value)
            }
            is String -> {
                val utf8 = value.toByteArray()
                head(out, 3, utf8.size.toLong())
                out.write(utf8)
            }
            is List<*> -> {
                head(out, 4, value.size.toLong())
                value.forEach { write(out, it) }
            }
            is Map<*, *> -> {
                head(out, 5, value.size.toLong())
                value.forEach { (k, v) ->
                    write(out, k)
                    write(out, v)
                }
            }
            is Tagged -> {
                head(out, 6, value.tag)
                write(out, value.value)
            }
            else -> throw IllegalArgumentException("cannot encode $value")
        }
    }

    /** The initial byte: major type in the top 3 bits, then the argument in its shortest form. */
    private fun head(out: ByteArrayOutputStream, major: Int, n: Long) {
        val m = major shl 5
        val (info, size) = when {
            n < 24 -> n.toInt() to 0
            n < 0x100 -> 24 to 1
            n < 0x10000 -> 25 to 2
            n < 0x100000000 -> 26 to 4
            else -> 27 to 8
        }
        out.write(m or info)
        for (shift in (size - 1) downTo 0) out.write((n shr (8 * shift)).toInt() and 0xff)
    }

    // --- URLs -----------------------------------------------------------------------------------
    // Handled as strings on purpose: URI and HttpUrl rewrite what they parse.

    private data class Parts(val scheme: String, val host: String, val port: String, val path: String, val query: String?)

    private val URL = Regex("""^(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?""")
    private val HOST_PORT = Regex("""^(\[[^\]]*]|[^:]*)(?::(.*))?$""")
    private val ESCAPE = Regex("%([0-9a-fA-F]{2})")

    /** RFC 3986 Appendix B, plus the authority split into host and port. */
    private fun split(url: String): Parts {
        val m = URL.find(url)!!
        val authority = (m.groups[2]?.value ?: "").substringAfterLast('@')
        val hostPort = HOST_PORT.find(authority)!!
        return Parts(
            scheme = m.groups[1]?.value ?: "",
            host = hostPort.groupValues[1],
            port = hostPort.groups[2]?.value ?: "",
            path = m.groupValues[3],
            query = m.groups[4]?.value,
        )
    }

    /**
     * The values of the CAT parameters in a query, and the query without them. The query is split
     * on "&"; a name is everything before the first "=", percent-decoded once.
     */
    private fun extractTokens(query: String?): Pair<List<String>, String?> {
        if (query == null) return emptyList<String>() to null
        val (tokens, rest) = query.split("&").partition { field ->
            ESCAPE.replace(field.substringBefore('=')) { it.groupValues[1].toInt(16).toChar().toString() } == "CAT"
        }
        return tokens.map { it.substringAfter('=', "") } to rest.joinToString("&").takeIf { rest.isNotEmpty() }
    }

    /** RFC 9110 §4.2.3, then RFC 3986 §6.2.2 and §6.2.3. */
    private fun normalize(parts: Parts): Parts {
        val scheme = parts.scheme.lowercase()
        val defaultPort = mapOf("http" to "80", "https" to "443")[scheme]
        return Parts(
            scheme = scheme,
            host = percentNormalize(parts.host).lowercase(),
            port = if (parts.port == defaultPort) "" else parts.port,
            path = removeDotSegments(percentNormalize(parts.path)).ifEmpty { "/" },
            query = parts.query?.let(::percentNormalize),
        )
    }

    /**
     * Uppercase the hex digits of percent-escapes and decode the ones that stand for unreserved
     * characters (letters, digits, "-", ".", "_", "~").
     */
    private fun percentNormalize(text: String): String = ESCAPE.replace(text) { escape ->
        val char = escape.groupValues[1].toInt(16).toChar()
        if (char in 'a'..'z' || char in 'A'..'Z' || char in '0'..'9' || char in "-._~") char.toString() else escape.value.uppercase()
    }

    /** RFC 3986 §5.2.4. */
    private fun removeDotSegments(path: String): String {
        var input = path
        val out = ArrayDeque<String>()
        while (input.isNotEmpty()) {
            when {
                input.startsWith("../") -> input = input.drop(3)
                input.startsWith("./") || input.startsWith("/./") -> input = input.drop(2)
                input == "/." -> input = "/"
                input.startsWith("/../") -> {
                    input = input.drop(3)
                    out.removeLastOrNull()
                }
                input == "/.." -> {
                    input = "/"
                    out.removeLastOrNull()
                }
                input == "." || input == ".." -> input = ""
                else -> {
                    val end = input.indexOf('/', 1).let { if (it == -1) input.length else it }
                    out.addLast(input.take(end))
                    input = input.drop(end)
                }
            }
        }
        return out.joinToString("")
    }
}
