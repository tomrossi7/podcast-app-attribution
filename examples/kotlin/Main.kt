// Mints a token with a private JWK and prints the URL to request, or the bare token for a
// session token.
//
//     kotlinc Attribution.kt Main.kt -include-runtime -d attribution.jar
//     java -jar attribution.jar <private-keys.json> <kid> <iss> [url]

import java.io.File
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    if (args.size < 3) {
        System.err.println("usage: java -jar attribution.jar <private-keys.json> <kid> <iss> [url]")
        exitProcess(2)
    }
    val (file, kid, iss) = args
    val url = args.getOrNull(3)

    // Enough JSON reading for a sample key file: find the key object naming this kid and take its "d".
    val jwk = Regex("""\{[^{}]*\}""").findAll(File(file).readText()).map { it.value }
        .first { Regex(""""kid"\s*:\s*"${Regex.escape(kid)}"""").containsMatchIn(it) }
    val d = Regex(""""d"\s*:\s*"([^"]+)"""").find(jwk)!!.groupValues[1]

    val token = Attribution.mint(Attribution.privateKey(d), kid = kid, iss = iss, url = url)
    println(if (url != null) Attribution.attach(url, token) else token)
}
