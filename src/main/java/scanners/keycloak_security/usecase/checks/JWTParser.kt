package scanners.keycloak_security.usecase.checks

import com.fasterxml.jackson.databind.ObjectMapper
import java.util.*

object JwtParser {

    private val mapper = ObjectMapper()

    fun parse(token: String): Map<String, Any> {
        val parts = token.split(".")
        require(parts.size == 3) { "Invalid JWT format" }

        val payload = String(Base64.getUrlDecoder().decode(parts[1]))
        return mapper.readValue(payload, Map::class.java) as Map<String, Any>
    }

    fun parseHeader(token: String): Map<String, Any> =
        decodePart(token, 0)

    private fun decodePart(token: String, index: Int): Map<String, Any> {
        val parts = token.split(".")
        require(parts.size >= 2) { "Invalid JWT format" }

        val json = String(
            java.util.Base64.getUrlDecoder().decode(parts[index])
        )

        @Suppress("UNCHECKED_CAST")
        return mapper
            .readValue(json, Map::class.java) as Map<String, Any>
    }
}
