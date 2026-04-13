package scanners.keycloak_security.scanner.checks.tokens

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.service.JwtParser
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper.createErrorResult

@Component
class JwtSignaturePresenceCheck : SecurityCheck {

    override fun id() = "9.1.1"
    override fun title() = "Наличие криптографической подписи JWT"
    override fun description() =
        "Проверка, что self-contained токены подписываются и не используют alg=none"
    override fun severity() = Severity.HIGH

    companion object {
        val SYMMETRIC_ALGORITHMS = setOf(
            "HS256", "HS384", "HS512"
        )
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        return try {
            val token = context.adminService.getAccessToken().accessToken
            val header = JwtParser.parseHeader(token)

            val alg = header["alg"]?.toString()

            if (alg == null) {
                findings += Finding(
                    id(),
                    "Алгоритм подписи не указан",
                    "JWT не содержит заголовок 'alg'",
                    Severity.HIGH,
                    CheckStatus.DETECTED,
                    context.realmName,
                    recommendation =
                        "Убедитесь, что токены подписываются с использованием криптографического алгоритма."
                )
            } else if (alg.equals("none", ignoreCase = true)) {
                findings += Finding(
                    id(),
                    "Используется alg=none",
                    "JWT подписан с использованием небезопасного алгоритма 'none'",
                    Severity.HIGH,
                    CheckStatus.DETECTED,
                    context.realmName,
                    evidence = listOf(Evidence("alg", alg)),
                    recommendation =
                        "Запретите использование алгоритма 'none'. Используйте RS256 или ES256."
                )
            }

            // Проверяем per-client override алгоритма подписи
            val clients = context.adminService.getClients()
            val internalClients = setOf(
                "account", "account-console", "admin-cli",
                "broker", "realm-management", "security-admin-console"
            )
            clients.forEach { client ->
                if (client.clientId in internalClients) return@forEach
                if (client.clientId?.endsWith("-realm") == true) return@forEach

                val attrs = client.attributes ?: emptyMap()
                val clientAlg = attrs["access.token.signed.response.alg"] ?: ""
                if (clientAlg.uppercase() in SYMMETRIC_ALGORITHMS) {
                    findings += Finding(
                        id(),
                        "Клиент '${client.clientId}' использует симметричную подпись токенов",
                        "Клиент '${client.clientId}' переопределяет алгоритм подписи на '$clientAlg'. " +
                                "Симметричный алгоритм (HMAC) означает, что любой, кто знает shared secret, " +
                                "может подделать access token.",
                        Severity.MEDIUM,
                        CheckStatus.DETECTED,
                        context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(
                            Evidence("clientId", client.clientId),
                            Evidence("access.token.signed.response.alg", clientAlg)
                        ),
                        recommendation = "Используйте асимметричный алгоритм (RS256, ES256) для подписи токенов"
                    )
                }
            }

            CheckResult(
                checkId = id(),
                status = if (findings.isEmpty()) CheckStatus.OK else CheckStatus.DETECTED,
                findings = findings,
                durationMs = System.currentTimeMillis() - start
            )

        } catch (e: Exception) {
            createErrorResult(id(), title(), e, start, context.realmName)
        }
    }
}
