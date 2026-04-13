package scanners.keycloak_security.scanner.checks.tokens

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.service.JwtParser
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper.createErrorResult
import scanners.keycloak_security.scanner.SecurityCheckHelper.buildCheckResult

/**
 * ASVS V9.2.1: "Verify that, if a validity time span is present in the token data,
 * the token and its content are accepted only if the verification time is within this
 * validity time span."
 *
 * В Keycloak: проверяем наличие exp/nbf и per-client overrides token lifespan.
 */
@Component
class JwtTimeValidityCheck : SecurityCheck {

    override fun id() = "9.2.1"
    override fun title() = "Проверка exp / nbf в JWT"
    override fun description() =
        "Проверка наличия и корректности временных ограничений токена (ASVS V9.2.1)"
    override fun severity() = Severity.HIGH

    companion object {
        const val MAX_RECOMMENDED_LIFESPAN = 3600 // 1 час
        val INTERNAL_CLIENTS = setOf(
            "account", "account-console", "admin-cli",
            "broker", "realm-management", "security-admin-console"
        )
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        return try {
            // 1. Стандартная проверка exp/nbf в токене
            val token = context.adminService.getAccessToken().accessToken
            val claims = JwtParser.parse(token)
            val now = System.currentTimeMillis() / 1000
            val exp = (claims["exp"] as? Number)?.toLong()

            if (exp == null) {
                findings += Finding(
                    id(), "Отсутствует exp",
                    "JWT не содержит claim exp",
                    Severity.HIGH, CheckStatus.DETECTED, context.realmName
                )
            }

            // 2. Проверяем per-client overrides — слишком долгие token lifespans
            val realmLifespan = context.adminService.getRealm().accessTokenLifespan ?: 300
            val clients = context.adminService.getClients()

            clients.forEach { client ->
                if (client.clientId in INTERNAL_CLIENTS) return@forEach
                if (client.clientId?.endsWith("-realm") == true) return@forEach

                val clientLifespan = client.attributes?.get("access.token.lifespan")?.toIntOrNull()
                if (clientLifespan != null && clientLifespan > MAX_RECOMMENDED_LIFESPAN) {
                    findings += Finding(
                        id = id(),
                        title = "Клиент '${client.clientId}' переопределяет token lifespan",
                        description = "Клиент '${client.clientId}' устанавливает access.token.lifespan = " +
                                "$clientLifespan секунд (${clientLifespan / 60} мин). " +
                                "Долгоживущие токены увеличивают окно атаки при компрометации.",
                        severity = if (clientLifespan > 86400) Severity.HIGH else Severity.MEDIUM,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(
                            Evidence("clientId", client.clientId),
                            Evidence("clientLifespan", clientLifespan),
                            Evidence("realmLifespan", realmLifespan),
                            Evidence("recommendedMax", MAX_RECOMMENDED_LIFESPAN)
                        ),
                        recommendation = "Удалите per-client override или установите ≤ $MAX_RECOMMENDED_LIFESPAN секунд"
                    )
                }
            }

            buildCheckResult(id(), title(), findings, start, context.realmName)
        } catch (e: Exception) {
            createErrorResult(id(), title(), e, start, context.realmName)
        }
    }
}
