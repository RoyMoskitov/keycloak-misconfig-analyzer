package scanners.keycloak_security.scanner.checks.tokens

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.service.JwtParser
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper.buildCheckResult
import scanners.keycloak_security.scanner.SecurityCheckHelper.createErrorResult

/**
 * ASVS V9.2.2: "Verify that the service receiving a token validates the token to be the
 * correct type and is meant for the intended purpose before accepting the token's contents.
 * For example, only access tokens can be accepted for authorization decisions and only ID
 * Tokens can be used for proving user authentication."
 *
 * В Keycloak: проверяем что authorization claims (roles, resource_access) не дублируются
 * в ID Token — это делает ID Token и Access Token взаимозаменяемыми, нарушая token type separation.
 */
@Component
class JwtTokenTypeCheck : SecurityCheck {

    override fun id() = "9.2.2"
    override fun title() = "Проверка разделения типов токенов"
    override fun description() =
        "Проверка, что access token и ID token имеют разные назначения и не взаимозаменяемы (ASVS V9.2.2)"
    override fun severity() = Severity.LOW

    companion object {
        val INTERNAL_CLIENTS = setOf(
            "account", "account-console", "admin-cli",
            "broker", "realm-management", "security-admin-console"
        )
        val AUTHORIZATION_CLAIM_NAMES = setOf(
            "realm_access", "resource_access", "groups",
            "roles", "authorities", "permissions", "scope"
        )
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        return try {
            // 1. Стандартная проверка typ
            val token = context.adminService.getAccessToken().accessToken
            val claims = JwtParser.parse(token)
            val typ = claims["typ"]?.toString()

            if (typ == null) {
                findings += Finding(
                    id(), "Тип токена не указан",
                    "JWT не содержит claim 'typ'.",
                    Severity.INFO, CheckStatus.DETECTED, context.realmName,
                    recommendation = "Рассмотрите явное указание типа токена."
                )
            }

            // 2. Проверяем protocol mappers — authorization claims в ID Token
            val clients = context.adminService.getClients()
            clients.forEach { client ->
                if (client.clientId in INTERNAL_CLIENTS) return@forEach
                if (client.clientId?.endsWith("-realm") == true) return@forEach

                val mappers = client.protocolMappers ?: return@forEach
                val authzMappersInIdToken = mappers.filter { mapper ->
                    val config = mapper.config ?: emptyMap()
                    val claimName = config["claim.name"] ?: mapper.name ?: ""
                    val inIdToken = config["id.token.claim"]?.toBoolean() ?: false
                    val inAccessToken = config["access.token.claim"]?.toBoolean() ?: false

                    inIdToken && inAccessToken && AUTHORIZATION_CLAIM_NAMES.any {
                        claimName.contains(it, ignoreCase = true)
                    }
                }

                if (authzMappersInIdToken.isNotEmpty()) {
                    findings += Finding(
                        id = id(),
                        title = "Authorization claims в ID Token клиента '${client.clientId}'",
                        description = "Клиент '${client.clientId}' включает authorization claims " +
                                "(${authzMappersInIdToken.joinToString { it.name ?: "?" }}) " +
                                "одновременно в Access Token и ID Token. Это делает токены " +
                                "взаимозаменяемыми — ID Token может быть использован для авторизации " +
                                "вместо Access Token, нарушая разделение token types.",
                        severity = Severity.LOW,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(
                            Evidence("clientId", client.clientId),
                            Evidence("mappers", authzMappersInIdToken.joinToString { "${it.name}: claim=${it.config?.get("claim.name")}" })
                        ),
                        recommendation = "Отключите id.token.claim для authorization mappers (roles, groups). " +
                                "ID Token предназначен для аутентификации, Access Token — для авторизации."
                    )
                }
            }

            buildCheckResult(id(), title(), findings, start, context.realmName)
        } catch (e: Exception) {
            createErrorResult(id(), title(), e, start, context.realmName)
        }
    }
}
