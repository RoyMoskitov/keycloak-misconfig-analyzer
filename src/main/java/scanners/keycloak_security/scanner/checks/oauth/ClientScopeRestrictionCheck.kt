package scanners.keycloak_security.scanner.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

/**
 * ASVS V10.4.11: "Verify that the authorization server configuration
 * only assigns the required scopes to the OAuth client."
 */
@Component
class ClientScopeRestrictionCheck : SecurityCheck {

    override fun id() = "10.4.11"
    override fun title() = "Минимальные scopes для клиентов"
    override fun description() =
        "Проверка, что клиентам назначены только необходимые scopes (ASVS V10.4.11)"
    override fun severity() = Severity.MEDIUM

    companion object {
        val INTERNAL_CLIENTS = setOf(
            "account", "account-console", "admin-cli",
            "broker", "realm-management", "security-admin-console"
        )

        // Типичные scopes, которые могут быть избыточными для простых клиентов
        val POTENTIALLY_EXCESSIVE_SCOPES = setOf(
            "offline_access"  // даёт offline tokens — должен быть только при необходимости
        )
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            context.adminService.getClients().forEach { client ->
                if (client.clientId in INTERNAL_CLIENTS) return@forEach
                if (client.clientId?.endsWith("-realm") == true) return@forEach
                if (client.isBearerOnly == true) return@forEach

                val defaultScopes = client.defaultClientScopes ?: emptyList()
                val optionalScopes = client.optionalClientScopes ?: emptyList()
                val allScopes = defaultScopes + optionalScopes

                // Проверяем offline_access в default scopes (не optional)
                if ("offline_access" in defaultScopes) {
                    findings += Finding(
                        id = id(),
                        title = "offline_access как default scope для '${client.clientId}'",
                        description = "Клиент '${client.clientId}' имеет 'offline_access' в default scopes. " +
                                "Это означает, что КАЖДЫЙ token request получает offline token, " +
                                "который не истекает при закрытии сессии.",
                        severity = Severity.MEDIUM,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(
                            Evidence("clientId", client.clientId),
                            Evidence("defaultScopes", defaultScopes.joinToString()),
                            Evidence("offlineAccessLocation", "default (should be optional)")
                        ),
                        recommendation = "Переместите 'offline_access' из Default Scopes в Optional Scopes, " +
                                "чтобы offline токены выдавались только по явному запросу"
                    )
                }

                // Проверяем избыточное количество default scopes (> 10)
                if (defaultScopes.size > 10) {
                    findings += Finding(
                        id = id(),
                        title = "Много default scopes для '${client.clientId}'",
                        description = "Клиент '${client.clientId}' имеет ${defaultScopes.size} default scopes. " +
                                "Каждый default scope включается в каждый token request. " +
                                "Принцип least privilege требует минимальный набор scopes.",
                        severity = Severity.LOW,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(
                            Evidence("clientId", client.clientId),
                            Evidence("defaultScopesCount", defaultScopes.size),
                            Evidence("defaultScopes", defaultScopes.joinToString())
                        ),
                        recommendation = "Пересмотрите список default scopes, оставьте только необходимые"
                    )
                }
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
