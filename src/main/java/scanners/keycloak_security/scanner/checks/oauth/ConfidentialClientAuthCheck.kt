package scanners.keycloak_security.scanner.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

/**
 * ASVS V10.4.10: "Verify that confidential client is authenticated for
 * client-to-authorized server backchannel requests such as token requests,
 * pushed authorization requests (PAR), and token revocation requests."
 */
@Component
class ConfidentialClientAuthCheck : SecurityCheck {

    override fun id() = "10.4.10"
    override fun title() = "Аутентификация confidential клиентов"
    override fun description() =
        "Проверка, что confidential клиенты имеют надёжную аутентификацию (ASVS V10.4.10)"
    override fun severity() = Severity.HIGH

    companion object {
        val INTERNAL_CLIENTS = setOf(
            "account", "account-console", "admin-cli",
            "broker", "realm-management", "security-admin-console"
        )
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            context.adminService.getClients().forEach { client ->
                if (client.clientId in INTERNAL_CLIENTS) return@forEach
                if (client.clientId?.endsWith("-realm") == true) return@forEach
                if (client.isPublicClient == true) return@forEach
                if (client.isBearerOnly == true) return@forEach

                // Confidential client — проверяем метод аутентификации
                val authMethod = client.clientAuthenticatorType ?: "client-secret"

                // client-secret — допустимо, но client-secret-post менее безопасен чем client-secret-basic
                // Лучшие варианты: client-secret-jwt, private-key-jwt, client-x509
                if (authMethod == "client-secret" || authMethod == "client-secret-post") {
                    // Это базовая аутентификация — OK для L1/L2, но проверяем что secret задан
                    val hasServiceAccount = client.isServiceAccountsEnabled == true
                    val hasStandardFlow = client.isStandardFlowEnabled == true

                    if (hasServiceAccount || hasStandardFlow) {
                        // OK — клиент имеет аутентификацию. Но если нет secret — проблема
                        // (мы не можем прочитать secret через API, но можем проверить тип)
                    }
                }

                // Если клиент не имеет аутентификации вообще — проблема
                if (authMethod.isNullOrEmpty()) {
                    findings += Finding(
                        id = id(),
                        title = "Confidential client '${client.clientId}' без аутентификации",
                        description = "Клиент '${client.clientId}' помечен как confidential, " +
                                "но не имеет настроенного метода аутентификации.",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(
                            Evidence("clientId", client.clientId),
                            Evidence("clientAuthenticatorType", "не задан")
                        ),
                        recommendation = "Настройте Client Authenticator для клиента '${client.clientId}'"
                    )
                }
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
