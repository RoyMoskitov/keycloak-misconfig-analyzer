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

                val authMethod = client.clientAuthenticatorType ?: ""

                if (authMethod.isEmpty()) {
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
                } else if (authMethod in listOf("client-secret", "client-secret-post")) {
                    val severity = if (client.isServiceAccountsEnabled == true) Severity.MEDIUM else Severity.LOW
                    findings += Finding(
                        id = id(),
                        title = "Confidential client '${client.clientId}' использует shared secret",
                        description = "Клиент '${client.clientId}' аутентифицируется методом '$authMethod'. " +
                                "Shared secret подвержен утечке и не обеспечивает защиту от replay-атак. " +
                                "ASVS V10.4.10 рекомендует методы на основе public-key криптографии.",
                        severity = severity,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(
                            Evidence("clientId", client.clientId),
                            Evidence("clientAuthenticatorType", authMethod),
                            Evidence("serviceAccountEnabled", client.isServiceAccountsEnabled == true)
                        ),
                        recommendation = "Переключите на 'private_key_jwt' или 'client-x509' для стойкой аутентификации"
                    )
                }
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
