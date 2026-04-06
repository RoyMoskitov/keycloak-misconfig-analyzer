package scanners.keycloak_security.scanner.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class ExplicitConsentCheck : SecurityCheck {

    override fun id() = "10.7.1"
    override fun title() = "Явное согласие пользователя"
    override fun description() =
        "Проверка, что клиенты требуют явного согласия пользователя (ASVS V10.7.1)"
    override fun severity() = Severity.MEDIUM

    companion object {
        // Внутренние и first-party клиенты Keycloak — consent не требуется по дизайну
        val INTERNAL_CLIENTS = setOf(
            "account", "account-console", "admin-cli",
            "broker", "realm-management", "security-admin-console"
        )
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        // ASVS V10.7.1: "if the identity of the client cannot be assured,
        // the authorization server must always explicitly prompt the user for consent."
        // Для confidential first-party клиентов consent не обязателен.
        // Для public и third-party клиентов — обязателен.

        context.adminService.getClients().forEach { client ->
            if (client.clientId in INTERNAL_CLIENTS) return@forEach
            if (client.protocol != "openid-connect") return@forEach
            // Bearer-only и service-account-only клиенты не взаимодействуют с пользователем
            if (client.isBearerOnly == true) return@forEach
            if (client.isStandardFlowEnabled != true && client.isImplicitFlowEnabled != true) return@forEach

            if (client.isConsentRequired != true) {
                // Public client без consent — более серьёзная проблема
                val severity = if (client.isPublicClient == true) Severity.MEDIUM else Severity.LOW

                findings += Finding(
                    id = id(),
                    title = "Клиент '${client.clientId}' не требует согласия пользователя",
                    description = if (client.isPublicClient == true)
                        "Public client '${client.clientId}' не требует consent. " +
                                "Public clients не могут подтвердить свою идентичность (нет client_secret), " +
                                "поэтому consent обязателен."
                    else
                        "Confidential client '${client.clientId}' не требует consent. " +
                                "Для first-party доверенных клиентов это допустимо, " +
                                "но для third-party клиентов consent должен быть включён.",
                    severity = severity,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    clientId = client.clientId,
                    evidence = listOf(
                        Evidence("clientId", client.clientId),
                        Evidence("consentRequired", false),
                        Evidence("publicClient", client.isPublicClient ?: false)
                    ),
                    recommendation = "Включите Consent Required для клиента '${client.clientId}'"
                )
            }
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
