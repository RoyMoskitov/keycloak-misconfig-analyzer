package scanners.keycloak_security.scanner.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class PkceEnforcementCheck : SecurityCheck {

    override fun id() = "10.2.1"
    override fun title() = "PKCE enforcement"
    override fun description() = "Проверка использования PKCE (S256) для OAuth Authorization Code Flow (ASVS V10.2.1)"
    override fun severity() = Severity.HIGH

    companion object {
        // Внутренние клиенты Keycloak, которые не используют Authorization Code Flow
        val INTERNAL_CLIENTS = setOf(
            "account", "account-console", "admin-cli",
            "broker", "realm-management", "security-admin-console"
        )
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        context.adminService.getClients().forEach { client ->
            // Пропускаем внутренние клиенты и realm-management клиенты (*-realm)
            if (client.clientId in INTERNAL_CLIENTS) return@forEach
            if (client.clientId?.endsWith("-realm") == true) return@forEach
            if (client.isStandardFlowEnabled != true) return@forEach

            val attrs = client.attributes ?: emptyMap()
            val pkceMethod = attrs["pkce.code.challenge.method"]

            if (client.isPublicClient == true) {
                // Для public clients PKCE S256 обязателен (ASVS V10.4.6)
                if (pkceMethod != "S256") {
                    findings += Finding(
                        id = id(),
                        title = "PKCE не настроен для public client",
                        description = "Public client '${client.clientId}' использует Authorization Code Flow " +
                                "без PKCE S256. Public clients не имеют client_secret, поэтому PKCE — " +
                                "единственная защита от перехвата authorization code.",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(
                            Evidence("pkce.code.challenge.method", pkceMethod ?: "not set"),
                            Evidence("publicClient", true)
                        ),
                        recommendation = "Установите pkce.code.challenge.method = S256 для клиента '${client.clientId}'"
                    )
                }
            } else {
                // Для confidential clients PKCE рекомендуется (OAuth 2.1 требует PKCE для всех)
                if (pkceMethod != "S256") {
                    findings += Finding(
                        id = id(),
                        title = "PKCE не настроен дл�� confidential client",
                        description = "Confidential client '${client.clientId}' не использует PKCE. " +
                                "OAuth 2.1 рекомендует PKCE для всех клиентов как дополнительный " +
                                "уровень защиты от CSRF и code injection атак.",
                        severity = Severity.LOW,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(
                            Evidence("pkce.code.challenge.method", pkceMethod ?: "not set"),
                            Evidence("publicClient", false)
                        ),
                        recommendation = "Рассмотрите включение PKCE S256 для клиента '${client.clientId}'"
                    )
                }
            }
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
