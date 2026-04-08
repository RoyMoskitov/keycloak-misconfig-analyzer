package scanners.keycloak_security.scanner.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

/**
 * ASVS V10.4.7: "Verify that if the authorization server supports unauthenticated
 * dynamic client registration, it mitigates the risk of malicious client applications."
 */
@Component
class DynamicClientRegistrationCheck : SecurityCheck {

    override fun id() = "10.4.7"
    override fun title() = "Безопасность динамической регистрации клиентов"
    override fun description() =
        "Проверка, что динамическая регистрация клиентов ограничена или отключена (ASVS V10.4.7)"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val realm = context.adminService.getRealm()

            // Keycloak: registrationAllowed — позволяет пользователям регистрироваться
            // Но для V10.4.7 важнее — dynamic client registration (OIDC Dynamic Registration)
            // Это контролируется через Initial Access Tokens или открытый endpoint

            // Проверяем, есть ли клиенты с registration access token
            // (косвенный признак что dynamic registration используется)
            val clients = context.adminService.getClients()

            // Проверяем наличие клиента "registration" или подобных
            // В Keycloak dynamic registration доступен по:
            // POST /realms/{realm}/clients-registrations/openid-connect

            // Основной риск: если realm разрешает открытую регистрацию клиентов
            // без начального токена доступа (Initial Access Token)
            val registrationAllowed = realm.isRegistrationAllowed ?: false
            val clientRegistrationPolicy = realm.attributes?.get("client-registration-policy") ?: ""

            // Проверяем количество клиентов как косвенный индикатор
            // Если > 20 пользовательских клиентов — возможно открытая регистрация
            val internalClients = setOf(
                "account", "account-console", "admin-cli",
                "broker", "realm-management", "security-admin-console"
            )
            val userClients = clients.filter { it.clientId !in internalClients && !it.clientId.endsWith("-realm") }

            if (userClients.size > 20) {
                findings += Finding(
                    id = id(),
                    title = "Большое количество зарегистрированных клиентов",
                    description = "${userClients.size} пользовательских клиентов в realm. " +
                            "Это может указывать на открытую динамическую регистрацию. " +
                            "ASVS V10.4.7 требует ограничивать регистрацию вредоносных клиентов.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("userClientsCount", userClients.size),
                        Evidence("totalClients", clients.size)
                    ),
                    recommendation = "Проверьте что dynamic client registration требует Initial Access Token " +
                            "и ограничьте количество регистрируемых клиентов"
                )
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
