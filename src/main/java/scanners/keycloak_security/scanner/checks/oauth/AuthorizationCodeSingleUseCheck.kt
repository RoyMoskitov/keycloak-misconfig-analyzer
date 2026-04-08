package scanners.keycloak_security.scanner.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

/**
 * ASVS V10.4.2: "authorization code can be used only once for a token request."
 *
 * Keycloak гарантирует single-use authorization code по умолчанию —
 * это встроенное поведение, которое нельзя отключить через конфигурацию.
 *
 * Проверяем только то, что Standard Flow (Authorization Code Flow) используется
 * вместо устаревших flows, которые не имеют concept одноразового кода.
 */
@Component
class AuthorizationCodeSingleUseCheck : SecurityCheck {

    override fun id() = "10.4.2"
    override fun title() = "Authorization code single-use"
    override fun description() =
        "Проверка одноразового использования authorization code (ASVS V10.4.2)"
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

        // Keycloak обеспечивает single-use auth code by design.
        // Проверяем, что клиенты используют Authorization Code Flow (standard flow),
        // а не Implicit Flow, который выдаёт токены напрямую без одноразового кода.
        context.adminService.getClients().forEach { client ->
            if (client.clientId in INTERNAL_CLIENTS) return@forEach

            if (client.isImplicitFlowEnabled == true && client.isStandardFlowEnabled != true) {
                findings += Finding(
                    id = id(),
                    title = "Клиент '${client.clientId}' не использует Authorization Code Flow",
                    description = "У клиента включён только Implicit Flow, который выдаёт токены " +
                            "напрямую без одноразового authorization code. " +
                            "ASVS V10.4.2 требует модель с одноразовым кодом.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    clientId = client.clientId,
                    evidence = listOf(
                        Evidence("implicitFlowEnabled", true),
                        Evidence("standardFlowEnabled", client.isStandardFlowEnabled ?: false)
                    ),
                    recommendation = "Включите Standard Flow и отключите Implicit Flow"
                )
            }
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
