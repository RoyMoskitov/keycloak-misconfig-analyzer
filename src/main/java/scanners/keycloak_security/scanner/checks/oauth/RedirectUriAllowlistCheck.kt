package scanners.keycloak_security.scanner.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class RedirectUriAllowlistCheck : SecurityCheck {

    override fun id() = "10.4.1"
    override fun title() = "Redirect URI allowlist"
    override fun description() = "Проверка строгой allowlist redirect URIs без wildcard и prefix matching (ASVS V10.4.1)"
    override fun severity() = Severity.HIGH

    companion object {
        // Внутренние клиенты Keycloak — redirect URIs управляются сервером
        val INTERNAL_CLIENTS = setOf(
            "account", "account-console", "admin-cli",
            "broker", "realm-management", "security-admin-console"
        )
        val SAFE_LOCAL_HOSTS = setOf("localhost", "127.0.0.1", "[::1]")
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        context.adminService.getClients().forEach { client ->
            if (client.clientId in INTERNAL_CLIENTS) return@forEach
            // Bearer-only клиенты не используют redirect URIs
            if (client.isBearerOnly == true) return@forEach
            // Клиенты без Standard Flow не используют redirect URIs
            if (client.isStandardFlowEnabled != true && client.isImplicitFlowEnabled != true) return@forEach

            val redirectUris = client.redirectUris

            // Пустой список redirect URIs или null — Keycloak не позволит аутентификацию,
            // но наличие только "*" означает принятие любого URI
            if (redirectUris.isNullOrEmpty()) {
                findings += Finding(
                    id = id(),
                    title = "Redirect URIs не настроены",
                    description = "Client '${client.clientId}' имеет пустой список redirect URIs.",
                    severity = Severity.LOW,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    clientId = client.clientId,
                    evidence = listOf(Evidence("redirectUris", "empty")),
                    recommendation = "Настройте конкретные redirect URIs для клиента"
                )
                return@forEach
            }

            redirectUris.forEach { uri ->
                // Wildcard URI — самая опасная проблема
                if (uri == "*") {
                    findings += Finding(
                        id = id(),
                        title = "Wildcard redirect URI",
                        description = "Client '${client.clientId}' принимает ЛЮБОЙ redirect URI (wildcard '*'). " +
                                "Это позволяет атакующему перенаправить authorization code на свой сервер.",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(Evidence("redirectUri", uri)),
                        recommendation = "Замените '*' на конкретные redirect URIs"
                    )
                    return@forEach
                }

                // Wildcard в path — prefix matching
                if (uri.contains("*")) {
                    findings += Finding(
                        id = id(),
                        title = "Wildcard в redirect URI",
                        description = "Client '${client.clientId}' использует wildcard в redirect URI: '$uri'. " +
                                "Prefix matching позволяет open redirect через подпути.",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(Evidence("redirectUri", uri)),
                        recommendation = "Используйте exact-match redirect URI без wildcard"
                    )
                }

                // HTTP без TLS (кроме localhost/127.0.0.1)
                if (uri.startsWith("http://")) {
                    val isLocal = SAFE_LOCAL_HOSTS.any { host ->
                        uri.startsWith("http://$host")
                    }
                    if (!isLocal) {
                        findings += Finding(
                            id = id(),
                            title = "HTTP redirect URI без TLS",
                            description = "Client '${client.clientId}' использует HTTP redirect URI: '$uri'. " +
                                    "Authorization code передаётся в открытом виде, доступен для перехвата.",
                            severity = Severity.HIGH,
                            status = CheckStatus.DETECTED,
                            realm = context.realmName,
                            clientId = client.clientId,
                            evidence = listOf(Evidence("redirectUri", uri)),
                            recommendation = "Используйте HTTPS для redirect URI"
                        )
                    }
                }
            }
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
