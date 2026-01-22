package scanners.keycloak_security.usecase.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class RedirectUriAllowlistCheck : SecurityCheck {

    override fun id() = "10.4.1"
    override fun title() = "Redirect URI allowlist"
    override fun description() = "Проверка строгой allowlist redirect URIs без wildcard и prefix matching"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        val clients = context.adminService.getClients()

        clients.forEach { client ->
            client.redirectUris?.forEach { uri ->
                val invalid =
                    uri.contains("*") ||
                            uri.contains("{") ||
                            uri.contains("}") ||
                            (uri.startsWith("http://") && !uri.contains("localhost"))

                if (invalid) {
                    findings += Finding(
                        id = id(),
                        title = title(),
                        description = "Client '${client.clientId}' использует небезопасный redirect URI",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(Evidence("redirectUri", uri)),
                        recommendation = "Используйте строгий exact-match redirect URI без wildcard"
                    )
                }
            }
        }

        return if (findings.isNotEmpty()) {
            CheckResult(id(), CheckStatus.DETECTED, findings, System.currentTimeMillis() - start)
        } else {
            CheckResult(id(), CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
        }
    }
}
