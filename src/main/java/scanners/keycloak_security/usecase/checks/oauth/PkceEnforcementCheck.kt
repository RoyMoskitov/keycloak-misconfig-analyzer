package scanners.keycloak_security.usecase.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class PkceEnforcementCheck : SecurityCheck {

    override fun id() = "10.2.1"
    override fun title() = "PKCE enforcement"
    override fun description() = "Проверка использования PKCE (S256) для OAuth Authorization Code Flow"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        val clients = context.adminService.getClients()

        clients.forEach { client ->
            if (client.isPublicClient == true && client.isStandardFlowEnabled == true) {

                val method = client.attributes?.get("pkce.code.challenge.method")
                val required = client.attributes?.get("pkce.required")

                if (method != "S256" || required != "true") {
                    findings += Finding(
                        id = id(),
                        title = title(),
                        description = "Client '${client.clientId}' использует Authorization Code Flow без PKCE S256",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(
                            Evidence("pkce.method", method ?: "not set"),
                            Evidence("pkce.required", required ?: "not set")
                        ),
                        recommendation = "Включите PKCE и используйте только S256"
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
