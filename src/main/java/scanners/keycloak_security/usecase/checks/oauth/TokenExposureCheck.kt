package scanners.keycloak_security.usecase.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class TokenExposureCheck : SecurityCheck {

    override fun id() = "10.1.1"
    override fun title() = "Tokens only where strictly needed"
    override fun description() = "Проверка корректного использования access/refresh tokens в зависимости от типа клиента"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        val clients = context.adminService.getClients()

        clients.forEach { client ->
            if (client.isPublicClient == true) {

                val refreshEnabled = client.attributes?.get("use.refresh.tokens") == "true"
                if (refreshEnabled) {
                    findings += Finding(
                        id = id(),
                        title = title(),
                        description = "Public client '${client.clientId}' имеет включённые refresh tokens",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(Evidence("use.refresh.tokens", "true")),
                        recommendation = "Отключите refresh tokens для public clients"
                    )
                }

                if (client.isDirectAccessGrantsEnabled == true) {
                    findings += Finding(
                        id = id(),
                        title = title(),
                        description = "Public client '${client.clientId}' использует Direct Access Grants",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        recommendation = "Не используйте Direct Access Grants для public clients"
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
