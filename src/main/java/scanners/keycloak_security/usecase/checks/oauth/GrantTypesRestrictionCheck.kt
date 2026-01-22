package scanners.keycloak_security.usecase.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class GrantTypesRestrictionCheck : SecurityCheck {

    override fun id() = "10.4.4"
    override fun title() = "Restrict OAuth grant types per client"
    override fun description() = "Проверка отключения Implicit и Password grant types"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        context.adminService.getClients().forEach { client ->

            if (client.isImplicitFlowEnabled == true) {
                findings += Finding(
                    id = id(),
                    title = title(),
                    description = "Client '${client.clientId}' использует Implicit Flow",
                    severity = severity(),
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    clientId = client.clientId,
                    evidence = listOf(Evidence("implicitFlowEnabled", true)),
                    recommendation = "Отключите Implicit Flow"
                )
            }

            if (client.isDirectAccessGrantsEnabled == true) {
                findings += Finding(
                    id = id(),
                    title = title(),
                    description = "Client '${client.clientId}' использует Password Grant (Direct Access Grants)",
                    severity = severity(),
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    clientId = client.clientId,
                    evidence = listOf(Evidence("directAccessGrantsEnabled", true)),
                    recommendation = "Не используйте Password Grant, применяйте Authorization Code Flow"
                )
            }
        }

        return if (findings.isNotEmpty()) {
            CheckResult(id(), CheckStatus.DETECTED, findings, System.currentTimeMillis() - start)
        } else {
            CheckResult(id(), CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
        }
    }
}
