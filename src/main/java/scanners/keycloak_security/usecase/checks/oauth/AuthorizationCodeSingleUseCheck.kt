package scanners.keycloak_security.usecase.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class AuthorizationCodeSingleUseCheck : SecurityCheck {

    override fun id() = "10.4.2"
    override fun title() = "Authorization code single-use"
    override fun description() =
        "Проверка отсутствия legacy OAuth flows, нарушающих single-use authorization code"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        context.adminService.getClients().forEach { client ->
            if (client.isStandardFlowEnabled == true) {

                if (client.isImplicitFlowEnabled == true) {
                    findings += Finding(
                        id = id(),
                        title = title(),
                        description = "Client '${client.clientId}' использует Implicit Flow, нарушая модель single-use authorization code",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(
                            Evidence("implicitFlowEnabled", true),
                            Evidence("standardFlowEnabled", true)
                        ),
                        recommendation = "Отключите Implicit Flow и используйте только Authorization Code Flow"
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
