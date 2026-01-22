package scanners.keycloak_security.usecase.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class NoImplicitFlowCheck : SecurityCheck {

    override fun id() = "10.6.1"
    override fun title() = "Запрет Implicit Flow"
    override fun description() = "Проверка, что Implicit Flow отключён для OIDC клиентов"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()

        val insecureClients = context.adminService.getClients()
            .filter { client ->
                client.protocol == "openid-connect" &&
                        client.isImplicitFlowEnabled == true
            }

        return if (insecureClients.isNotEmpty()) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = insecureClients.map { client ->
                    Finding(
                        id = id(),
                        title = title(),
                        description = "У клиента включён Implicit Flow",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("clientId", client.clientId),
                            Evidence("implicitFlowEnabled", true)
                        ),
                        recommendation =
                            "Отключите implicitFlowEnabled и используйте Authorization Code Flow"
                    )
                },
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(id(), CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
        }
    }
}
