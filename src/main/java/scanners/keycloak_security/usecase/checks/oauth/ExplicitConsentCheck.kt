package scanners.keycloak_security.usecase.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class ExplicitConsentCheck : SecurityCheck {

    override fun id() = "10.7.1"
    override fun title() = "Явное согласие пользователя"
    override fun description() =
        "Проверка, что клиент требует явного согласия пользователя"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()

        val clientsWithoutConsent = context.adminService.getClients()
            .filter { client ->
                client.protocol == "openid-connect" &&
                        client.isConsentRequired != true &&
                        client.clientId !in listOf("account", "account-console")
            }

        return if (clientsWithoutConsent.isNotEmpty()) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = clientsWithoutConsent.map { client ->
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Клиент не требует согласия пользователя",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("clientId", client.clientId),
                            Evidence("consentRequired", client.isConsentRequired)
                        ),
                        recommendation =
                            "Включите consentRequired для untrusted клиентов"
                    )
                },
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(id(), CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
        }
    }
}
