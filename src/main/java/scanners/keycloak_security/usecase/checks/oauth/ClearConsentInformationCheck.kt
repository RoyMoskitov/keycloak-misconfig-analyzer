package scanners.keycloak_security.usecase.checks.oauth

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class ClearConsentInformationCheck : SecurityCheck {

    override fun id() = "10.7.2"
    override fun title() = "Понятный consent screen"
    override fun description() =
        "Проверка полноты информации на consent экране"
    override fun severity() = Severity.LOW

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()

        val badClients = context.adminService.getClients()
            .filter { client ->
                client.isConsentRequired == true &&
                        (client.name.isNullOrBlank() || client.description.isNullOrBlank())
            }

        return if (badClients.isNotEmpty()) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = badClients.map { client ->
                    Finding(
                        id = id(),
                        title = title(),
                        description =
                            "Consent экран не содержит полной информации о клиенте",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("clientId", client.clientId),
                            Evidence("name", client.name),
                            Evidence("description", client.description)
                        ),
                        recommendation =
                            "Заполните name и description клиента для понятного consent UI"
                    )
                },
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(id(), CheckStatus.OK, durationMs = System.currentTimeMillis() - start)
        }
    }
}
