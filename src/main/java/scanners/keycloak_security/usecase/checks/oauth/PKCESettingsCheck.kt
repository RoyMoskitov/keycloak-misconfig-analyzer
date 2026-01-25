package scanners.keycloak_security.usecase.checks.oauth


import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class PKCESettingsCheck : SecurityCheck {

    override fun id() = "10.4.6"
    override fun title() = "Обязательное использование PKCE для публичных клиентов"
    override fun description() =
        "Проверка, что публичные OAuth2/OIDC клиенты используют PKCE с методом S256, чтобы защититься от перехвата authorization code"

    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val realm = context.adminService.getRealm()
        val clients = context.adminService.getClients()
        val findings = mutableListOf<Finding>()

        clients.forEach { client ->
            if (!client.isPublicClient) return@forEach

            val attrs = client.attributes ?: emptyMap()
            val pkceRequired = attrs["pkce.code.challenge.required"]?.toBoolean() ?: false
            val pkceMethod = attrs["pkce.code.challenge.method"]

            if (!pkceRequired || pkceMethod != "S256") {
                val details = mutableListOf<Evidence>()
                details.add(Evidence("publicClient", client.isPublicClient.toString()))
                details.add(Evidence("pkceRequired", pkceRequired.toString()))
                details.add(Evidence("pkceMethod", pkceMethod ?: "not set"))

                findings.add(
                    Finding(
                        id = id(),
                        title = "PKCE не настроен корректно",
                        description = "Публичный клиент не использует обязательный PKCE с методом S256, что позволяет перехват authorization code",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = details,
                        recommendation =
                            "Включите PKCE для публичного клиента: " +
                                    "pkce.code.challenge.required = true, pkce.code.challenge.method = S256"
                    )
                )
            }
        }

        return if (findings.isNotEmpty()) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = findings,
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(
                checkId = id(),
                status = CheckStatus.OK,
                durationMs = System.currentTimeMillis() - start
            )
        }
    }
}
