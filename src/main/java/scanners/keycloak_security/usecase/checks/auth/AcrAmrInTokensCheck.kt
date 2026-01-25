package scanners.keycloak_security.usecase.checks.auth

import org.keycloak.representations.idm.ProtocolMapperRepresentation
import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class AcrAmrPresenceCheck : SecurityCheck {

    override fun id() = "6.8.4"
    override fun title() = "Отсутствие acr / amr claims в токенах"
    override fun description() =
        "Проверка, что в OIDC токенах присутствуют claims acr и/или amr для оценки уровня аутентификации"

    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val realm = context.adminService.getRealm()
        val clients = context.adminService.getClients() ?: emptyList()
        val findings = mutableListOf<Finding>()

        clients.forEach { client ->

            val mappers = mutableListOf<ProtocolMapperRepresentation>()
            mappers.addAll(client.protocolMappers ?: emptyList())

            val scopeIds = (client.defaultClientScopes ?: emptyList()) + (client.optionalClientScopes ?: emptyList())
            scopeIds.forEach { scopeId ->
                try {
                    val scope = context.adminService.getClientScope(realm.id, scopeId)
                    mappers.addAll(scope.protocolMappers ?: emptyList())
                } catch (e: Exception) {
                    // можно логировать warning
                }
            }

            val claimNames = mappers.mapNotNull { it.config?.get("claim.name") }

            val hasAcr = claimNames.any { it == "acr" }
            val hasAmr = claimNames.any { it == "amr" }

            if (!hasAcr && !hasAmr) {
                findings.add(
                    Finding(
                        id = id(),
                        title = "acr / amr не выдаются в токенах",
                        description = "OIDC клиент не включает claims acr или amr, что делает невозможной проверку уровня assurance",
                        severity = severity(),
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(
                            Evidence("protocol", client.protocol),
                            Evidence("mappersCount", mappers.size)
                        ),
                        recommendation =
                            "Добавьте protocol mapper для acr и/или amr (например через user-session-note mapper или hardcoded claim)"
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
