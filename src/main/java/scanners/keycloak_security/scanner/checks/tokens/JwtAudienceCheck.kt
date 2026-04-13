package scanners.keycloak_security.scanner.checks.tokens

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.service.JwtParser
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper.createErrorResult
import scanners.keycloak_security.scanner.SecurityCheckHelper.buildCheckResult

/**
 * ASVS V9.2.3: "Verify that the service only accepts tokens which are intended
 * for use with that service (audience). For JWTs, this can be achieved by validating
 * the 'aud' claim against an allowlist defined in the service."
 *
 * В Keycloak: проверяем что service/confidential клиенты имеют audience mapper,
 * чтобы access tokens были ограничены по аудитории и не переиспользовались между сервисами.
 */
@Component
class JwtAudienceCheck : SecurityCheck {

    override fun id() = "9.2.3"
    override fun title() = "Проверка назначения токена (audience)"
    override fun description() =
        "Проверка, что токены ограничены по аудитории для каждого сервиса (ASVS V9.2.3)"
    override fun severity() = Severity.MEDIUM

    companion object {
        val INTERNAL_CLIENTS = setOf(
            "account", "account-console", "admin-cli",
            "broker", "realm-management", "security-admin-console"
        )
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        return try {
            val clients = context.adminService.getClients()

            // Проверяем service-account и confidential клиенты
            val serviceClients = clients.filter { client ->
                client.clientId !in INTERNAL_CLIENTS &&
                        client.clientId?.endsWith("-realm") != true &&
                        client.isBearerOnly != true &&
                        (client.isServiceAccountsEnabled == true ||
                                (client.isPublicClient != true && client.isStandardFlowEnabled == true))
            }

            val clientsWithoutAudience = serviceClients.filter { client ->
                val mappers = client.protocolMappers ?: emptyList()
                mappers.none { it.protocolMapper == "oidc-audience-mapper" }
            }

            if (clientsWithoutAudience.isNotEmpty()) {
                clientsWithoutAudience.forEach { client ->
                    val isServiceAccount = client.isServiceAccountsEnabled == true
                    findings += Finding(
                        id = id(),
                        title = "Нет audience restriction для '${client.clientId}'",
                        description = "Клиент '${client.clientId}' " +
                                (if (isServiceAccount) "(service account) " else "") +
                                "не имеет Audience Protocol Mapper. " +
                                "Без aud claim сервис-получатель не может проверить, " +
                                "что токен предназначен именно для него.",
                        severity = if (isServiceAccount) Severity.MEDIUM else Severity.LOW,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        clientId = client.clientId,
                        evidence = listOf(
                            Evidence("clientId", client.clientId),
                            Evidence("serviceAccount", isServiceAccount),
                            Evidence("audienceMapper", "отсутствует")
                        ),
                        recommendation = "Добавьте Audience Protocol Mapper для ограничения token audience"
                    )
                }
            }

            buildCheckResult(id(), title(), findings, start, context.realmName)

        } catch (e: Exception) {
            createErrorResult(id(), title(), e, start, context.realmName)
        }
    }
}
