package scanners.keycloak_security.usecase.checks.session

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck
import scanners.keycloak_security.usecase.checks.SecurityCheckHelper.createErrorResult

@Component
class DynamicSessionTokensCheck : SecurityCheck {
    override fun id() = "7.2.2"
    override fun title() = "Динамические session tokens"
    override fun description() = "Проверка использования временных токенов (access/refresh) вместо статических API ключей для пользовательских сессий"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        try {
            val clients = context.adminService.getClients()
            val findings = mutableListOf<Finding>()
            val serviceAccountClients = mutableListOf<String>()

            clients.forEach { client ->
                val clientId = client.clientId ?: "unknown"

                // 1. Проверка: стандартные потоки (Authorization Code) должны быть включены для веб-приложений
                val isPublicClient = client.isPublicClient ?: false
                val standardFlowEnabled = client.isStandardFlowEnabled ?: false

                if (!isPublicClient && !standardFlowEnabled) {
                    // Для confidential clients должен быть включен хотя бы один стандартный поток
                    val directAccessGrantsEnabled = client.isDirectAccessGrantsEnabled ?: false
                    if (!directAccessGrantsEnabled) {
                        findings.add(Finding(
                            id = id(),
                            title = "Клиент не использует стандартные потоки аутентификации",
                            description = "Клиент '$clientId' не имеет включенных стандартных OAuth2/OIDC потоков.",
                            severity = Severity.HIGH,
                            status = CheckStatus.DETECTED,
                            realm = context.realmName,
                            evidence = listOf(
                                Evidence("clientId", clientId),
                                Evidence("standardFlowEnabled", "false"),
                                Evidence("directAccessGrantsEnabled", "false"),
                                Evidence("publicClient", isPublicClient.toString())
                            ),
                            recommendation = "Для пользовательских сессий включите Standard Flow (Authorization Code) или Direct Access Grants."
                        ))
                    }
                }

                // 2. Выявление сервисных аккаунтов (service accounts)
                val serviceAccountsEnabled = client.isServiceAccountsEnabled ?: false
                if (serviceAccountsEnabled) {
                    serviceAccountClients.add(clientId)
                    // Предупреждение: сервисные аккаунты не должны использоваться для эмуляции пользовательских сессий
                    findings.add(Finding(
                        id = id(),
                        title = "Обнаружен клиент с сервисным аккаунтом",
                        description = "Клиент '$clientId' имеет включенный Service Accounts Enabled.",
                        severity = Severity.LOW,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(Evidence("clientId", clientId)),
                        recommendation = "Убедитесь, что сервисные аккаунты не используются вместо пользовательских сессий. Они предназначены для machine-to-machine аутентификации."
                    ))
                }
            }

            return if (findings.isEmpty()) {
                CheckResult(
                    checkId = id(),
                    status = CheckStatus.OK,
                    durationMs = System.currentTimeMillis() - start
                )
            } else {
                CheckResult(
                    checkId = id(),
                    status = CheckStatus.DETECTED,
                    findings = findings,
                    durationMs = System.currentTimeMillis() - start
                )
            }
        } catch (e: Exception) {
            return createErrorResult(id(), title(), e, start, context.realmName)
        }
    }
}