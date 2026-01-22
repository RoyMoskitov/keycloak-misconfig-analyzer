package scanners.keycloak_security.usecase.checks.authorization

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck
import scanners.keycloak_security.usecase.checks.SecurityCheckHelper.createErrorResult

@Component
class TrustedServiceLayerAuthCheck : SecurityCheck {
    override fun id() = "8.3.1"
    override fun title() = "Авторизация на доверенном сервисном слое"
    override fun description() = "Проверка, что авторизация выполняется на backend, а не полагается на клиентскую проверку"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val client = context.adminService.getClientRepresentation()
            val clientResource = context.adminService.getClientResource()

            if (client == null || clientResource == null) {
                return CheckResult(
                    checkId = id(),
                    status = CheckStatus.ERROR,
                    findings = listOf(Finding(
                        id = id(),
                        title = "Клиент не найден",
                        description = "Не удалось получить клиент для проверки доверенного сервисного слоя",
                        severity = Severity.HIGH,
                        status = CheckStatus.ERROR,
                        realm = context.realmName,
                        evidence = emptyList(),
                        recommendation = "Убедитесь, что clientId в конфигурации указан верно"
                    )),
                    durationMs = System.currentTimeMillis() - start
                )
            }

            val clientId = client.clientId ?: "unknown"

            // 1. Проверка алгоритма подписи токенов
            val tokenSignatureCheck = checkTokenSignature(client, clientId)
            tokenSignatureCheck?.let { findings.add(it) }

            // 2. Проверка backend валидации для bearer-only и service accounts
            val backendValidationCheck = checkBackendValidation(client, clientId)
            findings.addAll(backendValidationCheck)

            // 3. Проверка Policy Enforcement для клиентов с Authorization Services
            val policyEnforcementCheck = checkPolicyEnforcement(client, clientResource, clientId)
            policyEnforcementCheck?.let { findings.add(it) }

            // 4. Проверка рисков клиентской проверки (implicit flow и др.)
            val clientSideRiskCheck = checkClientSideRisks(client, clientId)
            findings.addAll(clientSideRiskCheck)

            // 5. Проверка использования UMA или Resource Server capabilities
            val resourceServerCheck = checkResourceServerConfig(client, clientResource, clientId)
            resourceServerCheck?.let { findings.add(it) }

            return createResult(findings, clientId, start)

        } catch (e: Exception) {
            return createErrorResult(id(), title(), e, start, context.realmName)
        }
    }

    private fun checkTokenSignature(client: org.keycloak.representations.idm.ClientRepresentation, clientId: String): Finding? {
        // Проверка через атрибуты клиента
        val algorithm = client.attributes?.get("access.token.signed.response.alg")

        return when {
            algorithm == null -> {
                Finding(
                    id = id(),
                    title = "Алгоритм подписи токенов не настроен",
                    description = "Клиент '$clientId' не имеет явно заданного алгоритма подписи токенов",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = "", // заполнится в основном методе
                    evidence = listOf(
                        Evidence("clientId", clientId),
                        Evidence("algorithm", "not configured")
                    ),
                    recommendation = "Явно задайте алгоритм подписи токенов (рекомендуется RS256 или RS512)"
                )
            }

            algorithm.equals("none", ignoreCase = true) -> {
                Finding(
                    id = id(),
                    title = "Токены без подписи (algorithm=none)",
                    description = "Клиент '$clientId' использует неподписанные токены",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = "",
                    evidence = listOf(
                        Evidence("clientId", clientId),
                        Evidence("algorithm", algorithm)
                    ),
                    recommendation = "Немедленно измените алгоритм подписи на RS256, RS512 или ES256"
                )
            }

            algorithm.startsWith("HS", ignoreCase = true) -> {
                Finding(
                    id = id(),
                    title = "Симметричная подпись токенов (HMAC)",
                    description = "Клиент '$clientId' использует HMAC подпись, которая требует хранения секрета на всех сервисах",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = "",
                    evidence = listOf(
                        Evidence("clientId", clientId),
                        Evidence("algorithm", algorithm)
                    ),
                    recommendation = "Перейдите на асимметричную подпись (RS256/RS512) для лучшей безопасности"
                )
            }

            algorithm.startsWith("RS", ignoreCase = true) || algorithm.startsWith("ES", ignoreCase = true) -> {
                Finding(
                    id = id(),
                    title = "Алгоритм подписи токенов настроен корректно",
                    description = "Клиент '$clientId' использует асимметричную подпись токенов ($algorithm)",
                    severity = Severity.INFO,
                    status = CheckStatus.OK,
                    realm = "",
                    evidence = listOf(
                        Evidence("clientId", clientId),
                        Evidence("algorithm", algorithm)
                    ),
                    recommendation = "Продолжайте использовать текущий алгоритм подписи"
                )
            }

            else -> null
        }
    }

    private fun checkBackendValidation(client: org.keycloak.representations.idm.ClientRepresentation, clientId: String): List<Finding> {
        val findings = mutableListOf<Finding>()

        // Bearer-only клиенты ДОЛЖНЫ использовать introspection
        if (client.isBearerOnly == true) {
            // Проверяем, есть ли атрибут или признак использования introspection
            val usesIntrospection = client.attributes?.get("use.introspection.endpoint") == "true" ||
                    client.attributes?.get("validate.token.on.backend") == "true"

            if (!usesIntrospection) {
                findings.add(Finding(
                    id = id(),
                    title = "Bearer-only client без явного использования introspection",
                    description = "Клиент '$clientId' (bearer-only) не настроен на использование introspection endpoint",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = "",
                    evidence = listOf(
                        Evidence("clientId", clientId),
                        Evidence("clientType", "bearer-only"),
                        Evidence("introspectionConfigured", "false")
                    ),
                    recommendation = "Настройте использование introspection endpoint для проверки токенов на backend"
                ))
            }
        }

        return findings
    }

    private fun checkPolicyEnforcement(
        client: org.keycloak.representations.idm.ClientRepresentation,
        clientResource: org.keycloak.admin.client.resource.ClientResource,
        clientId: String
    ): Finding? {
        val authzEnabled = client.authorizationServicesEnabled == true || client.authorizationSettings != null

        if (!authzEnabled) {
            return null
        }

        return try {
            val authzResource = clientResource.authorization()
            val policies = authzResource.policies().policies()

            // Ищем enforcement политики или политики, связанные с resource server
            val enforcementPolicies = policies.filter { policy ->
                policy.type == "enforcer" ||
                        policy.name?.contains("enforce", ignoreCase = true) == true ||
                        policy.name?.contains("policy-enforcer", ignoreCase = true) == true ||
                        policy.config?.get("enforcementMode") != null
            }

            if (enforcementPolicies.isEmpty()) {
                Finding(
                    id = id(),
                    title = "Authorization Services без Policy Enforcer",
                    description = "Клиент '$clientId' имеет включенные Authorization Services, но нет настроенных enforcement политик",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = "",
                    evidence = listOf(
                        Evidence("clientId", clientId),
                        Evidence("totalPolicies", policies.size.toString()),
                        Evidence("hasEnforcementPolicies", "false")
                    ),
                    recommendation = "Настройте Policy Enforcer для защиты API endpoints на resource server"
                )
            } else {
                null
            }
        } catch (e: Exception) {
            // Authorization Services включены, но API недоступно
            Finding(
                id = id(),
                title = "Не удалось проверить Policy Enforcer",
                description = "Клиент '$clientId' имеет Authorization Services, но не удалось получить политики",
                severity = Severity.LOW,
                status = CheckStatus.DETECTED,
                realm = "",
                evidence = listOf(
                    Evidence("clientId", clientId),
                    Evidence("error", e.message?.take(100) ?: "unknown")
                ),
                recommendation = "Проверьте конфигурацию Authorization Services или отключите их, если не используются"
            )
        }
    }

    private fun checkClientSideRisks(client: org.keycloak.representations.idm.ClientRepresentation, clientId: String): List<Finding> {
        val findings = mutableListOf<Finding>()

        // Implicit flow часто ведет к клиентской проверке прав
        if (client.isImplicitFlowEnabled == true) {
            findings.add(Finding(
                id = id(),
                title = "Используется Implicit Flow",
                description = "Клиент '$clientId' использует implicit flow, что может привести к клиентской проверке авторизации",
                severity = Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = "",
                evidence = listOf(
                    Evidence("clientId", clientId),
                    Evidence("implicitFlowEnabled", "true"),
                    Evidence("standardFlowEnabled", client.isStandardFlowEnabled?.toString() ?: "false")
                ),
                recommendation = "Рассмотрите переход на Authorization Code Flow с PKCE для SPA клиентов"
            ))
        }

        // Публичные клиенты SPA без backend
        if (client.isPublicClient == true && client.isStandardFlowEnabled == true) {
            val isLikelySPA = client.clientId?.contains("spa") == true ||
                    client.clientId?.contains("webapp") == true ||
                    client.clientId?.contains("frontend") == true

            if (isLikelySPA) {
                findings.add(Finding(
                    id = id(),
                    title = "SPA клиент требует особого внимания",
                    description = "Клиент '$clientId' похож на SPA приложение, где возможна клиентская проверка прав",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = "",
                    evidence = listOf(
                        Evidence("clientId", clientId),
                        Evidence("clientType", "public SPA"),
                        Evidence("risk", "client-side authorization checks")
                    ),
                    recommendation = "Убедитесь, что все проверки прав дублируются на backend через introspection или resource server"
                ))
            }
        }

        return findings
    }

    private fun checkResourceServerConfig(
        client: org.keycloak.representations.idm.ClientRepresentation,
        clientResource: org.keycloak.admin.client.resource.ClientResource,
        clientId: String
    ): Finding? {
        // Проверяем, настроен ли клиент как resource server
        if (client.isBearerOnly != true && client.isServiceAccountsEnabled != true) {
            return null
        }

        return try {
            // Проверяем наличие ресурсов, если это resource server
            val authzResource = clientResource.authorization()
            val resources = authzResource.resources().resources()

            if (resources.isEmpty()) {
                Finding(
                    id = id(),
                    title = "Resource server без защищенных ресурсов",
                    description = "Клиент '$clientId' (bearer-only/service account) не имеет настроенных защищенных ресурсов",
                    severity = Severity.LOW,
                    status = CheckStatus.DETECTED,
                    realm = "",
                    evidence = listOf(
                        Evidence("clientId", clientId),
                        Evidence("resourcesCount", "0"),
                        Evidence("isResourceServer", "true")
                    ),
                    recommendation = "Настройте ресурсы и permissions для защиты API endpoints"
                )
            } else {
                null
            }
        } catch (e: Exception) {
            // Не является resource server или ошибка доступа
            null
        }
    }

    private fun createResult(findings: List<Finding>, clientId: String, start: Long): CheckResult {
        val hasCriticalIssues = findings.any {
            it.status == CheckStatus.DETECTED &&
                    (it.severity == Severity.HIGH || it.severity == Severity.HIGH)
        }

        val hasDetectedIssues = findings.any {
            it.status == CheckStatus.DETECTED && it.severity != Severity.INFO
        }

        return if (findings.isNotEmpty()) {
            CheckResult(
                checkId = id(),
                status = when {
                    hasCriticalIssues -> CheckStatus.DETECTED
                    hasDetectedIssues -> CheckStatus.DETECTED
                    else -> CheckStatus.OK
                },
                findings = findings,
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(
                checkId = id(),
                status = CheckStatus.OK,
                findings = listOf(),
                durationMs = System.currentTimeMillis() - start
            )
        }
    }
}