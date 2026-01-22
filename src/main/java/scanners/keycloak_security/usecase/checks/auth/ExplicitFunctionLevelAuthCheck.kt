package scanners.keycloak_security.usecase.checks.auth

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.KeycloakAdminService
import scanners.keycloak_security.usecase.checks.SecurityCheck
import scanners.keycloak_security.usecase.checks.SecurityCheckHelper.createErrorResult

@Component
class ExplicitFunctionLevelAuthCheck() : SecurityCheck {
    override fun id() = "8.2.1"
    override fun title() = "Явная авторизация на уровне функций"
    override fun description() = "Проверка, что доступ к функциям требует явной авторизации через роли, scopes или политики"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            // 1. Получаем ClientResource и ClientRepresentation для целевого клиента
            val clientResource = context.adminService.getClientResource()
            val client = context.adminService.getClientRepresentation()

            if (client == null || clientResource == null) {
                return CheckResult(
                    checkId = id(),
                    status = CheckStatus.ERROR,
                    findings = listOf(Finding(
                        id = id(),
                        title = "Клиент не найден",
                        description = "Клиент не найден в realm ${context.realmName}",
                        severity = Severity.HIGH,
                        status = CheckStatus.ERROR,
                        realm = context.realmName,
                        evidence = emptyList(),
                        recommendation = "Убедитесь, что clientId в конфигурации указан верно и клиент существует"
                    )),
                    durationMs = System.currentTimeMillis() - start
                )
            }

            val clientId = client.clientId ?: "unknown"

            // 2. Проверка public clients без ограничений
            if (client.isPublicClient == true) {
                // Получаем роли клиента
                val clientRoles = try {
                    clientResource.roles().list()
                } catch (e: Exception) {
                    emptyList<org.keycloak.representations.idm.RoleRepresentation>()
                }

                // Получаем default и optional client scopes
                val defaultScopes = client.defaultClientScopes ?: emptyList()
                val optionalScopes = client.optionalClientScopes ?: emptyList()
                val allScopes = defaultScopes + optionalScopes

                // Проверяем, есть ли у клиента хоть какие-то механизмы контроля доступа
                if (clientRoles.isEmpty() && allScopes.isEmpty()) {
                    findings.add(Finding(
                        id = id(),
                        title = "Public client без контроля доступа",
                        description = "Клиент '$clientId' доступен публично без требуемых scopes или ролей",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("clientId", clientId),
                            Evidence("clientType", "public"),
                            Evidence("defaultScopes", defaultScopes.joinToString()),
                            Evidence("optionalScopes", optionalScopes.joinToString()),
                            Evidence("clientRolesCount", clientRoles.size.toString())
                        ),
                        recommendation = "Настройте обязательные client scopes или role-based доступ для клиента"
                    ))
                } else {
                    // Если есть роли или scopes - это хорошо
                    findings.add(Finding(
                        id = id(),
                        title = "Public client имеет механизмы контроля доступа",
                        description = "Клиент '$clientId' использует ${clientRoles.size} ролей и ${allScopes.size} scopes для контроля доступа",
                        severity = Severity.INFO,
                        status = CheckStatus.OK,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("clientId", clientId),
                            Evidence("clientRolesCount", clientRoles.size.toString()),
                            Evidence("scopesCount", allScopes.size.toString())
                        ),
                        recommendation = "Продолжайте поддерживать текущую конфигурацию"
                    ))
                }
            }

            // 3. Проверка bearer-only clients (микросервисы)
            if (client.isBearerOnly == true) {
                val serviceAccountEnabled = client.isServiceAccountsEnabled ?: false
                // Правильный способ проверки включения Authorization Services
                val authzEnabled = client.authorizationServicesEnabled == true || client.authorizationSettings != null

                if (!serviceAccountEnabled && !authzEnabled) {
                    findings.add(Finding(
                        id = id(),
                        title = "Bearer-only client без механизмов авторизации",
                        description = "Микросервис '$clientId' не использует service accounts или Authorization Services",
                        severity = Severity.MEDIUM,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("clientId", clientId),
                            Evidence("serviceAccountsEnabled", serviceAccountEnabled.toString()),
                            Evidence("authorizationEnabled", authzEnabled.toString())
                        ),
                        recommendation = "Включите Service Accounts (для M2M) или Authorization Services (для fine-grained контроля)"
                    ))
                } else {
                    val mechanism = if (serviceAccountEnabled) "Service Accounts" else "Authorization Services"
                    findings.add(Finding(
                        id = id(),
                        title = "Bearer-only client имеет механизм авторизации",
                        description = "Микросервис '$clientId' использует $mechanism для авторизации",
                        severity = Severity.INFO,
                        status = CheckStatus.OK,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("clientId", clientId),
                            Evidence("mechanism", mechanism)
                        ),
                        recommendation = "Продолжайте использовать текущий механизм авторизации"
                    ))
                }
            }

            // 4. Проверка Fine-Grained Permissions (клиенты с включенными Authorization Services)
            val authzEnabled = client.authorizationServicesEnabled == true || client.authorizationSettings != null
            if (authzEnabled) {
                try {
                    val authzResource = clientResource.authorization()
                    val policies = authzResource.policies().policies()

                    // Правильная фильтрация политик по типу
                    val rolePolicies = policies.filter { it.type == "role" }
                    val jsPolicies = policies.filter { it.type == "js" }
                    val userPolicies = policies.filter { it.type == "user" }

                    if (rolePolicies.isEmpty() && jsPolicies.isEmpty() && userPolicies.isEmpty()) {
                        findings.add(Finding(
                            id = id(),
                            title = "Authorization Services без явных политик доступа",
                            description = "Клиент '$clientId' использует Authorization Services, но не имеет явных политик доступа",
                            severity = Severity.MEDIUM,
                            status = CheckStatus.DETECTED,
                            realm = context.realmName,
                            evidence = listOf(
                                Evidence("clientId", clientId),
                                Evidence("totalPolicies", policies.size.toString()),
                                Evidence("policyTypes", policies.joinToString { it.type ?: "unknown" })
                            ),
                            recommendation = "Создайте явные политики доступа (role-based, user-based, js, time-based и т.д.)"
                        ))
                    } else {
                        val policyTypes = listOfNotNull(
                            if (rolePolicies.isNotEmpty()) "role-based (${rolePolicies.size})" else null,
                            if (jsPolicies.isNotEmpty()) "js (${jsPolicies.size})" else null,
                            if (userPolicies.isNotEmpty()) "user-based (${userPolicies.size})" else null
                        ).joinToString(", ")

                        findings.add(Finding(
                            id = id(),
                            title = "Authorization Services сконфигурированы правильно",
                            description = "Клиент '$clientId' имеет ${policies.size} политик доступа ($policyTypes)",
                            severity = Severity.INFO,
                            status = CheckStatus.OK,
                            realm = context.realmName,
                            evidence = listOf(
                                Evidence("clientId", clientId),
                                Evidence("totalPolicies", policies.size.toString()),
                                Evidence("policyTypes", policyTypes)
                            ),
                            recommendation = "Регулярно пересматривайте политики на соответствие бизнес-требованиям"
                        ))
                    }
                } catch (e: Exception) {
                    // Если не удалось получить политики, возможно, authorization services не полностью настроены
                    findings.add(Finding(
                        id = id(),
                        title = "Не удалось проверить политики Authorization Services",
                        description = "Клиент '$clientId' имеет включенные Authorization Services, но при попытке получения политик произошла ошибка",
                        severity = Severity.LOW,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("clientId", clientId),
                            Evidence("error", e.message ?: "unknown error")
                        ),
                        recommendation = "Проверьте конфигурацию Authorization Services клиента"
                    ))
                }
            }

            // 5. Проверка административных клиентов
            val isAdminClient = clientId.contains("admin", ignoreCase = true) ||
                    client.name?.contains("admin", ignoreCase = true) == true ||
                    client.baseUrl?.contains("admin", ignoreCase = true) == true

            if (isAdminClient) {
                val clientRoles = try {
                    clientResource.roles().list()
                } catch (e: Exception) {
                    emptyList<org.keycloak.representations.idm.RoleRepresentation>()
                }

                val adminRoles = clientRoles.filter { role ->
                    role.name?.contains("admin", ignoreCase = true) == true ||
                            role.name?.contains("manage", ignoreCase = true) == true ||
                            role.name?.contains("super", ignoreCase = true) == true
                }

                if (adminRoles.isEmpty() && clientRoles.isNotEmpty()) {
                    findings.add(Finding(
                        id = id(),
                        title = "Admin client без выделенных административных ролей",
                        description = "Клиент с признаками административного доступа '$clientId' не имеет явно выделенных admin ролей",
                        severity = Severity.MEDIUM,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("clientId", clientId),
                            Evidence("totalClientRoles", clientRoles.size.toString()),
                            Evidence("existingRoles", clientRoles.joinToString { it.name ?: "unnamed" })
                        ),
                        recommendation = "Создайте явные административные роли (admin, manager, auditor) для чёткого разделения обязанностей"
                    ))
                } else if (adminRoles.isNotEmpty()) {
                    findings.add(Finding(
                        id = id(),
                        title = "Admin client имеет выделенные административные роли",
                        description = "Клиент '$clientId' имеет ${adminRoles.size} выделенных административных ролей",
                        severity = Severity.INFO,
                        status = CheckStatus.OK,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("clientId", clientId),
                            Evidence("adminRoles", adminRoles.joinToString { it.name ?: "unnamed" })
                        ),
                        recommendation = "Убедитесь, что права административных ролей соответствуют принципу минимальных привилегий"
                    ))
                }
            }

            return createResult(findings, clientId, start)

        } catch (e: Exception) {
            return createErrorResult(id(), title(), e, start, context.realmName)
        }
    }

    private fun createResult(findings: List<Finding>, clientId: String, start: Long): CheckResult {
        return if (findings.isNotEmpty()) {
            CheckResult(
                checkId = id(),
                status = if (findings.any { it.status == CheckStatus.DETECTED }) CheckStatus.DETECTED else CheckStatus.OK,
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