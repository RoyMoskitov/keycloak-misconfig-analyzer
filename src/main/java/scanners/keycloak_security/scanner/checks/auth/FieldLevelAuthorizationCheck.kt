package scanners.keycloak_security.scanner.checks.auth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper.createErrorResult

@Component
class FieldLevelAuthorizationCheck : SecurityCheck {
    override fun id() = "8.2.3"
    override fun title() = "Контроль доступа на уровне полей (BOPLA)"
    override fun description() = "Проверка ограничения доступа к полям токенов через protocol mappers и client scopes"
    override fun severity() = Severity.MEDIUM

    companion object {
        // Стандартные Keycloak клиенты — у них mappers/scopes управляются Keycloak, не пользователем
        private val SYSTEM_CLIENTS = setOf(
            "account", "account-console", "admin-cli",
            "broker", "realm-management", "security-admin-console"
        )

        private val SENSITIVE_ATTRIBUTES = listOf(
            "email", "phone", "mobile", "telephone",
            "address", "street", "city", "postal", "zip",
            "birthdate", "birthday", "ssn", "passport",
            "creditcard", "iban", "account", "salary"
        )
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val clients = context.adminService.getClients()

            val userClients = clients.filter { client ->
                val cid = client.clientId ?: return@filter false
                cid !in SYSTEM_CLIENTS && !cid.startsWith("__")
            }

            if (userClients.isEmpty()) {
                return CheckResult(
                    checkId = id(),
                    status = CheckStatus.OK,
                    findings = listOf(Finding(
                        id = id(),
                        title = "Нет пользовательских клиентов для проверки",
                        description = "В realm '${context.realmName}' не найдены пользовательские клиенты",
                        severity = Severity.INFO,
                        status = CheckStatus.OK,
                        realm = context.realmName,
                        evidence = emptyList()
                    )),
                    durationMs = System.currentTimeMillis() - start
                )
            }

            for (client in userClients) {
                val clientId = client.clientId ?: continue
                checkClientMappers(client, clientId, context.realmName, findings)
                checkClientScopes(client, clientId, context.realmName, findings)
            }

            return buildResult(findings, start)

        } catch (e: Exception) {
            return createErrorResult(id(), title(), e, start, context.realmName)
        }
    }

    private fun checkClientMappers(
        client: org.keycloak.representations.idm.ClientRepresentation,
        clientId: String,
        realmName: String,
        findings: MutableList<Finding>
    ) {
        val mappers = client.protocolMappers ?: emptyList()

        val sensitiveMappers = mappers.filter { mapper ->
            val userAttribute = mapper.config?.get("user.attribute")?.lowercase() ?: ""
            val claimName = mapper.config?.get("claim.name")?.lowercase() ?: ""
            val mapperName = mapper.name?.lowercase() ?: ""

            SENSITIVE_ATTRIBUTES.any { attr ->
                userAttribute.contains(attr) ||
                        claimName.contains(attr) ||
                        mapperName.contains(attr)
            }
        }

        if (sensitiveMappers.isNotEmpty()) {
            val isPublic = client.isPublicClient == true
            findings += Finding(
                id = id(),
                title = if (isPublic) "Public client раскрывает чувствительные данные"
                else "Клиент раскрывает чувствительные данные в токенах",
                description = "Клиент '$clientId' включает чувствительные атрибуты в токены" +
                        if (isPublic) " без должного контроля (public client)" else "",
                severity = if (isPublic) Severity.HIGH else Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = realmName,
                clientId = clientId,
                evidence = listOf(
                    Evidence("clientId", clientId),
                    Evidence("clientType", if (isPublic) "public" else "confidential"),
                    Evidence("sensitiveMappers",
                        sensitiveMappers.joinToString {
                            "${it.name} → ${it.config?.get("user.attribute") ?: "unknown"}"
                        }
                    )
                ),
                recommendation = "Вынесите чувствительные мапперы в optional client scopes"
            )
        }

        // Wildcard/избыточные мапперы
        val wildcardMappers = mappers.filter { mapper ->
            val claimName = mapper.config?.get("claim.name") ?: ""
            val userAttribute = mapper.config?.get("user.attribute") ?: ""

            claimName.contains("*") || userAttribute.contains("*")
        }

        if (wildcardMappers.isNotEmpty()) {
            findings += Finding(
                id = id(),
                title = "Wildcard мапперы у '$clientId'",
                description = "Клиент '$clientId' использует мапперы с wildcard выборкой полей",
                severity = Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = realmName,
                clientId = clientId,
                evidence = listOf(
                    Evidence("clientId", clientId),
                    Evidence("wildcardMappers",
                        wildcardMappers.joinToString {
                            "${it.name}: ${it.config?.get("claim.name") ?: it.config?.get("user.attribute") ?: "unknown"}"
                        }
                    )
                ),
                recommendation = "Замените wildcard мапперы на явное перечисление необходимых claims"
            )
        }
    }

    private fun checkClientScopes(
        client: org.keycloak.representations.idm.ClientRepresentation,
        clientId: String,
        realmName: String,
        findings: MutableList<Finding>
    ) {
        val defaultScopes = client.defaultClientScopes ?: emptyList()
        val optionalScopes = client.optionalClientScopes ?: emptyList()

        if (defaultScopes.isEmpty() && optionalScopes.isEmpty()) {
            findings += Finding(
                id = id(),
                title = "Клиент '$clientId' не использует Client Scopes",
                description = "Клиент '$clientId' не настроил scopes для гранулярного контроля claims",
                severity = Severity.LOW,
                status = CheckStatus.DETECTED,
                realm = realmName,
                clientId = clientId,
                evidence = listOf(
                    Evidence("clientId", clientId),
                    Evidence("defaultScopesCount", "0"),
                    Evidence("optionalScopesCount", "0")
                ),
                recommendation = "Создайте client scopes для разделения claims по уровням доступа"
            )
        }
    }

    private fun buildResult(findings: List<Finding>, start: Long): CheckResult {
        val hasDetected = findings.any { it.status == CheckStatus.DETECTED }

        return CheckResult(
            checkId = id(),
            status = if (hasDetected) CheckStatus.DETECTED else CheckStatus.OK,
            findings = findings,
            durationMs = System.currentTimeMillis() - start
        )
    }
}
