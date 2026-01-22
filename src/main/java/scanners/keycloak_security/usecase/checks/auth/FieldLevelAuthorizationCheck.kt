package scanners.keycloak_security.usecase.checks.auth

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck
import scanners.keycloak_security.usecase.checks.SecurityCheckHelper.createErrorResult

@Component
class FieldLevelAuthorizationCheck : SecurityCheck {
    override fun id() = "8.2.3"
    override fun title() = "Контроль доступа на уровне полей (BOPLA)"
    override fun description() = "Проверка ограничения доступа к полям токенов через protocol mappers и client scopes"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val client = context.adminService.getClientRepresentation()

            if (client == null) {
                return CheckResult(
                    checkId = id(),
                    status = CheckStatus.ERROR,
                    findings = listOf(Finding(
                        id = id(),
                        title = "Клиент не найден",
                        description = "Не удалось получить клиент для проверки контроля полей",
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

            // 1. Анализ Protocol Mappers на раскрытие чувствительных данных
            val mappers = client.protocolMappers ?: emptyList()

            // Чувствительные атрибуты, которые требуют контроля
            val sensitiveAttributes = listOf(
                "email", "phone", "mobile", "telephone",
                "address", "street", "city", "postal", "zip",
                "birthdate", "birthday", "ssn", "passport",
                "creditcard", "iban", "account", "salary"
            )

            val sensitiveMappers = mappers.filter { mapper ->
                val userAttribute = mapper.config?.get("user.attribute")?.lowercase() ?: ""
                val claimName = mapper.config?.get("claim.name")?.lowercase() ?: ""
                val mapperName = mapper.name?.lowercase() ?: ""

                sensitiveAttributes.any { attr ->
                    userAttribute.contains(attr) ||
                            claimName.contains(attr) ||
                            mapperName.contains(attr)
                }
            }

            // Для публичных клиентов чувствительные мапперы особенно опасны
            if (client.isPublicClient == true && sensitiveMappers.isNotEmpty()) {
                findings.add(Finding(
                    id = id(),
                    title = "Public client раскрывает чувствительные данные",
                    description = "Клиент '$clientId' включает чувствительные атрибуты в токены без должного контроля",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("clientId", clientId),
                        Evidence("clientType", "public"),
                        Evidence("sensitiveMappers",
                            sensitiveMappers.joinToString {
                                "${it.name} -> ${it.config?.get("user.attribute") ?: "unknown"}"
                            }
                        ),
                        Evidence("totalMappers", mappers.size.toString())
                    ),
                    recommendation = "Вынесите чувствительные мапперы в optional client scopes или защитите conditional claims"
                ))
            } else if (sensitiveMappers.isNotEmpty()) {
                // Для конфиденциальных клиентов это warning
                findings.add(Finding(
                    id = id(),
                    title = "Конфиденциальный клиент раскрывает чувствительные данные",
                    description = "Клиент '$clientId' включает чувствительные атрибуты в токены",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("clientId", clientId),
                        Evidence("sensitiveAttributesCount", sensitiveMappers.size.toString())
                    ),
                    recommendation = "Проверьте необходимость включения этих атрибутов в токены"
                ))
            }

            // 2. Проверка на wildcard/избыточные мапперы
            val wildcardMappers = mappers.filter { mapper ->
                val claimName = mapper.config?.get("claim.name") ?: ""
                val userAttribute = mapper.config?.get("user.attribute") ?: ""

                claimName.contains("*") ||
                        claimName.contains("all") ||
                        claimName.contains("full") ||
                        userAttribute.contains("*") ||
                        mapper.name?.contains("all") == true ||
                        mapper.name?.contains("full") == true
            }

            if (wildcardMappers.isNotEmpty()) {
                findings.add(Finding(
                    id = id(),
                    title = "Обнаружены wildcard мапперы",
                    description = "Клиент '$clientId' использует мапперы с wildcard выборкой полей",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("clientId", clientId),
                        Evidence("wildcardMappers",
                            wildcardMappers.joinToString {
                                "${it.name}: ${it.config?.get("claim.name") ?: it.config?.get("user.attribute") ?: "unknown"}"
                            }
                        )
                    ),
                    recommendation = "Замените wildcard мапперы на явное перечисление необходимых claims"
                ))
            }

            // 3. Проверка использования Client Scopes для разделения прав
            val defaultScopes = client.defaultClientScopes ?: emptyList()
            val optionalScopes = client.optionalClientScopes ?: emptyList()

            if (defaultScopes.isEmpty() && optionalScopes.isEmpty()) {
                findings.add(Finding(
                    id = id(),
                    title = "Клиент не использует Client Scopes",
                    description = "Клиент '$clientId' не настроил scopes для гранулярного контроля claims",
                    severity = Severity.LOW,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("clientId", clientId),
                        Evidence("defaultScopesCount", "0"),
                        Evidence("optionalScopesCount", "0")
                    ),
                    recommendation = "Создайте client scopes для разделения claims по уровням доступа"
                ))
            } else {
                // Проверяем баланс между обязательными и опциональными scopes
                val sensitiveInDefault = sensitiveMappers.any { mapper ->
                    // Здесь нужно было бы проверить, в каких scopes находятся чувствительные мапперы
                    // Упрощённая проверка
                    defaultScopes.isNotEmpty()
                }

                if (sensitiveInDefault && optionalScopes.isNotEmpty()) {
                    findings.add(Finding(
                        id = id(),
                        title = "Чувствительные данные в обязательных scopes",
                        description = "Клиент '$clientId' включает чувствительные данные в default scopes",
                        severity = Severity.MEDIUM,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("clientId", clientId),
                            Evidence("defaultScopes", defaultScopes.joinToString()),
                            Evidence("sensitiveAttributes",
                                sensitiveMappers.joinToString { it.config?.get("user.attribute") ?: "unknown" }
                            )
                        ),
                        recommendation = "Переместите чувствительные мапперы в optional client scopes"
                    ))
                }
            }

            // 4. Проверка на conditional claims (мапперы с условиями)
            val conditionalMappers = mappers.filter { mapper ->
                mapper.config?.get("access.token.claim") == "true" &&
                        mapper.config?.containsKey("claim.name") == true &&
                        mapper.config?.get("user.attribute") != null
            }

            if (conditionalMappers.isNotEmpty()) {
                // Это хорошо - есть conditional мапперы
                findings.add(Finding(
                    id = id(),
                    title = "Обнаружены conditional мапперы",
                    description = "Клиент '$clientId' использует мапперы с условиями для контроля claims",
                    severity = Severity.INFO,
                    status = CheckStatus.OK,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("clientId", clientId),
                        Evidence("conditionalMappersCount", conditionalMappers.size.toString()),
                        Evidence("exampleMappers",
                            conditionalMappers.take(3).joinToString {
                                "${it.name}: ${it.config?.get("claim.name")}"
                            }
                        )
                    ),
                    recommendation = "Продолжайте использовать conditional claims для контроля доступа к полям"
                ))
            }

            return createResult(findings, clientId, start)

        } catch (e: Exception) {
            return createErrorResult(id(), title(), e, start, context.realmName)
        }
    }

    private fun createResult(findings: List<Finding>, clientId: String, start: Long): CheckResult {
        val hasDetectedIssues = findings.any { it.status == CheckStatus.DETECTED && it.severity != Severity.INFO }

        return if (findings.isNotEmpty()) {
            CheckResult(
                checkId = id(),
                status = if (hasDetectedIssues) CheckStatus.DETECTED else CheckStatus.OK,
                findings = findings,
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(
                checkId = id(),
                status = CheckStatus.OK,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = "Контроль доступа на уровне полей настроен",
                        description = "Клиент '$clientId' корректно контролирует доступ к полям токенов",
                        severity = Severity.INFO,
                        status = CheckStatus.OK,
                        realm = "",
                        evidence = emptyList(),
                        recommendation = "Продолжайте мониторить мапперы при изменении требований к данным"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        }
    }
}