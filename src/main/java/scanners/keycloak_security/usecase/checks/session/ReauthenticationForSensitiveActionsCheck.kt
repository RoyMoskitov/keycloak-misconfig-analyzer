package scanners.keycloak_security.usecase.checks.session

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck
import scanners.keycloak_security.usecase.checks.SecurityCheckHelper.createErrorResult
import org.slf4j.LoggerFactory

@Component
class ReauthenticationForSensitiveActionsCheck : SecurityCheck {
    private val logger = LoggerFactory.getLogger(ReauthenticationForSensitiveActionsCheck::class.java)

    override fun id() = "7.5.1"
    override fun title() = "Повторная аутентификация для критических действий"
    override fun description() = "Проверка, что критические действия (смена email, пароля, MFA) требуют повторной аутентификации"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        try {
            val authMgmt = context.adminService.getAuthenticationFlows()
            val findings = mutableListOf<Finding>()

            // 1. Проверка потока Reset Credentials
            val resetFlow = authMgmt.flows?.find { it.alias == "reset credentials" }
            if (resetFlow == null) {
                findings.add(Finding(
                    id = id(),
                    title = "Поток сброса учётных данных не найден",
                    description = "Не найден стандартный поток 'reset credentials'",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("flow", "reset credentials")),
                    recommendation = "Настройте поток 'reset credentials' для безопасного сброса паролей"
                ))
            } else {
                val resetExecutions = authMgmt.getExecutions("reset credentials")

                // Безопасная проверка с полной обработкой null
                val hasReauth = resetExecutions?.any { execution ->
                    try {
                        val providerId = execution.providerId ?: return@any false
                        val requirement = execution.requirement ?: return@any false

                        providerId == "auth-username-password-form" && requirement == "REQUIRED"
                    } catch (e: Exception) {
                        logger.warn("Ошибка при проверке execution в потоке reset credentials: ${e.message}")
                        false
                    }
                } ?: false

                // Добавляем отладочную информацию для анализа
                val debugInfo = resetExecutions?.mapNotNull { exec ->
                    try {
                        "ID: ${exec.id}, Provider: ${exec.providerId ?: "NULL"}, Requirement: ${exec.requirement ?: "NULL"}"
                    } catch (e: Exception) {
                        "ID: ${exec.id}, ERROR: ${e.message}"
                    }
                } ?: listOf("No executions")

                findings.add(Finding(
                    id = id(),
                    title = "Отладочная информация: reset credentials",
                    description = "Структура потока для анализа",
                    severity = Severity.INFO,
                    status = CheckStatus.INFO,
                    realm = context.realmName,
                    evidence = listOf(Evidence("executions_debug", debugInfo.joinToString("; "))),
                    recommendation = "Используйте эту информацию для настройки потока"
                ))

                if (!hasReauth) {
                    findings.add(Finding(
                        id = id(),
                        title = "Сброс пароля не требует повторной аутентификации",
                        description = "В потоке 'reset credentials' отсутствует обязательная проверка текущего пароля",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("flow", "reset credentials"),
                            Evidence("reauthRequired", "false"),
                            Evidence("executions_count", resetExecutions?.size?.toString() ?: "0")
                        ),
                        recommendation = "Добавьте execution 'auth-username-password-form' с requirement=REQUIRED в поток reset credentials"
                    ))
                }
            }

            // 2. Проверка других критических потоков
            val criticalFlows = listOf("update profile", "update email")
            criticalFlows.forEach { flowAlias ->
                try {
                    val executions = authMgmt.getExecutions(flowAlias)
                    if (executions != null) {
                        // Безопасная проверка для каждого потока
                        val hasReauth = executions.any { execution ->
                            try {
                                val providerId = execution.providerId ?: return@any false
                                val requirement = execution.requirement ?: return@any false

                                providerId == "auth-username-password-form" && requirement == "REQUIRED"
                            } catch (e: Exception) {
                                logger.warn("Ошибка при проверке execution в потоке $flowAlias: ${e.message}")
                                false
                            }
                        }

                        if (!hasReauth) {
                            findings.add(Finding(
                                id = id(),
                                title = "Поток '$flowAlias' не требует повторной аутентификации",
                                description = "Критическое действие не защищено проверкой пароля",
                                severity = Severity.MEDIUM,
                                status = CheckStatus.DETECTED,
                                realm = context.realmName,
                                evidence = listOf(
                                    Evidence("flow", flowAlias),
                                    Evidence("reauthRequired", "false")
                                ),
                                recommendation = "Защитите поток '$flowAlias' обязательной проверкой пароля"
                            ))
                        }
                    }
                } catch (e: Exception) {
                    // Поток может не существовать - это нормально
                    logger.debug("Поток $flowAlias не найден или ошибка доступа: ${e.message}")
                }
            }

            // 3. Дополнительная проверка через Required Actions (альтернативный подход)
            try {
                val requiredActions = context.adminService.getRequiredActions()
                val sensitiveActions = listOf("UPDATE_PASSWORD", "UPDATE_PROFILE", "CONFIGURE_TOTP")

                sensitiveActions.forEach { actionAlias ->
                    val action = requiredActions.find { it.alias == actionAlias }
                    if (action != null && action.isEnabled == true) {
                        // Проверяем, требует ли действие повторной аутентификации
                        val config = action.config ?: emptyMap()
                        val reauthEnabled = config["reauth"]?.toBoolean() == true

                        if (!reauthEnabled) {
                            findings.add(Finding(
                                id = id(),
                                title = "Required Action '$actionAlias' не требует повторной аутентификации",
                                description = "Критическое действие включено, но не настроена повторная аутентификация",
                                severity = Severity.MEDIUM,
                                status = CheckStatus.DETECTED,
                                realm = context.realmName,
                                evidence = listOf(
                                    Evidence("action", actionAlias),
                                    Evidence("enabled", action.isEnabled.toString()),
                                    Evidence("reauthConfigured", "false")
                                ),
                                recommendation = "Настройте повторную аутентификацию для Required Action '$actionAlias' в административной консоли"
                            ))
                        }
                    }
                }
            } catch (e: Exception) {
                logger.warn("Не удалось проверить Required Actions: ${e.message}")
            }

            return if (findings.isNotEmpty()) {
                // Фильтруем только DETECTED находки для основного результата
                val detectedFindings = findings.filter { it.status == CheckStatus.DETECTED }

                if (detectedFindings.isNotEmpty()) {
                    CheckResult(
                        checkId = id(),
                        status = CheckStatus.DETECTED,
                        findings = detectedFindings,
                        durationMs = System.currentTimeMillis() - start
                    )
                } else {
                    // Если есть только INFO находки (отладочная информация)
                    CheckResult(
                        checkId = id(),
                        status = CheckStatus.OK,
                        findings = findings.filter { it.status == CheckStatus.INFO },
                        durationMs = System.currentTimeMillis() - start
                    )
                }
            } else {
                CheckResult(
                    checkId = id(),
                    status = CheckStatus.OK,
                    durationMs = System.currentTimeMillis() - start
                )
            }

        } catch (e: Exception) {
            logger.error("Критическая ошибка при выполнении проверки ${id()}: ${e.message}", e)
            return createErrorResult(id(), title(), e, start, context.realmName)
        }
    }
}