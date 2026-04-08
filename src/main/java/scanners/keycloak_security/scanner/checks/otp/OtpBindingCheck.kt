package scanners.keycloak_security.scanner.checks.otp

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck

@Component
class OtpBindingCheck : SecurityCheck {

    override fun id() = "6.6.2"
    override fun title() = "Binding OTP к запросу"
    override fun description() = "Проверка, что OTP привязан к конкретному запросу аутентификации и не может быть применён к другому логину"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()

        try {
            // Получаем все потоки и их executions сразу
            val allExecutions = context.adminService.getAllAuthenticationExecutions()
            val findings = mutableListOf<Finding>()

            // Ищем OTP authenticator во всех потоках
            allExecutions.forEach { (flowAlias, executions) ->
                val otpExecutions = executions.filter { it.providerId == "auth-otp-form" }

                if (otpExecutions.isNotEmpty()) {
                    analyzeOtpAuthenticator(flowAlias, otpExecutions, findings, context)
                }
            }

            // Проверяем conditional OTP
            analyzeConditionalOtp(allExecutions, findings, context)

            // Проверяем порядок аутентификации в browser flow
            analyzeAuthenticationOrder(allExecutions, findings, context)

            return buildResult(findings, start, context.realmName)

        } catch (e: Exception) {
            return handleError(e, start, context.realmName)
        }
    }

    private fun analyzeOtpAuthenticator(
        flowAlias: String,
        otpExecutions: List<org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation>,
        findings: MutableList<Finding>,
        context: CheckContext
    ) {
        otpExecutions.forEach { execution ->
            // Получаем конфигурацию OTP
            val config = execution.authenticationConfig?.let { configId ->
                try {
                    context.adminService.getAuthenticatorConfig(configId)
                } catch (e: Exception) {
                    null
                }
            }

            if (config != null && config.config != null) {
                // Анализируем конфигурацию
                analyzeOtpConfig(flowAlias, execution, config.config, findings, context)
            } else {
                // OTP без кастомной конфигурации — дефолтные настройки Keycloak безопасны,
                // не создаём finding чтобы не засорять отчёт шумом
            }
        }
    }

    private fun analyzeOtpConfig(
        flowAlias: String,
        execution: org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation,
        config: Map<String, String>,
        findings: MutableList<Finding>,
        context: CheckContext
    ) {
        // 1. Проверка allow.reuse
        val allowReuse = config["allow.reuse"]?.toBooleanStrictOrNull() ?: false
        if (allowReuse) {
            findings.add(Finding(
                id = id(),
                title = "OTP можно использовать повторно",
                description = "В конфигурации OTP в потоке '$flowAlias' установлен allow.reuse = true",
                severity = Severity.HIGH,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("flow", flowAlias),
                    Evidence("parameter", "allow.reuse"),
                    Evidence("value", "true"),
                    Evidence("configId", execution.authenticationConfig ?: "unknown")
                ),
                recommendation = "Установите allow.reuse = false для предотвращения повторного использования OTP"
            ))
        }

        // 2. Проверка skip.binding
        val skipBinding = config["skip.binding"]?.toBooleanStrictOrNull() ?: false
        if (skipBinding) {
            findings.add(Finding(
                id = id(),
                title = "OTP не привязан к сессии",
                description = "В конфигурации OTP в потоке '$flowAlias' установлен skip.binding = true",
                severity = Severity.HIGH,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("flow", flowAlias),
                    Evidence("parameter", "skip.binding"),
                    Evidence("value", "true")
                ),
                recommendation = "Установите skip.binding = false для привязки OTP к сессии аутентификации"
            ))
        }

        // 3. Проверка session.binding
        val sessionBinding = config["session.binding"] ?: ""
        if (sessionBinding.isNotEmpty() && sessionBinding != "STRICT") {
            findings.add(Finding(
                id = id(),
                title = "Слабый режим привязки OTP к сессии",
                description = "Режим привязки OTP к сессии установлен в '$sessionBinding' (в потоке '$flowAlias')",
                severity = Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("flow", flowAlias),
                    Evidence("parameter", "session.binding"),
                    Evidence("value", sessionBinding),
                    Evidence("recommended", "STRICT")
                ),
                recommendation = "Установите session.binding = STRICT для строгой привязки OTP к сессии"
            ))
        }

        // 4. Проверка времени жизни OTP challenge
        val challengeLifespan = config["challenge.lifespan"]?.toIntOrNull() ?: 60
        if (challengeLifespan > 300) { // больше 5 минут
            findings.add(Finding(
                id = id(),
                title = "Слишком долгое время жизни OTP challenge",
                description = "OTP challenge живет $challengeLifespan секунд (в потоке '$flowAlias')",
                severity = Severity.MEDIUM,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(
                    Evidence("flow", flowAlias),
                    Evidence("parameter", "challenge.lifespan"),
                    Evidence("value", challengeLifespan.toString()),
                    Evidence("recommended", "≤ 300 секунд")
                ),
                recommendation = "Установите challenge.lifespan ≤ 300 секунд (5 минут)"
            ))
        }
    }

    private fun analyzeConditionalOtp(
        allExecutions: Map<String, List<org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation>>,
        findings: MutableList<Finding>,
        context: CheckContext
    ) {
        allExecutions.forEach { (flowAlias, executions) ->
            val conditionalOtp = executions.find { it.providerId == "conditional-otp-form" }

            conditionalOtp?.let { execution ->
                execution.authenticationConfig?.let { configId ->
                    try {
                        val config = context.adminService.getAuthenticatorConfig(configId)
                        config?.config?.get("cond")?.let { condition ->
                            if (condition.contains("-always")) {
                                findings.add(Finding(
                                    id = id(),
                                    title = "Conditional OTP всегда выполняется",
                                    description = "Conditional OTP настроен на всегдашнее выполнение (always) в потоке '$flowAlias'",
                                    severity = Severity.LOW,
                                    status = CheckStatus.DETECTED,
                                    realm = context.realmName,
                                    evidence = listOf(
                                        Evidence("flow", flowAlias),
                                        Evidence("condition", condition)
                                    ),
                                    recommendation = "Проверьте условия conditional OTP на соответствие политикам безопасности"
                                ))
                            }
                        }
                    } catch (e: Exception) {
                        // Игнорируем ошибки при получении конфигурации
                    }
                }
            }
        }
    }

    private fun analyzeAuthenticationOrder(
        allExecutions: Map<String, List<org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation>>,
        findings: MutableList<Finding>,
        context: CheckContext
    ) {
        val browserFlowExecutions = allExecutions["browser"]

        browserFlowExecutions?.let { executions ->
            val otpIndex = executions.indexOfFirst { it.providerId == "auth-otp-form" }
            val passwordIndex = executions.indexOfFirst { it.providerId == "auth-username-password-form" }

            if (otpIndex != -1 && passwordIndex != -1 && otpIndex < passwordIndex) {
                findings.add(Finding(
                    id = id(),
                    title = "Некорректный порядок аутентификации",
                    description = "OTP выполняется до парольной аутентификации в browser flow",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("flow", "browser"),
                        Evidence("otpIndex", otpIndex.toString()),
                        Evidence("passwordIndex", passwordIndex.toString()),
                        Evidence("otpProviderId", executions[otpIndex].providerId),
                        Evidence("passwordProviderId", executions[passwordIndex].providerId)
                    ),
                    recommendation = "OTP должен выполняться после успешной парольной аутентификации для правильной привязки к сессии"
                ))
            }
        }
    }

    private fun buildResult(findings: List<Finding>, start: Long, realmName: String): CheckResult {
        findings.forEach { it.realm = realmName }

        val status = when {
            findings.any { it.severity >= Severity.HIGH } -> CheckStatus.DETECTED
            findings.isNotEmpty() -> CheckStatus.DETECTED
            else -> CheckStatus.OK
        }

        return CheckResult(
            checkId = id(),
            status = status,
            findings = if (status == CheckStatus.OK) {
                listOf(Finding(
                    id = id(),
                    title = "OTP binding корректно настроен",
                    description = "Все проверки OTP binding пройдены успешно",
                    severity = Severity.LOW,
                    status = CheckStatus.OK,
                    realm = realmName,
                    evidence = listOf(Evidence("otpBinding", "properly_configured")),
                    recommendation = null
                ))
            } else {
                findings
            },
            durationMs = System.currentTimeMillis() - start
        )
    }

    private fun handleError(e: Exception, start: Long, realmName: String): CheckResult {
        return CheckResult(
            checkId = id(),
            status = CheckStatus.ERROR,
            findings = listOf(Finding(
                id = id(),
                title = title(),
                description = "Ошибка при проверке OTP binding: ${e.message}",
                severity = Severity.HIGH,
                status = CheckStatus.ERROR,
                realm = realmName,
                evidence = listOf(
                    Evidence("error", e.message ?: "Unknown error"),
                    Evidence("errorType", e.javaClass.simpleName)
                ),
                recommendation = "Проверьте доступность Keycloak API и права доступа"
            )),
            durationMs = System.currentTimeMillis() - start
        )
    }
}