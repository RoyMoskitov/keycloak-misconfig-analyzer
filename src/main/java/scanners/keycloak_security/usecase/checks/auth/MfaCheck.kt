package scanners.keycloak_security.usecase.checks.auth

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class MfaCheck : SecurityCheck {

    override fun id() = "6.3.3"
    override fun title() = "Многофакторная аутентификация (MFA)"
    override fun description() = "Проверка включения и настройки MFA (TOTP/WebAuthn) в authentication flows"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()

        try {
            val authMgmt = context.adminService.getAuthenticationFlows()
            val findings = mutableListOf<Finding>()

            // Получаем список всех потоков аутентификации
            val flows = authMgmt.flows

            if (flows.isNullOrEmpty()) {
                return CheckResult(
                    checkId = id(),
                    status = CheckStatus.ERROR,
                    findings = listOf(
                        Finding(
                            id = id(),
                            title = title(),
                            description = "Не удалось получить потоки аутентификации",
                            severity = Severity.HIGH,
                            status = CheckStatus.ERROR,
                            realm = context.realmName,
                            evidence = listOf(Evidence("error", "flows is null or empty")),
                            recommendation = "Проверьте доступность Keycloak API"
                        )
                    ),
                    durationMs = System.currentTimeMillis() - start
                )
            }

            // Ищем browser flow (основной поток для веб-аутентификации)
            val browserFlow = flows.find { it.alias == "browser" }

            if (browserFlow == null) {
                findings.add(
                    Finding(
                        id = id(),
                        title = "Браузерный поток аутентификации не найден",
                        description = "Не удалось найти стандартный browser flow",
                        severity = Severity.HIGH,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("availableFlows", flows.joinToString { it.alias ?: "unknown" })
                        ),
                        recommendation = "Проверьте конфигурацию потоков аутентификации"
                    )
                )
            } else {
                // Получаем executions для browser flow
                val executions = authMgmt.getExecutions(browserFlow.alias)

                if (executions.isNullOrEmpty()) {
                    findings.add(
                        Finding(
                            id = id(),
                            title = "Нет executions в browser flow",
                            description = "Браузерный поток не содержит шагов аутентификации",
                            severity = Severity.HIGH,
                            status = CheckStatus.DETECTED,
                            realm = context.realmName,
                            evidence = listOf(
                                Evidence("flow", browserFlow.alias),
                                Evidence("flowId", browserFlow.id ?: "N/A")
                            ),
                            recommendation = "Настройте шаги аутентификации в браузерном потоке"
                        )
                    )
                } else {
                    // Ищем MFA authenticators в executions
                    val mfaAuthenticators = listOf(
                        "auth-otp-form",          // TOTP authenticator
                        "webauthn-authenticator", // WebAuthn authenticator
                        "auth-webauthn-passwordless-form", // Passwordless WebAuthn
                        "conditional-otp-form"    // Conditional OTP
                    )

                    val foundMfa = executions.filter { execution ->
                        mfaAuthenticators.any { mfa -> execution.providerId == mfa }
                    }

                    if (foundMfa.isEmpty()) {
                        findings.add(
                            Finding(
                                id = id(),
                                title = "MFA не настроена в браузерном потоке",
                                description = "В потоке аутентификации browser не найден MFA authenticator",
                                severity = Severity.HIGH,
                                status = CheckStatus.DETECTED,
                                realm = context.realmName,
                                evidence = listOf(
                                    Evidence("flow", browserFlow.alias),
                                    Evidence("executionsCount", executions.size.toString()),
                                    Evidence("executionProviders", executions.joinToString { it.providerId }),
                                    Evidence("mfaAuthenticatorsSearched", mfaAuthenticators.toString())
                                ),
                                recommendation = "Добавьте MFA authenticator (TOTP или WebAuthn) в браузерный поток аутентификации"
                            )
                        )
                    } else {
                        // В Keycloak статус включается через requirement, а не isEnabled
                        // requirement может быть: REQUIRED, ALTERNATIVE, DISABLED, CONDITIONAL

                        val disabledMfa = foundMfa.filter { execution ->
                            // Проверяем, отключен ли execution
                            execution.requirement == "DISABLED" ||
                                    execution.requirement == null || // если requirement null, возможно отключен
                                    execution.authenticationFlow == true && execution.requirement == "DISABLED" // если это подпоток
                        }

                        if (disabledMfa.isNotEmpty()) {
                            findings.add(
                                Finding(
                                    id = id(),
                                    title = "MFA authenticators отключены",
                                    description = "Найдены отключенные MFA authenticators",
                                    severity = Severity.MEDIUM,
                                    status = CheckStatus.DETECTED,
                                    realm = context.realmName,
                                    evidence = listOf(
                                        Evidence("disabledAuthenticators", disabledMfa.joinToString {
                                            "${it.providerId ?: "unknown"} (${it.requirement ?: "null"})"
                                        }),
                                        Evidence("totalFoundMfa", foundMfa.size.toString())
                                    ),
                                    recommendation = "Включите MFA authenticators (установите requirement в REQUIRED или ALTERNATIVE)"
                                )
                            )
                        }

                        // Проверяем, являются ли MFA authenticators обязательными
                        val optionalMfa = foundMfa.filter { execution ->
                            execution.requirement != "REQUIRED" && execution.requirement != "DISABLED"
                        }

                        if (optionalMfa.isNotEmpty()) {
                            findings.add(
                                Finding(
                                    id = id(),
                                    title = "MFA настроена как опциональная",
                                    description = "MFA authenticators не являются обязательными",
                                    severity = Severity.MEDIUM,
                                    status = CheckStatus.DETECTED,
                                    realm = context.realmName,
                                    evidence = listOf(
                                        Evidence("optionalAuthenticators", optionalMfa.joinToString {
                                            "${it.providerId ?: "unknown"}: ${it.requirement ?: "null"}"
                                        }),
                                        Evidence("recommendedRequirement", "REQUIRED")
                                    ),
                                    recommendation = "Настройте MFA authenticators как REQUIRED для всех пользователей"
                                )
                            )
                        }

                        // Проверяем наличие conditional MFA
                        val conditionalMfa = foundMfa.filter { it.providerId == "conditional-otp-form" }

                        if (conditionalMfa.isNotEmpty()) {
                            // Проверяем конфигурацию conditional MFA
                            conditionalMfa.forEach { execution ->
                                val configId = execution.authenticationConfig
                                if (configId != null) {
                                    try {
                                        val config = authMgmt.getAuthenticatorConfig(configId)
                                        if (config != null) {
                                            val conditions = config.config?.get("cond") ?: ""
                                            if (conditions.contains("-user-role") ||
                                                conditions.contains("role") ||
                                                conditions.contains("group")) {
                                                findings.add(
                                                    Finding(
                                                        id = id(),
                                                        title = "MFA применяется только к определённым ролям или группам",
                                                        description = "Conditional MFA настроена с условиями по ролям или группам",
                                                        severity = Severity.LOW,
                                                        status = CheckStatus.DETECTED,
                                                        realm = context.realmName,
                                                        evidence = listOf(
                                                            Evidence("configConditions", conditions),
                                                            Evidence("authenticator", execution.providerId ?: "unknown")
                                                        ),
                                                        recommendation = "Рассмотрите применение MFA ко всем пользователям, а не только к определённым ролям или группам"
                                                    )
                                                )
                                            }
                                        }
                                    } catch (e: Exception) {
                                        // Игнорируем ошибки при получении конфигурации
                                    }
                                }
                            }
                        }

                        // Если всё хорошо, добавляем информационное сообщение
                        if (findings.none { it.severity >= Severity.MEDIUM }) {
                            val requiredMfa = foundMfa.filter { it.requirement == "REQUIRED" }
                            findings.add(
                                Finding(
                                    id = id(),
                                    title = "MFA правильно настроена",
                                    description = "Многофакторная аутентификация корректно настроена в браузерном потоке",
                                    severity = Severity.LOW,
                                    status = CheckStatus.OK,
                                    realm = context.realmName,
                                    evidence = listOf(
                                        Evidence("mfaAuthenticators", foundMfa.joinToString {
                                            "${it.providerId ?: "unknown"} (${it.requirement ?: "null"})"
                                        }),
                                        Evidence("requiredMfaCount", requiredMfa.size.toString()),
                                        Evidence("totalMfa", foundMfa.size.toString())
                                    ),
                                    recommendation = null
                                )
                            )
                        }
                    }
                }
            }

            // Проверка direct grant flow (для OAuth2 client credentials и т.д.)
            val directGrantFlow = flows.find { it.alias == "direct grant" }
            if (directGrantFlow != null) {
                val executions = authMgmt.getExecutions(directGrantFlow.alias)
                if (!executions.isNullOrEmpty()) {
                    val mfaAuthenticators = listOf(
                        "auth-otp-form", "webauthn-authenticator",
                        "auth-webauthn-passwordless-form", "conditional-otp-form"
                    )

                    val hasMfaInDirectGrant = executions.any { execution ->
                        mfaAuthenticators.any { mfa -> execution.providerId == mfa }
                    }

                    if (hasMfaInDirectGrant) {
                        findings.add(
                            Finding(
                                id = id(),
                                title = "MFA в direct grant flow",
                                description = "MFA настроена в direct grant flow, что может быть избыточно",
                                severity = Severity.LOW,
                                status = CheckStatus.DETECTED,
                                realm = context.realmName,
                                evidence = listOf(
                                    Evidence("flow", directGrantFlow.alias ?: "unknown"),
                                    Evidence("mfaInDirectGrant", "true")
                                ),
                                recommendation = "Проверьте необходимость MFA в direct grant flow (обычно используется для machine-to-machine аутентификации)"
                            )
                        )
                    }
                }
            }

            // Проверка наличия WebAuthn как более безопасной альтернативы TOTP
            var hasWebAuthn = false
            flows.forEach { flow ->
                val executions = authMgmt.getExecutions(flow.alias)
                if (!executions.isNullOrEmpty()) {
                    hasWebAuthn = hasWebAuthn || executions.any { execution ->
                        execution.providerId?.contains("webauthn", ignoreCase = true) == true
                    }
                }
            }

            if (!hasWebAuthn) {
                findings.add(
                    Finding(
                        id = id(),
                        title = "WebAuthn не настроен",
                        description = "WebAuthn (FIDO2/CTAP) не настроен как метод MFA",
                        severity = Severity.LOW,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("hasWebAuthn", "false"),
                            Evidence("recommendedMfa", "WebAuthn или TOTP")
                        ),
                        recommendation = "Рассмотрите настройку WebAuthn как более безопасной альтернативы TOTP"
                    )
                )
            }

            // Определяем общий статус проверки
            val status = when {
                findings.any { it.severity == Severity.HIGH } -> CheckStatus.DETECTED
                findings.any { it.severity == Severity.MEDIUM } -> CheckStatus.DETECTED
                findings.any { it.severity == Severity.LOW } -> CheckStatus.WARNING
                else -> CheckStatus.OK
            }

            // Если статус OK и нет информационных findings, добавляем успешное finding
            val finalFindings = if (status == CheckStatus.OK && findings.none { it.severity == Severity.LOW }) {
                findings + listOf(
                    Finding(
                        id = id(),
                        title = "MFA корректно настроена",
                        description = "Все проверки MFA пройдены успешно",
                        severity = Severity.LOW,
                        status = CheckStatus.OK,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("flowsChecked", flows.size.toString()),
                            Evidence("mfaConfigured", "true")
                        ),
                        recommendation = null
                    )
                )
            } else {
                findings
            }

            return CheckResult(
                checkId = id(),
                status = status,
                findings = finalFindings,
                durationMs = System.currentTimeMillis() - start
            )

        } catch (e: Exception) {
            return CheckResult(
                checkId = id(),
                status = CheckStatus.ERROR,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Ошибка при проверке MFA: ${e.message}",
                        severity = Severity.HIGH,
                        status = CheckStatus.ERROR,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("error", e.message ?: "Unknown error"),
                            Evidence("errorType", e.javaClass.simpleName)
                        ),
                        recommendation = "Проверьте доступность Keycloak API и права доступа"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        }
    }
}