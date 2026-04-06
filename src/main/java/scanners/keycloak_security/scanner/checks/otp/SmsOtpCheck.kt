package scanners.keycloak_security.scanner.checks.otp

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck

@Component
class SmsOtpCheck : SecurityCheck {

    override fun id() = "6.6.1"
    override fun title() = "Использование SMS / phone OTP"
    override fun description() = "Проверка использования SMS-OTP и наличия более сильных альтернатив"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()

        try {
            // Используем новый метод для получения всех executions
            val allExecutions = context.adminService.getAllAuthenticationExecutions()
            val findings = mutableListOf<Finding>()

            // Определяем список возможных SMS authenticator providerId
            val smsAuthenticators = listOf(
                "sms-auth", "sms-authenticator", "phone-authentication",
                "sms-otp-authenticator", "sms-verification"
            )

            var hasSmsAuth = false
            val smsFlowDetails = mutableListOf<String>()

            // Проходим по всем потокам и их executions
            allExecutions.forEach { (flowAlias, executions) ->
                executions.forEach { execution ->
                    val providerId = execution.providerId ?: ""
                    if (smsAuthenticators.any { sms -> providerId.equals(sms, ignoreCase = true) }) {
                        hasSmsAuth = true
                        smsFlowDetails.add("$flowAlias: $providerId (${execution.requirement})")
                    }
                }
            }

            if (hasSmsAuth) {
                findings.add(
                    Finding(
                        id = id(),
                        title = "Обнаружен SMS OTP authenticator",
                        description = "В потоках аутентификации используется SMS-based OTP",
                        severity = Severity.MEDIUM,
                        status = CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("smsAuthenticatorsFound", smsFlowDetails.joinToString("; ")),
                            Evidence("smsSecurityLevel", "Низкий - подвержен SIM swap, фишингу SMS")
                        ),
                        recommendation = "Рассмотрите замену SMS OTP на более безопасные методы: TOTP (Google Authenticator, Authy) или WebAuthn (FIDO2)"
                    )
                )

                // Проверяем, является ли SMS единственным фактором
                allExecutions.forEach { (flowAlias, executions) ->
                    val hasPasswordAuth = executions.any {
                        it.providerId == "auth-username-password-form"
                    }

                    val hasSmsInFlow = executions.any { execution ->
                        val providerId = execution.providerId ?: ""
                        smsAuthenticators.any { sms -> providerId.equals(sms, ignoreCase = true) }
                    }

                    if (hasSmsInFlow && !hasPasswordAuth) {
                        findings.add(
                            Finding(
                                id = id(),
                                title = "SMS используется как единственный фактор",
                                description = "В потоке '$flowAlias' SMS используется без дополнительного фактора аутентификации",
                                severity = Severity.HIGH,
                                status = CheckStatus.DETECTED,
                                realm = context.realmName,
                                evidence = listOf(
                                    Evidence("flow", flowAlias),
                                    Evidence("hasPassword", "false"),
                                    Evidence("smsOnly", "true"),
                                    Evidence("executionsInFlow", executions.size.toString())
                                ),
                                recommendation = "Никогда не используйте SMS как единственный фактор. Добавьте как минимум пароль или другой фактор."
                            )
                        )
                    }
                }

                // Проверяем наличие более сильных альтернатив
                var hasStrongerAlternatives = false
                allExecutions.forEach { (_, executions) ->
                    if (executions.any { execution ->
                            execution.providerId == "auth-otp-form" ||
                                    execution.providerId?.contains("webauthn", ignoreCase = true) == true
                        }) {
                        hasStrongerAlternatives = true
                    }
                }

                if (!hasStrongerAlternatives) {
                    findings.add(
                        Finding(
                            id = id(),
                            title = "Отсутствуют более сильные альтернативы SMS",
                            description = "SMS OTP используется, но более безопасные методы (TOTP, WebAuthn) не настроены",
                            severity = Severity.HIGH,
                            status = CheckStatus.DETECTED,
                            realm = context.realmName,
                            evidence = listOf(
                                Evidence("hasTOTP", "false"),
                                Evidence("hasWebAuthn", "false"),
                                Evidence("onlySms", "true")
                            ),
                            recommendation = "Настройте TOTP или WebAuthn как более безопасные альтернативы SMS OTP"
                        )
                    )
                } else {
                    findings.add(
                        Finding(
                            id = id(),
                            title = "Доступны альтернативы SMS OTP",
                            description = "Вместе с SMS OTP настроены более безопасные методы аутентификации",
                            severity = Severity.LOW,
                            status = CheckStatus.DETECTED,
                            realm = context.realmName,
                            evidence = listOf(
                                Evidence("hasStrongAlternatives", "true")
                            ),
                            recommendation = "Рекомендуется перевести пользователей с SMS OTP на TOTP или WebAuthн"
                        )
                    )
                }

                // Проверка конфигурации SMS authenticator
                allExecutions.forEach { (flowAlias, executions) ->
                    val smsExecutions = executions.filter { execution ->
                        val providerId = execution.providerId ?: ""
                        smsAuthenticators.any { sms -> providerId.equals(sms, ignoreCase = true) }
                    }

                    smsExecutions.forEach { smsExecution ->
                        smsExecution.authenticationConfig?.let { configId ->
                            try {
                                val config = context.adminService.getAuthenticatorConfig(configId)
                                config?.config?.let { smsConfig ->
                                    // Проверка длины кода
                                    val codeLength = smsConfig.get("length")?.toIntOrNull() ?: 6
                                    if (codeLength < 6) {
                                        findings.add(
                                            Finding(
                                                id = id(),
                                                title = "Слишком короткий SMS код",
                                                description = "SMS код состоит только из $codeLength цифр (в потоке '$flowAlias')",
                                                severity = Severity.MEDIUM,
                                                status = CheckStatus.DETECTED,
                                                realm = context.realmName,
                                                evidence = listOf(
                                                    Evidence("codeLength", codeLength.toString()),
                                                    Evidence("authenticator", smsExecution.providerId ?: "unknown"),
                                                    Evidence("flow", flowAlias)
                                                ),
                                                recommendation = "Установите длину SMS кода не менее 6 цифр"
                                            )
                                        )
                                    }

                                    // Проверка времени жизни кода
                                    val ttl = smsConfig.get("ttl")?.toIntOrNull() ?: 300
                                    if (ttl > 300) { // больше 5 минут
                                        findings.add(
                                            Finding(
                                                id = id(),
                                                title = "Слишком долгое время жизни SMS кода",
                                                description = "SMS код живет $ttl секунд (в потоке '$flowAlias')",
                                                severity = Severity.MEDIUM,
                                                status = CheckStatus.DETECTED,
                                                realm = context.realmName,
                                                evidence = listOf(
                                                    Evidence("ttl", ttl.toString()),
                                                    Evidence("recommended", "≤ 300 секунд (5 минут)"),
                                                    Evidence("flow", flowAlias)
                                                ),
                                                recommendation = "Уменьшите время жизни SMS кода до 5 минут или менее"
                                            )
                                        )
                                    }
                                }
                            } catch (e: Exception) {
                                // Логируем ошибку, но не останавливаем проверку
                                findings.add(
                                    Finding(
                                        id = id(),
                                        title = "Не удалось проверить конфигурацию SMS authenticator",
                                        description = "Ошибка при получении конфигурации для SMS authenticator в потоке '$flowAlias': ${e.message}",
                                        severity = Severity.LOW,
                                        status = CheckStatus.DETECTED,
                                        realm = context.realmName,
                                        evidence = listOf(
                                            Evidence("flow", flowAlias),
                                            Evidence("error", e.message ?: "Unknown error")
                                        ),
                                        recommendation = "Проверьте доступность конфигурации SMS authenticator вручную"
                                    )
                                )
                            }
                        }
                    }
                }
            } else {
                findings.add(
                    Finding(
                        id = id(),
                        title = "SMS OTP не используется",
                        description = "SMS-based аутентификация не настроена",
                        severity = Severity.LOW,
                        status = CheckStatus.OK,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("hasSmsAuth", "false"),
                            Evidence("totalFlowsChecked", allExecutions.size.toString())
                        ),
                        recommendation = null
                    )
                )
            }

            val hasCriticalFindings = findings.any { it.severity >= Severity.HIGH }
            val hasMediumFindings = findings.any { it.severity == Severity.MEDIUM }

            val status = when {
                hasCriticalFindings -> CheckStatus.DETECTED
                hasMediumFindings -> CheckStatus.DETECTED
                findings.isNotEmpty() -> CheckStatus.WARNING
                else -> CheckStatus.OK
            }

            return CheckResult(
                checkId = id(),
                status = status,
                findings = findings,
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
                        description = "Ошибка при проверке SMS OTP: ${e.message}",
                        severity = Severity.HIGH,
                        status = CheckStatus.ERROR,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("error", e.message ?: "Unknown error"),
                            Evidence("errorType", e.javaClass.simpleName)
                        ),
                        recommendation = "Проверьте доступность API Keycloak"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        }
    }
}