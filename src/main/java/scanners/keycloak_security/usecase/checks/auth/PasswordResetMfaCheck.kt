//package scanners.keycloak_security.usecase.checks.auth
//
//import org.springframework.stereotype.Component
//import scanners.keycloak_security.domain.model.*
//import scanners.keycloak_security.usecase.checks.SecurityCheck
//
//@Component
//class PasswordResetMfaCheck : SecurityCheck {
//
//    override fun id() = "6.4.3"
//    override fun title() = "Password reset не обходит MFA"
//    override fun description() = "Проверка, что сброс пароля не снижает уровень аутентификации и требует MFA после восстановления"
//    override fun severity() = Severity.HIGH
//
//    override fun run(context: CheckContext): CheckResult {
//        val start = System.currentTimeMillis()
//
//        try {
//            val flows = context.adminService.getAuthenticationFlowsList()
//            val findings = mutableListOf<Finding>()
//
//            // Ищем reset credentials flow
//            val resetFlow = flows.find { it.alias == "reset credentials" }
//
//            if (resetFlow == null) {
//                findings.add(
//                    Finding(
//                        id = id(),
//                        title = "Поток сброса пароля не найден",
//                        description = "Не найден flow 'reset credentials'",
//                        severity = Severity.HIGH,
//                        status = CheckStatus.DETECTED,
//                        realm = context.realmName,
//                        evidence = listOf(
//                            Evidence("availableFlows", flows.joinToString { it.alias ?: "unknown" })
//                        ),
//                        recommendation = "Проверьте конфигурацию потоков аутентификации"
//                    )
//                )
//            } else {
//                val executions = context.adminService.getAuthenticationFlowExecutions(resetFlow.id)
//
//                // Ищем шаги в потоке сброса пароля
//                val executionSteps = executions.sortedBy { it.index }
//
//                // Проверяем структуру потока
//                val resetPasswordStep = executionSteps.find { it.providerId == "reset-password" }
//                val resetPasswordEmailStep = executionSteps.find { it.providerId == "reset-password-email" }
//
//                if (resetPasswordStep == null && resetPasswordEmailStep == null) {
//                    findings.add(
//                        Finding(
//                            id = id(),
//                            title = "Шаг сброса пароля не найден",
//                            description = "В потоке сброса пароля не найден шаг reset-password или reset-password-email",
//                            severity = Severity.HIGH,
//                            status = CheckStatus.DETECTED,
//                            realm = context.realmName,
//                            evidence = listOf(
//                                Evidence("executionSteps", executionSteps.joinToString { it.providerId })
//                            ),
//                            recommendation = "Добавьте шаг сброса пароля в поток reset credentials"
//                        )
//                    )
//                }
//
//                // Ищем MFA шаги после сброса пароля
//                val mfaAuthenticators = listOf(
//                    "auth-otp-form",
//                    "conditional-otp-form",
//                    "webauthn-authenticator"
//                )
//
//                // Находим индекс шага сброса пароля
//                val resetStepIndex = executionSteps.indexOfFirst {
//                    it.providerId == "reset-password" || it.providerId == "reset-password-email"
//                }
//
//                if (resetStepIndex != -1) {
//                    // Проверяем, есть ли MFA шаги после сброса пароля
//                    val mfaAfterReset = executionSteps.drop(resetStepIndex + 1).any { step ->
//                        mfaAuthenticators.contains(step.providerId)
//                    }
//
//                    if (!mfaAfterReset) {
//                        findings.add(
//                            Finding(
//                                id = id(),
//                                title = "Сброс пароля обходит MFA",
//                                description = "После сброса пароля не требуется повторная MFA аутентификация",
//                                severity = Severity.HIGH,
//                                status = CheckStatus.DETECTED,
//                                realm = context.realmName,
//                                evidence = listOf(
//                                    Evidence("resetStep", executionSteps[resetStepIndex].providerId),
//                                    Evidence("stepsAfterReset", executionSteps.drop(resetStepIndex + 1).joinToString { it.providerId }),
//                                    Evidence("mfaRequired", "false")
//                                ),
//                                recommendation = "Добавьте обязательный MFA шаг после сброса пароля для восстановления уровня аутентификации"
//                            )
//                        )
//                    } else {
//                        // Проверяем, что MFA шаг является обязательным
//                        val mfaStep = executionSteps.drop(resetStepIndex + 1).firstOrNull { step ->
//                            mfaAuthenticators.contains(step.providerId)
//                        }
//
//                        mfaStep?.let { step ->
//                            if (step.requirement != "REQUIRED") {
//                                findings.add(
//                                    Finding(
//                                        id = id(),
//                                        title = "MFA после сброса пароля не обязательна",
//                                        description = "MFA после сброса пароля настроена как опциональная",
//                                        severity = Severity.MEDIUM,
//                                        status = CheckStatus.DETECTED,
//                                        realm = context.realmName,
//                                        evidence = listOf(
//                                            Evidence("mfaStep", step.providerId),
//                                            Evidence("requirement", step.requirement),
//                                            Evidence("recommended", "REQUIRED")
//                                        ),
//                                        recommendation = "Настройте MFA шаг после сброса пароля как REQUIRED"
//                                    )
//                                )
//                            }
//
//                            if (!step.isEnabled) {
//                                findings.add(
//                                    Finding(
//                                        id = id(),
//                                        title = "MFA после сброса пароля отключена",
//                                        description = "MFA шаг после сброса пароля отключен",
//                                        severity = Severity.HIGH,
//                                        status = CheckStatus.DETECTED,
//                                        realm = context.realmName,
//                                        evidence = listOf(
//                                            Evidence("mfaStep", step.providerId),
//                                            Evidence("enabled", "false")
//                                        ),
//                                        recommendation = "Включите MFA шаг после сброса пароля"
//                                    )
//                                )
//                            }
//                        }
//                    }
//                }
//
//                // Проверяем, используется ли conditional flow для MFA
//                val conditionalFlows = executionSteps.filter { it.providerId == "conditional-user-configured" }
//                conditionalFlows.forEach { conditionalStep ->
//                    conditionalStep.authenticationConfig?.let { configId ->
//                        val config = context.adminService.getAuthenticatorConfig(configId)
//                        config?.config?.get("cond")?.let { condition ->
//                            if (condition.contains("otp-configured")) {
//                                // Проверяем, что conditional flow ведет к MFA
//                                val subFlowId = conditionalStep.flowId
//                                if (subFlowId != null) {
//                                    val subExecutions = context.adminService.getAuthenticationFlowExecutions(subFlowId)
//                                    val hasMfaInSubflow = subExecutions.any { subExec ->
//                                        mfaAuthenticators.contains(subExec.providerId)
//                                    }
//
//                                    if (!hasMfaInSubflow) {
//                                        findings.add(
//                                            Finding(
//                                                id = id(),
//                                                title = "Conditional flow не ведет к MFA",
//                                                description = "Условный поток после сброса пароля не содержит MFA",
//                                                severity = Severity.MEDIUM,
//                                                status = CheckStatus.DETECTED,
//                                                realm = context.realmName,
//                                                evidence = listOf(
//                                                    Evidence("conditionalStep", conditionalStep.providerId),
//                                                    Evidence("condition", condition),
//                                                    Evidence("subflowHasMfa", "false")
//                                                ),
//                                                recommendation = "Настройте conditional flow для обязательного перехода к MFA после сброса пароля"
//                                            )
//                                        )
//                                    }
//                                }
//                            }
//                        }
//                    }
//                }
//            }
//
//            // Дополнительная проверка: время жизни токена сброса пароля
//            val realm = context.adminService.getRealm()
//            val actionTokenLifespan = realm.actionTokenGeneratedByUserLifespan ?: 43200 // default 12h
//
//            if (actionTokenLifespan > 3600) { // больше 1 часа
//                findings.add(
//                    Finding(
//                        id = id(),
//                        title = "Долгий срок жизни токена сброса пароля",
//                        description = "Токен сброса пароля живет $actionTokenLifespan секунд (${actionTokenLifespan / 3600} часов)",
//                        severity = Severity.MEDIUM,
//                        status = CheckStatus.DETECTED,
//                        realm = context.realmName,
//                        evidence = listOf(
//                            Evidence("actionTokenGeneratedByUserLifespan", actionTokenLifespan.toString())
//                        ),
//                        recommendation = "Установите срок жизни токена сброса пароля ≤ 3600 секунд (1 час) для уменьшения окна атаки"
//                    )
//                )
//            }
//
//            return if (findings.isNotEmpty()) {
//                CheckResult(
//                    checkId = id(),
//                    status = CheckStatus.DETECTED,
//                    findings = findings,
//                    durationMs = System.currentTimeMillis() - start
//                )
//            } else {
//                CheckResult(
//                    checkId = id(),
//                    status = CheckStatus.OK,
//                    durationMs = System.currentTimeMillis() - start
//                )
//            }
//
//        } catch (e: Exception) {
//            return CheckResult(
//                checkId = id(),
//                status = CheckStatus.ERROR,
//                findings = listOf(
//                    Finding(
//                        id = id(),
//                        title = title(),
//                        description = "Ошибка при проверке сброса пароля: ${e.message}",
//                        severity = Severity.HIGH,
//                        status = CheckStatus.ERROR,
//                        realm = context.realmName,
//                        evidence = listOf(
//                            Evidence("error", e.message ?: "Unknown error")
//                        ),
//                        recommendation = "Проверьте доступность API Keycloak"
//                    )
//                ),
//                durationMs = System.currentTimeMillis() - start
//            )
//        }
//    }
//}