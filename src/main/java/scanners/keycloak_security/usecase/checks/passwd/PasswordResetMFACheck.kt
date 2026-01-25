package scanners.keycloak_security.usecase.checks.passwd

import org.keycloak.representations.idm.AuthenticationFlowRepresentation
import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class PasswordResetMFACheck : SecurityCheck {

    override fun id() = "6.4.3"
    override fun title() = "Проверка MFA при сбросе пароля"
    override fun description() = "Проверка, что сброс пароля не обходит многофакторную аутентификацию"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            // Получаем все потоки аутентификации
            val flows = context.adminService.getAuthenticationFlows().flows

            // Ищем поток сброса пароля
            val resetFlow = flows.find { it.alias == "reset credentials" }

            if (resetFlow == null) {
                // Если поток не найден - это проблема
                findings.add(Finding(
                    id = id(),
                    title = "Поток сброса пароля не найден",
                    description = "В realm не найден стандартный поток 'reset credentials'",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("missing_flow", "reset credentials")),
                    recommendation = "Восстановите стандартный поток 'reset credentials' или проверьте кастомную реализацию"
                ))
            } else {
                // Проверяем executions в основном потоке
                checkForMFAInExecutions(resetFlow, findings, context.realmName)

                // Если есть подпотоки, проверяем и их
                resetFlow.authenticationExecutions?.forEach { execution ->
                    if (execution.isAuthenticatorFlow && execution.flowAlias != null) {
                        // Получаем детали подпотока
                        val subFlow = context.adminService.getAuthenticationFlows()
                            .getFlow(execution.flowAlias!!)
                        checkForMFAInExecutions(subFlow, findings, context.realmName)
                    }
                }
            }
        } catch (e: Exception) {
            findings.add(Finding(
                id = id(),
                title = "Ошибка проверки потоков аутентификации",
                description = "Исключение: ${e.message}",
                severity = Severity.LOW,
                status = CheckStatus.ERROR,
                realm = context.realmName,
                evidence = emptyList(),
                recommendation = "Проверьте доступ к API Keycloak"
            ))
        }

        return if (findings.isNotEmpty()) {
            CheckResult(
                checkId = id(),
                status = CheckStatus.DETECTED,
                findings = findings,
                durationMs = System.currentTimeMillis() - start
            )
        } else {
            CheckResult(
                checkId = id(),
                status = CheckStatus.OK,
                durationMs = System.currentTimeMillis() - start
            )
        }
    }

    private fun checkForMFAInExecutions(
        flow: AuthenticationFlowRepresentation,
        findings: MutableList<Finding>,
        realmName: String
    ) {
        val mfaProviders = listOf(
            "auth-otp-form",           // OTP (TOTP/HOTP)
            "webauthn-authenticator",  // WebAuthn/Passkeys
            "webauthn-passwordless",   // Passwordless WebAuthn
            "auth-spnego",             // Kerberos
            "identity-provider-redirect" // External IDP
        )

        flow.authenticationExecutions?.forEach { execution ->
            if (execution.flowAlias in mfaProviders) {
                when (execution.requirement) {
                    "REQUIRED" -> {
                        findings.add(Finding(
                            id = id(),
                            title = "MFA обязательна при сбросе пароля",
                            description = "В потоке '${flow.alias}' найдена обязательная MFA)",
                            severity = Severity.HIGH,
                            status = CheckStatus.DETECTED,
                            realm = realmName,
                            evidence = listOf(
                                Evidence("flow_alias", flow.alias),
                                Evidence("requirement", execution.requirement),
                            ),
                            recommendation = "Убедитесь, что MFA не требуется при сбросе пароля. Измените требование на DISABLED или удалите этот шаг из потока"
                        ))
                    }
                    "ALTERNATIVE", "CONDITIONAL" -> {
                        findings.add(Finding(
                            id = id(),
                            title = "MFA может требоваться при сбросе пароля",
                            description = "В потоке '${flow.alias}' найдена условная/альтернативная MFA)",
                            severity = Severity.MEDIUM, // WARNING
                            status = CheckStatus.DETECTED,
                            realm = realmName,
                            evidence = listOf(
                                Evidence("flow_alias", flow.alias),
                                Evidence("requirement", execution.requirement),
                            ),
                            recommendation = "Проверьте условия срабатывания MFA. Для сброса пароля MFA не должна требоваться"
                        ))
                    }
                }
            }
        }
    }
}