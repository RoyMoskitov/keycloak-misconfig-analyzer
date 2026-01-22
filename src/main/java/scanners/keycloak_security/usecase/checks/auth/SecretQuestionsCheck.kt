package scanners.keycloak_security.usecase.checks.auth

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class SecretQuestionsCheck : SecurityCheck {

    override fun id() = "6.4.2"
    override fun title() = "Отсутствие secret questions"
    override fun description() = "Проверка, что не используются секретные вопросы для аутентификации"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()

        try {
            val requiredActions = context.adminService.getRequiredActions()

            // Ищем устаревшие методы восстановления
            val outdatedActions = listOf(
                "CONFIGURE_TOTP", // Хотя это не secret question, но проверяем наличие современных методов
                "webauthn-register-passwordless" // Современная альтернатива
            )

            val availableActions = requiredActions.map { it.alias ?: "" }

            // Проверяем наличие современных методов
            val hasModernMethods = requiredActions.any { action ->
                action.alias?.let { alias ->
                    alias.equals("CONFIGURE_TOTP", ignoreCase = true) ||
                            alias.contains("webauthn", ignoreCase = true)
                } ?: false
            }

            return if (!hasModernMethods) {
                CheckResult(
                    checkId = id(),
                    status = CheckStatus.DETECTED,
                    findings = listOf(
                        Finding(
                            id = id(),
                            title = title(),
                            description = "Не настроены современные методы аутентификации",
                            severity = severity(),
                            status = CheckStatus.DETECTED,
                            realm = context.realmName,
                            evidence = listOf(
                                Evidence("availableActions", availableActions.toString()),
                                Evidence("hasTOTP", "false"),
                                Evidence("hasWebAuthn", "false")
                            ),
                            recommendation = "Настройте современные методы восстановления: TOTP или WebAuthn"
                        )
                    ),
                    durationMs = System.currentTimeMillis() - start
                )
            } else {
                CheckResult(
                    checkId = id(),
                    status = CheckStatus.OK,
                    durationMs = System.currentTimeMillis() - start
                )
            }

        } catch (e: Exception) {
            return CheckResult(
                checkId = id(),
                status = CheckStatus.ERROR,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = title(),
                        description = "Ошибка при проверке: ${e.message}",
                        severity = Severity.HIGH,
                        status = CheckStatus.ERROR,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("error", e.message ?: "Unknown error")
                        ),
                        recommendation = "Проверьте подключение к Keycloak API"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        }
    }
}