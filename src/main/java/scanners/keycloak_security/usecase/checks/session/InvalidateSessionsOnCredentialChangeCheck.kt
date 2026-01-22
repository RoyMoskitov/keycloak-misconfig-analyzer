package scanners.keycloak_security.usecase.checks.session

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class InvalidateSessionsOnCredentialChangeCheck : SecurityCheck {
    override fun id() = "7.4.3"
    override fun title() = "Завершение сессий при смене учётных данных"
    override fun description() = "Проверка настроек принудительного завершения сессий при смене пароля или MFA"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        try {
            val realm = context.adminService.getRealm()
            val requiredActions = context.adminService.getRequiredActions()
            val findings = mutableListOf<Finding>()

            // 1. Проверка Required Action UPDATE_PASSWORD
            val updatePasswordAction = requiredActions.find {
                it.alias.equals("UPDATE_PASSWORD", ignoreCase = true)
            }

            if (updatePasswordAction == null) {
                findings.add(Finding(
                    id = id(),
                    title = "Действие UPDATE_PASSWORD не настроено",
                    description = "Отсутствует Required Action для принудительной смены пароля",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("updatePasswordAction", "not found")),
                    recommendation = "Настройте Required Action UPDATE_PASSWORD для контроля смены паролей"
                ))
            } else if (updatePasswordAction.isEnabled == false) {
                findings.add(Finding(
                    id = id(),
                    title = "UPDATE_PASSWORD отключен",
                    description = "Действие принудительной смены пароля отключено",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("actionAlias", updatePasswordAction.alias ?: "unknown"),
                        Evidence("enabled", "false")
                    ),
                    recommendation = "Включите UPDATE_PASSWORD для обеспечения смены паролей по политике безопасности"
                ))
            }

            // 2. Проверка настройки Logout All Sessions
            // В Keycloak нет прямой настройки через Realm API, но можно проверить через события
            // Добавляем информационное сообщение о необходимости ручной проверки
            findings.add(Finding(
                id = id(),
                title = "Требуется ручная проверка поведения",
                description = "Keycloak не предоставляет API для проверки настройки 'Logout all sessions on password reset'",
                severity = Severity.LOW,
                status = CheckStatus.DETECTED,
                realm = context.realmName,
                evidence = listOf(Evidence("manualCheckRequired", "true")),
                recommendation = "Проверьте вручную в административной консоли: Realm Settings -> Events -> Config. " +
                        "Убедитесь, что при сбросе пароля включается опция 'Logout all sessions'"
            ))

            // 3. Проверка MFA Required Actions
            val mfaActions = listOf("CONFIGURE_TOTP", "webauthn-register")
            val configuredMfaActions = requiredActions.filter { action ->
                mfaActions.any { mfa -> action.alias?.equals(mfa, ignoreCase = true) == true }
            }

            if (configuredMfaActions.isNotEmpty()) {
                findings.add(Finding(
                    id = id(),
                    title = "Настроены действия для MFA",
                    description = "Обнаружены Required Actions для настройки MFA: ${configuredMfaActions.joinToString { it.alias ?: "unknown" }}",
                    severity = Severity.INFO,
                    status = CheckStatus.OK,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("mfaActions", configuredMfaActions.joinToString { it.alias ?: "unknown" })
                    ),
                    recommendation = "Убедитесь, что при смене MFA-факторов старые сессии завершаются"
                ))
            }

            return if (findings.any { it.severity >= Severity.MEDIUM }) {
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
                    findings = findings,
                    durationMs = System.currentTimeMillis() - start
                )
            }

        } catch (e: Exception) {
            return createErrorResult(e, start, context.realmName)
        }
    }

    private fun createErrorResult(e: Exception, start: Long, realmName: String): CheckResult {
        return CheckResult(
            checkId = id(),
            status = CheckStatus.ERROR,
            findings = listOf(
                Finding(
                    id = id(),
                    title = "Ошибка при проверке",
                    description = "Ошибка при проверке завершения сессий при смене учётных данных: ${e.message}",
                    severity = Severity.HIGH,
                    status = CheckStatus.ERROR,
                    realm = realmName,
                    evidence = listOf(
                        Evidence("error", e.message ?: "Unknown"),
                        Evidence("errorType", e.javaClass.simpleName)
                    ),
                    recommendation = "Проверьте доступность Keycloak API"
                )
            ),
            durationMs = System.currentTimeMillis() - start
        )
    }
}