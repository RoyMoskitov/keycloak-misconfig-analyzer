package scanners.keycloak_security.scanner.checks.auth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

/**
 * Проверка защиты от спам-регистрации.
 * Если регистрация открыта, должны быть механизмы защиты:
 * CAPTCHA, верификация email, ограничение по домену.
 */
@Component
class RegistrationSpamProtectionCheck : SecurityCheck {

    override fun id() = "6.3.6"
    override fun title() = "Защита от спам-регистрации"
    override fun description() =
        "Проверка наличия CAPTCHA или других механизмов защиты при открытой регистрации"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val realm = context.adminService.getRealm()

            if (realm.isRegistrationAllowed != true) {
                return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
            }

            // Проверяем registration flow на наличие CAPTCHA
            val registrationFlowAlias = realm.registrationFlow ?: "registration"
            val allExecutions = context.adminService.getAllAuthenticationExecutions()
            val registrationExecs = allExecutions[registrationFlowAlias] ?: emptyList()

            val hasCaptcha = registrationExecs.any { exec ->
                exec.providerId in setOf(
                    "registration-recaptcha-action",
                    "registration-recaptcha-enterprise",
                    "registration-google-recaptcha"
                ) && exec.requirement in listOf("REQUIRED", "ALTERNATIVE")
            }

            if (!hasCaptcha) {
                findings += Finding(
                    id = id(),
                    title = "Регистрация без CAPTCHA",
                    description = "Самостоятельная регистрация включена без CAPTCHA. " +
                            "Автоматизированные боты могут массово создавать аккаунты " +
                            "для спама, DoS или credential stuffing.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("registrationAllowed", true),
                        Evidence("registrationFlow", registrationFlowAlias),
                        Evidence("captchaEnabled", false)
                    ),
                    recommendation = "Добавьте reCAPTCHA в Registration Flow или отключите открытую регистрацию"
                )
            }

            // Если регистрация открыта и email не верифицируется
            if (realm.isVerifyEmail != true) {
                findings += Finding(
                    id = id(),
                    title = "Регистрация без верификации email",
                    description = "Пользователи могут регистрироваться с любым email без подтверждения. " +
                            "Это позволяет создавать аккаунты с поддельными email для фишинга или спама.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("registrationAllowed", true),
                        Evidence("verifyEmail", false)
                    ),
                    recommendation = "Включите Verify Email в настройках Realm → Login"
                )
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
