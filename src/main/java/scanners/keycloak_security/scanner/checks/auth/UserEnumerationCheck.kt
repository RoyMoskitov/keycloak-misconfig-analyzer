package scanners.keycloak_security.scanner.checks.auth

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

/**
 * ASVS V6.3.8: "Verify that valid users cannot be deduced from failed authentication
 * challenges, such as by basing on error messages, HTTP response codes, or different
 * response times."
 *
 * В Keycloak: при registrationAllowed=true и duplicateEmailsAllowed=false
 * форма регистрации раскрывает существование пользователей через ошибки
 * "Email already exists" / "Username already exists".
 */
@Component
class UserEnumerationCheck : SecurityCheck {

    override fun id() = "6.3.8"
    override fun title() = "Защита от перечисления пользователей"
    override fun description() =
        "Проверка, что конфигурация realm не позволяет определить существование учётных записей (ASVS V6.3.8)"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val realm = context.adminService.getRealm()

            // Вектор 1: Registration + duplicateEmailsAllowed=false
            // При попытке регистрации с существующим email/username KC возвращает
            // "Email already exists" / "Username already exists"
            val registrationAllowed = realm.isRegistrationAllowed == true
            val duplicateEmailsAllowed = realm.isDuplicateEmailsAllowed == true

            if (registrationAllowed && !duplicateEmailsAllowed) {
                findings += Finding(
                    id = id(),
                    title = "Перечисление пользователей через форму регистрации",
                    description = "Регистрация разрешена (registrationAllowed=true) и дублирование email запрещено " +
                            "(duplicateEmailsAllowed=false). При попытке регистрации с существующим email " +
                            "Keycloak возвращает 'Email already exists', раскрывая наличие учётной записи.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("registrationAllowed", true),
                        Evidence("duplicateEmailsAllowed", false),
                        Evidence("vector", "registration form email/username enumeration")
                    ),
                    recommendation = "Если регистрация необходима, включите duplicateEmailsAllowed=true " +
                            "или используйте CAPTCHA для ограничения автоматизированного перебора"
                )
            }

            // Вектор 2: Reset password + SMTP настроен → timing oracle
            val resetPasswordAllowed = realm.isResetPasswordAllowed == true
            val smtpConfigured = realm.smtpServer != null &&
                    !realm.smtpServer["host"].isNullOrBlank()

            if (resetPasswordAllowed && smtpConfigured) {
                findings += Finding(
                    id = id(),
                    title = "Потенциальное перечисление через timing при сбросе пароля",
                    description = "Сброс пароля включён и SMTP настроен. При запросе сброса для существующего " +
                            "пользователя сервер отправляет email (задержка), для несуществующего — отвечает мгновенно. " +
                            "Разница во времени ответа позволяет определить валидные email.",
                    severity = Severity.LOW,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("resetPasswordAllowed", true),
                        Evidence("smtpConfigured", true),
                        Evidence("vector", "password reset timing oracle")
                    ),
                    recommendation = "Используйте асинхронную отправку email при сбросе пароля " +
                            "или добавьте искусственную задержку для выравнивания времени ответа"
                )
            }

            // Вектор 3: loginWithEmailAllowed раскрывает формат username
            val loginWithEmail = realm.isLoginWithEmailAllowed == true
            val registrationEmailAsUsername = realm.isRegistrationEmailAsUsername == true

            if (registrationAllowed && loginWithEmail && !registrationEmailAsUsername) {
                findings += Finding(
                    id = id(),
                    title = "Раздельные username и email увеличивают поверхность перечисления",
                    description = "Регистрация разрешена, вход по email включён, но email не используется как username. " +
                            "Атакующий может перечислять и username, и email — два вектора вместо одного.",
                    severity = Severity.LOW,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("loginWithEmailAllowed", true),
                        Evidence("registrationEmailAsUsername", false),
                        Evidence("registrationAllowed", true)
                    ),
                    recommendation = "Используйте registrationEmailAsUsername=true для уменьшения поверхности атаки"
                )
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
