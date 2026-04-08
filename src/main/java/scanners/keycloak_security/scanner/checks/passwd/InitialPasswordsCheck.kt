package scanners.keycloak_security.scanner.checks.passwd

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck

@Component
class InitialPasswordsCheck : SecurityCheck {

    override fun id() = "6.4.1"
    override fun title() = "Временные пароли и ссылки активации"
    override fun description() = "Проверка настроек времени жизни временных паролей и ссылок активации"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val realm = context.adminService.getRealm()

        val adminTokenLifespan = realm.actionTokenGeneratedByAdminLifespan ?: 43200 // default 12h
        val userTokenLifespan = realm.actionTokenGeneratedByUserLifespan ?: 43200 // default 12h

        val findings = mutableListOf<Finding>()

        // Проверка времени жизни токенов администратора
        if (adminTokenLifespan > 3600) { // больше 1 часа
            findings.add(
                Finding(
                    id = id(),
                    title = "Долгий срок жизни токенов администратора",
                    description = "Токены, сгенерированные администратором, живут $adminTokenLifespan секунд (${adminTokenLifespan / 3600} часов)",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("actionTokenGeneratedByAdminLifespan", adminTokenLifespan.toString())
                    ),
                    recommendation = "Установите actionTokenGeneratedByAdminLifespan ≤ 3600 секунд (1 час)"
                )
            )
        }

        // Проверка времени жизни токенов пользователя
        if (userTokenLifespan > 3600) { // больше 1 часа
            findings.add(
                Finding(
                    id = id(),
                    title = "Долгий срок жизни токенов пользователя",
                    description = "Токены, сгенерированные пользователем, живут $userTokenLifespan секунд (${userTokenLifespan / 3600} часов)",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("actionTokenGeneratedByUserLifespan", userTokenLifespan.toString())
                    ),
                    recommendation = "Установите actionTokenGeneratedByUserLifespan ≤ 3600 секунд (1 час)"
                )
            )
        }

        // Дополнительная проверка: верификация email должна быть включена
        val verifyEmail = realm.isVerifyEmail ?: false
        if (!verifyEmail && realm.isRegistrationAllowed == true) {
            findings.add(
                Finding(
                    id = id(),
                    title = "Верификация email отключена при разрешенной регистрации",
                    description = "Регистрация новых пользователей разрешена, но верификация email отключена",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("verifyEmail", "false"),
                        Evidence("registrationAllowed", "true")
                    ),
                    recommendation = "Включите верификацию email (Verify Email) при разрешенной регистрации"
                )
            )
        }

        // Проверяем настроен ли SMTP — без него email verification и password reset не работают
        val smtpServer = realm.smtpServer
        val smtpConfigured = smtpServer != null && smtpServer["host"]?.isNotBlank() == true
        val verifyEmailEnabled = realm.isVerifyEmail ?: false
        val resetPasswordEnabled = realm.isResetPasswordAllowed ?: false

        if (!smtpConfigured && (verifyEmailEnabled || resetPasswordEnabled)) {
            findings.add(
                Finding(
                    id = id(),
                    title = "SMTP не настроен при активных email-зависимых функциях",
                    description = "SMTP сервер не настроен, но " +
                            (if (verifyEmailEnabled) "Verify Email включён" else "") +
                            (if (verifyEmailEnabled && resetPasswordEnabled) " и " else "") +
                            (if (resetPasswordEnabled) "Reset Password включён" else "") +
                            ". Без SMTP эти функции не работают — ложная безопасность.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("smtpConfigured", false),
                        Evidence("verifyEmail", verifyEmailEnabled),
                        Evidence("resetPasswordAllowed", resetPasswordEnabled)
                    ),
                    recommendation = "Настройте SMTP сервер в Realm Settings → Email"
                )
            )
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
}