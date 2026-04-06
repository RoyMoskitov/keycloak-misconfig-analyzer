package scanners.keycloak_security.scanner.checks.passwd

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class PasswordResetMFACheck : SecurityCheck {

    override fun id() = "6.4.3"
    override fun title() = "Сброс пароля не обходит MFA"
    override fun description() = "Проверка, что после сброса пароля пользователь всё ещё должен пройти MFA при входе"
    override fun severity() = Severity.HIGH

    companion object {
        private val MFA_AUTHENTICATORS = setOf(
            "auth-otp-form",
            "webauthn-authenticator",
            "webauthn-authenticator-passwordless",
            "auth-recovery-authn-code-form"
        )
    }

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            val allExecutions = context.adminService.getAllAuthenticationExecutions()

            // 1. Проверяем, что в browser flow присутствует MFA
            //    (если MFA нет в основном потоке входа, сброс пароля автоматически "обходит" MFA)
            val realm = context.adminService.getRealm()
            val browserFlowAlias = realm.browserFlow ?: "browser"
            val browserExecutions = allExecutions[browserFlowAlias] ?: emptyList()

            val browserHasMfa = browserExecutions.any { exec ->
                exec.providerId in MFA_AUTHENTICATORS &&
                        exec.requirement in listOf("REQUIRED", "ALTERNATIVE", "CONDITIONAL")
            }

            if (!browserHasMfa) {
                findings += Finding(
                    id = id(),
                    title = "MFA отсутствует в основном потоке аутентификации",
                    description = "В потоке '$browserFlowAlias' не обнаружены шаги MFA. " +
                            "Без MFA в потоке входа вопрос обхода при сбросе пароля не актуален, " +
                            "но это сама по себе проблема безопасности.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("browserFlow", browserFlowAlias),
                        Evidence("mfaFound", false)
                    ),
                    recommendation = "Добавьте MFA (OTP, WebAuthn) в основной поток аутентификации ($browserFlowAlias)"
                )
            }

            // 2. Проверяем поток reset credentials — после сброса пароля
            //    пользователь должен будет при следующем входе пройти MFA из browser flow.
            //    Проблема возникает, если reset flow содержит шаг "Set Password" без
            //    последующего требования MFA, и при этом reset flow сам аутентифицирует пользователя.
            val resetFlowAlias = realm.resetCredentialsFlow ?: "reset credentials"
            val resetExecutions = allExecutions[resetFlowAlias] ?: emptyList()

            // Проверяем, есть ли в reset flow шаг, который полностью аутентифицирует пользователя
            // без MFA (т.е. создаёт сессию без прохождения MFA)
            val resetHasDirectLogin = resetExecutions.any { exec ->
                exec.providerId in listOf(
                    "reset-password",          // стандартный шаг сброса
                    "reset-credential-email"   // email-based reset
                )
            }

            val resetRequiresMfa = resetExecutions.any { exec ->
                exec.providerId in MFA_AUTHENTICATORS &&
                        exec.requirement in listOf("REQUIRED", "CONDITIONAL")
            }

            // Если reset flow аутентифицирует пользователя напрямую и
            // при этом browser flow имеет MFA, но reset flow — нет,
            // это значит что сброс пароля обходит MFA
            if (browserHasMfa && resetHasDirectLogin && !resetRequiresMfa) {
                findings += Finding(
                    id = id(),
                    title = "Сброс пароля обходит MFA",
                    description = "Основной поток '$browserFlowAlias' требует MFA, " +
                            "но поток сброса пароля '$resetFlowAlias' не содержит шага MFA. " +
                            "Атакующий, получивший доступ к email жертвы, может через сброс пароля " +
                            "войти в аккаунт без прохождения MFA.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("browserFlow", browserFlowAlias),
                        Evidence("browserFlowHasMfa", true),
                        Evidence("resetFlow", resetFlowAlias),
                        Evidence("resetFlowHasMfa", false)
                    ),
                    recommendation = "Добавьте шаг MFA-верификации в поток '$resetFlowAlias' " +
                            "после шага сброса пароля, либо настройте conditional OTP в reset flow"
                )
            }

            // 3. Проверяем время жизни токена сброса — слишком длинный токен увеличивает окно атаки
            val resetTokenLifespan = realm.actionTokenGeneratedByAdminLifespan ?: 43200
            if (resetTokenLifespan > 900) { // > 15 минут
                findings += Finding(
                    id = id(),
                    title = "Долгий срок жизни токена сброса пароля",
                    description = "Токен сброса пароля действителен $resetTokenLifespan секунд " +
                            "(${resetTokenLifespan / 60} минут). Длительное окно увеличивает " +
                            "вероятность перехвата токена.",
                    severity = Severity.LOW,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("actionTokenLifespan", resetTokenLifespan)
                    ),
                    recommendation = "Сократите время жизни токена сброса до 15 минут (900 секунд)"
                )
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
