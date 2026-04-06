package scanners.keycloak_security.scanner.checks.passwd

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper

@Component
class PasswordChangeEnabledCheck : SecurityCheck {

    override fun id() = "6.2.2"
    override fun title() = "Возможность смены пароля пользователем"
    override fun description() = "Проверка доступности самостоятельной смены пароля (ASVS V6.2.2)"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        val findings = mutableListOf<Finding>()

        try {
            // 1. Проверяем доступность Account Console — основной способ смены пароля
            val accountConsoleAvailable = context.adminService.isAccountConsoleAvailable()

            if (!accountConsoleAvailable) {
                findings += Finding(
                    id = id(),
                    title = "Account Console недоступна",
                    description = "Клиент 'account-console' отключён или не найден. " +
                            "Это основной интерфейс для самостоятельной смены пароля пользователями.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("accountConsoleAvailable", false)),
                    recommendation = "Включите клиент 'account-console' в настройках Realm"
                )
            }

            // 2. Проверяем, что Required Action UPDATE_PASSWORD доступна и включена
            val requiredActions = context.adminService.getRequiredActions()
            val updatePasswordAction = requiredActions.find {
                it.alias.equals("UPDATE_PASSWORD", ignoreCase = true)
            }

            if (updatePasswordAction == null) {
                findings += Finding(
                    id = id(),
                    title = "Действие UPDATE_PASSWORD не найдено",
                    description = "Required Action 'UPDATE_PASSWORD' отсутствует в realm. " +
                            "Без этого действия администраторы не смогут принудительно запросить смену пароля.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("availableActions", requiredActions.joinToString { it.alias ?: "?" })
                    ),
                    recommendation = "Восстановите Required Action 'UPDATE_PASSWORD'"
                )
            } else if (updatePasswordAction.isEnabled == false) {
                findings += Finding(
                    id = id(),
                    title = "Действие UPDATE_PASSWORD отключено",
                    description = "Required Action 'UPDATE_PASSWORD' существует, но отключена.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(
                        Evidence("actionAlias", updatePasswordAction.alias ?: "?"),
                        Evidence("enabled", false)
                    ),
                    recommendation = "Включите Required Action 'UPDATE_PASSWORD'"
                )
            }

        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }

        return SecurityCheckHelper.buildCheckResult(id(), title(), findings, start, context.realmName)
    }
}
