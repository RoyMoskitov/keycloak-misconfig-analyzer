package scanners.keycloak_security.usecase.checks.session

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck
import scanners.keycloak_security.usecase.checks.SecurityCheckHelper.createErrorResult

@Component
class UserSessionVisibilityCheck : SecurityCheck {
    override fun id() = "7.5.2"
    override fun title() = "Видимость и завершение сессий пользователем"
    override fun description() = "Проверка возможности пользователя просматривать и завершать свои сессии через Account Console"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        try {
            val accountConsoleAvailable = context.adminService.isAccountConsoleAvailable()

            return CheckResult(
                checkId = id(),
                status = if (accountConsoleAvailable) CheckStatus.OK else CheckStatus.DETECTED,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = if (accountConsoleAvailable)
                            "Account Console доступен"
                        else
                            "Account Console недоступен или отключен",
                        description = if (accountConsoleAvailable)
                            "Пользователи могут использовать Account Console для просмотра и завершения своих сессий"
                        else
                            "Функциональность управления сессиями через Account Console недоступна",
                        severity = if (accountConsoleAvailable) Severity.LOW else Severity.MEDIUM,
                        status = if (accountConsoleAvailable) CheckStatus.OK else CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("accountConsoleAvailable", accountConsoleAvailable.toString()),
                            Evidence("clientId", "account-console"),
                            Evidence("feature", "Active Sessions management")
                        ),
                        recommendation = if (accountConsoleAvailable)
                            null
                        else
                            "Включите клиент 'account-console' и убедитесь, что пользователи имеют к нему доступ"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        } catch (e: Exception) {
            return createErrorResult(id(), title(), e, start, context.realmName)
        }
    }
}