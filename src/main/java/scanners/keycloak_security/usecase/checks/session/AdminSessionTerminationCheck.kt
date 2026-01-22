package scanners.keycloak_security.usecase.checks.session

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck
import scanners.keycloak_security.usecase.checks.SecurityCheckHelper

@Component
class AdminSessionTerminationCheck : SecurityCheck {
    override fun id() = "7.4.5"
    override fun title() = "Завершение сессий администратором"
    override fun description() = "Проверка возможности администратора завершать сессии пользователей"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        try {
            val canRevoke = context.adminService.canRevokeUserSessions()

            return CheckResult(
                checkId = id(),
                status = CheckStatus.INFO,
                findings = listOf(
                    Finding(
                        id = id(),
                        title = if (canRevoke) "Администратор может завершать сессии" else "Ограниченные права администратора",
                        description = if (canRevoke)
                            "Keycloak предоставляет API для завершения сессий пользователей администратором"
                        else
                            "Текущий административный клиент может иметь ограниченные права для управления сессиями",
                        severity = if (canRevoke) Severity.INFO else Severity.LOW,
                        status = if (canRevoke) CheckStatus.OK else CheckStatus.DETECTED,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("canRevokeSessions", canRevoke.toString()),
                            Evidence("requiredRole", "manage-users"),
                            Evidence("apiEndpoint", "POST /admin/realms/{realm}/users/{user-id}/logout")
                        ),
                        recommendation = if (canRevoke)
                            null
                        else
                            "Назначьте роль 'manage-users' административному клиенту для полного контроля над сессиями"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        } catch (e: Exception) {
            return SecurityCheckHelper.createErrorResult(id(), title(), e, start, context.realmName)
        }
    }
}