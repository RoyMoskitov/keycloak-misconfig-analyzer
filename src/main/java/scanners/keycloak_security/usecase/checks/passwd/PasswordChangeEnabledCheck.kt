package scanners.keycloak_security.usecase.checks.passwd

import org.springframework.stereotype.Component
import scanners.keycloak_security.domain.model.*
import scanners.keycloak_security.usecase.checks.SecurityCheck

@Component
class PasswordChangeEnabledCheck : SecurityCheck {

    override fun id() = "6.2.2"
    override fun title() = "Возможность смены пароля пользователем"
    override fun description() = "Проверка доступности функции самостоятельной смены пароля"
    override fun severity() = Severity.MEDIUM

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()

        try {
            val requiredActions = context.adminService.getRequiredActions()

            val updatePasswordAction = requiredActions.find {
                it.alias.equals("UPDATE_PASSWORD", ignoreCase = true)
            }

            return if (updatePasswordAction == null) {
                CheckResult(
                    checkId = id(),
                    status = CheckStatus.DETECTED,
                    findings = listOf(
                        Finding(
                            id = id(),
                            title = title(),
                            description = "Действие UPDATE_PASSWORD не найдено в списке доступных действий",
                            severity = severity(),
                            status = CheckStatus.DETECTED,
                            realm = context.realmName,
                            evidence = listOf(
                                Evidence("availableActions",
                                    requiredActions.joinToString { it.alias ?: "unknown" }
                                ),
                                Evidence("updatePasswordFound", "false")
                            ),
                            recommendation = "Включите действие UPDATE_PASSWORD в настройках аутентификации"
                        )
                    ),
                    durationMs = System.currentTimeMillis() - start
                )
            } else if (updatePasswordAction.isEnabled == false) {
                CheckResult(
                    checkId = id(),
                    status = CheckStatus.DETECTED,
                    findings = listOf(
                        Finding(
                            id = id(),
                            title = title(),
                            description = "Действие UPDATE_PASSWORD отключено",
                            severity = severity(),
                            status = CheckStatus.DETECTED,
                            realm = context.realmName,
                            evidence = listOf(
                                Evidence("actionAlias", updatePasswordAction.alias ?: "UNKNOWN"),
                                Evidence("actionEnabled", "false"),
                                Evidence("actionName", updatePasswordAction.name ?: "Unknown"),
                                Evidence("actionPriority", updatePasswordAction.priority?.toString() ?: "N/A")
                            ),
                            recommendation = "Включите действие UPDATE_PASSWORD в настройках аутентификации"
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
                        description = "Ошибка при проверке доступности смены пароля: ${e.message}",
                        severity = Severity.HIGH,
                        status = CheckStatus.ERROR,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("error", e.message ?: "Unknown error"),
                            Evidence("errorType", e.javaClass.simpleName)
                        ),
                        recommendation = "Проверьте доступность Keycloak API и права доступа"
                    )
                ),
                durationMs = System.currentTimeMillis() - start
            )
        }
    }
}