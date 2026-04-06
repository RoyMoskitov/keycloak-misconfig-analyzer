package scanners.keycloak_security.scanner.checks.session

import org.springframework.stereotype.Component
import scanners.keycloak_security.model.*
import scanners.keycloak_security.scanner.SecurityCheck
import scanners.keycloak_security.scanner.SecurityCheckHelper.createErrorResult

@Component
class LogoutSessionInvalidationCheck : SecurityCheck {
    override fun id() = "7.4.1"
    override fun title() = "Инвалидация сессий при logout"
    override fun description() = "Проверка, что выход из системы (logout) отзывает refresh tokens и делает сессию недействительной"
    override fun severity() = Severity.HIGH

    override fun run(context: CheckContext): CheckResult {
        val start = System.currentTimeMillis()
        try {
            val realm = context.adminService.getRealm()
            val findings = mutableListOf<Finding>()

            // Основная проверка: включена ли опция отзыва refresh token
            val revokeRefreshToken = realm.revokeRefreshToken ?: false
            if (!revokeRefreshToken) {
                findings.add(Finding(
                    id = id(),
                    title = "Отзыв refresh token при logout отключен",
                    description = "Опция 'Revoke Refresh Token' выключена. Старые refresh tokens могут оставаться валидными после выхода.",
                    severity = Severity.HIGH,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("revokeRefreshToken", "false")),
                    recommendation = "Включите 'Revoke Refresh Token' в настройках Realm для гарантированного отзыва токенов при выходе."
                ))
            }

            // Связанная проверка: максимум повторного использования refresh token
            val refreshTokenMaxReuse = realm.refreshTokenMaxReuse ?: 0
            if (revokeRefreshToken && refreshTokenMaxReuse > 0) {
                findings.add(Finding(
                    id = id(),
                    title = "Разрешено повторное использование refresh token",
                    description = "Refresh Token Max Reuse = $refreshTokenMaxReuse. Токен может быть использован несколько раз.",
                    severity = Severity.MEDIUM,
                    status = CheckStatus.DETECTED,
                    realm = context.realmName,
                    evidence = listOf(Evidence("refreshTokenMaxReuse", refreshTokenMaxReuse.toString())),
                    recommendation = "Для строгой инвалидации установите Refresh Token Max Reuse = 0."
                ))
            }

            return if (findings.isEmpty()) {
                CheckResult(
                    checkId = id(),
                    status = CheckStatus.OK,
                    findings = listOf(Finding(
                        id = id(),
                        title = "Инвалидация сессий при logout настроена корректно",
                        description = "Refresh tokens гарантированно отзываются при выходе пользователя.",
                        severity = Severity.INFO,
                        status = CheckStatus.OK,
                        realm = context.realmName,
                        evidence = listOf(
                            Evidence("revokeRefreshToken", "true"),
                            Evidence("refreshTokenMaxReuse", refreshTokenMaxReuse.toString())
                        ),
                        recommendation = null
                    )),
                    durationMs = System.currentTimeMillis() - start
                )
            } else {
                CheckResult(
                    checkId = id(),
                    status = CheckStatus.DETECTED,
                    findings = findings,
                    durationMs = System.currentTimeMillis() - start
                )
            }
        } catch (e: Exception) {
            return createErrorResult(id(), title(), e, start, context.realmName)
        }
    }
}